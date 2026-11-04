#!/usr/bin/env python3
"""Owned loopback fixtures and external clients; NEVER controls/configures Burp.

First load the distribution JAR and configure the disposable Burp UI manually.
See docs/MANUAL_BURP_SMOKE.md. No CAIRN/worker, licensing, trust-store or native
project APIs are used. Results are observations, not full acceptance coverage.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, field
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import ssl
import threading
import time
from urllib.parse import parse_qs
from uuid import UUID, uuid4

SYNTHETIC_AUTH = "Bearer synthetic-native-fixture-not-a-real-token"
SYNTHETIC_COOKIE = "fixture_session=synthetic-native-cookie"
BODY = b'{"note":"harmless fixture","password":"synthetic-native-password"}'
LARGE_BYTES = 6 * 1024 * 1024
PENTEST_PATHS = ("/c/;/main.do", "/c/%2e/main.do", "/c/%252e/main.do", "/c/%25252e/main.do",
                 "/c/./main.do", "/c/a/../main.do", "/c/;x/main.do", "/c/%3b/main.do", "/c/%253b/main.do",
                 "/c%2fmain.do", "/c%252fmain.do", "/c\\\\main.do", "//c///main.do", "/c/%ZZ/main.do?bad=%ZZ")


def loopback(value: str) -> str:
    if not ipaddress.ip_address(value).is_loopback:
        raise ValueError("Only numeric loopback addresses are permitted")
    return value


@dataclass
class State:
    lock: threading.Lock = field(default_factory=threading.Lock)
    events: list = field(default_factory=list)
    active: int = 0
    peak: int = 0

    def snapshot(self):
        with self.lock:
            return list(self.events)


def fixture(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass  # Never write request/credential logs.

        def handle_fixture(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 1024 * 1024 + 4096:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            # BaseHTTPRequestHandler normalizes a leading // in self.path. Keep the actual bounded
            # request-line bytes for equality assertions, including malformed-percent targets.
            target = self.raw_requestline.split(b" ", 2)[1].decode("ascii")
            event = {"at": time.monotonic(), "host": self.server.server_address[0], "host_header": self.headers.get("Host"),
                     "method": self.command, "path": target, "request_target": target,
                     "authorization": self.headers.get("Authorization"),
                     "cookie": self.headers.get("Cookie"), "body": body}
            with state.lock:
                if len(state.events) >= 500:
                    self.send_error(503)
                    return
                state.events.append(event)
                state.active += 1
                state.peak = max(state.peak, state.active)
            try:
                path, _, query_text = target.partition("?")
                query = parse_qs(query_text)
                if path == "/hold":
                    time.sleep(min(3.0, max(0, float(query.get("seconds", ["1.5"])[0]))))
                response = (b"L" * LARGE_BYTES if path == "/large" else
                    json.dumps({"fixture": "owned-loopback", "method": self.command,
                                "path": target, "host_header": event["host_header"], "body": body.decode("utf-8", errors="replace"),
                                "body_hex": body.hex(), "authorization": event["authorization"],
                                "cookie": event["cookie"]}, separators=(",", ":")).encode())
                self.send_response(503 if path == "/status5xx" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Fixture", "owned-loopback")
                self.send_header("Set-Cookie", "fixture_response=synthetic-native-response; HttpOnly")
                self.send_header("Content-Length", str(len(response)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response)
            finally:
                with state.lock:
                    state.active -= 1

        do_GET = do_HEAD = do_POST = do_DELETE = handle_fixture
    return Handler


class Run:
    def __init__(self, args, state):
        self.args, self.state = args, state
        self.results = []

    def request(self, path="/safe", method="GET", body=None, headers=None, second=False, proxy_port=None):
        host, port = ("127.0.0.2", self.args.second_port) if second else ("127.0.0.1", self.args.port)
        if self.args.https:
            assert not second, "Two-host pacing is a separate HTTP experiment"
            host = "localhost"  # Real DNS identity: Burp's numeric-IP certificates may have DNS-only SANs.
        # Hardcoded loopback targets only. CLI cannot redirect traffic externally.
        headers = dict(headers or {})
        headers.setdefault("Connection", "close")
        selected_proxy = self.args.proxy_port if proxy_port is None else proxy_port
        # http.client sends this target as-is; do not replace with a URL-normalizing client. For curl
        # reproductions use --path-as-is. Clients/fixtures never configure or call Burp admin APIs.
        connection = http.client.HTTPConnection(loopback(self.args.proxy_host), selected_proxy, timeout=40)
        try:
            if self.args.https:
                # A human must explicitly export the disposable instance's PUBLIC CA.
                connection = http.client.HTTPSConnection(
                    loopback(self.args.proxy_host), selected_proxy, timeout=40,
                    context=ssl.create_default_context(cafile=self.args.burp_ca))
                connection.set_tunnel(host, port)
                target = path
            else:
                target = f"http://{host}:{port}{path}"
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def blocked(self, response):
        status, _, body = response
        assert status == 451, f"Expected local 451, got {status}"
        payload = json.loads(body)
        assert payload["source"] == "cairn-proxy-guard"
        assert payload["outcome"] == "blocked" and payload["retryable"] is False
        UUID(payload["evidenceId"])
        assert payload["local"] is True
        assert payload["guardState"] in {"PROTECTED", "PAUSED_BY_OPERATOR", "POLICY_INVALID", "POLICY_SAVE_UNCERTAIN",
            "PROJECT_UNVERIFIED", "SHUTDOWN", "CIRCUIT_OPEN", "OVERLAY_BLOCK", "INTENT_BUDGET", "LISTENER_UNVERIFIED", "CAPACITY", "IN_FLIGHT_STALLED"}
        assert type(payload["policyRevision"]) is int and payload["policyRevision"] >= 0
        if "overlayId" in payload:
            UUID(payload["overlayId"])
        return payload["reason"]

    def case(self, name, action):
        action()
        self.results.append({"case": name, "result": "PASS"})
        print(f"PASS {name}", flush=True)

    def assert_block(self, expected_reason=None, **kwargs):
        before = len(self.state.snapshot())
        reason = self.blocked(self.request(**kwargs))
        if expected_reason is not None:
            assert reason == expected_reason, f"Expected {expected_reason}, got {reason}"
        time.sleep(.04)
        assert len(self.state.snapshot()) == before, "Blocked request reached fixture"
        return reason

    def assert_arrives(self, path="/safe", method="GET", body=None, headers=None, second=False, proxy_port=None):
        before = len(self.state.snapshot())
        kwargs = dict(path=path, method=method, body=body, headers=headers, second=second)
        if proxy_port is not None:
            kwargs["proxy_port"] = proxy_port
        response = self.request(**kwargs)
        assert response[0] == 200 and response[1]["X-Fixture"] == "owned-loopback"
        events = self.state.snapshot()[before:]
        assert len(events) == 1, "Expected exactly one owned socket handoff"
        observed = events[0]
        assert observed["path"] == path and observed["method"] == method, "Native target/method changed"
        assert observed["body"] == (body or b""), "Native body bytes changed"
        if headers and "Host" in headers:
            assert observed["host_header"] == headers["Host"], "Fuzzed Host changed"
        if not getattr(self.args, "https", False):
            assert observed["host"] == ("127.0.0.2" if second else "127.0.0.1"), "Actual destination changed"
        return response

    def rawpaths(self):
        """Requires all-path scope on actual first service; no custom path/body block rules."""
        fuzzed_host = f"127.0.0.2:{self.args.second_port}"  # Also owned if proxy interprets Host differently.
        for path in PENTEST_PATHS:
            self.case("all-path raw request-target equality: " + path,
                      lambda p=path: self.assert_arrives(path=p, headers={"Host": fuzzed_host}))
        for name, body, headers in [
            ("unsupported charset", b"\xff\x00fixture", {"Content-Type": "text/plain; charset=unsupported-fixture"}),
            ("binary", b"\x00\xfffixture", {"Content-Type": "application/octet-stream"}),
            ("multipart", b"--fixture\r\nopaque\r\n--fixture--", {"Content-Type": "multipart/form-data; boundary=fixture"}),
            ("encoded", b"not-decompressed-by-guard", {"Content-Encoding": "gzip", "Content-Type": "text/plain"}),
            ("malformed JSON", b'{"broken":', {"Content-Type": "application/json"}),
            ("optional capture overflow", b"C" * (1024 * 1024 + 1), {"Content-Type": "application/octet-stream"}),
        ]:
            self.case("same native payload: " + name,
                      lambda b=body, h=headers: self.assert_arrives(method="POST", body=b, headers=h))
        if not self.args.https:
            self.case("Host cannot authorize outside actual service", lambda: self.assert_block(
                expected_reason="SCOPE_NOT_ALLOWED", second=True, headers={"Host": f"127.0.0.1:{self.args.port}"}))

    def heavy(self):
        """Human sets 5MiB response threshold and no other availability detector interference."""
        def large():
            before = len(self.state.snapshot())
            response = self.request("/large")
            assert response[0] == 200 and len(response[2]) == LARGE_BYTES and response[2] == b"L" * LARGE_BYTES
            assert len(self.state.snapshot()) == before + 1
        self.case("first owned6MiB response is untouched", large)
        self.case("next same path quarantined locally", lambda: self.assert_block(expected_reason="HEAVY_ENDPOINT_AUTO_BLOCKED", path="/large"))
        input("HUMAN: release this overlay in the automatic-block UI, then press Enter (script does not control Burp): ")
        self.case("human release allows next untouched6MiB response", large)

    def circuit(self):
        """Human sets threshold5/window60s/open --open-seconds; health bypass disabled."""
        for _ in range(5):
            before = len(self.state.snapshot())
            response = self.request("/status5xx")
            assert response[0] == 503 and response[1]["X-Fixture"] == "owned-loopback"
            assert len(self.state.snapshot()) == before + 1
        self.case("five5xx open service circuit", lambda: self.assert_block(expected_reason="CIRCUIT_OPEN"))
        time.sleep(self.args.open_seconds + .1)
        before = len(self.state.snapshot())
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, "/hold?seconds=1.5")
            deadline = time.monotonic() + 5
            while len(self.state.snapshot()) == before:
                assert time.monotonic() < deadline, "Half-open request did not reach fixture"
                time.sleep(.01)
            self.case("single in-flight half-open lease", lambda: self.assert_block(expected_reason="CIRCUIT_OPEN"))
            assert pending.result(timeout=5)[0] == 200
        self.case("successful half-open closes circuit", lambda: self.assert_arrives())

    def exempt(self):
        """Human authors both BLOCK PATH=/broker and EXEMPT PATH=/broker; keep DELETE default."""
        self.case("EXEMPT wins same-path BLOCK", lambda: self.assert_arrives(path="/broker"))
        self.case("DELETE ordinary default still blocked", lambda: self.assert_block(expected_reason="RULE_BLOCK", method="DELETE"))

    def intent(self):
        """Human sets per-intent limit20; labels are untrusted accounting, not authorization."""
        run_id = "fixture-" + uuid4().hex
        headers = {"X-Cairn-Intent": "i048", "X-Cairn-Run": run_id}
        for _ in range(20):
            self.assert_arrives(headers=headers)
        self.case("exact21st intent final handoff denied", lambda: self.assert_block(expected_reason="INTENT_BUDGET_EXCEEDED", headers=headers))
        self.case("other intent unaffected", lambda: self.assert_arrives(headers=dict(headers, **{"X-Cairn-Intent": "other"})))

    def alllisteners(self):
        """Current scope: empty guardListenerPorts, both owned inbound listeners protected."""
        for name, port in (("first", self.args.proxy_port), ("second", self.args.unselected_proxy_port)):
            self.case(name + " inbound: DELETE protected", lambda p=port: self.assert_block(
                expected_reason="RULE_BLOCK", method="DELETE", proxy_port=p))
            self.case(name + " inbound: allowed GET unchanged", lambda p=port: self.assert_arrives(proxy_port=p))

    def health(self):
        """Human paused; only exact GET /health enabled, both routes in actual service scope."""
        self.case("explicit exact empty GET health bypasses operator pause", lambda: self.assert_arrives(path="/health"))
        for name, kwargs in [
            ("query", {"path": "/health?probe=1"}),
            ("body", {"path": "/health", "body": b"fixture"}),
            ("POST", {"path": "/health", "method": "POST", "body": b""}),
            ("different path", {"path": "/safe"}),
        ]:
            self.case(name + " does not receive health exception", lambda k=kwargs: self.assert_block(expected_reason="PAUSED", **k))
        def head():
            before = len(self.state.snapshot())
            status, headers, body = self.request("/health", "HEAD")
            assert status == 451 and {k.lower(): v for k, v in headers.items()}.get("x-cairn-guard") == "blocked"
            assert body == b"", "HEAD client must not consume a response body"
            assert len(self.state.snapshot()) == before, "HEAD health bypass reached fixture"
        self.case("HEAD denied: local header and zero arrivals (no HEAD body claim)", head)

    def fanout(self):
        """Human configures distinctPaths3/action BLOCK or PAUSE; no pre-existing seen episode."""
        for path in ("/fanout/one?value=1", "/fanout/one?value=2", "/fanout/two"):
            self.case("query-free distinct-path accounting: " + path, lambda p=path: self.assert_arrives(path=p))
        self.case("third distinct path rejected at final admission", lambda: self.assert_block(
            expected_reason="FANOUT_SUSPECTED", path="/fanout/three"))
        self.case("active fanout protects earlier path", lambda: self.assert_block(
            expected_reason="FANOUT_SUSPECTED", path="/fanout/one"))
        if self.args.phase == "fanout-block":
            self.case("service-local BLOCK leaves other owned service available", lambda: self.assert_arrives(second=True))
        else:
            self.case("automatic PAUSE also protects other owned service", lambda: self.assert_block(
                expected_reason="FANOUT_SUSPECTED", second=True))
        input("HUMAN: explicitly release the fanout overlay in the human UI, then press Enter (no Burp control API): ")
        self.case("human release restores an already-seen path", lambda: self.assert_arrives(path="/fanout/one"))

    def listeners(self):
        """DEFERRED future contract, not current acceptance: protect only --proxy-port."""
        self.case("selected listener enforces DELETE default", lambda: self.assert_block(expected_reason="RULE_BLOCK", method="DELETE"))
        self.case("known unselected listener forwards same DELETE", lambda: self.assert_arrives(method="DELETE", proxy_port=self.args.unselected_proxy_port))
        print("HUMAN CHECK: unselected request created no history/raw capture, approval, watcher or intent entry; external clients cannot prove memory non-capture", flush=True)

    def empty(self):
        self.case("empty allowlist: local 451 and zero fixture hits",
                  lambda: self.assert_block(expected_reason="SCOPE_NOT_ALLOWED"))

    def exact(self):
        """Human URL form allows ONLY /safe, with the v2 DELETE-method default retained."""
        def allowed_get_head():
            before = len(self.state.snapshot())
            for method in ("GET", "HEAD"):
                status, headers, body = self.request("/safe", method)
                assert status == 200 and headers["X-Fixture"] == "owned-loopback"
                if method == "HEAD":
                    assert body == b""
            assert len(self.state.snapshot()) == before + 2
        self.case("URL form exact target: GET and HEAD arrive", allowed_get_head)
        for name, kwargs in [
            ("descendant path stays outside scope", {"path": "/safe/child"}),
            ("similar path stays outside scope", {"path": "/safex"}),
        ]:
            self.case(name, lambda k=kwargs: self.assert_block(expected_reason="SCOPE_NOT_ALLOWED", **k))
        self.case("exact target retains DELETE rule", lambda: self.assert_block(expected_reason="RULE_BLOCK", method="DELETE"))
        self.case("v2 defaults do not block benign delete query text", lambda: self.assert_arrives(path="/safe?operation=%2564elete"))
        def preserved():
            status, headers, body = self.request("/safe", "POST", BODY,
                {"Content-Type": "application/json", "Authorization": SYNTHETIC_AUTH, "Cookie": SYNTHETIC_COOKIE})
            assert status == 200 and headers["X-Fixture"] == "owned-loopback"
            data = json.loads(body)
            assert data["authorization"] == SYNTHETIC_AUTH and data["cookie"] == SYNTHETIC_COOKIE
            assert data["body"].encode() == BODY
        self.case("exact target preserves allowed synthetic request values", preserved)

    def examples(self):
        """Human forms registered exact /safe + /api/items and the three documented rule examples."""
        def get_is_not_asked():
            before = len(self.state.snapshot())
            response = self.request("/api/items")
            assert response[0] == 200 and len(self.state.snapshot()) == before + 1
        self.case("POST-path example does not ask for GET", get_is_not_asked)
        self.case("example target does not include descendants", lambda: self.assert_block(
            expected_reason="SCOPE_NOT_ALLOWED", path="/api/items/1", method="POST"))
        self.case("query example blocks operation=purge", lambda: self.assert_block(
            expected_reason="RULE_BLOCK", path="/api/items?operation=purge"))
        self._example_approval("/api/items", b'{"name":"sample"}', "POST-path example: human approval")
        self._example_approval("/safe", b'{"action":"review"}', "JSON review example: human approval")

    def _example_approval(self, path, body, label):
        def reviewed():
            before = len(self.state.snapshot())
            print("WAITING: " + label + "; inspect the human UI; do not approve before the one-second unresolved check", flush=True)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.request, path, "POST", body, {"Content-Type": "application/json"})
                time.sleep(1)
                assert len(self.state.snapshot()) == before, "Unresolved example approval reached fixture"
                response = pending.result(timeout=38)
            assert response[0] == 200 and response[1]["X-Fixture"] == "owned-loopback"
            assert len(self.state.snapshot()) == before + 1
            assert json.loads(response[2])["body"].encode() == body
        self.case(label, reviewed)

    def passthrough(self):
        """Human explicitly enabled ALL passthrough; keep the original empty/narrow scope/rules."""
        for label, path, method, body, headers, second in [
            ("scope bypass: unregistered path", "/outside", "GET", None, {}, False),
            ("rule bypass: DELETE", "/safe", "DELETE", None, {}, False),
            ("rule bypass: decoded delete", "/safe?operation=%2564elete", "GET", None, {}, False),
            ("inspection bypass: malformed JSON", "/safe", "POST", b'{"broken":', {"Content-Type": "application/json"}, False),
            ("inspection bypass: opaque binary", "/safe", "POST", b"\x00synthetic-binary", {"Content-Type": "application/octet-stream"}, False),
            ("preserves synthetic auth/cookie/body", "/safe", "POST", BODY,
             {"Content-Type": "application/json", "Authorization": SYNTHETIC_AUTH, "Cookie": SYNTHETIC_COOKIE}, False),
            ("scope bypass: second owned loopback host", "/outside", "GET", None, {}, True),
        ]:
            if second and self.args.https:
                continue  # This is deliberately a two-host HTTP experiment, not TLS coverage.
            def check(p=path, m=method, b=body, h=headers, s=second):
                before = len(self.state.snapshot())
                status, response_headers, response = self.request(p, m, b, h, second=s)
                assert status == 200 and response_headers["X-Fixture"] == "owned-loopback"
                assert len(self.state.snapshot()) == before + 1
                data = json.loads(response)
                assert data["method"] == m and data["path"] == p
                assert data["body"].encode() == (b or b"")
                assert data["authorization"] == h.get("Authorization") and data["cookie"] == h.get("Cookie")
            self.case("explicit OFF: " + label, check)
        def burst():
            before = len(self.state.snapshot())
            with self.state.lock:
                self.state.peak = 0
            barrier = threading.Barrier(6)
            def worker(index):
                barrier.wait(timeout=5)
                return self.request(f"/hold?seconds=1.5&worker={index}")
            with ThreadPoolExecutor(max_workers=6) as pool:
                responses = list(pool.map(worker, range(6)))
            assert all(r[0] == 200 for r in responses)
            assert len(self.state.snapshot()) == before + 6
            assert self.state.peak > 1, "OFF should not enforce the documented protected 1/1/1 precondition"
        self.case("explicit OFF: six clients bypass protected 1/1/1", burst)

    def default(self):
        self.basic()
        self.rate()
        self.concurrency()

    def basic(self):
        def allowed_get_head():
            for method in ("GET", "HEAD"):
                status, headers, body = self.request(method=method)
                assert status == 200 and headers["X-Fixture"] == "owned-loopback"
                if method == "HEAD":
                    assert body == b""
        self.case("allowed GET and HEAD", allowed_get_head)
        def allowed():
            status, headers, body = self.request("/echo", "POST", BODY,
                {"Content-Type": "application/json", "Authorization": SYNTHETIC_AUTH, "Cookie": SYNTHETIC_COOKIE})
            assert status == 200 and headers["X-Fixture"] == "owned-loopback"
            assert headers["Set-Cookie"] == "fixture_response=synthetic-native-response; HttpOnly"
            data = json.loads(body)
            assert data["authorization"] == SYNTHETIC_AUTH and data["cookie"] == SYNTHETIC_COOKIE
            assert data["body"].encode() == BODY
            event = self.state.snapshot()[-1]
            assert event["body"] == BODY and event["authorization"] == SYNTHETIC_AUTH
            assert event["cookie"] == SYNTHETIC_COOKIE and event["method"] == "POST"
        self.case("allowed POST: synthetic credentials/body/response values preserved", allowed)
        self.case("DELETE method: local451 and no target hit", lambda: self.assert_block(expected_reason="RULE_BLOCK", method="DELETE"))
        for name, kwargs in [
            ("mixed-case path", {"path": "/DeLeTe"}),
            ("percent-encoded path", {"path": "/%64%65lete"}),
            ("double-encoded query", {"path": "/safe?operation=%2564elete"}),
            ("header substring", {"headers": {"X-Fixture-Operation": "DeLeTe"}}),
            ("form value", {"method": "POST", "body": b"operation=%64elete", "headers": {"Content-Type": "application/x-www-form-urlencoded"}}),
            ("JSON unicode escape", {"method": "POST", "body": b'{"operation":"\\u0064elete"}', "headers": {"Content-Type": "application/json"}}),
            ("unsupported encoding", {"method": "POST", "body": b"fixture", "headers": {"Content-Type": "text/plain", "Content-Encoding": "gzip"}}),
            ("unsupported body", {"method": "POST", "body": b"fixture", "headers": {"Content-Type": "application/octet-stream"}}),
        ]:
            self.case(name + ": v2 defaults pass unchanged", lambda k=kwargs: self.assert_arrives(**k))
        self.case("scope mismatch: local 451 and zero fixture hits",
                  lambda: self.assert_block(expected_reason="SCOPE_NOT_ALLOWED", path="/outside-fixture-scope"))
        self.case("explicit block scope: local 451 and zero fixture hits",
                  lambda: self.assert_block(expected_reason="SCOPE_BLOCKED", path="/scope-block"))

    def custom(self):
        for name, kwargs in [
            ("AND/OR RE2 header", {"method": "POST", "headers": {"X-Fixture-Action": "purge-7"}}),
            ("AND/OR JSON pointer", {"method": "POST", "body": b'{"operation":"purge"}', "headers": {"Content-Type": "application/json"}}),
            ("AND/OR form selector", {"method": "POST", "body": b"operation=purge", "headers": {"Content-Type": "application/x-www-form-urlencoded"}}),
        ]:
            self.case(name + ": BLOCK dominates broad ALLOW/MONITOR", lambda k=kwargs: self.assert_block(expected_reason="RULE_BLOCK", **k))
        def allowed(**kwargs):
            assert self.request(**kwargs)[0] == 200
        self.case("AND negative: GET with matching header passes", lambda: allowed(headers={"X-Fixture-Action": "purge-7"}))
        self.case("case-sensitive negative: uppercase header value passes", lambda: allowed(method="POST", headers={"X-Fixture-Action": "PURGE-7"}))
        self.case("ALLOW/MONITOR cannot override allow-scope mismatch", lambda: self.assert_block(expected_reason="SCOPE_NOT_ALLOWED", path="/outside-fixture-scope"))
        self.case("ALLOW/MONITOR cannot override explicit block scope", lambda: self.assert_block(expected_reason="SCOPE_BLOCKED", path="/scope-block"))
        self.case("unavailable optional body inspection is not automatic451", lambda: self.assert_arrives(method="POST", body=b"fixture", headers={"Content-Type": "application/octet-stream"}))

    def disabled(self):
        before = len(self.state.snapshot())
        assert self.request(method="POST", headers={"X-Fixture-Action": "purge-7"})[0] == 200
        assert len(self.state.snapshot()) == before + 1
        self.case("disabled custom BLOCK rule no longer matches", lambda: None)

    def rate(self):
        before = len(self.state.snapshot())
        barrier = threading.Barrier(6)
        def worker(index):
            barrier.wait()
            for attempt in range(3):
                response = self.request(f"/rate?worker={index}&attempt={attempt}", second=index % 2 == 1)
                assert response[0] == 200, f"Rate fixture received {response[0]}"
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(worker, range(6)))
        events = sorted(self.state.snapshot()[before:], key=lambda x: x["at"])
        assert len(events) == 18
        span = events[-1]["at"] - events[0]["at"]
        assert span >= 17 / 5 - .15, f"Global5RPS span too short: {span:.3f}s"
        result = {"case": "six clients, two hosts share global5RPS", "result": "PASS", "arrivals": 18,
                  "arrival_span_seconds": round(span, 3),
                  "minimum_arrival_gap_seconds": round(min(b["at"]-a["at"] for a,b in zip(events,events[1:])), 3)}
        if self.args.phase == "host":
            spans = []
            for host in ("127.0.0.1", "127.0.0.2"):
                group = [e for e in events if e["host"] == host]
                host_span = group[-1]["at"] - group[0]["at"]
                assert host_span >= (len(group)-1) / 2 - .15, "Per-host2RPS span too short"
                spans.append(round(host_span, 3))
            result["per_host2RPS_arrival_spans_seconds"] = spans
        self.results.append(result)
        print(json.dumps(result), flush=True)

    def concurrency(self):
        with self.state.lock:
            self.state.peak = 0
        barrier = threading.Barrier(6)
        def worker(index):
            barrier.wait()
            assert self.request(f"/hold?seconds=1.5&worker={index}")[0] == 200
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(worker, range(6)))
        assert 1 < self.state.peak <= self.args.expected_concurrent
        result = {"case": "six held requests: native in-flight limit", "result": "PASS",
                  "observed_fixture_peak": self.state.peak, "configured_limit": self.args.expected_concurrent}
        self.results.append(result)
        print(json.dumps(result), flush=True)

    def approval(self):
        # Operator acts through Burp's human UI while this request waits.
        action = "enable all-passthrough using the human top-bar confirmation" if self.args.phase == "passthrough-cancel" else "use the human Approval tab"
        print("WAITING: " + action + "; no request should reach the fixture yet", flush=True)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, "/ask")
            time.sleep(1)
            assert not self.state.snapshot(), "Unresolved approval reached fixture"
            response = pending.result(timeout=38)
        if self.args.phase == "approve":
            assert response[0] == 200 and len(self.state.snapshot()) == 1
        else:
            reason = self.blocked(response)
            expected = {"deny": "DENIED", "expire": "APPROVAL_TIMEOUT", "stale": "POLICY_CHANGED", "passthrough-cancel": "POLICY_CHANGED"}[self.args.phase]
            assert reason == expected, f"Expected {expected}, got {reason}"
            assert not self.state.snapshot()
            print("Blocked category: " + reason, flush=True)
        self.results.append({"case": "human approval: " + self.args.phase, "result": "PASS"})
        print("PASS human approval: " + self.args.phase, flush=True)

    def paused(self):
        self.case("human pause rejects new traffic without fixture hits", lambda: self.assert_block(expected_reason="PAUSED"))

    def queue(self):
        barrier = threading.Barrier(6)
        def worker(_):
            barrier.wait()
            return self.request("/hold?seconds=1.5")
        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(worker, range(6)))
        passed = sum(r[0] == 200 for r in responses)
        blocked = [self.blocked(r) for r in responses if r[0] != 200]
        assert passed == 1 and len(blocked) == 5 and len(self.state.snapshot()) == 1
        assert set(blocked) == {"QUEUE_TIMEOUT"}
        self.results.append({"case": "bounded queue timeout", "result": "PASS", "arrivals": passed,
                             "local_blocks": len(blocked), "block_categories": sorted(set(blocked))})

    def quarantine(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, "/hold?seconds=1.5")
            deadline = time.monotonic() + 4
            while not self.state.snapshot():
                assert time.monotonic() < deadline, "Held request never arrived"
                time.sleep(.02)
            time.sleep(.75)  # Set in-flight threshold to 500ms in the UI.
            reason = self.assert_block(expected_reason="IN_FLIGHT_TIMEOUT")
            assert pending.result()[0] == 200
        assert self.request()[0] == 200, "Real response completion did not release gate"
        self.results.append({"case": "missing-response quarantine until real completion", "result": "PASS",
                             "block_category": reason, "arrivals": len(self.state.snapshot())})


def validate_incident(document):
    """Offline shape/window/retention checks of a human-exported REDACTED incident, no Burp API."""
    assert isinstance(document, dict)
    window = document["window"]
    assert set(window) == {"from", "to"}
    assert all(type(window[k]) is int for k in window)
    assert 0 < window["to"] - window["from"] <= 86_400_000
    events = document["events"]
    assert isinstance(events, list) and len(events) <= 4096
    for event in events:
        assert event["kind"] in {"HEAVY_ENDPOINT_AUTO_BLOCKED", "CIRCUIT_OPEN", "FANOUT_SUSPECTED"}
        assert type(event["ts"]) is int and window["from"] <= event["ts"] < window["to"]
        for key in ("bytes", "5xx", "distinctPaths"):
            if key in event:
                assert type(event[key]) is int and event[key] >= 0
        for key in ("path", "host"):
            if key in event:
                assert isinstance(event[key], str) and len(event[key]) <= 16_384
    for key in ("top5xx", "topBytes"):
        assert isinstance(document[key], list) and len(document[key]) <= 20
        for candidate in document[key]:
            # Candidate IDs are keyed route hashes from ResponseWatcher, NOT overlay/evidence UUIDs.
            identifier = candidate["id"]
            assert isinstance(identifier, str) and len(identifier) == 64
            assert all(char in "0123456789abcdef" for char in identifier)
            for scalar in ("maxBytes", "p95Bytes", "count", "lastSeen", "count5xx"):
                assert type(candidate[scalar]) is int and candidate[scalar] >= 0
            for text in ("host", "path", "policyUrl"):
                assert isinstance(candidate[text], str) and len(candidate[text]) <= 16_384
    for flag in ("complete", "truncated", "approximate"):
        assert type(document[flag]) is bool
    assert document["approximate"] is True
    assert document["complete"] is not document["truncated"]
    assert isinstance(document["approximation"], dict)
    retention = document["retention"]
    assert retention["maxMillis"] == 86_400_000 and type(retention["startedAt"]) is int
    for flag in ("eventsComplete", "observationsComplete", "eventsDropped", "observationsDropped", "clockRegressed"):
        assert type(retention[flag]) is bool
    # Epoch-wide conservative fan-out history disclosure: any omission makes the incident incomplete.
    omitted = retention["fanoutHistoryOmitted"]
    assert type(omitted) is int and omitted >= 0
    assert type(document["fanoutHistoryComplete"]) is bool and document["fanoutHistoryComplete"] is (omitted == 0)
    assert document["fanoutHistoryComplete"] or not document["complete"]
    encoded = json.dumps(document)
    for secret in (SYNTHETIC_AUTH, SYNTHETIC_COOKIE, "synthetic-native-password", "synthetic-native-response"):
        assert secret not in encoded, "Synthetic secret must not be in exported incident"
    return {"events": len(events), "top5xx": len(document["top5xx"]), "topBytes": len(document["topBytes"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=["empty", "exact", "examples", "passthrough", "passthrough-cancel", "default", "basic", "custom", "disabled", "host", "concurrency", "approve", "deny", "expire", "stale", "paused", "queue", "quarantine", "rawpaths", "heavy", "circuit", "exempt", "intent", "alllisteners", "health", "fanout-block", "fanout-pause", "listeners", "incident"])
    parser.add_argument("--proxy-host", default="127.0.0.1", type=loopback)
    parser.add_argument("--proxy-port", default=8080, type=int)
    parser.add_argument("--port", default=18080, type=int)
    parser.add_argument("--second-port", default=18081, type=int)
    parser.add_argument("--expected-concurrent", default=5, type=int)
    parser.add_argument("--unselected-proxy-port", default=8081, type=int)
    parser.add_argument("--open-seconds", default=1.0, type=float, help="Must match human circuit open duration;1s in disposable test profile")
    parser.add_argument("--incident-file", help="Human-exported redacted incident JSON, checked offline only")
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--fixture-cert")
    parser.add_argument("--fixture-key")
    parser.add_argument("--burp-ca", help="Explicit PUBLIC CA PEM exported from disposable Burp; no global trust changes")
    args = parser.parse_args()
    if not __debug__:
        parser.error("Smoke assertions must be enabled; do not use Python -O/PYTHONOPTIMIZE")
    if args.phase == "incident":
        if not args.incident_file:
            parser.error("incident phase needs --incident-file; no fixture/client is started")
        with open(args.incident_file, "rb") as source:
            content = source.read(4 * 1024 * 1024 + 1)
        if len(content) > 4 * 1024 * 1024:
            parser.error("incident input exceeds bounded4MiB")
        print(json.dumps({"offline_incident_schema": "PASS", **validate_incident(json.loads(content))}))
        return
    if not 1 <= args.open_seconds <= 3600 or any(not 1 <= p <= 65535 for p in
            (args.proxy_port, args.unselected_proxy_port, args.port, args.second_port)):
        parser.error("Invalid bounded duration/port")
    if args.phase in ("listeners", "alllisteners") and args.unselected_proxy_port == args.proxy_port:
        parser.error("Listener proof requires two distinct ports")
    if args.https and not all((args.fixture_cert, args.fixture_key, args.burp_ca)):
        parser.error("HTTPS requires fixture certificate/key and explicitly exported disposable Burp public CA")
    if args.https:
        if args.phase in ("default", "host", "passthrough"):
            parser.error("Use --phase basic for strict localhost TLS; two-host pacing is an HTTP experiment")
        addresses = {item[4][0] for item in socket.getaddrinfo("localhost", None, type=socket.SOCK_STREAM)}
        if not addresses or not all(ipaddress.ip_address(a).is_loopback for a in addresses):
            parser.error("localhost must resolve exclusively to loopback addresses")
    state = State()
    with ExitStack() as stack:
        endpoints = (("127.0.0.1", args.port), ("127.0.0.2", args.second_port))
        if args.https:
            endpoints = tuple((host, args.port) for host in sorted(addresses))
        for host, port in endpoints:
            class Server(ThreadingHTTPServer):
                address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
            server = Server((host, port), fixture(state))
            stack.callback(server.server_close)
            if args.https:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(args.fixture_cert, args.fixture_key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
        run = Run(args, state)
        if args.phase in ("approve", "deny", "expire", "stale", "passthrough-cancel"):
            run.approval()
        elif args.phase == "host":
            run.rate()
        elif args.phase in ("fanout-block", "fanout-pause"):
            run.fanout()
        else:
            getattr(run, args.phase)()
        print(json.dumps({"protocol": "HTTPS" if args.https else "HTTP/1.1", "phase": args.phase,
                          "results": run.results, "fixture_arrivals": len(state.snapshot()),
                          "note": "Actual client/fixture observations only; proxy admission timing and complete wire equality are not inferred."}, indent=2))


if __name__ == "__main__":
    main()
