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
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

SYNTHETIC_AUTH = "Bearer synthetic-native-fixture-not-a-real-token"
SYNTHETIC_COOKIE = "fixture_session=synthetic-native-cookie"
BODY = b'{"note":"harmless fixture","password":"synthetic-native-password"}'


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
            if not 0 <= length <= 65536:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            event = {"at": time.monotonic(), "host": self.server.server_address[0],
                     "method": self.command, "path": self.path,
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
                query = parse_qs(urlsplit(self.path).query)
                if urlsplit(self.path).path == "/hold":
                    time.sleep(min(3.0, max(0, float(query.get("seconds", ["1.5"])[0]))))
                response = json.dumps({"fixture": "owned-loopback", "method": self.command,
                                       "path": self.path, "body": body.decode("utf-8"),
                                       "authorization": event["authorization"],
                                       "cookie": event["cookie"]}, separators=(",", ":")).encode()
                self.send_response(200)
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

    def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
        host, port = ("127.0.0.2", self.args.second_port) if second else ("127.0.0.1", self.args.port)
        if self.args.https:
            assert not second, "Two-host pacing is a separate HTTP experiment"
            host = "localhost"  # Real DNS identity: Burp's numeric-IP certificates may have DNS-only SANs.
        # Hardcoded loopback targets only. CLI cannot redirect traffic externally.
        headers = dict(headers or {})
        headers.setdefault("Connection", "close")
        connection = http.client.HTTPConnection(loopback(self.args.proxy_host), self.args.proxy_port, timeout=40)
        try:
            if self.args.https:
                # A human must explicitly export the disposable instance's PUBLIC CA.
                connection = http.client.HTTPSConnection(
                    loopback(self.args.proxy_host), self.args.proxy_port, timeout=40,
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

    def empty(self):
        self.case("empty allowlist: local 451 and zero fixture hits",
                  lambda: self.assert_block(expected_reason="SCOPE_NOT_ALLOWED"))

    def exact(self):
        """Human URL form has allowed ONLY /safe, with the two default rules retained."""
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
        self.case("exact target retains decoded-query rule", lambda: self.assert_block(expected_reason="RULE_BLOCK", path="/safe?operation=%2564elete"))
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
        for name, kwargs in [
            ("DELETE method", {"method": "DELETE"}),
            ("mixed-case path", {"path": "/DeLeTe"}),
            ("percent-encoded path", {"path": "/%64%65lete"}),
            ("double-encoded query", {"path": "/safe?operation=%2564elete"}),
            ("header substring", {"headers": {"X-Fixture-Operation": "DeLeTe"}}),
            ("form value", {"method": "POST", "body": b"operation=%64elete", "headers": {"Content-Type": "application/x-www-form-urlencoded"}}),
            ("JSON unicode escape", {"method": "POST", "body": b'{"operation":"\\u0064elete"}', "headers": {"Content-Type": "application/json"}}),
            ("unsupported encoding", {"method": "POST", "body": b"fixture", "headers": {"Content-Type": "text/plain", "Content-Encoding": "gzip"}}),
            ("unsupported body", {"method": "POST", "body": b"fixture", "headers": {"Content-Type": "application/octet-stream"}}),
        ]:
            reason = {"unsupported encoding": "UNSUPPORTED_CONTENT_ENCODING", "unsupported body": "UNSUPPORTED_BODY"}.get(name, "RULE_BLOCK")
            self.case(name + ": local 451 and zero fixture hits",
                      lambda k=kwargs, r=reason: self.assert_block(expected_reason=r, **k))
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
        self.case("ALLOW/MONITOR cannot override unsupported inspection", lambda: self.assert_block(expected_reason="UNSUPPORTED_BODY", method="POST", body=b"fixture", headers={"Content-Type": "application/octet-stream"}))

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=["empty", "exact", "examples", "passthrough", "passthrough-cancel", "default", "basic", "custom", "disabled", "host", "concurrency", "approve", "deny", "expire", "stale", "paused", "queue", "quarantine"])
    parser.add_argument("--proxy-host", default="127.0.0.1", type=loopback)
    parser.add_argument("--proxy-port", default=8080, type=int)
    parser.add_argument("--port", default=18080, type=int)
    parser.add_argument("--second-port", default=18081, type=int)
    parser.add_argument("--expected-concurrent", default=5, type=int)
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--fixture-cert")
    parser.add_argument("--fixture-key")
    parser.add_argument("--burp-ca", help="Explicit PUBLIC CA PEM exported from disposable Burp; no global trust changes")
    args = parser.parse_args()
    if not __debug__:
        parser.error("Smoke assertions must be enabled; do not use Python -O/PYTHONOPTIMIZE")
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
        else:
            getattr(run, args.phase)()
        print(json.dumps({"protocol": "HTTPS" if args.https else "HTTP/1.1", "phase": args.phase,
                          "results": run.results, "fixture_arrivals": len(state.snapshot()),
                          "note": "Actual client/fixture observations only; proxy admission timing and complete wire equality are not inferred."}, indent=2))


if __name__ == "__main__":
    main()
