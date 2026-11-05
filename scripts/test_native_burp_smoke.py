"""Offline harness self-checks. These do NOT load Burp or count as native smoke."""
import json
import copy
import http.client
from http.server import ThreadingHTTPServer
from contextlib import contextmanager
import threading
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from native_burp_smoke import BODY, SYNTHETIC_AUTH, SYNTHETIC_COOKIE, LARGE_BYTES, PENTEST_PATHS, Run, State, fixture, loopback, validate_incident


class NativeSmokeHarnessTest(unittest.TestCase):
    def setUp(self):
        self.run_case = Run(None, State())
        self.payload = {"source": "cairn-proxy-guard", "outcome": "blocked", "retryable": False,
                        "evidenceId": "00000000-0000-4000-8000-000000000001", "reason": "RULE_BLOCK",
                        "guardState": "PROTECTED", "local": True, "policyRevision": 7}

    def response(self, status=451):
        return status, {}, json.dumps(self.payload).encode()

    def test_numeric_loopback_only(self):
        for host in ("127.0.0.1", "127.0.0.2", "::1"):
            self.assertEqual(host, loopback(host))
        for host in ("192.0.2.1", "10.0.0.1", "0.0.0.0", "::", "example.test", "localhost"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                loopback(host)

    def test_actual_local_denial_marker_required(self):
        self.assertEqual("RULE_BLOCK", self.run_case.blocked(self.response()))

    def test_generic_451_is_not_a_guard_result(self):
        with self.assertRaises((ValueError, KeyError)):
            self.run_case.blocked((451, {}, b"unrelated upstream response"))

    def test_wrong_status_is_not_a_guard_result(self):
        with self.assertRaises(AssertionError):
            self.run_case.blocked(self.response(200))

    def test_wrong_source_is_not_a_guard_result(self):
        self.payload["source"] = "upstream-fixture"
        with self.assertRaises(AssertionError):
            self.run_case.blocked(self.response())

    def test_retryable_denial_is_not_accepted(self):
        self.payload["retryable"] = True
        with self.assertRaises(AssertionError):
            self.run_case.blocked(self.response())

    def test_evidence_id_must_be_a_uuid(self):
        self.payload["evidenceId"] = "unavailable"
        with self.assertRaises(ValueError):
            self.run_case.blocked(self.response())

    def test_fixture_states_are_not_shared_between_runs(self):
        first, second = State(), State()
        first.events.append({"synthetic": True})
        self.assertFalse(second.snapshot())
        self.assertIsNot(first.lock, second.lock)

    def test_exact_phase_checks_narrow_scope_default_rules_and_preserved_values(self):
        owner = self
        class SyntheticRun(Run):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                owner.assertFalse(second)
                if path.partition("?")[0] != "/safe" or method == "DELETE":
                    reason = "RULE_BLOCK" if method == "DELETE" else "SCOPE_NOT_ALLOWED"
                    return 451, {}, json.dumps(dict(owner.payload, reason=reason)).encode()
                self.state.events.append({"method": method, "path": path, "body": body or b"", "host": "127.0.0.1"})
                response = b"" if method == "HEAD" else json.dumps({"authorization": SYNTHETIC_AUTH,
                    "cookie": SYNTHETIC_COOKIE, "body": BODY.decode()}).encode()
                return 200, {"X-Fixture": "owned-loopback"}, response
        run = SyntheticRun(None, State())
        run.exact()
        self.assertEqual(6, len(run.results))
        self.assertEqual(4, len(run.state.snapshot()))

    def test_typed_denial_requires_local_guard_state_revision_and_safe_overlay(self):
        for key, value in (("local", False), ("guardState", "uncontrolled text"), ("policyRevision", "7"), ("policyRevision", True), ("overlayId", "unsafe")):
            with self.subTest(key=key, value=value):
                payload = dict(self.payload, **{key: value})
                with self.assertRaises((AssertionError, ValueError)):
                    self.run_case.blocked((451, {}, json.dumps(payload).encode()))

    def test_exact_phase_rejects_a_broader_policy(self):
        class BroadRun(Run):
            def request(self, *args, **kwargs):
                self.state.events.append({"synthetic": True})
                return 200, {"X-Fixture": "owned-loopback"}, b""
        with self.assertRaises(AssertionError):
            BroadRun(None, State()).exact()

    def test_examples_phase_checks_named_query_post_path_and_json_recipes(self):
        owner = self
        class SyntheticRun(Run):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                owner.assertFalse(second)
                if path == "/api/items/1" or "operation=purge" in path:
                    reason = "SCOPE_NOT_ALLOWED" if path.endswith("/1") else "RULE_BLOCK"
                    return 451, {}, json.dumps(dict(owner.payload, reason=reason)).encode()
                self.state.events.append({"method": method, "path": path})
                return 200, {"X-Fixture": "owned-loopback"}, json.dumps({"body": (body or b"").decode()}).encode()
        class DeferredPool:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, function, *args):
                class Pending:
                    def result(self, timeout=None): return function(*args)
                return Pending()
        run = SyntheticRun(None, State())
        with patch("native_burp_smoke.ThreadPoolExecutor", DeferredPool), patch("native_burp_smoke.time.sleep"):
            run.examples()
        self.assertEqual(5, len(run.results))
        self.assertEqual(["GET", "POST", "POST"], [e["method"] for e in run.state.snapshot()])

    def test_example_approval_rejects_any_arrival_before_the_human_decision(self):
        run = Run(None, State())
        def premature(*args):
            run.state.events.append({"synthetic": True})
            return 200, {"X-Fixture": "owned-loopback"}, b"{}"
        run.request = premature
        class ImmediatePool:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, function, *args): function(*args); return None
        with patch("native_burp_smoke.ThreadPoolExecutor", ImmediatePool), patch("native_burp_smoke.time.sleep"):
            with self.assertRaisesRegex(AssertionError, "Unresolved example approval"):
                run._example_approval("/safe", b"{}", "synthetic offline case")

    def test_passthrough_phase_checks_scope_rules_inspection_preservation_and_burst(self):
        class SyntheticRun(Run):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                with self.state.lock:
                    self.state.events.append({"synthetic": True})
                    if path.startswith("/hold"):
                        self.state.peak = 6
                headers = headers or {}
                response = {"method": method, "path": path, "body": (body or b"").decode(),
                            "authorization": headers.get("Authorization"), "cookie": headers.get("Cookie")}
                return 200, {"X-Fixture": "owned-loopback"}, json.dumps(response).encode()
        run = SyntheticRun(SimpleNamespace(https=False), State())
        run.passthrough()
        self.assertEqual(8, len(run.results))
        self.assertEqual(13, len(run.state.snapshot()))

    def test_passthrough_phase_rejects_a_still_enabled_guard(self):
        class StillProtected(Run):
            def request(self, *args, **kwargs):
                return 451, {}, b"{}"
        with self.assertRaises(AssertionError):
            StillProtected(SimpleNamespace(https=False), State()).passthrough()

    def test_all_listener_scope_requires_both_inbound_ports_to_enforce_delete(self):
        owner = self
        class SyntheticRun(Run):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False, proxy_port=None):
                owner.assertIn(proxy_port, (54321, 54322))
                if method == "DELETE":
                    return owner.response()
                self.state.events.append({"path": path, "method": method, "body": body or b"", "host": "127.0.0.1"})
                return 200, {"X-Fixture": "owned-loopback"}, b"{}"
        args = SimpleNamespace(proxy_port=54321, unselected_proxy_port=54322, https=False)
        run = SyntheticRun(args, State())
        run.alllisteners()
        self.assertEqual(4, len(run.results)); self.assertEqual(2, len(run.state.snapshot()))
        class UnprotectedSecond(SyntheticRun):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False, proxy_port=None):
                if proxy_port == 54322:
                    return 200, {"X-Fixture": "owned-loopback"}, b"{}"
                return super().request(path, method, body, headers, second, proxy_port)
        with self.assertRaises(AssertionError):
            UnprotectedSecond(args, State()).alllisteners()

    def test_all_listener_phase_refuses_identical_ports_before_starting_fixtures(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("native_burp_smoke.py")),
                                 "--phase", "alllisteners", "--proxy-port", "54321", "--unselected-proxy-port", "54321"],
                                capture_output=True, text=True)
        self.assertEqual(2, result.returncode); self.assertIn("two distinct ports", result.stderr)

    def test_health_only_allows_exact_empty_get_and_checks_head_without_parsing_a_body(self):
        owner = self
        class SyntheticRun(Run):
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                if method == "GET" and path == "/health" and not body:
                    self.state.events.append({"path": path, "method": method, "body": b"", "host": "127.0.0.1"})
                    return 200, {"X-Fixture": "owned-loopback"}, b"{}"
                if method == "HEAD": return 451, {"X-Cairn-Guard": "blocked"}, b""
                return 451, {}, json.dumps(dict(owner.payload, reason="PAUSED", guardState="PAUSED_BY_OPERATOR")).encode()
        run = SyntheticRun(SimpleNamespace(https=False), State()); run.health()
        self.assertEqual(6, len(run.results)); self.assertEqual(1, len(run.state.snapshot()))
        class Overbroad(SyntheticRun):
            def request(self, *args, **kwargs): return 200, {"X-Fixture": "owned-loopback"}, b"{}"
        with self.assertRaises(AssertionError): Overbroad(SimpleNamespace(https=False), State()).health()

    def test_fanout_phases_check_query_dedup_final_admission_service_scope_and_explicit_release(self):
        for phase in ("fanout-block", "fanout-pause"):
            run = Run(SimpleNamespace(phase=phase), State())
            run.assert_arrives = Mock(); run.assert_block = Mock()
            with patch("builtins.input", return_value="") as human:
                run.fanout()
            self.assertEqual(7, len(run.results)); human.assert_called_once()
            self.assertEqual("/fanout/one?value=1", run.assert_arrives.call_args_list[0].kwargs["path"])
            self.assertEqual("/fanout/one?value=2", run.assert_arrives.call_args_list[1].kwargs["path"])
            self.assertEqual({"expected_reason": "FANOUT_SUSPECTED", "path": "/fanout/three"}, run.assert_block.call_args_list[0].kwargs)
            if phase == "fanout-block": run.assert_arrives.assert_any_call(second=True)
            else: run.assert_block.assert_any_call(expected_reason="FANOUT_SUSPECTED", second=True)
            self.assertEqual({"path": "/fanout/one"}, run.assert_arrives.call_args.kwargs)

    def test_passthrough_tls_cannot_be_mislabeled_as_two_host_http(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("native_burp_smoke.py")),
                                 "--phase", "passthrough", "--https", "--fixture-cert", "unused", "--fixture-key", "unused",
                                 "--burp-ca", "unused"], capture_output=True, text=True)
        self.assertEqual(2, result.returncode)
        self.assertIn("two-host pacing is an HTTP experiment", result.stderr)

    def test_optimized_python_is_refused_before_any_fixture_or_client_starts(self):
        result = subprocess.run([sys.executable, "-O", str(Path(__file__).with_name("native_burp_smoke.py")),
                                 "--phase", "empty"], capture_output=True, text=True)
        self.assertEqual(2, result.returncode)
        self.assertIn("assertions must be enabled", result.stderr)

    def test_tls_two_host_measurement_cannot_be_mislabeled(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("native_burp_smoke.py")),
                                 "--phase", "host", "--https", "--fixture-cert", "unused", "--fixture-key", "unused",
                                 "--burp-ca", "unused"], capture_output=True, text=True)
        self.assertEqual(2, result.returncode)
        self.assertIn("two-host pacing is an HTTP experiment", result.stderr)


@contextmanager
def owned_fixture():
    state = State()
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


class V2OwnedFixtureTest(unittest.TestCase):
    """DIRECT owned socket tests only. No installed Burp, proxy or native claims."""
    def exchange(self, port, target="/safe", body=b"", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("POST", target, body, headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_raw_target_matrix_nested_percent_separator_and_invalid_percent_are_not_normalized(self):
        with owned_fixture() as (port, state):
            for path in PENTEST_PATHS:
                with self.subTest(path=path):
                    body = b"\x00\xffsynthetic"
                    result = self.exchange(port, path, body, {"Host": "synthetic.invalid", "Content-Type": "application/octet-stream"})
                    self.assertEqual(200, result[0])
                    observed = state.snapshot()[-1]
                    self.assertEqual(path, observed["request_target"])
                    self.assertEqual("synthetic.invalid", observed["host_header"])
                    self.assertEqual(body, observed["body"])
                    self.assertEqual(body.hex(), json.loads(result[2])["body_hex"])

    def test_sixMiB_and_five5xx_are_real_owned_fixture_responses(self):
        with owned_fixture() as (port, state):
            response = self.exchange(port, "/large")
            self.assertEqual(200, response[0]); self.assertEqual(LARGE_BYTES, len(response[2]))
            self.assertEqual(b"L" * LARGE_BYTES, response[2])
            for _ in range(5):
                self.assertEqual(503, self.exchange(port, "/status5xx")[0])
            self.assertEqual(6, len(state.snapshot()))

    def test_optional_capture_overflow_fixture_preserves_original_bytes(self):
        with owned_fixture() as (port, state):
            body = b"C" * (1024 * 1024 + 1)
            result = self.exchange(port, "/safe?malformed=%ZZ", body, {"Content-Type": "text/plain; charset=unsupported-fixture"})
            self.assertEqual(200, result[0]); self.assertEqual(body, state.snapshot()[0]["body"])
            self.assertEqual(body.hex(), json.loads(result[2])["body_hex"])

    def test_assert_arrives_detects_native_target_host_body_or_destination_change(self):
        for field, changed in (("path", "/normalized"), ("host_header", "changed.invalid"), ("body", b"changed"), ("host", "127.0.0.2")):
            class Changed(Run):
                def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                    event = {"path": path, "method": method, "body": body or b"", "host_header": headers["Host"], "host": "127.0.0.1"}
                    event[field] = changed
                    self.state.events.append(event)
                    return 200, {"X-Fixture": "owned-loopback"}, b"{}"
            with self.subTest(field=field), self.assertRaises(AssertionError):
                Changed(SimpleNamespace(https=False), State()).assert_arrives(path="/c/%2e/main.do", body=b"original", headers={"Host": "synthetic.invalid"})

    def test_exact_twenty_first_phase_and_other_intent_and_same_run(self):
        owner = self
        class Budget(Run):
            def __init__(self):
                super().__init__(SimpleNamespace(https=False), State()); self.counts = {}; self.runs = set()
            def request(self, path="/safe", method="GET", body=None, headers=None, second=False):
                intent = headers["X-Cairn-Intent"]; self.runs.add(headers["X-Cairn-Run"])
                self.counts[intent] = self.counts.get(intent, 0) + 1
                if self.counts[intent] > 20:
                    return 451, {}, json.dumps({"source": "cairn-proxy-guard", "outcome": "blocked", "retryable": False,
                        "evidenceId": "00000000-0000-4000-8000-000000000001", "reason": "INTENT_BUDGET_EXCEEDED",
                        "local": True, "guardState": "INTENT_BUDGET", "policyRevision": 7}).encode()
                self.state.events.append({"method": method, "path": path, "body": body or b"", "host": "127.0.0.1"})
                return 200, {"X-Fixture": "owned-loopback"}, b"{}"
        run = Budget(); run.intent()
        self.assertEqual({"i048": 21, "other": 1}, run.counts); self.assertEqual(1, len(run.runs)); self.assertEqual(21, len(run.state.snapshot()))


class IncidentSchemaTest(unittest.TestCase):
    def setUp(self):
        self.document = {"window": {"from": 1000, "to": 2000},
            "events": [{"kind": "HEAVY_ENDPOINT_AUTO_BLOCKED", "path": "/large", "bytes": LARGE_BYTES, "ts": 1500}],
            "top5xx": [], "topBytes": [{"id": "ab" * 32, "host": "127.0.0.1", "path": "/large",
                "policyUrl": "http://127.0.0.1/large", "maxBytes": LARGE_BYTES, "p95Bytes": 8388608, "count": 1, "lastSeen": 1500, "count5xx": 0}],
            "complete": True, "truncated": False, "fanoutHistoryComplete": True, "approximate": True,
            "approximation": {"p95Bytes": "log2_histogram_upper_bound", "countMaxBytesLastSeen5xx": "exact_retained_window"},
            "retention": {"mode": "UNTIL_CLEAR_PROJECT_OR_UNLOAD", "startedAt": 1000, "eventsComplete": True, "observationsComplete": True,
                "eventsDropped": False, "observationsDropped": False, "clockRegressed": False, "fanoutHistoryOmitted": 0}}

    def test_valid_unlimited_retention_schema(self):
        self.assertEqual({"events": 1, "top5xx": 0, "topBytes": 1}, validate_incident(self.document))

    def test_no_event_count_window_length_or_string_length_limit_and_plaintext_values_are_accepted(self):
        item = copy.deepcopy(self.document)
        item["window"] = {"from": 0, "to": 90 * 86_400_000}
        item["events"] = [{"kind": "CIRCUIT_OPEN", "ts": 1500 + i, "path": "/p" + "x" * 20_000 + SYNTHETIC_AUTH} for i in range(5000)]
        item["topBytes"][0]["host"] = "h" * 300
        item["topBytes"][0]["policyUrl"] = "http://127.0.0.1/" + SYNTHETIC_COOKIE
        self.assertEqual({"events": 5000, "top5xx": 0, "topBytes": 1}, validate_incident(item))
        legacy_max = copy.deepcopy(self.document); legacy_max["retention"]["maxMillis"] = 86400000
        with self.assertRaises(AssertionError):
            validate_incident(legacy_max)

    def test_fanout_history_omission_is_sticky_incomplete_and_consistent(self):
        item = copy.deepcopy(self.document)
        item.update({"complete": False, "truncated": True, "fanoutHistoryComplete": False})
        item["retention"]["fanoutHistoryOmitted"] = 3
        self.assertEqual({"events": 1, "top5xx": 0, "topBytes": 1}, validate_incident(item))
        for complete, history, omitted in ((True, False, 3), (False, True, 3), (False, False, 0), (False, False, -1), (False, False, True)):
            bad = copy.deepcopy(item)
            bad.update({"complete": complete, "truncated": not complete, "fanoutHistoryComplete": history})
            bad["retention"]["fanoutHistoryOmitted"] = omitted
            with self.subTest(complete=complete, history=history, omitted=omitted), self.assertRaises(AssertionError):
                validate_incident(bad)
        bad = copy.deepcopy(self.document); del bad["fanoutHistoryComplete"]
        with self.assertRaises(KeyError):
            validate_incident(bad)

    def test_keyed_candidate_ids_work_in_both_top_lists_without_uuid_conflation(self):
        item = copy.deepcopy(self.document)
        item["top5xx"] = copy.deepcopy(item["topBytes"])
        item["top5xx"][0]["count5xx"] = 1
        self.assertEqual({"events": 1, "top5xx": 1, "topBytes": 1}, validate_incident(item))

    def test_candidate_identifier_shape_is_bounded_lowercase_hmac_not_an_overlay_uuid(self):
        for identifier in ("a" * 63, "g" * 64, "A" * 64, "00000000-0000-4000-8000-000000000001", None, True):
            item = copy.deepcopy(self.document)
            item["topBytes"][0]["id"] = identifier
            with self.subTest(identifier=identifier), self.assertRaises(AssertionError):
                validate_incident(item)

    def test_invalid_window_event_timestamp_flags_kind_or_raw_secret_are_rejected(self):
        invalid = []
        for key, value in (("to", 1000), ("from", True)):
            item = copy.deepcopy(self.document); item["window"][key] = value; invalid.append(item)
        for key, value in (("kind", "arbitrary"), ("ts", 2000), ("bytes", -1), ("bytes", True), ("path", 7)):
            item = copy.deepcopy(self.document); item["events"][0][key] = value; invalid.append(item)
        item = copy.deepcopy(self.document); item["truncated"] = True; invalid.append(item)
        item = copy.deepcopy(self.document); item["topBytes"][0]["id"] = "unsafe"; invalid.append(item)
        item = copy.deepcopy(self.document); item["retention"]["eventsDropped"] = "false"; invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises((AssertionError, ValueError)):
                validate_incident(item)


class HumanIncidentSchemaTest(unittest.TestCase):
    def setUp(self):
        self.document = {"format": "cairn-human-incident", "formatVersion": 1,
            "_cairnGuard": {"exportMode": "HUMAN_ORIGINAL", "warning": "PLAINTEXT_ORIGINALS: may contain Authorization, Cookie, tokens",
                "completeWireCapture": False, "forwardedMeans": "NATIVE_RELEASE_NOT_PROVEN_DELIVERY", "timingsKnown": False,
                "retention": "MEMORY_ONLY_NO_COLLECTION_QUOTA_UNTIL_CLEAR_PROJECT_OR_UNLOAD", "snapshot": {"projectId": "p", "revision": 7}},
            "window": {"from": 1000, "to": 2000},
            "events": [{"kind": "HEAVY_ENDPOINT_AUTO_BLOCKED", "bytes": LARGE_BYTES, "ts": 1500,
                        "service": {"scheme": "http", "host": "127.0.0.1", "port": 18080}, "host": "127.0.0.1",
                        "path": "/download/" + SYNTHETIC_AUTH},
                       {"kind": "CIRCUIT_OPEN", "5xx": 1, "ts": 1600, "host": None, "path": None,
                        "originalUnavailable": "NOT_RETAINED_OR_CLEARED"}],
            "top5xx": [], "topBytes": [{"id": "ab" * 32, "maxBytes": LARGE_BYTES, "p95Bytes": 8388608, "count": 1, "lastSeen": 1500,
                "count5xx": 0, "service": {"scheme": "http", "host": "127.0.0.1", "port": 18080}, "host": "127.0.0.1",
                "path": "/download/" + SYNTHETIC_AUTH}],
            "complete": True, "truncated": False, "fanoutHistoryComplete": True, "approximate": True,
            "approximation": {"p95Bytes": "log2_histogram_upper_bound", "countMaxBytesLastSeen5xx": "exact_retained_window"},
            "retention": {"mode": "UNTIL_CLEAR_PROJECT_OR_UNLOAD", "startedAt": 1000, "eventsComplete": True, "observationsComplete": True,
                "eventsDropped": False, "observationsDropped": False, "clockRegressed": False, "fanoutHistoryOmitted": 0}}

    def test_consented_plaintext_human_incident_with_originals_and_categorical_absence(self):
        self.assertEqual({"events": 2, "top5xx": 0, "topBytes": 1, "format": "cairn-human-incident", "originalsUnavailable": 1},
                         validate_incident(self.document))

    def test_human_provenance_absence_masking_and_opaque_references_are_rejected(self):
        mutations = [
            lambda d: d.update({"format": "unknown"}),
            lambda d: d.update({"formatVersion": 2}),
            lambda d: d["_cairnGuard"].update({"exportMode": "REDACTED"}),
            lambda d: d["_cairnGuard"].update({"warning": "nothing"}),
            lambda d: d["_cairnGuard"].update({"completeWireCapture": True}),
            lambda d: d["events"][0].update({"_source": "opaque-ref"}),
            lambda d: d["events"][1].update({"host": "guessed.test"}),
            lambda d: d["events"][0].pop("service"),
            lambda d: d["events"][0]["service"].update({"host": "other.test"}),
            lambda d: d["topBytes"][0].update({"policyUrl": "http://127.0.0.1/x"}),
            lambda d: d["topBytes"][0].pop("host"),
        ]
        for index, mutate in enumerate(mutations):
            item = copy.deepcopy(self.document); mutate(item)
            with self.subTest(index=index), self.assertRaises((AssertionError, KeyError)):
                validate_incident(item)

    def test_literal_original_values_containing_private_markers_are_preserved_not_refused(self):
        # Original route/value text is operator data: literal "_source", "[REDACTED]" and JSON-looking strings are valid.
        for literal in ("/_source", "/[REDACTED]", "/a/_source/[REDACTED]?q=_source", '/{"_source":"x"}', "/x?_source=[REDACTED]"):
            for row in ("event", "top"):
                item = copy.deepcopy(self.document)
                target = item["events"][0] if row == "event" else item["topBytes"][0]
                target["path"] = literal
                with self.subTest(literal=literal, row=row):
                    self.assertEqual("cairn-human-incident", validate_incident(item)["format"])

    def test_actual_private_source_object_keys_are_rejected_structurally_at_any_depth(self):
        # True-negative controls: each location is otherwise shape-valid (unknown extra keys are tolerated elsewhere).
        mutations = [
            lambda d: d.update({"_source": "x"}),
            lambda d: d["_cairnGuard"]["snapshot"].update({"_source": "x"}),
            lambda d: d["approximation"].update({"_source": "x"}),
            lambda d: d["events"][0].update({"extra": {"deep": {"_source": "x"}}}),
            lambda d: d["events"][0].update({"extra": [{"_source": "x"}]}),
            lambda d: d["events"][0]["service"].update({"_source": "x"}),
            lambda d: d["topBytes"][0].update({"extra": [[{"_source": "x"}]]}),
        ]
        for index, mutate in enumerate(mutations):
            item = copy.deepcopy(self.document)
            self.assertEqual("cairn-human-incident", validate_incident(copy.deepcopy(item))["format"])  # baseline without the key passes
            mutate(item)
            with self.subTest(index=index), self.assertRaises(AssertionError):
                validate_incident(item)

    def test_formats_are_never_mixed_safe_document_cannot_claim_human_provenance(self):
        safe = IncidentSchemaTest(); safe.setUp()
        item = copy.deepcopy(safe.document); item["_cairnGuard"] = self.document["_cairnGuard"]
        with self.assertRaises(AssertionError):
            validate_incident(item)
        item = copy.deepcopy(safe.document); item["events"][0]["path"] = "/x/" + SYNTHETIC_AUTH
        self.assertEqual(1, validate_incident(item)["events"], "plaintext originals are valid in the legacy shape too")
        item = copy.deepcopy(safe.document); item["events"][0]["_source"] = "opaque"
        with self.assertRaises(AssertionError):
            validate_incident(item)


if __name__ == "__main__":
    unittest.main()
