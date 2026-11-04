"""Offline harness self-checks. These do NOT load Burp or count as native smoke."""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_burp_smoke import BODY, SYNTHETIC_AUTH, SYNTHETIC_COOKIE, Run, State, loopback


class NativeSmokeHarnessTest(unittest.TestCase):
    def setUp(self):
        self.run_case = Run(None, State())
        self.payload = {"source": "cairn-proxy-guard", "outcome": "blocked", "retryable": False,
                        "evidenceId": "00000000-0000-4000-8000-000000000001", "reason": "RULE_BLOCK"}

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
                if path != "/safe" or method == "DELETE":
                    reason = "RULE_BLOCK" if method == "DELETE" or path.startswith("/safe?") else "SCOPE_NOT_ALLOWED"
                    return 451, {}, json.dumps(dict(owner.payload, reason=reason)).encode()
                self.state.events.append({"method": method})
                response = b"" if method == "HEAD" else json.dumps({"authorization": SYNTHETIC_AUTH,
                    "cookie": SYNTHETIC_COOKIE, "body": BODY.decode()}).encode()
                return 200, {"X-Fixture": "owned-loopback"}, response
        run = SyntheticRun(None, State())
        run.exact()
        self.assertEqual(6, len(run.results))
        self.assertEqual(3, len(run.state.snapshot()))

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


if __name__ == "__main__":
    unittest.main()
