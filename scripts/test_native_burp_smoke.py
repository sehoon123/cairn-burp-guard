"""Offline harness self-checks. These do NOT load Burp or count as native smoke."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

from native_burp_smoke import Run, State, loopback


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
