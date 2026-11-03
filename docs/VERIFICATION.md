# Verification status

This is an independent development candidate, not a certified safety boundary or a finished release.

## Confirmed automated results

- Java 21 / Montoya API 2026.7 build: `./gradlew --no-daemon --offline clean test jar` followed by a corrected repeat of `test jar`.
- **528 JUnit cases passed**, zero failures/errors/skips in the full repeat. A Mockito exception-restubbing fixture was corrected; no failing test was skipped.
- These include pure policy/evidence/rate/approval tests, headless Swing tests, mocked Montoya adapter/lifecycle tests, and owned-loopback forwarding tests.
- The owned-loopback harness is **not actual Burp**. A native adapter fake is **not a native API smoke**. Read [CONTROLLER_TESTS.md](CONTROLLER_TESTS.md) and [BURP_ADAPTER.md](BURP_ADAPTER.md) for boundaries.
- CAIRN external prompt groups have been checked against the read-only upstream loader/contracts at commit `8e7e0ea67552383851dfcabfba0c4e9c8d007878`. A separate `uv run --no-project --with 'pydantic>=2,<3' --with PyYAML python scripts/verify_templates.py --cairn-root /trusted/CAIRN --require-full-config` passed **both profiles**, all 18 verifier regressions, and actual `DispatchConfig.load`. Source/resource fingerprints remained unchanged. No dispatcher, worker/model or report-file E2E run is implied.

## Actual Burp experiments

**Pending in this development snapshot.** The user authorized testing the installed Burp using a separate temporary profile/project and exclusively owned loopback fixtures. Licensing/activation is never bypassed or copied. No actual native check may be inferred from the JUnit count. Native results will be appended only after observing them.

## Explicitly not established

- Mandatory network/OS proxy enforcement, direct-socket prevention, TLS pass-through or WebSocket-frame coverage.
- Arbitrary other extensions' later modifications, exact wire provenance, or strict remote server-arrival RPS.
- Authentication/session coordination, automatic login/refresh, or account/role management (excluded).
- KISA official code-by-code compliance, complete coverage of every web assessment item, or absence of vulnerabilities.
- Prompt-only reporting/availability budgets as a sandbox or guaranteed report creation after forced termination.

Build reports, raw native logs, screenshots, temporary Burp projects/profiles, generated certificates and synthetic runtime credential material are not source artifacts and must not be committed.
