# Verification status — 2026-11-03

This is an independent **development preview**, not a certified safety boundary or a finished production release. Source, automated tests and installed-Burp observations are separate evidence.

## Confirmed automated results

- Java21 / Montoya API2026.7: **584 JUnit cases passed**, zero failures/errors/skips. Command: `./gradlew --no-daemon --offline clean test jar` (and full `test jar` after correcting the expected preserved pause category).
- Coverage includes policy/evidence/rate/approval, headless Swing/filesystem checks, mocked Montoya adapter/lifecycle and owned-loopback forwarding. The latter is **not actual Burp**. See [CONTROLLER_TESTS.md](CONTROLLER_TESTS.md) and [BURP_ADAPTER.md](BURP_ADAPTER.md).
- **18 template verifier regressions** and **10 offline smoke-harness self-checks** passed. The harness self-checks do not load Burp. No failing check was skipped to obtain these counts.
- Both external CAIRN prompt profiles passed the actual read-only upstream loader/renderer/parser/contracts plus **actual `DispatchConfig.load` and `validate_prompt_resources`** at commit `8e7e0ea67552383851dfcabfba0c4e9c8d007878`:

  ```sh
  uv run --no-project --with 'pydantic>=2,<3' --with PyYAML \
    python scripts/verify_templates.py --cairn-root /trusted/CAIRN --require-full-config
  ```

  Source/resource fingerprints remained unchanged and bytecode writes were disabled. An expired tool-managed checkout was replaced with a fresh independent checkout at that same commit before the final successful run. No dispatcher, worker/model or report-file E2E run is implied.
- Dependency locks and strict SHA256 verification metadata are checked in. Initial cold-cache CI exposed missing BOM/parent checksums; reviewed metadata was added instead of turning verification off. [GitHub Actions](https://github.com/sehoon123/cairn-burp-guard/actions) runs Java tests/JAR, the18 template regressions and10 offline harness checks. It does **not** run Burp or the upstream/model E2E.

## Confirmed installed-Burp experiments

[Detailed native results](NATIVE_BURP_RESULTS.md) and [reproduction instructions](MANUAL_BURP_SMOKE.md).

- Installed Burp **Community Edition2026.10.1**, product-provided edition selection, separate temporary profile/in-memory project, owned loopback fixtures only. No activation/licensing state was copied or bypassed.
- Final JAR `cairn-proxy-guard-0.1.0-SNAPSHOT.jar`, SHA256:

  ```text
  56d0d1e3e02b6430352cd493bff97f8900eb4d5268140f44bac980d90c952d1a
  ```

- **54 native logical scenarios across14 phases passed**, covering HTTP and certificate-verified HTTPS/HTTP1.1; scope/rule/inspection blocks with zero fixture hits; six-client global5RPS/two-host pacing; true held-response concurrency; approvals/denial/expiry/policy cancellation; queue timeout, late-response quarantine and pause.
- Final evidence had **57 upstream200 /45 local451**, no pending entries. Actual GUI search/bookmark/filter JSON and selected HAR each exported one marked fixture row; full JSON/HAR each had102 entries. Synthetic authorization/cookie/password/response-cookie strings were absent and all four exports had mode0600.
- Real UI testing found a collapsed Traffic pane and generic runtime denial labels; fixes were included before reloading/retesting the final-hash JAR. All53 native categorical reasons also have snapshot/JSON/HAR unit regressions; that does **not** mean every corresponding native error path was induced.
- Six clients are external Python fixture clients, **not live CAIRN Native Pi workers**. Arrival timings, tested versions, setup failures and remaining native gaps are explicitly recorded in the detailed results.

## Explicitly not established

- Mandatory network/OS proxy enforcement, direct-socket prevention, TLS pass-through, HTTP/2 native coverage or WebSocket-frame coverage.
- Arbitrary other extensions' later modifications, complete wire provenance/equality, or strict remote server-arrival RPS.
- Licensed Professional/disk-project verification, native cross-project races, every worst-case capacity/shutdown path, or Burp-restart persistence. Idle reload within the same temporary project was observed.
- Live CAIRN dispatcher/Pi/model execution and report-file creation E2E; prompt-only reporting/availability budgets are not a sandbox or a forced-termination completion guarantee.
- Authentication/session coordination, login/refresh or account/role management (excluded).
- KISA official code-by-code compliance, complete assessment coverage or absence of vulnerabilities.

Build reports, raw native logs, screenshots, temporary Burp projects/profiles, generated certificates and runtime credential material are not source artifacts and are not committed. Only sanitized result descriptions and deliberately synthetic source fixtures are published.
