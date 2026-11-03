# Verification status — 2026-11-04

This is an independent **development preview**, not a certified safety boundary or a finished production release. Source, automated checks and installed-Burp observations are separate evidence. Results below distinguish the guided-UI build from the earlier JSON-oriented build.

## Current guided-UI artifact

`cairn-proxy-guard-0.1.0-SNAPSHOT.jar`, Java21 / Montoya API2026.7:

```text
a924d6c5aa08a10c3eceaf32f5e442cb5e423dc3499b3f4c2b5b9528e51eb2cc
```

The final copy-only guidance correction was included **before** the clean build, final JAR reload and the seven native phases below. Intermediate-candidate native runs are not counted as verification of this artifact.

## Confirmed automated results

- **771 JUnit cases / 22 suites**, zero failures/errors/skips, confirmed from the XML reports:

  ```sh
  ./gradlew --offline clean test jar --console=plain --no-daemon --max-workers=1
  ```

- Coverage includes unchanged policy/evidence/rate/approval/native adapter suites, owned-loopback forwarding, headless EDT/access/form/runtime integration and temporary-filesystem export regressions. Loopback and mocked Montoya tests are **not actual Burp**.
- Guided-UI regressions include independent saves/cancel/stale dialogs, preservation of existing scope/rule/settings semantics, strict advanced JSON, all seven numeric fields being editable, actual `AWAITING_APPROVAL`/`QUEUED` vocabulary and pending filtering through a real controller/queue, large-font form layout, non-scrolling guidance and selection/detail stability.
- **18 template verifier regressions + 12 offline smoke-harness self-checks** passed:

  ```sh
  python3 scripts/verify_templates.py
  python3 -m unittest discover -s scripts -p 'test_*.py'
  ```

  The current verifier explicitly reports local/fixture-only success and **SKIP actual-upstream**. These commands do not run CAIRN/Pi/model/report-file E2E or load Burp. Harness self-check output that says PASS is still offline test output, not native evidence.
- Dependency locks and strict SHA256 verification metadata remain enabled. [GitHub Actions](https://github.com/sehoon123/cairn-burp-guard/actions) is configured to run Java/JAR and Python checks; it does not run Burp or model E2E. Local success is not a claim that an unobserved remote workflow passed.

## Confirmed installed-Burp observations for this artifact

See [detailed native results](NATIVE_BURP_RESULTS.md) and [reproduction instructions](MANUAL_BURP_SMOKE.md).

- Normally available **Community Edition2026.10.1**, separate temporary home/config/data/preferences/in-memory project and authenticated nested display. No license/activation state or user project was copied or bypassed.
- Loaded a hash-verified copy of the final JAR through the product UI. Used only owned numeric-loopback HTTP fixtures and external Python clients, **not CAIRN Native Pi workers**.
- **12 logical HTTP/1.1 scenarios across7 phases passed**: empty allowlist; exact URL-form target with GET/HEAD, descendant/similar-path negatives, retained DELETE/decoded-query guards and synthetic allowed values; one-shot approval/denial/expiry; policy-change cancellation; fail-closed pause.
- Used guided forms without whole-policy JSON for target registration, nested AND approval conditions, keyboard numeric entry and seconds-based timeout changes. Reviewed separate traffic/approval windows in the actual product.
- Final evidence: **4 upstream200 + 9 local451 = 13 entries**. Actual UI full JSON had13 entries; selected HAR had1. Both were mode0600 and lacked the four synthetic authorization/cookie/password/response-cookie secret values. Masked request/response display was also observed.
- Test Burp exited through its UI; only this task's display/window manager and private temporary profile/exports/logs/screenshots were removed. No raw runtime artifacts are published.

This is a limited native regression, not a repeat of the entire previous54-case native matrix. HTTPS, multi-client pacing/concurrency, host overrides, queue saturation and late-response quarantine were **not rerun natively on this new hash**. Related automated backend tests passed, but are not substitutes for those native checks.

## Earlier-build evidence, not current-build native acceptance

The previous JAR SHA256 was:

```text
56d0d1e3e02b6430352cd493bff97f8900eb4d5268140f44bac980d90c952d1a
```

On that earlier UI build,584 Java tests and28 Python checks passed. An isolated Community2026.10.1 run passed **54 logical scenarios / 14 phases**, including certificate-verified HTTPS/HTTP1.1, six-client pacing/two-host overrides, held-response concurrency, queue timeout and late-response quarantine. Its102-entry evidence/export results and arrival timing measurements remain historical in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md). Do not add those54 to the current12 or present them as a current-artifact rerun.

The earlier template work also passed actual read-only upstream loader/renderer/parser/contracts, `DispatchConfig.load` and `validate_prompt_resources` at CAIRN commit `8e7e0ea67552383851dfcabfba0c4e9c8d007878` using:

```sh
uv run --no-project --with 'pydantic>=2,<3' --with PyYAML \
  python scripts/verify_templates.py --cairn-root /trusted/CAIRN --require-full-config
```

That was an upstream contract check with unchanged source/resource fingerprints, not a dispatcher/worker/report-file run. It was not repeated during this UI-only iteration. The current default fixture-only verifier must not be described as that upstream check.

## Explicitly not established

- Mandatory network/OS proxy enforcement, direct-socket prevention, opaque CONNECT/TLS pass-through, HTTP/2 native coverage or WebSocket-frame coverage.
- Other extensions' later modifications, complete wire provenance/equality, or strict remote server-arrival RPS.
- Professional/disk projects, native cross-project races, every worst-case capacity/shutdown path, or Burp-restart persistence.
- Full HiDPI/cross-platform/accessibility verification. The desired1100×760 native window could not be tested because of the product's minimum-window constraints in this environment. Headless large-font/form layout is a separate result.
- Live CAIRN dispatcher/Pi/model execution and report-file creation E2E. Prompt-only reporting/availability budgets are not a sandbox or a forced-termination completion guarantee.
- Authentication/session coordination, login/refresh or account/role management (excluded).
- KISA official code-by-code compliance, complete assessment coverage or absence of vulnerabilities.

Only reviewed source/docs, deliberately synthetic fixtures and intentional release artifacts are published. Build reports, original logs/screenshots, temporary Burp profiles/projects, generated certificates, private targets and credential material are not source artifacts.
