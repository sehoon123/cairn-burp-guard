# Verification status — 2026-11-04

This is an independent **development preview**, not a certified safety boundary or a finished production release. Source, automated checks and installed-Burp observations are separate evidence. Results distinguish this development preview from the previous published examples/shortcuts artifact and two older artifacts; do not combine their native totals.

## Current modal/passthrough/condition-add development preview

Release tag: `dev-2026-11-04-conditions-passthrough`. The user explicitly requested publishing this limited bug-fix preview; expanded-feature design sign-off remains separate and incomplete. Automated results: **845 Java cases / 25 suites**, **20 real Swing desktop cases / 2 suites** (14/28-point fonts, explicit X11 display; also rerun with UI scale2), **35 Python checks** (18 template +17 offline harness). Real Enter/Escape/Tab/Space and mouse events were exercised only in the disposable Swing harness, **not native Burp**. Inherited Wayland/session-bus/nonreparenting environment is excluded from this harness; no global desktop settings change.

Preview JAR SHA256: `4232ae63d0a158d294fbe9ee3cf40cf58b9e8bdc85a300c8f829a5135b4bd159`.

Desktop condition regressions use real mouse actions for root/sibling/AND/OR additions and explicit save, assert actual focus on the new value, reopen/compare the form, and verify row bounds after one native resize without a second user edit. Field values themselves are set programmatically. The final toolkit runs used an authenticated nested1440×1000 X11 display, at UI scales1 and2. These are not Burp LAF/platform/accessibility certification.

Expanded-spec review is **incomplete**: one requested-model independent review plus orchestrator draft completed; two requested-model sessions were stopped by the provider. No model substitution or full consensus claim. That independent reviewer reproduced the previous frozen `5c7839e3…3a0a69` source/JAR and839/25 tests. A subsequent requested-model scoped implementation audit accepted the whitespace/deselection/visibility/grant-issuance fixes for a development preview, but found an in-pass parent-revalidation defect in the wrapping layout. That defect was fixed by deferring revalidation until after the pass, with displayability/parent/width checks; a separate requested-model narrow follow-up reproduced the old/new headless behavior and accepted the correction. A deterministic regression fails on the old inline call; the minimal no-viewport layout checks also prime the preferred-size cache. These code reviews are not full-spec/four-way/native approval, and did not independently rebuild or byte-verify this final JAR. The final clean automated run above and hash are local evidence. See [review status and proposal](AVAILABILITY_REVIEW.md).

**Native Burp has not yet been exercised on this preview JAR.** The evidence below belongs to the older examples JAR only. EXEMPT, ResponseWatcher, overlays, intent budgets, incident export, per-host RR/listener selection and schema2 are proposed expanded work, not implemented acceptance. Grant masking has focused automated header/reflection and first-issuance JSON/echo/export regressions; these are not native grant-header/broker tests.

## Previous published examples/shortcuts artifact

`cairn-proxy-guard-0.1.0-SNAPSHOT.jar`, Java21 / Montoya API2026.7:

```text
c07116e051f6f49f7e582ffd8490e2ae234a91b22b6a8958bb82e55e646cf508
```

The clean build included all production UI changes before this exact JAR was loaded through the disposable product UI. Its hash was rechecked after the native run. No intermediate or older JAR's native observations count as current-artifact acceptance.

## Confirmed automated results

- **783 JUnit cases / 23 suites**, zero failures/errors/skips, confirmed from the XML reports:

  ```sh
  ./gradlew --offline clean test jar --console=plain --no-daemon --max-workers=1
  ```

- Coverage retains policy/evidence/rate/approval/native adapter suites, owned-loopback forwarding, headless EDT/access/form/runtime integration and temporary-filesystem export regressions. Loopback and mocked Montoya tests are **not actual Burp**.
- Current UI regressions include read-only bounded/copyable guidance, Enter and double-click navigation, sorted/empty/stale row handling, approval review without a decision, URL Enter without a save, recipe preview without draft replacement, all six rule recipes' positive/negative behavior, default delete precedence, existing rule preservation, exact advanced settings/host-edit preservation while filling basic numbers, and small/large-font scrolling. Earlier guided-UI save/cancel/revision, editable numeric fields, runtime pending vocabulary, selection/detail and export regressions remain enabled.
- **18 template verifier regressions + 14 offline smoke-harness self-checks** passed:

  ```sh
  python3 scripts/verify_templates.py
  python3 -m unittest discover -s scripts -p 'test_*.py'
  ```

  The verifier explicitly reports local/fixture-only success and **SKIP actual-upstream**. These commands do not run CAIRN/Pi/model/report-file E2E or load Burp. Harness self-check PASS lines, including the new examples phase's fake responses, are offline test output, not native evidence.
- Dependency locks and strict SHA256 verification metadata remain enabled. [GitHub Actions](https://github.com/sehoon123/cairn-burp-guard/actions) is configured to run Java/JAR and Python checks; it does not run Burp or model E2E. Local success is not a claim that an unobserved remote workflow passed.

## Confirmed installed-Burp observations for this artifact

See [detailed native results](NATIVE_BURP_RESULTS.md) and [reproduction instructions](MANUAL_BURP_SMOKE.md).

- Normally available **Community Edition2026.10.1**, bundled JVM26.0.2, separate temporary home/config/data/cache/preferences/tmp/in-memory project and authenticated nested1440×1000 display. No user project or license/activation state was copied, changed or bypassed. An occupied default listener was left alone; only the disposable instance used a different owned loopback port.
- Loaded the hash-verified clean-build JAR through the product UI. Used owned numeric-loopback HTTP fixtures and external Python clients, **not CAIRN Native Pi workers**. All policy/approval operations were human UI actions; the harness has no Burp control API.
- **13 logical HTTP/1.1 scenarios / 4 phases passed**: empty allowlist; exact URL-form target with GET/HEAD, descendant/similar-path negatives, retained DELETE/decoded-query guards and preserved synthetic allowed values; three documented rule recipes including two human approvals; fail-closed pause.
- Observed all three guide tabs, URL Enter filling without saving, target/rule table opening and cancellation, recipe preview before explicit filling, both basic-number buttons, separate Enter/double-click traffic and approval reviews, and the distinct one-shot approval action. Saving1/1/1 was a UI check, **not a pacing/concurrency measurement**.
- **14 evidence entries = 6 upstream200 + 8 local451**, no pending entries. Actual UI full JSON had14 entries; selected HAR had1. Both were mode0600 and lacked four synthetic authorization/cookie/password/response-cookie secret values. Masked request/response display was also observed.
- Test Burp exited through its UI; its PID disappeared without forced termination. Only this task's display/window manager and private temporary profile/exports/logs/screenshots were removed. No raw runtime artifacts are published.

This is a limited native regression, not a rerun of either historical matrix. Native denial/expiry/policy-change cancellation, HTTPS, multi-client pacing/concurrency, host overrides, queue saturation and late-response quarantine were **not rerun on this hash**. Related automated backend tests passed but do not substitute for those native checks.

## Historical evidence, not current-build native acceptance

| Previous artifact | Automated result at that time | Native result at that time |
| --- | --- | --- |
| `a924d6c5aa08a10c3eceaf32f5e442cb5e423dc3499b3f4c2b5b9528e51eb2cc` | 771 Java / 30 Python | 12 logical HTTP scenarios / 7 phases; guided forms, approval/denial/expiry/policy-change cancellation/pause and JSON13/HAR1 exports |
| `56d0d1e3e02b6430352cd493bff97f8900eb4d5268140f44bac980d90c952d1a` | 584 Java / 28 Python | 54 logical scenarios / 14 phases; certificate-verified HTTPS/HTTP1.1, six-client pacing/two-host overrides, held-response concurrency, queue timeout, late-response quarantine and102-entry exports |

Those observations and timing measurements remain historical in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md). Do not add their12/54 cases to the current13 or describe them as a current-artifact rerun.

Earlier template work also passed actual read-only upstream loader/renderer/parser/contracts, `DispatchConfig.load` and `validate_prompt_resources` at CAIRN commit `8e7e0ea67552383851dfcabfba0c4e9c8d007878` using:

```sh
uv run --no-project --with 'pydantic>=2,<3' --with PyYAML \
  python scripts/verify_templates.py --cairn-root /trusted/CAIRN --require-full-config
```

That was an upstream contract check with unchanged source/resource fingerprints, not a dispatcher/worker/report-file run. It was not repeated in this UI-only iteration. The current default fixture-only verifier must not be described as that upstream check.

## Explicitly not established

- Mandatory network/OS proxy enforcement, direct-socket prevention, opaque CONNECT/TLS pass-through, HTTP/2 native coverage or WebSocket-frame coverage.
- Other extensions' later modifications, complete wire provenance/equality, or strict remote server-arrival RPS.
- Professional/disk projects, native cross-project races, every worst-case capacity/shutdown path, or Burp-restart persistence.
- Full HiDPI/cross-platform/accessibility verification. The desired1100×760 native window remains untested because of the product's minimum-window constraints in this environment. Headless large-font/form layout is a separate result.
- Live CAIRN dispatcher/Pi/model execution and report-file creation E2E. Prompt-only reporting/availability budgets are not a sandbox or a forced-termination completion guarantee.
- Authentication/session coordination, login/refresh or account/role management (excluded).
- KISA official code-by-code compliance, complete assessment coverage or absence of vulnerabilities.

Only reviewed source/docs, deliberately synthetic fixtures and intentional release artifacts are published. Build reports, original logs/screenshots, temporary Burp profiles/projects, generated certificates, private targets and credential material are not source artifacts.
