# Isolated actual-Burp smoke checklist

Use a separate disposable Burp instance/project and an owned numeric-loopback HTTP server. Do not import a real browser profile, real credentials or a production project. Stop if licensing needs user input; never copy license/activation state or bypass checks. Keep raw logs/screenshots/profile data private and outside Git.

Record installed product version/build, exact distribution JAR SHA256, fixture protocol, test date, case results and limitations. Do not publish host paths or original runtime artifacts.

1. Load the distribution JAR. Confirm the independent tab/name and all six sections; no initialization exceptions. Empty allowlist must locally block.
2. Configure only the fixture's loopback host/port/path. Disable Proxy's own interactive intercept in this disposable instance. Verify a safe HTTP request reaches the fixture once.
3. Send DELETE, `/delete`, query/form/JSON `delete`, mixed case and percent/JSON-escaped variants. Confirm local451 marker/evidence ID **and zero fixture requests** for blocked cases.
4. Exercise explicit method/header/body/AND/OR/regex rules and toggles. A hard scope denial must never be overridden by Allow/Monitor/Ask approval.
5. Start at least six independent clients through the same Proxy. At global5RPS verify the observed fixture sequence and the native admission counters; document callback pacing versus arrival timing. Hold responses to check max concurrency, queue timeout and missing-response quarantine.
6. ASK: verify unresolved requests do not arrive, approve one and observe one arrival; deny another and observe zero; let another expire and verify zero. Change policy while waiting and reject the stale decision. Inspect masked UI evidence, not raw secrets.
7. Carry **synthetic** Cookie/Authorization and JSON/form data through an allowed request. Compare the fixture's values/body and returned response with intended values. Inspect JSON/HAR exports for masking/omission and local-versus-upstream provenance. Native Burp may independently normalize transport/hop-by-hop headers; do not misattribute that to extension mutation.
8. HTTPS requires a fixture certificate and explicit temporary client trust, never global CA changes or insecure verification flags. Verify safe/blocked HTTPS paths through Burp MITM. Separately label untested HTTP/2 or TLS-pass-through paths.
9. Unload/reload the extension and close only the disposable instance. No timer leak or already-started request completion should be invented. Unloaded extension is no protection. Remove only owned temporary artifacts after reviewing sanitized results.

CAIRN itself and forced network egress are separate acceptance tests. No Burp control API/extension is supplied to a worker by this checklist.

## Modal / all-passthrough regression (2026-11-04)

All changes below are in the disposable product UI, never via an API/worker. Record the final exact JAR hash. Earlier examples results do not cover this feature.

1. Load into an empty-policy project. Run `--phase empty`. Open **모두 통과 (보호 끔)…**, read/scroll to the last warning, resize the modal, then cancel with Escape and verify the next `--phase empty` still blocks. Enter without selecting the affirmative button must also cancel. Separately resize actual Swing dialogs with14/28pt fonts using `desktopTest` on an isolated display; do not call those a Burp run.
2. Keep the empty allowlist and both built-in guards. Set only basic limits to **1/1/1** and save. Explicitly confirm **모두 통과**. All tabs must retain the unprotected status/restore button. Run `--phase passthrough` (HTTP only): **8 cases / 13 requests**, all fixture200, covering unregistered path/second host, DELETE/encoded delete, malformed JSON, opaque body, unchanged synthetic auth/cookie/body and six concurrent held clients. Confirm only the OFF counter changes, not evidence/approval/permit count.
3. Restore protection and run `--phase empty`; empty scope blocks again. Toggle OFF, use **새 요청 모두 차단**, run `--phase paused`. Resume and recheck scope. Reload the extension while OFF and confirm OFF is not restored, then verify protected empty scope again. Do not reset permits to simulate completion.
4. Register exact `/ask`, create an ASK rule, keep protection ON. Run `--phase passthrough-cancel`: after its one-second no-arrival check, enable OFF through the human confirmation (do NOT approve). Expect `POLICY_CHANGED` and zero fixture arrivals. The old approval must disappear. Newly issued OFF requests can pass; restoring protection must require new approval for a new `/ask` request.
5. If a protected native response is held, entering OFF must not decrement its permit. Its actual response still updates the original masked evidence. OFF-originated responses must not be recaptured after restore. Project change/save/factory races and shutdown have separate synthetic regressions; label any native case not actually exercised.
6. Review/export only masked protected evidence and verify the OFF request/response contents are absent. Burp's own history remains outside extension control. Stop only the disposable instance/display/owned fixture processes and remove only their private artifacts.

## Examples/shortcuts regression (earlier c071 artifact:13 logical cases)

Use a clean disposable project and keep both built-in guards. If8080 belongs to another instance, select an unused loopback listener in the disposable product UI and append `--proxy-port <owned-listener-port>` to **every** phase command. Never stop or reconfigure a live instance. All configuration and decisions remain human UI actions.

1. Open **사용 예시…**, read its three tabs, then close it. No policy revision should change. Run `python3 scripts/native_burp_smoke.py --phase empty`.
2. Register exact `http://127.0.0.1:18080/safe` through the URL field: type → **Enter** → review preview → **저장하고 적용**. Enter must leave the draft open, not save it. Run `--phase exact` (6 logical cases). Test target-table double-click/Enter, then cancel without changing policy.
3. Register the separate exact URL `http://127.0.0.1:18080/api/items`. In **규칙 만들기…**, create and explicitly save each recipe: **POST /api/items 승인 요청**, **JSON action=review 승인 요청**, **쿼리 operation=purge 차단**. First select and inspect the match/non-match preview: the original draft must stay unchanged until **예제로 폼 채우기**. Do not replace either built-in rule. Test rule-table opening and cancel.
4. Open settings. Check **천천히 · 1/1/1** and **기본 · 5/5/5** fill only the three basic fields. Nothing is saved before **저장하고 적용**. For the recorded run, explicitly save1/1/1; retain default advanced settings and no host overrides. This does **not** measure pacing/concurrency.
5. Run `--phase examples` (5 cases). GET `/api/items` arrives; POST `/api/items/1` is outside scope; `?operation=purge` gets `RULE_BLOCK`. Then two requests wait in turn: POST `/api/items` and JSON `{"action":"review"}` to `/safe`. Let each pass the script's one-second no-arrival check; use table Enter/double-click to review masked evidence, close, then separately choose **한 번만 승인**. Review-only navigation must not resolve the request. Do not change policy while waiting.
6. In **개요**, pause new requests, run `--phase paused`, then resume. No fixture arrival is allowed while paused.
7. Review masked traffic via Enter/double-click. Export full current-table JSON, then search POST, select its original synthetic-secret200 row and export selected HAR. Verify **14 JSON entries / 1 HAR entry**, mode0600 and absence of the four synthetic secret values.

This subset is **4 phases / 13 logical cases / 14 requests = 6 upstream200 + 8 local451**. It does not rerun native denial/expiry/policy-change cancellation or the historical HTTPS/rate/concurrency/queue/quarantine matrix. Offline self-checks of `--phase examples` are not native observations. See [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md) for the exact current hash and historical separation.

## Earlier guided-UI regression (a924 artifact:12 logical cases)

The following limited workflow was exercised on the **previous** guided-UI JAR (`a924…b2cc`), not the current examples/shortcuts artifact. Record its exact hash; do not call the broader historical matrix below a current-build rerun. All configuration/decisions are local human UI actions, not script/worker controls.

1. Load a clean disposable instance with the empty allowlist; run `python3 scripts/native_burp_smoke.py --phase empty`.
2. In **개요 → 허용 대상 등록…**, enter `http://127.0.0.1:18080/safe`, choose **폼에 반영**, review the exact host/port/path preview and **저장하고 적용**. Retain both default rules. Run `--phase exact`: GET/HEAD and synthetic POST must arrive; `/safe/child`, `/safex`, DELETE and the encoded delete query must not.
3. Register the separate exact URL `http://127.0.0.1:18080/ask`. In **규칙 만들기…**, choose **승인 요청**, make an AND group with URL path EXACT `/ask` and method EXACT `GET`, then save. Do not replace the two default guards.
4. Run `--phase approve`, review the waiting entry in **승인 대기**, then approve once. Run `--phase deny` and choose **거절**. The external CLI waits while the human uses the product UI.
5. In **설정 → 요청 제어 설정 변경… → 상세 설정 펼치기**, set approval limit to **4 seconds**, save, run `--phase expire` without deciding. Restore30 seconds, run `--phase stale`, and while waiting change a numeric setting and save; expect `POLICY_CHANGED` and zero arrivals.
6. In **개요**, pause all new requests, run `--phase paused`, then resume. This is fail-closed pause, not a protection-OFF mode.
7. In **요청 기록**, inspect separate masked request/response details. Export current-table JSON; search/select/bookmark the POST and export **선택한 요청만 / HAR**. Check entry counts, secret absence, omission/provenance labels and POSIX mode0600. Do not publish the exports or screenshots.

An uncontaminated run has12 logical cases but13 requests:4 upstream200 and9 local451. No HTTPS/rate/concurrency/quarantine claim follows from this subset. See [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md).

## Broader external fixture/client harness

The following reproduces the broader matrix previously run on the old hash. It is also available for future acceptance work; it is **not evidence that every phase was rerun on the current build**.

`scripts/native_burp_smoke.py` uses Python's standard library, creates owned loopback echo servers and sends **only synthetic fixture traffic** through an already configured local Proxy. Strings such as `delete`/`purge` have no operation behind them: the servers only echo data. The script never starts, loads, configures, approves, or controls Burp. All policy/approval actions below are made in the disposable product's human UI. Do not give this operator workflow to a CAIRN worker.

1. Use an isolated, normally licensed/available Burp edition. A product-provided **Community Edition** selection is legitimate; copying Professional activation state or bypassing its activation is not. Use a temporary in-memory project if Community does not support a project file.
2. Load the exact JAR and record its SHA256. Confirm Proxy Intercept is off and the listener is exclusively the disposable instance's loopback listener (defaults below: `127.0.0.1:8080`). No live project or global proxy settings are needed.
3. With an empty allowlist run `python3 scripts/native_burp_smoke.py --phase empty`. The local451 must contain the fixed guard marker, categorical reason, UUID evidence ID, and `retryable:false`; the fixture must receive zero requests.
4. [guard.loopback-smoke.json](../templates/examples/guard.loopback-smoke.json) is a **full example policy**, NOT an import/control endpoint. For this broader synthetic matrix, use **설정 → 고급: 정책 JSON 가져오기 / 복사…**. `jq '.rules |= .[0:2]' templates/examples/guard.loopback-smoke.json` prints the complete initial policy with only its two built-in guards and default limits. Review every target/field, manually paste the complete object and choose **전체 정책 저장**. Ordinary target/rule/settings work uses the guided forms instead; there are no per-list JSON editors or Apply ALL drafts button.
5. Run `python3 scripts/native_burp_smoke.py --phase default`. Six clients/two numeric-loopback hosts share global5RPS; the controlled 1.5s hold case measures fixture concurrency. The harness records arrival timing, **not a guaranteed wire-admission clock**.
6. Replace the advanced whole-policy text with the original **complete example document**, review it and save. Composite nodes deliberately include all record fields, including `caseSensitive:false`; missing primitive values are rejected. Run `--phase custom`. In **규칙**, select `fixture-composite`, choose **사용 / 중지** and confirm, then run `--phase disabled`; re-enable it with the same confirmed action. Each action saves directly, with no second global Apply. These checks distinguish actual BLOCK categories from scope/inspection failures and exercise negative/case-sensitive conditions.

Additional phases require these explicit UI preconditions (other values remain at example defaults):

| Phase | UI configuration/action | Expected result |
|---|---|---|
| `approve` | `fixture-ask` enabled; review pending `/ask`, choose **한 번만 승인** | No unresolved arrival; one after approval |
| `deny` | Same, choose **거절** | `DENIED`, zero arrivals |
| `expire` | Approval limit **4 seconds**; no decision | `APPROVAL_TIMEOUT`, zero arrivals |
| `stale` | Approval limit30 seconds; while pending change queue limit to29 seconds and save | `POLICY_CHANGED`, zero arrivals |
| `host` | Global5/default-host5; host-exception table: exact `127.0.0.1` and `127.0.0.2`, each2RPS | Two hosts independently limited to2RPS, still sharing global5 |
| `queue` | Clear overrides; max concurrent1; queue limit **0.080 seconds**; response limit60 seconds | One fixture arrival, five `QUEUE_TIMEOUT` local blocks |
| `quarantine` | Max concurrent1; queue limit30 seconds; response limit **0.500 seconds** | Probe blocked with `IN_FLIGHT_TIMEOUT` while first response is held; real completion permits a later request |
| `paused` | **개요**: pause new Proxy requests | `PAUSED`, zero arrivals |

These numeric fields are in **요청 제어 설정 변경…**; expand the advanced section for timeouts and host exceptions. UI time is in seconds, stored exactly in milliseconds. Restore example limits and unpause when finished. Pause changes revision: if an old editor is stale, close it, refresh and reopen from current values. Never lower the in-flight threshold to infer that an already sent request was cancelled.

### Strict TLS variant

The TLS tests use `localhost`, after checking it resolves **exclusively to loopback**, because the installed Burp's numeric-IP certificate did not satisfy strict IP-SAN verification. The test does not turn off chain/hostname verification or install a global CA. The harness refuses to label this single-host TLS variant as the two-host HTTP pacing experiment.

- Retain the explicit `https`/`localhost:18080` allow/block entries from the example.
- In the disposable Burp UI, Proxy settings → Import/export CA certificate → **Certificate in DER format**. Export **only the public certificate**, never the private key/keystore. This is not license or activation data.
- Generate a temporary fixture certificate/key outside the checkout, with owner-only permissions. Use no real credentials:

```sh
SMOKE_DIR="$(mktemp -d)"
chmod 700 "$SMOKE_DIR"
# Export Burp's PUBLIC certificate to "$SMOKE_DIR/disposable-burp-ca.der" in its UI first.
openssl x509 -inform DER -in "$SMOKE_DIR/disposable-burp-ca.der" \
  -out "$SMOKE_DIR/disposable-burp-ca.pem"
(umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$SMOKE_DIR/fixture-key.pem" -out "$SMOKE_DIR/fixture-cert.pem" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1')
python3 scripts/native_burp_smoke.py --phase basic --https \
  --fixture-cert "$SMOKE_DIR/fixture-cert.pem" --fixture-key "$SMOKE_DIR/fixture-key.pem" \
  --burp-ca "$SMOKE_DIR/disposable-burp-ca.pem"
python3 scripts/native_burp_smoke.py --phase custom --https \
  --fixture-cert "$SMOKE_DIR/fixture-cert.pem" --fixture-key "$SMOKE_DIR/fixture-key.pem" \
  --burp-ca "$SMOKE_DIR/disposable-burp-ca.pem"
```

These clients use CONNECT plus certificate-verified TLS with HTTP/1.1 inside the tunnel; HTTP/2 and opaque TLS pass-through remain separate, unverified cases. Keep generated keys, CA files, exports, screenshots and logs outside Git. Inspect masked JSON/HAR, test search/bookmarks and restore/unload/close only the owned disposable instance. The script closes its own servers on phase exit; the human is responsible for the Burp/profile/certificate cleanup.

Harness self-checks are **offline unit checks, not native experiments**:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Do not run the harness with `python -O` / `PYTHONOPTIMIZE`; it refuses optimized execution rather than silently disabling its checks. Observed results and gaps are recorded separately in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md).
