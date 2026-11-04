# Owned native A–G plus OFF checklist — unreleased v2

**Latest user scope: H per-port protection is explicitly DEFERRED, not a current gate or PASS.** Use all Proxy listeners (`guardListenerPorts=[]`); new restrictions cannot be saved. Current exact-artifact observations are in [ALL_LISTENERS_ACCEPTANCE.md](ALL_LISTENERS_ACCEPTANCE.md).

**Procedure, not a PASS log. Historical H is FAIL/UNSUPPORTED.**
After explicit authorization for the temporary instance's terms, Main ran individual
owned Community2026.10.1 cases and found/fixed HEX export reflection, but listener
identity remained unsupported. The prior first-EULA stop is historical. See
[actual-artifact findings](V2_NATIVE_FINDINGS.md), [verification](VERIFICATION.md)
and [native records](NATIVE_BURP_RESULTS.md). Do not turn partial observations,
Swing/Mockito/owned sockets or historical hashes into full native A–H approval.

Only a human/operator may perform this workflow under appropriate authorization.
It is not a worker prompt, Burp control API or permission to accept terms, bypass
activation, use a live project, change desktop/provider/credentials or publish a
candidate. Stop at licensing/EULA/user-input blockers and report them. Never copy
license/activation/profile/auth state from an existing installation.

## Preconditions and recording

1. Freeze intended source/lock/legal files, run clean Java/Python and isolated Swing
   separately, resolve failures, build and independently reproduce the exact intended
   JAR. Record source revision/manifest, full JAR SHA256, product/build/JVM, protocol,
   date and per-case result/limitations. Revision3's Java1221 and isolated Swing27
   each at scale1/2 (scale2 repeated) PASS, and locally repeated217730… JAR bytes,
   are **not** actual Burp, independent implementation review or platform proof.
2. Use a separate disposable HOME, config/data/cache/preferences/temp directories,
   project and display, not an existing Burp instance. Use only **owned ephemeral loopback ports** and
   synthetic payloads. Leave occupied user listeners/processes alone. No global
   proxy/CA/desktop changes. Keep raw logs/screenshots/exports/profile material
   private outside Git; only generic `$TMP` references/sanitized facts belong here.
3. Human loads the hash-verified JAR through Extensions UI only after legitimate
   product access. Verify extension identity,8 tabs, no initialization failure,
   protected state and empty allowlist local451. Disable the disposable Proxy's
   interactive intercept as appropriate. No extension probe/control endpoint.
4. Inspect [INTERFACES.md](INTERFACES.md) and current source. Start with an actual
   **new schema2 profile**, not an imported legacy fixture assumed equivalent.
   New default: DELETE-method BLOCK only; no broad delete-string. Importing v1
   retains all its rules and turns new detectors off until explicit human save.
   Historical `guard.loopback-smoke.json`/old instructions are not an automatically
   correct v2 all-feature profile. Do not silently delete a legacy/custom rule.
5. Configure each phase's **minimal exact owned service/path scope and matching
   settings** through human UI. Restore between phases; do not let circuit/heavy/
   fanout/budget leftovers contaminate unrelated tests. Overlay expiry/release and
   explicit intent reset are separate from saving detector settings. Record both.
6. Compare original allowed target/Host/body/response at the owned fixture, not
   redacted export. Compare native continuation identity separately from transport
   equality. Native buffering/other extensions may alter later wire bytes; do not
   attribute all product transport changes to this extension.

A local block requires **all**: expected categorical reason, guard marker/typed
metadata and **zero additional fixture arrivals**. Upstream451/5xx is not a local
block merely because of HTTP status. `FORWARDED`/handoff count is not delivery.
Never reset a true native permit or lower a timeout to simulate completion.

## External fixture/client helper, not Burp automation

`scripts/native_burp_smoke.py` starts owned loopback echo fixtures and external
Python clients only. It never starts/loads/configures/approves Burp or saves policy.
Its incident phase reads a human-chosen export offline and starts no client/fixture.
Do not give this operator helper or a Burp management connection to CAIRN workers.

Choose unused owned ports and pass them **on every invocation**; defaults8080/
8081/18080/18081 are examples, not permission to occupy them. For example, after
human configuration (variables contain only the chosen owned ports):

```sh
python3 scripts/native_burp_smoke.py --phase empty \
  --proxy-port "$GUARDED_PORT" --port "$FIXTURE_PORT" --second-port "$SECOND_FIXTURE_PORT"
```

`--proxy-host` is numeric loopback. The two HTTP fixture hosts are127.0.0.1 /
127.0.0.2; HTTPS uses explicitly verified loopback-only localhost. Fixture route
names such as delete/purge have **no operation** behind them: servers echo only.
Raw target equality uses the bounded received request line rather than a
normalized framework path. Client/harness self-check PASS is **not native PASS**.
Do not use Python `-O`/`PYTHONOPTIMIZE`; assertions must remain enabled.

## Baseline scope / latest path and optional-content regressions

Before A–H, establish the changed pentest semantics on the exact candidate:

- `empty`: empty allowlist -> `SCOPE_NOT_ALLOWED`, local451, zero arrivals.
- `exact`: human exact `/safe` on first actual fixture service, DELETE-method only.
  GET/HEAD + synthetic allowed POST arrive; `/safe/child` and `/safex` do not.
  Encoded benign `delete` query text now arrives; it is **not a default substring
  denial**. Preserve body/Authorization/Cookie unchanged at fixture.
- `rawpaths`: explicit **all-path** scope on the first actual service only, no
  conflicting custom rule/availability episode. Include exact `/c/;/main.do`,
  `/c/%2e/main.do`, nested/encoded dot/matrix/separator variants and malformed
  percent spellings. Verify exact target string at fixture; no unsolicited
  `AMBIGUOUS_PATH` sanitizer or native target normalization by the extension.
  If using curl instead of this helper, use `--path-as-is`.
- Fuzz Host with the **second owned fixture service**, never a real/unowned host.
  In-scope actual service with different Host must continue unchanged; spoofed
  allowed Host must not authorize an out-of-scope actual service. HTTP proxies
  may derive destination from Host; client URL alone does not prove native
  `httpService`. If needed, use legitimately configured CONNECT+MITM with a pinned
  actual service and verify that service through existing authorized product
  observations. Do not report Host independence without proving actual destination.
- Same rawpaths phase sends unsupported charset/binary/multipart/encoding,
  malformed JSON and optional >1MiB capture payload. Otherwise in-scope traffic
  must arrive unchanged, not automatically451. Enable a relevant explicit body/
  header rule to verify fixed unavailable-inspection warnings rather than falsely
  claiming parsing succeeded. Available explicit HEADER/BODY/JSON/FORM rules still
  enforce their match. An unavailable condition must never grant EXEMPT.
- Restricted path scope must still reject route escapes across bounded views;
  matching blockScope still wins. Incomplete interpretation can pass explicit
  all-path with warning, not prove restricted scope or path-dependent EXEMPT.
  Strict authored probe/threshold route validation stays strict, unlike traffic.

External clients cannot establish the extension's internal inspection-completeness
or actual service source alone; pair fixture data with human UI/current source
observations and label unobservable aspects as pending.

## A — EXEMPT and default false positives

Human creates ordinary BLOCK PATH `/broker` and matching narrow EXEMPT on the
same in-scope owned service; retain default DELETE-method. `--phase exempt`
expects broker arrival and DELETE at a non-exempt path blocked. Inspect outcome
`exempt`, rule hits and unchanged native synthetic values.

Also verify: out-of-scope actual service, operator pause, heavy/fanout/circuit,
intent limit and rate/capacity still block an EXEMPT request as appropriate. An
unavailable-content OR branch cannot lend EXEMPT through another known true branch.
EXEMPT save warns that ordinary BLOCK/ASK are bypassed; cancel writes nothing.
New-profile in-scope GET `/ui/bp/common/board/deleteInfoBoardComnt.do` and `undelete`
text pass absent an authored block. This does **not** authorize an out-of-scope GET
or silently remove an existing v1/customized rule. No session-broker/authentication
service is implemented or tested; `/broker` is an echo route only.

## B — ResponseWatcher / overlays

### Heavy

Human enables5MiB threshold,10minute TTL (or records explicit test TTL), allows
`/large` on the owned service, and avoids unrelated detectors. `--phase heavy`:
first **6MiB** response reaches client intact; next same path gives
`HEAVY_ENDPOINT_AUTO_BLOCKED` with overlay ID and zero new fixture hit. Human
releases that overlay in UI, then acknowledges the helper's prompt; a subsequent
large response passes and can re-open protection. This is not an automated release.

Inspect actual responseBytes=6291456 even though >copy bounds means raw/masked
body omitted. No Content-Length/copy-size shortcut. Test TTL expiry, route-alias
protection, another path's independence and explicit zero override separately.
First-heavy detection is **post-response**; it cannot prevent/cut off the first
large transfer or undo target work. Record these limitations.

### Circuit / half-open

Human configures five5xx in60seconds, open1second for the disposable test (or
matches helper `--open-seconds`), health bypass disabled. `--phase circuit`
observes five actual503s then `CIRCUIT_OPEN`, waits the chosen open time, observes
one held GET half-open and concurrent denial, then successful close.

The helper does **not** prove every state: separately check safe GET/HEAD-only,
failed5xx/unknown/missing response reopen,30second per-service attempt cadence,
late/duplicate response and old-epoch/released-episode ABA. Open expiry is not
unprotected automatic recovery. If true permits are stalled, do not recycle them
to force a half-open result; quiesce traffic or report the interference.
Health GET may observe errors but must never heal circuit state.

### Fanout, capacity and human controls

With a small explicitly authored threshold/window, send distinct query-free paths
to the owned service. Verify one incident per episode for WARN, service-local
BLOCK, separate automatic global PAUSE; query-only variants are not distinct paths.
Overlay list retains cause/created/expiry, selected/all release confirmations and
reopen-on-new-detection. No persistent policy edit: compare a reviewed local policy
export/hash before/after; no native console/control endpoint or profile/log export.
Disabling a detector/same-project save/OFF does not erase active protection/debt.
Capacity fence/no-active-eviction and all worst-case races may remain synthetic;
label anything not run natively instead of extrapolating.

## C — Typed local451 and optional health GET

Preserve original five JSON keys **in order**:
`source`, `outcome`, `reason`, `evidenceId`, `retryable:false`. Append enum-only
`guardState`, `local:true`, nonnegative `policyRevision` and safe optional overlay
UUID. Header `X-Cairn-Guard: blocked`, JSON/no-store distinguish it from target451.
No URL/host/path/intent/run/credential/pattern/exception text in the local body.
Compare actual reason from final commit (heavy/circuit/intent/listener etc.), not
blanket `FINAL_CHECK_REJECTED`. Denial-factory failure must not continue upstream;
ambiguous duplicate ID is drop-only to preserve older-flight ownership.

Health default OFF. Through UI explicitly enable exact actual scheme/host/port/path
GET exception, read side-effect warning, cancel once, then save deliberately.
Only **no query / verified empty body / GET** can bypass operator pause/circuit.
HEAD, body/query, different service/path or ambiguous authored routes are not
health passthrough. Hard scope/lifecycle/invalid/save-uncertain/project/shutdown,
ordinary BLOCK/ASK, heavy/fanout/rate/intent/capacity still apply. Allowed evidence
outcome is `probe_allowed`; health response does not close a circuit. This observes
client requests only, never extension-generated health polling.

## D — Attribution / exact final-handoff budget

Human sets perIntentMaxRequests20; no unrelated watcher failure. `--phase intent`
sends20 with one synthetic(run,intent), requires21st `INTENT_BUDGET_EXCEEDED`,
another intent passes. Inspect human raw tag columns/filter and masked export
metadata; client tags remain unchanged and **untrusted**, not authenticated quotas.
Missing intent is unbudgeted. Duplicate/invalid or incomplete captured headers
reject when enabled; disabling accounting preserves debt, explicit human reset
warns it grants fresh quota. Other run IDs are separate pairs.

Reject an ASK, queue expiry, final watcher/lifecycle gate and local continuation/
correlation factory failure without consuming new quota. Some local failure
injection may be synthetic-only: do not add extension probes or claim native
coverage without actually observing it. EXEMPT/health/half-open successful protected
handoffs count; OFF/known-unselected do not. Native continuation is accounting
boundary, not delivery; no refund after uncertain dispatch.

## E — Candidate actions and raw history separation

Human inspects maximum-descending candidates, max/p95/count/lastSeen/5xx and
retention/truncation indicators. p95 is a **log2 upper-bound approximation**, count/
max/5xx/lastSeen are exact for retained observations, not lifetime traffic.

- Safe unchanged query-free actual-service `policyUrl` can open an **unsaved**
  ordinary BLOCK draft; cancel must not save. A saved ordinary BLOCK is still
  outranked by matching EXEMPT, unlike an automatic overlay.
- Exact path NMiB threshold draft is separate from a rule, warns first-heavy
  limitation, validates exact bytes and strict route.0 disables only that route's
  size detection. Save leaves pre-existing overlay until expiry/release.
- Ignore suppresses candidate display only, not policy/incident/active overlay.
- Masked/changed/unrepresentable URL has no actionable policyUrl. Buttons must not
  copy raw history into policy. Response-only synthetic grant echoed in earlier
  path must remask watcher values and invalidate the draft, including older
  pending endpoints. No raw getter for runtime watcher/export.

Human history is **unmasked by request**, unlike older preview expectations:
Authorization/Cookie/grant may appear **only in local bounded raw UI getters**,
with UTF8/HEX/omitted/truncated inspection-copy labels. JSON/HAR/incident remain
masked/sealed as appropriate. Test eviction/clear/project uncertainty and no late
raw resurrection; clipboard/screenshots/private exports never enter Git.

## F — Human incident / evidence export

Choose a `[from,to)` window (max24hours) in human UI and export one owner-only
file. Verify `window`, `events`, top20 `top5xx`/`topBytes`, numeric scalars,
`complete`/`truncated`/`approximate`, retention/clock/ring-loss and approximation
metadata. Startup/clear/out-of-retention/capacity loss cannot be claimed complete.
No raw auth/cookie/grant/path reflections; no original response body in incidents.

JSON/HAR uses sealed masked TrafficEntry, including actual responseBytes/warnings/
state/outcome; stale retained selections use latest redaction. Full/selected/filtered
counts, local451 vs callback status, unknown sizes/timings and missing-response
labels must remain honest. Exports are inspection copies, not replay/wire proof.

Optional offline helper after human export:

```sh
python3 scripts/native_burp_smoke.py --phase incident \
  --incident-file "$TMP/incident.json"
```

Watcher candidate IDs are lowercase64-character keyed route identifiers, not
overlay/evidence UUIDs. The helper's old UUID assumption was fixed;27 harness tests
and a network-free export produced by the actual217730… watcher JAR passed its
offline validator with one event and nonempty top5xx/topBytes. This is producer/
validator compatibility, **not a real Burp human export or native acceptance**.
Never rewrite an export's IDs to manufacture PASS. Offline shape/known-synthetic-
secret checking is not generic provenance validation or comprehensive DLP proof.

## G — Shared pacing, eligible hosts and true permit lifetime

For `default`/`host`/`concurrency`/`queue`/`quarantine`, configure matching scope and
settings manually. The v2 basic/default helper now expects benign delete text and
unsupported optional bodies to arrive; old preview expectations do not apply.

- Global5/default-host5, six clients/two owned hosts: shared admission counters
  and fixture arrival sequence; arrival timing is an observation, not strict
  network-server-arrival pacing guarantee.
- Host overrides2RPS on both exact fixture hosts retain global5. Host means
  canonical host, not scheme/port. Slow host A must not hold ready B's turn when
  genuine global capacity exists; no unconditional no-HOL promise under global
  pacing/concurrency saturation.
- Hold replies to reach maxConcurrent; verify no new admission beyond true slots.
  Queue saturation/timeout gives local denial with zero added arrivals; unresolved
  native operation is never decremented by a timer/reset/settings/close.
- Host-local overdue work gives `IN_FLIGHT_TIMEOUT`; another host may use a real
  free global slot. If stalled permits alone pin all maxConcurrent slots, every
  host fails. Only matching actual late response closes its permit.
- Inspect top64 host metrics/truncation and recent128-admission p95 wait, not target
  throughput/latency. Larger-capacity/fairness cases not run natively remain labeled
  synthetic-only.

`quarantine` helper uses concurrency1, queue30seconds, request timeout0.500seconds
and1.5second fixture hold. `queue` uses concurrency1/queue0.080seconds. Match these
explicitly, then restore; do not confuse them with new-profile defaults60/30seconds.

## H — Actual inbound listener restriction (DEFERRED future work)

**The user removed H from the current delivery scope. Do not run this as a current gate.** The procedure below is only the future contract once a supported implementation exists; current human UI/JSON cannot create a restricted selection. Production no longer feeds Proxy numeric IDs/annotations into the HTTP
listener registry. Both restricted ports currently reject LISTENER_UNVERIFIED
before native capture; UI says unsupported. The script should FAIL the selected
RULE_BLOCK expectation. Do not accept that mitigation as H PASS or add heuristic
identity/traffic markers. A supported shared identity/design decision is needed first.

Human creates **two distinct owned inbound Proxy listeners** in the disposable
instance in that FUTURE supported implementation. Start empty selection (all protected), then explicitly save only
`$GUARDED_PORT` after its future warning; `$UNSELECTED_PORT` is a different inbound port,
not a fixture destination port.

```sh
python3 scripts/native_burp_smoke.py --phase listeners \
  --proxy-port "$GUARDED_PORT" --unselected-proxy-port "$UNSELECTED_PORT" \
  --port "$FIXTURE_PORT" --second-port "$SECOND_FIXTURE_PORT"
```

Same actual destination/payload: selected enforces DELETE default; known unselected
forwards the unchanged DELETE. Check no new raw/masked contents, approval, watcher,
budget, rate permit or response correlation for unselected traffic, only the
separate saturating counter. Pause must not block known-unselected traffic.
Unknown/missing/collision/expired/stale mapping must deny `LISTENER_UNVERIFIED`
**before capture**, not silently protect/capture or bypass via destination fallback.

**Prove a supported shared identity, do not infer one** from Proxy→HTTP numbers,
annotation identity/values, order, timing or content fingerprints. Native testing
already falsified the original numeric and annotation-identity assumptions.
`javap`/Mockito/registry tests only establish API/source compatibility.
If existing authorized product observations cannot establish it, record that
blocker; do not add probes/control APIs, copy logs containing content or call this
H PASS. External clients alone cannot prove in-memory no-capture. Test selection
changes/project/generation and observer unload/late callbacks without reusing
ambiguous IDs/permits. Global OFF comes before listener mapping.

## OFF / retained pause / old flights / migration / dialogs

These cross-cut A–H; they are not a separate approval bypass:

1. Empty scope, open OFF confirmation: scroll to last warning, resize, Escape/close
   and default Enter cancel. Recheck empty blocks. Then explicitly confirm OFF;
   persistent warning/restore controls remain across all8 tabs.
2. Set protected1/1/1; `--phase passthrough` tests HTTP-only8 cases/13 requests,
   including scope/DELETE/opaque bodies/synthetic values and six held clients.
   Only OFF count changes, no new content/raw/evidence/permit. Restore and recheck
   scope. Scope/binary tolerance in protected v2 must not be misattributed to OFF.
3. Pause first, enter OFF, restore ON: **old operator pause is retained** until
   explicit Resume. While OFF `paused=false` does not erase `operatorPaused`.
   Heavy/circuit/intent debt/stalled native permits remain across OFF/save/ON.
4. `--phase passthrough-cancel`: old ASK's unresolved check, then human OFF (not
   Approve). Old request rejects `POLICY_CHANGED`, zero fixture hits; new OFF may
   pass. Restore requires fresh approval. Protected Prepared never inherits OFF.
5. Hold an old protected response: entering OFF does not close its permit. Actual
   response updates its old bounded raw/masked record if still valid; OFF-origin
   responses never become captured after ON. Stop traffic and independently
   quiesce OFF connections before relying on protected concurrency.
6. Project/restart/uncertainty resets OFF and raw ownership, never true permit
   completion. Successful same-project save preserves OFF; uncertain save blocks.
   Stale modal/project/revision/tokens reject, not silently refreshed authorization.
7. Load synthetic strict v1 policy: banner/original/migrated comparison, new
   detectors OFF, legacy rules retained, no read-time save. Cancel unchanged.
   Original-policy export is operator-authored data, **not masked traffic**.
   Optional exact legacy removal unchecked by default; customized/disabled rules
   remain. Explicit v2 save warns old preview cannot read it; backup original for
   deliberate rollback. No automatic downgrade or implicit deletion.
8. Exercise EXEMPT/listener/health/threshold/release/ignore/reset/clear/overwrite
   confirmations, editable settings and stale CAS. Dialogs plain/selectable/
   scrollable/resizable; safe default cancel, action area reachable. Guide/Enter/
   double-click/recipe filling never saves or decides implicitly. Real isolated
   Isolated Swing scale1/2 success does not clear pending native LAF/layout checks.

## HTTPS and cleanup boundaries

HTTPS needs an owned fixture certificate/key and explicit **temporary client trust**
of the disposable Burp's **public CA only**. Never export a private CA key/keystore,
copy activation data, disable hostname/chain verification or alter global trust.
Verify localhost resolves exclusively to loopback. Pass `--https --fixture-cert
"$TMP/fixture-cert.pem" --fixture-key "$TMP/fixture-key.pem" --burp-ca
"$TMP/disposable-public-ca.pem"` with matching human https scope. Use `basic` rather
than two-host `default`/`host`/`passthrough` TLS variants; HTTP2/opaque CONNECT/TLS
pass-through are separate unverified cases. Historical strict localhost TLS success
does not prove numeric-IP SAN or v2 HTTPS compatibility.

After tests recheck JAR hash, human policy state and sanitized per-case outcomes.
Exit only the disposable instance through UI when possible; stop/join only owned
fixture/display/window-manager processes and remove only owned private artifacts.
Do not invent completion/cancel of already-started requests on unload. Unloaded
extension is no protection. Leave licensing/native/audit/release blockers explicit.

CAIRN/Pi/model/report-file E2E, mandatory egress, Professional disk projects,
other extensions' final wire changes, authentication/session coordination and
production reliability certification are outside this checklist's evidence.
Historical12/13/54 native scenarios remain per-artifact records, not v2 results.
