# Controller, native-boundary mocks and owned-loopback verification

## Current source and evidence boundary

These tests invoke real `GuardController`, `PolicyEngine`, `RateGate`,
`ApprovalQueue`, `ResponseWatcher`, `IntentBudget`, `ListenerRegistry` and
`EvidenceStore` dependencies. They do not substitute a policy-only fake controller.
They are **not installed-Burp acceptance, release or independent implementation
approval**. Current integration records are in [VERIFICATION.md](VERIFICATION.md);
old native results remain historical in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md).

`ProxyLoopbackTest` is a controlled forwarding harness, **not an HTTP proxy,
Montoya runtime, real-target test or forced-network-routing proof**. Its actual
socket is always pinned to its owned numeric-loopback fixture. Controller and
watcher themselves perform no outbound HTTP, automatic saves, health polling or
authentication actions. No installed Burp/user project/display/license/system
settings are required by these tests.

## Recorded runs — do not add overlapping slices

| Snapshot / scope | Result / boundary |
|---|---|
| Model/policy/attribution slice |278 synthetic cases, including23 pentest-routing cases; not full integration |
| Controller integration slice |685 cases /19 suites with real dependencies, including41 new controller v2,30 listener,6 watcher remasking/URI/IPv6 and2 evidence warning/masking cases; not adapter/UI/native acceptance |
| Native adapter + owned-loopback integration snapshot |Full headless1220, including225 adapter+owned-loopback cases; mocks/sockets, not native Burp |
| Main clean locked153-file revision1 |Full Java1220 PASS / focused Python25 PASS |
| Main revision2 |One BODY-help correction plus regression, full Java1221 PASS |
| Main revision3 / isolated Swing |Clean Java1221 PASS. Real Xvfb+owned-WM Swing27 PASS at scale1 and27 at scale2, plus27 scale2-repeat; test-only stable-layout/click waits retain focus/scroll assertions. Not native or broad platform certification |
| Current Python / incident compatibility |Native harness27 + local-template18 PASS (actual upstream SKIP). Actual network-free217730… watcher output passed offline incident validation with nonempty top lists; not a native human export |

These are supplied integration records, **not runs made by this documentation
task**. Slices overlap; adding685+225+1221 would double-count. Headless `test`
excludes desktop tags. No native v2 phase was run: the fully isolated disposable
Burp attempt stopped at the first EULA, without agreement/extension loading.
The revision2/3 candidate reproducibility and requested final-audit gaps are
explicit in [VERIFICATION.md](VERIFICATION.md).

For a future **isolated frozen snapshot**, commands include:

```sh
./gradlew --offline --no-daemon --max-workers=2 clean test
# Focused investigations, not replacements for the full clean suite:
./gradlew --offline --no-daemon test \
  --tests '*GuardController*Test' --tests '*ListenerRegistryTest' \
  --tests '*ResponseWatcher*Test' --tests '*IntentBudgetTest' \
  --tests '*ProxyLoopbackTest' --tests 'dev.cairnguard.burp.*'
python3 -m unittest discover -s scripts -p test_native_burp_smoke.py
```

Reports under `build/test-results/` / `build/reports/` are local build outputs, not
new publishable source/evidence. Concurrent filtered reports can replace earlier
outputs; retain the frozen manifest/result association privately, not raw logs in
Git. Commands here do not authorize shared builds/native execution.

## Controller coverage and current contracts

### Project validity, strict migration and CAS

`GuardControllerTest` / `GuardControllerV2Test` use in-memory `ProjectAccess` with
fabricated projects and hooks for switch/load/save failures. They cover:

- Empty/blank storage starts new schema2 empty-scope defaults without implicit
  save. Valid same-project refresh retains baseline unless recovery is required.
- `PolicyCodec` rejects unsupported schema, missing/null/unknown/duplicate keys,
  wrong/fractional primitive types, oversized documents, trailing tokens and
  invalid disabled rules. Failure is typed policy-invalid/default-deny, not
  partially applied config or raw exception text.
- Strict frozen-v1 decoding gives **memory-only v2**, new detectors OFF, original
  rules/limits retained. `migrationView` original/migrated comparison and explicit
  CAS save only; no automatic legacy delete-string removal or v1 rewrite.
- Successful saves emit schema2; original project/revision CAS rejects stale or
  competing drafts. Uncertain/partial save latches `POLICY_SAVE_UNCERTAIN`; Resume
  cannot revive an older permissive cached policy. Verified reload/save repairs
  validity, then explicit resume is still required for the recovery/pause latch.
- Observed project switch/unavailability invalidates pending/prepared/admitted
  work even before UI refresh. A→B→A cannot revive old generations. Native
  persistence/project methods are separate calls, so fixtures do not establish
  Burp's atomic switch semantics or exclude an unobserved native ABA.

### Scope, optional inspection and EXEMPT

- Actual service host/scheme/port and untouched path establish scope, **not Host**
  or possibly header-derived request.url authority. An allowed actual destination
  with fuzzed Host passes; a spoofed Host cannot allow another actual destination.
- ALL-path `/c/;/main.do`, `/c/%2e/main.do` and nested/encoded/matrix/separator/
  malformed-percent variants survive unchanged. Internal routing aliases do not
  replace the forwarded target or impose an unsolicited sanitizer. Restricted
  scope/explicit blockScope and mandatory routing limits remain fail-closed.
- Unsupported charset/body/encoding, binary/multipart, malformed JSON/percent and
  optional capture bounds are **unavailable-inspection warnings**, not automatic
  denials for otherwise in-scope traffic. Explicit field-authored BLOCK rules
  still match available METHOD/PATH/QUERY/HEADER/BODY/JSON/FORM. Known positive
  ordinary OR/ANY branches remain usable; incomplete conditions cannot grant EXEMPT.
- EXEMPT wins ordinary BLOCK/ASK only; actual scope, lifecycle/pause, automatic
  heavy/circuit/fanout, budget/rate/capacity/shutdown still apply.
- New defaults contain DELETE-method only. Older tests' broad delete-string and
  hard malformed/unsupported-body assumptions were updated, **not retained as v2
  acceptance requirements**; explicit operator rule coverage remains.

### Admission, accounting and lifecycle

- ASK waits have only opaque references; no rate/concurrency permit before the
  human decision. Denial/expiry/interruption/stale click/project/policy/pause/OFF/
  shutdown cancels, including provisional-approved or approved-but-rate-queued work.
- Prepare/authorize are not sends. `commitDetailed` rechecks under mutation lock;
  only instance-owned one-shot Prepared can claim handoff. Forged/replayed
  projections cannot send/spend/mutate another evidence row.
- Watcher claims precede intent consume. Exact limit20 denies21st; other(run,intent)
  pairs remain separate. Concurrent final commits have exactly the bounded winners.
  Invalid/duplicate/incomplete tags reject only with budgets enabled; absent intent
  is unbudgeted and labels are untrusted. Disabling budgets preserves debt.
- No new quota is spent for local continuation factory/correlation/final watcher/
  lifecycle/budget failure. Conclusively-unsent logical tickets cancel; uncertain
  native dispatch is never refunded/recycled. EXEMPT/health/half-open handoffs count.
- Operator pause is retained across OFF/ON. OFF cancels old waits without approval,
  bypasses new scope/rules/availability/rate/content capture and counts handoffs only.
  Successful save does not silently restore protection; project uncertainty/restart
  ends OFF. Old protected native permits/correlation remain until actual response.
- Data-free listener registry checks before capture;4096 entries/30seconds,
  generation-bound single consumption. Unknown/duplicate(even identical)/expired/
  stale/capacity/invalid interface is UNKNOWN, not unselected bypass. No destination
  fallback. Known unselected has separate count and no new capture/permit/budget.

### Response watcher and evidence privacy

- Actual response body-length scalar is independent of inspection copy size,
  Content-Length, optional slots and incomplete flags. Unknown remains unknown in
  evidence, not fabricated wire bytes. Large/omitted responses can still trigger
  size gates from independently observed scalars.
- First heavy response is intact, subsequent route/alias attempts meet TTL overlay;
  actual-service circuit opens after5xx threshold, expiry is half-open eligibility,
  GET/HEAD single claim and30second cadence are enforced. Failed/unknown/missing
  probe reopens, local cancel does not refund cadence. Logical deadlines never
  close true native permits. Health GET bypasses only operator pause/circuit and
  never heals it; no query/body/ambiguous authored route.
- Fanout BLOCK/PAUSE/WARN, watcher capacity fences without evicting active
  enforcement, explicit release/ignore and retained-window incident/candidate
  statistics. Clearing diagnostics does not clear active overlays/probe debt.
- `RawTrafficStoreTest`, `EvidenceStoreWatcherMaskingTest` and
  `ResponseWatcherRemaskingTest`: human unmasked cache separate/bounded/project-bound,
  UTF8/HEX and truncation/omission; no raw in masked JSON/HAR/incident/logs.
  Response-only grants remask earlier watcher values/pending flights under the
  display/export lock. Changed policyUrl becomes non-actionable; old endpoints/
  aliases cannot revive a secret. No raw fallback or policy harvesting.
- Sealed immutable TrafficEntry covers v2 fields/tampering; stale retained export
  selections refresh to latest masking. Precise denial categories/typed causes,
  local vs upstream451, missing response, actual size/warnings and cumulative /
  retained/orphan counters are distinct from wire/delivery claims.

## Owned raw-loopback harness design

Each `ProxyLoopbackTest` harness owns a bounded **raw ServerSocket** on
127.0.0.1 / OS-assigned ephemeral port (byte-address construction, no DNS/wildcard).
It no longer uses generic URI/JDK HttpServer request parsing as a hidden path
sanitizer. The bounded request-line parser observes exact origin target spelling,
ordered captured headers and body, including malformed-percent pentest inputs.
It is a synthetic fixture parser, **not a general production HTTP proxy**.

A separate original fixture owns method/target/ordered headers/body; controller
gets only immutable RequestData. After `prepare -> authorize -> commitDetailed`,
transport connects to the **independently pinned owned address/port**, never an
untrusted URL, Host, redirect, proxy environment or DNS result. No retries,
fallback-to-direct or external destinations are supported.

The fixture parser bounds lines/headers/body, uses one Content-Length and no
Transfer-Encoding. Reply reader bounds64 headers/16KiB header text/64KiB body.
Connect/read deadlines are2/4seconds and latches/worker waits finite. Payloads are
synthetic and request fixtures bounded to1MiB.6MiB/oversized capture behavior lives
in separate native mocks/Python fixtures, not this small response reader.

### Non-arrival and fidelity assertions

- Explicit authored dangerous METHOD/PATH/QUERY/HEADER/BODY/JSON/FORM rules,
  empty scope/blockScope, denied ASK and adjacent stale commit produce **zero
  socket opens / zero additional owned hits**. An earlier admitted held request
  remains one real hit; tests do not misreport that as zero total traffic.
- Allowed all-path spellings, fuzzed Host and unsupported optional content reach
  the pinned fixture with exact request target/header values/body bytes. This is
  no longer an automatic unsupported-body/malformed-path block test.
- ASK opens no socket until the one-shot human simulation allows it. One allowed
  original fixture produces exactly one request.
- Allowed Authorization/Cookie/Proxy-Authorization/API-key, ordinary duplicates,
  JSON/form/text bytes and synthetic response/Set-Cookie are compared unchanged;
  masked evidence is separate. Raw fixture equality is **not Montoya/native wire
  identity**, HTTP2 framing, TLS bytes or another extension's mutation proof.
- Six workers send12 safe requests through one shared controller at global/host5RPS
  and concurrency2. First two handlers hold responses; two permits/four queued,
  no third admission before completion. Max active owned handlers2, all12 complete,
  active/queue end zero. Gaps use the package-private monotonic
  `Permit.admittedAtNanos()` observation (>=200000000ns), not rescheduled caller or
  server-arrival timestamps. Cross-host aliases/RR are separate RateGate tests.
- A held real reply beyond deadline quarantines its host without reusing a permit;
  only actual completion-owned close restores capacity. Other-host free-slot/global
  stalled-slots behavior is tested separately in RateGate, not inferred from one
  loopback host.

Permits remain through full response read **and** a conservative test-only owned
handler-completion rendezvous, preventing trailing cleanup from inflating fixture
concurrency. `controller.response()` observes/captures but never owns permit close.
A post-commit I/O error deliberately keeps its uncertain permit. Teardown closes
owned sockets, releases latches, joins owned acceptor/handlers/callers with finite
deadlines, then closes remaining synthetic permits only after owned work quiesces.
No installed watcher/service/background process is left behind.

## Native adapter tests are a separate synthetic layer

`ProxyGuardHandlerTest`, `NativeCaptureTest`, `ProxyV2Test`, `ListenerObserverTest`,
`BurpLifecycleTest` use pinned Montoya mocks and real component dependencies.
They cover original request/response/annotation identity, actual-service capture,
optional flags/actual bytes, final exact reasons/typed451, local factory no-spend,
message ID collision, callback/correlation bounds and reentrant unload/registration.
Observer is registered before HttpHandler and deregistered on error/close, with
late handles cleaned. `javap` confirms API presence only.

**Neither mocks nor listener-registry tests prove the real product's observer /
HttpHandler message IDs are shared or ordered as assumed**, nor actual two-listener
no-capture, native response correlation or final exact-JAR behavior. Future native
acceptance must record those facts rather than infer them from these suites.

## Historical controller runs (2026-11-03)

The original controller task passed72 controller +27 loopback =99 cases in five
forced-rebuild repeats. A concurrent full521 run had two lifecycle failures while
those99 passed; later integration fixed them and full584 passed. These are
**historical** results of the earlier controller/global quarantine/default-body
semantics, not current v2 full-suite counts. Subsequent PAUSED/reason fixes preserved
exact finite categories instead of the old generic evidence fallback.

Original fixes included strict primitive policy decoding, oversized whitespace
bounds, uncertain-save recovery latching and categorical project lookup errors.
Production now routes strict storage through PolicyCodec and typed lifecycle.
Those fixes never justified resetting true permits or authentication state.

## Remaining limits

No actual HTTP Proxy listener, installed Montoya session, HTTPS/CA/CONNECT/HTTP2,
opaque TLS/WebSocket frames, live CAIRN/Pi/model/report E2E, egress enforcement,
Professional disk project, native project-switch atomicity, all-scale desktop
acceptance or final implementation audit is established here. Fabricated auth
fields are fidelity/privacy fixtures, not login/session tests. This documentation
leaves native/audit/release work **in progress**, not approved or complete.
