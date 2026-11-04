# V2 source integration contracts — unreleased

These are the APIs in the **current source worktree**, not the contract of the
published preview or proof of installed/native behavior. Java package:
`dev.cairnguard`. Source is authoritative. See [VERIFICATION.md](VERIFICATION.md)
for the frozen-snapshot results and pending acceptance gates. No worker/network
control API, outbound HTTP client, authentication mutation or automatic policy
save is introduced by these interfaces.

**Per-port protection H is explicitly DEFERRED by the user, not a current gate or PASS.** Current delivery protects all Proxy listeners and rejects new nonempty UI/JSON selections. Legacy data remains fail-closed until explicit confirmed clearing. The old cross-namespace ID assumption was falsified; trusted registry tests are model seams, not a production Montoya identity producer. See [current scope/results](ALL_LISTENERS_ACCEPTANCE.md) and [historical findings](V2_NATIVE_FINDINGS.md).

## Models and strict project policy

### `model.GuardConfig`

```java
record GuardConfig(int schemaVersion, List<ScopeEntry> allowScope,
    List<ScopeEntry> blockScope, List<Rule> rules, Mode defaultMode,
    Limits limits, List<Integer> guardListenerPorts)
```

The original six-argument constructor remains; it supplies an empty listener list
and **does not silently upgrade** its schema argument. Collections are copied.

- `Mode { EXEMPT, ALLOW, BLOCK, MONITOR, ASK }`. EXEMPT is a v2 rule action,
  never a default mode. Ordinary priority is **EXEMPT > BLOCK > ASK > ALLOW**;
  MONITOR records only. EXEMPT does not override scope, lifecycle, pause,
  automatic protections, budget, pacing, queue/capacity or shutdown.
- `Field { METHOD, URL, PATH, QUERY, HEADER, BODY, JSON, FORM, ANY }`,
  `Match { CONTAINS, EXACT, REGEX }`, `Logic { LEAF, AND, OR }`.
- `ScopeEntry(boolean enabled, String host, String scheme, int port,
  String pathRegex)`: actual service host/scheme/port + request-target path,
  not Host/`:authority`. Exact/IDN-canonical host or proper-subdomain wildcard;
  `http`/`https`/`any`; port `0` means any; path regex full-matches path only.
  Empty path regex means **all paths**; empty allowlist allows nothing.
- `Rule(String id, String name, boolean enabled, Mode mode, Condition condition)`.
- `Condition(Logic logic, Field field, String name, Match match, String value,
  boolean caseSensitive, List<Condition> children)`. AND/OR contain children,
  LEAF contains match metadata. Named selectors are for HEADER/QUERY/JSON/FORM;
  JSON uses RFC6901 pointers. No negative-condition operator is provided.
- `FanoutAction { BLOCK, PAUSE, WARN }`.
- `Circuit5xx(long windowMillis, int threshold, long openMillis, int halfOpenProbe)`.
- `Fanout(long windowMillis, int distinctPaths, FanoutAction action)`.
- `ProbePath(String scheme, String host, int port, String path)`.
- `PathByteLimit(String scheme, String host, int port, String path, long maxBytes)`.

```java
record Limits(int globalRps, int perHostRps, Map<String,Integer> hostRps,
    int maxConcurrent, int maxQueued, long queueTimeoutMillis,
    long approvalTimeoutMillis, long requestTimeoutMillis,
    long perPathMaxResponseBytes, long autoBlockMillis,
    Circuit5xx circuit5xx, Fanout fanout, int perIntentMaxRequests,
    boolean healthProbePassthrough, List<ProbePath> healthProbePaths,
    List<PathByteLimit> heavyPathLimits)
```

The original eight-argument `Limits` constructor disables new detectors/budgets/
health exceptions: bytes `0`, TTL `600000`, circuit/fanout `null`, intent `0`,
health `false`, route lists empty. This is also the **v1 migration** behavior.
It is intentionally different from a **new v2 profile**:

| New-profile default | Value |
|---|---|
| Scope / default action | No allowed targets / ALLOW inside valid scope only |
| Rules | Enabled exact DELETE-method BLOCK only; **no broad delete-string rule** |
| RPS / in-flight / queue | Global5, host5, concurrent5, queued100 |
| Queue / approval / request timeout | 30000 / 30000 / 60000 ms |
| Response size / overlay TTL | 5 MiB / 600000 ms |
| Circuit | Five5xx in60000 ms, open600000 ms, one half-open probe |
| Fanout | 100 distinct paths in60000 ms, WARN |
| Intent / health / listener selection | Off / off / empty = all Proxy listeners protected |

`guardListenerPorts` retains the **legacy/future** actual-inbound-listener model,
not target server ports: at most16 unique integers1–65535. Empty protects all.
Current UI/whole-policy JSON cannot create/change a nonempty selection; unrelated
edits preserve legacy values. Explicit confirmed clearing alone switches it to all
listeners. With the current native adapter, legacy nonempty selection rejects before native content capture:
there is no verified shared-identity producer. Core known-unselected bypass needs
trusted proof and is synthetic-only, not successful H. See native seam below.
Authored health/byte-limit routes remain strict exact scheme/host/port/path,
without query/fragment or ambiguous routing aliases. Relaxed pentest **traffic**
acceptance is not permission to write ambiguous probe configuration.

### `model.PolicyCodec` / `Json`

- `Decoded(GuardConfig config, boolean migrationPending, String originalDocument)`.
- `decode(String)` dispatches strict schema1/2; null/blank means new v2 defaults.
  Maximum document is2097152 characters. Exact shapes include all required keys,
  even explicit nullable detector fields in v2. Missing/unknown/duplicate keys,
  null/wrong primitive types, fractional integers, trailing tokens and invalid
  disabled entries fail categorically as `INVALID_PROJECT_POLICY`.
- V1 loads through a frozen legacy DTO into an in-memory v2 policy. It preserves
  all original rules (including legacy broad delete-string), scope and limits;
  new protections stay off. **Load/status/observation never writes the migration.**
- `encode(GuardConfig)` / `toV2(GuardConfig)` validate; explicit production saves
  emit full schema2. `encodeLegacy` exists for old Java fixtures only.
- `removeLegacyDeleteString(config)` is an **optional human-selected** operation
  removing only the exact enabled original `delete-string` rule/condition/name.
  Modified, disabled and look-alike rules remain; normal saves do not call it.
- `Json.MAPPER`, `write(Object)`, `read(String, Class<T>)` provide bounded strict
  parsing, without default typing. Production policy storage uses `PolicyCodec`,
  not direct deserialization into today's record.

`ProjectAccess` exposes `Ref(id,name)`, `current()`, `load()`, `save(json)`.
`MontoyaProjectAccess` uses project-scoped extension data, not global preferences.
The legacy storage key prefix remains for compatibility; it does not mean the
stored document stays schema1. Native project operations are separate calls;
observed project/revision checks are not an atomic Burp project-switch guarantee.

### Request, decision, attribution and typed cause

```java
record RequestData(String method, String url, String host, int port,
    boolean secure, List<Header> headers, byte[] body,
    boolean headersComplete, boolean bodyComplete)
record Decision(Mode mode, String reason, List<RuleHit> hits,
    List<String> inspectionWarnings)
```

`Header(name,value)`, `header(name)`, `bodyLength()` and defensive `body()` copies
remain. `MAX_INSPECT_BYTES=1048576`. The original seven-argument request constructor
sets both completeness flags true; the original three-argument decision constructor
sets warnings empty. These are **inspection copies**, never native replacements.
`RuleHit(id,name,mode)` contains no regex captures.

`RequestAttribution(intentId,runId,valid)` parses unchanged `X-Cairn-Intent` /
`X-Cairn-Run`. Absent is `-`, invalid is `?`; at most64 ASCII alphanumeric or
`._:-` characters, no duplicate tag headers. These are **untrusted client labels**,
not identity or an authorization boundary. Incomplete headers cannot prove tags
absent/unique; an enabled budget rejects that uncertainty. The controller retains
keyed hashes, not raw labels, across waits.

`GuardState` is typed independently of UI note text:
`PROTECTED`, `PAUSED_BY_OPERATOR`, `POLICY_INVALID`, `POLICY_SAVE_UNCERTAIN`,
`PROJECT_UNVERIFIED`, `SHUTDOWN`, `CIRCUIT_OPEN`, `OVERLAY_BLOCK`, `INTENT_BUDGET`,
`LISTENER_UNVERIFIED`, `CAPACITY`, `IN_FLIGHT_STALLED`.

`DenialReasons.ALL` is the finite adapter/evidence vocabulary; `category(value)`
returns `ADAPTER_ERROR` for unknown inputs. New categories include
`HEAVY_ENDPOINT_AUTO_BLOCKED`, `CIRCUIT_OPEN`, `FANOUT_SUSPECTED`,
`RESPONSE_WATCHER_CAPACITY`, `INVALID_INTENT_TAG`, `INTENT_BUDGET_EXCEEDED`,
`INTENT_BUDGET_CAPACITY`, `LISTENER_UNVERIFIED`. `PAUSED` / `IN_FLIGHT_TIMEOUT`
remain preserved in masked JSON/HAR. Legacy names such as `AMBIGUOUS_PATH`,
`AUTHORITY_MISMATCH` or `UNSUPPORTED_BODY` in the vocabulary are **not** a mandate
for automatic denial of pentest paths, Host fuzzing or optional content failures.

## Policy API and the latest scope/inspection contract

`PolicyEngine.validate(config)`, `evaluate(config,request)`,
`canonicalHost(host)` and static `routingPaths(request)` are network-free.
Validation includes disabled entries, strict limits and bounded RE2/J programs.
Expected invalid policy/mandatory-target errors become categorical BLOCK decisions.

- Actual destination service and the untouched target path drive scope. A fuzzed
  Host/`:authority` neither denies an allowed actual service nor permits another.
  URL-rule authority is reconstructed from the **actual destination**.
- ALL-path scope accepts `/c/;/main.do`, `/c/%2e/main.do`, nested/encoded dot,
  matrix and separator variants **unchanged**. There is no blanket pre-scope
  `AMBIGUOUS_PATH` sanitizer. At most8 bounded raw/decoded/conservative normalized
  aliases are internal scope/rule/watcher views, never a forwarded target.
- A restricted allow entry must cover every known routing view; a matching block
  view wins. Incomplete decoding can pass explicit all-path scope with
  `PATH_INTERPRETATION_INCOMPLETE`, but cannot prove restricted scope or grant
  path-dependent EXEMPT. Unresolved destination-matching block-path constraints
  still fail closed. Common universal path expressions are recognized, not every
  arbitrary RE2 expression's mathematical universality.
- Optional inspection is demand-driven. Unsupported charset/media/encoding,
  binary/multipart, malformed JSON/percent data, incomplete optional capture or
  optional capacity limits produce warnings for affected fields, **not an
  automatic451**. Scope uncertainty and mandatory enforcement capacity still deny.
- Unavailable inspection is not a successful evaluation. Known positive ordinary
  PATH/ANY/OR matches may still enforce a rule. **No EXEMPT is granted from a
  condition with unavailable content**, even if another OR branch is true.
- Examples of fixed warnings: `HEADERS_INCOMPLETE`, `BODY_INCOMPLETE`,
  `PATH_INTERPRETATION_INCOMPLETE`,
  `JSON_INSPECTION_UNAVAILABLE_MALFORMED_JSON`. They are diagnostic categories,
  not payload/error text. See [POLICY.md](POLICY.md) for inspection/work bounds.

## Controller: prepare, wait, final handoff, response

`GuardController(ProjectAccess)` implements `GuardUiAccess`, `AutoCloseable`.

- `Prepared prepare(RequestData)` / `prepareRejected(reason)`.
- `Admission(boolean allowed,String reason,RateGate.Permit permit)` from
  `authorize(Prepared)`; `reject(Prepared,reason)` records a local denial.
- `CommitResult(boolean allowed,String reason) commitDetailed(Prepared)`;
  compatibility `boolean commit(Prepared)` delegates. **Use the actual final
  reason**, not a blanket `FINAL_CHECK_REJECTED` for overlay/budget failures.
- `Denial(String guardState,long policyRevision,String overlayId)` from
  `denial(Prepared,reason)`; fixed typed provenance, never inferred from note text.
- `boolean current(Prepared)` is a short current-state predicate, not admission.

`Prepared` is a final accessor-compatible **class**, not a record. Original
constructor `(evidenceId,projectId,revision,rateHost,decision)` remains. Additive
accessors are `endpoint()`, `attribution()`, `healthProbe()`. Only controller-issued
objects have one-shot authorization/commit provenance. Caller-constructed BLOCK
projections may deny categorically but cannot acquire a permit, send or mutate
another entry. No request body, raw URL/path, native message or continuation is
retained in Prepared/approval waits. Native callback ownership is separate.

```text
nativeMode(messageId) BEFORE capture
  protected -> prepare -> hard checks / ASK (no rate permit)
            -> watcher/budget advisory rechecks -> rate permit
            -> build non-sending original-object continuation
            -> install bounded flight -> commitDetailed under mutation lock
               -> watcher claim FIRST -> intent consume -> FORWARDED
            -> return native continuation
  bypass    -> build original-object continuation -> commitPassthrough -> return
  rejection -> data-free local451 or fail-closed drop
```

All rejecting local work precedes quota consumption. A final watcher/budget/policy
failure cancels a conclusively-unsent logical watcher claim and closes only that
unsent native permit; no new intent quota is spent. Final commit is handoff
accounting, **not target delivery**. Uncertain dispatch is not refunded/recycled.

Responses:

```java
void response(String id,int status,List<RequestData.Header> headers,byte[] body)
void response(String id,int status,List<RequestData.Header> headers,byte[] body,
              long actualResponseBytes)
void response(String id,int status,List<RequestData.Header> headers,byte[] body,
              long actualResponseBytes,boolean headersComplete,boolean bodyComplete)
void localResponse(String id,byte[] body)
```

Native callers use the seven-argument overload. Observe native status and
`body().length()` independently of optional copying/slots; never infer size from
Content-Length or a zero-filled omission sentinel. `-1` means unknown, not zero
measured wire bytes. Scalars describe the Montoya body view, not headers/TLS/framing.
The four-argument compatibility overload derives only a bounded copy's size and
cannot establish an omitted large response's actual size.

The controller learns response secrets in masked evidence **first**, synchronously
refreshes structured watcher display with current fingerprints, then observes
status/size under the same lock as watcher display/export. Old-project response
tickets cannot affect the new epoch. Tickets are bounded4096 logical observations
with deadlines, **not native permits**. Abandonment/expiry never recycles a native
permit. `response()` itself does not own/close a RateGate permit.

## Availability, accounting and pacing APIs

### `ResponseWatcher`

Construct with `Limits` (public bounded clock/capacity seams also exist). Public API:

- `Endpoint endpoint(RequestData,String redactedUrl,List<String> routingPaths)`.
  Actual service + query-free routing aliases become keyed HMAC identities;
  only already-masked display metadata is retained.
- `update(Limits)` retains same-project protections/debt; `reset()` starts a new
  epoch. `check(endpoint,health)` is advisory. `commit(endpoint,health,evidenceId)`
  returns an opaque `Ticket`; evidenceId is not retained by the watcher.
- `observe(ticket,status,bytes)`, `cancel(ticket)` (conclusively unsent),
  `abandon(ticket)` (logical missing response only).
- `overlays()`, `release(id)`, `releaseAll()`, `candidates()`, `ignoreCandidate(id)`,
  `snapshot()`, `incidentJson(fromMillis,toMillis)` and diagnostic `clearEvidence()`.
- `refreshDisplay(UnaryOperator<String>)` synchronously remasks individual display
  **values** and pending flights. Never apply it to JSON/schema keys or retain the
  sanitizer across waits. Hashed privacy fences prevent old endpoints/aliases
  reviving response-discovered secrets; saturation makes display opaque without
  evicting enforcement state.

Projections:

```java
record Gate(boolean allowed,String reason,GuardState guardState,String overlayId)
record Overlay(String id,String kind,String host,String path,
               long createdAt,long expiresAt,String reason)
record Candidate(String id,String host,String path,String policyUrl,long maxBytes,
                 long p95Bytes,long count,long lastSeen,long count5xx)
```

`Endpoint` is an immutable class with original five-field constructor/accessors
`hostKey,pathKeys,host,path,policyUrl`. That constructor is display-only/fail-closed;
only the factory grants instance/epoch/safe-method admission provenance. `Ticket`
is opaque with `epoch()`/`halfOpen()`. `Rejected` exposes reason/guardState/overlayId.
Overlay IDs are UUIDs; candidate IDs are opaque keyed route identifiers, not URLs
or authentication. Do not assume candidates are UUIDs.

- Size `>` configured nonzero bound installs a TTL route overlay **after** the
  response; the first heavy response is not prevented, cut off or replaced.
  A sole exact zero override disables size detection there. Active overlays
  survive detector disabling/settings/OFF until expiry or explicit release.
- Circuit counts5xx per actual service. Open expiry permits one GET/HEAD half-open
  claim at most once per service/30seconds, not automatic healing.2xx–4xx closes;
  5xx/unknown/missing response reopens. Local cancel does not refund cadence.
- Fanout counts query-free route identity within its window; BLOCK is service-local,
  PAUSE is an automatic global overlay, WARN is a diagnostic episode. These are
  not operator pause and do not persist policy.
- An exact configured, bodyless, queryless **GET** health exception bypasses only
  operator pause/circuit. It still obeys lifecycle/scope/rules/ASK/heavy/fanout/
  budget/rate/capacity; its response never heals a circuit.
- Bounds:1024 services,2048 path keys/candidate metadata,1024 protections including
  a reserved capacity fence,4096 flights/events,8192 scalar observations,16 route
  aliases. Active protections are never evicted to admit traffic.
- Candidates use retained24-hour observations: maximum/count/lastSeen/5xx are exact
  for retained observations, p95 is a log2-histogram **upper-bound approximation**.
  Unknown byte scalars contribute zero to watcher aggregates and cannot establish
  a real zero-size response or trigger a size overlay. Retention/eviction is visible.
- `policyUrl` is an optional already-masked, query-free, unchanged actual-service
  route for a human draft, not a raw URL getter. Masked/changed/unrepresentable
  routes have `policyUrl=""`; no automatic policy save or raw fallback is allowed.
- Incidents accept `[from,to)` up to24hours and expose `window`, `events`, top20
  `top5xx`/`topBytes`, `complete`, `truncated`, `approximate`, `approximation`,
  `retention`. Completeness is retained-window coverage, not lifetime/wire proof.
  Clears, ring loss, out-of-retention windows or wall-clock regression constrain it.

### `IntentBudget`, `RateGate`, `ApprovalQueue`

`IntentBudget.check(attribution,limit)` is advisory; `commit` checks and increments
only at final protected handoff, including EXEMPT/health/half-open. Limit20 denies
the21st committed pair. Absent intent is unbudgeted; invalid/duplicate/incomplete
tags fail only when enabled. At most4096 keyed(run,intent)pairs; no eviction,
automatic reset/refund or raw-label index. `reset()` is explicit/project-epoch only;
zero limit suspends accounting without erasing debt. `snapshot()` is aggregate-only.

`RateGate(Limits)`, `update`, `acquire(host,BooleanSupplier)` -> `Permit`,
`snapshot`, `close` remain. Checked `Rejected.reason()` is one of
`QUEUE_TIMEOUT`, `QUEUE_FULL`, `SHUTDOWN`, `POLICY_CHANGED`, `IN_FLIGHT_TIMEOUT`,
`HOST_CAPACITY`. Global+canonical-host monotonic no-burst pacing uses per-host FIFO
and eligible round-robin, **not global FIFO**. A stalled native permit quarantines
its host; other hosts may use genuinely free global slots. If stalled permits alone
pin maxConcurrent, all hosts fail. Never recycle permits on timeout/close/update.
Status includes bounded top64 host metrics/recent128-admission p95 wait samples;
these are human operational data, not wire arrival measurements. See
[RATE_APPROVAL.md](RATE_APPROVAL.md) for queue fairness/limits.

`ApprovalQueue.await(evidenceId,projectId,timeout,BooleanSupplier)` ->
`Result(allowed,reason)`; `decide`, `snapshot`, `cancelAll`, `close` remain.
`Pending(id,evidenceId,projectId,createdAt,expiresAt)` has no request/URL/body.
At most100 provisional waits, monotonic expiry, no rate permit during ASK. A click
is one-shot and still subject to cancellation/expiry until consumed.

## Native listener / OFF seam and local451

- `recordListener(int messageId,String listenerInterface)` is a data-free trusted
  synthetic/future-bridge seam. Production does NOT call it: `ListenerObserver`
  only continues original objects/annotations and reads no ID/listener/content.
  Native Proxy and HTTP numeric IDs or annotations are not a shared identity.
- `ListenerRegistry.record(id,interface,generation)`, `consume(id,generation)`,
  `reset`, `snapshot`:4096 entries,30second TTL, strict host:port / bracketedIPv6.
  Duplicate (even identical), missing, expired, stale or capacity mappings are
  UNKNOWN, never evidence of an unselected listener.
- `nativeMode(int messageId)` checks **before capture**: protected `(null,null)`,
  data-free rejection, or controller-issued `PassthroughToken`. Global OFF comes
  first. Empty ports protects all. Supplied trusted model proof can protect a
  selected or bypass an unselected port; production supplies no such proof, so
  every configured restriction rejects `LISTENER_UNVERIFIED` before native capture.
  A fixed synthetic UNKNOWN/redacted omission record is not native content capture.
- Compatibility `nativeMode()` / `passthroughToken()` remain; no-ID cannot prove
  a selected/unselected listener when ports are restricted.
- `PassthroughToken` is a final class with original `(projectId,revision)` and
  additive `(projectId,revision,kind,listenerPort)` constructors/accessors;
  `BypassKind { OFF, UNSELECTED_LISTENER }`. Only instance-issued tokens can pass
  `commitPassthrough(token)`. Build the non-sending action before this final check.
  OFF and unselected counters are separate, saturating handoff counts.

Only `ToolType.PROXY` enters protection. `BurpLifecycle` registers the observer
before HttpHandler and deregisters both/tab/unload on normal/error/reentrant close,
including late registration handles. Source wiring is not identity proof. Native
checks falsified shared Proxy/HTTP ID and annotation-identity assumptions. H remains
FAILED/UNSUPPORTED; accepting equal numbers would not fix it. Ordinary HTTP-handler
request/response flight correlation remains separate.

Native allows continue the **same request/response objects and annotations**.
Native bounds are128 protected callbacks,8 optional inspection slots,100 flights;
no new OFF/unselected flight/permit/correlation/content is retained. Losing an
optional inspection slot omits content with flags, not an automatic scope denial.
True permits close only on matching actual Proxy response or conclusively-unsent
failure. Unload/deadlines do not prove completion.

The local451 preserves original key order and adds only typed fields:

```json
{"source":"cairn-proxy-guard","outcome":"blocked","reason":"CIRCUIT_OPEN","evidenceId":"00000000-0000-0000-0000-000000000001","retryable":false,"guardState":"CIRCUIT_OPEN","local":true,"policyRevision":7}
```

`overlayId` is appended only for a safe opaque UUID. `guardState` is enum-only,
revision nonnegative, missing evidence uses `unavailable`. No URL/host/path/tag/
pattern/exception enters the denial document. Header `X-Cairn-Guard: blocked`,
JSON content type and no-store distinguish it from a target451. Spoof failure drops,
never allows; an ambiguous duplicate native message ID is drop-only to protect
its older permit. Montoya baseline2026.7 supports spoof (introduced2026.4), but API
compatibility/mock identity is not installed-Burp/wire proof.

## Evidence and human-only UI boundary

`EvidenceStore` owns **two separate bounded memory stores**: sealed MASKED
`TrafficEntry` evidence and UNMASKED human-local `RawTrafficStore`. No native
objects, automatic disk persistence or export/log path receives raw UI content.
See [EVIDENCE.md](EVIDENCE.md) for masking/seals/bounds.

Masked API: `begin`, `outcome`, `response` (four args and completeness-six args),
`context(id,outcome,guardState,overlayId)`, `responseBytes(id,long)`, `entry(id)`,
`snapshot`, `bookmark`, `stats`, `clear`, `exportJson`, `exportHar`.
`displaySanitizer(id)` is ephemeral current-fingerprint masking of individual
structured watcher values; disposed evidence returns opaque display, not raw.

`TrafficEntry` retains original constructors/accessors plus `intentId`, `runId`,
`outcome`, `guardState`, `overlayId`, `responseBytes`, `inspectionWarnings`.
`Message(headers,body,mimeType,bodyOmitted,truncated,present)` and rendered
`request()`/`response()` are always masked. JSON/provenance schemaVersion is2;
HAR1.2 carries v2 additions in `_cairnGuard`. A seal rejects foreign/forged entries
and stale retained selections refresh to latest masking. Raw data is not a field
on this serializable/exportable model.

Human-local getters: `rawRequest(id)`, `rawResponse(id)`, `rawUrl(id)`,
`rawCaptureInfo(id)` and `clearRawUi()`. They may be unavailable/truncated/omitted;
label `UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF`. Raw cache is project-bound, cleared
on uncertainty/switch/close/clear, removed with evidence eviction and independently
bounded. Existing records can remain across OFF; **new OFF/unselected content is
never captured**. Raw getters must never feed runtime watcher display, exports,
logging or policy harvesting.

`GuardUiAccess` is **in-process human UI only**:

- Existing `config`, `updateConfig(config,expectedProjectId,expectedRevision)`,
  `status`, `traffic`, `approvals`, `decideApproval`, `bookmark`, `exportJson`,
  `exportHar`, `clearEvidence`, `pause`, `refreshProject`.
- `passthrough(enabled,expectedProjectId,expectedRevision)` explicitly turns
  protection OFF/ON, runtime-only. It cancels old waits without approving them,
  preserves operator pause, protections/debt and true permits across OFF/ON.
- Additive defaults implemented by controller: `overlays`,
  `releaseOverlay(id,projectId,revision)`, `releaseAllOverlays(projectId,revision)`,
  `heavyCandidates`, `ignoreCandidate(id,projectId,revision)`,
  `resetIntentBudgets(projectId,revision)`, `exportIncident(from,to)`,
  `migrationView()` and the four raw getters.

`migrationView` returns `pending`, `original`, `migrated`; no implicit write.
Status retains old keys plus `guardState`, `pauseCause`, `operatorPaused`,
`policyRevision`, `migrationPending`, `guardListenerPorts`, `reasonCounters`,
`watchers`, `intents`, `listeners`, `watcherTickets`, `unguardedListenerCount`.
`revision` / `policyRevision` are the runtime generation, including mode changes,
not just persisted-save counters. `paused=false` while OFF does not erase
`operatorPaused`; ON returns to the retained pause. Lifecycle/recovery failure
requires verified reload/save and explicit resume, never a generic bypass.
Same-project saves retain overlays/budget debt. Project epoch change/uncertainty
resets watcher/budget/listener/tickets/raw UI, **never native permit ownership**.
See [RUNTIME_UI_CONTRACT.md](RUNTIME_UI_CONTRACT.md) for confirmation/CAS behavior.

## Boundaries not established by these contracts

No complete wire capture, mandatory egress enforcement, strict remote-arrival RPS,
server-semantic parsing, authenticated worker quota, TLS-pass-through/CONNECT/
WebSocket-frame coverage, native HTTP2 matrix, Professional disk-project behavior,
CAIRN/Pi/model/report E2E or final independent implementation approval is implied.
Other extensions/native layers can alter traffic after this callback. Historical
preview hashes and native runs do not certify this unreleased source.
