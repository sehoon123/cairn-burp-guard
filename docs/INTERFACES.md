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
    List<PathByteLimit> heavyPathLimits, List<ProbePath> circuit5xxExceptions,
    boolean heavyResponseEnabled, List<ProbePath> fanoutExceptions)
```

0.2.0 appends three fields (19 total). The 8-, 16- and 17-argument constructors
remain compatibility shapes: they mean no circuit/fan-out exceptions and
`heavyResponseEnabled=true`. Production copiers (settings editor, candidate N MiB,
overlay exception, controller validation) use the full constructor so authored
detector settings are never dropped. Exception lists hold at most 16 strict exact
routes each (canonical duplicates rejected); `heavyResponseEnabled=false` keeps the
authored default/route byte limits but disables ALL heavy actuation.

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
| Large-response master | ON (`heavyResponseEnabled=true`) |
| Circuit | **OFF** (`circuit5xx=null`, optional). When a human turns it on the editor proposes five5xx in60000 ms, open600000 ms, one half-open probe |
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
  emit full schema2. `encodeLegacy` exists for old Java fixtures only and refuses a
  policy carrying heavy=false or nonempty exceptions (never drops them silently).
- Optional schema-2 fields, and ONLY these: `limits.circuit5xxExceptions` and
  `limits.fanoutExceptions` (absent = empty; present must be a nonnull array of
  exact `{scheme,host,port,path}` objects) and `limits.heavyResponseEnabled`
  (absent = true; present must be a JSON boolean). Encode OMITS an empty list and a
  true master, so a policy with only default detector settings keeps the first
  schema-2 shape that older readers accept; a policy with heavy=false or a nonempty
  exception list needs this (or a newer) reader. V1 rejects all three, even
  true/empty. Every previously required field stays required; there is no schema 3.
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
    boolean headersComplete, boolean bodyComplete, String nativeTarget)
record Decision(Mode mode, String reason, List<RuleHit> hits,
    List<String> inspectionWarnings)
```

`Header(name,value)`, `header(name)`, `bodyLength()` and defensive `body()` copies
remain. `MAX_INSPECT_BYTES=1048576` is the **policy inspection** bound only (larger
bodies are unavailable to rules), never a capture limit. The original seven- and nine-argument request
constructors remain; seven arguments set both completeness flags true. They leave
`nativeTarget=null` for legacy URL-derived target handling. Native capture instead
supplies the complete, untouched `request.path()` as `nativeTarget`, including an
empty/non-origin-form target. It is transient inspection data, never a Prepared or
watcher display field. The original three-argument decision constructor sets
warnings empty. These are complete **inspection copies** (no capture quota), never native replacements.
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
remain preserved in evidence JSON/HAR. Legacy names such as `AMBIGUOUS_PATH`,
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
  `AMBIGUOUS_PATH` sanitizer. At most9 bounded raw/decoded/conservative normalized
  views are internal scope/rule/watcher inputs, never a forwarded target. Incomplete
  non-origin-form targets retain the untouched first view plus a slash-rooted alias;
  raw controls, DEL/C1 and lone surrogates likewise mark routing incomplete rather
  than imposing an automatic path sanitizer.
- A restricted allow entry must cover every known routing view; a matching block
  view wins. Incomplete decoding can pass explicit all-path scope with
  `PATH_INTERPRETATION_INCOMPLETE`, but cannot prove restricted scope or grant
  path-dependent EXEMPT. Unresolved destination-matching block-path constraints
  still fail closed. Common universal path expressions are recognized, not every
  arbitrary RE2 expression's mathematical universality.
- Privileged EXEMPT PATH/URL leaves must match **every** routing view, including
  the routing part of ANY. Ordinary BLOCK/ASK rules can match any known view. URL
  views use the actual service authority with every routing alias and the available
  raw/decoded query views. A candidate exact-URL BLOCK therefore also sees known
  dot/matrix/encoded aliases; malformed optional queries cannot grant URL EXEMPT.
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
- Warning provenance: `HEADERS_INCOMPLETE`/`BODY_INCOMPLETE` record optional
  capture completeness for every request, whether or not a rule needed the field.
  Only `<FIELD>_INSPECTION_UNAVAILABLE_<CATEGORY>` shows that an enabled rule
  demanded that field and it could not be evaluated. The human request table and
  detail (`UiText.warnings`) render these as separate fixed labels (detail also
  lists the recognized fixed IDs) and show unknown/literal IDs plainly under a fixed
  "unknown code" label; there is no label-count cap. Evidence/export keep every supplied
  warning verbatim. `<FIELD>_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY` means no bounded
  inspection slot was free: only that demanded condition is unevaluated; the copy is complete.

## Controller: prepare, wait, final handoff, response

`GuardController(ProjectAccess)` implements `GuardUiAccess`, `AutoCloseable`.

- `Prepared prepare(RequestData)` / `prepareRejected(reason)`. Adapter overload
  `prepare(RequestData, boolean contentInspectionAvailable)`: `false` (no bounded
  inspection slot) still records the complete copy and evaluates scope/METHOD/PATH/
  URL/QUERY, but optional HEADER/BODY/JSON/FORM conditions are unavailable (never
  EXEMPT-granting, never an automatic denial). `PolicyEngine.evaluate(config, request,
  boolean)` is the matching policy overload; the two-argument forms mean `true`.
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
The four-argument compatibility overload uses the supplied complete copy's length (any
size). After `close()` responses are ignored (nothing new is recorded).

The controller records the original response, then observes status/size under the
same lock as watcher display/export (no masking or re-masking step exists). Old-project response
tickets cannot affect the new epoch. Tickets are bounded4096 logical observations
with deadlines, **not native permits**. Expiry marks logical failure once but
retains the bounded endpoint and host/path reservations until actual
observation, conclusively-unsent cancellation or epoch reset. A late ordinary
response still contributes heavy/5xx scalars at completion time; an expired
half-open response cannot heal or fail a replacement probe. Abandonment/expiry
never recycles a native permit. `response()` itself does not own/close a RateGate
permit. Exceptions before `authorize` transfers an acquired permit to its caller
close only that conclusively-unsent permit.

## Availability, accounting and pacing APIs

### `ResponseWatcher`

Construct with `Limits` (public bounded clock/capacity seams also exist). Public API:

- `Endpoint endpoint(RequestData,List<String> routingPaths)`.
  Actual service + at most9 query-free routing views (each at most16384 Java code
  units) become keyed HMAC identities. Bounds/nulls are checked before hashing;
  empty/non-slash first views, controls/C1 and lone surrogates are not rejected.
  HMAC input uses length-framed exact UTF-16 code units, avoiding charset replacement
  collisions. Display keeps the ORIGINAL actual-service host and untouched first routing
  view (never the fuzzed Host or URL authority); the query is not part of the route.
- `update(Limits)` retains same-project protections/debt; `reset()` starts a new
  epoch. `check(endpoint,health)` is advisory. `commit(endpoint,health,evidenceId)`
  returns an opaque `Ticket`; evidenceId is not retained by the watcher.
- `observe(ticket,status,bytes)`, `cancel(ticket)` (conclusively unsent),
  `abandon(ticket)` (logical missing response only).
- `overlays()`, `release(id)`, `releaseAll()`, `candidates()`, `ignoreCandidate(id)`,
  `snapshot()`, `incidentJson(fromMillis,toMillis)` and diagnostic `clearEvidence()`.
- `clearEvidence()` discards diagnostic history (events, observations, candidate
  ignores) and the display originals of active protections/flights and bumps a display
  generation, so an endpoint issued before the clear can be committed/completed later
  without resurrecting cleared display text. Enforcement keys, leases, reservations,
  deadlines, Seen/omission debt and protections are unchanged.
- Capacity seam: `ResponseWatcher(limits, nanoTime, milliTime, hostCapacity,
  pathCapacity, overlayCapacity)`; there are no event/observation capacities.

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
  Only a flight that was eligible at final commit (master ON, positive bound) and is
  of the current heavy generation can actuate. `heavyResponseEnabled=false`
  removes heavy overlays at once and bumps the generation (pre-OFF, while-OFF and
  late callbacks cannot actuate after re-enable). An AUTHORED zero route override
  (`PathByteLimit.maxBytes=0`) is a size exception: it bypasses only heavy gating,
  immediately, using the existing actual-service bounded-alias matching where any
  positive alias override beats zero and the smallest positive wins. Retained
  overlays stay (they may protect another alias view); a merely default 0 is not
  an exception and retained overlays keep their expiry. Raising/lowering a positive
  bound never rewrites or releases an existing overlay.
- Circuit counts5xx per actual service. Open expiry permits one GET/HEAD half-open
  claim at most once per service/30seconds, not automatic healing.2xx–4xx closes;
  5xx/unknown/missing response reopens. Local cancel does not refund cadence.
- Fanout counts query-free route identity within its window; BLOCK is service-local,
  PAUSE is an automatic global overlay, WARN is a diagnostic episode. These are
  not operator pause and do not persist policy.
- Mode transitions (0.2.0) detach logical episodes only, never Seen history,
  pending marks or omission debt: fan-out OFF removes every episode; BLOCK/PAUSE ->
  WARN removes enforcing episodes; BLOCK <-> PAUSE changes the existing episode's
  action/global flag in place (same id, source and TTL); WARN -> BLOCK/PAUSE retires
  WARN latches and a NEW final admission may retrigger from live history. Operator
  pause is never touched. Explicit release/expiry keep their old semantics.
- Exact exceptions: `circuit5xxExceptions` and `fanoutExceptions` match the sealed
  instance-issued exact-route HMAC of the ACTUAL service plus ONE complete unchanged
  routing view (no Host/:authority, no normalized-alias guessing, no wildcard/prefix);
  every method and every query variant is covered. A fan-out-excluded final admission
  creates no count, Seen/Mark, path retention, episode or omission debt and bypasses
  only fan-out service BLOCK / global PAUSE; it still reserves physical host/path/
  flight capacity and cannot bypass ENFORCING omission debt. Old marks finish with
  their original window when an exception is added or removed.
- Shared capacity fence (`capacityProtection`, no contributor ledger) is cleared on
  `update()` ONLY when heavy master is false, circuit is null, fan-out is null or WARN
  and no other protection remains: its producers (heavy observation, circuit
  sampling, enforcing fan-out commit) cannot run in that state and older flights are
  generation-fenced. Otherwise it is retained until expiry/explicit release. Real
  host/path/flight/native ownership and omission deadlines are never touched.
- Fanout history: one indexed route-identity budget equal to the path-key capacity
  (2048), shared by every service and action. WARN admissions pin paths only while
  physically in flight; BLOCK/PAUSE admissions keep window retention. When the
  budget is full, a WARN admission with a NEW identity is still admitted but its
  history is omitted (saturating `fanoutHistoryOmitted`), so fanout counts are
  retained-history lower bounds. Omission debt lasts until the latest omitted
  original window ends (monotonic clock; same-project save/OFF/detector disable/
  `clearEvidence`/`releaseAll` keep it, `reset()` clears it). Later cancellation of
  an unsent logical admission can conservatively leave its omission count/deadline;
  these are not exact sent-request counts, and there is no per-ticket refund ledger.
  While BLOCK/PAUSE is configured, active debt, or a new identity without a free history slot, denies
  `RESPONSE_WATCHER_CAPACITY`/`CAPACITY` before half-open claim or intent spend,
  for health/EXEMPT too. Entering BLOCK/PAUSE ends only stale WARN latches; it
  keeps history, debt, and every enforcing protection. Detached history held by
  unresolved flights is bounded by the 4096-flight ceiling and never reinserted.
- `snapshot()` adds `fanoutHistoryIndexed`, `fanoutHistoryCapacity`,
  `fanoutHistoryOmitted` (epoch cumulative), `fanoutHistoryIncomplete` (active
  debt) and diagnostic-only wall-clock `fanoutHistoryIncompleteUntil` (0 when
  inactive). These are separate from `candidatesIncomplete`. `incidentJson` adds
  `fanoutHistoryComplete` and `retention.fanoutHistoryOmitted`; any omission in the
  epoch makes `complete=false`/`truncated=true` for every window (conservative,
  not attributed to the selected window).
- Additive enforcement diagnostics: `fanoutHistoryEnforcing` is true only while
  debt is live AND the configured fanout action is BLOCK/PAUSE (false under WARN or
  a disabled detector, where debt is retained but not enforced), and
  `fanoutHistoryRemainingMillis` is the monotonic remaining debt rounded up (0 when
  inactive; wall time is never used). `capacityBlocked` keeps its meaning (the
  fixed capacity overlay only). These are watcher-local configuration: they do not
  include the controller's OFF/lifecycle bypass. `GuardController.status()` inserts
  `fanoutHistoryEnforcing -> CAPACITY` after `capacityBlocked` and `automaticPause`
  and before circuits/overlays, only while protection is ON; per-request gate
  order and reasons are unchanged. The UI shows an active gate only when
  enforcing and not OFF, otherwise "retained, not enforced" with the remaining time.
- Host-capacity reclaim (WARN or disabled fan-out only, and only when the 1024
  service-host limit is the blocker): `commit()` may discard ONE host whose state
  is purely idle diagnostic history - no in-flight or late ticket, circuit,
  enforcing (BLOCK/PAUSE) episode, retained 5xx sample, live 30 s probe cadence or
  pending Seen mark. Selection is shared with `gate()` feasibility, but `check()`
  never evicts or creates debt. Every discarded confirmed history adds one to the
  saturating `fanoutHistoryOmitted` and extends omission debt to its ORIGINAL
  monotonic deadline (never shortening existing debt), so the counter covers
  discarded host history as well as admissions omitted at the index limit. Retained
  paths, heavy/other protections, scalar observations and native reservations are
  untouched; BLOCK/PAUSE never reclaims and still fails closed.
- An exact configured, bodyless, queryless **GET** health exception bypasses only
  operator pause/circuit. It still obeys lifecycle/scope/rules/ASK/heavy/fanout/
  budget/rate/capacity; its response never heals a circuit.
- Enforcement bounds:1024 services,2048 path keys,1024 protections including
  a reserved capacity fence,4096 flights,9 route views. Diagnostic events,
  observations and candidates have **no** count or age bound (until clear/epoch/unload). Uncompleted expired flights count toward the same4096 ceiling, not a
  separate unbounded map. Active protections are never evicted to admit traffic.
- Candidates use every retained observation: maximum/count/lastSeen/5xx are exact,
  p95 is a log2-histogram **upper-bound approximation**. Unknown byte scalars
  contribute zero and cannot establish a real zero-size response or trigger a size
  overlay. Ignoring a candidate hides it only; new candidates still appear.
- `policyUrl` is an optional query-free actual-service route hint for a human draft,
  set only for one exact routing view whose path is a faithful ordinary URL path;
  otherwise `""`. No automatic policy save is allowed.
- Incidents accept any ordered `[from,to)` (`to > from`) and expose `window`, `events`,
  top20 `top5xx`/`topBytes`, `complete`, `truncated`, `approximate`, `approximation`,
  `retention` (`mode: UNTIL_CLEAR_PROJECT_OR_UNLOAD`, `startedAt`, `clockRegressed`,
  `fanoutHistoryOmitted`; legacy `…Dropped` flags are always false). Completeness is
  retained-window coverage, not lifetime/wire proof: a window before start/clear, a
  future end, clock regression or fan-out omission make it incomplete.

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
  A fixed synthetic `UNKNOWN https://capture-omitted.invalid/` record is not native content capture.
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
no new OFF/unselected flight/permit/correlation/content is retained. Capture of the
complete original is always attempted regardless of the8 optional inspection slots;
without a slot only demanded policy inspection is unavailable
(`<FIELD>_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY`), not an automatic451 or scope
denial, and capture completeness flags are not falsified.
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

`EvidenceStore` owns sealed ORIGINAL `TrafficEntry` rows and the structured byte
captures (`RawTrafficStore`) they are built from, with **no masking and no collection/
retention/export quota** (memory grows until clear/project change/unload; OOM is a
documented user-managed risk). No native objects or automatic disk persistence. Every
projection and export may contain plaintext credentials. See [EVIDENCE.md](EVIDENCE.md).

API: `begin`, `outcome`, `response` (four args and completeness-six args),
`context(id,outcome,guardState,overlayId)`, `responseBytes(id,long)`, `entry(id)`,
`snapshot`, `bookmark`, `stats`, `clear` (releases rows, captures and sources),
`exportJson`, `exportHar`, static `jsonBytes(Object)` (uncapped serializer).

`TrafficEntry` retains original constructors/accessors plus `intentId`, `runId`,
`outcome`, `guardState`, `overlayId`, `responseBytes`, `inspectionWarnings`.
`Message(headers,body,mimeType,bodyOmitted,truncated,present,bodyEncoding)` (the
six-argument constructor remains) carries original headers and the complete body as
`UTF8_TEXT`, lossless `HEX`, `EMPTY` or `UNAVAILABLE`; rendered `request()`/`response()`
are original. JSON/provenance schemaVersion is2 (label `ORIGINAL_EVIDENCE_NOT_WIRE_CAPTURE`);
HAR1.2 carries v2 additions in `_cairnGuard` and HEX bodies as base64. Its `request.url`
and `queryString` are filled only when the retained untouched actual-service target is a
faithful ordinary URL; `_rawTarget`/`_service` come exactly from the retained capture
route when present; otherwise `url` is `""`, `queryString` is `[]`, `_urlUnavailable`
names the reason (`NO_SERVICE_ROUTE` without a route) and `_displayUrl` keeps the
retained display text only (not a target claim). Nothing is guessed or normalized. The
human HAR file uses the same `url`/`_rawTarget`/`_service`/`_urlUnavailable` rule for a
retained original (a missing original is `url:""` with `_unavailable`) but has no
`_displayUrl`, and its `queryString` is always `[]` with `_queryStringNotParsed`. A seal (covering
`bodyEncoding`) rejects foreign/forged entries; stale retained selections export the
current row; a selection whose ID is no longer retained is rejected with
`INVALID_EVIDENCE_SELECTION`.

Human-local getters: `rawRequest(id)`, `rawResponse(id)`, `rawUrl(id)`,
`rawCaptureInfo(id)` render the same retained parts as text; they may be unavailable
(cleared, never captured, genuine native read failure); label
`UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF`. Storage is project-bound and released on
uncertainty/switch/close/clear (no eviction). Existing records can remain across OFF;
**new OFF/unselected content is never captured**. `GuardController.traffic()`,
`exportJson/Har/Incident` and watcher reads first reconcile a discovered close/project
change (which releases old rows and watcher history), so old selections are rejected by the
seal/membership check and empty selections/incidents contain no old originals; `status().projectName` is the verified name or
`PROJECT_NAME_UNAVAILABLE`. Nothing harvests originals into policy automatically.

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
- 0.2.0 human projections: `humanCandidates()` (`HumanCandidate`: safe candidate +
  ORIGINAL actual-service scheme/host/port/no-query path of its latest retained
  source, `ruleUrl` for an unsaved ordinary URL BLOCK draft, `limitPath` only for a
  strict exact route, categorical unavailability, opaque `CandidateSource`) and
  `humanOverlays()` (`HumanOverlay`: original host and, for heavy only, path; plus an
  `OverlayException` review of the overlay's own triggering request with an opaque
  `OverlaySource`, or a reason: NO_SERVICE_SOURCE / ORIGINAL_UNAVAILABLE /
  ENCODED_OR_AMBIGUOUS_ROUTE / EXCEPTION_TABLE_FULL). Originals resolve through an
  opaque random source reference sealed in the issued watcher Endpoint and bound to
  the raw capture; never through Host, display strings, candidate joins or caller URLs.
- `updateConfig(config,project,revision,CandidateSource,byteLimit)` and
  `updateConfig(config,project,revision,OverlaySource)` revalidate, under the
  controller lock and adjacent to the existing CAS, the token owner/project/runtime
  epoch/raw generation, the current candidate (latest source) or overlay (same id,
  kind, source) and the keyed route seal. An overlay save must equal exactly
  `GuardUiAccess.withDetectorException(current policy, kind, route)` - HEAVY upserts
  a size-0 `PathByteLimit`, CIRCUIT/FANOUT add one exact route - so no unrelated
  field, other detector or enable flag can change. `overlayExceptionCurrent` is the
  UI's post-confirmation check. Stale/forged/substituted tokens write nothing.
- `humanExport(evidenceIds, har)` / `humanIncident(from,to)` return an opaque
  `HumanExport` snapshot created under the controller lock (shares immutable raw
  parts); `serialize()` runs off the EDT and outside every runtime lock with **no size
  cap** (a serialization/IO failure publishes nothing). `humanExportCurrent(export)` is the final
  pre-rename checkpoint (project, revision, runtime epoch, raw generation, AND that every
  original the snapshot actually used - by capture identity for JSON/HAR, by source
  reference for incident rows - is still retained; a clear of such an original aborts
  publication, while unrelated captures and later response updates do not,
  and originals already absent at snapshot time stay categorical `originalUnavailable`).
  The check is memory-only under the controller lock; serialization/filesystem stay outside. Formats:
  `cairn-human-inspection` v1 JSON, HAR 1.2 with `_cairnGuard.exportMode=HUMAN_ORIGINAL`,
  `cairn-human-incident` v1 (rows resolved by their OWN source; missing originals are
  null + `originalUnavailable`; no `_source`, enforcement keys or tokens in files).
  The check-to-rename race and sampled Burp project boundary are documented, not
  prevented; a later clear cannot retract an exported file.

`migrationView` returns `pending`, `original`, `migrated`; no implicit write.
Status retains old keys plus `guardState`, `pauseCause`, `operatorPaused`,
`policyRevision`, `migrationPending`, `guardListenerPorts`, `reasonCounters`,
`watchers`, `intents`, `listeners`, `watcherTickets`, `watcherLateTickets`,
`unguardedListenerCount`. `watcherTickets` counts nonexpired logical tickets;
`watcherLateTickets` counts expired tickets awaiting actual completion. Nested
watcher `activeTickets` / `lateTickets` have the same logical split; neither
counter reports free native permits.
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
