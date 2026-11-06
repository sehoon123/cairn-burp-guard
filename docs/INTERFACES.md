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
  authored budget, pacing, queue/capacity or shutdown.
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

The 8-,16-,17-argument compatibility constructors and strict schema2 shapes remain.
All production copies preserve all19 fields. **Operational:** global/per-host/
override rates (0=off,1–1000), maxQueued, queueTimeoutMillis,
approvalTimeoutMillis, perIntentMaxRequests (0=off), healthProbePassthrough and
healthProbePaths. **INACTIVE legacy:** maxConcurrent, requestTimeoutMillis,
perPathMaxResponseBytes, autoBlockMillis, circuit5xx, fanout, heavyPathLimits,
circuit5xxExceptions, heavyResponseEnabled and fanoutExceptions. They are still
strictly validated/preserved on load/save but NEVER execute, even if true/positive.
No new auto-block switch or reason allowlist exists. Ordinary authored BLOCK rules
remain active; legacy detector routes are not converted into new rules.

New-profile defaults: empty allowlist, default ALLOW inside valid scope, DELETE
method BLOCK only, global/default-host rates0/0, queue100, queue/approval30000ms,
intent0, healthfalse, empty listener selection. Legacy detector/concurrency/timeout
values retain their serialized defaults solely for read/round-trip compatibility.
V1 migration preserves its original rates/scopes/rules and is never auto-saved.

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
`LISTENER_UNVERIFIED`, `CAPACITY`. CIRCUIT_OPEN/OVERLAY_BLOCK/IN_FLIGHT_STALLED
remain enum/decoding categories for historical compatibility, not current gates.

`DenialReasons.ALL` is the finite adapter/evidence vocabulary; `category(value)`
returns `ADAPTER_ERROR` for unknown inputs. New categories include
`HEAVY_ENDPOINT_AUTO_BLOCKED`, `CIRCUIT_OPEN`, `FANOUT_SUSPECTED`,
`RESPONSE_WATCHER_CAPACITY`, `INVALID_INTENT_TAG`, `INTENT_BUDGET_EXCEEDED`,
`INTENT_BUDGET_CAPACITY`, `LISTENER_UNVERIFIED`. `PAUSED` / historical `IN_FLIGHT_TIMEOUT`
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

## Controller and final native handoff

`GuardController(ProjectAccess)` implements `GuardUiAccess`, `AutoCloseable`.
`prepare(RequestData[,boolean contentInspectionAvailable])` stores complete originals;
false makes optional demanded content inspection unavailable, not a denial/truncated
capture or successful EXEMPT check. `prepareRejected(reason)` creates a categorical
capture-omitted placeholder for immediate adapter/lifecycle failures.

`Prepared` remains an accessor-compatible class with original five-argument
constructor, plus endpoint/attribution/healthProbe accessors. Only controller-issued
single-use ownership can authorize/commit; display/forged objects cannot send or
mutate another row. No body/native request/continuation is retained across waits;
the optional observational endpoint contains bounded route metadata/source identity.

```java
record Admission(boolean allowed, String reason)
record CommitResult(boolean allowed, String reason)
record Denial(String guardState, long policyRevision, String overlayId)
Admission authorize(Prepared p)
Admission reject(Prepared p, String reason)
CommitResult commitDetailed(Prepared p)
boolean commit(Prepared p)
boolean current(Prepared p)
```

Order: nativeMode before capture → actual destination/path policy → explicit ASK
wait if needed → authored pacing/queue → construct non-sending original-object
continuation → final project/revision/pause/policy/shutdown + intent consumption →
evidence-only correlation association → return continuation. Use the actual final
CommitResult reason. There is no watcher admission/check/claim, logical ticket,
permit, native concurrency or response timeout stage. Factory/final rejection
precedes intent spend; uncertain native dispatch is not retried/refunded. Forwarded
means native handoff, not target arrival. Manual pause/approval/current-project
and final-send protections remain; old response behavior never authorizes denial.

```java
void response(String id, int status, List<RequestData.Header> headers, byte[] body)
void response(String id, int status, List<RequestData.Header> headers, byte[] body,
              long actualResponseBytes)
void response(String id, int status, List<RequestData.Header> headers, byte[] body,
              long actualResponseBytes, boolean headersComplete, boolean bodyComplete)
void unpairedResponse(String protectedSource, int status, List<RequestData.Header> headers,
              byte[] body, long actualBytes, boolean headersComplete, boolean bodyComplete)
void localResponse(String id, byte[] body)
```

Native size/status are independently observed, not Content-Length or zero-filled
sentinels. -1 means unknown; supplied body completeness remains truthful. Matched
responses record originals then observational scalars under the runtime lock.
Cleared/old-project sources and shutdown cannot resurrect originals. Unpaired
responses require a still-retained protected source proving only the evidence
epoch, NOT which request produced them; no route/headers/hits/tags are guessed.

## Observational watcher, authored pacing and intent

ResponseWatcher exposes `endpoint(request,routingPaths)`, `observe(endpoint,status,
bytes)`, `candidates()`, `snapshot()`, `incidentJson(from,to)` and
`incidentDocument(from,to,sourced)`, plus `update/reset/clearEvidence`. All are
memory-only; none affects sends. Reset/clear/foreign-endpoint provenance fences
late observations. No actuator/overlay/half-open/ticket/Seen/debt/capacity APIs remain.
An optional endpoint failure cannot deny a policy-allowed request.

Candidate is an observational aggregate with id/host/path/policyUrl/maxBytes/
p95Bytes/count/lastSeen/count5xx. Count/max/5xx/lastSeen use all retained observations;
p95 is a log2 histogram upper-bound approximation, not wire latency. Incident
windows are any ordered [from,to), with explicit since-clear/clock completeness.
All observations/aggregate rows are retained without count/age/export quotas.
`events` is an empty compatibility array; fanoutHistoryOmitted=0 and
fanoutHistoryComplete=true. No source reference/key/token may be serialized.
Unpaired response rows have no known route, so cannot be assigned to these stats.

`RateGate.acquire(host,stillCurrent)` returns a monotonic `long` admission timestamp,
not a Permit/resource. Independent0/off global/default/host-override axes; positive
1–1000 use no-burst pacing, host FIFO and eligible-host round-robin. Native
completion never changes eligibility. Genuine authored queue/time/host-key capacity
remains; no active/stalled/timedOut/maxConcurrent status. Exact live-update,
fairness/deadline/metrics contracts: [RATE_APPROVAL.md](RATE_APPROVAL.md).

IntentBudget is deterministic final-handoff counting for untrusted client tags.
0=off; enabled budgets reject invalid/duplicate/incomplete labels and key-capacity
exhaustion, never learn authenticated identity. EXEMPT/health still consume an
authored budget. Save/OFF/disable does not clear usage. Reset is explicit human CAS
or project epoch reset. ApprovalQueue remains100 provisional, monotonic one-shot
ASK waits with final-current-state validation; hard blocks are not approvable.

## Native adapter, correlation and OFF

Only Proxy requests are protected; allowed native request/response/annotations are
the exact original objects. Immediate callback128 and optional-inspection8 bounds
remain. No native-flight100 cap or correlation-capacity denial remains. Missing or
reused IDs do not stop otherwise allowed requests. A missing/unreadable ID can
make response provenance unavailable; it never licenses a guessed match.

Used numeric IDs remain content-free tombstones for handler lifetime (including
OFF IDs); no admission authority, OFF association/contents, TTL or persistence.
Never-reused protected IDs may pair one actual Proxy response. Reuse remains
ambiguous even after completion/clear. Retained protected-only provenance permits
response-only rows where safe; mixed OFF/protected, foreign tool, unknown,
cleared/old-project provenance is not captured or assigned to current evidence.
The adapter does not infer/recycle/release native ownership because it no longer
owns native admission permits. Unload releases metadata/originals; late callbacks
cannot record. Response continuations remain original and independent of capture.

`nativeMode([messageId])` checks human-confirmed OFF first, then all-listener policy.
Empty guardListenerPorts protects all. H remains deferred: no supported native
shared-listener identity producer exists, no listener inference. Existing nonempty
restrictions fail closed before capture; new UI/JSON selections reject and old
values require explicit confirmed clear. Synthetic trusted registry behavior is
not native per-port support. ListenerObserver is data-free continuation only.

`passthrough(enabled,expectedProjectId,expectedRevision)` is runtime-only human OFF,
separately confirmed/visible. NEW callbacks skip scope/rules/inspection/ASK/pacing/
intent and capture nothing, keeping a count (plus content-free used-ID fencing).
Old protected waits cancel without approval, old response associations can finish
logging, manual pause/intent usage persist. Project/restart/unavailability resets
OFF. Native factory/shutdown/stale generation still fail closed. This is not an
automatic-block toggle/recovery and not required for all-rates-off behavior.

Local451 preserves ordered source/outcome/reason/evidenceId/retryable keys and fixed
typed guardState/local/policyRevision metadata. Historical optional overlayId
shape remains readable, but no active overlay emits it. Native spoof failure drops,
never allows. Local metadata never echoes traffic or exception strings. A remote
451 is not automatically a local guard verdict. See [BURP_ADAPTER.md](BURP_ADAPTER.md).

## Evidence and human-only interface

EvidenceStore retains complete original rows/byte captures/metadata until explicit
clear/project/unload, without masking, harvesting, quotas or disk spool. OOM and
plaintext credentials are accepted risks. Parser/inspection/operational capacities
are separate. API `begin/outcome/response/context/responseBytes/entry/snapshot/
bookmark/stats/clear/exportJson/exportHar/jsonBytes`, raw getters, immutable human
snapshots, source/epoch membership and provenance seals remain.

`unpairedResponse(protectedSource,status,headers,body,actualBytes,headersComplete,
bodyComplete)` creates `UNPAIRED_RESPONSE`/`unpaired_response` evidence with
RESPONSE_CORRELATION_UNAVAILABLE. Method/URL/hits/tags/revision/request capture are
unavailable, not borrowed from the source. Full original response is retained.
Counters separate unpaired from local/upstream, with no invented begun/forwarded
request. Raw request is null; JSON original.request is null with requestUnavailable;
HAR empty request has `_unavailable`. Ordinary raw/JSON/HAR/seal/clear/export
checks apply to this row as well. No fabricated pair enters watcher statistics.

GuardUiAccess consists of config/updateConfig/status/traffic/approvals/
decideApproval/bookmark/exportJson/exportHar/clearEvidence/pause/passthrough/
refreshProject, resetIntentBudgets/exportIncident/migrationView/raw getters and
humanExport/humanIncident/humanExportCurrent. Automatic overlay/candidate APIs,
source-seeded authoring/ignore/release/exception actions and controls are removed.
No network/worker control surface exists.

`humanExport(ids,har)` / `humanIncident(from,to)` produce opaque immutable snapshots.
serialize runs outside runtime locks/off EDT with no output cap. Every file needs
plaintext consent, owner-only atomic publication and a final project/revision/
epoch/raw-generation/source-retention check. No silent non-atomic fallback. A tiny
check-to-rename race and sampled project boundary remain. Already-exported files
cannot be retracted. Schema2 machine JSON/HAR also contain originals; no automatic
file write. Full formats and faithful raw-target/unknown-wire semantics:
[EVIDENCE.md](EVIDENCE.md).

Status keeps typed lifecycle/operator pause/revision/project/migration/listener,
rate queue/approval/intent/evidence counters and observational watcher count/clock
state. No active stalled/quarantine/watcher ticket status or native-concurrency
claim remains. Legacy reason enum/zero counter decoding is not active enforcement.
Same-project save preserves manual rate/intent usage; project uncertainty clears
old original/observer state and fails closed, without guessing native completion.

## Validation and nonclaims

See [test inventory](AUTOBLOCK_REMOVAL_TEST_MAP.md), [controller test boundaries](CONTROLLER_TESTS.md)
and [runtime/UI contract](RUNTIME_UI_CONTRACT.md). Unit/adapter/owned-loopback and
real isolated Swing are separate from installed Burp. This change does not prove
callback coverage, target delivery, mandatory egress, wire equality from copies,
TLS-pass-through/CONNECT/WebSocket visibility, authenticated quotas, native
concurrency bounds or a stable/released/independently approved artifact.
