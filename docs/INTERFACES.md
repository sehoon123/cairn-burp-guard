# MVP implementation contracts

Root: this repository; Java package `dev.cairnguard`.

## Shared models (orchestrator-owned)

`model.GuardConfig` record:
- `int schemaVersion`, `List<ScopeEntry> allowScope`, `List<ScopeEntry> blockScope`, `List<Rule> rules`, `Mode defaultMode`, `Limits limits`.
- nested `Mode { ALLOW, BLOCK, MONITOR, ASK }`, `Field { METHOD, URL, PATH, QUERY, HEADER, BODY, JSON, FORM, ANY }`, `Match { CONTAINS, EXACT, REGEX }`, `Logic { LEAF, AND, OR }`.
- `ScopeEntry(boolean enabled, String host, String scheme, int port, String pathRegex)`; host exact ASCII/IDN-normalized name or `*.example.test` (subdomains only, not apex), scheme `http`/`https`/`any`, port 0 = any, regex full matches path ONLY. URL query must not be used to broaden scope. URL/actual service authority must agree. Config validation rejects malformed entries.
- `Rule(String id,String name,boolean enabled,Mode mode,Condition condition)`.
- `Condition(Logic logic,Field field,String name,Match match,String value,boolean caseSensitive,List<Condition> children)`; AND/OR children, LEAF other fields; optional selector name for HEADER/QUERY/JSON/FORM. JSON selector = RFC6901 pointer or empty for flattened keys/scalars. Empty selector examines names and values.
- `Limits(int globalRps,int perHostRps,Map<String,Integer> hostRps,int maxConcurrent,int maxQueued,long queueTimeoutMillis,long approvalTimeoutMillis,long requestTimeoutMillis)`; default 5,5,{},5,100,30000,30000,60000. Hard bounds validated.
- `static GuardConfig defaults()` includes no allow hosts, enabled DELETE exact rule and case-insensitive ANY contains `delete` rule. DefaultMode ALLOW. Immutable defensive list/map copies.

`model.RequestData(String method,String url,String host,int port,boolean secure,List<Header> headers,byte[] body)`; `Header(String name,String value)`, `header(String)` accessor, defensive copies, MAX_INSPECT_BYTES = 1048576. No auth mutation. Headers passed exactly as observed to native continuation. RequestData is only an inspection COPY.

`model.Decision(Mode mode,String reason,List<RuleHit> hits)` with `RuleHit(String id,String name,Mode mode)`; reason must be categorical, no request values or regex captures. Decision only ALLOW/MONITOR/BLOCK/ASK. Hard scope/inspection errors are BLOCK.

`model.DenialReasons.ALL` is the immutable, finite native denial vocabulary shared by the adapter and evidence boundary. `category(String)` maps unknown/null adapter inputs to `ADAPTER_ERROR`. Evidence must preserve every listed category (including `PAUSED`, `IN_FLIGHT_TIMEOUT` and capacity/capture failures) in snapshots and JSON/HAR; arbitrary text still maps to fixed generic fallbacks.

`model.Json` static `ObjectMapper MAPPER`, `String write(Object)`, `<T>T read(String,Class<T>)`; strict duplicate keys, trailing tokens, unknown config properties, bounded input/depth; no default typing.

## Policy task-owned public API

`policy.PolicyEngine`:
- `void validate(GuardConfig config)` throws IllegalArgumentException on invalid config, invalid RE2 expression, duplicate IDs, malformed conditions, limits etc.
- `Decision evaluate(GuardConfig config, RequestData request)`; never throw expected inspection/config errors across network callback; instead BLOCK with categorical reason. Hard scope gates before matching. BLOCK > ASK > ALLOW; MONITOR records only, then default if no actionable rule. Mandatory scope/inspection gates cannot be overridden.
- Match raw and bounded percent-decoded views (path: '+' literal; form/query: '+' space), JSON strings Unicode-unescaped, query/form keys and values. Decode at most 3 rounds and fail closed on exceeding nesting, malformed percent/JSON/form or excessive structures. Reject unsupported nonidentity Content-Encoding and nonempty binary/multipart bodies rather than silently partial-inspecting. Reject WebSocket upgrades by default (frames unsupported). No network I/O, no native Burp APIs. RE2/J only.

## Evidence task-owned public API

`evidence.EvidenceStore`:
- `EvidenceStore()` bounded in-memory redacted entries (max 2000, total estimated text budget <=32 MiB; max per captured request/response part <=64KiB). Raw request only transient during redaction, never retained.
- `String begin(String projectId,String projectName,RequestData request,Decision decision,long revision)` returns unique ID; captures request redacted before insertion.
- `void outcome(String id,String disposition,String reason,Integer statusCode)`; `FORWARDED` means native send released, NOT proven target delivery; `BLOCKED` locally blocked.
- `void response(String id,int statusCode,List<RequestData.Header> headers,byte[] body)`; redacted capture, distinguish local block response via outcome.
- `void bookmark(String id,boolean value)`.
- `List<TrafficEntry> snapshot()` newest first; `void clear()`.
- `Map<String,Object> stats()` aggregate counts incl evictions/truncations/retained entries (fixed keys).
- `String exportJson(List<TrafficEntry> entries)`; `String exportHar(List<TrafficEntry> entries)` valid HAR1.2 with `_cairnGuard` provenance and redacted data label. Exports do not imply complete wire capture.
- optional `public Redactor` methods for dedicated redaction tests.

`evidence.TrafficEntry` record minimum accessors `id(),projectId(),projectName(),timestamp()` (ISO8601 String), `method(),url(),mode()` (String), `disposition(),reason(),statusCode()` (Integer nullable), `hits()` (List<Decision.RuleHit>), `revision()` (long), `bookmarked()` (boolean), `request(),response()` (masked text Strings), `truncated()` (boolean). Can add fields if needed; immutable copies; default absent response empty string. Only redacted URL/method/headers/body exposed to UI/export. Unknown/binary/malformed bodies should be omitted rather than leaked. Secret header/query/JSON/form keys case-insensitive; entire Cookie/Set-Cookie/Authorization/Proxy-Authorization/API keys and token values masked. Suppress unstructured HTML/text bodies if reliable masking cannot be guaranteed; document loss of fidelity. Fixed '[REDACTED]' marker. No automatic disk persistence, no credentials in audit/error strings.

## Orchestrator runtime/UI

Global/per-host fair shared pacing and in-flight concurrency permit release at response. Queue and approvals bounded; waits off EDT; live settings update wakes waiters. Missing responses never automatically free concurrency permits: after request timeout, gate closes new admissions (quarantine) to avoid exceeding true in-flight maximum. UI shows this as uncertain/stalled, operator may start a fresh run only after quiescing native traffic. Policy revision/project change while waiting blocks rather than forwarding under stale approval.

Use Montoya HttpHandler restricted to ToolType.PROXY. RequestToBeSentAction.spoof(HttpResponse) is available since API2026.4, baseline2026.7; generates local451 with fixed marker and evidenceId, retryable=false. ContinueWith SAME native request/response objects and annotations unchanged. No header/cookie mutations. Callback capture may not be exact wire provenance; other extensions, TLS pass-through, raw CONNECT/WebSocket frames, traffic not exposed to callback, or direct sockets are outside guarantee.

## Explicit human-only temporary protection OFF (2026-11-04)

The preceding hard gates/pacing apply with **protection ON**. The user's requested all-passthrough is a separate, explicitly confirmed runtime state, not an ALLOW/MONITOR policy override. See [PASSTHROUGH.md](PASSTHROUGH.md).

- `GuardUiAccess.passthrough(boolean enabled, String expectedProjectId, long expectedRevision)` atomically checks the original human UI snapshot and live project. No worker/network API. Mode changes increment revision, cancel existing approval/queue waits and wake the existing gate; they never approve waits or recycle native in-flight permits.
- `GuardController.NativeMode(token, rejection)` / `nativeMode()` atomically distinguish protected, verified OFF, and data-free rejection. Unverified OFF must never fall back to native capture. The protected fast path does not take the mutation lock. `PassthroughToken(projectId, revision)`, `passthroughToken()` and `commitPassthrough(token)` are the native adapter's data-free snapshot/final-commit pair. Build the original-object action before commit. Protected `Prepared` requests never inherit OFF authorization. Restore/re-enter/save/project/close invalidate old tokens.
- New Proxy callbacks in explicit OFF skip capture/policy/approval/rate/callback/inspection admission, retain no raw/native data, no permit and no response correlation. Only a saturating `passthroughCount` for the current controller-bound project epoch is counted. Binding a different project ID resets it, including A→B→A actual bindings; ending OFF for an unverifiable project without binding a different ID preserves the previous count. Status adds `passthrough` / `passthroughAvailable` / `passthroughEnded` (booleans) and `passthroughCount` (long), atomically consistent with project/revision/pause. The count means native continuation released, not delivery.
- Previously protected native flights stay tracked through their actual responses and may append masked evidence. New OFF responses remain untracked even after protection is restored. Protection after OFF applies only to new requests; independently quiesce OFF connections before relying on concurrency limits.
- OFF is never persisted in `GuardConfig` or preferences. Restart/project change resets it; project/save uncertainty disables it and blocks new requests pending verification. A valid, loaded policy/project is required to enter OFF. Lifecycle errors, stale final commit, shutdown and ambiguous old protected message IDs still fail closed.
- A successful config save while OFF preserves OFF and is clearly labelled; it does not silently turn protection back on. The separate pause action exits OFF and blocks new requests. Scope/inspection blocks remain non-overridable by rules/approval in protection ON.

## Templates task ownership

Own `templates/**`, `scripts/verify_templates.py`, `docs/CAIRN_TEMPLATES.md`, `docs/KISA_MAPPING.md`, `src/test/...` only if needed coordinate. Inspect a trusted upstream CAIRN checkout at commit `8e7e0ea67552383851dfcabfba0c4e9c8d007878` read-only. Must prove external prompt_group works without source edits using current resource loader semantics (absolute path works on filesystem installs; verify). All five required prompt files and exact runtime tokens/contracts. CAIRN Native Pi no extensions/MCP; no instructions to control Burp, no login/session recovery. CAIRN authors Korean Markdown report files before completion. Report every exit path (timeouts/failures/policy block), evidence refs, uncertainty, coverage, availability budgets. KISA-inspired mapping must cite official source and version honestly; never invent exact official codes/compliance. Provide Origin/Goal/Hints, report template, checklist; zero real targets/secrets. No modifying CAIRN source or its installed files. No guaranteed network enforcement claims from proxy environment alone.
