# Original evidence, no masking, no collection quota — current source

This describes **current source** (user requirement 2026-11-05: *no masking and no
collection limit; the user manages memory by hand*). It is not the contents or native
acceptance of the historical `738b41e` / `4232ae…` preview, and the historical native
measurements in [V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md) /
[NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md) (which describe the former redacting
and bounded implementation) do **not** certify this source. Frozen-snapshot results
are in [VERIFICATION.md](VERIFICATION.md). `EvidenceStore` implements
[INTERFACES.md](INTERFACES.md); source is authoritative.

## Read this first: plaintext and unbounded memory

- **Every output carries plaintext originals**: the human screens, `TrafficEntry`
  rows, schema-2 JSON/HAR, human JSON/HAR/incident exports, watcher
  candidate/overlay/incident projections. Authorization, Cookie, tokens and any other
  secret in captured traffic appear exactly as captured. Nothing is masked,
  fingerprinted, harvested or re-masked, and there is no replacement option. Literal
  `[REDACTED]`/`[OMITTED]` text in traffic is ordinary data. Do not publish or hand
  such files/screens to others.
- **No collection, retention or export quota.** All headers, full bodies, full
  URL/native target, all metadata (project name, rule hits, warnings), all rows,
  observations, events and candidates are retained until an explicit **clear**,
  a **project change/unverified project/save-uncertain** boundary or **unload**.
  Incident windows have no maximum; export documents have no size cap. The retained
  size numbers in `stats()` are informational estimates, not a cap. Heap use grows
  without bound: large traffic can cause `OutOfMemoryError`, GC pressure or a slow
  Swing UI. There is no automatic disk spool or persistence and no quota setting;
  clear history yourself.
- Clear/project/unload release the store-owned references. Java strings, arrays that
  consumers already copied (snapshots, clipboard, screenshots, exported files) are
  not revoked or zeroized.
- What is **not** unlimited: policy inspection and parser bounds (see below), the
  concurrency/queue/rate/intent/approval capacities, detector thresholds and windows,
  host/path/flight/overlay capacities, lifecycle timeouts and the atomic-export checks.

## One store model

`EvidenceStore` owns synchronized, memory-only evidence rows (`TrafficEntry`) and the
structured byte captures (package-private `RawTrafficStore`) they are built from. It
opens no file/server, changes no authentication and never replaces native
request/response objects; inputs are copies and no native message object is retained.

`FORWARDED` means native continuation released, **not delivery or target
processing**. `BLOCKED` means a local block, not a target HTTP error. No capture is
invented for a missing response (`Message.EMPTY`, `present=false`); a local denial body
is recorded separately through `localResponse`.

### Capture

`NativeCapture` always copies the complete supplied request/response (all headers in
order with duplicates, the full body, the complete untouched native target) whether or
not an optional policy-inspection slot is free. The bounded inspection slots
(`MAX_INSPECTIONS`) only gate optional **policy parsing** of header/body/JSON/form
conditions: when no slot is free, rules that demand those fields report
`<FIELD>_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY`, cannot grant EXEMPT, and the
request is not blocked for that reason; the copy's `headersComplete`/`bodyComplete`
flags stay true. Truthful incompleteness exists only for a genuine native read failure
(`HEADERS_INCOMPLETE`/`BODY_INCOMPLETE`, actual size -1 or the supplied prefix).

### `TrafficEntry`

Immutable original row: method, synthetic actual-service URL (never a fuzzed Host),
project id/name, rule hits, warnings, intent/run tags, and
`Message(headers, body, mimeType, bodyOmitted, truncated, present, bodyEncoding)`.
`bodyEncoding` is part of the HMAC seal:

| `bodyEncoding` | `body` |
|---|---|
| `UTF8_TEXT` | the exact text (valid UTF-8 and accepted declared charset) |
| `HEX` | lossless lowercase hex of **every** supplied byte (unsupported charset, binary, controls, unknown/overlong/ambiguous Content-Type, or headers that could not be read) |
| `EMPTY` | verified empty body |
| `UNAVAILABLE` | no bytes supplied (native read failure / absent response) |

`bodyOmitted` means no bytes were supplied; `truncated` means the supplied copy itself
was incomplete (a prefix is shown with that label). A non-JSON, malformed, oversized or
unsupported-for-policy body is **retained**; it is only unavailable to policy rules.

`outcome`, `guardState`, `overlayId`, `responseBytes` (native `body().length()`, -1 =
unknown, never Content-Length) and `inspectionWarnings` (every supplied warning,
verbatim, de-duplicated, no count cap) keep their earlier meaning. Decision/outcome
reasons stay a **fixed categorical vocabulary** (`DenialReasons.ALL` and runtime
reasons; unknown text becomes `POLICY_DECISION`/`OUTCOME_RECORDED`) so exception text
and traffic never become reason strings; unknown dispositions become `ERROR`. That is a
vocabulary rule, not masking.

The capture-omission placeholder for adapter/listener failures is a fixed synthetic
row (`UNKNOWN https://capture-omitted.invalid/`); it is not a guess about the request.

### Human views

`rawRequest(id)`, `rawResponse(id)`, `rawUrl(id)`, `rawCaptureInfo(id)` render the same
retained parts as text (label **`UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF`**); missing data
returns null / `available:false`. Raw storage is project-bound: switch/uncertainty,
clear and controller close release it. New OFF or known-unselected-listener callbacks
capture no content. Late responses cannot resurrect a cleared row.

### Explicitly consented human exports

Each human JSON/HAR/incident export (new file AND overwrite) first shows a
cancel-default warning that the file contains plaintext Authorization/Cookie/tokens,
has no size cap and is a callback copy, not wire proof. Then:

- an immutable snapshot is taken under the controller lock (it shares the immutable
  parts); serialization and ALL filesystem work run outside every runtime lock and off
  the EDT; the owner-only, symlink/inode-checked atomic writer publishes after a final
  `humanExportCurrent` checkpoint (project, revision, runtime epoch, raw generation).
  A clear/project change/unavailability/close observed at that checkpoint publishes
  nothing and removes only the task's temp/reservation. A change between that check and
  the rename cannot be prevented; the Burp project is sampled, not locked.
- formats are distinct from the schema-2 evidence (which now also carries originals): `cairn-human-inspection` v1
  (`_cairnGuard.exportMode=HUMAN_ORIGINAL`, entries with categorical runtime fields
  and `original` = method/URL/project/hits/tags/service/raw target and structured
  request/response parts whose body is base64 of every supplied byte with
  byte counts, completeness and UTF-8 validity); HAR 1.2 with the
  same provenance (`postData.text` only for valid UTF-8, otherwise `_bodyBase64`;
  response content base64; the standard `url` only when the UNCHANGED actual-service target
  is a faithful ordinary URL - `/a#b`, invalid `%` escapes, spaces/controls and non-ASCII
  give `_urlUnavailable` while `_rawTarget`/`_service` stay exact, and valid encoded/matrix
  targets stay exportable; `postData.text` only for valid UTF-8 under an accepted declared
  charset (absent/utf-8, or us-ascii with ASCII-only bytes - the same decision as the raw
  display and the JSON body facts) over EVERY captured Content-Type declaration: duplicates
  keep their captured order and all must accept the bytes, and a declaration that is
  over the 1024-character classification bound (checked before any cut), null or not
  retained - or whose headers were OMITTED by an incomplete capture (frozen at capture,
  a complete empty list is a verified absence) - makes the type unknown, so the body stays
  bytes (never "no charset"). One value is classified only inside a conservative
  recognized subset: a token `/` token media type, then EVERY parameter (charset or not) as
  `token=token` or a whole-value quoted string without inner quotes/backslashes, with SP/HTAB
  outer OWS only. Anything else - malformed media type, empty present value, empty parameter
  segment (`text/plain;`), invalid token characters, misplaced or balanced-but-misplaced
  quotes, OWS around `=`, control characters, a duplicate or unsupported charset - is
  unknown => bytes; a parameter name beginning `charset*` (RFC 2231 continuation family,
  never decoded) is also unknown; only a parameter named exactly `charset` counts (`xcharset=` or
  `name="charset=..."` text never grants anything). Lenient forms outside the subset are
  deliberately not decoded as text. The exported
  `headersComplete` flags are true only when the incoming capture was complete AND the raw
  part retained the supplied header list (every header is retained now);
  otherwise `_bodyBase64`; timings/httpVersion marked unknown); and
  `cairn-human-incident` v1 (each event/top row resolved by its OWN source; missing
  originals are `null` + `originalUnavailable`). No enforcement HMAC key, source
  reference or admission token is ever written.
- there is **no document size cap** (`EvidenceStore.jsonBytes` is ordinary Jackson
  serialization); only a genuine IO/serialization failure aborts, publishing no partial
  file. A very large selection needs equally large heap.

## Counters, rows and schema-2 exports

`stats()` is an immutable map of long counters/gauges; none contains payload.
`begun`, `forwarded`, `blocked`, `responses`, `localResponses`, `upstreamResponses`, `unpairedResponses`,
`truncations` (rows whose supplied copy was incomplete), `retainedEntries`,
`retainedBytes`/`rawRetainedBytes` (informational estimates only), `bookmarked`,
`clears`, `clearedEntries`, `orphan*`, `outcomeCallbacks`, `responseCallbacks`,
`reasonCounters` (fixed categories), `rawRetainedEntries`. `evictions` is kept at 0 for
compatibility: nothing is evicted.

`snapshot()` is newest-first and immutable. `entry(id)` is the current row. `bookmark`
creates a new immutable record. `clear()` releases rows, byte captures and source
references (not cumulative counters); the controller's `clearEvidence()` also clears the
watcher's diagnostic history and display/source references, but not authored rate
debt or intent usage. No native permit, timeout quarantine or automatic overlay exists.

`exportJson(selection)` / `exportHar(selection)` return strings and never write
automatically. An in-memory HMAC seal over every exported field (including
`bodyEncoding`) rejects foreign/forged entries; a selection whose row was cleared is
rejected whole (`INVALID_EVIDENCE_SELECTION`); stale-but-retained selections export the
current row. `schemaVersion` 2 JSON carries the original messages. HAR 1.2 keeps its
shape: text bodies as text, `HEX` bodies as base64 with `encoding`/`_bodyBase64` and the
exact byte `content.size`; standard header/body sizes stay `-1` (wire unknown);
timings are placeholders with `timingsKnown:false`. Its `request.url`/`queryString` are
filled only when the retained untouched actual-service target is a faithful ordinary URL
(the human HAR rule above); `_rawTarget`/`_service` come exactly from the retained capture
route when present; otherwise `url` is `""`, `queryString` is `[]`, `_urlUnavailable`
names the reason (`NO_SERVICE_ROUTE` without a route, nothing guessed or normalized) and
`_displayUrl` keeps the retained display text only, not a target claim (the human HAR has
no `_displayUrl`). Provenance label
**`ORIGINAL_EVIDENCE_NOT_WIRE_CAPTURE`**, `completeWireCapture:false`,
`forwardedMeans:NATIVE_RELEASE_NOT_PROVEN_DELIVERY`.

`GuardController.traffic()`, `exportJson/Har/Incident` and watcher reads first reconcile a
discovered close/project change (releasing old rows and watcher history), so a previous
project's originals are never returned by the first read that discovers a change; old
selections then fail with `INVALID_EVIDENCE_SELECTION`.
`status().projectName` is the verified current project's name (or
`PROJECT_NAME_UNAVAILABLE`).

## Incident JSON

A scalar watcher projection of retained diagnostic history with the **original**
actual-service host and untouched path. `[from,to)` is any ordered window
(`to > from`); the 24-hour limit, the 4096-event/8192-observation rings, the day
pruning and the 2048-candidate LRU no longer exist. Automatic-block events no longer
exist: `events` remains an empty compatibility array. Fields: `window`, `events`, all retained
`top5xx`/`topBytes` aggregates (ordered by count5xx/maxBytes, without a row quota), `complete`, `truncated`,
`approximate`, `approximation`, `retention`. Retention is
`{"mode":"UNTIL_CLEAR_PROJECT_OR_UNLOAD","startedAt":…,"clockRegressed":…,
"fanoutHistoryOmitted":…}` (the event/observation `…Dropped` flags stay `false`).
`complete` is false for a window starting before collection started or an explicit
clear, a future window or a regressed clock. Fan-out enforcement/history debt no longer
exists; `fanoutHistoryOmitted` is zero and `fanoutHistoryComplete` is true. Count/max/lastSeen/
5xx are exact over the retained observations; `p95Bytes` is a **log2-histogram
upper-bound approximation**. Candidate IDs are opaque keyed route IDs. `policyUrl` is an
optional query-free actual-service draft hint, empty when the path is not a faithful
ordinary URL path. Aggregates are observational exports only; candidate authoring/ignore and overlay UI/APIs are removed.

## Response correlation is evidence only

Never-reused Proxy IDs pair an original response with its retained protected request.
Missing/reused/ambiguous IDs never deny a policy-allowed request. Content-free used-ID
tombstones last until handler unload, including IDs encountered while OFF. They have
no admission authority, capture no OFF contents/association, and are not persisted.

When an ID's protected provenance still resolves in the current evidence epoch but
its request pairing is ambiguous, retain each complete supplied response in a new
`UNPAIRED_RESPONSE` / `unpaired_response` row. Its reason/warning is
`RESPONSE_CORRELATION_UNAVAILABLE`; request method/URL/hits/tags/revision are unavailable,
not copied from a guessed request. `rawRequest` is null, `requestAvailable=false`,
human JSON `original.request=null` with `requestUnavailable`, and both HAR formats
have empty method/URL and `_unavailable`. Response headers and every body byte remain
original; the row supports bookmarks, consented exports and clear/project/unload.
`unpairedResponses` is separate from `upstreamResponses`/`localResponses`: ambiguous
origin is not guessed. `begun`/`forwarded` are not incremented for response-only rows.

Unknown provenance, mixed OFF/protected reuse, unreadable IDs, wrong-tool callbacks,
and cleared/old-project sources cannot be assigned to current evidence and are not
captured. Missing response capture is unavailable, not a fabricated match/completion.
Unpaired rows cannot be attributed to a route for watcher statistics; use request
history JSON/HAR for their originals. No timeout, clear or callback manufactures
native completion; the extension no longer owns native admission permits.

## Limits that remain (enforcement / parser / algorithm, not collection)

Policy inspection: `RequestData.MAX_INSPECT_BYTES` (1 MiB, **policy only**), header/
pair/JSON-node/depth/pattern/program/decode-round budgets, 16 KiB routing-view URL
bound, method token length; unavailable inspection is reported, never silently passed.
Capacities: callbacks 128, inspection slots 8, approvals, authored pacing queues/
host state, intent keys and listener entries. Native-flight/correlation100 and
controller/watcher ticket/host/path/overlay admission capacities are removed.
Bounded routing views remain9. Content-Type **classification** is bounded at 1024 characters
(longer values are kept whole but treated as an unknown declaration → bytes). Policy/
config editors keep their own input limits. These are not raw-traffic quotas.

## Verification boundary

Synthetic tests live under `src/test/java/dev/cairnguard/evidence/` (notably
`UnmaskedCollectionTest`, beyond-old-limit retention) with runtime and UI coverage in
their packages. Developer command: `./gradlew --offline --no-daemon test`. Native Burp
behavior of this source has not been run by these tests.
