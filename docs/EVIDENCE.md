# Human raw history and masked evidence — unreleased v2 source

This describes **current source**, not the contents or native acceptance of the
historical `738b41e` / `4232ae…` preview. Frozen-snapshot results and pending gates
are in [VERIFICATION.md](VERIFICATION.md). `EvidenceStore` implements
[INTERFACES.md](INTERFACES.md); source is authoritative.

**Native finding:** the old217730… candidate leaked a credential reflected as HEX.
The current437503… source fixes and rechecks that case; see
[V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md). This is not universal DLP or release approval.
Native listener restriction is separately unsupported and fails closed.

## Two stores, not two export modes

`EvidenceStore` owns synchronized, bounded, **memory-only** masked evidence and a
**separate human-local unmasked cache**. It opens no file/server, changes no
authentication and never replaces native request/response objects. Inputs are
inspection copies. No native message/parser tree is retained. Raw credentials
can exist in human display strings; they are **not fields of `TrafficEntry` or
the keyed fingerprint index**. Do not log inputs, raw getters or exception text.

`FORWARDED` means native continuation released, **not delivery, receipt or target
processing**. `BLOCKED` means a local block, not a target HTTP error. A captured
upstream451 remains nonlocal/FORWARDED. No capture is invented for a missing
response. A local denial body is recorded separately through `localResponse`.

### Unmasked human history

History is **unmasked by default**, as requested by the user. Package-private
`RawTrafficStore` is not a serializable evidence model, export source or worker
API. Human-only bridges on EvidenceStore/GuardUiAccess are:

- `rawRequest(id)`, `rawResponse(id)`, `rawUrl(id)`; missing data returns null.
- `rawCaptureInfo(id)` reports availability, request/response truncation/omission,
  header/body completeness, body display type, untrusted intent/run and warnings.
- `clearRawUi()` on EvidenceStore disposes raw-only state.

Label: **`UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF`**. Representable UTF-8 text is
shown; unsupported charset/non-text bytes use bounded lossless **HEX of captured
bytes**, not replacement characters or inferred content. Prefixes/omission are
explicit. These are not full original messages, protocol measurements or replay.
The UI's human URL/tag search/detail uses these getters. Missing raw metadata is
explicitly labeled as unavailable/masked fallback, never presented as original.

The raw cache has its **own** max2000 entries / estimated32MiB /64KiB per
request/response display part; URL is independently bounded. This is additional
to masked-store bounds, **not a combined32MiB or whole-JVM heap cap**. Oldest raw
entries can evict independently; masked-entry eviction also removes corresponding
raw data. Bookmarks pin neither. Late responses cannot resurrect a removed raw row.

Raw storage is project-bound: switch/uncertainty, clear and controller close discard
store-owned references. Existing records can remain across OFF/ON; **new OFF or
known-unselected-listener callbacks capture no request/response contents**. Data-free
failures may leave only a synthetic omission placeholder. Native Burp history /
project persistence is separate and unchanged. Java Strings/consumer copies are
not guaranteed zeroizable. Human clipboard/screenshots may expose secrets. There
is **no raw export**, automatic persistence or harvesting into policy configuration.

### Masked immutable evidence

`begin(projectId,projectName,request,decision,revision)` returns a random UUID.
Discovery/redaction precedes masked insertion. `TrafficEntry` is immutable, with
masked `requestCapture()` / `responseCapture()`:

```java
Message(List<Header> headers,String body,String mimeType,
        boolean bodyOmitted,boolean truncated,boolean present)
```

Rendered `request()` / `response()` are masked inspection-copy text; absent response
is empty. Timestamp is ISO8601 UTC observation time, **not measured wire timing**.
HTTP/1.1 in render/HAR is a placeholder, not observed protocol.

V2 adds masked `intentId`, `runId`, `outcome`, `guardState`, `overlayId`,
`responseBytes`, `inspectionWarnings` with original constructors preserved.
`outcome` (`pending`, `forwarded`, `blocked`, `exempt`, `probe_allowed`, `half_open`)
is separate from `disposition` (`PENDING`, `QUEUED`, `AWAITING_APPROVAL`, `FORWARDED`,
`BLOCKED`, `STALLED`, `CANCELLED`, `ERROR`). Context accepts fixed typed GuardState
and a safe UUID overlay, never note-text inference. Tags are **untrusted client
claims**, not identity/authorization. A masked label is not automatically a safe
policy value.

Native `responseBytes` is observed from `body().length()` separately from optional
copy/slots; `-1` means unknown. It is not Content-Length, total wire bytes, headers,
TLS/framing, timing or delivery proof. A6MiB response may have actual scalar bytes
but omitted raw/masked body copies. Unknown bytes do not establish an empty response.
The native controller uses the seven-argument response overload carrying actual
bytes and completeness; older four-argument response can derive only a bounded
copy's size.

## Redaction and deliberate fidelity loss

The fixed marker is **`[REDACTED]`**. Discovery precedes rendering, so a secret in
a later JSON field/header can be removed from earlier URL/project/rule/echo data.

- Header/key recognition is case-insensitive, separator-insensitive and handles
  bracketed/nested names. Authorization, Proxy-Authorization, authentication,
  Cookie/Set-Cookie, API/access/private keys, token/JWT, password, secret,
  credentials, session, CSRF/XSRF, nonce, signature, OTP/PIN, OAuth code and grant
  fields are treated conservatively. Entire sensitive header values are masked.
  A non-sensitive field name is not proof its value is public.
- URL userinfo/fragments are not retained. Query keys/values and nested form/JSON
  strings are inspected. A component after a sensitive path component is masked;
  known reflected secrets in path/hostname/metadata/JSON keys are also removed.
  Unsafe credential-bearing authority falls back to `https://redacted.invalid/`.
  Display URLs may be normalized/re-encoded by **redaction only**; this is not the
  forwarded target, scope input or permission to sanitize pentest traffic.
- Query/form decoding treats `+` as space, path decoding keeps `+`. Strict UTF-8
  percent/Unicode views are bounded to three rounds. Malformed/over-encoded input
  is not partially exposed as exportable text. `[REDACTED]` can be percent-encoded
  in display URLs/forms.
- Strict JSON rejects duplicate keys/trailing tokens and bounds nested traversal
  (32 levels /8192 redaction nodes plus shared parser bounds). Arrays/objects,
  Unicode/percent names, stringified JSON, embedded forms and recognizable inline
  assignments are inspected. Sensitive subtrees are replaced and their scalar
  secrets discovered for reflection masking.
- Structured JSON/form bodies support UTF-8/US-ASCII and identity Content-Encoding.
  Nonempty HTML/free text/XML/binary/multipart, unsupported charset/encoding,
  malformed or oversized bodies become **`[OMITTED: UNSAFE_OR_UNSUPPORTED_BODY]`**.
  No raw-prefix fallback exists in the masked store. Unsafe discovery can suppress
  unconstrained metadata/scalars conservatively. Empty bodies remain empty.
- Request credentials reflected in a response, benign field/long string,
  percent/Unicode escape, UTF-8 HEX or standard/URL Base64 can be detected by bounded
  keyed **HMAC-SHA256 fingerprints**. HEX lower/upper aliases use the same bounded
  builder; transient case-folding of HEX runs catches mixed-case reflections and
  masks a matching run in full. Nonmatching text retains original case. Basic
  credentials are also decoded. A rolling-hash prefilter is verified by HMAC.
  This is not arbitrary decryption or a universal transformation/DLP classifier.
- Fingerprints are bounded to128 candidates,24 distinct lengths,8192 characters
  per candidate; overflow switches to conservative suppression, not silent loss.
  Derived keys/fingerprints stay private in memory and are discarded on eviction/
  clear, never exported or persisted.
- Response-only secrets extend the index and remask retained request/project/rule/
  tag copies. Previously truncated unparseable bodies are omitted instead of
  reused as unchecked prefixes. Previously returned immutable snapshots cannot
  be changed; consumers must refresh and not retain unbounded history.
- Incomplete optional capture suppresses affected export content/metadata.
  `HEADERS_INCOMPLETE`, `BODY_INCOMPLETE`, `PATH_INTERPRETATION_INCOMPLETE` and
  bounded field-specific unavailable categories remain visible. **Evidence omission
  is not policy denial**: unsupported body/charset, malformed JSON or optional
  capture limits do not automatically451 otherwise in-scope traffic. Available
  explicit conditions still apply; unavailable conditions cannot grant EXEMPT.
- Decision/outcome/error text is not blindly retained. Only finite categories,
  including `DenialReasons.ALL`, survive; unknown text becomes `POLICY_DECISION` /
  `OUTCOME_RECORDED`, unknown disposition `ERROR`. `PAUSED`, `IN_FLIGHT_TIMEOUT`,
  watcher/circuit/fanout/intent/listener/capacity reasons are preserved. Legacy
  vocabulary names are not automatic-denial requirements. No raw URL/capture/
  parser exception becomes an error string. Status outside100–599 becomes unknown.

Unrecognized secrets deliberately put in benign fields or unsupported transformations
cannot be identified with certainty. Inspect exports before sharing. No complete
wire coverage, unseen native traffic, TLS pass-through, CONNECT/WebSocket frames,
direct sockets or other extensions' later changes are certified.

## Bounds, lifecycle and response-time display privacy

Masked-store defaults: **2000 entries**, **32MiB estimated retained bytes**,
**64KiB per captured request/response text part** including start line. Oldest
insertion evicts even bookmarked entries; response/outcome/bookmark growth enforces
the same bound. An overlarge entry may itself evict.

Estimate charges `max(UTF-8 bytes,2×UTF-16 length)` plus object/header/hit/fingerprint
overhead. It is not a whole-heap cap: transient parsers, export buffers and consumer
snapshots are additional. Inputs are independently bounded to1MiB/256 headers.
**Mask first, then bound**: a secret past byte65536 can remove an earlier reflection.
Output cuts at UTF-8 boundaries with `[TRUNCATED]`; header overflow sets truncation.
Metadata has separate masked bounds (512bytes/project or rule string,128 hits,
8192byte URL with whole-URL fallback; warnings max32). A truncated JSON/form display
need not remain a replayable valid body. Omission and truncation are distinct.

`snapshot()` is newest-first and immutable, including nested lists. `entry(id)` is
the latest MASKED row. `bookmark` creates a new immutable record. Unknown IDs count
as orphan updates. Local BLOCKED and native-released terminal facts cannot be
relabelled as one another by a late callback. `clear()` discards masked evidence,
fingerprints and raw UI, resetting retained gauges **not cumulative counters**.
Controller clear also clears watcher diagnostic rings/candidates, **not active
overlays, probe cadence, intent debt or native permits**.

`displaySanitizer(id)` is an ephemeral current-fingerprint operation for individual
structured watcher **values**, not serialized JSON/schema keys; disposed/missing
rows yield opaque values, never raw fallback. Do not retain it across waits.
Under one controller lock: learn response secrets first → refresh watcher incidents/
candidates/overlays/pending flights → observe actual scalars. Watcher display/export
shares that lock. A response-only grant reflected in an earlier path cannot stay
permanently safe merely because the send-time URL was masked. Changed URLs lose
`policyUrl`; bounded hashed privacy fences stop older Prepared/endpoints/aliases
reviving them. Fence saturation makes display opaque, without dropping enforcement.
**Raw UI getters are never consulted** for this process or incident/export.

### `stats()`

Immutable map; scalar values are long counters/gauges. `reasonCounters` is a bounded
fixed-category numeric map, not payload-derived keys or a delivery count.

| Key | Meaning |
|---|---|
| `begun` | All begin observations, including evicted/cleared |
| `forwarded`, `blocked` | First terminal outcome per retained ID; duplicate callback not a new send |
| `responses` | First captured response per retained ID |
| `localResponses`, `upstreamResponses` | Local BLOCKED vs nonlocal callback, not independently verified origin |
| `evictions`, `truncations` | Capacity removals / entries ever truncated while retained |
| `retainedEntries`, `retainedBytes`, `bookmarked` | Masked current gauges |
| `clears`, `clearedEntries` | Clear operations/discarded records |
| `orphanUpdates`, `orphanOutcomes`, `orphanResponses` | Unknown/evicted ID updates/callbacks |
| `outcomeCallbacks`, `responseCallbacks` | All corresponding callbacks |
| `reasonCounters` | Categorical reason-transition observations |
| `rawRetainedEntries`, `rawRetainedBytes` | Separate raw-cache gauges, no raw values |

No unbounded tombstone map is kept; evicted/cleared late callbacks cannot always be
uniquely deduplicated/reclassified. Their orphan activity remains visible.

## JSON / HAR / incidents — masked only

`exportJson(selection)` / `exportHar(selection)` return strings, **never write
automatically**. At most2000 genuine store-created entries /32MiB selection estimate.
An in-memory HMAC authenticity seal covers all exported fields including v2
additions. Foreign/forged entries reject categorically. The seal is not emitted.
For retained IDs, stale selections use latest masked rows, so old UI snapshots
cannot undo response-time redaction. A selection whose row was cleared or evicted
**fails** (`INVALID_EVIDENCE_SELECTION`, whole selection rejected, JSON and HAR alike),
because the historical seal no longer proves current masking. Export while rows remain
retained; re-export from a fresh snapshot. Bookmarks do not pin rows. This does not
retract strings or files already produced before disposal.

JSON and provenance use **schemaVersion2** with masked messages, omission/truncation,
revision/hits/bookmark/disposition, intent/run/outcome/state/overlay/responseBytes/
warnings. This is not policy JSON, a Burp project or request replay.

HAR remains1.2 with required log/entry/request/response/cache/timing fields; v2
metadata is in `_cairnGuard`. Cookies arrays are deliberately empty and sensitive
header copies masked. Standard header/body sizes are `-1` (original wire unknown);
`content.size` measures masked text only with `_sizeIsRedactedTextOnly:true`.
`_cairnGuard.responseBytes` separately carries the native body scalar. Time/timing
zeroes are placeholders with `timingsKnown:false`, not measured zero latency.
Missing response has status0, empty content, `responseObserved:false`;
`responseSource` distinguishes `NOT_OBSERVED`, `LOCAL_BLOCK`, `RESPONSE_CALLBACK`.
No redirect is inferred from a header/display URL.

Both are labeled **`REDACTED_EVIDENCE_NOT_WIRE_CAPTURE`**,
`completeWireCapture:false`, `forwardedMeans:NATIVE_RELEASE_NOT_PROVEN_DELIVERY`.
Truncation/omission/local disposition must accompany downstream excerpts.

Incident JSON is a **separate masked scalar watcher projection**, not a sealed
TrafficEntry/raw-message export. `[from,to)` is at most24hours; fields are `window`,
`events`, top20 `top5xx`/`topBytes`, `complete`, `truncated`, `approximate`,
`approximation`, `retention`. Count/max/lastSeen/5xx are exact for retained
observations; p95Bytes is a **log2-histogram upper-bound approximation**. Startup,
clear, ring loss, clock regression and retention constrain completeness; unknown
bytes do not prove zero-size responses. Candidate IDs are opaque keyed route IDs,
**not overlay UUIDs**. `policyUrl` is an optional safe query-free route, empty after
masking/change/unrepresentability. Never rebuild it from raw UI or automatically
persist candidates. UI export remains an explicit owner-only file choice.

## Verification boundary

Synthetic tests live under `src/test/java/dev/cairnguard/evidence/` with watcher
privacy integration under runtime. Developer command (not run by this doc task):

```sh
./gradlew --offline --no-daemon test --tests 'dev.cairnguard.evidence.*' \
  --tests '*ResponseWatcherRemaskingTest'
```

Coverage includes nested/encoded/reflected/Basic/Base64 secrets, unsupported-body
omission, mask-before-bound, UTF-8 cuts, eviction/update/clear, immutable snapshots,
categorical reasons/counters, JSON/HAR, forged seals/v2-field tampering, raw UI
lifecycle/limits/HEX, incomplete captures and response-only watcher remasking.

Historical initial evidence-module run(2026-11-03):60 synthetic cases; historical
pre-v2 integration added53-category native-denial regressions. Those counts are
**not current v2 native proof**. Current tests iterate the shared denial vocabulary;
full frozen-snapshot results are in [VERIFICATION.md](VERIFICATION.md). Historical
installed-Burp masking observations in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md)
do not certify this unreleased source or final exact artifact. No actual v2 native
phase or final independent implementation audit is recorded as complete.
