# Redacted evidence — storage and exports

## Contract and trust boundary

`dev.cairnguard.evidence.EvidenceStore` implements the evidence API in
[`INTERFACES.md`](INTERFACES.md). It is a synchronized, **memory-only** store. It does
not open files, contact a server, change authentication, or replace native Burp
request/response objects. Callers supply **inspection copies**. A `FORWARDED` outcome
means the native continuation was released; it does **not** prove delivery, receipt,
or successful processing by a target. `BLOCKED` means a local block, not a target
HTTP error.

`begin(projectId, projectName, request, decision, revision)` returns a random unique
ID. Redaction/discovery finishes before insertion. Raw `RequestData`, bodies,
headers, URI/parser trees and plaintext credential candidates are transient locals,
never fields of the store or `TrafficEntry`. `response` similarly captures only a
masked copy. Do not log those inputs or exception messages in adapters.

`TrafficEntry` is an immutable record. Its minimum contract accessors are supplemented
with `requestCapture()` / `responseCapture()`, immutable `Message` records containing
masked headers, body, MIME type, `bodyOmitted`, `truncated`, and `present` flags.
`request()` and `response()` render inspection-copy text, not original HTTP bytes;
an absent response is the empty string. `timestamp()` is an ISO8601 UTC observation
time, **not** measured wire timing. HTTP versions displayed as HTTP/1.1 are export
placeholders, not a measured protocol version.

## Redaction and deliberate fidelity loss

The fixed replacement marker is **`[REDACTED]`**. Discovery precedes rendering, so a
credential in a later JSON property/header can also be removed from an earlier
URL, project name, rule name, or innocent-looking `echo` property.

- Header/key matching is case-insensitive, removes separators for recognition, and
  handles bracketed/nested names. Authorization, Proxy-Authorization, authentication,
  Cookie, Set-Cookie, API/access/private keys, token/JWT, password, secret,
  credentials, session, CSRF/XSRF, nonce, signature, OTP/PIN and OAuth code fields
  are treated conservatively. **Entire sensitive header values are masked**, not
  just selected cookie pairs. Unknown non-sensitive fields are not an endorsement
  that their contents are public.
- URL user information and fragments are never retained. Query keys and values
  are inspected, including nested form/JSON strings. A path component following a
  sensitive component (for example `/token/value`) is masked. Known credentials
  reflected in other path components, hostname, headers, metadata, JSON keys or
  values are also masked; a credential-bearing hostname makes the URL fall back
  to `https://redacted.invalid/`.
- Query/form decoding uses `+` as space; path decoding leaves `+` literal. Strict
  UTF-8 percent and Unicode escape decoding is limited to three rounds. Malformed
  or over-encoded input is **not** partially captured. Display URLs/form data are
  normalized/re-encoded, so `[REDACTED]` appears percent-encoded there.
- JSON is strictly parsed, including duplicate-key and trailing-token rejection.
  Nested arrays/objects, Unicode escapes, percent-encoded keys, stringified JSON,
  embedded forms and recognizable inline secret assignments are inspected. A
  sensitive subtree is replaced as a whole; its scalar secrets are discovered for
  reflection checks. Parsing is limited to 32 traversal levels / 8192 nodes and
  the shared JSON parser's hard limits.
- Structured JSON and URL-encoded form bodies are supported only with UTF-8 /
  US-ASCII and identity Content-Encoding. Nonempty HTML, free text, XML, binary,
  multipart, unsupported encodings/charsets, malformed data and oversized input
  bodies are replaced **wholly** with
  `[OMITTED: UNSAFE_OR_UNSUPPORTED_BODY]`. There is no raw-prefix fallback.
  This deliberately loses fidelity rather than trying to guess secrets in HTML
  or arbitrary text. An unsafe/ambiguous discovery also suppresses unconstrained
  metadata and scalar text conservatively. Empty bodies stay empty.
- Credentials discovered in a request can reappear in a response under a benign
  key, embedded in a longer string, percent/Unicode-escaped, or in standard/URL
  Base64 encodings. A bounded per-entry index of **keyed HMAC-SHA256 fingerprints**
  supports these reflection checks without retaining plaintext credentials. A
  rolling-hash prefilter is always verified by HMAC before replacing a substring.
  Basic credentials are also decoded for user/password reflection checks. This
  is not universal decoding of arbitrary transformations/encryption.
- The fingerprint index is capped at 128 candidates, 24 distinct lengths, and
  8192 characters per candidate. Exceeding any cap switches to conservative text
  suppression instead of quietly missing credentials. These derived fingerprints
  and random keys stay private in memory; they are neither exported nor persisted,
  and are discarded on eviction/clear.
- New response secrets extend that bounded index and re-mask currently retained
  request/project/rule copies as well. Structured display values are parsed again
  for this step (including escaped strings); a previously truncated body that can
  no longer be parsed safely is omitted rather than reused as an unchecked prefix. Already returned immutable snapshots cannot
  be retroactively changed; consumers should refresh their view rather than
  keeping an unbounded history of snapshots.
- Arbitrary decision/outcome/error strings are **not** stored. Recognized fixed
  categorical reasons are accepted (case/hyphen/space normalized), including the
  shared finite `model.DenialReasons.ALL` vocabulary. Native `PAUSED`,
  `IN_FLIGHT_TIMEOUT` and adapter/capacity failure labels are preserved, not replaced
  by a generic label. Unknown reasons become `POLICY_DECISION` / `OUTCOME_RECORDED`. Unknown dispositions become
  `ERROR`. No parser exception text, captures, raw URL, or raw secret is placed in
  an error string. Status codes outside 100–599 become unknown.

This is defensive redaction, not a general data-loss-prevention classifier: an
unrecognized secret deliberately put in a benign field or transformed using an
unsupported scheme cannot be identified with certainty. Do not feed unneeded
sensitive content into evidence; inspect exports before sharing. No claim is made
about traffic absent from the Burp callback, other extensions' changes, TLS
pass-through, direct sockets, CONNECT/WebSocket frames, or complete wire coverage.

## Bounds and lifecycle

Defaults are **2000 entries**, **32 MiB total estimated retained bytes**, and
**64 KiB per request/response captured text part** (including the rendered start
line). Oldest insertion is evicted first; bookmarking does **not** pin evidence or
bypass the bounds. Response growth and bookmark/outcome updates enforce the same
total bound. A record larger than the total capacity can itself be evicted.

The total estimate charges strings at `max(UTF-8 bytes, 2 × UTF-16 length)` plus
per-string/record/header/rule overhead and fingerprint storage. This is a
conservative retained-text estimate, **not a cap on the entire JVM heap**. Transient
input/parser/redaction/export buffers and immutable snapshots held by consumers
are outside the retained-store budget. Callers must not accumulate snapshots.
Input parsing is independently capped at 1 MiB, with at most 256 captured headers.
Oversized input is omitted wholly, not truncated raw.

**Mask first, then bound.** An otherwise supported body is fully inspected and
masked before its copy is bounded. A secret beyond byte 65536 can still remove a
reflection earlier in the URL or body. Masked output is cut on UTF-8 code-point
boundaries with `[TRUNCATED]`; header overflow is dropped with a truncation flag.
A truncated JSON/form body is display text and need not remain a valid original
body document. Metadata has separate masked bounds (512 bytes per project/rule
string, 128 rule hits, 8192-byte URL bound with whole-URL fallback). Omission and
truncation are different: unsupported bodies are omitted, not described as full
captures. Capture flags and the entry's sticky `truncated()` communicate losses.

`snapshot()` returns an unmodifiable newest-first list; nested hit/header lists
are also copied. UI search/filter/bookmark selection must operate on these masked
fields. `bookmark(id, value)` creates a new record, never mutates a prior snapshot.
Unknown/evicted IDs are no-ops counted as orphan updates. Native release and local
block are mutually exclusive terminal facts: a `BLOCKED` entry cannot later be
mislabeled `FORWARDED`, and a released entry cannot be relabeled as locally blocked
by a late generic callback. `clear()` discards retained
evidence/fingerprints and resets retained gauges, **not cumulative counters**.

### Fixed `stats()` keys

All values are numbers (`long`); the returned map is immutable.

| Key | Meaning |
| --- | --- |
| `begun` | Total `begin` observations, including later evictions/clears |
| `forwarded`, `blocked` | First such outcome per retained ID; duplicate callbacks do not inflate it |
| `responses` | First successfully captured response per retained ID, not proof of target delivery |
| `localResponses`, `upstreamResponses` | Captured-response classification; local BLOCKED responses are separate; `upstreamResponses` means a nonlocal response callback, not independently verified origin |
| `evictions` | Cumulative capacity removals, including update-time evictions |
| `truncations` | Entries ever truncated while retained, counted once per ID |
| `retainedEntries`, `retainedBytes`, `bookmarked` | Current gauges |
| `clears`, `clearedEntries` | Clear operations and entries discarded by clear (not capacity evictions) |
| `orphanUpdates` | Updates whose ID was no longer retained / unknown |
| `outcomeCallbacks`, `responseCallbacks` | All corresponding API callbacks, including duplicates/orphans |
| `orphanOutcomes`, `orphanResponses` | Corresponding callbacks lacking a retained ID |

No unbounded tombstone/history map is kept. Therefore late callbacks for an evicted
ID cannot be uniquely deduplicated or reclassified; their activity is still visible
in the callback/orphan counters rather than silently presented as retained captures.

## JSON and HAR 1.2

`exportJson(selection)` and `exportHar(selection)` return strings; **neither writes
a file automatically**. Export at most 2000 store-created immutable entries, within
the 32 MiB selection estimate. Each entry carries an in-memory authenticity seal
over its redacted fields. Exports reject foreign/forged entries categorically,
preventing a caller-created raw `TrafficEntry` from becoming a redaction bypass.
The seal is not a credential and is not emitted in either export. For still-retained
IDs, exports use the latest masked record, so selecting a stale UI snapshot cannot
undo redaction learned from a response. Old genuine snapshots remain exportable
after eviction/clear using the same store instance; the store cannot learn more
about an ID after discarding it.

JSON includes a schema version, masked entries, separate omitted/truncated capture
flags, revision, decision hits, bookmark, disposition and `_cairnGuard` provenance.
It is an evidence-copy schema, not a raw Burp project or native request replay.

HAR exports a `log` with version `1.2`, creator, entries, pages, standard request /
response / cache / timing fields, masked headers/query/postData/content, and
`_cairnGuard` at log and entry level. Cookies are deliberately **not parsed** into
HAR cookie arrays (empty arrays); Cookie/Set-Cookie header copies remain masked.
Headers/body sizes are `-1` (unknown original size). `content.size` measures only
the masked display text and has `_sizeIsRedactedTextOnly: true`. Timing fields and
`time` are zero placeholders with `timingsKnown: false`, not measured zero latency.
A missing response has status `0`, empty content and `responseObserved: false`;
it is not fabricated as a success or a target block. A captured local block is
labeled `responseSource: LOCAL_BLOCK`. No redirect is inferred from display data.

Both formats are labeled **`REDACTED_EVIDENCE_NOT_WIRE_CAPTURE`**,
`completeWireCapture: false`, and
`forwardedMeans: NATIVE_RELEASE_NOT_PROVEN_DELIVERY`. Truncation, omission and the
local disposition must accompany excerpts in downstream reports.

## Unit verification (separate from native experiments)

Tests are under `src/test/java/dev/cairnguard/evidence/` and use synthetic fixture
hosts/credentials only:

```sh
./gradlew test --tests 'dev.cairnguard.evidence.*'
```

Coverage includes nested/encoded/Unicode/malformed JSON and forms, sensitive
headers and reflected secrets (including Basic/Base64), unknown/unstructured body
omission, mask-before-bound regression, UTF-8 cuts, count/byte/update eviction,
immutable snapshots/bookmarks, categorical errors, cumulative counters, concurrent
callbacks/export, JSON parseability, HAR required fields/provenance, and forged
export rejection. These are **unit tests**, not real Burp smoke or wire fidelity
validation. No real target traffic or installed Burp project is required.

Initial isolated evidence-module verification on 2026-11-03 (historical): Java 21 main compilation succeeded; the focused Gradle
suite passed **60 synthetic unit cases**. The first offline test attempt lacked
cached test dependencies; the normal wrapper test invocation resolved those
existing build dependencies, and the focused suite then passed offline. No
build/shared model files were changed and no native Burp smoke was run **in that initial module task**.

Subsequent native integration work found and fixed generic fallback labels for some runtime denials. Parameterized regressions now check **all 53 native denial categories** in snapshots and both exports, while unknown raw text remains excluded. See [VERIFICATION.md](VERIFICATION.md) and [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md) for the current full suite and actual installed-Burp observations.
