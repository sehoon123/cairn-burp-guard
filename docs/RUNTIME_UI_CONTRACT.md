# Runtime / human UI contract — v0.3.0 history candidate, automatic blocking still removed

This describes current source, not a published JAR/native acceptance claim.
`GuardUiAccess` remains in-process human-only: no worker/MCP/network control API,
request sender/replay, authentication/session mutation or automatic policy save.
See [INTERFACES.md](INTERFACES.md) for exact API shapes.

## Ownership and lifecycle

One controller owns policy/project/revision, authored RateGate/ApprovalQueue,
IntentBudget/ListenerRegistry, observational ResponseWatcher and complete unmasked
in-memory evidence. Prepared is a single-use controller-issued capability; forged
projections cannot authorize/commit. No body/native object/continuation is retained
across waits. Observation metadata never owns native execution.

Lifecycle and operator pause remain independent. Current states are PROTECTED,
PAUSED_BY_OPERATOR, POLICY_INVALID, POLICY_SAVE_UNCERTAIN, PROJECT_UNVERIFIED,
SHUTDOWN; individual authored intent/listener/queue/callback capacity denials remain.
Old CIRCUIT_OPEN/OVERLAY_BLOCK/IN_FLIGHT_STALLED categories are historical only, not
current status. Save uncertainty and project uncertainty fail closed; verified
reload/save does not silently resume retained pause/recovery. Revision changes on
policy/project/mode/pause transitions, not just saves. Clear/project/unload dispose
originals. Source/epoch fences prevent late callbacks resurrecting cleared data.

## Protected native handoff

```text
nativeMode before capture
 -> complete original copy + optional bounded content inspection
 -> actual destination/path scope and explicit rules
 -> Prepared; lifecycle/intent checks; ASK wait if required
 -> authored pacing/queue admission off EDT
 -> construct non-sending original-object native continuation
 -> final project/revision/pause/policy/shutdown and intent commit
 -> evidence-only ID association; return continuation
```

Continuation factories may reenter/fail; they run before final commit. Fixed local
451/drop fails closed on immediate native errors. Forwarded means native handoff,
not delivery/success. Unknown dispatch is not automatically retried/refunded.
No watcher check/claim, ticket capacity, native permit, correlation100 cliff,
configured native concurrency, timeout quarantine or response-dependent admission
exists. Prior5xx/oversize/fan-out/slow/streaming/missing callbacks cannot auto-block
or auto-pause later allowed requests. No master/per-reason bypass switch was added.

Known never-reused Proxy IDs associate responses only with retained protected
originals. Reuse is permanently ambiguous, not a new denial. Protected-only
provenance can permit response-only unpaired evidence, never a guessed pair.
OFF/mixed/cleared/old-project/unknown provenance is not guessed/captured. Used-ID
tombstones are content-free, memory-only, including OFF IDs; no admission authority.
Full unpaired originals and unavailable request metadata survive JSON/HAR exports.
Actual native status/body-length scalars are independent of content-copy success;
unknown is -1, not a zero sentinel. Close records no new responses.

## Manual settings and seven tabs

The tabs are **개요, 대상, 규칙, 요청 기록, 승인 대기, 설정, 사건 내보내기**.
Automatic-block/candidate tabs, release/ignore/exception/detector authoring and
native-stall recovery advice are removed. Incident count/max/lastSeen/5xx remain
observational; p95 is a log2 upper-bound approximation. No actuator events exist.

Settings expose global/default/host-override rates (0=off,1–1000), queue/approval
timing, explicit intent budget (0=off) and strict exact GET health paths. New rates
are0/0; saved positive rates remain. **모든 속도 제한 끄기 (초안)** sets every rate,
including existing override rows, to0 without saving or changing any other field.
Cancel does nothing; normal Save/CAS applies. Presets change only two draft rates.
Manual intent reset stays confirmed/CAS and does not save policy.

Legacy maxConcurrent/requestTimeout/response-size/TTL/circuit/fan-out and detector
exceptions remain strict, inactive, round-trippable data. They have no authoring
controls or load/save reactivation. Full-policy advanced JSON preserves their old
shape but cannot make them operational. No collection quota or masking is added.

## Scope, explicit rules and health

Scope uses actual transport host/scheme/port and untouched request path, never
Host/:authority. All-path accepts dot/matrix/encoded pentest spellings unchanged;
restricted paths cover bounded routing views. Unavailable optional inspection is
reported, never pretended successful or a blanket denial. EXEMPT outranks ordinary
BLOCK/ASK, not scope/lifecycle/manual pause/authored rate or intent constraints.
Exact configured GET health needs empty verified body, no query and one complete
route. It bypasses only manual pause, never scope/rules/ASK/project/shutdown/rate/
intent. Health configuration remains strict even though traffic acceptance is not
a path sanitizer. GET can have side effects; enabling/changing needs confirmation.

## Listener boundary and temporary OFF

H is user-DEFERRED, not a current gate/PASS. Empty guardListenerPorts protects ALL
Proxy listeners. Current native observer supplies no trusted cross-namespace ID.
New nonempty selections cannot be created in UI/whole-policy JSON. Preserve old
restrictions on unrelated saves; they fail closed before capture until explicit
confirmed clearing to all-listener protection. Never infer listener identity.

Human-confirmed **모두 통과 (보호 끔)…** is separate runtime-only ALL Proxy OFF,
not ALLOW or pause. NEW OFF callbacks bypass scope/rules/inspection/approval/rate/
intent, capture no contents/association and keep a count. Old protected response
associations may finish logging. Old waits cancel without approval; operator pause
and intent usage survive OFF/ON. Project/restart/unavailability resets OFF; native
failure/shutdown/stale final token still fail closed. OFF is not needed to remove
retired auto-blocking or to disable all authored pacing. Native concurrency is
uncontrolled in protected mode as well; independently quiesce traffic for rollback.

## Human drafts, data and exports

EDT-only forms and one-second coalescing refresh preserve the original modal
project/revision baseline, never rebase a stale save. Explicit confirmations/CAS
remain for EXEMPT, health, legacy listener clearing, migration, intent reset,
protection OFF, destructive clear/delete/overwrite and every plaintext export.
V1 migration stays memory-only until explicit save; no automatic legacy rule
removal. Risky modal Enter/Escape/close defaults to Cancel. Raw/header/body/metadata viewers remain plain selectable scrollable text. Optional
static HTML inspection uses a sink-free closed projection, not an HTML engine;
close disposes owned dialogs/timers/workers.

All headers/bodies/URLs/metadata/rows/observations remain complete and unmasked in
memory until clear/project/unload. Plaintext credentials and unbounded heap/OOM/UI
latency are accepted risks, not reasons to cap or automatically spool originals.
Optional parser/inspection limits and immediate callback/approval/queue/intent
capacities remain distinct. Response-only evidence exposes unavailable request
metadata rather than fabricated traffic.

JSON/HAR/incident human file exports require per-file plaintext confirmation,
lock-time immutable snapshot, serialization/IO outside runtime locks/off EDT,
owner-only permissions and same-directory atomic publication with final source/
project/revision/raw-generation check. No output size cap/non-atomic fallback.
The short final-check-to-rename race, sampled project boundary, non-POSIX ACLs and
wire completeness remain limitations; clear cannot retract existing exported files.

## History search, paired inspectors and static preview ownership

Proxy-only capture is unchanged. Search is human inspection only. It cannot change
policy, approval, pacing, OFF, forwarding bytes, capture, authentication or provenance.
The default and Reset are empty text, All, Literal. Empty text disables general search
in every location and mode. Whitespace is data. Dedicated filters stay literal AND.

The immutable `TrafficSearch.Query(text, location, mode)` key contains exact source
text, one of ALL, METADATA, REQUEST_HEADERS, REQUEST_BODY, RESPONSE_HEADERS or
RESPONSE_BODY, and LITERAL or RE2. Pattern identity is not part of equality.
The closed `Input` is either `CompiledQuery` with a private pattern or a fixed
`Invalid` category. The EDT compiles on text or selector edits, not timer refresh or
structured-filter changes. RE2 source and compiled program are each bounded at
4,096 characters and instructions respectively. The UI field keeps its existing
4,096-character authoring limit. Pure Literal matching has no new compiler bound.
These are authoring/compiler limits, never field, result, capture or retention caps.

All searches the existing metadata OR selected request/response content. Metadata
contains only displayed original URL, displayed method, UTC timestamp, status string,
raw and translated reason, and evidence ID. Existing unavailable-source fallbacks
remain. Tags, guardState, MIME, warnings, preview and synthetic first lines are not
metadata candidates. Header and body locations select only the named side/field.
Literal metadata keeps Locale.ROOT lowercase substring behavior and immediate hits.
Literal content keeps the existing character-folding algorithm. RE2 uses installed
RE2/J CASE_INSENSITIVE and Boolean find, with inline flags unchanged. It does not
lowercase, quote or trim patterns, or use Java backtracking regex. No query DSL,
index, second search scheduler, capture groups, replay or persistence is added.

Each duplicate header is an independent `name: value` field. Metadata values,
headers, bodies and request/response never join, even with `(?s)`. Only present,
nonempty UTF8_TEXT and displayed contiguous HEX bodies are eligible. Odd-position
HEX matches remain possible; binary is never reinterpreted as UTF-8. Absent, EMPTY
and UNAVAILABLE bodies cannot satisfy zero-width expressions. Retained headers
remain searchable when their body is unavailable. Known incomplete content keeps
its warnings. Empty metadata values can satisfy zero-width patterns without proving
body availability. Response-only evidence never invents a request match.

The EDT constructs `Subject(entry, originalAvailable, metadata)` with a copied list
of immutable metadata strings. Session/Pump takes these snapshots, never runtime
access. Content results retain the Message identity cache. RE2 All/Metadata matching
runs on the same Pump, not the EDT. Its sole additional cache uses TrafficEntry
identity and exact metadata/availability snapshots. Equivalent new Subjects reuse
results, changed snapshots and equal-but-distinct entries do not. No generated record
equality or hashing is a result key. One job covers missing content and metadata;
pending includes both. Both caches and scanning sets prune retired inputs. Merge
checks still-retained identities and snapshots. All three Query components invalidate
old work and hits; independently compiled equal keys reuse results. Unchanged Messages
survive timer and bookmark changes, while replacement response identities rescan.

Malformed/unsupported RE2, rejected oversized edits and oversized programs publish
fixed BAD_RE2, TOO_LONG or TOO_COMPLEX feedback. No raw pattern, exception or cause
enters diagnostics. Invalid input cancels results, empties rows/selection and clears
owned presentation plaintext. A rejected edit does not truncate or silently resume
the retained document text. Timer refresh and other filters leave it invalid; an
actual text/selector edit or Reset recovers. Unavailable/closed guards still apply.
Pending exposes known current-query results only. Failure retains known same-query
partial results and is not retried on unchanged timer refresh. Retired/cancelled
generations publish nothing. Invalid, pending and failed are distinct states.

Two owned lanes, search and presentation, each have one processing thread, one
replaceable latest input and one coalesced latest EDT result. Replacements follow
actual task exit/finally, not Future cancellation/done. RE2 receives zero-copy,
non-String field views whose character reads count Work units. Bounded subsequences
retain the same cancellation accounting. Checks also bracket find and separate
fields. Headers are not copied into a second full line and fields are not chunked,
so anchors and spanning semantics stay intact. Pinned-library cancellation tests
prove interruption inside giant body, header and metadata scans, not a fixed latency.
No access calls or whole raw getters run on workers, and body formatting does not run
under Proxy-shared locks. Unchanged content/presentation projections are reused.

Search location/mode stay visible with Detailed filters collapsed. Labels target
the controls and renderers remain inert. The history scrolls when wrapped controls,
feedback and the split pane's minimum height do not fit, rather than clipping errors.
Export freezes click-time currently visible or selected-visible IDs and the
pending/failed incomplete-results notice. Search completion or selector changes during
chooser/consent neither add eventual matches nor invalidate that snapshot solely
because search changed. Existing source loss and project/revision/epoch/raw-generation
checks still apply. Exporter/formats/originals are unchanged and never read viewer,
search or preview text. No body, row, result or export quota is added.
General-search and every dedicated-filter edit reuse refreshNow to reconcile
project/revision and current source membership before publishing, without compiling
again on refresh. A retained row without raw originals stays metadata-searchable.
The panel keeps immutable evidence-ID/lead-ID selection intent across unresolved
verification of that subject, never TrafficEntry/Message/plaintext references.
Only verified displayed rows receive JTable selection; all inspection, navigation,
resolution and selected-visible exports still read that actual selection. Traffic
sorts reproject IDs/lead under the selection guard, not JTable's automatic reselection.
New human selection/navigation/filter edits supersede dormant intent. Ordinary AND
filter exclusion, a settled miss (even while another subject is pending), source
retirement, invalid input, project/revision change, failure, clear and close discard
obsolete intent. Temporary presentation clearing does not discard unresolved intent.
Before publication the EDT refreshes project/status/snapshot, brackets revision,
and checks Message identity/availability/selection/generation. This is sampled,
not an atomic runtime authorization. Clear invalidates work and blanks all owned
views first. Source loss/project transition/failed refresh/close drop pending,
cache/selection/plaintext; failed refresh empties traffic so typing cannot revive
it. Close signals/interrupts owned threads without an indefinite EDT join; replacement
work cannot overlap retired processing. Native/unrelated work is untouched.

The first11 columns retain meanings; sortable appended observed response body
bytes (Long/unknown null), declared MIME and capture state do not invent latency,
Tool or wire lengths. Native column resize/reorder and view-only outcome colors
preserve text/selection contrast. A vertical collapsible split holds table and
inline horizontally paired raw/headers/bodyHEX inspectors, visible reason/navigation
and metadata. Raw first lines are explicitly synthetic inspection projections.
The one optional modal popout owns separate documents/components; it never reparents
inline viewers. Previous/next uses current sorted/filtered view order without wrap.
All windows drop plaintext on disposal/clear/project/failure/close. Panel close also
blanks the same owned approval-review Document before disposing its dialog; this is
not zeroization of copied Strings, clipboard data or exported files.

Preview is lazy for the selected tab/response, never direct raw/native rendering.
Complete present UTF8_TEXT/empty plus exactly one valid HTML/XHTML Content-Type
with absent or one supported UTF8/UTF-8/US-ASCII charset is required. Absent charset
uses the store's already strictly validated inspection copy, not encoding detection.
Duplicate/malformed/unsupported/HEX/incomplete/unavailable or ambiguous/nonidentity
encoding produces an honest unavailable reason; no sniff/decompress/XML guessing.
An iterative quote-aware scanner drops every attribute/URL/CSS/event. Closed blocks,
runs/styles become ordinary JPanel/GridBag table layout and explicit StyledEditorKit
DefaultStyledDocument leaves. No HTML/XML/native engine, URL/file/resource loader,
HTML ViewFactory, component/icon attribute, class loading or hyperlink/form action
receives captured data. Decoded entities are never reparsed as markup. Headings,
paragraphs/lists/tables/formatting are basic layout; complex/nested layout, uncommon
entities and nesting beyond64 are approximations, without cutting ordinary text or
originals. Script/style/title/template is suppressed; active/media elements are inert
placeholders. No CSS/images/JS/navigation/forms/full-browser fidelity. Large AST,
components/documents and EDT layout may consume unbounded heap/time. Raw/export is
authoritative. Logger++ workflow inspiration includes no AGPL code/assets/dependency.

## Evidence boundary

Tests distinguish pure unit/model/controller, Mockito Montoya boundary, owned raw
loopback, real isolated Swing scale1/2, and installed Burp. No automatic removal
source change repairs/proves native callback delivery, extension ordering, target
arrival, TLS-pass-through or authenticated quotas. Historical native reports and
old heavy/circuit/fan-out runner phases describe previous behavior, not current
acceptance. Use [test inventory](AUTOBLOCK_REMOVAL_TEST_MAP.md); do not infer release
or independent review from source/tests alone.
