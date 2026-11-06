# Runtime / human UI contract — automatic blocking removed

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
removal. Risky modal Enter/Escape/close defaults to Cancel. Viewers render plain
selectable scrollable text, never HTML; close disposes owned dialogs/timers/workers.

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

## Evidence boundary

Tests distinguish pure unit/model/controller, Mockito Montoya boundary, owned raw
loopback, real isolated Swing scale1/2, and installed Burp. No automatic removal
source change repairs/proves native callback delivery, extension ordering, target
arrival, TLS-pass-through or authenticated quotas. Historical native reports and
old heavy/circuit/fan-out runner phases describe previous behavior, not current
acceptance. Use [test inventory](AUTOBLOCK_REMOVAL_TEST_MAP.md); do not infer release
or independent review from source/tests alone.
