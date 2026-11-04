# Runtime / human UI contract — unreleased v2 source

Read [AGENTS.md](../AGENTS.md) and [INTERFACES.md](INTERFACES.md). This supersedes
the older second-wave global-FIFO, always-masked-history, six-tab and JSON-list
editor assumptions. It documents **source behavior**, not installed behavior,
release completion or independent approval. Exact snapshot/test limits are in
[VERIFICATION.md](VERIFICATION.md); native acceptance is still pending.

`GuardUiAccess` is in-process **human UI only**. It is not exposed to CAIRN/Pi
workers, a network server, MCP or automation endpoint. No authentication/session
management, request sending/replay, policy autosave or target polling is added.

## Controller ownership and lifecycle

One `GuardController` owns project policy/generation, one RateGate/ApprovalQueue,
ResponseWatcher, IntentBudget, ListenerRegistry and bounded masked/raw evidence.
It retains no request body/native object in `Prepared` across waits. Prepared is
a final class with original five-argument constructor/accessors; only
controller-issued one-shot provenance can authorize/commit. Display projections
or forged Prepared/token objects cannot acquire admission.

Lifecycle and operator pause are independent:

| Typed cause | Recovery / meaning |
|---|---|
| `PROTECTED` | Valid current project/policy; individual gates still apply |
| `PAUSED_BY_OPERATOR` | Human paused selected/protected listeners; exact configured health GET may bypass this only |
| `POLICY_INVALID` | Invalid project document, default-deny/reload required |
| `POLICY_SAVE_UNCERTAIN` | Save outcome uncertain; do not resume an older cached policy |
| `PROJECT_UNVERIFIED` | Project/recovery uncertainty; data-free failure, verified reload/save then explicit resume |
| `SHUTDOWN` | Closed; no new protected/bypass handoff |
| `CIRCUIT_OPEN`, `OVERLAY_BLOCK`, `INTENT_BUDGET`, `LISTENER_UNVERIFIED`, `CAPACITY`, `IN_FLIGHT_STALLED` | Typed runtime gates, not note-text guesses or target statuses |

`operatorPaused`, recovery-resume latch and lifecycle cause are separate. A valid
reload/save can repair policy validity but does not silently resume a retained
pause/recovery latch. `pause(false)` fails while reload is required. The controller
never infers safety from note strings. Runtime generation (`revision` and
`policyRevision`) changes on saves/project/mode/pause changes, not just disk writes.

Same-project saves, detector disabling and OFF/ON **retain existing overlays,
probe cadence and intent debt**. Epoch changes/uncertainty reset watcher/budget/
listener/tickets and dispose raw UI, but **never close true native permits**.
Old-epoch response tickets cannot mutate new watcher state. Verified persistence
recovery is not native in-flight recovery.

### Protected pipeline

```text
nativeMode(messageId) before capture
  -> bounded inspection copy -> actual-service/path scope and policy
  -> Prepared with masked/keyed metadata only
  -> hard lifecycle/watcher/budget advisory checks
  -> ASK human wait without rate permit
  -> rate/concurrency admission off EDT
  -> native original-object continuation factory (not a send)
  -> bounded native flight registration
  -> commitDetailed: final checks + watcher claim BEFORE intent consume
  -> return continuation = FORWARDED / native handoff, NOT delivery
```

Local factory/correlation/final policy/watcher/budget failures occur before new
quota is spent. A conclusively-unsent failure cancels its logical watcher ticket
and closes its own unsent permit. Uncertain dispatch is not refunded. Native
permit ownership ends only at matching actual completion; controller response
capture, deadlines, clear, settings, pause, OFF and close are not completion.

Response processing carries actual native status/body length independently of
optional copies/slots, with explicit completeness flags. Learn new response
secrets first, remask structured watcher values/pending flights, then observe
scalars under the controller lock also used for watcher display/incident export.
Never use raw getters for watcher metadata or replace text in serialized JSON.
Logical expiry fails the lease once but retains the same bounded masked ticket
and host/path reservations for actual late observation. Late ordinary heavy/5xx
scalars are still processed; an expired half-open cannot heal a replacement lease.
Status distinguishes nonexpired `watcherTickets` from `watcherLateTickets`
(nested watcher `activeTickets` / `lateTickets`); neither is free native capacity.
Exceptions before authorization transfers its permit close only that conclusively
unsent permit, never another flight or a timeout-quarantined native operation.

## Pacing, approvals and availability

- RateGate: global and canonical-host monotonic no-burst pacing; per-host FIFO,
  eligible-host round-robin, bounded queues/4096 host keys. Slow/quarantined A
  need not block ready B when genuine global slots exist. Global pacing/concurrency
  can still block everyone; this is not unconditional no-HOL or remote-arrival RPS.
- A stalled permit quarantines **its host** without recycling. Other hosts use
  genuine free global slots. If stalled permits alone pin maxConcurrent, all
  admission fails `IN_FLIGHT_TIMEOUT`. Late actual response can close its permit.
- Status top64 host rows (`host,rps,inFlight,queued,p95WaitMillis`) disclose
  canonical host operational metadata intentionally; p95 is the recent128
  successful-admission wait ring, not lifetime/target latency. Truncation is visible.
- ApprovalQueue: max100 unresolved/provisional waits, opaque IDs/project/evidence
  references only, monotonic expiry. A click is one-shot and provisional until
  consumed; stale/expired/cancelled allow never becomes handoff. No rate permit
  during human wait; callbacks/waits never EDT.
- ResponseWatcher: first `>` size response passes intact, **then** an automatic
  TTL route overlay blocks later attempts. Circuit expiry permits one GET/HEAD
  half-open at most once/service/30seconds, not auto-close.2xx–4xx closes;
  5xx/unknown/missing response reopens. Logical timeout cannot recycle native work.
- Fanout BLOCK is service-local, PAUSE a separate automatic global overlay, WARN
  diagnostic-only. Disabling a detector does not erase an existing episode.
- Intent labels are untrusted, unchanged `X-Cairn-Intent`/`X-Cairn-Run`. Final
  protected handoffs include EXEMPT/health/half-open; limit20 denies21st. Enabled
  accounting rejects invalid/duplicate/incomplete tag metadata. Absent intent is
  unbudgeted; toggling to0 does not erase prior debt. No authenticated worker quota.

See [RATE_APPROVAL.md](RATE_APPROVAL.md) / [INTERFACES.md](INTERFACES.md) for exact
bounds, queue fairness and component APIs.

## Eight human tabs and shared actions

`GuardPanel(GuardUiAccess)` constructs/refreshes on Swing EDT; `close()` stops the
refresh timer/export worker, disposes owned dialogs and releases UI references.
The one-second refresh rechecks project/status before displaying a new snapshot;
an open editor retains **its original** project/revision/policy baseline.

1. **개요**: typed state/cause, scope and cumulative/retained gauges, per-host
   metrics, watcher/intent summary, block/resume and explicit intent reset.
2. **대상**: exact URL draft/preview and explicit save; no automatic wildcard or
   path sanitization. All-path really permits raw pentest spellings within actual
   destination scope; restricted scope still checks internal routing views.
3. **규칙**: add/edit/toggle/delete, selectors/literal/RE2/case/AND/OR, EXEMPT mode.
   EXEMPT displayed with a warning/pinned view order without reordering stored
   policy. Unavailable header/body inspection is a warning, not successful matching.
4. **요청 기록**: separate **unmasked human-local** request/response/URL/tag display,
   bounded literal filters including intent/run/state/outcome and diagnostic
   masked metadata. Selected IDs/sort conversions survive bounded refresh.
5. **승인 대기**: review-only navigation is separate from one-shot approve/deny;
   hard scope/lifecycle/automatic blocks are not approvable.
6. **설정**: independent guided limits/safety/listener/health drafts; whole-policy
   JSON is optional advanced import/copy, not per-list JSON editors/Apply ALL.
7. **자동 차단**: masked overlay cause/host/path/creation/expiry, selected/all
   release with confirmation. Expired/replaced IDs cannot release another overlay.
8. **대용량 후보**: retained-window maximum descending, approximate p95/count/
   lastSeen/5xx and incompleteness labels. No automatic policy creation.

Usage guide/recipes/Enter/double-click are navigation or **draft filling only**.
They do not save policy, send traffic, approve requests or reset protections.
All captured text uses bounded plain JTextArea/text renderers, not active HTML.

### Raw UI versus masked outputs

Human history uses `rawRequest`, `rawResponse`, `rawUrl`, `rawCaptureInfo` only for
local display/search. It labels unmasked/inspection-copy/not-wire, truncated,
omitted, unavailable and UTF8/HEX. A missing raw row is not silently presented as
original; masked fallback metadata is identified. Raw content can include synthetic
or real credentials; human copying/screenshots require care.

Raw cache is separate from sealed masked TrafficEntry and independently bounded
(max2000 /estimated32MiB /64KiB per part). Project change/uncertainty/clear/close
and eviction dispose it. Late old callbacks cannot revive it. Existing raw history
can survive OFF, but **new OFF/unselected requests and responses have no content
capture**. No raw export/worker API/logging or automatic policy harvesting exists.

JSON/HAR selected/filtered exports serialize sealed masked TrafficEntry, not visible
raw strings. Masked incidents/candidates/overlays never read raw UI. Response-time
remasking invalidates changed `policyUrl`; export metadata includes actual scalar
bytes/warnings and retained/approximate/incomplete semantics. See [EVIDENCE.md](EVIDENCE.md).

### Candidate controls are drafts, not authority

Only an unchanged, query-free, already-masked actual-service `policyUrl` is eligible
for a candidate-derived draft. Missing/changed/redacted/unrepresentable route means
buttons disabled/rejected; **never reconstruct from raw URL/path**. Candidate ID is
an opaque keyed route ID, overlay ID a UUID; mutations use IDs, not display paths.
The UI re-fetches the candidate/URL before save and checks the original baseline.

- **일반 BLOCK 규칙 초안…** opens a human-editable unsaved URL rule. It remains an
  ordinary BLOCK, so a matching EXEMPT may outrank it. It is not an overlay.
- **이 경로 N MiB 초과 차단…** edits an exact watcher byte threshold, not a rule.
  It warns the first excess response already passes and existing overlays need
  separate expiry/release.0 disables size detection there, not other protections.
- **이 후보 무시…** hides bounded runtime candidate display only, not policy,
  incidents, active overlays, traffic or future request enforcement.

Candidate/incident count/max/lastSeen/5xx are exact only for retained observations;
p95 is a log2 upper-bound approximation. Retention is at most24hours, with bounded
rings/candidate eviction and explicit completeness/truncation. No lifetime or wire
coverage claim is made. Unknown size is not evidence of zero actual response bytes.

## Strict schema migration and human save

`PolicyCodec.decode` returns in-memory v2 plus `migrationPending` and original v1.
No load/status/watcher read saves it. V1 scope/limits/rules, including broad legacy
`delete-string`, remain; new protections default OFF. Fresh v2 defaults instead
include DELETE-method only and enabled conservative response detectors.

The persistent migration banner opens bounded original/migrated/line-position
comparison tabs and optional original-document export. Comparison is not a
semantic/LCS equivalence proof. Cancel/close writes nothing. Optional legacy removal
is **unchecked by default**, matches only the exact original enabled rule and never
removes disabled/customized/look-alike rules. Any explicit policy save while
migration is pending warns that it replaces storage with full schema2; saving some
other section does **not** silently remove that rule.

Before replacing a v1 document, export/review its operator-authored original locally.
The original is **not a redacted traffic export** and may contain authored sensitive
patterns. An older preview cannot read schema2. Rollback requires restoring that
original policy deliberately; loading an old JAR alone does not downgrade it.

`updateConfig(candidate,expectedProjectId,expectedRevision)` validates full config,
including disabled rows, then CAS-saves through current project storage. Before
and after confirmations the UI rechecks the **original** baseline, never swaps in
a fresh revision to make an old draft pass. Concurrent/stale/malformed drafts reject
categorically with no raw error text. Cancel/no-op leaves policy unchanged.
Runtime release/ignore/reset controls likewise use project/revision CAS but do not
save human policy or release native permits.

## Settings and risk confirmations

Guided forms preserve other policy sections and exact advanced/route/host data.
RPS/concurrency recipes fill only three draft fields. Seconds convert exactly to
milliseconds; MiB converts exactly to bytes, not rounded tolerances. Invalid table
edits/duplicates/out-of-bound inputs must not silently truncate or save.

Current risk confirmations in the common save path:

| Action | Confirmation / retained constraints |
|---|---|
| New/enabled/changed enabled EXEMPT | Explicit ordinary BLOCK/ASK bypass warning; hard/automatic/budget gates retained |
| New/changed nonempty listener selection | Rejected before save in UI/whole-policy JSON: H deferred, no verified native identity. Unrelated edits preserve legacy selection |
| Explicit clearing of legacy listener selection | Separate confirmation of transition to ALL Proxy protection, followed by original project/revision CAS; cancel/stale preserves old data |
| Health enabled or enabled routes changed | GET can have side effects; exact authored service/path only, no query/body; bypass only operator pause/circuit |
| Pending v1 → v2 save | Original backup/comparison, full schema2 save, no automatic legacy removal/old-JAR compatibility |
| Candidate path threshold | First-heavy limitation and retained active overlays |
| Overlay release/all / candidate ignore / intent reset | Scope of runtime change; no policy/native completion implied |
| Protection OFF / destructive clear/delete/overwrite | Separate explicit choice; stale baseline rejects |

Empty `guardListenerPorts` protects all. Native Proxy/HTTP shared-ID and original-
annotation assumptions were falsified. The observer supplies no trusted registry
proof; every current restriction rejects `LISTENER_UNVERIFIED` before native
capture. H is user-DEFERRED, not a current gate/PASS or merely pending confirmation.
New nonempty selections cannot be authored; old values remain until confirmed clearing.
No destination, number, timing or content-fingerprint fallback. Synthetic trusted-registry
behavior must not be presented as native support. See [current scope](ALL_LISTENERS_ACCEPTANCE.md)
and [historical findings](V2_NATIVE_FINDINGS.md).

Health exception requires exact configured actual service/path, **GET**, verified
empty body metadata, no query, and all routing views identical. It cannot bypass
invalid/save-uncertain/unverified/shutdown state, ordinary rules/ASK, heavy/fanout,
intent/rate/capacity. Health response does not heal a circuit. Authored routes stay
strict even though all-path traffic accepts semicolon/dot/encoded pentest variants.

## Protection OFF, retained pause and safe dialogs

`passthrough(enabled,expectedProjectId,expectedRevision)` is explicit runtime-only
all-Proxy OFF, not ALLOW/EXEMPT, not pause, and not persisted. Global OFF precedes
listener mapping/capture; new OFF callbacks keep only a saturating handoff count.
Known unselected listener bypass has its own count. Both retain final project/
generation/shutdown/native factory checks, never approve old protected Prepared.

OFF cancels waits, retains true flights, active protections and intent debt.
**Operator pause is retained across OFF/ON**. Status `paused=false` while OFF is
compatibility display only; `operatorPaused` remains true. ON returns to that pause
until explicit Resume. Pause action exits OFF. Successful save preserves OFF;
project/restart/uncertainty ends it. Quiesce OFF connections independently before
trusting protected concurrency after restoration. See [PASSTHROUGH.md](PASSTHROUGH.md).

Confirm/error dialogs use selectable plain wrapping text, real vertical scrolling,
resizable monitor-bounded windows and a separate wrapping button area. Default
Enter/Escape/close cancels risky confirmation; explicit affirmative selection is
required. Panel close disposes owned dialogs. If status refresh fails, emergency
block remains available but cannot resume or enable OFF from a stale view. These
are extension-tab warnings, not overlays across every native Burp tool tab.

Explicit export uses a chooser, bounded background serialization/write, owner-only
POSIX permissions when supported, symlink/change rejection, same-directory atomic
publication and overwrite confirmation. No non-atomic fallback or automatic path;
errors are categorical. Policy-original export is explicitly distinguished from
masked JSON/HAR/incident. No original logs/screenshots/profile data belong in Git.

## Validation status, not approval

Latest actual-artifact observations, HEX fix and unsupported-listener mitigation
are in [V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md) and
[VERIFICATION.md](VERIFICATION.md). No all-A–H/release approval exists.

**Historical pre-authorization checkpoint only:** revision3 clean Java1221 PASS; native-harness Python27
and local-template18 PASS (actual upstream not run). Real isolated Xvfb+owned-WM
Swing passed27 each at scale1 and scale2, then27 in a scale2 repeat. Test-only
synchronization now observes stable native wrap geometry and click coordinates;
actual focus/bottom-line assertions remain intact. The same217730… JAR reproduced
across local clean/repeated rebuilds; this is not an independent code review or
native Burp/platform/accessibility certification.
The disposable Burp attempt stopped at first EULA, with no terms accepted/extension
loaded/native phase. Requested independent design attempts are not final
implementation audits. No exact-artifact native A–H, release or production
reliability/completion approval is asserted.
