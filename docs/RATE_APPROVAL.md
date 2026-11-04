# Shared pacing, in-flight uncertainty, and human approvals

Implemented in `src/main/java/dev/cairnguard/runtime/RateGate.java` and
`ApprovalQueue.java`. Public APIs follow `INTERFACES.md` and
`RUNTIME_UI_CONTRACT.md`. These classes contain no Swing, Montoya, network I/O,
authentication mutation, traffic storage, or background/timer threads.

## Explicit human protection-OFF boundary (2026-11-04)

The following RateGate/ApprovalQueue guarantees apply to **protected** requests. Human-confirmed all-passthrough is a separate native-boundary path, not an approval, a gate reset or a new Allow rule. New OFF requests bypass both classes and have no permit/retained evidence. Mode transitions cancel existing waits, including approved-but-queued requests, and never recycle a protected in-flight permit. Old protected responses still complete normally. Restoring protection only governs new requests; stop traffic and independently confirm OFF connections have completed before relying on protected concurrency. OFF status is persistently visible and runtime/project bound. See [PASSTHROUGH.md](PASSTHROUGH.md).

## What is and is not paced

One controller must share **one RateGate** across all participating workers and
hosts. Each admission satisfies **both** the global and canonical-host cadence,
as well as the in-flight concurrency bound. Host means host, not scheme/port:
requests to different ports or schemes on the same canonical host share its
budget. The policy/adapter remains responsible for actual-destination scope
and best-effort content inspection; this scheduler does not inspect HTTP headers.

Cadences use `System.nanoTime()`, with integer interval
`ceil(1_000_000_000 / RPS)` nanoseconds. On admission the next slot is scheduled
from the **actual admission time**, never the previously scheduled slot. Thus
idle time, delayed scheduling, completed responses, and settings changes do not
accumulate burst credits. This is deliberately more conservative than a token
bucket or a sliding-window average.

The guarantee is **callback admission spacing**, not exact HTTP wire timing,
arrival order, target delivery, or a firewall. Scheduling after this gate, other
extensions, native buffering, traffic outside the exposed Proxy callbacks,
CONNECT/WebSocket frames and direct sockets are outside this class's guarantee.
A count of admitted callbacks is not a count of target-delivered requests.

### Per-host FIFO, eligible round-robin, and bounded host state

- A fair lock serializes admission. Each canonical host has a FIFO of genuinely
  waiting calls. FIFO means **enqueue order within that host**, not thread-start
  order or a global ordering across hosts. Only the head of a host's FIFO can
  receive a permit.
- Waiting hosts form a round-robin ring. Select the first **eligible** host head,
  skipping hosts still owing cadence or quarantined by their own stalled native
  work. A successful admission moves that host to the ring's tail if it still
  has waiters. Skipped hosts retain their turn; once eligible, a continuously
  queued host cannot be overtaken repeatedly by the same competing host.
  Cancellation removes a waiter without spending the host's turn.
- A fresh caller cannot jump an eligible queued host or its own host's FIFO.
  It may admit immediately when all queued host heads are ineligible and its
  own cadence and the global gates allow it. Thus slow A does not impose
  **host-rate head-of-line blocking** on ready B. This is not an unconditional
  "no HOL" guarantee: global RPS still serializes admissions, and occupied
  global concurrency slots, including stalled permits, still block everyone.
- `maxQueued=0` still permits an immediate admission when both cadence and
  concurrency are available. Only a call that actually needs to wait consumes a
  queue slot. The global queue bound always applies; overflow is `QUEUE_FULL`.
- A sole waiting host may use all `maxQueued` slots for compatibility. Once
  another host needs to queue, each competing host is capped at
  `max(1, ceil(maxQueued / 2))` waiters. A newcomer reclaims capacity from an
  overrepresented host by rejecting its **newest excess waiters** as
  `QUEUE_FULL`, retaining that host's oldest waiters. It does not evict host
  enforcement state or revoke permits/debt. If all global slots are already
  occupied by fair-sized queues, the newcomer is rejected instead. With a
  bound of one, the existing waiter keeps that single slot. If competition
  disappears the remaining host may again grow to the full global bound;
  previously rejected calls are never revived.
- Request hosts and configured `hostRps` keys both use
  `PolicyEngine.canonicalHost`: ASCII case, one terminal DNS dot, IDN/punycode,
  and equivalent IPv6 spellings share a key. Duplicate canonical override keys
  are invalid, rather than silently choosing one. No DNS resolution occurs.
- Host state is bounded to **4096 keys**, including active and queued hosts.
  At capacity, a host can be evicted only if it has no active/queued reference
  and all of its committed rate debt has expired. A host created for an attempt
  that never admitted and is no longer queued is removed. There is no eviction
  of an active, waiting, or still-rate-indebted host to make an admission fit.
  Exhaustion fails closed as `HOST_CAPACITY`. Malformed hosts also fail closed
  under this categorical reason; no raw host value is placed in exceptions.

## True in-flight ownership and timeout quarantine

`acquire(host, stillCurrent)` returns a `RateGate.Permit`. The permit starts at
admission (conservatively including any subsequent pre-dispatch delay). The
caller must hold it until either:

1. native completion/response is actually observed; or
2. dispatch **conclusively has not begun**, such as an adjacent policy rejection
   before native continuation.

Only in these cases should the caller call `Permit.close()`. Close is idempotent
and can run on a different thread. A caller timeout, an uncertain transport
failure, pausing, switching projects, cancelling approvals, updating policy, or
unloading the gate is **not** evidence of native completion and must not cause
release. The class cannot infer native completion from an ordinary `close()`
call; this is an integration obligation, not a proof made by this API.

If an open permit reaches `requestTimeoutMillis`, that permit is latched as
stalled. New and queued acquisitions for **that canonical host** fail with
`IN_FLIGHT_TIMEOUT`; its other ports/schemes share that quarantine. The permit
stays active and continues counting toward true **global** concurrency. Other
hosts may use genuinely free global slots and may wait for still-non-stalled
operations to complete. A single stalled host is not a global pause.

If the number of stalled permits alone reaches the live `maxConcurrent`, every
usable global slot is pinned: acquisitions for **all** hosts fail with
`IN_FLIGHT_TIMEOUT`. There is no promise of cross-host progress in this state.
There is never automatic recycling, retry, timed release, optimistic decrement,
or a hidden reset. A late actual completion can close its own permit and free
that slot; a host's quarantine clears only after all its stalled permits close.
Increasing the timeout after expiry cannot clear a latch. Raising concurrency
can allow other hosts to use newly available slots, without revoking existing
permits or clearing the stalled host. Non-stalled permits also continue counting
against concurrency until their explicit completion-owned release.

Waiting calls wake at the relevant cadence, request deadline, queue deadline,
or a bounded 50ms current-state poll, even without a response or external
signal. There are no watcher threads. An idle gate discovers aging on the next
acquire/update/snapshot/explicit permit close. This does not send anything or
recycle anything in the meantime.

`RateGate.close()` permanently rejects/wakes waiters as `SHUTDOWN`, **without
closing outstanding permits**. Late real completions may still close their own
permits after gate shutdown. Replacing the controller/gate is not a safe way to
clear uncertain native operations: an operator may begin a genuinely fresh run
only after independently quiescing/completing native traffic. There is no public
"force release"/"reset stalled" operation.

## Live settings, current-state checks, and hard bounds

`update(Limits)` validates before publishing any state and wakes waiters. It
uses the policy engine's exact bounds; invalid updates are atomic and expose
only `INVALID_LIMITS`:

| Setting | Accepted inclusive range |
| --- | --- |
| Global/default per-host/override RPS | 1–1000 |
| Maximum concurrent | 1–100 |
| Maximum queued | 0–10000 |
| Queue/approval/request timeout | 1–600000 ms |
| Host overrides | 0–256 distinct canonical hosts |

- Lower concurrency affects new admissions; it never revokes existing permits.
  The active count can therefore exceed a newly lowered limit until real
  completions occur. Higher concurrency can admit eligible older waiters.
- Rate increases do not erase the previous committed slot; subsequent slots use
  the faster interval. Rate decreases extend retained global/host debt from the
  last admission if needed. Updating a setting never mints burst credit.
- A reduced queue bound first keeps the oldest global waiters and rejects
  excess newest waits with `QUEUE_FULL`. If multiple waiting hosts remain,
  it also applies the new per-host fairness cap, rejecting each host's newest
  excess waits. A queue/rate/concurrency update never changes per-host FIFO
  ordering or the surviving hosts' round-robin turns.
- Queue timeout uses total monotonic time since enqueue and the live setting,
  not time since the latest wake/update. Expired waits are denied **before** an
  increased timeout can take effect; an increase may extend only still-live
  waits. A lower timeout can expire older waits immediately.
- Lower request timeout can quarantine already-open permits immediately.
  Raising it cannot revive operations already expired under the previous
  setting. A latched stall persists until explicit completion-owned release.
- `stillCurrent` is checked before waiting and immediately adjacent to
  admission; false or a runtime exception means `POLICY_CHANGED`. It must be a
  short, nonblocking state check, without capturing native/raw traffic. The
  controller/adapter must also recheck project/revision/pause adjacent to the
  native continuation: no stand-alone predicate check can make that external
  operation atomic.
- Interruption propagates `InterruptedException` and removes the waiter. It
  never releases an unrelated/open permit. Checked `Rejected` reasons are
  `QUEUE_TIMEOUT`, `QUEUE_FULL`, `SHUTDOWN`, `POLICY_CHANGED`,
  `IN_FLIGHT_TIMEOUT`, `HOST_CAPACITY`.

### Bounded gate status

`snapshot()` and its nested rows/list are immutable. Existing numeric fields,
particularly `hosts`, retain their types. The additive `hostMetrics` list
contains **canonical hostnames** (not URLs, paths, headers, or request bodies),
so status is operational metadata for the existing human UI, not a new worker
or network control API:

| Key | Meaning |
| --- | --- |
| `active` | All open permits, including reserved pre-dispatch and stalled ones |
| `queued` | Currently queued waiting calls, not active sends |
| `stalled` | All open latched-overdue permits; affected hosts are quarantined, not necessarily the whole gate |
| `admitted` | Cumulative callback admissions, not proven delivery |
| `rejected` | Cumulative checked rejections observed by acquire callers |
| `closed` | Permanent gate shutdown state |
| `globalRps`, `perHostRps`, `maxConcurrent`, `maxQueued` | Live settings |
| `hosts` | Retained bounded host-state keys, including unexpired rate debt |
| `timedOut` | Cumulative permits ever latched overdue, counted once each |
| `hostMetrics` | At most 64 retained-host rows, described below |
| `hostMetricsTruncated` | True when retained hosts were omitted from the list |
| `hostMetricsOmitted` | Number of retained hosts omitted, not an eviction count |

Each host row has exactly `host`, `rps`, `inFlight`, `queued`, and
`p95WaitMillis`. `rps` is the **effective configured admission-rate ceiling**,
including a canonical host override, not measured target throughput.
`inFlight` includes stalled/reserved permits. Rows are ranked by
`inFlight + queued` descending, then canonical hostname ascending; top-64
truncation never deletes underlying enforcement state. Aggregating visible rows
is not a complete total when truncation is true.

`p95WaitMillis` is nearest-rank p95 over that retained host's most recent **128
successful admissions**, including zero waits for immediate admissions. The
fixed-size ring is not a lifetime or time-window statistic; rejected,
interrupted and timed-out waits are excluded. Nanoseconds are rounded up to
milliseconds after percentile selection, and an unsampled host reports zero.
At most 4096 host rings are retained, and only 64 rings are copied/sorted per
snapshot. Inactive, debt-free host eviction also discards that host's samples;
it never evicts a live permit, queue or rate debt. Snapshot may reap already
expired queue entries but never releases a native permit.

Counters saturate at `Long.MAX_VALUE`. Interrupted waits are not counted as
checked rejections. No URLs, evidence values, parser text, or request contents
appear in this status. Canonical hostname disclosure is intentional for the
requested per-host diagnostics; malformed input is never echoed.

## Human-only bounded approvals

`ApprovalQueue` contains at most **100** live waits. It takes only an evidence ID,
project ID, timeout, and current-state predicate; the caller supplies opaque
metadata references, and the UI resolves the evidence ID through already-masked
`EvidenceStore` data. There is no request object, raw request/header/body/URL
field, native continuation callback, or rate/concurrency permit in the queue.
Do not pass traffic/secrets in reference fields or capture traffic in predicates.
References are bounded to 512 UTF-16 characters, nonblank, without controls or
surrogate code units; invalid metadata is rejected with a categorical exception.

`Pending(id,evidenceId,projectId,createdAt,expiresAt)` is an immutable public
record. `snapshot()` returns immutable unresolved rows in oldest-enqueued order,
not wall-clock sort order, at most 100. Display timestamps are ISO8601 UTC wall
clock; **all expiry decisions use monotonic time**, so wall-clock jumps cannot
extend or shorten an approval. Timeout is fixed per wait, inclusive 1–600000ms.

- `decide(id, allow)` is one-shot. Unknown, consumed, already-decided, expired or
  stale IDs return false. Expired/stale entries are denied, never allowed by a
  late click. New attempts for the same evidence get new approval IDs.
- A successful click is provisional until the waiting caller consumes it:
  current-state, expiry, cancellation and shutdown are checked again before an
  allow returns. Approved-but-not-consumed entries remain capacity-counted and
  cancellable; they are no longer shown as pending. Capacity is conservative
  rather than opening a gap that could bypass cancellation.
- `cancelAll(reason)` denies/wakes existing waits but does not close the queue
  to future attempts. `DENIED` and `SHUTDOWN` stay categorical denials;
  policy/project/pause/unknown/null reasons normalize to `POLICY_CHANGED`.
  Untrusted caller reason strings are never echoed. `close()` permanently
  denies all waits and future attempts as `SHUTDOWN`.
- Expiry, staleness, interruption, denial and successful consumption all clean
  up entries. Capacity checks and snapshots also reap stale/expired entries;
  there is no accumulating completed-history map or background worker.
- `Result` reasons are exactly `APPROVED`, `DENIED`, `APPROVAL_TIMEOUT`,
  `APPROVAL_CAPACITY`, `SHUTDOWN`, `POLICY_CHANGED`; only `APPROVED` can be an
  allowed result produced by the queue.

**Ordering obligation:** evaluate policy first; only an ASK may enter this
queue. A hard scope/lifecycle BLOCK must never be presented as approvable.
Await approval **before** acquiring a rate/concurrency permit, and do both waits
off the Swing EDT. An approval is not a scope bypass and is not a native-send
command. Controller revision/project/pause changes must cancel approvals and
invalidate `stillCurrent`; the controller must still perform its adjacent
native-release check after these APIs return.

## Synthetic verification and limits of evidence

Owned tests:

- `src/test/java/dev/cairnguard/runtime/RateGateTest.java`
- `src/test/java/dev/cairnguard/runtime/ApprovalQueueTest.java`

Run without changing normal Gradle locking:

```sh
./gradlew test --tests 'dev.cairnguard.runtime.RateGateTest' \
  --tests 'dev.cairnguard.runtime.ApprovalQueueTest' --offline --no-daemon
```

Historical verification on 2026-11-03: **59/59 then-owned tests passed**
(34 RateGate and 25 ApprovalQueue), including five forced-rebuild repeat runs.
The then-current full synthetic project suite passed 299/299 tests. Those
results describe the earlier global-FIFO/global-quarantine implementation;
they are not evidence for the new scheduling semantics.

Verification on 2026-11-04 for the eligible per-host scheduler: **68/68 tests
passed** (43 RateGate and 25 unchanged ApprovalQueue), in **five forced-rebuild
repeat runs** (`--rerun-tasks`) in an isolated private scratch project, using a
snapshot of the v2 models/policy validator and the same dependency lockfile.
The tests exercise both the original eight-argument `Limits` fixtures and v2
new-profile defaults; invalid v2 limits are rejected atomically. No build was
run in the shared live project. An initial test-only compilation issue was
corrected before these passing runs. These are local unit/synthetic results,
not a full-project regression or native Burp proof.

The suites use only synthetic hosts, fabricated metadata, fake monotonic clocks
and local worker threads. Five workers start simultaneously in several real
clock tests. Strict minimum gaps are asserted at the gate's actual monotonic
admission timestamp (a package-private test observation), **not** a timestamp
recorded after arbitrary caller-thread rescheduling, and never at the wire.
Tests cover shared global/host cadences, aliases/IDN/IPv6 overrides, rounding,
per-host FIFO and eligible round-robin, deterministic slow-A/fast-B progress
and starvation prevention, idle no-burst behavior, five-worker true in-flight
maximum, explicit/late/idempotent/cross-thread release, host-local latched
quarantine and all-global-slots-pinned failure, real unsignalled deadline wake,
live updates, exact deadlines and nanoTime wrap, queue overflow/shrink,
single-host capacity/competing-host reclamation and cancellation, immutable
per-host metrics and recent-ring p95, top-64 truncation with 4096 simultaneous
retained host keys, 100 pending human approvals, provisional clicks,
stale/expired allows, wall-clock jumps,
interruption, cancellation, reentrant shutdown/cancellation during validation,
and categorical failures. Test-only constructors can supply a monotonic clock
and a smaller capacity; public constructors always use production bounds and
system clocks. Executors are shut down and waits are unblocked in cleanup.

No native Burp project, real target, proxy loopback, installed application,
license state, system settings, credentials, or production request was used for
these tests. They do not establish native callback coverage, byte-for-byte
continuation, response correlation, true on-wire pacing, or real target
delivery; those remain separate adapter/native integration obligations. Later installed-Burp pacing, held-response concurrency, approval/queue and late-response quarantine observations are recorded separately in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md); they do not convert these unit tests into native tests.
