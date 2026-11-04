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
budget. The policy/adapter remains responsible for authority/scope inspection.

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

### FIFO and bounded host state

- A fair lock serializes admission, with an explicit FIFO queue of genuinely
  waiting calls. FIFO order is enqueue order, not the time an OS thread was
  originally started. A new immediate caller cannot jump an existing waiter.
- **Head-of-line blocking is intentional**: a slow host at the front can delay
  other hosts even if their individual cadence is available. There is no
  host-skipping scheduler that could starve the slow host.
- `maxQueued=0` still permits an immediate admission when both cadence and
  concurrency are available. Only a call that actually needs to wait consumes a
  queue slot. Overflow fails closed as `QUEUE_FULL`.
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

If **any** open permit reaches `requestTimeoutMillis`, that permit is latched as
stalled and **all new admissions stop**, including those to other hosts. New and
queued acquisitions fail with `IN_FLIGHT_TIMEOUT`. The permit stays active and
continues counting toward true concurrency: there is no automatic recycle,
retry, timed release, optimistic decrement, or hidden reset. A late actual
completion can close it; quarantine clears only when no stalled permits remain.
Increasing the timeout after expiry cannot clear the latch. Other outstanding
non-stalled permits still count against concurrency.

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
- A reduced queue bound keeps the oldest waiters and rejects excess newest
  waiters with `QUEUE_FULL` immediately on wake.
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

### Safe gate status

`snapshot()` is immutable and contains only fixed numeric/boolean fields:

| Key | Meaning |
| --- | --- |
| `active` | All open permits, including reserved pre-dispatch and stalled ones |
| `queued` | Currently queued waiting calls, not active sends |
| `stalled` | Currently open latched-overdue permits; nonzero means quarantine |
| `admitted` | Cumulative callback admissions, not proven delivery |
| `rejected` | Cumulative checked rejections observed by acquire callers |
| `closed` | Permanent gate shutdown state |
| `globalRps`, `perHostRps`, `maxConcurrent`, `maxQueued` | Live settings |
| `hosts` | Retained bounded host-state keys, including unexpired rate debt |
| `timedOut` | Cumulative permits ever latched overdue, counted once each |

Counters saturate at `Long.MAX_VALUE`. Interrupted waits are not counted as
checked rejections. No hostnames, URLs, evidence values, parser text, or request
contents appear in this status.

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
queue. A hard scope/inspection BLOCK must never be presented as approvable.
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

Verification on 2026-11-03: **59/59 owned tests passed** (34 RateGate and 25
ApprovalQueue), including **five forced-rebuild repeat runs** using the command
above plus `--rerun-tasks`. The then-current full synthetic project suite also
passed: **299/299 tests**, via `./gradlew test --offline --no-daemon`. These
results are local unit/synthetic evidence, not a native Burp smoke test.

The suites use only synthetic hosts, fabricated metadata, fake monotonic clocks
and local worker threads. Five workers start simultaneously in several real
clock tests. Strict minimum gaps are asserted at the gate's actual monotonic
admission timestamp (a package-private test observation), **not** a timestamp
recorded after arbitrary caller-thread rescheduling, and never at the wire.
Tests cover shared global/host cadences, aliases/IDN/IPv6 overrides, rounding,
FIFO/head-of-line blocking, idle no-burst behavior, five-worker true in-flight
maximum, explicit/late/idempotent/cross-thread release, latched quarantine,
real unsignalled deadline wake, live updates, exact deadlines and nanoTime wrap,
queue overflow/shrink, 4096 simultaneous retained host keys, 100 pending human
approvals, provisional clicks, stale/expired allows, wall-clock jumps,
interruption, cancellation, reentrant shutdown/cancellation during validation,
and categorical failures. Test-only constructors can supply a monotonic clock
and a smaller capacity; public constructors always use production bounds and
system clocks. Executors are shut down and waits are unblocked in cleanup.

No native Burp project, real target, proxy loopback, installed application,
license state, system settings, credentials, or production request was used for
these tests. They do not establish native callback coverage, byte-for-byte
continuation, response correlation, true on-wire pacing, or real target
delivery; those remain separate adapter/native integration obligations. Later installed-Burp pacing, held-response concurrency, approval/queue and late-response quarantine observations are recorded separately in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md); they do not convert these unit tests into native tests.
