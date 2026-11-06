# Authored pacing and human approval

These are source contracts, not native Burp arrival/callback-delivery guarantees.
Automatic blocking and native-completion-dependent admission have been removed.
There is no `RateGate.Permit`, native concurrency limit, timeout quarantine,
response-size/fan-out overlay, circuit or half-open claim.

## Independent rate axes and defaults

`globalRps`, `perHostRps` and each exact-host `hostRps` value accept **0=off** or
**1–1000**. Negative/overflow values are invalid; host overrides are at most256
canonical distinct hosts. New profiles use0/0; saved positive values are preserved.
An override replaces that host's default rate, not the global axis. Thus a zero
override disables that host's cadence while any positive global rate still applies.
A disabled global rate does not disable a positive default/override host cadence.

The guided **모든 속도 제한 끄기 (초안)** action sets global/default and EVERY host
row rate to0. It preserves host spellings/rows and every unrelated setting. It is
only a draft: cancel does nothing; normal explicit Save/project-revision CAS is
required. Intent budget0=off remains separate, visible and manually resettable.
Protection OFF is not required to disable pacing and is not an automatic-block fix.

## `RateGate` contract

`long acquire(String host, BooleanSupplier stillCurrent)` returns its monotonic
admission timestamp, not a lifetime resource. Global and canonical-host intervals
round up to nanoseconds and never accumulate idle burst credit. Host FIFO and
eligible-head round-robin prevent an ineligible slow host owning a ready host's
turn. A disabled rate imposes no interval/debt or divide-by-zero path. Disabling a
rate immediately discards only that axis's old debt; reenabling enforces the newly
authored interval from recent admission. Positive-to-positive increases preserve
committed debt; decreases extend it from the last admission as necessary.

Waiting calls alone consume `maxQueued` (0–10000). `maxQueued=0` still permits an
immediately eligible call. Queue deadlines use monotonic total enqueue age and
live `queueTimeoutMillis` (1–600000ms); a live update cannot revive an already
expired waiter. Queue shrink rejects newest excess waits, preserving oldest; a
competing host reclaims newest excess from a sole-host backlog using the existing
ceil(maxQueued/2) fairness bound. Interruption removes only its waiter.

At most4096 pacing host keys retain queues/unexpired rate debt; debt-free,
unqueued keys can be reclaimed. This is bounded authored pacing metadata, not a
response/correlation capacity and never waits for a native completion. An invalid
host or exhausted genuine pacing key capacity yields categorical `HOST_CAPACITY`.

`stillCurrent` is short/nonblocking and retains no raw/native traffic. It is checked
before waits and adjacent to admission; false/exception yields `POLICY_CHANGED`.
The controller/adapter separately recheck policy/project/manual pause/shutdown
adjacent to final original-object continuation. `update` validates atomically;
`close` permanently rejects/wakes waits as `SHUTDOWN`. Other checked reasons are
`QUEUE_FULL`, `QUEUE_TIMEOUT`, `HOST_CAPACITY`; there is no `IN_FLIGHT_TIMEOUT`.

`snapshot()` is immutable: `queued`, `admitted`, `rejected`, `closed`, `globalRps`,
`perHostRps`, `maxQueued`, numeric `hosts`, `hostMetrics`, `hostMetricsTruncated`,
`hostMetricsOmitted`. No `active`, `stalled`, `timedOut` or `maxConcurrent` claim.
Top64 rows contain `host,rps,queued,p95WaitMillis`, ranked by queued count then
canonical host. p95 is the most recent128 successful admission waits, not target
latency or capture retention. These operational samples remain bounded; raw
traffic/observations have no collection quota. Counters saturate; status has no
request URLs/headers/bodies. Callback pacing is not remote-arrival timing.

## Human-only bounded approvals

`ApprovalQueue` remains max100 unresolved/provisional waits with opaque approval,
evidence and project IDs, monotonic expiry (1–600000ms) and current-state checks.
It retains no request/body/native continuation. Only ASK enters; hard scope or
lifecycle denial is never approvable. Waits run off EDT, before pacing admission.

`Pending(id,evidenceId,projectId,createdAt,expiresAt)` snapshots are immutable and
oldest-enqueued first. Wall timestamps are display-only. One-shot `decide(id,allow)`
rejects stale/expired/consumed IDs. An allowed click is provisional until consumed:
expiry/current-state/cancellation/shutdown are checked again, and a provisional
entry still counts toward capacity. Cancellation cannot turn an old click into a
new handoff. `cancelAll` denies existing waits; `close` also denies future waits.
Categorical results: `APPROVED`, `DENIED`, `APPROVAL_TIMEOUT`, `APPROVAL_CAPACITY`,
`SHUTDOWN`, `POLICY_CHANGED`. Only `APPROVED` allows. Interrupted/completed/expired
entries are cleaned up without a completed-history quota or background thread.

## Verification boundary

`RateGateTest` retains/adapts exact pacing, aliases/IDN/IPv6, FIFO/fairness, queue
bounds/deadlines/wrap, cancellation/interrupt/shutdown, live updates and metrics.
`ApprovalQueueTest` is unchanged. `AutomaticBlockingRemovalTest` and adapter tests
prove absence of callback-dependent denial with synthetic traffic. See the
method-by-method [inventory](AUTOBLOCK_REMOVAL_TEST_MAP.md). These are not proof
that Burp supplies every callback or that a target received a continued request.
