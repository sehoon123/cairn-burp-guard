package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.policy.PolicyEngine;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * One shared, bounded, FIFO callback-admission gate, not a wire-delivery scheduler.
 * No timer threads, network I/O, traffic copies, or idle burst credit. A permit MUST stay open
 * until native completion, or until the caller knows dispatch conclusively did not begin.
 */
public final class RateGate implements AutoCloseable {
    private static final int MAX_HOSTS = 4_096;
    private static final long SECOND = TimeUnit.SECONDS.toNanos(1);
    private static final long CURRENT_POLL = TimeUnit.MILLISECONDS.toNanos(50);
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition changed = lock.newCondition();
    private final ArrayDeque<Waiter> queue = new ArrayDeque<>();
    private final Map<String, Host> hosts = new HashMap<>();
    private final Set<Permit> active = new LinkedHashSet<>();
    private final LongSupplier nanoTime;
    private final int hostCapacity;
    private Settings settings;
    private boolean closed;
    private boolean hasAdmission;
    private long lastAdmission;
    private long nextAdmission;
    private long admitted;
    private long rejected;
    private long timedOut;

    public RateGate(Limits limits) {
        this(limits, System::nanoTime, MAX_HOSTS);
    }

    /** Package-local deterministic-clock/capacity seam; production always uses nanoTime/4096. */
    RateGate(Limits limits, LongSupplier nanoTime, int hostCapacity) {
        if (hostCapacity < 1 || hostCapacity > MAX_HOSTS) throw new IllegalArgumentException("INVALID_HOST_CAPACITY");
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.hostCapacity = hostCapacity;
        this.settings = validated(limits);
    }

    /** Atomic live update. Previously committed rate debt is never erased by a settings change. */
    public void update(Limits limits) {
        Settings replacement = validated(limits);
        lock.lock();
        try {
            long now = nanoTime.getAsLong();
            // An increase of the timeout cannot un-stall an already expired native operation.
            markStalled(now);
            expireWaiters(now);
            settings = replacement;
            if (hasAdmission) nextAdmission = extend(nextAdmission, lastAdmission + settings.globalInterval(), now);
            for (Map.Entry<String, Host> entry : hosts.entrySet()) {
                Host host = entry.getValue();
                if (host.hasAdmission)
                    host.nextAdmission = extend(host.nextAdmission, host.lastAdmission + hostInterval(entry.getKey()), now);
            }
            markStalled(now);
            expireWaiters(now);
            // Retain the oldest waiters if the human lowers the live queue bound.
            while (queue.size() > limits.maxQueued()) {
                Waiter excess = queue.removeLast();
                excess.queued = false;
                excess.host.queued--;
                excess.failure = "QUEUE_FULL";
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits off the EDT. The supplied predicate must be short, nonblocking, and contain no traffic.
     * FIFO is enqueue order (including head-of-line blocking across different hosts).
     */
    public Permit acquire(String host, BooleanSupplier stillCurrent) throws Rejected, InterruptedException {
        Objects.requireNonNull(stillCurrent);
        String key;
        try { key = PolicyEngine.canonicalHost(host); }
        catch (IllegalArgumentException e) {
            lock.lockInterruptibly();
            try { throw reject(closed ? "SHUTDOWN" : "HOST_CAPACITY"); }
            finally { lock.unlock(); }
        }
        lock.lockInterruptibly();
        Waiter waiter = null;
        Host state = null;
        try {
            while (true) {
                if (closed) throw reject("SHUTDOWN");
                if (!current(stillCurrent)) throw reject("POLICY_CHANGED");
                if (closed) throw reject("SHUTDOWN");
                long now = nanoTime.getAsLong();
                if (markStalled(now) != 0) throw reject("IN_FLIGHT_TIMEOUT");
                if (waiter != null) {
                    if (waiter.failure != null) throw reject(waiter.failure);
                    if (elapsed(now, waiter.createdAt) >= millis(settings.limits().queueTimeoutMillis()))
                        throw reject("QUEUE_TIMEOUT");
                }
                if (state == null) state = host(key, now);
                if (eligible(waiter, state, now)) {
                    // Check again immediately adjacent to admission; the adapter/controller must
                    // additionally check policy/project adjacent to its actual native continuation.
                    if (!current(stillCurrent)) throw reject("POLICY_CHANGED");
                    if (closed) throw reject("SHUTDOWN");
                    now = nanoTime.getAsLong();
                    if (markStalled(now) != 0) throw reject("IN_FLIGHT_TIMEOUT");
                    if (waiter != null) {
                        if (waiter.failure != null) throw reject(waiter.failure);
                        if (elapsed(now, waiter.createdAt) >= millis(settings.limits().queueTimeoutMillis()))
                            throw reject("QUEUE_TIMEOUT");
                    }
                    // Defensive against a predicate reentering update/close/acquire. Normal
                    // predicates are pure state checks, but a mutation must never bypass bounds.
                    if (hosts.get(key) != state) { state = null; continue; }
                    if (!eligible(waiter, state, now)) continue;
                    if (waiter != null) remove(waiter);
                    hasAdmission = true;
                    lastAdmission = now;
                    nextAdmission = now + settings.globalInterval();
                    state.hasAdmission = true;
                    state.lastAdmission = now;
                    state.nextAdmission = now + hostInterval(key);
                    state.active++;
                    Permit permit = new Permit(state, now);
                    active.add(permit);
                    admitted = increment(admitted);
                    changed.signalAll();
                    return permit;
                }
                // maxQueued=0 still permits the immediate path above; only actual waits count.
                if (waiter == null) {
                    if (queue.size() >= settings.limits().maxQueued()) throw reject("QUEUE_FULL");
                    waiter = new Waiter(state, now);
                    state.queued++;
                    queue.addLast(waiter);
                }
                long wait = Math.min(CURRENT_POLL,
                        millis(settings.limits().queueTimeoutMillis()) - elapsed(now, waiter.createdAt));
                for (Permit permit : active) {
                    long untilStalled = millis(settings.limits().requestTimeoutMillis()) - elapsed(now, permit.admittedAt);
                    wait = Math.min(wait, untilStalled);
                }
                if (queue.peekFirst() == waiter && active.size() < settings.limits().maxConcurrent()) {
                    long rateWait = Math.max(hasAdmission ? remaining(nextAdmission, now) : 0,
                            state.hasAdmission ? remaining(state.nextAdmission, now) : 0);
                    if (rateWait > 0) wait = Math.min(wait, rateWait);
                }
                if (wait > 0) changed.awaitNanos(wait);
            }
        } finally {
            if (waiter != null && waiter.queued) {
                remove(waiter);
                changed.signalAll();
            }
            // Do not retain a host created solely for a rejected/interrupted attempt. No rate
            // debt exists until an admission; active/queued references still pin their host.
            if (state != null && !state.hasAdmission && state.active == 0 && state.queued == 0)
                hosts.remove(key, state);
            lock.unlock();
        }
    }

    /** Fixed, safe operational metadata; no host/request/approval values are exposed. */
    public Map<String, Object> snapshot() {
        lock.lock();
        try {
            int stalled = markStalled(nanoTime.getAsLong());
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("active", active.size());
            result.put("queued", queue.size());
            result.put("stalled", stalled);
            result.put("admitted", admitted);
            result.put("rejected", rejected);
            result.put("closed", closed);
            result.put("globalRps", settings.limits().globalRps());
            result.put("perHostRps", settings.limits().perHostRps());
            result.put("maxConcurrent", settings.limits().maxConcurrent());
            result.put("maxQueued", settings.limits().maxQueued());
            result.put("hosts", hosts.size());
            result.put("timedOut", timedOut);
            return Map.copyOf(result);
        } finally {
            lock.unlock();
        }
    }

    /** Rejects/wakes waiters; never frees a possibly still-running native operation. */
    @Override public void close() {
        lock.lock();
        try {
            closed = true;
            while (!queue.isEmpty()) {
                Waiter waiter = queue.removeFirst();
                waiter.queued = false;
                waiter.host.queued--;
                waiter.failure = "SHUTDOWN";
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public static final class Rejected extends Exception {
        private static final long serialVersionUID = 1L;
        private final String reason;
        private Rejected(String reason) {
            super(reason);
            this.reason = reason;
        }
        public String reason() { return reason; }
    }

    /**
     * Sole release mechanism, idempotent and cross-thread safe. Timeout, policy changes and gate
     * shutdown NEVER call this on the caller's behalf. It does not itself prove native completion.
     */
    public final class Permit implements AutoCloseable {
        private final Host host;
        private final long admittedAt;
        private boolean stalled;
        private boolean released;
        private Permit(Host host, long admittedAt) {
            this.host = host;
            this.admittedAt = admittedAt;
        }
        // Strict synthetic assertions use the admission clock, not thread rescheduling after return.
        long admittedAtNanos() { return admittedAt; }
        @Override public void close() {
            lock.lock();
            try {
                if (released) return;
                markStalled(nanoTime.getAsLong());
                released = true;
                active.remove(this);
                host.active--;
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    private boolean eligible(Waiter waiter, Host host, long now) {
        return (waiter == null ? queue.isEmpty() : queue.peekFirst() == waiter)
                && active.size() < settings.limits().maxConcurrent()
                && (!hasAdmission || remaining(nextAdmission, now) == 0)
                && (!host.hasAdmission || remaining(host.nextAdmission, now) == 0);
    }

    private Host host(String key, long now) throws Rejected {
        Host existing = hosts.get(key);
        if (existing != null) return existing;
        if (hosts.size() >= hostCapacity) {
            Iterator<Host> iterator = hosts.values().iterator();
            while (iterator.hasNext()) {
                Host candidate = iterator.next();
                if (candidate.active == 0 && candidate.queued == 0
                        && (!candidate.hasAdmission || remaining(candidate.nextAdmission, now) == 0)) iterator.remove();
            }
        }
        if (hosts.size() >= hostCapacity) throw reject("HOST_CAPACITY");
        Host created = new Host();
        hosts.put(key, created);
        return created;
    }

    private int markStalled(long now) {
        int count = 0;
        for (Permit permit : active) {
            if (!permit.stalled && elapsed(now, permit.admittedAt) >= millis(settings.limits().requestTimeoutMillis())) {
                permit.stalled = true;
                timedOut = increment(timedOut);
                changed.signalAll();
            }
            if (permit.stalled) count++;
        }
        return count;
    }

    private void expireWaiters(long now) {
        Iterator<Waiter> iterator = queue.iterator();
        while (iterator.hasNext()) {
            Waiter waiter = iterator.next();
            if (elapsed(now, waiter.createdAt) >= millis(settings.limits().queueTimeoutMillis())) {
                iterator.remove();
                waiter.queued = false;
                waiter.host.queued--;
                waiter.failure = "QUEUE_TIMEOUT";
            }
        }
    }

    private void remove(Waiter waiter) {
        if (!waiter.queued) return;
        queue.remove(waiter);
        waiter.queued = false;
        waiter.host.queued--;
    }

    private Rejected reject(String reason) {
        rejected = increment(rejected);
        return new Rejected(reason);
    }

    private long hostInterval(String host) {
        return settings.hostIntervals().getOrDefault(host, settings.perHostInterval());
    }

    private static Settings validated(Limits limits) {
        try {
            // Reuse the policy's exact hard bounds and duplicate-alias validation, without traffic.
            new PolicyEngine().validate(new GuardConfig(1, List.of(), List.of(), List.of(), GuardConfig.Mode.BLOCK, limits));
            Map<String, Long> overrides = new HashMap<>();
            limits.hostRps().forEach((key, value) -> overrides.put(PolicyEngine.canonicalHost(key), interval(value)));
            return new Settings(limits, interval(limits.globalRps()), interval(limits.perHostRps()), Map.copyOf(overrides));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("INVALID_LIMITS");
        }
    }

    private static boolean current(BooleanSupplier predicate) {
        try { return predicate.getAsBoolean(); }
        catch (RuntimeException e) { return false; }
    }
    private static long interval(int rps) { return (SECOND + rps - 1) / rps; }
    private static long millis(long value) { return TimeUnit.MILLISECONDS.toNanos(value); }
    private static long elapsed(long now, long start) { return now - start; }
    private static long remaining(long deadline, long now) { return Math.max(0, deadline - now); }
    private static long extend(long oldDeadline, long newDeadline, long now) {
        return now + Math.max(remaining(oldDeadline, now), remaining(newDeadline, now));
    }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }

    private record Settings(Limits limits, long globalInterval, long perHostInterval, Map<String, Long> hostIntervals) {}
    private static final class Host {
        private boolean hasAdmission;
        private long lastAdmission;
        private long nextAdmission;
        private int active;
        private int queued;
    }
    private static final class Waiter {
        private final Host host;
        private final long createdAt;
        private boolean queued = true;
        private String failure;
        private Waiter(Host host, long createdAt) {
            this.host = host;
            this.createdAt = createdAt;
        }
    }
}
