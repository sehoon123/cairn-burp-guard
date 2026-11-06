package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.policy.PolicyEngine;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/** Authored fixed-rate pacing only: host FIFO and eligible-host round-robin, never native lifetime. */
public final class RateGate implements AutoCloseable {
    private static final int MAX_HOSTS = 4_096;
    private static final int MAX_HOST_METRICS = 64;
    private static final int WAIT_SAMPLES = 128;
    private static final long SECOND = TimeUnit.SECONDS.toNanos(1);
    private static final long CURRENT_POLL = TimeUnit.MILLISECONDS.toNanos(50);
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition changed = lock.newCondition();
    // Global enqueue order is used only for capacity/deadlines/live queue shrink, not eligibility.
    private final ArrayDeque<Waiter> queue = new ArrayDeque<>();
    private final ArrayDeque<Host> roundRobin = new ArrayDeque<>();
    private final Map<String, Host> hosts = new HashMap<>();
    private final LongSupplier nanoTime;
    private final int hostCapacity;
    private Settings settings;
    private boolean closed;
    private boolean hasAdmission;
    private long lastAdmission;
    private long nextAdmission;
    private long admitted;
    private long rejected;

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

    /** Atomic live update: positive rates retain committed debt; zero disables that axis immediately. */
    public void update(Limits limits) {
        Settings replacement = validated(limits);
        lock.lock();
        try {
            long now = nanoTime.getAsLong();
            // Queued deadlines still apply when an authored timeout changes.
            expireWaiters(now);
            settings = replacement;
            if (hasAdmission) nextAdmission = settings.globalInterval() == 0 ? now
                    : extend(nextAdmission, lastAdmission + settings.globalInterval(), now);
            for (Host host : hosts.values()) {
                if (host.hasAdmission)
                    host.nextAdmission = hostInterval(host.key) == 0 ? now
                            : extend(host.nextAdmission, host.lastAdmission + hostInterval(host.key), now);
            }
            expireWaiters(now);
            // Retain oldest globally, subject to the competing-host fairness bound below.
            while (queue.size() > limits.maxQueued()) fail(queue.peekLast(), "QUEUE_FULL");
            if (roundRobin.size() > 1) trimHostQueues(fairQueueBound());
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits off the EDT. The predicate must be short, nonblocking, and contain no traffic.
     * Enqueue order is FIFO within a host; an ineligible host never owns another host's turn.
     */
    public long acquire(String host, BooleanSupplier stillCurrent) throws Rejected, InterruptedException {
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
                expireWaiters(now);
                if (waiter != null && waiter.failure != null) throw reject(waiter.failure);
                if (state == null) state = host(key, now);
                if (eligible(waiter, state, now)) {
                    // The adapter/controller must also check policy/project immediately adjacent
                    // to its native continuation. Predicates cannot make that external step atomic.
                    if (!current(stillCurrent)) throw reject("POLICY_CHANGED");
                    if (closed) throw reject("SHUTDOWN");
                    now = nanoTime.getAsLong();
                    expireWaiters(now);
                    if (waiter != null && waiter.failure != null) throw reject(waiter.failure);
                    // Defensive against predicates reentering update/close/acquire.
                    if (hosts.get(key) != state) { state = null; continue; }
                    if (!eligible(waiter, state, now)) continue;
                    long waitNanos = waiter == null ? 0 : elapsed(now, waiter.createdAt);
                    if (waiter != null) {
                        remove(waiter);
                        // A successful head consumes this host's turn; cancellation does not.
                        if (!state.waiters.isEmpty()) {
                            roundRobin.remove(state);
                            roundRobin.addLast(state);
                        }
                    }
                    hasAdmission = true;
                    lastAdmission = now;
                    nextAdmission = now + settings.globalInterval();
                    state.hasAdmission = true;
                    state.lastAdmission = now;
                    state.nextAdmission = now + hostInterval(key);
                    state.recordWait(waitNanos);
                    admitted = increment(admitted);
                    changed.signalAll();
                    return now;
                }
                // maxQueued=0 still permits the immediate path; only actual waits consume slots.
                if (waiter == null) waiter = enqueue(state, now);
                long wait = Math.min(CURRENT_POLL,
                        millis(settings.limits().queueTimeoutMillis()) - elapsed(now, waiter.createdAt));
                if (state.waiters.peekFirst() == waiter) {
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
            // A never-admitted, unreferenced host has no rate debt to retain.
            if (state != null && !state.hasAdmission && state.waiters.isEmpty())
                hosts.remove(key, state);
            lock.unlock();
        }
    }

    /** Bounded operational metadata, including canonical hosts but never URLs or request contents. */
    public Map<String, Object> snapshot() {
        lock.lock();
        try {
            long now = nanoTime.getAsLong();
            expireWaiters(now);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("queued", queue.size());
            result.put("admitted", admitted);
            result.put("rejected", rejected);
            result.put("closed", closed);
            result.put("globalRps", settings.limits().globalRps());
            result.put("perHostRps", settings.limits().perHostRps());
            result.put("maxQueued", settings.limits().maxQueued());
            result.put("hosts", hosts.size()); // Preserve numeric compatibility; rows are separate.
            List<Host> ranked = hosts.values().stream().sorted(Comparator
                    .comparingInt((Host host) -> host.waiters.size()).reversed()
                    .thenComparing(host -> host.key)).limit(MAX_HOST_METRICS).toList();
            List<Map<String, Object>> metrics = new ArrayList<>(ranked.size());
            for (Host host : ranked) {
                Map<String, Object> metric = new LinkedHashMap<>();
                metric.put("host", host.key);
                metric.put("rps", settings.hostRates().getOrDefault(host.key, settings.limits().perHostRps()));
                metric.put("queued", host.waiters.size());
                metric.put("p95WaitMillis", host.p95WaitMillis());
                metrics.add(Map.copyOf(metric));
            }
            result.put("hostMetrics", List.copyOf(metrics));
            result.put("hostMetricsTruncated", hosts.size() > metrics.size());
            result.put("hostMetricsOmitted", hosts.size() - metrics.size());
            return Map.copyOf(result);
        } finally {
            lock.unlock();
        }
    }

    /** Rejects and wakes pacing waiters. */
    @Override public void close() {
        lock.lock();
        try {
            closed = true;
            while (!queue.isEmpty()) fail(queue.peekFirst(), "SHUTDOWN");
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

    private boolean eligible(Waiter waiter, Host host, long now) {
        if ((hasAdmission && remaining(nextAdmission, now) != 0) || !hostReady(host, now)) return false;
        if (waiter == null) return host.waiters.isEmpty() && nextEligibleHost(now) == null;
        return host.waiters.peekFirst() == waiter && nextEligibleHost(now) == host;
    }

    private Host nextEligibleHost(long now) {
        for (Host host : roundRobin) if (hostReady(host, now)) return host;
        return null;
    }

    private static boolean hostReady(Host host, long now) {
        return !host.hasAdmission || remaining(host.nextAdmission, now) == 0;
    }

    private Waiter enqueue(Host host, long now) throws Rejected {
        boolean competing = roundRobin.size() > (host.waiters.isEmpty() ? 0 : 1);
        if (competing) {
            // A sole host may fill maxQueued. A newly waiting competitor reclaims capacity by
            // rejecting newest excess waiters, never by erasing committed rate debt.
            trimHostQueues(fairQueueBound());
            if (host.waiters.size() >= fairQueueBound()) throw reject("QUEUE_FULL");
        }
        if (queue.size() >= settings.limits().maxQueued()) throw reject("QUEUE_FULL");
        Waiter waiter = new Waiter(host, now);
        if (host.waiters.isEmpty()) roundRobin.addLast(host);
        host.waiters.addLast(waiter);
        queue.addLast(waiter);
        changed.signalAll();
        return waiter;
    }

    private int fairQueueBound() { return Math.max(1, (settings.limits().maxQueued() + 1) / 2); }

    private void trimHostQueues(int bound) {
        for (Host host : List.copyOf(roundRobin))
            while (host.waiters.size() > bound) fail(host.waiters.peekLast(), "QUEUE_FULL");
    }

    private Host host(String key, long now) throws Rejected {
        Host existing = hosts.get(key);
        if (existing != null) return existing;
        if (hosts.size() >= hostCapacity) {
            Iterator<Host> iterator = hosts.values().iterator();
            while (iterator.hasNext()) {
                Host candidate = iterator.next();
                if (candidate.waiters.isEmpty()
                        && (!candidate.hasAdmission || remaining(candidate.nextAdmission, now) == 0)) iterator.remove();
            }
        }
        if (hosts.size() >= hostCapacity) throw reject("HOST_CAPACITY");
        Host created = new Host(key);
        hosts.put(key, created);
        return created;
    }

    private void expireWaiters(long now) {
        // All waiters share the live timeout; global enqueue order also orders their deadlines.
        while (!queue.isEmpty()
                && elapsed(now, queue.peekFirst().createdAt) >= millis(settings.limits().queueTimeoutMillis()))
            fail(queue.peekFirst(), "QUEUE_TIMEOUT");
    }

    private void fail(Waiter waiter, String reason) {
        remove(waiter);
        waiter.failure = reason;
        changed.signalAll();
    }

    private void remove(Waiter waiter) {
        if (!waiter.queued) return;
        queue.remove(waiter);
        detach(waiter);
    }

    private void detach(Waiter waiter) {
        waiter.queued = false;
        waiter.host.waiters.remove(waiter);
        if (waiter.host.waiters.isEmpty()) roundRobin.remove(waiter.host);
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
            new PolicyEngine().validate(new GuardConfig(2, List.of(), List.of(), List.of(), GuardConfig.Mode.BLOCK, limits));
            Map<String, Long> overrides = new HashMap<>();
            Map<String, Integer> rates = new HashMap<>();
            limits.hostRps().forEach((key, value) -> {
                String canonical = PolicyEngine.canonicalHost(key);
                overrides.put(canonical, interval(value));
                rates.put(canonical, value);
            });
            return new Settings(limits, interval(limits.globalRps()), interval(limits.perHostRps()),
                    Map.copyOf(overrides), Map.copyOf(rates));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("INVALID_LIMITS");
        }
    }

    private static boolean current(BooleanSupplier predicate) {
        try { return predicate.getAsBoolean(); }
        catch (RuntimeException e) { return false; }
    }
    private static long interval(int rps) { return rps == 0 ? 0 : (SECOND + rps - 1) / rps; }
    private static long millis(long value) { return TimeUnit.MILLISECONDS.toNanos(value); }
    private static long elapsed(long now, long start) { return now - start; }
    private static long remaining(long deadline, long now) { return Math.max(0, deadline - now); }
    private static long extend(long oldDeadline, long newDeadline, long now) {
        return now + Math.max(remaining(oldDeadline, now), remaining(newDeadline, now));
    }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }

    private record Settings(Limits limits, long globalInterval, long perHostInterval,
                            Map<String, Long> hostIntervals, Map<String, Integer> hostRates) {}
    private static final class Host {
        private final String key;
        private final ArrayDeque<Waiter> waiters = new ArrayDeque<>();
        private final long[] waitNanos = new long[WAIT_SAMPLES];
        private int sampleCount;
        private int sampleCursor;
        private boolean hasAdmission;
        private long lastAdmission;
        private long nextAdmission;
        private Host(String key) { this.key = key; }
        private void recordWait(long nanos) {
            waitNanos[sampleCursor] = nanos;
            sampleCursor = (sampleCursor + 1) % WAIT_SAMPLES;
            sampleCount = Math.min(WAIT_SAMPLES, sampleCount + 1);
        }
        private long p95WaitMillis() {
            if (sampleCount == 0) return 0;
            long[] sorted = Arrays.copyOf(waitNanos, sampleCount);
            Arrays.sort(sorted);
            long nanos = sorted[(sampleCount * 95 + 99) / 100 - 1];
            return (nanos + 999_999) / 1_000_000;
        }
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
