package dev.cairnguard.runtime;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * Bounded human approvals containing only opaque references to already-masked evidence, never
 * native requests, URLs, headers or bodies. No rate permit is acquired or held by this class.
 * All waits are caller-thread condition waits; there are no watcher/timer threads.
 */
public final class ApprovalQueue implements AutoCloseable {
    private static final int CAPACITY = 100;
    private static final int MAX_REFERENCE_CHARS = 512;
    private static final long CURRENT_POLL = TimeUnit.MILLISECONDS.toNanos(50);
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition changed = lock.newCondition();
    // Includes approved-but-not-yet-consumed entries, so cancellation can still revoke their allow.
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final int capacity;
    private final LongSupplier nanoTime;
    private final Clock wallClock;
    private boolean closed;

    public ApprovalQueue() {
        this(CAPACITY, System::nanoTime, Clock.systemUTC());
    }

    /** Package-local deterministic test seam. Production capacity is always 100. */
    ApprovalQueue(int capacity, LongSupplier nanoTime, Clock wallClock) {
        if (capacity < 1 || capacity > CAPACITY) throw new IllegalArgumentException("INVALID_APPROVAL_CAPACITY");
        this.capacity = capacity;
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.wallClock = Objects.requireNonNull(wallClock);
    }

    public record Result(boolean allowed, String reason) {}

    /** Wall-clock strings are display-only; expiry decisions use monotonic elapsed time. */
    public record Pending(String id, String evidenceId, String projectId, String createdAt, String expiresAt) {}

    /**
     * References are bounded metadata supplied by the controller, NOT request text. The predicate
     * must be short, nonblocking and must not capture traffic. Invalid metadata fails categorically.
     */
    public Result await(String evidenceId, String projectId, long timeoutMillis, BooleanSupplier stillCurrent)
            throws InterruptedException {
        reference(evidenceId);
        reference(projectId);
        if (timeoutMillis < 1 || timeoutMillis > 600_000) throw new IllegalArgumentException("INVALID_APPROVAL_TIMEOUT");
        Objects.requireNonNull(stillCurrent);
        lock.lockInterruptibly();
        Entry entry = null;
        try {
            if (closed) return denied("SHUTDOWN");
            if (!current(stillCurrent)) return denied("POLICY_CHANGED");
            if (closed) return denied("SHUTDOWN");
            reap();
            if (closed) return denied("SHUTDOWN");
            if (entries.size() >= capacity) return denied("APPROVAL_CAPACITY");
            long now = nanoTime.getAsLong();
            Instant created = wallClock.instant();
            Pending pending = new Pending(UUID.randomUUID().toString(), evidenceId, projectId,
                    created.toString(), created.plusMillis(timeoutMillis).toString());
            entry = new Entry(pending, now, TimeUnit.MILLISECONDS.toNanos(timeoutMillis), stillCurrent);
            entries.put(pending.id(), entry);
            while (true) {
                // An accepted click is provisional until this wait returns: expired, cancelled,
                // switched-project or shutdown state must never yield an allow to the controller.
                Result failure = failure(entry);
                if (failure != null) return failure;
                if (entry.result != null) return entry.result;
                long remaining = entry.timeoutNanos - (nanoTime.getAsLong() - entry.createdAt);
                if (remaining > 0) changed.awaitNanos(Math.min(CURRENT_POLL, remaining));
            }
        } finally {
            if (entry != null) entries.remove(entry.pending.id(), entry);
            lock.unlock();
        }
    }

    /** One-shot click. Missing, already decided, expired or stale IDs return false, never allow. */
    public boolean decide(String approvalId, boolean allow) {
        lock.lock();
        try {
            Entry entry = entries.get(approvalId);
            if (entry == null || entry.result != null) return false;
            Result failure = failure(entry);
            if (failure != null) {
                entry.result = failure;
                entries.remove(approvalId);
                changed.signalAll();
                return false;
            }
            entry.result = allow ? new Result(true, "APPROVED") : denied("DENIED");
            // Keep provisional allows cancellable until the await caller actually consumes them.
            if (!allow) entries.remove(approvalId);
            changed.signalAll();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** Immutable oldest-first unresolved snapshot, with no request/URL/secret fields. */
    public List<Pending> snapshot() {
        lock.lock();
        try {
            reap();
            List<Pending> result = new ArrayList<>(entries.size());
            for (Entry entry : entries.values()) if (entry.result == null) result.add(entry.pending);
            return List.copyOf(result);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Project/policy/pause changes deny all current waits, not future ones. Unknown strings
     * (including PROJECT_CHANGED/PAUSED) normalize to POLICY_CHANGED, never echo caller data.
     */
    public void cancelAll(String reason) {
        lock.lock();
        try {
            cancel(cancellationReason(reason));
        } finally {
            lock.unlock();
        }
    }

    @Override public void close() {
        lock.lock();
        try {
            closed = true;
            cancel("SHUTDOWN");
        } finally {
            lock.unlock();
        }
    }

    private void cancel(String reason) {
        for (Entry entry : entries.values()) entry.result = denied(reason);
        entries.clear();
        changed.signalAll();
    }

    private void reap() {
        boolean removed = false;
        // Bounded copy also makes reentrant cancellation from a predicate safe during reaping.
        for (Entry entry : List.copyOf(entries.values())) {
            Result failure = failure(entry);
            if (failure != null) {
                entry.result = failure;
                removed |= entries.remove(entry.pending.id(), entry);
            }
        }
        if (removed) changed.signalAll();
    }

    private Result failure(Entry entry) {
        if (closed) return denied("SHUTDOWN");
        // A cancellation result must survive map removal and remain a denial when the waiter wakes.
        if (entry.result != null && !entry.result.allowed()) return entry.result;
        boolean live = current(entry.stillCurrent);
        // Preserve even reentrant close/cancel from a predicate: an accepted click must not
        // overwrite a denial that linearized during the current-state check.
        if (closed) return denied("SHUTDOWN");
        if (entry.result != null && !entry.result.allowed()) return entry.result;
        if (!live) return denied("POLICY_CHANGED");
        // Read time AFTER the predicate: a slow predicate cannot accidentally extend a deadline.
        if (nanoTime.getAsLong() - entry.createdAt >= entry.timeoutNanos) return denied("APPROVAL_TIMEOUT");
        return null;
    }

    private static boolean current(BooleanSupplier predicate) {
        try { return predicate.getAsBoolean(); }
        catch (RuntimeException e) { return false; }
    }
    private static Result denied(String reason) { return new Result(false, reason); }
    private static String cancellationReason(String reason) {
        if ("SHUTDOWN".equals(reason)) return "SHUTDOWN";
        if ("DENIED".equals(reason)) return "DENIED";
        return "POLICY_CHANGED";
    }
    private static void reference(String reference) {
        if (reference == null || reference.isBlank() || reference.length() > MAX_REFERENCE_CHARS)
            throw new IllegalArgumentException("INVALID_APPROVAL_REFERENCE");
        for (int i = 0; i < reference.length(); i++) {
            char c = reference.charAt(i);
            if (Character.isISOControl(c) || Character.isSurrogate(c))
                throw new IllegalArgumentException("INVALID_APPROVAL_REFERENCE");
        }
    }
    private static final class Entry {
        private final Pending pending;
        private final long createdAt;
        private final long timeoutNanos;
        private final BooleanSupplier stillCurrent;
        private Result result;
        private Entry(Pending pending, long createdAt, long timeoutNanos, BooleanSupplier stillCurrent) {
            this.pending = pending;
            this.createdAt = createdAt;
            this.timeoutNanos = timeoutNanos;
            this.stillCurrent = stillCurrent;
        }
    }
}
