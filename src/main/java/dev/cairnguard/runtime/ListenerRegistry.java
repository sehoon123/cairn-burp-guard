package dev.cairnguard.runtime;

import dev.cairnguard.policy.PolicyEngine;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Data-free, single-consumption correlation of an actual inbound Proxy listener to a message ID.
 * No destination-port fallback, native objects, traffic, DNS, threads or I/O. Unknown, collided,
 * expired and capacity-exhausted mappings all remain UNKNOWN (never an unprotected listener).
 */
public final class ListenerRegistry {
    private static final int MAX_ENTRIES = 4_096;
    private static final long TTL_NANOS = TimeUnit.SECONDS.toNanos(30);
    private final Map<Integer, Entry> entries = new HashMap<>();
    private final LongSupplier nanoTime;
    private final int capacity;
    private final long ttl;
    private long recorded;
    private long unknown;
    private long collisions;
    private long expired;
    private long full;

    public ListenerRegistry() { this(System::nanoTime, MAX_ENTRIES, TTL_NANOS); }

    /** Package-local deterministic clock/capacity seam, bounded by the production ceilings. */
    ListenerRegistry(LongSupplier nanoTime, int capacity, long ttlNanos) {
        if (capacity < 1 || capacity > MAX_ENTRIES || ttlNanos < 1 || ttlNanos > TTL_NANOS)
            throw new IllegalArgumentException("INVALID_LISTENER_REGISTRY_LIMITS");
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.capacity = capacity;
        this.ttl = ttlNanos;
    }

    public synchronized void record(int messageId, String listenerInterface, long generation) {
        long now = nanoTime.getAsLong();
        sweep(now);
        Entry previous = entries.get(messageId);
        if (previous != null) {
            // Even an identical duplicate is ambiguous. Never overwrite the older mapping or
            // extend its TTL; both callbacks must fail closed when consumed.
            entries.put(messageId, new Entry(0, previous.generation, previous.created));
            collisions = increment(collisions);
            return;
        }
        if (entries.size() >= capacity) { full = increment(full); return; }
        int port = parsePort(listenerInterface);
        entries.put(messageId, new Entry(port, generation, now));
        recorded = increment(recorded);
    }

    public synchronized OptionalInt consume(int messageId, long generation) {
        sweep(nanoTime.getAsLong());
        Entry entry = entries.remove(messageId);
        if (entry == null || entry.port == 0 || entry.generation != generation) {
            unknown = increment(unknown);
            return OptionalInt.empty();
        }
        return OptionalInt.of(entry.port);
    }

    public synchronized void reset() {
        entries.clear();
        recorded = unknown = collisions = expired = full = 0;
    }

    public synchronized Map<String, Object> snapshot() {
        sweep(nanoTime.getAsLong());
        return Map.of("retained", entries.size(), "capacity", capacity, "ttlMillis", TimeUnit.NANOSECONDS.toMillis(ttl),
                "recorded", recorded, "unknown", unknown, "collisions", collisions, "expired", expired, "capacityRejected", full);
    }

    /** Strict host:decimal-port or [numeric IPv6]:decimal-port; no URI, path or loose suffix parsing. */
    static int parsePort(String value) {
        if (value == null || value.isEmpty() || value.length() > 512) return 0;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch <= 32 || ch >= 127 || "/\\?#@".indexOf(ch) >= 0) return 0;
        }
        int colon;
        String host;
        if (value.charAt(0) == '[') {
            int bracket = value.indexOf(']');
            if (bracket <= 1 || bracket + 1 >= value.length() || value.charAt(bracket + 1) != ':') return 0;
            host = value.substring(0, bracket + 1);
            if (host.indexOf(':') < 0 || value.indexOf('[', 1) >= 0 || value.indexOf(']', bracket + 1) >= 0) return 0;
            colon = bracket + 1;
        } else {
            colon = value.indexOf(':');
            if (colon <= 0 || colon != value.lastIndexOf(':')) return 0;
            host = value.substring(0, colon);
            if (host.indexOf('[') >= 0 || host.indexOf(']') >= 0) return 0;
        }
        try { PolicyEngine.canonicalHost(host); }
        catch (IllegalArgumentException ignored) { return 0; }
        int length = value.length() - colon - 1;
        if (length < 1 || length > 5) return 0;
        int port = 0;
        for (int i = colon + 1; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < '0' || ch > '9') return 0;
            port = port * 10 + ch - '0';
        }
        return port >= 1 && port <= 65_535 ? port : 0;
    }

    private void sweep(long now) {
        int before = entries.size();
        entries.values().removeIf(entry -> now - entry.created >= ttl);
        expired = add(expired, before - entries.size());
    }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }
    private static long add(long value, long delta) { return value > Long.MAX_VALUE - delta ? Long.MAX_VALUE : value + delta; }
    private record Entry(int port, long generation, long created) {}
}
