package dev.cairnguard.runtime;

import dev.cairnguard.model.RequestAttribution;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Bounded accounting for UNTRUSTED client labels, not authentication or an agent quota boundary.
 * The controller calls commit exactly at final protected handoff, including EXEMPT and probes.
 * There is deliberately no eviction, refund, timer, persistent storage, or raw-label index.
 */
public final class IntentBudget {
    private static final int MAX_KEYS = 4_096;
    private final int capacity;
    private final byte[] key = new byte[32];
    private final Map<String, Long> counts = new HashMap<>();
    private long consumed;
    private long denied;
    private long invalid;
    private long full;

    public IntentBudget() { this(MAX_KEYS); }

    /** Deterministic capacity seam; production always permits at most 4096 distinct pairs. */
    IntentBudget(int capacity) {
        if (capacity < 1 || capacity > MAX_KEYS) throw new IllegalArgumentException("INVALID_INTENT_CAPACITY");
        this.capacity = capacity;
        new SecureRandom().nextBytes(key);
    }

    /** Advisory only. Does not reserve or consume anything; commit MUST check again. */
    public synchronized String check(RequestAttribution attribution, int limit) {
        validateLimit(limit);
        return rejection(attribution, limit);
    }

    /** Atomic final check-and-increment. A zero limit suspends accounting without erasing debt. */
    public synchronized String commit(RequestAttribution attribution, int limit) {
        validateLimit(limit);
        String reason = rejection(attribution, limit);
        if (reason != null) {
            denied = increment(denied);
            if (reason.equals("INTENT_BUDGET_CAPACITY")) full = increment(full);
            if (reason.equals("INVALID_INTENT_TAG")) invalid = increment(invalid);
            return reason;
        }
        if (limit == 0 || attribution == null || attribution.intentId().equals("-")) return null;
        String hash = hash(attribution.runId(), attribution.intentId());
        counts.put(hash, increment(counts.getOrDefault(hash, 0L)));
        consumed = increment(consumed);
        return null;
    }

    /** Explicit operator/project reset only; policy updates and limit toggles never call this. */
    public synchronized void reset() {
        counts.clear();
        consumed = denied = invalid = full = 0;
        new SecureRandom().nextBytes(key);
    }

    /** Fixed aggregate metadata only; neither labels nor their hashes escape this object. */
    public synchronized Map<String, Object> snapshot() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keys", counts.size());
        out.put("capacity", capacity);
        out.put("consumed", consumed);
        out.put("rejected", denied);
        out.put("invalidTags", invalid);
        out.put("capacityRejected", full);
        out.put("untrustedLabels", true);
        return Map.copyOf(out);
    }

    private String rejection(RequestAttribution attribution, int limit) {
        if (limit == 0 || attribution == null) return null;
        // Defend the public record constructor as well as the normal header parser. No raw value
        // becomes an error message, retained map key, or unbounded hashing input.
        if (!attribution.valid() || !tag(attribution.intentId()) || !tag(attribution.runId()))
            return "INVALID_INTENT_TAG";
        if (attribution.intentId().equals("-")) return null;
        String hash = hash(attribution.runId(), attribution.intentId());
        Long count = counts.get(hash);
        if (count != null && count >= limit) return "INTENT_BUDGET_EXCEEDED";
        if (count == null && counts.size() >= capacity) return "INTENT_BUDGET_CAPACITY";
        return null;
    }

    private String hash(String run, String intent) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String value : new String[]{run, intent}) {
                byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
                mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                mac.update(bytes);
            }
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("INTENT_HASH_UNAVAILABLE");
        }
    }

    private static boolean tag(String value) {
        if (value == null || value.isEmpty() || value.length() > 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
                    || c == '.' || c == '_' || c == ':' || c == '-')) return false;
        }
        return true;
    }

    private static void validateLimit(int limit) {
        if (limit < 0 || limit > 1_000_000) throw new IllegalArgumentException("INVALID_INTENT_LIMIT");
    }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }
}
