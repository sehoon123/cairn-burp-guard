package dev.cairnguard.evidence;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Bounded, per-entry keyed fingerprints. Never keeps plaintext credential values. */
final class SecretFingerprints {
    private static final int MAX_SECRETS = 128;
    private static final int MAX_LENGTHS = 24;
    private static final int MAX_SECRET_LENGTH = 8192;
    private final byte[] key;
    private final long base;
    private final long salt;
    private final Map<Integer, Map<Long, List<byte[]>>> byLength;
    private final int count;
    private final boolean opaque;

    private SecretFingerprints(byte[] key, long base, long salt, Map<Integer, Map<Long, List<byte[]>>> byLength,
                               int count, boolean opaque) {
        this.key = key.clone();
        this.base = base;
        this.salt = salt;
        this.byLength = byLength;
        this.count = count;
        this.opaque = opaque;
    }

    static Builder builder() { return new Builder(null); }
    Builder extend() { return new Builder(this); }
    boolean opaque() { return opaque; }
    long estimatedBytes() { return 256L + count * 128L + byLength.size() * 128L; }

    String mask(String text) {
        if (text.isEmpty() || text.equals(Redactor.REDACTED)) return text;
        if (opaque || text.length() > Redactor.MAX_INPUT) return Redactor.REDACTED;
        if (byLength.isEmpty()) return text;
        boolean[] hidden = null;
        Mac mac = mac(key);
        for (var lengths : byLength.entrySet()) {
            int length = lengths.getKey();
            if (length > text.length()) continue;
            long power = 1;
            for (int j = 1; j < length; j++) power *= base;
            long hash = hash(text, 0, length, base);
            for (int start = 0; start <= text.length() - length; start++) {
                List<byte[]> candidates = lengths.getValue().get(hash ^ salt);
                if (candidates != null) {
                    byte[] digest = digest(mac, text.substring(start, start + length));
                    for (byte[] candidate : candidates) {
                        if (MessageDigest.isEqual(candidate, digest)) {
                            if (hidden == null) hidden = new boolean[text.length()];
                            Arrays.fill(hidden, start, start + length, true);
                            break;
                        }
                    }
                }
                if (start < text.length() - length) {
                    hash = (hash - text.charAt(start) * power) * base + text.charAt(start + length);
                }
            }
        }
        if (hidden == null) return text;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length();) {
            if (!hidden[i]) { out.append(text.charAt(i++)); continue; }
            out.append(Redactor.REDACTED);
            while (i < text.length() && hidden[i]) i++;
        }
        return out.toString();
    }

    private static long hash(String value, int start, int length, long base) {
        long result = 0;
        for (int i = start; i < start + length; i++) result = result * base + value.charAt(i);
        return result;
    }
    private static Mac mac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) { throw new IllegalStateException("EVIDENCE_CRYPTO_UNAVAILABLE"); }
    }
    private static byte[] digest(Mac mac, String text) {
        return mac.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }

    static final class Builder {
        private final byte[] key;
        private final long base;
        private final long salt;
        private final Map<Integer, Map<Long, List<byte[]>>> byLength = new LinkedHashMap<>();
        private int count;
        private boolean opaque;
        Builder(SecretFingerprints previous) {
            if (previous == null) {
                SecureRandom random = new SecureRandom();
                key = new byte[32];
                random.nextBytes(key);
                base = random.nextLong() | 1L;
                salt = random.nextLong();
            } else {
                key = previous.key.clone();
                base = previous.base;
                salt = previous.salt;
                count = previous.count;
                opaque = previous.opaque;
                previous.byLength.forEach((length, values) -> {
                    Map<Long, List<byte[]>> copy = new LinkedHashMap<>();
                    values.forEach((hash, digests) -> copy.put(hash, new ArrayList<>(digests)));
                    byLength.put(length, copy);
                });
            }
        }
        void uncertain() { opaque = true; byLength.clear(); count = 0; }
        void add(String value) {
            if (opaque || value == null || value.isEmpty() || value.equals(Redactor.REDACTED)) return;
            if (value.length() > MAX_SECRET_LENGTH) { uncertain(); return; }
            if (!byLength.containsKey(value.length()) && byLength.size() >= MAX_LENGTHS) {
                uncertain(); return;
            }
            long hash = hash(value, 0, value.length(), base) ^ salt;
            var values = byLength.get(value.length());
            List<byte[]> candidates = values == null ? null : values.get(hash);
            byte[] digest = digest(mac(key), value);
            if (candidates != null) for (byte[] candidate : candidates) if (MessageDigest.isEqual(candidate, digest)) return;
            if (count >= MAX_SECRETS) { uncertain(); return; }
            byLength.computeIfAbsent(value.length(), ignored -> new LinkedHashMap<>())
                    .computeIfAbsent(hash, ignored -> new ArrayList<>()).add(digest);
            count++;
        }
        SecretFingerprints build() {
            Map<Integer, Map<Long, List<byte[]>>> frozen = new LinkedHashMap<>();
            byLength.forEach((length, values) -> {
                Map<Long, List<byte[]>> copy = new LinkedHashMap<>();
                values.forEach((hash, digests) -> copy.put(hash, List.copyOf(digests)));
                frozen.put(length, Map.copyOf(copy));
            });
            return new SecretFingerprints(key, base, salt, Map.copyOf(frozen), count, opaque);
        }
    }
}
