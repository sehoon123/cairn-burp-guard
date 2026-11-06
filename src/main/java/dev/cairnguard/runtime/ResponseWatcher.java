package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Memory-only observational response statistics. Never participates in send admission. */
public final class ResponseWatcher {
    private static final int MAX_ROUTE_VIEWS = 9;
    private static final int MAX_URL = 16_384;
    private final LongSupplier milliTime;
    private final byte[] key = new byte[32];
    private final Object identity = new Object();
    private final List<Observation> observations = new ArrayList<>();
    private long epoch = 1;
    private long displayGeneration;
    private long startedAt;
    private long lastMillis;
    private boolean clockRegressed;
    public ResponseWatcher(Limits limits) { this(limits, System::nanoTime, System::currentTimeMillis); }
    public ResponseWatcher(Limits limits, LongSupplier nanoTime, LongSupplier milliTime) {
        this.milliTime = Objects.requireNonNull(milliTime);
        Objects.requireNonNull(nanoTime);
        validated(limits);
        new SecureRandom().nextBytes(key);
        startedAt = lastMillis = milliTime.getAsLong();
    }
    public synchronized void update(Limits replacement) { validated(replacement); }
    public synchronized void reset() { epoch++; clearEvidence(); new SecureRandom().nextBytes(key); }
    public synchronized void clearEvidence() {
        observations.clear(); displayGeneration++;
        startedAt = lastMillis = milliTime.getAsLong(); clockRegressed = false;
    }
    public synchronized void observe(Endpoint endpoint, int status, long bytes) {
        if (endpoint == null || endpoint.owner != identity || endpoint.epoch != epoch
                || endpoint.displayGeneration != displayGeneration) return;
        long now = time();
        observations.add(new Observation(endpoint.pathKeys().getLast(), endpoint.hostKey(), endpoint.pathKeys(),
                endpoint.host(), endpoint.path(), endpoint.policyUrl(), status, Math.max(0, bytes), now, 0, endpoint.source));
    }
    public synchronized List<Candidate> candidates() {
        return aggregate(Long.MIN_VALUE, Long.MAX_VALUE).values().stream().map(Aggregate::candidate)
                .sorted(CANDIDATE_ORDER).toList();
    }
    public synchronized Map<String,Object> snapshot() {
        return Map.of("observations", observations.size(), "clockRegressed", clockRegressed,
                "observationsTruncated", false, "p95Approximate", true);
    }
    public synchronized Endpoint endpoint(RequestData request, List<String> routingPaths) {
        Objects.requireNonNull(request);
        if (routingPaths == null || routingPaths.isEmpty() || routingPaths.size() > MAX_ROUTE_VIEWS)
            throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        String service = service(request.secure() ? "https" : "http", request.host(), request.port());
        // Validate every bounded view BEFORE allocating HMAC input. Traffic is not a navigated
        // URI: the first view may be empty/non-origin-form or contain raw controls/surrogates.
        // PolicyEngine decides scope completeness; watcher must not impose a second sanitizer.
        for (String route : routingPaths) {
            if (route == null || route.length() > MAX_URL)
                throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        }
        String rawPath = routingPaths.getFirst();
        LinkedHashSet<String> hashed = new LinkedHashSet<>();
        for (String route : routingPaths) hashed.add(hash("path", service, route));
        // Exact-route identity only for one complete, unambiguous routing view of the ACTUAL target.
        String exact = PolicyEngine.exactRoutingPath(request);
        boolean single = exact != null && routingPaths.size() == 1 && rawPath.equals(exact);
        // Query-free draft hint only when the original path is a faithful ordinary URL path.
        String policyUrl = single && draftable(rawPath) ? service + rawPath : "";
        return new Endpoint(hash("service", service), List.copyOf(hashed), request.host(), rawPath,
                policyUrl, identity, epoch, UUID.randomUUID().toString(), displayGeneration);
    }

    private static boolean draftable(String path) {
        if (!path.startsWith("/")) return false;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c <= 0x20 || c >= 0x7f || c == '#' || c == '?' || c == '\\') return false;
            if (c == '%' && (i + 2 >= path.length() || Character.digit(path.charAt(i + 1), 16) < 0
                    || Character.digit(path.charAt(i + 2), 16) < 0)) return false;
        }
        return true;
    }

    /** Exact statistics of retained scalar observations in [from,to) (since start/explicit clear), not wire totals. */
    public synchronized String incidentJson(long fromMillis, long toMillis) {
        return Json.write(incidentDocument(fromMillis, toMillis, false));
    }

    /**
     * Incident document. With sourced=true (in-process human export only) every event/top row also
     * carries its opaque "_source" original reference, for the controller to resolve or report
     * unavailable; such a map must never be serialized as is.
     */
    public synchronized Map<String, Object> incidentDocument(long fromMillis, long toMillis, boolean sourced) {
        if (toMillis <= fromMillis) throw new IllegalArgumentException("INVALID_INCIDENT_WINDOW");
        long now = time();
        List<Aggregate> stats = List.copyOf(aggregate(fromMillis, toMillis).values());
        boolean eventComplete = complete(fromMillis, toMillis, now);
        boolean observationComplete = eventComplete;
        // Epoch-wide and conservative: omissions are not attributed to a specific incident window.
        boolean fanoutComplete = true;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("window", Map.of("from", fromMillis, "to", toMillis));
        out.put("events", List.of());
        out.put("top5xx", stats.stream().filter(a -> a.count5xx > 0)
                .sorted(Comparator.comparingLong((Aggregate a) -> a.count5xx).reversed().thenComparing(a -> a.id))
                .map(a -> sourced ? a.sourcedView() : (Object) a.candidate()).toList());
        out.put("topBytes", stats.stream().sorted(Comparator.comparing(Aggregate::candidate, CANDIDATE_ORDER))
                .map(a -> sourced ? a.sourcedView() : (Object) a.candidate()).toList());
        out.put("complete", eventComplete && observationComplete && fanoutComplete);
        out.put("truncated", !eventComplete || !observationComplete || !fanoutComplete);
        out.put("fanoutHistoryComplete", fanoutComplete);
        out.put("approximate", true);
        out.put("approximation", Map.of("p95Bytes", "log2_histogram_upper_bound",
                "countMaxBytesLastSeen5xx", "exact_retained_window"));
        out.put("retention", Map.of("mode", "UNTIL_CLEAR_PROJECT_OR_UNLOAD", "startedAt", startedAt,
                "eventsComplete", eventComplete, "observationsComplete", observationComplete,
                "eventsDropped", false, "observationsDropped", false,
                "clockRegressed", clockRegressed, "fanoutHistoryOmitted", 0));
        return out;
    }

    public record Candidate(String id, String host, String path, String policyUrl, long maxBytes,
                            long p95Bytes, long count, long lastSeen, long count5xx) {}

    /**
     * Immutable observational projection; private provenance fences foreign, cleared and old-epoch callbacks.
     * The public five-field constructor is display-only and cannot record observations.
     */
    public static final class Endpoint {
        private final String hostKey;
        private final List<String> pathKeys;
        private final String host;
        private final String path;
        private final String policyUrl;
        private final Object owner;
        private final long epoch;
        // Random opaque reference to the human-local original of THIS request; never serialized.
        private final String source;
        private final long displayGeneration;
        public Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl) {
            this(hostKey, pathKeys, host, path, policyUrl, null, 0, null, 0);
        }
        private Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl,
                         Object owner, long epoch, String source, long displayGeneration) {
            this.hostKey = Objects.requireNonNull(hostKey);
            this.pathKeys = List.copyOf(pathKeys);
            this.host = Objects.requireNonNull(host);
            this.path = Objects.requireNonNull(path);
            this.policyUrl = Objects.requireNonNull(policyUrl);
            this.owner = owner;
            this.epoch = epoch;
            this.source = source;
            this.displayGeneration = displayGeneration;
        }
        /** Opaque human-original reference (controller binds it to the retained raw capture). */
        String source() { return source; }
        public String hostKey() { return hostKey; }
        public List<String> pathKeys() { return pathKeys; }
        public String host() { return host; }
        public String path() { return path; }
        public String policyUrl() { return policyUrl; }
    }

    private Map<String, Aggregate> aggregate(long from, long to) {
        Map<String, Aggregate> out = new HashMap<>();
        for (Observation o : observations) if (o.ts >= from && o.ts < to)
            out.computeIfAbsent(o.id, ignored -> new Aggregate(o)).add(o);
        return out;
    }
    private boolean complete(long from, long to, long now) {
        return !clockRegressed && from >= startedAt && to <= add(now, 1);
    }
    private long time() {
        long now = milliTime.getAsLong();
        if (now < lastMillis) clockRegressed = true;
        lastMillis = now; return now;
    }
    private String hash(String... components) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String component : components) {
                // Encode exact Java code units, including lone surrogates, without a Charset
                // encoder's lossy replacement. Distinct hostile targets must not share '?' keys.
                ByteBuffer encoded = ByteBuffer.allocate(component.length() * Character.BYTES);
                for (int i = 0; i < component.length(); i++) encoded.putChar(component.charAt(i));
                byte[] bytes = encoded.array();
                mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                mac.update(bytes);
            }
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (GeneralSecurityException e) { throw new IllegalStateException("WATCHER_HASH_UNAVAILABLE"); }
    }

    private static Limits validated(Limits limits) {
        try {
            new PolicyEngine().validate(new GuardConfig(2, List.of(), List.of(), List.of(), GuardConfig.Mode.BLOCK, limits));
            return limits;
        } catch (RuntimeException ignored) { throw new IllegalArgumentException("INVALID_LIMITS"); }
    }

    private static String service(String scheme, String host, int port) {
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
                || port < 1 || port > 65_535) throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        String canonical = PolicyEngine.canonicalHost(host);
        if (canonical.indexOf(':') >= 0 && !canonical.startsWith("[")) canonical = "[" + canonical + "]";
        String lower = scheme.equalsIgnoreCase("https") ? "https" : "http";
        return lower + "://" + canonical + ((lower.equals("https") ? port == 443 : port == 80) ? "" : ":" + port);
    }
    private static long add(long a, long b) {
        long result = a + b;
        return ((a ^ result) & (b ^ result)) < 0 ? b < 0 ? Long.MIN_VALUE : Long.MAX_VALUE : result;
    }

    private static final Comparator<Candidate> CANDIDATE_ORDER = Comparator.comparingLong(Candidate::maxBytes)
            .reversed().thenComparing(Candidate::id);
    private record Observation(String id, String hostKey, List<String> pathKeys, String host, String path,
                               String policyUrl, int status, long bytes, long ts, long nano, String source) {}
    private static final class Aggregate {
        final String id;
        String host;
        String path;
        String policyUrl;
        String source;
        long max;
        long count;
        long lastSeen = Long.MIN_VALUE;
        long count5xx;
        final long[] histogram = new long[64];
        Aggregate(Observation observation) { id = observation.id; }
        void add(Observation observation) {
            count++;
            if (observation.bytes > max) max = observation.bytes;
            histogram[bucket(observation.bytes)]++;
            if (observation.status >= 500 && observation.status <= 599) count5xx++;
            if (observation.ts >= lastSeen) {
                lastSeen = observation.ts;
                host = observation.host;
                path = observation.path;
                policyUrl = observation.policyUrl;
                source = observation.source;
            }
        }
        Candidate candidate() { return new Candidate(id, host, path, policyUrl, max, p95(), count, lastSeen, count5xx); }
        Map<String, Object> sourcedView() {
            Map<String, Object> view = new LinkedHashMap<>();
            view.put("id", id); view.put("host", host); view.put("path", path); view.put("policyUrl", policyUrl);
            view.put("maxBytes", max); view.put("p95Bytes", p95()); view.put("count", count);
            view.put("lastSeen", lastSeen); view.put("count5xx", count5xx); view.put("_source", source == null ? "" : source);
            return view;
        }
        long p95() {
            long rank = (count * 95 + 99) / 100;
            long seen = 0;
            for (int i = 0; i < histogram.length; i++) {
                seen += histogram[i];
                if (seen >= rank) return i == 0 ? 0 : i == 63 ? Long.MAX_VALUE : (1L << i) - 1;
            }
            return 0;
        }
        static int bucket(long bytes) { return bytes == 0 ? 0 : 64 - Long.numberOfLeadingZeros(bytes); }
    }
}
