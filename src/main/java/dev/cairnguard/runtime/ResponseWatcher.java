package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Circuit5xx;
import dev.cairnguard.model.GuardConfig.Fanout;
import dev.cairnguard.model.GuardConfig.FanoutAction;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardState;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Project-epoch, memory-only availability protections. No I/O, timer threads, policy writes, native
 * messages, response copies, or native permits. Call observe with the native body LENGTH scalar,
 * independently of whether optional response content inspection was possible. All public mutations
 * are serialized; check is advisory and commit is the final, atomic admission/half-open claim.
 */
public final class ResponseWatcher {
    private static final int MAX_HOSTS = 1_024;
    private static final int MAX_PATHS = 2_048;
    private static final int MAX_OVERLAYS = 1_024;
    private static final int MAX_EVENTS = 4_096;
    private static final int MAX_OBSERVATIONS = 8_192;
    private static final int MAX_FLIGHTS = 4_096;
    private static final int MAX_ROUTE_VIEWS = 16;
    private static final int MAX_URL = 16_384;
    private static final int MAX_DISPLAY = 2_048;
    private static final long DAY_MILLIS = 86_400_000L;
    private static final long DAY_NANOS = TimeUnit.MILLISECONDS.toNanos(DAY_MILLIS);
    private static final long PROBE_INTERVAL = TimeUnit.SECONDS.toNanos(30);
    private static final String HEAVY = "HEAVY_ENDPOINT_AUTO_BLOCKED";
    private static final String CIRCUIT = "CIRCUIT_OPEN";
    private static final String FANOUT = "FANOUT_SUSPECTED";
    private static final String CAPACITY = "RESPONSE_WATCHER_CAPACITY";
    private static final Gate ALLOWED = new Gate(true, "", GuardState.PROTECTED, "");

    private final LongSupplier nanoTime;
    private final LongSupplier milliTime;
    private final int hostCapacity;
    private final int pathCapacity;
    private final int overlayCapacity;
    private final byte[] key = new byte[32];
    private final Object identity = new Object();
    private final Map<String, Host> hosts = new HashMap<>();
    private final Map<String, PathState> paths = new HashMap<>();
    private final Map<String, Protection> protections = new LinkedHashMap<>();
    private final Map<String, Protection> heavyPaths = new HashMap<>();
    private final Map<Ticket, Flight> flights = new LinkedHashMap<>();
    private final LinkedHashMap<String, CandidateMeta> candidateIndex = new LinkedHashMap<>(16, .75f, true);
    private final Ring<Event> events;
    private final Ring<Observation> observations;
    private final Map<String, Long> pathLimits = new HashMap<>();
    // Bounded privacy fences, not enforcement identities. Old prepared endpoints must not reintroduce
    // display secrets learned by a later response. Saturation makes all display opaque, never evicts.
    private final LinkedHashSet<String> maskedPaths = new LinkedHashSet<>();
    private final LinkedHashSet<String> maskedServices = new LinkedHashSet<>();
    private boolean displayOpaque;
    private Limits limits;
    private long epoch = 1;
    private long startedAt;
    private long lastMillis;
    private boolean clockRegressed;
    private Protection capacityProtection;
    private long admitted;
    private long rejected;
    private long timedOut;
    private long candidateEvictions;
    private long abandoned;

    public ResponseWatcher(Limits limits) {
        this(limits, System::nanoTime, System::currentTimeMillis, MAX_HOSTS, MAX_PATHS,
                MAX_OVERLAYS, MAX_EVENTS, MAX_OBSERVATIONS);
    }

    public ResponseWatcher(Limits limits, LongSupplier nanoTime, LongSupplier milliTime) {
        this(limits, nanoTime, milliTime, MAX_HOSTS, MAX_PATHS, MAX_OVERLAYS, MAX_EVENTS, MAX_OBSERVATIONS);
    }

    /** Bounded fake-clock/capacity seam. All production ceilings still apply. */
    public ResponseWatcher(Limits limits, LongSupplier nanoTime, LongSupplier milliTime,
                           int hostCapacity, int pathCapacity, int overlayCapacity,
                           int eventCapacity, int observationCapacity) {
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.milliTime = Objects.requireNonNull(milliTime);
        this.hostCapacity = capacity(hostCapacity, MAX_HOSTS);
        this.pathCapacity = capacity(pathCapacity, MAX_PATHS);
        this.overlayCapacity = capacity(overlayCapacity, MAX_OVERLAYS);
        events = new Ring<>(capacity(eventCapacity, MAX_EVENTS));
        observations = new Ring<>(capacity(observationCapacity, MAX_OBSERVATIONS));
        this.limits = validated(limits);
        new SecureRandom().nextBytes(key);
        startedAt = lastMillis = milliTime.getAsLong();
        compilePathLimits();
    }

    /**
     * Converts transient raw routing views to per-instance keyed HMACs. ONLY the supplied, already
     * redacted URL supplies display data. Query, credentials, and raw route strings are not retained.
     * The actual service, not a fuzzed Host header or URL authority, supplies enforcement identity.
     */
    public synchronized Endpoint endpoint(RequestData request, String redactedUrl, List<String> routingPaths) {
        Objects.requireNonNull(request);
        if (routingPaths == null || routingPaths.isEmpty() || routingPaths.size() > MAX_ROUTE_VIEWS)
            throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        String service = service(request.secure() ? "https" : "http", request.host(), request.port());
        // Traffic is not a navigated URI: malformed-percent and literal-fragment pentest paths
        // are legal under explicit ALL-path scope. PolicyEngine supplied the untouched first view.
        String rawPath = routingPaths.getFirst();
        LinkedHashSet<String> hashed = new LinkedHashSet<>();
        hashed.add(hash("path", service, rawPath));
        for (String route : routingPaths) {
            if (route == null || route.isEmpty() || route.charAt(0) != '/' || route.length() > MAX_URL)
                throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
            hashed.add(hash("path", service, route));
        }
        String host = "[REDACTED]";
        String displayPath = "[REDACTED]";
        String policyUrl = "";
        try {
            URI safe = uri(redactedUrl);
            if (safe.getRawUserInfo() != null || safe.getRawFragment() != null)
                throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
            String safePath = path(safe);
            host = safe.getHost();
            displayPath = safePath.length() <= MAX_DISPLAY ? safePath : "[OMITTED: PATH_LIMIT]";
            String safeService = service(safe.getScheme(), safe.getHost(), port(safe));
            if (safePath.length() <= MAX_DISPLAY && service.equals(safeService)
                    && rawPath.equals(safePath)) policyUrl = safeService + safePath;
        } catch (IllegalArgumentException ignored) {
            // A failed redaction never falls back to the raw request URL/host/path.
        }
        boolean safeMethod = "GET".equals(request.method()) || "HEAD".equals(request.method());
        return fenced(new Endpoint(hash("service", service), List.copyOf(hashed), host, displayPath,
                policyUrl, identity, epoch, safeMethod));
    }

    /** Same-project updates retain active protections, probe debt, and in-flight logical deadlines. */
    public synchronized void update(Limits replacement) {
        replacement = validated(replacement);
        Time now = time();
        sweep(now);
        limits = replacement;
        compilePathLimits();
    }

    /** Actual project epoch change/explicit reset only. Old tickets/endpoints/releases cannot act. */
    public synchronized void reset() {
        hosts.clear();
        paths.clear();
        protections.clear();
        heavyPaths.clear();
        flights.clear();
        candidateIndex.clear();
        maskedPaths.clear();
        maskedServices.clear();
        displayOpaque = false;
        events.clear();
        observations.clear();
        capacityProtection = null;
        admitted = rejected = timedOut = candidateEvictions = abandoned = 0;
        epoch++;
        new SecureRandom().nextBytes(key);
        startedAt = lastMillis = milliTime.getAsLong();
        clockRegressed = false;
        compilePathLimits();
    }

    public synchronized Gate check(Endpoint endpoint, boolean healthProbe) {
        Time now = time();
        sweep(now);
        return gate(endpoint, healthProbe, now);
    }

    /**
     * Rechecks gates, then atomically claims at most ONE GET/HEAD half-open attempt per service per
     * 30 seconds. A fan-out breach can reject here, BEFORE the caller consumes its intent budget.
     */
    public synchronized Ticket commit(Endpoint endpoint, boolean healthProbe, String evidenceId) throws Rejected {
        Time now = time();
        sweep(now);
        Gate gate = gate(endpoint, healthProbe, now);
        if (!gate.allowed()) throw reject(gate);
        endpoint = fenced(endpoint);
        Host host = hosts.get(endpoint.hostKey());
        if (host == null) { host = new Host(endpoint.host()); hosts.put(endpoint.hostKey(), host); }
        Fanout fanout = limits.fanout();
        if (fanout != null) {
            pruneSeen(host, now);
            String pathKey = endpoint.pathKeys().getLast();
            int projected = host.seen.size() + (host.seen.containsKey(pathKey) ? 0 : 1);
            if (host.episode == null && projected >= fanout.distinctPaths()) {
                Protection episode = fanout(host, endpoint, fanout, projected, now);
                if (fanout.action() != FanoutAction.WARN || episode == capacityProtection)
                    throw reject(gate(endpoint, healthProbe, now));
            }
        }
        // All potentially rejecting work precedes the claim. check() never reserves a probe.
        Protection circuit = host.circuit;
        boolean halfOpen = !healthProbe && circuit != null;
        Ticket ticket = new Ticket(epoch, halfOpen);
        if (halfOpen) {
            circuit.probe = ticket;
            host.hasProbeAttempt = true;
            host.lastProbeAttempt = now.nano;
        }
        for (String pathKey : endpoint.pathKeys()) {
            PathState state = paths.computeIfAbsent(pathKey, ignored -> new PathState());
            state.inFlight++;
            if (fanout != null) retain(state, now.nano, fanout.windowMillis());
        }
        Seen seen = null;
        Mark mark = null;
        if (fanout != null) {
            seen = host.seen.computeIfAbsent(endpoint.pathKeys().getLast(), ignored -> new Seen());
            mark = new Mark(now.nano, millis(fanout.windowMillis()));
            seen.pending.put(ticket, mark);
        }
        host.inFlight++;
        flights.put(ticket, new Flight(endpoint, host, healthProbe, halfOpen ? circuit : null,
                now.nano, millis(limits.requestTimeoutMillis()), seen, mark));
        admitted = increment(admitted);
        // evidenceId is intentionally NOT retained. It can contain reflected client metadata.
        return ticket;
    }

    public synchronized void observe(Ticket ticket, int status, long bytes) {
        Time now = time();
        sweep(now);
        Flight flight = current(ticket);
        if (flight == null) return;
        flights.remove(ticket);
        finish(ticket, flight, true, now);
        Endpoint endpoint = fenced(flight.endpoint);
        bytes = Math.max(0, bytes);
        rememberCandidate(endpoint);
        observations.add(new Observation(endpoint.pathKeys().getLast(), endpoint.hostKey(), endpoint.pathKeys(),
                endpoint.host(), endpoint.path(), endpoint.policyUrl(), status, bytes, now.millis, now.nano));
        long bound = responseBound(endpoint);
        if (bound > 0 && bytes > bound) heavy(endpoint, bytes, now);
        if (flight.probeCircuit != null) {
            // A released/replaced/expired probe's late callback cannot close another episode (ABA).
            if (flight.host.circuit == flight.probeCircuit && flight.probeCircuit.probe == ticket) {
                flight.probeCircuit.probe = null;
                if (status >= 200 && status <= 499) remove(flight.probeCircuit);
                else reopen(flight.host, flight.probeCircuit, now);
            }
        } else if (status >= 500 && status <= 599) {
            record5xx(flight.host, endpoint, now);
        }
    }

    /** Conclusively unsent. Cancels a logical claim but NEVER refunds the 30-second probe cadence. */
    public synchronized void cancel(Ticket ticket) {
        Time now = time();
        sweep(now);
        Flight flight = current(ticket);
        if (flight == null) return;
        flights.remove(ticket);
        finish(ticket, flight, false, now);
        if (flight.probeCircuit != null && flight.host.circuit == flight.probeCircuit
                && flight.probeCircuit.probe == ticket) flight.probeCircuit.probe = null;
    }

    /** Logical missing-response failure ONLY; there is no native permit to release or recycle. */
    public synchronized void abandon(Ticket ticket) {
        Time now = time();
        sweep(now);
        Flight flight = current(ticket);
        if (flight == null) return;
        flights.remove(ticket);
        finish(ticket, flight, true, now);
        abandoned = increment(abandoned);
        failProbe(ticket, flight, now);
    }

    /**
     * Response-time privacy refresh. Apply CURRENT per-entry evidence fingerprints to individual
     * structured display values, never a serialized incident document or its schema keys. Refreshes
     * existing observations/events/overlays and all flights, so late/concurrent completions cannot
     * revive send-time URLs. Keyed enforcement identities, leases, statistics and TTLs are unchanged.
     * The sanitizer is used synchronously and never retained. Missing evidence must sanitize opaque.
     */
    public synchronized void refreshDisplay(UnaryOperator<String> sanitizer) {
        Objects.requireNonNull(sanitizer);
        sweep(time());
        flights.replaceAll((ticket, flight) -> new Flight(sanitized(flight.endpoint, sanitizer), flight.host,
                flight.healthProbe, flight.probeCircuit, flight.started, flight.timeout, flight.seen, flight.mark));
        observations.map(observation -> {
            String host = safeDisplay(sanitizer, observation.host);
            String path = safeDisplay(sanitizer, observation.path);
            String policy = safePolicy(sanitizer, observation.policyUrl);
            rememberMask(observation.hostKey, observation.pathKeys, !host.equals(observation.host),
                    !path.equals(observation.path) || !policy.equals(observation.policyUrl));
            return new Observation(observation.id, observation.hostKey, observation.pathKeys,
                    host, path, policy, observation.status, observation.bytes, observation.ts, observation.nano);
        });
        events.map(event -> new Event(event.kind, safeDisplay(sanitizer, event.host), safeDisplay(sanitizer, event.path),
                event.bytes, event.count5xx, event.distinctPaths, event.ts, event.nano));
        for (Protection protection : protections.values()) {
            String host = safeDisplay(sanitizer, protection.displayHost);
            String path = safeDisplay(sanitizer, protection.displayPath);
            rememberMask(protection.serviceKey, protection.pathKeys, !host.equals(protection.displayHost),
                    !path.equals(protection.displayPath));
            protection.displayHost = host;
            protection.displayPath = path;
        }
        for (Host host : hosts.values()) host.display = safeDisplay(sanitizer, host.display);
        // Fences cover alias-equivalent routes and older prepared endpoints as well as future ones.
        flights.replaceAll((ticket, flight) -> new Flight(fenced(flight.endpoint), flight.host, flight.healthProbe,
                flight.probeCircuit, flight.started, flight.timeout, flight.seen, flight.mark));
        observations.map(observation -> {
            boolean hostMasked = displayOpaque || maskedServices.contains(observation.hostKey);
            boolean pathMasked = displayOpaque || observation.pathKeys.stream().anyMatch(maskedPaths::contains);
            return new Observation(observation.id, observation.hostKey, observation.pathKeys,
                    hostMasked ? "[REDACTED]" : observation.host, pathMasked ? "[REDACTED]" : observation.path,
                    hostMasked || pathMasked ? "" : observation.policyUrl,
                    observation.status, observation.bytes, observation.ts, observation.nano);
        });
    }

    /** Clear only diagnostic history, NOT active automatic protections, probe debt or native work. */
    public synchronized void clearEvidence() {
        events.clear();
        observations.clear();
        candidateIndex.clear();
        candidateEvictions = 0;
        Time now = time();
        startedAt = now.millis;
    }

    private Endpoint sanitized(Endpoint endpoint, UnaryOperator<String> sanitizer) {
        String host = safeDisplay(sanitizer, endpoint.host());
        String path = safeDisplay(sanitizer, endpoint.path());
        String policy = safePolicy(sanitizer, endpoint.policyUrl());
        rememberMask(endpoint.hostKey(), endpoint.pathKeys(), !host.equals(endpoint.host()),
                !path.equals(endpoint.path()) || !policy.equals(endpoint.policyUrl()));
        return new Endpoint(endpoint.hostKey(), endpoint.pathKeys(), host, path, policy,
                endpoint.owner, endpoint.epoch, endpoint.safeMethod);
    }
    private Endpoint fenced(Endpoint endpoint) {
        boolean host = displayOpaque || maskedServices.contains(endpoint.hostKey());
        boolean path = displayOpaque || endpoint.pathKeys().stream().anyMatch(maskedPaths::contains);
        if (!host && !path) return endpoint;
        return new Endpoint(endpoint.hostKey(), endpoint.pathKeys(), host ? "[REDACTED]" : endpoint.host(),
                path ? "[REDACTED]" : endpoint.path(), "", endpoint.owner, endpoint.epoch, endpoint.safeMethod);
    }
    private void rememberMask(String host, List<String> paths, boolean maskHost, boolean maskPath) {
        if (maskHost && host != null && !host.isEmpty()) maskedServices.add(host);
        if (maskPath) maskedPaths.addAll(paths);
        if (maskedServices.size() > MAX_HOSTS || maskedPaths.size() > MAX_PATHS) {
            displayOpaque = true;
            maskedServices.clear();
            maskedPaths.clear();
        }
    }
    private static String safeDisplay(UnaryOperator<String> sanitizer, String value) {
        if (value.isEmpty()) return "";
        try {
            String safe = sanitizer.apply(value);
            if (safe == null || safe.length() > MAX_DISPLAY) return "[REDACTED]";
            for (int i = 0; i < safe.length(); i++) if (Character.isISOControl(safe.charAt(i))) return "[REDACTED]";
            return safe;
        } catch (RuntimeException ignored) { return "[REDACTED]"; }
    }
    private static String safePolicy(UnaryOperator<String> sanitizer, String value) {
        if (value.isEmpty()) return "";
        // Any changed/opaque URL is non-actionable. Never turn a masked display into a policy draft.
        return value.equals(safeDisplay(sanitizer, value)) ? value : "";
    }

    public synchronized List<Overlay> overlays() {
        sweep(time());
        List<Overlay> out = new ArrayList<>();
        for (Protection protection : protections.values()) out.add(protection.view());
        if (capacityProtection != null) out.add(capacityProtection.view());
        return List.copyOf(out);
    }

    public synchronized boolean release(String id) {
        sweep(time());
        if (id == null) return false;
        if (capacityProtection != null && capacityProtection.id.equals(id)) {
            capacityProtection = null;
            return true;
        }
        Protection protection = protections.get(id);
        if (protection == null) return false;
        remove(protection);
        return true;
    }

    public synchronized int releaseAll() {
        sweep(time());
        int count = protections.size() + (capacityProtection == null ? 0 : 1);
        for (Protection protection : List.copyOf(protections.values())) remove(protection);
        capacityProtection = null;
        // WARN episodes have no enforced overlay, but an explicit all-release resets their episode.
        for (Host host : hosts.values()) { host.episode = null; host.seen.clear(); }
        return count;
    }

    public synchronized List<Candidate> candidates() {
        sweep(time());
        Map<String, Aggregate> stats = aggregate(Long.MIN_VALUE, Long.MAX_VALUE, true);
        return stats.values().stream().map(Aggregate::candidate).sorted(CANDIDATE_ORDER).toList();
    }

    /** Runtime candidate-list suppression only, NOT a policy edit or a protection bypass. */
    public synchronized boolean ignoreCandidate(String id) {
        sweep(time());
        CandidateMeta meta = candidateIndex.get(id);
        if (meta == null) return false;
        meta.ignored = true;
        return true;
    }

    public synchronized Map<String, Object> snapshot() {
        Time now = time();
        sweep(now);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("epoch", epoch);
        out.put("hosts", hosts.size());
        out.put("paths", paths.size());
        out.put("activeTickets", flights.size());
        out.put("overlays", protections.size() + (capacityProtection == null ? 0 : 1));
        out.put("circuits", hosts.values().stream().filter(h -> h.circuit != null).count());
        out.put("halfOpen", hosts.values().stream().filter(h -> h.circuit != null && h.circuit.probe != null).count());
        out.put("fanoutWarnings", hosts.values().stream().filter(h -> h.episode != null).count());
        out.put("automaticPause", protections.values().stream().anyMatch(p -> p.global));
        out.put("capacityBlocked", capacityProtection != null);
        out.put("admitted", admitted);
        out.put("rejected", rejected);
        out.put("timedOut", timedOut);
        out.put("abandoned", abandoned);
        out.put("events", events.values.size());
        out.put("observations", observations.values.size());
        out.put("eventsTruncated", events.dropped);
        out.put("observationsTruncated", observations.dropped);
        out.put("candidateEvictions", candidateEvictions);
        out.put("ignoredCandidates", candidateIndex.values().stream().filter(c -> c.ignored).count());
        out.put("candidatesIncomplete", observations.dropped || candidateEvictions != 0);
        out.put("p95Approximate", true);
        out.put("clockRegressed", clockRegressed);
        return Map.copyOf(out);
    }

    /** Exact statistics of RETAINED scalar observations in [from,to), not lifetime candidate totals. */
    public synchronized String incidentJson(long fromMillis, long toMillis) {
        if (toMillis <= fromMillis || toMillis - fromMillis < 0 || toMillis - fromMillis > DAY_MILLIS)
            throw new IllegalArgumentException("INVALID_INCIDENT_WINDOW");
        Time now = time();
        sweep(now);
        List<Map<String, Object>> selectedEvents = events.values.stream()
                .filter(e -> e.ts >= fromMillis && e.ts < toMillis).map(Event::view).toList();
        List<Candidate> stats = aggregate(fromMillis, toMillis, false).values().stream()
                .map(Aggregate::candidate).toList();
        boolean eventComplete = complete(events, fromMillis, toMillis, now);
        boolean observationComplete = complete(observations, fromMillis, toMillis, now);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("window", Map.of("from", fromMillis, "to", toMillis));
        out.put("events", selectedEvents);
        out.put("top5xx", stats.stream().filter(c -> c.count5xx() > 0)
                .sorted(Comparator.comparingLong(Candidate::count5xx).reversed().thenComparing(Candidate::id))
                .limit(20).toList());
        out.put("topBytes", stats.stream().sorted(CANDIDATE_ORDER).limit(20).toList());
        out.put("complete", eventComplete && observationComplete);
        out.put("truncated", !eventComplete || !observationComplete);
        out.put("approximate", true);
        out.put("approximation", Map.of("p95Bytes", "log2_histogram_upper_bound",
                "countMaxBytesLastSeen5xx", "exact_retained_window"));
        out.put("retention", Map.of("maxMillis", DAY_MILLIS, "startedAt", startedAt,
                "eventsComplete", eventComplete, "observationsComplete", observationComplete,
                "eventsDropped", events.dropped, "observationsDropped", observations.dropped,
                "clockRegressed", clockRegressed));
        return Json.write(out);
    }

    public record Gate(boolean allowed, String reason, GuardState guardState, String overlayId) {}
    public record Overlay(String id, String kind, String host, String path, long createdAt,
                          long expiresAt, String reason) {}
    public record Candidate(String id, String host, String path, String policyUrl, long maxBytes,
                            long p95Bytes, long count, long lastSeen, long count5xx) {}

    /**
     * Immutable endpoint projection with the specified public fields. The private provenance/method
     * prevents old-epoch endpoints and unsafe methods from acquiring a half-open claim. The public
     * five-field constructor is a display-only projection; use endpoint(...) for admission.
     */
    public static final class Endpoint {
        private final String hostKey;
        private final List<String> pathKeys;
        private final String host;
        private final String path;
        private final String policyUrl;
        private final Object owner;
        private final long epoch;
        private final boolean safeMethod;
        public Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl) {
            this(hostKey, pathKeys, host, path, policyUrl, null, 0, false);
        }
        private Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl,
                         Object owner, long epoch, boolean safeMethod) {
            this.hostKey = Objects.requireNonNull(hostKey);
            this.pathKeys = List.copyOf(pathKeys);
            this.host = Objects.requireNonNull(host);
            this.path = Objects.requireNonNull(path);
            this.policyUrl = Objects.requireNonNull(policyUrl);
            this.owner = owner;
            this.epoch = epoch;
            this.safeMethod = safeMethod;
        }
        public String hostKey() { return hostKey; }
        public List<String> pathKeys() { return pathKeys; }
        public String host() { return host; }
        public String path() { return path; }
        public String policyUrl() { return policyUrl; }
    }

    /** Opaque, immutable, instance-bound logical observation token. NOT a native admission permit. */
    public static final class Ticket {
        private final long epoch;
        private final boolean halfOpen;
        private Ticket(long epoch, boolean halfOpen) { this.epoch = epoch; this.halfOpen = halfOpen; }
        public long epoch() { return epoch; }
        public boolean halfOpen() { return halfOpen; }
    }

    public static final class Rejected extends Exception {
        private static final long serialVersionUID = 1L;
        private final String reason;
        private final GuardState guardState;
        private final String overlayId;
        private Rejected(Gate gate) {
            super(gate.reason());
            reason = gate.reason();
            guardState = gate.guardState();
            overlayId = gate.overlayId();
        }
        public String reason() { return reason; }
        public GuardState guardState() { return guardState; }
        public String overlayId() { return overlayId; }
    }

    private Gate gate(Endpoint endpoint, boolean healthProbe, Time now) {
        if (endpoint == null || endpoint.owner != identity || endpoint.epoch != epoch)
            return new Gate(false, "POLICY_CHANGED", GuardState.PROJECT_UNVERIFIED, "");
        if (capacityProtection != null) return denied(capacityProtection, GuardState.CAPACITY);
        for (Protection protection : protections.values()) {
            if (protection.global) return denied(protection, GuardState.OVERLAY_BLOCK);
        }
        for (String path : endpoint.pathKeys()) {
            Protection heavy = heavyPaths.get(path);
            if (heavy != null) return denied(heavy, GuardState.OVERLAY_BLOCK);
        }
        Host host = hosts.get(endpoint.hostKey());
        if (host != null && host.episode != null && host.episode.action == FanoutAction.BLOCK)
            return denied(host.episode, GuardState.OVERLAY_BLOCK);
        if (host != null && host.circuit != null && !healthProbe) {
            Protection circuit = host.circuit;
            if (!endpoint.safeMethod || circuit.probe != null || !reached(now.nano, circuit.until)
                    || host.hasProbeAttempt && now.nano - host.lastProbeAttempt < PROBE_INTERVAL)
                return denied(circuit, GuardState.CIRCUIT_OPEN);
        }
        if (host == null && hosts.size() >= hostCapacity || flights.size() >= MAX_FLIGHTS)
            return new Gate(false, CAPACITY, GuardState.CAPACITY, "");
        int additional = 0;
        for (String path : endpoint.pathKeys()) if (!paths.containsKey(path)) additional++;
        if (paths.size() + additional > pathCapacity)
            return new Gate(false, CAPACITY, GuardState.CAPACITY, "");
        return ALLOWED;
    }

    private Rejected reject(Gate gate) { rejected = increment(rejected); return new Rejected(gate); }
    private static Gate denied(Protection protection, GuardState state) {
        return new Gate(false, protection.reason, state, protection.id);
    }

    private void heavy(Endpoint endpoint, long bytes, Time now) {
        for (String pathKey : endpoint.pathKeys()) {
            Protection existing = heavyPaths.get(pathKey);
            if (existing != null) {
                // Repeated large responses extend protection, but never duplicate episode events or
                // shorten an existing TTL after a human lowers the setting.
                long until = now.nano + millis(limits.autoBlockMillis());
                if (remaining(until, now.nano) > remaining(existing.until, now.nano)) {
                    existing.until = until;
                    existing.expiresAt = add(now.millis, limits.autoBlockMillis());
                }
                return;
            }
        }
        Protection protection = new Protection(HEAVY, endpoint, now, limits.autoBlockMillis());
        events.add(new Event(HEAVY, endpoint.host(), endpoint.path(), bytes, -1, -1, now.millis, now.nano));
        if (!install(protection, now, limits.autoBlockMillis())) return;
        protection.pathKeys = endpoint.pathKeys();
        for (String pathKey : endpoint.pathKeys()) heavyPaths.put(pathKey, protection);
    }

    private void record5xx(Host host, Endpoint endpoint, Time now) {
        Circuit5xx config = limits.circuit5xx();
        if (config == null || host.circuit != null) return;
        long window = millis(config.windowMillis());
        while (!host.failures.isEmpty() && now.nano - host.failures.peekFirst() > window) host.failures.removeFirst();
        host.failureRetention = window;
        host.failures.addLast(now.nano);
        if (host.failures.size() < config.threshold()) return;
        Protection circuit = new Protection(CIRCUIT, endpoint, now, config.openMillis());
        circuit.openMillis = config.openMillis();
        circuit.host = host;
        events.add(new Event(CIRCUIT, endpoint.host(), "", -1, host.failures.size(), -1, now.millis, now.nano));
        if (!install(circuit, now, config.openMillis())) { host.failures.clear(); return; }
        host.circuit = circuit;
        host.failures.clear();
    }

    private Protection fanout(Host host, Endpoint endpoint, Fanout config, int distinct, Time now) {
        Protection episode = new Protection(FANOUT, endpoint, now, limits.autoBlockMillis());
        episode.host = host;
        episode.action = config.action();
        episode.global = config.action() == FanoutAction.PAUSE;
        // WARN is visible in the bounded host state and incident ring but is not an enforced overlay.
        events.add(new Event(FANOUT, endpoint.host(), "", -1, -1, distinct, now.millis, now.nano));
        if (config.action() != FanoutAction.WARN && !install(episode, now, limits.autoBlockMillis()))
            return capacityProtection;
        host.episode = episode;
        return episode;
    }

    private boolean install(Protection protection, Time now, long duration) {
        // Reserve ONE fixed slot for a visible global capacity fence. Never evict active protection.
        if (protections.size() >= overlayCapacity - 1) {
            if (capacityProtection == null)
                capacityProtection = new Protection(CAPACITY, null, now, duration);
            else if (remaining(now.nano + millis(duration), now.nano) > remaining(capacityProtection.until, now.nano)) {
                capacityProtection.until = now.nano + millis(duration);
                capacityProtection.expiresAt = add(now.millis, duration);
            }
            return false;
        }
        protections.put(protection.id, protection);
        return true;
    }

    private void reopen(Host host, Protection circuit, Time now) {
        circuit.probe = null;
        circuit.until = now.nano + millis(circuit.openMillis);
        circuit.expiresAt = add(now.millis, circuit.openMillis);
        host.failures.clear();
        events.add(new Event(CIRCUIT, circuit.displayHost, "", -1, 1, -1, now.millis, now.nano));
    }

    private void remove(Protection protection) {
        if (!protections.remove(protection.id, protection)) return;
        for (String path : protection.pathKeys) heavyPaths.remove(path, protection);
        Host host = protection.host;
        if (host != null) {
            if (host.circuit == protection) { host.circuit = null; host.failures.clear(); }
            if (host.episode == protection) { host.episode = null; host.seen.clear(); }
        }
    }

    private void sweep(Time now) {
        Iterator<Map.Entry<Ticket, Flight>> active = flights.entrySet().iterator();
        while (active.hasNext()) {
            Map.Entry<Ticket, Flight> entry = active.next();
            Flight flight = entry.getValue();
            if (now.nano - flight.started < flight.timeout) continue;
            active.remove();
            finish(entry.getKey(), flight, true, now);
            timedOut = increment(timedOut);
            failProbe(entry.getKey(), flight, now);
        }
        for (Protection protection : List.copyOf(protections.values())) {
            // An elapsed circuit enters half-open eligibility, NOT an unprotected/evictable state.
            if (!protection.reason.equals(CIRCUIT) && reached(now.nano, protection.until)) remove(protection);
        }
        if (capacityProtection != null && reached(now.nano, capacityProtection.until)) capacityProtection = null;
        for (Host host : hosts.values()) {
            pruneSeen(host, now);
            while (!host.failures.isEmpty() && now.nano - host.failures.peekFirst() > host.failureRetention)
                host.failures.removeFirst();
            if (host.episode != null && host.episode.action == FanoutAction.WARN
                    && reached(now.nano, host.episode.until)) host.episode = null;
        }
        paths.entrySet().removeIf(entry -> entry.getValue().inFlight == 0 && !heavyPaths.containsKey(entry.getKey())
                && (!entry.getValue().retained || reached(now.nano, entry.getValue().until)));
        hosts.values().removeIf(host -> host.inFlight == 0 && host.circuit == null && host.episode == null
                && host.seen.isEmpty() && host.failures.isEmpty()
                && (!host.hasProbeAttempt || now.nano - host.lastProbeAttempt >= PROBE_INTERVAL));
        events.prune(now.nano);
        observations.prune(now.nano);
        // Empty expired candidates must not retain stale policy URLs forever.
        LinkedHashSet<String> retained = new LinkedHashSet<>();
        for (Observation observation : observations.values) retained.add(observation.id);
        candidateIndex.entrySet().removeIf(entry -> !entry.getValue().ignored && !retained.contains(entry.getKey()));
    }

    private void failProbe(Ticket ticket, Flight flight, Time now) {
        if (flight.probeCircuit != null && flight.host.circuit == flight.probeCircuit
                && flight.probeCircuit.probe == ticket) reopen(flight.host, flight.probeCircuit, now);
    }

    private Flight current(Ticket ticket) {
        return ticket != null && ticket.epoch == epoch ? flights.get(ticket) : null;
    }

    private void finish(Ticket ticket, Flight flight, boolean accepted, Time now) {
        flight.host.inFlight--;
        for (String path : flight.endpoint.pathKeys()) {
            PathState state = paths.get(path);
            if (state != null) state.inFlight--;
        }
        if (flight.seen != null) {
            Seen seen = flight.seen;
            seen.pending.remove(ticket);
            if (accepted) seen.confirm(flight.mark, now.nano);
            if (!seen.active(now.nano)) flight.host.seen.remove(flight.endpoint.pathKeys().getLast(), seen);
        }
    }

    private static void pruneSeen(Host host, Time now) {
        host.seen.values().removeIf(seen -> !seen.active(now.nano));
    }

    private static void retain(PathState state, long now, long durationMillis) {
        long until = now + millis(durationMillis);
        if (!state.retained || remaining(until, now) > remaining(state.until, now)) state.until = until;
        state.retained = true;
    }

    private void compilePathLimits() {
        pathLimits.clear();
        for (GuardConfig.PathByteLimit limit : limits.heavyPathLimits()) {
            String service = service(limit.scheme(), limit.host(), limit.port());
            pathLimits.put(hash("path", service, limit.path()), limit.maxBytes());
        }
    }

    private long responseBound(Endpoint endpoint) {
        Long matched = null;
        for (String path : endpoint.pathKeys()) {
            Long value = pathLimits.get(path);
            if (value != null) {
                // Multiple routing aliases cannot use a more permissive authored override to evade
                // another explicit nonzero bound. A sole zero override disables the default.
                if (matched == null || matched == 0 || value > 0 && value < matched) matched = value;
            }
        }
        return matched == null ? limits.perPathMaxResponseBytes() : matched;
    }

    private void rememberCandidate(Endpoint endpoint) {
        String id = endpoint.pathKeys().getLast();
        if (candidateIndex.containsKey(id)) { candidateIndex.get(id); return; }
        if (candidateIndex.size() >= pathCapacity) {
            Iterator<Map.Entry<String, CandidateMeta>> iterator = candidateIndex.entrySet().iterator();
            boolean removed = false;
            while (iterator.hasNext()) {
                if (!iterator.next().getValue().ignored) { iterator.remove(); removed = true; break; }
            }
            candidateEvictions = increment(candidateEvictions);
            if (!removed) return;
        }
        candidateIndex.put(id, new CandidateMeta());
    }

    private Map<String, Aggregate> aggregate(long from, long to, boolean candidatesOnly) {
        Map<String, Aggregate> out = new HashMap<>();
        for (Observation observation : observations.values) {
            if (!candidatesOnly && (observation.ts < from || observation.ts >= to)) continue;
            if (candidatesOnly) {
                CandidateMeta meta = candidateIndex.get(observation.id);
                if (meta == null || meta.ignored) continue;
            }
            out.computeIfAbsent(observation.id, ignored -> new Aggregate(observation)).add(observation);
        }
        return out;
    }

    private boolean complete(Ring<?> ring, long from, long to, Time now) {
        return !clockRegressed && from >= startedAt && from >= add(now.millis, -DAY_MILLIS)
                && to <= add(now.millis, 1) && !ring.lostIn(from, to);
    }

    private Time time() {
        long nano = nanoTime.getAsLong();
        long millis = milliTime.getAsLong();
        if (millis < lastMillis) clockRegressed = true;
        lastMillis = millis;
        return new Time(nano, millis);
    }

    private String hash(String... components) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String component : components) {
                byte[] bytes = component.getBytes(StandardCharsets.UTF_8);
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

    private static URI uri(String url) {
        if (url == null || url.length() > MAX_URL) throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        try {
            URI uri = URI.create(url);
            if (uri.getHost() == null || uri.getScheme() == null
                    || !(uri.getScheme().equalsIgnoreCase("https") || uri.getScheme().equalsIgnoreCase("http")))
                throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
            return uri;
        } catch (RuntimeException ignored) { throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT"); }
    }

    private static String path(URI uri) {
        String path = uri.getRawPath();
        return path == null || path.isEmpty() ? "/" : path;
    }
    private static int port(URI uri) {
        return uri.getPort() == -1 ? uri.getScheme().equalsIgnoreCase("https") ? 443 : 80 : uri.getPort();
    }
    private static String service(String scheme, String host, int port) {
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
                || port < 1 || port > 65_535) throw new IllegalArgumentException("INVALID_WATCHER_ENDPOINT");
        String canonical = PolicyEngine.canonicalHost(host);
        if (canonical.indexOf(':') >= 0 && !canonical.startsWith("[")) canonical = "[" + canonical + "]";
        String lower = scheme.equalsIgnoreCase("https") ? "https" : "http";
        return lower + "://" + canonical + ((lower.equals("https") ? port == 443 : port == 80) ? "" : ":" + port);
    }
    private static int capacity(int value, int max) {
        if (value < 1 || value > max) throw new IllegalArgumentException("INVALID_WATCHER_CAPACITY");
        return value;
    }
    private static long millis(long value) { return TimeUnit.MILLISECONDS.toNanos(value); }
    private static boolean reached(long now, long deadline) { return now - deadline >= 0; }
    private static long remaining(long deadline, long now) { return Math.max(0, deadline - now); }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }
    private static long add(long a, long b) {
        long result = a + b;
        return ((a ^ result) & (b ^ result)) < 0 ? b < 0 ? Long.MIN_VALUE : Long.MAX_VALUE : result;
    }

    private static final Comparator<Candidate> CANDIDATE_ORDER = Comparator.comparingLong(Candidate::maxBytes)
            .reversed().thenComparing(Candidate::id);
    private record Time(long nano, long millis) {}
    private record Mark(long at, long window) {}
    /** At most one confirmed expiry plus one scalar mark per bounded in-flight ticket. */
    private static final class Seen {
        final Map<Ticket, Mark> pending = new HashMap<>();
        boolean confirmed;
        long until;
        void confirm(Mark mark, long now) {
            long deadline = mark.at + mark.window;
            if (!confirmed || remaining(deadline, now) > remaining(until, now)) until = deadline;
            confirmed = true;
        }
        boolean active(long now) {
            return confirmed && !reached(now, until)
                    || pending.values().stream().anyMatch(mark -> now - mark.at < mark.window);
        }
    }
    private interface Timed { long ts(); long nano(); }
    private record Observation(String id, String hostKey, List<String> pathKeys, String host, String path,
                               String policyUrl, int status, long bytes, long ts, long nano) implements Timed {}
    private record Event(String kind, String host, String path, long bytes, long count5xx,
                         long distinctPaths, long ts, long nano) implements Timed {
        Map<String, Object> view() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("kind", kind);
            if (!host.isEmpty()) out.put("host", host);
            if (!path.isEmpty()) out.put("path", path);
            if (bytes >= 0) out.put("bytes", bytes);
            if (count5xx >= 0) out.put("5xx", count5xx);
            if (distinctPaths >= 0) out.put("distinctPaths", distinctPaths);
            out.put("ts", ts);
            return Map.copyOf(out);
        }
    }
    private static final class Ring<T extends Timed> {
        final int capacity;
        final ArrayDeque<T> values = new ArrayDeque<>();
        boolean dropped;
        long lostMin = Long.MAX_VALUE;
        long lostMax = Long.MIN_VALUE;
        Ring(int capacity) { this.capacity = capacity; }
        void add(T value) {
            if (values.size() == capacity) lost(values.removeFirst());
            values.addLast(value);
        }
        void map(UnaryOperator<T> transform) {
            List<T> replacement = values.stream().map(transform).toList();
            values.clear();
            values.addAll(replacement);
        }
        void prune(long now) {
            while (!values.isEmpty() && now - values.peekFirst().nano() > DAY_NANOS) lost(values.removeFirst());
        }
        void lost(T value) {
            dropped = true;
            lostMin = Math.min(lostMin, value.ts());
            lostMax = Math.max(lostMax, value.ts());
        }
        boolean lostIn(long from, long to) { return dropped && from <= lostMax && to > lostMin; }
        void clear() { values.clear(); dropped = false; lostMin = Long.MAX_VALUE; lostMax = Long.MIN_VALUE; }
    }
    private static final class Host {
        String display;
        final ArrayDeque<Long> failures = new ArrayDeque<>();
        final Map<String, Seen> seen = new HashMap<>();
        int inFlight;
        long failureRetention;
        boolean hasProbeAttempt;
        long lastProbeAttempt;
        Protection circuit;
        Protection episode;
        Host(String display) { this.display = display; }
    }
    private static final class PathState {
        int inFlight;
        boolean retained;
        long until;
    }
    private static final class CandidateMeta { boolean ignored; }
    private record Flight(Endpoint endpoint, Host host, boolean healthProbe, Protection probeCircuit,
                          long started, long timeout, Seen seen, Mark mark) {}
    private static final class Protection {
        final String id = UUID.randomUUID().toString();
        final String reason;
        String displayHost;
        String displayPath;
        final String serviceKey;
        final long createdAt;
        long expiresAt;
        long until;
        long openMillis;
        List<String> pathKeys = List.of();
        Host host;
        Ticket probe;
        FanoutAction action;
        boolean global;
        Protection(String reason, Endpoint endpoint, Time now, long duration) {
            this.reason = reason;
            serviceKey = endpoint == null ? "" : endpoint.hostKey();
            displayHost = endpoint == null ? "" : endpoint.host();
            displayPath = reason.equals(HEAVY) && endpoint != null ? endpoint.path() : "";
            createdAt = now.millis;
            expiresAt = add(now.millis, duration);
            until = now.nano + millis(duration);
        }
        Overlay view() { return new Overlay(id, reason, displayHost, displayPath, createdAt, expiresAt, reason); }
    }
    private static final class Aggregate {
        final String id;
        String host;
        String path;
        String policyUrl;
        boolean redacted;
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
            }
            // A previously masked observation must never become an actionable raw policy URL.
            redacted |= observation.policyUrl.isEmpty();
            if (redacted) policyUrl = "";
        }
        Candidate candidate() { return new Candidate(id, host, path, policyUrl, max, p95(), count, lastSeen, count5xx); }
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
