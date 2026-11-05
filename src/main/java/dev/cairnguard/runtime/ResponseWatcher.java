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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Project-epoch, memory-only availability protections plus ORIGINAL diagnostic history (actual service
 * host and untouched path; no masking, no event/observation/candidate quota, retained until explicit
 * clear, project epoch reset or unload). No I/O, timer threads, policy writes, native messages, response
 * copies, or native permits. Call observe with the native body LENGTH scalar,
 * independently of whether optional response content inspection was possible. All public mutations
 * are serialized; check is advisory and commit is the final, atomic admission/half-open claim.
 */
public final class ResponseWatcher {
    private static final int MAX_HOSTS = 1_024;
    private static final int MAX_PATHS = 2_048;
    private static final int MAX_OVERLAYS = 1_024;
    private static final int MAX_FLIGHTS = 4_096;
    private static final int MAX_ROUTE_VIEWS = 9;
    private static final int MAX_URL = 16_384; // per routing-view enforcement key validity, same as policy
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
    // Subset of flights, not another unbounded history. Logical timeout cannot discard eventual
    // response observation or reuse the physical host/path reservations. No raw/native data here.
    private final java.util.Set<Ticket> expiredFlights = new HashSet<>();
    // Diagnostic history only (no enforcement authority): kept until clearEvidence/reset, no quota.
    private final Map<String, CandidateMeta> candidateIndex = new HashMap<>();
    private final List<Event> events = new ArrayList<>();
    private final List<Observation> observations = new ArrayList<>();
    private final Map<String, Long> pathLimits = new HashMap<>();
    // Keyed HMAC identities of the CURRENT exact 5xx circuit exception routes (no route plaintext).
    private final java.util.Set<String> circuitExceptions = new HashSet<>();
    // Bumped on every circuit enable/disable transition: older flights can never act on a newer circuit.
    private long circuitGeneration;
    // Bumped on every large-response master transition: older flights can never actuate a newer detector.
    private long heavyGeneration;
    // Keyed HMAC identities of the CURRENT exact fan-out exception routes (no route plaintext).
    private final java.util.Set<String> fanoutExceptions = new HashSet<>();
    // Bumped by clearEvidence: endpoints created earlier carry no display originals into later history.
    private long displayGeneration;
    private Limits limits;
    private long epoch = 1;
    private long startedAt;
    private long lastMillis;
    private boolean clockRegressed;
    private Protection capacityProtection;
    private long admitted;
    private long rejected;
    private long timedOut;
    private long abandoned;
    // Bounded scalars, not a per-ticket ledger: WARN admissions whose NEW identity had no indexed
    // Seen slot. Active debt keeps BLOCK/PAUSE fail-closed until every omitted original window ends.
    private long fanoutOmitted;
    private boolean omissionActive;
    private long omissionUntil;
    private long omissionExpiresAt; // Wall-clock diagnostic only; omissionUntil (monotonic) is authority.

    public ResponseWatcher(Limits limits) {
        this(limits, System::nanoTime, System::currentTimeMillis, MAX_HOSTS, MAX_PATHS, MAX_OVERLAYS);
    }

    public ResponseWatcher(Limits limits, LongSupplier nanoTime, LongSupplier milliTime) {
        this(limits, nanoTime, milliTime, MAX_HOSTS, MAX_PATHS, MAX_OVERLAYS);
    }

    /** Bounded fake-clock/enforcement-capacity seam. All production ceilings still apply. */
    public ResponseWatcher(Limits limits, LongSupplier nanoTime, LongSupplier milliTime,
                           int hostCapacity, int pathCapacity, int overlayCapacity) {
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.milliTime = Objects.requireNonNull(milliTime);
        this.hostCapacity = capacity(hostCapacity, MAX_HOSTS);
        this.pathCapacity = capacity(pathCapacity, MAX_PATHS);
        this.overlayCapacity = capacity(overlayCapacity, MAX_OVERLAYS);
        this.limits = validated(limits);
        new SecureRandom().nextBytes(key);
        startedAt = lastMillis = milliTime.getAsLong();
        compilePathLimits();
    }

    /**
     * Converts transient raw routing views to per-instance keyed HMACs for enforcement. Display keeps the
     * ORIGINAL actual service host and untouched first routing view (never a fuzzed Host header or URL
     * authority). The actual service, not a Host header, supplies enforcement identity.
     */
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
        boolean safeMethod = "GET".equals(request.method()) || "HEAD".equals(request.method());
        // Exact-route identity only for one complete, unambiguous routing view of the ACTUAL target.
        String exact = PolicyEngine.exactRoutingPath(request);
        boolean single = exact != null && routingPaths.size() == 1 && rawPath.equals(exact);
        String routeKey = single ? hash("path", service, exact) : null;
        // Query-free draft hint only when the original path is a faithful ordinary URL path.
        String policyUrl = single && draftable(rawPath) ? service + rawPath : "";
        return new Endpoint(hash("service", service), List.copyOf(hashed), request.host(), rawPath,
                policyUrl, identity, epoch, safeMethod, routeKey, UUID.randomUUID().toString(), displayGeneration);
    }

    /** Same-project updates retain active protections, probe debt, and in-flight logical deadlines. */
    public synchronized void update(Limits replacement) {
        replacement = validated(replacement);
        Time now = time();
        sweep(now);
        boolean wasOn = limits.circuit5xx() != null;
        boolean heavyWasOn = limits.heavyResponseEnabled();
        limits = replacement;
        compilePathLimits();
        if (heavyWasOn != replacement.heavyResponseEnabled()) {
            heavyGeneration++;
            // Large-response OFF ends heavy ENFORCEMENT only; observations, flights and reservations remain.
            if (heavyWasOn) for (Protection protection : List.copyOf(protections.values()))
                if (protection.reason.equals(HEAVY)) remove(protection);
        }
        if (wasOn != (replacement.circuit5xx() != null)) {
            circuitGeneration++;
            // Explicit OFF is a logical circuit reset, not releaseAll: flights, tickets, Seen history,
            // reservations and every other protection (including the shared capacity fence) remain.
            // OFF -> ON simply starts the new generation; nothing old can be revived.
            if (wasOn) for (Protection protection : List.copyOf(protections.values()))
                if (protection.reason.equals(CIRCUIT)) remove(protection);
            for (Host host : hosts.values()) { host.failures.clear(); host.hasProbeAttempt = false; }
        }
        Fanout fanout = replacement.fanout();
        // Mode transitions detach logical episodes only. Seen history, pending marks and omission debt stay
        // (never remove()'s destructive Seen clear). BLOCK <-> PAUSE keeps id/TTL/source of the episode.
        for (Host host : hosts.values()) {
            Protection episode = host.episode;
            if (episode == null) continue;
            boolean warnLatch = episode.action == FanoutAction.WARN;
            if (fanout == null) detachFanout(host);
            else if (fanout.action() == FanoutAction.WARN) { if (!warnLatch) detachFanout(host); }
            // A WARN latch is not a protection; it must not suppress enforcing detection.
            else if (warnLatch) host.episode = null;
            else { episode.action = fanout.action(); episode.global = fanout.action() == FanoutAction.PAUSE; }
        }
        // Shared capacity fence (no contributor ledger): only when EVERY automatic actuator is non-enforcing.
        // Its producers are install() via heavy (needs master ON), circuit sampling (needs circuit5xx) and an
        // enforcing fan-out commit; none can run in this state, and old flights are generation-fenced.
        if (!replacement.heavyResponseEnabled() && replacement.circuit5xx() == null
                && (fanout == null || fanout.action() == FanoutAction.WARN) && protections.isEmpty())
            capacityProtection = null;
    }

    /** Actual project epoch change/explicit reset only. Old tickets/endpoints/releases cannot act. */
    public synchronized void reset() {
        hosts.clear();
        paths.clear();
        protections.clear();
        heavyPaths.clear();
        flights.clear();
        expiredFlights.clear();
        candidateIndex.clear();
        events.clear();
        observations.clear();
        capacityProtection = null;
        admitted = rejected = timedOut = abandoned = 0;
        fanoutOmitted = omissionUntil = omissionExpiresAt = 0;
        omissionActive = false;
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
        endpoint = current(endpoint);
        Host host = hosts.get(endpoint.hostKey());
        if (host == null) {
            if (hosts.size() >= hostCapacity) reclaim(reclaimableHost(now), now); // gate() proved a candidate exists
            host = new Host();
            hosts.put(endpoint.hostKey(), host);
        }
        Fanout fanout = limits.fanout();
        boolean omitted = false;
        // Final-commit fan-out exclusion: no count, Seen/Mark, retention or debt for THIS admission.
        boolean fanoutExcluded = fanout != null && fanoutExcluded(endpoint);
        if (fanoutExcluded) fanout = null;
        if (fanout != null) {
            pruneSeen(host, now);
            String pathKey = endpoint.pathKeys().getLast();
            boolean known = host.seen.containsKey(pathKey);
            int projected = host.seen.size() + (known ? 0 : 1);
            if (host.episode == null && projected >= fanout.distinctPaths()) {
                Protection episode = fanout(host, endpoint, fanout, projected, now);
                if (fanout.action() != FanoutAction.WARN || episode == capacityProtection)
                    throw reject(gate(endpoint, healthProbe, now));
            }
            // Only reachable for WARN: gate() already rejected an enforcing identity without a slot.
            omitted = !known && indexedSeen() >= pathCapacity;
        }
        // All potentially rejecting work precedes the claim. check() never reserves a probe.
        Protection circuit = host.circuit;
        boolean excluded = circuitExcluded(endpoint);
        boolean halfOpen = !healthProbe && circuit != null && !excluded;
        Ticket ticket = new Ticket(epoch, halfOpen);
        if (halfOpen) {
            circuit.probe = ticket;
            host.hasProbeAttempt = true;
            host.lastProbeAttempt = now.nano;
        }
        for (String pathKey : endpoint.pathKeys()) {
            PathState state = paths.computeIfAbsent(pathKey, ignored -> new PathState());
            state.inFlight++;
            // WARN history is bounded by the indexed Seen budget, not by pinning completed paths.
            if (fanout != null && fanout.action() != FanoutAction.WARN) retain(state, now.nano, fanout.windowMillis());
        }
        Seen seen = null;
        Mark mark = null;
        if (omitted) {
            fanoutOmitted = increment(fanoutOmitted);
            long until = now.nano + millis(fanout.windowMillis());
            if (!omissionActive || remaining(until, now.nano) > remaining(omissionUntil, now.nano)) {
                omissionUntil = until;
                omissionExpiresAt = add(now.millis, fanout.windowMillis());
            }
            omissionActive = true;
        } else if (fanout != null) {
            seen = host.seen.computeIfAbsent(endpoint.pathKeys().getLast(), ignored -> new Seen());
            mark = new Mark(now.nano, millis(fanout.windowMillis()));
            seen.pending.put(ticket, mark);
        }
        host.inFlight++;
        boolean heavyEligible = limits.heavyResponseEnabled() && responseBound(endpoint) > 0;
        flights.put(ticket, new Flight(endpoint, host, healthProbe, halfOpen ? circuit : null,
                now.nano, millis(limits.requestTimeoutMillis()), seen, mark, excluded, circuitGeneration,
                heavyEligible, heavyGeneration));
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
        expiredFlights.remove(ticket);
        finish(ticket, flight, true, now);
        Endpoint endpoint = current(flight.endpoint);
        bytes = Math.max(0, bytes);
        rememberCandidate(endpoint);
        observations.add(new Observation(endpoint.pathKeys().getLast(), endpoint.hostKey(), endpoint.pathKeys(),
                endpoint.host(), endpoint.path(), endpoint.policyUrl(), status, bytes, now.millis, now.nano, endpoint.source));
        long bound = responseBound(endpoint);
        if (flight.heavyEligible && flight.heavyGeneration == heavyGeneration && limits.heavyResponseEnabled()
                && bound > 0 && bytes > bound) heavy(endpoint, bytes, now);
        if (flight.probeCircuit != null) {
            // A released/replaced/expired probe's late callback cannot close another episode (ABA).
            if (flight.host.circuit == flight.probeCircuit && flight.probeCircuit.probe == ticket) {
                flight.probeCircuit.probe = null;
                if (status >= 200 && status <= 499) remove(flight.probeCircuit);
                else reopen(flight.host, flight.probeCircuit, now, flight.endpoint.source);
            }
        } else if (status >= 500 && status <= 599 && !flight.circuitExcluded && flight.circuitGeneration == circuitGeneration) {
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
        expiredFlights.remove(ticket);
        finish(ticket, flight, false, now);
        if (flight.probeCircuit != null && flight.host.circuit == flight.probeCircuit
                && flight.probeCircuit.probe == ticket) flight.probeCircuit.probe = null;
    }

    /** Logical missing-response failure ONLY. Retain the bounded flight for a real late response. */
    public synchronized void abandon(Ticket ticket) {
        Time now = time();
        sweep(now);
        Flight flight = current(ticket);
        if (flight == null || !expiredFlights.add(ticket)) return;
        abandoned = increment(abandoned);
        failProbe(ticket, flight, now);
    }

    /**
     * Clear only diagnostic history and the display/source references to originals, NOT active automatic
     * protections, their keys/leases/deadlines, probe debt, reservations or native work.
     */
    public synchronized void clearEvidence() {
        events.clear();
        observations.clear();
        candidateIndex.clear();
        displayGeneration++;
        for (Protection protection : protections.values()) {
            protection.displayHost = "";
            protection.displayPath = "";
        }
        // WARN episodes are not installed as protections but still hold the original display host.
        for (Host host : hosts.values()) if (host.episode != null) { host.episode.displayHost = ""; host.episode.displayPath = ""; }
        // A released/OFF half-open circuit is detached from protections but its in-flight probe still references it.
        for (Flight flight : flights.values()) if (flight.probeCircuit != null) { flight.probeCircuit.displayHost = ""; flight.probeCircuit.displayPath = ""; }
        flights.replaceAll((ticket, flight) -> new Flight(current(flight.endpoint), flight.host, flight.healthProbe,
                flight.probeCircuit, flight.started, flight.timeout, flight.seen, flight.mark,
                flight.circuitExcluded, flight.circuitGeneration, flight.heavyEligible, flight.heavyGeneration));
        Time now = time();
        startedAt = now.millis;
    }

    /** An endpoint from before the latest explicit clear keeps its keys but carries no display originals. */
    private Endpoint current(Endpoint endpoint) {
        if (endpoint.displayGeneration == displayGeneration) return endpoint;
        return new Endpoint(endpoint.hostKey(), endpoint.pathKeys(), "", "", "", endpoint.owner, endpoint.epoch,
                endpoint.safeMethod, endpoint.routeKey, endpoint.source, displayGeneration);
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

    /** In-process human projection support: safe records plus their opaque original references. */
    public record SourcedCandidate(Candidate candidate, String source) {}
    public record SourcedOverlay(Overlay overlay, String source, boolean pathScoped) {}
    public synchronized List<SourcedCandidate> sourcedCandidates() {
        sweep(time());
        return aggregate(Long.MIN_VALUE, Long.MAX_VALUE, true).values().stream()
                .sorted(java.util.Comparator.comparing(Aggregate::candidate, CANDIDATE_ORDER))
                .map(a -> new SourcedCandidate(a.candidate(), a.source)).toList();
    }
    public synchronized List<SourcedOverlay> sourcedOverlays() {
        sweep(time());
        List<SourcedOverlay> out = new ArrayList<>();
        for (Protection p : protections.values()) out.add(new SourcedOverlay(p.view(), p.source, p.reason.equals(HEAVY)));
        if (capacityProtection != null) out.add(new SourcedOverlay(capacityProtection.view(), null, false));
        return List.copyOf(out);
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
        out.put("activeTickets", flights.size() - expiredFlights.size());
        out.put("lateTickets", expiredFlights.size());
        out.put("overlays", protections.size() + (capacityProtection == null ? 0 : 1));
        out.put("circuits", hosts.values().stream().filter(h -> h.circuit != null).count());
        out.put("halfOpen", hosts.values().stream().filter(h -> h.circuit != null && h.circuit.probe != null).count());
        out.put("fanoutWarnings", hosts.values().stream().filter(h -> h.episode != null).count());
        // Fan-out counts describe INDEXED history only and are lower bounds once anything is omitted.
        out.put("fanoutHistoryIndexed", indexedSeen());
        out.put("fanoutHistoryCapacity", pathCapacity);
        out.put("fanoutHistoryOmitted", fanoutOmitted);
        out.put("fanoutHistoryIncomplete", omissionActive);
        out.put("fanoutHistoryIncompleteUntil", omissionActive ? omissionExpiresAt : 0L);
        // Watcher-local configuration only: the controller's OFF/lifecycle bypass is not reflected here.
        Fanout fanout = limits.fanout();
        out.put("fanoutHistoryEnforcing", omissionActive && fanout != null && fanout.action() != FanoutAction.WARN);
        // Monotonic, rounded UP so live debt never reads as 0 ms remaining.
        out.put("fanoutHistoryRemainingMillis", omissionActive ? (remaining(omissionUntil, now.nano) + 999_999) / 1_000_000 : 0L);
        out.put("automaticPause", protections.values().stream().anyMatch(p -> p.global));
        out.put("capacityBlocked", capacityProtection != null);
        out.put("admitted", admitted);
        out.put("rejected", rejected);
        out.put("timedOut", timedOut);
        out.put("abandoned", abandoned);
        out.put("events", events.size());
        out.put("observations", observations.size());
        // Compatibility keys: diagnostic history has no capacity, ring or eviction any more.
        out.put("eventsTruncated", false);
        out.put("observationsTruncated", false);
        out.put("candidateEvictions", 0L);
        out.put("ignoredCandidates", candidateIndex.values().stream().filter(c -> c.ignored).count());
        out.put("candidatesIncomplete", false);
        out.put("p95Approximate", true);
        out.put("clockRegressed", clockRegressed);
        return Map.copyOf(out);
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
        Time now = time();
        sweep(now);
        List<Map<String, Object>> selectedEvents = events.stream()
                .filter(e -> e.ts >= fromMillis && e.ts < toMillis).map(e -> {
                    if (!sourced) return e.view();
                    Map<String, Object> view = new LinkedHashMap<>(e.view());
                    view.put("_source", e.source == null ? "" : e.source);
                    return view;
                }).toList();
        List<Aggregate> stats = List.copyOf(aggregate(fromMillis, toMillis, false).values());
        boolean eventComplete = complete(fromMillis, toMillis, now);
        boolean observationComplete = eventComplete;
        // Epoch-wide and conservative: omissions are not attributed to a specific incident window.
        boolean fanoutComplete = fanoutOmitted == 0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("window", Map.of("from", fromMillis, "to", toMillis));
        out.put("events", selectedEvents);
        out.put("top5xx", stats.stream().filter(a -> a.count5xx > 0)
                .sorted(Comparator.comparingLong((Aggregate a) -> a.count5xx).reversed().thenComparing(a -> a.id))
                .limit(20).map(a -> sourced ? a.sourcedView() : (Object) a.candidate()).toList());
        out.put("topBytes", stats.stream().sorted(Comparator.comparing(Aggregate::candidate, CANDIDATE_ORDER)).limit(20)
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
                "clockRegressed", clockRegressed, "fanoutHistoryOmitted", fanoutOmitted));
        return out;
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
        private final String routeKey; // exact-route HMAC, null when not eligible; never serialized
        // Random opaque reference to the human-local original of THIS request; never serialized.
        private final String source;
        private final long displayGeneration;
        public Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl) {
            this(hostKey, pathKeys, host, path, policyUrl, null, 0, false, null, null, 0);
        }
        private Endpoint(String hostKey, List<String> pathKeys, String host, String path, String policyUrl,
                         Object owner, long epoch, boolean safeMethod, String routeKey, String source, long displayGeneration) {
            this.hostKey = Objects.requireNonNull(hostKey);
            this.pathKeys = List.copyOf(pathKeys);
            this.host = Objects.requireNonNull(host);
            this.path = Objects.requireNonNull(path);
            this.policyUrl = Objects.requireNonNull(policyUrl);
            this.owner = owner;
            this.epoch = epoch;
            this.safeMethod = safeMethod;
            this.routeKey = routeKey;
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
        boolean fanoutExcluded = fanoutExcluded(endpoint);
        for (Protection protection : protections.values()) {
            // Only a fan-out episode is ever global (automatic PAUSE); an exact exception bypasses only it.
            if (protection.global && !fanoutExcluded) return denied(protection, GuardState.OVERLAY_BLOCK);
        }
        // Heavy gating is current: master OFF or an authored size-0 route exception bypasses ONLY heavy.
        if (limits.heavyResponseEnabled() && !heavyExcepted(endpoint)) {
            for (String path : endpoint.pathKeys()) {
                Protection heavy = heavyPaths.get(path);
                if (heavy != null) return denied(heavy, GuardState.OVERLAY_BLOCK);
            }
        }
        Host host = hosts.get(endpoint.hostKey());
        if (host != null && host.episode != null && host.episode.action == FanoutAction.BLOCK && !fanoutExcluded)
            return denied(host.episode, GuardState.OVERLAY_BLOCK);
        if (host != null && host.circuit != null && !healthProbe && !circuitExcluded(endpoint)) {
            Protection circuit = host.circuit;
            if (!endpoint.safeMethod || circuit.probe != null || !reached(now.nano, circuit.until)
                    || host.hasProbeAttempt && now.nano - host.lastProbeAttempt < PROBE_INTERVAL)
                return denied(circuit, GuardState.CIRCUIT_OPEN);
        }
        if (host == null && hosts.size() >= hostCapacity && reclaimableHost(now) == null || flights.size() >= MAX_FLIGHTS)
            return new Gate(false, CAPACITY, GuardState.CAPACITY, "");
        int additional = 0;
        for (String path : endpoint.pathKeys()) if (!paths.containsKey(path)) additional++;
        if (paths.size() + additional > pathCapacity)
            return new Gate(false, CAPACITY, GuardState.CAPACITY, "");
        Fanout fanout = limits.fanout();
        // Enforcing omission debt binds every request, excluded or not; an excluded admission needs no NEW Seen slot.
        if (fanout != null && fanout.action() != FanoutAction.WARN && (omissionActive
                || !fanoutExcluded && (host == null || !host.seen.containsKey(endpoint.pathKeys().getLast())) && indexedSeen() >= pathCapacity))
            return new Gate(false, CAPACITY, GuardState.CAPACITY, "");
        return ALLOWED;
    }

    /**
     * Idle, purely diagnostic host history that WARN/disabled fan-out may give up when HOST capacity is
     * the only blocker: no native work (incl. late), circuit, enforcing episode, failure samples, live
     * probe cadence or pending Seen mark. Pure selection, shared by gate() feasibility and commit().
     * Returns the candidate with the least remaining history, or null.
     */
    private Map.Entry<String, Host> reclaimableHost(Time now) {
        Fanout fanout = limits.fanout();
        if (fanout != null && fanout.action() != FanoutAction.WARN) return null;
        Map.Entry<String, Host> best = null;
        long bestRemaining = 0;
        for (Map.Entry<String, Host> entry : hosts.entrySet()) {
            Host host = entry.getValue();
            if (host.inFlight != 0 || host.circuit != null || !host.failures.isEmpty()
                    || host.episode != null && host.episode.action != FanoutAction.WARN
                    || host.hasProbeAttempt && now.nano - host.lastProbeAttempt < PROBE_INTERVAL) continue;
            long latest = 0;
            boolean idle = true;
            for (Seen seen : host.seen.values()) {
                if (!seen.pending.isEmpty() || !seen.confirmed) { idle = false; break; }
                latest = Math.max(latest, remaining(seen.until, now.nano));
            }
            if (idle && (best == null || latest < bestRemaining)) { best = entry; bestRemaining = latest; }
        }
        return best;
    }

    /** Each discarded confirmed history becomes saturating omission debt with its ORIGINAL monotonic deadline. */
    private void reclaim(Map.Entry<String, Host> candidate, Time now) {
        hosts.remove(candidate.getKey(), candidate.getValue());
        for (Seen seen : candidate.getValue().seen.values()) {
            fanoutOmitted = increment(fanoutOmitted);
            if (!omissionActive || remaining(seen.until, now.nano) > remaining(omissionUntil, now.nano)) {
                omissionUntil = seen.until;
                // Wall time is display only; round UP so live debt never displays as already expired.
                omissionExpiresAt = add(now.millis, (remaining(seen.until, now.nano) + 999_999) / 1_000_000);
            }
            omissionActive = true;
        }
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
        events.add(new Event(HEAVY, endpoint.host(), endpoint.path(), bytes, -1, -1, now.millis, now.nano, endpoint.source));
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
        events.add(new Event(CIRCUIT, endpoint.host(), "", -1, host.failures.size(), -1, now.millis, now.nano, endpoint.source));
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
        events.add(new Event(FANOUT, endpoint.host(), "", -1, -1, distinct, now.millis, now.nano, endpoint.source));
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

    private void reopen(Host host, Protection circuit, Time now, String source) {
        circuit.probe = null;
        circuit.until = now.nano + millis(circuit.openMillis);
        circuit.expiresAt = add(now.millis, circuit.openMillis);
        host.failures.clear();
        events.add(new Event(CIRCUIT, circuit.displayHost, "", -1, 1, -1, now.millis, now.nano, source));
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
            if (now.nano - flight.started < flight.timeout || !expiredFlights.add(entry.getKey())) continue;
            // Timeout fails a half-open lease ONCE, not its later native observation. Host/path
            // reservations and the endpoint stay bounded by MAX_FLIGHTS until
            // observe/cancel/reset. A late success can never heal the failed/replacement probe.
            timedOut = increment(timedOut);
            failProbe(entry.getKey(), flight, now);
        }
        for (Protection protection : List.copyOf(protections.values())) {
            // An elapsed circuit enters half-open eligibility, NOT an unprotected/evictable state.
            if (!protection.reason.equals(CIRCUIT) && reached(now.nano, protection.until)) remove(protection);
        }
        if (capacityProtection != null && reached(now.nano, capacityProtection.until)) capacityProtection = null;
        if (omissionActive && reached(now.nano, omissionUntil)) omissionActive = false;
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
    }

    private void failProbe(Ticket ticket, Flight flight, Time now) {
        if (flight.probeCircuit != null && flight.host.circuit == flight.probeCircuit
                && flight.probeCircuit.probe == ticket) reopen(flight.host, flight.probeCircuit, now, flight.endpoint.source);
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

    private int indexedSeen() {
        int count = 0;
        for (Host host : hosts.values()) count += host.seen.size();
        return count;
    }

    private static void pruneSeen(Host host, Time now) {
        host.seen.values().removeIf(seen -> !seen.active(now.nano));
    }

    private static void retain(PathState state, long now, long durationMillis) {
        long until = now + millis(durationMillis);
        if (!state.retained || remaining(until, now) > remaining(state.until, now)) state.until = until;
        state.retained = true;
    }

    /** Current exact exception membership; evaluated at check AND final commit, never at response time. */
    private boolean circuitExcluded(Endpoint endpoint) {
        return endpoint.owner == identity && endpoint.epoch == epoch && endpoint.routeKey != null
                && circuitExceptions.contains(endpoint.routeKey);
    }

    private boolean fanoutExcluded(Endpoint endpoint) {
        return endpoint.owner == identity && endpoint.epoch == epoch && endpoint.routeKey != null
                && fanoutExceptions.contains(endpoint.routeKey);
    }
    /** An AUTHORED zero for a matching route view (and no positive alias override) is a size exception. */
    private boolean heavyExcepted(Endpoint endpoint) {
        Long matched = authoredBound(endpoint);
        return matched != null && matched == 0;
    }
    /** Fan-out logical episode detach for configuration changes: never clears Seen history. */
    private void detachFanout(Host host) {
        Protection episode = host.episode;
        host.episode = null;
        if (episode != null) protections.remove(episode.id, episode);
    }

    private void compilePathLimits() {
        circuitExceptions.clear();
        fanoutExceptions.clear();
        for (GuardConfig.ProbePath route : limits.fanoutExceptions())
            fanoutExceptions.add(hash("path", service(route.scheme(), route.host(), route.port()), route.path()));
        for (GuardConfig.ProbePath route : limits.circuit5xxExceptions())
            circuitExceptions.add(hash("path", service(route.scheme(), route.host(), route.port()), route.path()));
        pathLimits.clear();
        for (GuardConfig.PathByteLimit limit : limits.heavyPathLimits()) {
            String service = service(limit.scheme(), limit.host(), limit.port());
            pathLimits.put(hash("path", service, limit.path()), limit.maxBytes());
        }
    }

    private long responseBound(Endpoint endpoint) {
        Long matched = authoredBound(endpoint);
        return matched == null ? limits.perPathMaxResponseBytes() : matched;
    }
    private Long authoredBound(Endpoint endpoint) {
        Long matched = null;
        for (String path : endpoint.pathKeys()) {
            Long value = pathLimits.get(path);
            if (value != null) {
                // Multiple routing aliases cannot use a more permissive authored override to evade
                // another explicit nonzero bound. A sole zero override disables the default.
                if (matched == null || matched == 0 || value > 0 && value < matched) matched = value;
            }
        }
        return matched;
    }

    private void rememberCandidate(Endpoint endpoint) {
        candidateIndex.putIfAbsent(endpoint.pathKeys().getLast(), new CandidateMeta());
    }

    private Map<String, Aggregate> aggregate(long from, long to, boolean candidatesOnly) {
        Map<String, Aggregate> out = new HashMap<>();
        for (Observation observation : observations) {
            if (!candidatesOnly && (observation.ts < from || observation.ts >= to)) continue;
            if (candidatesOnly) {
                CandidateMeta meta = candidateIndex.get(observation.id);
                if (meta == null || meta.ignored) continue;
            }
            out.computeIfAbsent(observation.id, ignored -> new Aggregate(observation)).add(observation);
        }
        return out;
    }

    private boolean complete(long from, long to, Time now) {
        return !clockRegressed && from >= startedAt && to <= add(now.millis, 1);
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
    private record Observation(String id, String hostKey, List<String> pathKeys, String host, String path,
                               String policyUrl, int status, long bytes, long ts, long nano, String source) {}
    private record Event(String kind, String host, String path, long bytes, long count5xx,
                         long distinctPaths, long ts, long nano, String source) {
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
    private static final class Host {
        final ArrayDeque<Long> failures = new ArrayDeque<>();
        final Map<String, Seen> seen = new HashMap<>();
        int inFlight;
        long failureRetention;
        boolean hasProbeAttempt;
        long lastProbeAttempt;
        Protection circuit;
        Protection episode;
    }
    private static final class PathState {
        int inFlight;
        boolean retained;
        long until;
    }
    private static final class CandidateMeta { boolean ignored; }
    private record Flight(Endpoint endpoint, Host host, boolean healthProbe, Protection probeCircuit,
                          long started, long timeout, Seen seen, Mark mark,
                          boolean circuitExcluded, long circuitGeneration,
                          boolean heavyEligible, long heavyGeneration) {}
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
        final String source; // triggering request's opaque human-original reference (null: capacity fence)
        Protection(String reason, Endpoint endpoint, Time now, long duration) {
            this.reason = reason;
            source = endpoint == null ? null : endpoint.source;
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
