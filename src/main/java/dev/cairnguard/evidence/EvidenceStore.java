package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.DenialReasons;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.model.RequestData.Header;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Thread-safe ORIGINAL evidence rows plus their structured byte captures. No masking and no collection,
 * retention or export quota: memory grows until clear(), a project/epoch change or unload. No native objects.
 */
public final class EvidenceStore {
    private static final Set<String> OUTCOMES = Set.of("pending", "forwarded", "blocked", "exempt", "probe_allowed", "half_open");
    private static final Set<String> GUARD_STATES = Set.of("PROTECTED", "PAUSED_BY_OPERATOR", "POLICY_INVALID",
            "POLICY_SAVE_UNCERTAIN", "PROJECT_UNVERIFIED", "SHUTDOWN", "CIRCUIT_OPEN", "OVERLAY_BLOCK",
            "INTENT_BUDGET", "LISTENER_UNVERIFIED", "CAPACITY", "IN_FLIGHT_STALLED");
    private static final Set<String> DISPOSITIONS = Set.of("PENDING", "QUEUED", "AWAITING_APPROVAL", "FORWARDED",
            "BLOCKED", "STALLED", "CANCELLED", "ERROR");
    private static final Set<String> REASONS = Set.of("ALLOW", "BLOCK", "MONITOR", "ASK", "DEFAULT", "DEFAULT_ALLOW",
            "DEFAULT_BLOCK", "RULE_ALLOW", "RULE_BLOCK", "RULE_ASK", "RULE_MONITOR", "POLICY_ALLOW", "POLICY_BLOCK",
            "POLICY_DECISION", "DEFAULT_MONITOR", "DEFAULT_ASK", "SCOPE_BLOCK", "SCOPE_BLOCKED", "SCOPE_NOT_ALLOWED", "SCOPE_MISMATCH", "OUT_OF_SCOPE", "EMPTY_ALLOWLIST", "NOT_ALLOWLISTED",
            "BLOCKLISTED", "INSPECTION_BLOCK", "INSPECTION_ERROR", "MALFORMED_REQUEST", "UNSUPPORTED_BODY",
            "UNSUPPORTED_ENCODING", "UNSUPPORTED_WEBSOCKET", "QUEUE_TIMEOUT", "APPROVAL_TIMEOUT", "REQUEST_TIMEOUT",
            "CAPACITY_EXHAUSTED", "QUEUE_FULL", "SHUTDOWN", "PROJECT_CHANGED", "POLICY_CHANGED", "REVISION_CHANGED",
            "APPROVED", "DENIED", "REJECTED", "FORWARDED_NATIVE", "NATIVE_RELEASED", "LOCAL_BLOCK", "LOCAL_BLOCKED",
            "RESPONSE_CAPTURED", "QUARANTINED", "CANCELLED", "OUTCOME_RECORDED", "UNSPECIFIED",
            "INVALID_CONFIG", "INVALID_REQUEST", "INVALID_METHOD", "INVALID_URI", "UNSUPPORTED_SCHEME", "AUTHORITY_MISMATCH",
            "INVALID_AUTHORITY", "INVALID_HOST", "INVALID_HEADERS", "REQUEST_TOO_LARGE", "WEBSOCKET_UNSUPPORTED",
            "UNSUPPORTED_CONTENT_ENCODING", "UNSUPPORTED_TRANSFER_ENCODING", "AMBIGUOUS_PATH", "INVALID_TEXT_ENCODING",
            "INVALID_CONTENT_LENGTH", "MALFORMED_CONTENT_TYPE", "UNSUPPORTED_CHARSET", "INSPECTION_LIMIT", "MALFORMED_JSON",
            "AMBIGUOUS_JSON_KEYS", "ENCODING_DEPTH_EXCEEDED", "MALFORMED_PERCENT_ENCODING",
            "EXEMPT", "RULE_EXEMPT", "PROBE_ALLOWED", "HALF_OPEN", "HEAVY_ENDPOINT_AUTO_BLOCKED", "CIRCUIT_OPEN",
            "FANOUT_SUSPECTED", "INTENT_BUDGET_EXCEEDED", "INTENT_INVALID", "INTENT_CAPACITY", "WATCHER_CAPACITY",
            "LISTENER_UNVERIFIED", "CAPTURE_INCOMPLETE", "INTENT_BUDGET_CAPACITY", "INVALID_INTENT_TAG", "RESPONSE_WATCHER_CAPACITY");


    private final byte[] exportKey = new byte[32];
    private final LinkedHashMap<String, Stored> entries = new LinkedHashMap<>();
    private final RawTrafficStore rawUi = new RawTrafficStore();
    private final Map<String, Long> reasonCounters = new LinkedHashMap<>();
    private String project;
    private long retainedBytes; // informational estimate, never an admission/eviction/export gate
    private long rawGeneration;
    private long begun;
    private long forwarded;
    private long blocked;
    private long responses;
    private long localResponses;
    private long upstreamResponses;
    private long truncations;
    private long clears;
    private long clearedEntries;
    private long orphanUpdates;
    private long outcomeCallbacks;
    private long responseCallbacks;
    private long orphanOutcomes;
    private long orphanResponses;

    private static final class Stored {
        TrafficEntry entry;
        long bytes;
        boolean countedForward;
        boolean countedBlock;
        boolean countedResponse;
        boolean responseLocal;
        boolean countedTruncation;
        String countedReason;
        Stored(TrafficEntry entry) { this.entry = entry; }
    }

    public EvidenceStore() {
        REASONS.stream().sorted().forEach(key -> reasonCounters.put(key, 0L));
        DenialReasons.ALL.stream().sorted().forEach(key -> reasonCounters.putIfAbsent(key, 0L));
        new SecureRandom().nextBytes(exportKey);
    }

    public synchronized String begin(String projectId, String projectName, RequestData request, Decision decision, long revision) {
        if (request == null || decision == null || decision.mode() == null) throw new IllegalArgumentException("INVALID_EVIDENCE_INPUT");
        // One project's originals never share a store with another project's.
        if (project != null && !project.equals(projectId)) discard();
        project = projectId;
        RequestAttribution attribution = RequestAttribution.parse(request.headers());
        List<String> warnings = new ArrayList<>();
        if (!request.headersComplete()) warnings.add("HEADERS_INCOMPLETE");
        if (!request.bodyComplete()) warnings.add("BODY_INCOMPLETE");
        warnings.addAll(decision.inspectionWarnings());
        warnings = warnings.stream().distinct().toList();
        String id = UUID.randomUUID().toString();
        // Decision reasons stay categorical; hits/warnings/metadata are the supplied originals.
        RawTrafficStore.Capture capture = rawUi.begin(projectId, projectName, id, request, attribution, warnings, decision.hits());
        TrafficEntry.Message message = RawTrafficStore.message(capture.request);
        TrafficEntry entry = new TrafficEntry(id, Objects.toString(projectId, ""), Objects.toString(projectName, ""),
                Instant.now().toString(), capture.method, capture.url, decision.mode().name(), "PENDING",
                reason(decision.reason(), "POLICY_DECISION"), null, decision.hits(), revision, false, message,
                TrafficEntry.Message.EMPTY, message.truncated(), "", attribution.intentId(), attribution.runId(),
                "pending", "", "", -1, warnings);
        Stored stored = new Stored(seal(entry));
        entries.put(id, stored);
        begun++;
        update(stored);
        return id;
    }

    public synchronized void outcome(String id, String disposition, String reason, Integer statusCode) {
        outcomeCallbacks++;
        Stored stored = find(id);
        if (stored == null) { orphanOutcomes++; return; }
        String next = category(disposition);
        if (!DISPOSITIONS.contains(next)) next = "ERROR";
        // A native release and a local block are mutually exclusive terminal facts.
        String previous = stored.entry.disposition();
        if (previous.equals("BLOCKED") && !next.equals("BLOCKED")) return;
        if (stored.countedForward && (next.equals("BLOCKED") || next.equals("PENDING") || next.equals("QUEUED") || next.equals("AWAITING_APPROVAL"))) return;
        if (next.equals("FORWARDED") && !stored.countedForward) { forwarded++; stored.countedForward = true; }
        if (next.equals("BLOCKED") && !stored.countedBlock) { blocked++; stored.countedBlock = true; }
        TrafficEntry old = stored.entry;
        String outcome = next.equals("BLOCKED") ? "blocked" : next.equals("FORWARDED")
                ? Set.of("exempt", "probe_allowed", "half_open").contains(old.outcome()) ? old.outcome() : "forwarded"
                : old.outcome();
        old = contextCopy(old, outcome, old.guardState(), old.overlayId(), old.responseBytes());
        stored.entry = copy(old, next, reason(reason, "OUTCOME_RECORDED"), validStatus(statusCode) == null ? old.statusCode() : validStatus(statusCode),
                old.bookmarked(), old.requestCapture(), old.responseCapture(), old.truncated());
        if (stored.countedResponse && !stored.responseLocal && next.equals("BLOCKED")) {
            upstreamResponses--;
            localResponses++;
            stored.responseLocal = true;
        }
        update(stored);
    }

    public synchronized void response(String id, int statusCode, List<Header> headers, byte[] body) {
        response(id, statusCode, headers, body, true, true);
    }

    /** Completeness refers to the supplied inspection copy, not a claim of exact wire capture. */
    public synchronized void response(String id, int statusCode, List<Header> headers, byte[] body,
                                      boolean headersComplete, boolean bodyComplete) {
        responseCallbacks++;
        Stored stored = find(id);
        if (stored == null) { orphanResponses++; return; }
        if (headers == null || body == null) throw new IllegalArgumentException("INVALID_EVIDENCE_INPUT");
        RawTrafficStore.Part part = rawUi.response(id, statusCode, headers, body, headersComplete, bodyComplete);
        TrafficEntry old = stored.entry;
        // A complete supplied copy is the native body length whatever its size; no inspection-size cutoff.
        if (bodyComplete && old.responseBytes() < 0)
            old = contextCopy(old, old.outcome(), old.guardState(), old.overlayId(), body.length);
        TrafficEntry.Message response = part == null ? TrafficEntry.Message.EMPTY : RawTrafficStore.message(part);
        stored.entry = copy(old, old.disposition(), old.reason(), validStatus(statusCode), old.bookmarked(), old.requestCapture(),
                response, old.requestCapture().truncated() || response.truncated());
        if (!stored.countedResponse) {
            responses++;
            stored.countedResponse = true;
            stored.responseLocal = old.disposition().equals("BLOCKED");
            if (stored.responseLocal) localResponses++; else upstreamResponses++;
        }
        update(stored);
    }

    /** Add fixed runtime context only; arbitrary caller strings cannot become export metadata. */
    public synchronized void context(String id, String outcome, String guardState, String overlayId) {
        Stored stored = find(id);
        if (stored == null) return;
        TrafficEntry old = stored.entry;
        String nextOutcome = OUTCOMES.contains(outcome == null ? "" : outcome) ? outcome : old.outcome();
        if (old.disposition().equals("BLOCKED")) nextOutcome = "blocked";
        if (stored.countedForward && (nextOutcome.equals("blocked") || nextOutcome.equals("pending"))) nextOutcome = old.outcome();
        String nextGuard = GUARD_STATES.contains(guardState == null ? "" : guardState) ? guardState : "";
        String nextOverlay = overlayId != null && uuid(overlayId) ? overlayId : "";
        TrafficEntry contextual = contextCopy(old, nextOutcome, nextGuard, nextOverlay, old.responseBytes());
        stored.entry = copy(contextual, old.disposition(), old.reason(), old.statusCode(), old.bookmarked(),
                old.requestCapture(), old.responseCapture(), old.truncated());
        update(stored);
    }

    /** Actual native body length is independent of optional content capture/slots; -1 means unknown. */
    public synchronized void responseBytes(String id, long bytes) {
        Stored stored = find(id);
        if (stored == null) return;
        TrafficEntry old = stored.entry;
        TrafficEntry measured = contextCopy(old, old.outcome(), old.guardState(), old.overlayId(), Math.max(-1, bytes));
        stored.entry = copy(measured, old.disposition(), old.reason(), old.statusCode(), old.bookmarked(),
                old.requestCapture(), old.responseCapture(), old.truncated());
        update(stored);
    }

    /** Immutable original row lookup for runtime projections. */
    public synchronized TrafficEntry entry(String id) {
        Stored stored = entries.get(id);
        return stored == null ? null : stored.entry;
    }

    /** Human UI text/byte views of the same retained originals. */
    public synchronized String rawRequest(String id) { return rawUi.request(id); }
    public synchronized String rawResponse(String id) { return rawUi.response(id); }
    public synchronized String rawUrl(String id) { return rawUi.url(id); }
    public synchronized Map<String, Object> rawCaptureInfo(String id) { return rawUi.info(id); }
    /** Changes whenever retained human originals are cleared; snapshots/tokens from earlier are stale. */
    public synchronized long rawGeneration() { return rawGeneration; }
    /** Binds an opaque watcher source reference to this request's retained original (released with it). */
    public synchronized void bindRawSource(String id, String source) { rawUi.bindSource(id, source); }

    /** Original actual-service route of a retained capture, resolved ONLY by its opaque source reference. */
    public record HumanRoute(String evidenceId, String scheme, String host, int port, String rawTarget, String exactPath) {}
    public synchronized HumanRoute humanRoute(String source) {
        RawTrafficStore.Capture c = rawUi.bySource(source);
        if (c == null || c.route == null) return null;
        RawTrafficStore.Route r = c.route;
        return new HumanRoute(rawUi.sourceId(source), r.scheme(), r.host(), r.port(), r.rawTarget(), r.exactPath());
    }
    /** True when the source reference still resolves to a retained original. */
    public synchronized boolean rawSourceRetained(String source) { return rawUi.bySource(source) != null; }
    /**
     * Final-checkpoint availability of the originals a frozen human snapshot actually USED (memory only; the
     * snapshot itself shares immutable parts, so later updates never enter it). Originals absent at snapshot
     * time were never recorded and cannot cancel it; unrelated clears of other rows are ignored.
     */
    public synchronized boolean humanOriginalsRetained(HumanEvidence snapshot, java.util.Collection<String> usedSources) {
        if (snapshot != null) for (HumanEvidence.Item item : snapshot.items)
            if (item.raw() != null && !rawUi.retained(item.entry().id(), item.raw().capture())) return false;
        if (usedSources != null) for (String source : usedSources) if (rawUi.bySource(source) == null) return false;
        return true;
    }

    /**
     * Point-in-time human snapshot for an EXPLICITLY CONSENTED original export. Shares the raw store's
     * immutable parts (no duplicate payload); categorical metadata comes from the current row.
     */
    public synchronized HumanEvidence humanEvidence(List<String> ids) {
        if (ids == null) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
        List<HumanEvidence.Item> items = new ArrayList<>();
        for (String id : List.copyOf(ids)) {
            Stored stored = entries.get(id);
            if (stored == null) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            items.add(new HumanEvidence.Item(stored.entry, rawUi.view(id)));
        }
        return new HumanEvidence(List.copyOf(items));
    }

    public synchronized void bookmark(String id, boolean value) {
        Stored stored = find(id);
        if (stored == null) return;
        TrafficEntry old = stored.entry;
        stored.entry = copy(old, old.disposition(), old.reason(), old.statusCode(), value, old.requestCapture(),
                old.responseCapture(), old.truncated());
        update(stored);
    }

    /** Newest first. Both the list and its entries/nested collections are immutable. */
    public synchronized List<TrafficEntry> snapshot() {
        List<TrafficEntry> result = new ArrayList<>(entries.size());
        for (Stored stored : entries.values()) result.add(stored.entry);
        Collections.reverse(result);
        return List.copyOf(result);
    }

    /** Releases every retained original (rows, byte captures, source references), not cumulative run counters. */
    public synchronized void clear() {
        clearedEntries += entries.size();
        discard();
        clears++;
    }
    private void discard() {
        entries.clear();
        rawUi.clear();
        rawGeneration++;
        retainedBytes = 0;
        project = null;
    }

    public synchronized Map<String, Object> stats() {
        long bookmarks = entries.values().stream().filter(s -> s.entry.bookmarked()).count();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("begun", begun);
        result.put("forwarded", forwarded);
        result.put("blocked", blocked);
        result.put("responses", responses);
        result.put("localResponses", localResponses);
        result.put("upstreamResponses", upstreamResponses);
        result.put("evictions", 0L); // compatibility: there is no quota-based eviction
        result.put("truncations", truncations);
        result.put("retainedEntries", (long) entries.size());
        result.put("retainedBytes", retainedBytes);
        result.put("bookmarked", bookmarks);
        result.put("clears", clears);
        result.put("clearedEntries", clearedEntries);
        result.put("orphanUpdates", orphanUpdates);
        result.put("outcomeCallbacks", outcomeCallbacks);
        result.put("responseCallbacks", responseCallbacks);
        result.put("orphanOutcomes", orphanOutcomes);
        result.put("orphanResponses", orphanResponses);
        result.put("reasonCounters", Collections.unmodifiableMap(new LinkedHashMap<>(reasonCounters)));
        result.put("rawRetainedEntries", (long) rawUi.size());
        result.put("rawRetainedBytes", rawUi.retainedBytes());
        return Collections.unmodifiableMap(result);
    }

    public String exportJson(List<TrafficEntry> selection) {
        List<TrafficEntry> safe = verified(selection);
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("schemaVersion", 2);
        document.put("_cairnGuard", provenance());
        document.put("entries", safe.stream().map(EvidenceStore::entryMap).toList());
        return json(document);
    }

    /** HAR 1.2 schema fields with explicit unknown timings and original callback-copy provenance. */
    public String exportHar(List<TrafficEntry> selection) {
        List<TrafficEntry> safe = verified(selection);
        List<Map<String, Object>> harEntries = new ArrayList<>();
        for (TrafficEntry e : safe) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", e.method());
            // Same faithful-URL/raw-route rule as the human HAR; the untouched native target is never normalized.
            RawTrafficStore.View raw = rawView(e.id());
            String urlProblem = raw == null ? "ORIGINAL_ROUTE_NOT_RETAINED" : HumanEvidence.urlProblem(raw.capture());
            request.put("url", urlProblem == null ? e.url() : "");
            if (raw != null && raw.capture().route != null) {
                RawTrafficStore.Route route = raw.capture().route;
                request.put("_rawTarget", route.rawTarget());
                request.put("_service", Map.of("scheme", route.scheme(), "host", route.host(), "port", route.port()));
            }
            if (urlProblem != null) {
                request.put("_urlUnavailable", urlProblem);
                request.put("_displayUrl", e.url()); // retained display text only, not a claim about the HTTP target
            }
            request.put("httpVersion", "HTTP/1.1");
            request.put("cookies", List.of());
            request.put("headers", headerMaps(e.requestCapture().headers()));
            request.put("queryString", urlProblem == null ? queryMaps(e.url()) : List.of());
            request.put("headersSize", -1);
            request.put("bodySize", -1);
            if (!e.requestCapture().body().isEmpty()) {
                Map<String, Object> post = new LinkedHashMap<>();
                post.put("mimeType", e.requestCapture().mimeType());
                if (e.requestCapture().bodyEncoding().equals("HEX")) {
                    post.put("text", "");
                    post.put("_bodyBase64", Base64.getEncoder().encodeToString(bodyBytes(e.requestCapture())));
                    post.put("_encoding", "base64");
                } else post.put("text", e.requestCapture().body());
                request.put("postData", post);
            }
            Map<String, Object> response = new LinkedHashMap<>();
            boolean absent = !e.responseCapture().present();
            response.put("status", e.statusCode() == null ? 0 : e.statusCode());
            response.put("statusText", "");
            response.put("httpVersion", "HTTP/1.1");
            response.put("cookies", List.of());
            response.put("headers", headerMaps(e.responseCapture().headers()));
            Map<String, Object> content = new LinkedHashMap<>();
            byte[] responseBody = bodyBytes(e.responseCapture());
            content.put("size", responseBody.length);
            content.put("mimeType", e.responseCapture().mimeType().isEmpty() ? "application/octet-stream" : e.responseCapture().mimeType());
            if (e.responseCapture().bodyEncoding().equals("HEX")) {
                content.put("text", Base64.getEncoder().encodeToString(responseBody));
                content.put("encoding", "base64");
            } else content.put("text", e.responseCapture().body());
            content.put("_bodyEncoding", e.responseCapture().bodyEncoding());
            response.put("content", content);
            // Redirect header values are never interpreted as evidence of an actual subsequent request.
            response.put("redirectURL", "");
            response.put("headersSize", -1);
            response.put("bodySize", -1);
            Map<String, Object> details = provenance();
            details.put("evidenceId", e.id());
            details.put("projectId", e.projectId());
            details.put("projectName", e.projectName());
            details.put("revision", e.revision());
            details.put("mode", e.mode());
            details.put("disposition", e.disposition());
            details.put("reason", e.reason());
            details.put("intentId", e.intentId());
            details.put("runId", e.runId());
            details.put("outcome", e.outcome());
            details.put("guardState", e.guardState());
            details.put("overlayId", e.overlayId());
            details.put("responseBytes", e.responseBytes());
            details.put("inspectionWarnings", e.inspectionWarnings());
            details.put("hits", e.hits());
            details.put("bookmarked", e.bookmarked());
            details.put("truncated", e.truncated());
            details.put("requestBodyOmitted", e.requestCapture().bodyOmitted());
            details.put("responseBodyOmitted", e.responseCapture().bodyOmitted());
            details.put("responseObserved", !absent);
            details.put("responseSource", absent ? "NOT_OBSERVED" : e.disposition().equals("BLOCKED") ? "LOCAL_BLOCK" : "RESPONSE_CALLBACK");
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("startedDateTime", e.timestamp());
            entry.put("time", 0);
            entry.put("request", request);
            entry.put("response", response);
            entry.put("cache", Map.of());
            entry.put("timings", Map.of("send", 0, "wait", 0, "receive", 0));
            entry.put("_cairnGuard", details);
            harEntries.add(entry);
        }
        Map<String, Object> log = new LinkedHashMap<>();
        log.put("version", "1.2");
        log.put("creator", Map.of("name", "Cairn Proxy Guard", "version", "0.1"));
        log.put("pages", List.of());
        log.put("entries", harEntries);
        log.put("_cairnGuard", provenance());
        return json(Map.of("log", log));
    }

    private synchronized RawTrafficStore.View rawView(String id) { return rawUi.view(id); }

    private Stored find(String id) {
        Stored result = entries.get(id);
        if (result == null) orphanUpdates++;
        return result;
    }
    private void update(Stored stored) {
        if (!stored.entry.reason().equals(stored.countedReason)) {
            reasonCounters.computeIfPresent(stored.entry.reason(), (key, count) -> count + 1);
            stored.countedReason = stored.entry.reason();
        }
        if (stored.entry.truncated() && !stored.countedTruncation) { truncations++; stored.countedTruncation = true; }
        retainedBytes -= stored.bytes;
        stored.bytes = estimatedBytes(stored.entry);
        retainedBytes += stored.bytes;
    }
    private static Integer validStatus(Integer status) { return status != null && status >= 100 && status <= 599 ? status : null; }
    private static String category(String text) { return text == null || text.length() > 64 ? "" : text.toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_'); }
    private static String reason(String text, String fallback) {
        String candidate = category(text);
        return REASONS.contains(candidate) || DenialReasons.ALL.contains(candidate) ? candidate : fallback;
    }

    private TrafficEntry copy(TrafficEntry old, String disposition, String reason, Integer status, boolean bookmark,
                              TrafficEntry.Message request, TrafficEntry.Message response, boolean truncated) {
        return seal(new TrafficEntry(old.id(), old.projectId(), old.projectName(), old.timestamp(), old.method(), old.url(),
                old.mode(), disposition, reason, status, old.hits(), old.revision(), bookmark, request, response, truncated, "",
                old.intentId(), old.runId(), old.outcome(), old.guardState(), old.overlayId(), old.responseBytes(),
                old.inspectionWarnings()));
    }
    private static TrafficEntry contextCopy(TrafficEntry e, String outcome, String state, String overlay, long bytes) {
        return new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(),
                e.responseCapture(), e.truncated(), "", e.intentId(), e.runId(), outcome, state, overlay, bytes, e.inspectionWarnings());
    }
    private static boolean uuid(String value) {
        if (value.length() != 36) return false;
        try { return UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException ignored) { return false; }
    }
    private static long estimatedBytes(TrafficEntry e) {
        // A conservative UTF-16/UTF-8 text estimate plus per-object overhead, not a JVM heap profiler.
        long bytes = 2048;
        for (String text : List.of(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(), e.disposition(), e.reason(), e.provenanceSeal())) bytes += textCost(text);
        for (String text : List.of(e.intentId(), e.runId(), e.outcome(), e.guardState(), e.overlayId())) bytes += textCost(text);
        for (String warning : e.inspectionWarnings()) bytes += textCost(warning);
        for (Decision.RuleHit h : e.hits()) bytes += 128 + textCost(h.id()) + textCost(h.name());
        for (TrafficEntry.Message m : List.of(e.requestCapture(), e.responseCapture())) {
            bytes += 128 + textCost(m.body()) + textCost(m.mimeType());
            for (Header h : m.headers()) bytes += 128 + textCost(h.name()) + textCost(h.value());
        }
        return bytes;
    }
    private static long textCost(String value) { return 48L + 2L * value.length(); }
    /** The supplied bytes of a projection: HEX is decoded losslessly, text is its UTF-8 encoding. */
    private static byte[] bodyBytes(TrafficEntry.Message m) {
        return m.bodyEncoding().equals("HEX") ? java.util.HexFormat.of().parseHex(m.body()) : m.body().getBytes(StandardCharsets.UTF_8);
    }

    private TrafficEntry seal(TrafficEntry e) {
        return new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(), e.disposition(),
                e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), signature(e),
                e.intentId(), e.runId(), e.outcome(), e.guardState(), e.overlayId(), e.responseBytes(), e.inspectionWarnings());
    }
    private String signature(TrafficEntry e) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(exportKey, "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal(json(entryMap(e)).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException ignored) { throw new IllegalStateException("EVIDENCE_CRYPTO_UNAVAILABLE"); }
    }
    private synchronized List<TrafficEntry> verified(List<TrafficEntry> selection) {
        if (selection == null) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
        List<TrafficEntry> copy = List.copyOf(selection);
        List<TrafficEntry> result = new ArrayList<>(copy.size());
        for (TrafficEntry entry : copy) {
            if (!MessageDigest.isEqual(signature(entry).getBytes(StandardCharsets.US_ASCII),
                    entry.provenanceSeal().getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            // Only currently retained rows of this store export; a cleared row's originals are gone.
            Stored current = entries.get(entry.id());
            if (current == null) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            result.add(current.entry);
        }
        return List.copyOf(result);
    }
    private static Map<String, Object> entryMap(TrafficEntry e) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", e.id());
        result.put("projectId", e.projectId());
        result.put("projectName", e.projectName());
        result.put("timestamp", e.timestamp());
        result.put("method", e.method());
        result.put("url", e.url());
        result.put("mode", e.mode());
        result.put("disposition", e.disposition());
        result.put("reason", e.reason());
        result.put("intentId", e.intentId());
        result.put("runId", e.runId());
        result.put("outcome", e.outcome());
        result.put("guardState", e.guardState());
        result.put("overlayId", e.overlayId());
        result.put("responseBytes", e.responseBytes());
        result.put("inspectionWarnings", e.inspectionWarnings());
        result.put("statusCode", e.statusCode());
        result.put("hits", e.hits());
        result.put("revision", e.revision());
        result.put("bookmarked", e.bookmarked());
        result.put("request", e.request());
        result.put("response", e.response());
        result.put("requestCapture", e.requestCapture());
        result.put("responseCapture", e.responseCapture());
        result.put("truncated", e.truncated());
        result.put("_cairnGuard", provenance());
        return result;
    }
    private static Map<String, Object> provenance() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 2);
        result.put("label", "ORIGINAL_EVIDENCE_NOT_WIRE_CAPTURE");
        result.put("source", "BURP_PROXY_CALLBACK_COPY");
        result.put("completeWireCapture", false);
        result.put("forwardedMeans", "NATIVE_RELEASE_NOT_PROVEN_DELIVERY");
        result.put("timingsKnown", false);
        result.put("omissionPolicy", "ONLY_UNAVAILABLE_NATIVE_COPIES_OMITTED; NON_TEXT_BODIES_ARE_HEX");
        result.put("warning", HUMAN_WARNING);
        return result;
    }
    private static List<Map<String, String>> headerMaps(List<Header> headers) {
        return headers.stream().map(h -> Map.of("name", h.name(), "value", h.value())).toList();
    }
    private static List<Map<String, String>> queryMaps(String url) {
        int query = url.indexOf('?');
        if (query < 0 || query + 1 == url.length()) return List.of();
        List<Map<String, String>> result = new ArrayList<>();
        for (int start = query + 1; start < url.length();) {
            int end = url.indexOf('&', start);
            if (end < 0) end = url.length();
            String pair = url.substring(start, end);
            int equals = pair.indexOf('=');
            // Original percent-encoded spellings. Do not re-decode them.
            result.add(Map.of("name", equals < 0 ? pair : pair.substring(0, equals), "value", equals < 0 ? "" : pair.substring(equals + 1)));
            start = end + 1;
        }
        return result;
    }
    private static String json(Object value) {
        try { return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value); }
        catch (Exception ignored) { throw new IllegalArgumentException("EVIDENCE_SERIALIZATION_FAILED"); }
    }

    public static final String HUMAN_WARNING = "PLAINTEXT_ORIGINALS: may contain Authorization, Cookie, tokens and other secrets; supplied callback copy, NOT wire proof";

    /** Ordinary UTF-8 JSON bytes; no output quota. A serialization failure publishes nothing. */
    public static byte[] jsonBytes(Object document) {
        try { return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(document); }
        catch (Exception e) { throw new IllegalStateException("HUMAN_EXPORT_FAILED"); }
    }

    /**
     * Explicitly consented HUMAN original export snapshot (distinct format from schema-2 JSON/HAR, which also
     * carry originals). Contains originals where retained, categorical unavailability otherwise; never
     * enforcement keys or admission tokens.
     */
    public static final class HumanEvidence {
        record Item(TrafficEntry entry, RawTrafficStore.View raw) {}
        private final List<Item> items;
        private HumanEvidence(List<Item> items) { this.items = items; }
        public int size() { return items.size(); }
        @Override public String toString() { return "HumanEvidence[" + items.size() + "]"; }

        public byte[] json(Map<String, Object> snapshot) {
            Map<String, Object> document = new LinkedHashMap<>();
            document.put("format", "cairn-human-inspection");
            document.put("formatVersion", 1);
            document.put("_cairnGuard", humanProvenance(snapshot));
            List<Map<String, Object>> list = new ArrayList<>();
            for (Item item : items) {
                TrafficEntry e = item.entry();
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("evidenceId", e.id());
                entry.put("timestamp", e.timestamp());
                entry.put("mode", e.mode());
                entry.put("disposition", e.disposition());
                entry.put("reason", e.reason());
                entry.put("statusCode", e.statusCode());
                entry.put("revision", e.revision());
                entry.put("outcome", e.outcome());
                entry.put("guardState", e.guardState());
                entry.put("overlayId", e.overlayId());
                entry.put("nativeResponseBodyBytes", e.responseBytes());
                entry.put("inspectionWarnings", e.inspectionWarnings());
                entry.put("bookmarked", e.bookmarked());
                if (item.raw() == null) {
                    entry.put("original", null);
                    entry.put("originalUnavailable", "NOT_RETAINED_CLEARED_OR_NOT_CAPTURED");
                } else entry.put("original", original(item.raw()));
                list.add(entry);
            }
            document.put("entries", list);
            return jsonBytes(document);
        }

        public byte[] har(Map<String, Object> snapshot) {
            List<Map<String, Object>> harEntries = new ArrayList<>();
            for (Item item : items) {
                TrafficEntry e = item.entry();
                RawTrafficStore.View raw = item.raw();
                Map<String, Object> request = new LinkedHashMap<>();
                Map<String, Object> response = new LinkedHashMap<>();
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("exportMode", "HUMAN_ORIGINAL");
                details.put("evidenceId", e.id());
                details.put("mode", e.mode());
                details.put("disposition", e.disposition());
                details.put("reason", e.reason());
                details.put("revision", e.revision());
                details.put("outcome", e.outcome());
                details.put("guardState", e.guardState());
                details.put("nativeResponseBodyBytes", e.responseBytes());
                details.put("inspectionWarnings", e.inspectionWarnings());
                details.put("inspectionCopyNotWire", true);
                if (raw == null) {
                    request.put("method", "");
                    request.put("url", "");
                    request.put("_unavailable", "ORIGINAL_NOT_RETAINED");
                    request.put("headers", List.of());
                    details.put("originalAvailable", false);
                } else {
                    RawTrafficStore.Capture c = raw.capture();
                    details.put("originalAvailable", true);
                    details.put("projectId", c.projectId);
                    details.put("projectName", c.projectName);
                    details.put("hits", hitMaps(c.hits));
                    details.put("intentId", c.intent);
                    details.put("runId", c.run);
                    request.put("method", c.method);
                    String urlProblem = urlProblem(c);
                    request.put("url", urlProblem == null ? c.url : "");
                    if (c.route != null) {
                        request.put("_rawTarget", c.route.rawTarget());
                        request.put("_service", Map.of("scheme", c.route.scheme(), "host", c.route.host(), "port", c.route.port()));
                    }
                    if (urlProblem != null) request.put("_urlUnavailable", urlProblem);
                    request.put("headers", headerMaps(raw.request().headers));
                    request.put("_headersComplete", raw.request().headersComplete);
                    byte[] body = raw.request().body();
                    if (body.length > 0) {
                        String text = RawTrafficStore.declaredText(raw.request(), body);
                        Map<String, Object> post = new LinkedHashMap<>();
                        post.put("mimeType", mime(raw.request().headers));
                        if (text != null) post.put("text", text);
                        else { post.put("text", ""); post.put("_bodyBase64", Base64.getEncoder().encodeToString(body)); post.put("_encoding", "base64"); }
                        request.put("postData", post);
                    }
                    request.put("_body", bodyFacts(raw.request()));
                }
                request.put("httpVersion", "HTTP/1.1");
                request.put("_httpVersionUnknown", true);
                request.put("cookies", List.of());
                request.put("queryString", List.of());
                request.put("_queryStringNotParsed", true);
                request.put("headersSize", -1);
                request.put("bodySize", -1);
                RawTrafficStore.Part part = raw == null ? null : raw.response();
                if (part == null) {
                    response.put("status", 0);
                    response.put("statusText", "");
                    response.put("headers", List.of());
                    response.put("content", Map.of("size", -1, "mimeType", "", "_notObserved", true));
                    details.put("responseObserved", false);
                } else {
                    response.put("status", part.status < 0 ? 0 : part.status);
                    response.put("statusText", "");
                    response.put("headers", headerMaps(part.headers));
                    response.put("_headersComplete", part.headersComplete);
                    Map<String, Object> content = new LinkedHashMap<>();
                    content.put("size", part.bodyLength());
                    content.put("mimeType", mime(part.headers));
                    content.put("text", Base64.getEncoder().encodeToString(part.body()));
                    content.put("encoding", "base64");
                    content.put("_body", bodyFacts(part));
                    response.put("content", content);
                    details.put("responseObserved", true);
                }
                response.put("httpVersion", "HTTP/1.1");
                response.put("_httpVersionUnknown", true);
                response.put("cookies", List.of());
                response.put("redirectURL", "");
                response.put("headersSize", -1);
                response.put("bodySize", -1);
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("startedDateTime", e.timestamp());
                entry.put("time", 0);
                entry.put("request", request);
                entry.put("response", response);
                entry.put("cache", Map.of());
                entry.put("timings", Map.of("send", -1, "wait", -1, "receive", -1, "_notMeasured", true));
                entry.put("_cairnGuard", details);
                harEntries.add(entry);
            }
            Map<String, Object> log = new LinkedHashMap<>();
            log.put("version", "1.2");
            log.put("creator", Map.of("name", "Cairn Proxy Guard", "version", "0.2.0"));
            log.put("pages", List.of());
            log.put("entries", harEntries);
            log.put("_cairnGuard", humanProvenance(snapshot));
            return jsonBytes(Map.of("log", log));
        }

        private static Map<String, Object> original(RawTrafficStore.View raw) {
            RawTrafficStore.Capture c = raw.capture();
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("method", c.method);
            o.put("url", c.url);
            o.put("projectId", c.projectId);
            o.put("projectName", c.projectName);
            o.put("hits", hitMaps(c.hits));
            o.put("intentId", c.intent);
            o.put("runId", c.run);
            o.put("service", c.route == null ? null : Map.of("scheme", c.route.scheme(), "host", c.route.host(), "port", c.route.port()));
            o.put("rawTarget", c.route == null ? null : c.route.rawTarget());
            o.put("request", part(raw.request()));
            o.put("response", raw.response() == null ? null : part(raw.response()));
            if (raw.response() == null) o.put("responseUnavailable", "NOT_OBSERVED_OR_NOT_RETAINED");
            return o;
        }
        private static Map<String, Object> part(RawTrafficStore.Part p) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("firstLine", p.firstLine);
            if (p.status >= 0) m.put("status", p.status);
            m.put("headers", headerMaps(p.headers));
            m.put("headersComplete", p.headersComplete);
            m.put("body", bodyFacts(p));
            return m;
        }
        private static Map<String, Object> bodyFacts(RawTrafficStore.Part p) {
            byte[] body = p.body();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("base64", Base64.getEncoder().encodeToString(body));
            m.put("retainedBytes", body.length);
            m.put("suppliedCopyBytes", body.length);
            m.put("bodyComplete", p.bodyComplete);
            m.put("retainedPrefixComplete", !p.omitted && p.bodyComplete);
            m.put("truncated", p.partial());
            m.put("omitted", p.omitted);
            String text = RawTrafficStore.declaredText(p, body);
            m.put("encoding", text == null ? "BINARY_OR_UNSUPPORTED" : "UTF8_VALID");
            if (text != null) m.put("utf8Text", text);
            return m;
        }
        /**
         * Reason the standard HAR url cannot faithfully represent the UNCHANGED actual-service target (null when it
         * can). Pure string/URI checks, no DNS; traffic is never normalized or rejected, _rawTarget/_service stay.
         */
        static String urlProblem(RawTrafficStore.Capture c) {
            if (c.route == null) return "NO_SERVICE_ROUTE";
            String target = c.route.rawTarget();
            if (!target.startsWith("/")) return "NON_ORIGIN_FORM_TARGET";
            if (!c.url.endsWith(target)) return "URL_TARGET_MISMATCH";
            for (int i = 0; i < target.length(); i++) {
                char ch = target.charAt(i);
                if (ch <= 0x20 || ch >= 0x7f) return "UNREPRESENTABLE_CHARACTER";
                if (ch == '#') return "FRAGMENT_IN_TARGET";
                if (ch == '%' && (i + 2 >= target.length() || Character.digit(target.charAt(i + 1), 16) < 0
                        || Character.digit(target.charAt(i + 2), 16) < 0)) return "INVALID_PERCENT_ESCAPE";
            }
            try {
                java.net.URI uri = java.net.URI.create(c.url);
                String rebuilt = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
                if (uri.getRawFragment() != null || uri.getRawPath() == null || !rebuilt.equals(target)) return "NOT_A_FAITHFUL_URI";
            } catch (RuntimeException e) { return "NOT_A_FAITHFUL_URI"; }
            return null;
        }
        private static String mime(List<Header> headers) {
            for (Header h : headers) if (h.name().equalsIgnoreCase("Content-Type")) return h.value();
            return "application/octet-stream";
        }
        private static List<Map<String, Object>> hitMaps(List<Decision.RuleHit> hits) {
            return hits.stream().map(h -> Map.<String, Object>of("id", h.id(), "name", h.name(), "mode", h.mode().name())).toList();
        }
    }

    /** Shared HUMAN_ORIGINAL provenance block for human JSON/HAR/incident documents. */
    public static Map<String, Object> humanProvenance(Map<String, Object> snapshot) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("exportMode", "HUMAN_ORIGINAL");
        result.put("warning", HUMAN_WARNING);
        result.put("completeWireCapture", false);
        result.put("forwardedMeans", "NATIVE_RELEASE_NOT_PROVEN_DELIVERY");
        result.put("timingsKnown", false);
        result.put("retention", "MEMORY_ONLY_NO_COLLECTION_QUOTA_UNTIL_CLEAR_PROJECT_OR_UNLOAD; missing originals are reported unavailable");
        result.put("snapshot", snapshot == null ? Map.of() : Map.copyOf(snapshot));
        return result;
    }
}
