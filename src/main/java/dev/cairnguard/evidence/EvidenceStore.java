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
import java.util.Set;
import java.util.UUID;

/** Thread-safe, bounded, masked evidence plus a separate human-local raw UI cache. No native objects retained. */
public final class EvidenceStore {
    public static final int MAX_ENTRIES = 2000;
    public static final long MAX_TOTAL_BYTES = 32L * 1024 * 1024;
    public static final int MAX_PART_BYTES = 64 * 1024;
    private static final int MAX_METADATA_BYTES = 512;
    private static final int MAX_URL_BYTES = 8192;
    private static final int MAX_HITS = 128;
    private static final int MAX_WARNINGS = 32;
    private static final Set<String> OUTCOMES = Set.of("pending", "forwarded", "blocked", "exempt", "probe_allowed", "half_open");
    private static final Set<String> GUARD_STATES = Set.of("PROTECTED", "PAUSED_BY_OPERATOR", "POLICY_INVALID",
            "POLICY_SAVE_UNCERTAIN", "PROJECT_UNVERIFIED", "SHUTDOWN", "CIRCUIT_OPEN", "OVERLAY_BLOCK",
            "INTENT_BUDGET", "LISTENER_UNVERIFIED", "CAPACITY", "IN_FLIGHT_STALLED");
    private static final Set<String> INSPECTION_FIELDS = Set.of("URL", "QUERY", "HEADER", "BODY", "JSON", "FORM", "ANY", "METHOD", "PATH");
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

    private final int maxEntries;
    private final long maxBytes;
    private final int partBytes;
    private final byte[] exportKey = new byte[32];
    private final LinkedHashMap<String, Stored> entries = new LinkedHashMap<>();
    private final RawTrafficStore rawUi;
    private final Map<String, Long> reasonCounters = new LinkedHashMap<>();
    private long retainedBytes;
    private long begun;
    private long forwarded;
    private long blocked;
    private long responses;
    private long localResponses;
    private long upstreamResponses;
    private long evictions;
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
        SecretFingerprints secrets;
        long bytes;
        boolean countedForward;
        boolean countedBlock;
        boolean countedResponse;
        boolean responseLocal;
        boolean countedTruncation;
        String countedReason;
        Stored(TrafficEntry entry, SecretFingerprints secrets) { this.entry = entry; this.secrets = secrets; }
    }

    public EvidenceStore() { this(MAX_ENTRIES, MAX_TOTAL_BYTES, MAX_PART_BYTES); }

    /** Smaller limits are useful for deterministic local capacity tests; never exceed production bounds. */
    EvidenceStore(int maxEntries, long maxBytes, int partBytes) {
        if (maxEntries < 1 || maxEntries > MAX_ENTRIES || maxBytes < 1024 || maxBytes > MAX_TOTAL_BYTES
                || partBytes < 256 || partBytes > MAX_PART_BYTES) throw new IllegalArgumentException("INVALID_EVIDENCE_LIMITS");
        this.maxEntries = maxEntries;
        this.maxBytes = maxBytes;
        this.partBytes = partBytes;
        this.rawUi = new RawTrafficStore(maxEntries, maxBytes, partBytes);
        REASONS.stream().sorted().forEach(key -> reasonCounters.put(key, 0L));
        DenialReasons.ALL.stream().sorted().forEach(key -> reasonCounters.putIfAbsent(key, 0L));
        new SecureRandom().nextBytes(exportKey);
    }

    public synchronized String begin(String projectId, String projectName, RequestData request, Decision decision, long revision) {
        if (request == null || decision == null || decision.mode() == null) throw new IllegalArgumentException("INVALID_EVIDENCE_INPUT");
        RequestAttribution attribution = RequestAttribution.parse(request.headers());
        List<String> metadata = new ArrayList<>();
        metadata.add(attribution.intentId());
        metadata.add(attribution.runId());
        metadata.add(projectId);
        metadata.add(projectName);
        // Decision reasons are not copied: they must be categorical, not regex captures or error text.
        for (Decision.RuleHit hit : decision.hits().stream().limit(MAX_HITS).toList()) { metadata.add(hit.id()); metadata.add(hit.name()); }
        Redactor.Prepared prepared = Redactor.prepare(request, metadata);
        if (decision.hits().size() > MAX_HITS) prepared.builder.uncertain();
        SecretFingerprints secrets = prepared.builder.build();
        String method = Redactor.method(request.method(), secrets);
        String rawUrl = Redactor.url(request.url(), secrets);
        String url = Redactor.bytes(rawUrl) > Math.min(MAX_URL_BYTES, partBytes / 2) ? Redactor.REDACTED_URL : rawUrl;
        String safeProjectId = metadata(projectId, secrets);
        String safeProjectName = metadata(projectName, secrets);
        List<Decision.RuleHit> hits = hits(decision.hits(), secrets);
        int requestBudget = requestBudget(method, url);
        TrafficEntry.Message message = Redactor.render(prepared.message, secrets, requestBudget);
        boolean cut = message.truncated() || !url.equals(rawUrl) || decision.hits().size() > MAX_HITS
                || metadataCut(projectId, secrets) || metadataCut(projectName, secrets) || hitsCut(decision.hits(), secrets)
                || decision.inspectionWarnings().size() > MAX_WARNINGS;
        List<String> warnings = new ArrayList<>();
        if (!request.headersComplete()) warnings.add("HEADERS_INCOMPLETE");
        if (!request.bodyComplete()) warnings.add("BODY_INCOMPLETE");
        warnings.addAll(decision.inspectionWarnings().stream().limit(MAX_WARNINGS).toList());
        List<String> safeWarnings = warnings(warnings);
        String id = UUID.randomUUID().toString();
        TrafficEntry entry = new TrafficEntry(id, safeProjectId, safeProjectName, Instant.now().toString(), method, url,
                decision.mode().name(), "PENDING", reason(decision.reason(), "POLICY_DECISION"), null, hits, revision,
                false, message, TrafficEntry.Message.EMPTY, cut, "", metadata(attribution.intentId(), secrets),
                metadata(attribution.runId(), secrets), "pending", "", "", -1, safeWarnings);
        Stored stored = new Stored(seal(entry), secrets);
        entries.put(id, stored);
        rawUi.begin(projectId, id, request, attribution, safeWarnings);
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
                old.bookmarked(), old.requestCapture(), old.responseCapture(), old.truncated(), stored.secrets);
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
        SecretFingerprints.Builder builder = stored.secrets.extend();
        Redactor.RawMessage raw = Redactor.prepareMessage(headers, body, builder, headersComplete, bodyComplete);
        stored.secrets = builder.build();
        rawUi.response(id, statusCode, headers, body, headersComplete, bodyComplete);
        TrafficEntry old = stored.entry;
        if (bodyComplete && body.length <= RequestData.MAX_INSPECT_BYTES && old.responseBytes() < 0)
            old = contextCopy(old, old.outcome(), old.guardState(), old.overlayId(), body.length);
        String method = Redactor.method(old.method(), stored.secrets);
        String url = Redactor.url(old.url(), stored.secrets);
        TrafficEntry.Message request = Redactor.remask(old.requestCapture(), stored.secrets, requestBudget(method, url));
        TrafficEntry.Message response = Redactor.render(raw, stored.secrets, partBytes - 64);
        stored.entry = copy(old, old.disposition(), old.reason(), validStatus(statusCode), old.bookmarked(), request,
                response, old.truncated() || request.truncated() || response.truncated(), stored.secrets);
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
        String nextOverlay = overlayId != null && uuid(overlayId) ? metadata(overlayId, stored.secrets) : "";
        TrafficEntry contextual = contextCopy(old, nextOutcome, nextGuard, nextOverlay, old.responseBytes());
        stored.entry = copy(contextual, old.disposition(), old.reason(), old.statusCode(), old.bookmarked(),
                old.requestCapture(), old.responseCapture(), old.truncated(), stored.secrets);
        update(stored);
    }

    /** Actual native body length is independent of optional content capture/slots; -1 means unknown. */
    public synchronized void responseBytes(String id, long bytes) {
        Stored stored = find(id);
        if (stored == null) return;
        TrafficEntry old = stored.entry;
        TrafficEntry measured = contextCopy(old, old.outcome(), old.guardState(), old.overlayId(), Math.max(-1, bytes));
        stored.entry = copy(measured, old.disposition(), old.reason(), old.statusCode(), old.bookmarked(),
                old.requestCapture(), old.responseCapture(), old.truncated(), stored.secrets);
        update(stored);
    }

    /** Immutable MASKED row lookup for runtime projections; never consult the raw UI cache. */
    public synchronized TrafficEntry entry(String id) {
        Stored stored = entries.get(id);
        return stored == null ? null : stored.entry;
    }

    /**
     * Ephemeral sanitizer for individual watcher display VALUES, using this row's latest keyed
     * secret fingerprints. Never apply it to serialized JSON/schema keys. A disposed/missing row
     * cannot prove safe display, so it returns only a redaction marker. No plaintext credentials or
     * raw UI accessors escape this boundary; callers must not retain the sanitizer across waits.
     */
    public synchronized java.util.function.UnaryOperator<String> displaySanitizer(String id) {
        Stored stored = entries.get(id);
        if (stored == null) return value -> value == null || value.isEmpty() ? "" : Redactor.REDACTED;
        SecretFingerprints current = stored.secrets;
        return value -> Redactor.text(value, current);
    }

    /** Human UI only. These accessors are deliberately absent from TrafficEntry and all exporters. */
    public synchronized String rawRequest(String id) { return rawUi.request(id); }
    public synchronized String rawResponse(String id) { return rawUi.response(id); }
    public synchronized String rawUrl(String id) { return rawUi.url(id); }
    public synchronized Map<String, Object> rawCaptureInfo(String id) { return rawUi.info(id); }
    /** Called on project epoch/uncertainty even when masked history is retained. */
    public synchronized void clearRawUi() { rawUi.clear(); }

    public synchronized void bookmark(String id, boolean value) {
        Stored stored = find(id);
        if (stored == null) return;
        TrafficEntry old = stored.entry;
        stored.entry = copy(old, old.disposition(), old.reason(), old.statusCode(), value, old.requestCapture(),
                old.responseCapture(), old.truncated(), stored.secrets);
        update(stored);
    }

    /** Newest first. Both the list and its entries/nested collections are immutable. */
    public synchronized List<TrafficEntry> snapshot() {
        List<TrafficEntry> result = new ArrayList<>(entries.size());
        for (Stored stored : entries.values()) result.add(stored.entry);
        Collections.reverse(result);
        return List.copyOf(result);
    }

    /** Clears retained evidence/fingerprints, not cumulative run counters. */
    public synchronized void clear() {
        clearedEntries += entries.size();
        entries.clear();
        rawUi.clear();
        retainedBytes = 0;
        clears++;
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
        result.put("evictions", evictions);
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

    /** HAR 1.2 schema fields with explicit unknown sizes/timings and redacted-callback provenance. */
    public String exportHar(List<TrafficEntry> selection) {
        List<TrafficEntry> safe = verified(selection);
        List<Map<String, Object>> harEntries = new ArrayList<>();
        for (TrafficEntry e : safe) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", e.method());
            request.put("url", e.url());
            request.put("httpVersion", "HTTP/1.1");
            request.put("cookies", List.of());
            request.put("headers", headerMaps(e.requestCapture().headers()));
            request.put("queryString", queryMaps(e.url()));
            request.put("headersSize", -1);
            request.put("bodySize", -1);
            if (!e.requestCapture().body().isEmpty()) request.put("postData", Map.of("mimeType", e.requestCapture().mimeType(), "text", e.requestCapture().body()));
            Map<String, Object> response = new LinkedHashMap<>();
            boolean absent = !e.responseCapture().present();
            response.put("status", e.statusCode() == null ? 0 : e.statusCode());
            response.put("statusText", "");
            response.put("httpVersion", "HTTP/1.1");
            response.put("cookies", List.of());
            response.put("headers", headerMaps(e.responseCapture().headers()));
            response.put("content", Map.of("size", Redactor.bytes(e.responseCapture().body()), "mimeType",
                    e.responseCapture().mimeType().isEmpty() ? "application/octet-stream" : e.responseCapture().mimeType(), "text", e.responseCapture().body(),
                    "_sizeIsRedactedTextOnly", true));
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
        stored.bytes = estimatedBytes(stored.entry) + stored.secrets.estimatedBytes();
        retainedBytes += stored.bytes;
        while (entries.size() > maxEntries || retainedBytes > maxBytes) {
            var oldest = entries.entrySet().iterator();
            Stored removed = oldest.next().getValue();
            oldest.remove();
            rawUi.remove(removed.entry.id());
            retainedBytes -= removed.bytes;
            evictions++;
        }
    }
    private int requestBudget(String method, String url) { return Math.max(64, partBytes - Redactor.bytes(method + " " + url + " HTTP/1.1 (inspection copy)\n")); }
    private static String metadata(String value, SecretFingerprints secrets) { return Redactor.limit(Redactor.text(value, secrets), MAX_METADATA_BYTES); }
    private static boolean metadataCut(String value, SecretFingerprints secrets) { return Redactor.bytes(Redactor.text(value, secrets)) > MAX_METADATA_BYTES; }
    private static List<Decision.RuleHit> hits(List<Decision.RuleHit> hits, SecretFingerprints secrets) {
        return hits.stream().limit(MAX_HITS).map(hit -> new Decision.RuleHit(metadata(hit.id(), secrets), metadata(hit.name(), secrets), hit.mode())).toList();
    }
    private static boolean hitsCut(List<Decision.RuleHit> hits, SecretFingerprints secrets) {
        return hits.stream().limit(MAX_HITS).anyMatch(h -> metadataCut(h.id(), secrets) || metadataCut(h.name(), secrets));
    }
    private static Integer validStatus(Integer status) { return status != null && status >= 100 && status <= 599 ? status : null; }
    private static String category(String text) { return text == null || text.length() > 64 ? "" : text.toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_'); }
    private static String reason(String text, String fallback) {
        String candidate = category(text);
        return REASONS.contains(candidate) || DenialReasons.ALL.contains(candidate) ? candidate : fallback;
    }

    private TrafficEntry copy(TrafficEntry old, String disposition, String reason, Integer status, boolean bookmark,
                              TrafficEntry.Message request, TrafficEntry.Message response, boolean truncated, SecretFingerprints secrets) {
        String method = Redactor.method(old.method(), secrets);
        String rawUrl = Redactor.url(old.url(), secrets);
        boolean urlCut = Redactor.bytes(rawUrl) > Math.min(MAX_URL_BYTES, partBytes / 2);
        String url = urlCut ? Redactor.REDACTED_URL : rawUrl;
        TrafficEntry.Message boundedRequest = Redactor.bound(request, requestBudget(method, url));
        boolean cut = truncated || urlCut || boundedRequest.truncated() || response.truncated()
                || metadataCut(old.projectId(), secrets) || metadataCut(old.projectName(), secrets) || hitsCut(old.hits(), secrets);
        return seal(new TrafficEntry(old.id(), metadata(old.projectId(), secrets), metadata(old.projectName(), secrets), old.timestamp(),
                method, url, old.mode(), disposition, reason, status, hits(old.hits(), secrets), old.revision(), bookmark,
                boundedRequest, response, cut, "", metadata(old.intentId(), secrets), metadata(old.runId(), secrets),
                old.outcome(), old.guardState(), metadata(old.overlayId(), secrets), old.responseBytes(), warnings(old.inspectionWarnings())));
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
    private static List<String> warnings(List<String> input) {
        // Fixed categories are diagnostic facts, never copies of payload/error text. Preserve them
        // even when missing content forces opaque redaction of all free-form display metadata.
        return input.stream().limit(MAX_WARNINGS).map(EvidenceStore::warning).distinct().toList();
    }
    private static String warning(String value) {
        if (Set.of("HEADERS_INCOMPLETE", "BODY_INCOMPLETE", "INSPECTION_UNAVAILABLE", "PATH_INTERPRETATION_INCOMPLETE", "[REDACTED]").contains(value == null ? "" : value)) return value;
        if (value != null && value.length() <= 128) {
            String marker = "_INSPECTION_UNAVAILABLE_";
            int split = value.indexOf(marker);
            if (split > 0 && INSPECTION_FIELDS.contains(value.substring(0, split))) {
                String category = value.substring(split + marker.length());
                if (REASONS.contains(category) || DenialReasons.ALL.contains(category)) return value;
            }
        }
        return "INSPECTION_UNAVAILABLE";
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
    private static long textCost(String value) { return 48L + Math.max(2L * value.length(), Redactor.bytes(value)); }

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
        if (selection == null || selection.size() > MAX_ENTRIES) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
        List<TrafficEntry> copy = List.copyOf(selection);
        List<TrafficEntry> result = new ArrayList<>(copy.size());
        long bytes = 0;
        for (TrafficEntry entry : copy) {
            if (estimatedBytes(entry) > MAX_TOTAL_BYTES || !MessageDigest.isEqual(signature(entry).getBytes(StandardCharsets.US_ASCII),
                    entry.provenanceSeal().getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            // A stale snapshot must not undo redaction learned later, and a disposed row can no longer prove its masking is current.
            Stored current = entries.get(entry.id());
            if (current == null) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            TrafficEntry latest = current.entry;
            bytes += estimatedBytes(latest);
            if (bytes > MAX_TOTAL_BYTES) throw new IllegalArgumentException("INVALID_EVIDENCE_SELECTION");
            result.add(latest);
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
        result.put("label", "REDACTED_EVIDENCE_NOT_WIRE_CAPTURE");
        result.put("source", "BURP_PROXY_CALLBACK_COPY");
        result.put("completeWireCapture", false);
        result.put("forwardedMeans", "NATIVE_RELEASE_NOT_PROVEN_DELIVERY");
        result.put("timingsKnown", false);
        result.put("omissionPolicy", "UNSTRUCTURED_UNSUPPORTED_MALFORMED_BODIES_OMITTED");
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
            // These are the already-redacted, percent-encoded display values. Do not re-decode them.
            result.add(Map.of("name", equals < 0 ? pair : pair.substring(0, equals), "value", equals < 0 ? "" : pair.substring(equals + 1)));
            start = end + 1;
        }
        return result;
    }
    private static String json(Object value) {
        try { return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value); }
        catch (Exception ignored) { throw new IllegalArgumentException("EVIDENCE_SERIALIZATION_FAILED"); }
    }
}
