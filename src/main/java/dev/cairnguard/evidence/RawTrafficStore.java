package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import dev.cairnguard.policy.PolicyEngine;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unmasked structured ORIGINAL captures: the complete supplied header list and body bytes plus completeness
 * flags. There is no masking and no collection/retention quota; heap use grows until an explicit clear,
 * project/epoch change or unload (Java Strings/arrays are not guaranteed zeroizable). Text is rendered on
 * demand. No native objects are retained. EvidenceStore owns synchronization and lifecycle.
 */
final class RawTrafficStore {
    static final String LABEL = "UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF";
    private static final String PREFIX = "[Unmasked inspection copy; NOT wire proof]\n";
    private static final String OMITTED = "[OMITTED: capture unavailable]";
    // Content-Type CLASSIFICATION bound only: an over-long declaration is kept whole but treated as unknown (bytes).
    private static final int CONTENT_TYPE_BOUND = 1024;
    private final LinkedHashMap<String, Capture> entries = new LinkedHashMap<>();
    // Opaque watcher source reference -> evidence id of the same retained capture (released with it).
    private final Map<String, String> sources = new HashMap<>();
    private long retainedBytes; // informational estimate, never an admission/eviction/export gate

    /** Immutable structured capture of one message part with every supplied body byte. */
    static final class Part {
        final String firstLine;
        final List<Header> headers;
        private final byte[] body;
        final boolean headersComplete;
        final boolean bodyComplete;
        // No bytes were supplied for an incomplete body (native read failure/unavailable), not a cut.
        final boolean omitted;
        final String bodyDisplay;
        final int status;
        // A Content-Type declaration that cannot be classified (null, over the bound, or headers missing): bytes only.
        final boolean typeUnknown;
        private Part(String firstLine, List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete,
                     int status) {
            this.firstLine = firstLine; this.headers = List.copyOf(headers); this.body = body;
            this.headersComplete = headersComplete; this.bodyComplete = bodyComplete; this.status = status;
            // Charset availability is FROZEN from the INCOMING capture: omitted headers (incomplete capture) are an
            // unknown declaration, not a verified absent one.
            boolean unknown = !headersComplete;
            for (Header h : headers)
                if (h.name() != null && h.name().equalsIgnoreCase("Content-Type")
                        && (h.value() == null || h.value().length() > CONTENT_TYPE_BOUND)) unknown = true;
            typeUnknown = unknown;
            omitted = body.length == 0 && !bodyComplete;
            bodyDisplay = omitted ? "UNAVAILABLE" : body.length == 0 ? "EMPTY" : declaredText(this, body) != null ? "UTF8_TEXT" : "HEX";
        }
        byte[] body() { return body.clone(); }
        int bodyLength() { return body.length; }
        /** Supplied bytes exist but the supplied copy itself is incomplete. */
        boolean partial() { return !bodyComplete && body.length > 0; }
        long cost() {
            long bytes = 128 + RawTrafficStore.cost(firstLine) + 16L + body.length;
            for (Header h : headers) bytes += 64 + RawTrafficStore.cost(h.name()) + RawTrafficStore.cost(h.value());
            return bytes;
        }
    }
    /** Actual service + untouched native target; exactPath only for one complete unambiguous routing view. */
    record Route(String scheme, String host, int port, String rawTarget, String exactPath) {}

    static final class Capture {
        final String method;
        final String url;
        final String projectId;
        final String projectName;
        final List<Decision.RuleHit> hits;
        final String intent;
        final String run;
        final List<String> warnings;
        final Route route;
        final Part request;
        Part response;
        String source;
        long bytes;
        private Capture(String method, String url, String projectId, String projectName, List<Decision.RuleHit> hits,
                        String intent, String run, List<String> warnings, Route route, Part request) {
            this.method = method; this.url = url; this.projectId = projectId; this.projectName = projectName;
            this.hits = List.copyOf(hits); this.intent = intent; this.run = run;
            this.warnings = List.copyOf(warnings); this.route = route; this.request = request;
        }
    }
    /** Immutable point-in-time view for an explicitly consented human export. Shares immutable parts. */
    record View(Capture capture, Part request, Part response) {}

    Capture begin(String projectId, String projectName, String id, RequestData request, RequestAttribution attribution,
                  List<String> warnings, List<Decision.RuleHit> hits) {
        String url = request.url() == null ? "" : request.url();
        String method = String.valueOf(request.method());
        Part part = new Part(method + " " + url + " HTTP/1.1", request.headers(), request.body(), request.headersComplete(),
                request.bodyComplete(), -1);
        Capture capture = new Capture(method, url, projectId, projectName, hits, attribution.intentId(), attribution.runId(),
                warnings, route(request), part);
        entries.put(id, capture);
        update(capture);
        return capture;
    }

    void beginUnpaired(String projectId, String projectName, String id) {
        var capture = new Capture("", "", projectId, projectName, List.of(), "-", "-",
                List.of("RESPONSE_CORRELATION_UNAVAILABLE"), null, null);
        entries.put(id, capture);
        update(capture);
    }

    Part response(String id, int status, List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        Capture capture = entries.get(id);
        // A late callback must not resurrect data cleared by an epoch change or explicit clear.
        if (capture == null) return null;
        boolean valid = status >= 100 && status <= 599;
        capture.response = new Part("HTTP/1.1 " + (valid ? status : "unknown"), headers, body.clone(), headersComplete,
                bodyComplete, valid ? status : -1);
        update(capture);
        return capture.response;
    }

    /** Associates one opaque watcher source reference with this retained capture (released with it). */
    void bindSource(String id, String source) {
        Capture capture = entries.get(id);
        if (capture == null || source == null || source.length() > 64 || capture.source != null) return;
        capture.source = source;
        sources.put(source, id);
        update(capture);
    }
    Capture bySource(String source) {
        String id = source == null ? null : sources.get(source);
        return id == null ? null : entries.get(id);
    }
    boolean retained(String id, Capture expected) { return expected != null && entries.get(id) == expected; }
    String sourceId(String source) { return source == null ? null : sources.get(source); }
    View view(String id) {
        Capture c = entries.get(id);
        return c == null ? null : new View(c, c.request, c.response);
    }

    String request(String id) { Capture c = entries.get(id); return c == null || c.request == null ? null : render(c.request); }
    String response(String id) { Capture c = entries.get(id); return c == null || c.response == null ? null : render(c.response); }
    String url(String id) { Capture c = entries.get(id); return c == null ? null : c.url; }
    Map<String, Object> info(String id) {
        Capture c = entries.get(id);
        if (c == null) return Map.of("available", false, "label", LABEL);
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("available", true);
        info.put("label", LABEL);
        info.put("completeWireCapture", false);
        info.put("requestAvailable", c.request != null);
        info.put("responseAvailable", c.response != null);
        info.put("requestTruncated", c.request != null && c.request.partial());
        info.put("responseTruncated", c.response != null && c.response.partial());
        info.put("requestOmitted", c.request == null || c.request.omitted);
        info.put("responseOmitted", c.response == null || c.response.omitted);
        info.put("headersComplete", c.request != null && c.request.headersComplete);
        info.put("bodyComplete", c.request != null && c.request.bodyComplete);
        info.put("responseHeadersComplete", c.response != null && c.response.headersComplete);
        info.put("responseBodyComplete", c.response != null && c.response.bodyComplete);
        info.put("requestBodyDisplay", c.request == null ? "UNAVAILABLE" : c.request.bodyDisplay);
        info.put("responseBodyDisplay", c.response == null ? "UNAVAILABLE" : c.response.bodyDisplay);
        info.put("intentId", c.intent);
        info.put("runId", c.run);
        info.put("inspectionWarnings", c.warnings);
        info.put("method", c.method);
        info.put("projectId", c.projectId == null ? "" : c.projectId);
        info.put("projectName", c.projectName == null ? "" : c.projectName);
        info.put("hits", c.hits.stream().map(h -> Map.of("id", h.id(), "name", h.name(), "mode", h.mode().name())).toList());
        info.put("routeAvailable", c.route != null);
        if (c.route != null) {
            info.put("scheme", c.route.scheme());
            info.put("host", c.route.host());
            info.put("port", c.route.port());
            info.put("rawTarget", c.route.rawTarget());
            info.put("exactRoute", c.route.exactPath() != null);
        }
        return Map.copyOf(info);
    }
    void clear() {
        entries.clear();
        sources.clear();
        retainedBytes = 0;
    }
    int size() { return entries.size(); }
    long retainedBytes() { return retainedBytes; }

    private static Route route(RequestData request) {
        try {
            String host = request.host();
            String target = request.nativeTarget() != null ? request.nativeTarget() : legacyTarget(request.url());
            if (host == null || host.isEmpty() || target == null || request.port() < 1 || request.port() > 65_535) return null;
            String exact = PolicyEngine.exactRoutingPath(request);
            return new Route(request.secure() ? "https" : "http", host, request.port(), target, exact);
        } catch (RuntimeException e) { return null; }
    }
    private static String legacyTarget(String url) {
        if (url == null) return null;
        int scheme = url.indexOf("://");
        if (scheme < 0) return null;
        int slash = url.indexOf('/', scheme + 3);
        int question = url.indexOf('?', scheme + 3);
        int start = slash < 0 ? question : question < 0 ? slash : Math.min(slash, question);
        return start < 0 ? "/" : (url.charAt(start) == '?' ? "/" : "") + url.substring(start);
    }

    private void update(Capture c) {
        retainedBytes -= c.bytes;
        c.bytes = 2048 + cost(c.url) + cost(c.method) + cost(c.projectId) + cost(c.projectName) + cost(c.intent) + cost(c.run)
                + cost(c.source) + (c.request == null ? 0 : c.request.cost()) + (c.response == null ? 0 : c.response.cost());
        for (String warning : c.warnings) c.bytes += cost(warning);
        for (Decision.RuleHit hit : c.hits) c.bytes += 64 + cost(hit.id()) + cost(hit.name());
        if (c.route != null) c.bytes += 96 + cost(c.route.scheme()) + cost(c.route.host()) + cost(c.route.rawTarget()) + cost(c.route.exactPath());
        if (c.source != null) c.bytes += 96; // source index entry
        retainedBytes += c.bytes;
    }
    private static long cost(String value) { return value == null ? 0 : 48L + 2L * value.length(); }

    /** Complete original text projection (layout only; nothing is cut). */
    static String render(Part part) {
        StringBuilder out = new StringBuilder(PREFIX).append(part.firstLine).append('\n');
        for (Header header : part.headers) out.append(header.name()).append(": ").append(header.value()).append('\n');
        out.append('\n');
        if (part.omitted) out.append(OMITTED);
        else if (part.bodyDisplay.equals("UTF8_TEXT")) out.append(utf8Text(part.body));
        else if (part.bodyDisplay.equals("HEX")) {
            // Unknown charsets, controls or binary use lossless hex, never replacement characters or invented bytes.
            out.append("[HEX: captured bytes; charset unsupported or non-text]\n");
            String hex = "0123456789abcdef";
            for (int i = 0; i < part.body.length; i++) {
                int value = part.body[i] & 255;
                out.append(hex.charAt(value >>> 4)).append(hex.charAt(value & 15)).append(i % 16 == 15 ? '\n' : ' ');
            }
        }
        if (!part.headersComplete) out.append("\n[Headers incomplete or omitted]");
        if (!part.bodyComplete) out.append("\n[Body incomplete or omitted]");
        return out.toString();
    }
    /** Evidence row projection of the same immutable part: originals, with an explicit body encoding. */
    static TrafficEntry.Message message(Part part) {
        String body = switch (part.bodyDisplay) {
            case "UTF8_TEXT" -> utf8Text(part.body);
            case "HEX" -> java.util.HexFormat.of().formatHex(part.body);
            default -> "";
        };
        String type = "";
        for (Header h : part.headers) if (h.name() != null && h.value() != null && h.name().equalsIgnoreCase("Content-Type")) { type = h.value(); break; }
        return new TrafficEntry.Message(part.headers, body, type, part.omitted, !part.headersComplete || !part.bodyComplete,
                true, part.bodyDisplay);
    }
    static String utf8Text(byte[] bytes) {
        try {
            String value = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c < 32 && c != '\n' && c != '\r' && c != '\t' || c == 127) return null;
            }
            return value;
        } catch (CharacterCodingException ignored) { return null; }
    }
    /**
     * The ONE shared charset decision for raw display and human exports: bytes are ordinary text only when
     * they are valid UTF-8 AND the declared charset is absent, utf-8, or us-ascii with ASCII-only bytes.
     * Anything else (windows-1252, unknown, non-ASCII under us-ascii) stays bytes/HEX/base64, never text.
     */
    static boolean charsetAccepts(String contentType, byte[] bytes) {
        int n = contentType.length();
        if (n > CONTENT_TYPE_BOUND) return false;
        for (int i = 0; i < n; i++) { char c = contentType.charAt(i); if (c != '\t' && (c < 0x20 || c == 0x7f)) return false; }
        // Conservative recognized subset, one linear scan, no regex:
        //   OWS token "/" token *( OWS ";" OWS token "=" ( token | DQUOTE *(no DQUOTE/backslash) DQUOTE ) ) OWS
        // (OWS = SP/HTAB). Anything outside it - empty segments, misplaced quotes, bad tokens, a duplicate or
        // unsupported charset - is UNKNOWN (bytes). Absence is accepted only after every segment is valid.
        String charset = null;
        int pos = 0;
        boolean first = true;
        while (true) {
            int end = pos;
            boolean quoted = false;
            while (end < n && (quoted || contentType.charAt(end) != ';')) {
                if (contentType.charAt(end) == '"') quoted = !quoted;
                end++;
            }
            if (quoted) return false;
            String segment = trimOws(contentType.substring(pos, end));
            if (first) {
                int slash = segment.indexOf('/');
                if (slash < 0 || !isToken(segment.substring(0, slash)) || !isToken(segment.substring(slash + 1))) return false;
            } else {
                int eq = segment.indexOf('=');
                if (eq < 0 || !isToken(segment.substring(0, eq))) return false;
                String value = segment.substring(eq + 1);
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                    if (value.indexOf('"') >= 0 || value.indexOf('\\') >= 0) return false;
                } else if (!isToken(value)) return false;
                // RFC 2231 charset*/charset*0* continuations are not decoded: the family is unknown, never text-authorizing.
                if (segment.regionMatches(true, 0, "charset*", 0, 8)) return false;
                if (segment.substring(0, eq).equalsIgnoreCase("charset")) {
                    if (charset != null) return false;
                    charset = value.toLowerCase(java.util.Locale.ROOT);
                }
            }
            first = false;
            if (end >= n) break;
            pos = end + 1;
        }
        if (charset == null || charset.equals("utf-8") || charset.equals("utf8")) return true;
        if (!charset.equals("us-ascii")) return false;
        for (byte b : bytes) if (b < 0) return false;
        return true;
    }
    /** Nonempty ASCII HTTP token: alnum and !#$%&'*+-.^_`|~ only. */
    private static boolean isToken(String value) {
        if (value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) return false;
        }
        return true;
    }
    private static boolean isOws(char c) { return c == ' ' || c == '\t'; }
    private static String trimOws(String value) {
        int a = 0, b = value.length();
        while (a < b && isOws(value.charAt(a))) a++;
        while (b > a && isOws(value.charAt(b - 1))) b--;
        return value.substring(a, b);
    }
    /** Every retained Content-Type declaration must accept the bytes; an unknown/over-long one never does. */
    static boolean typeAccepts(List<Header> headers, boolean typeUnknown, byte[] bytes) {
        if (typeUnknown) return false;
        for (Header h : headers) if ("Content-Type".equalsIgnoreCase(h.name()) && (h.value() == null || !charsetAccepts(h.value(), bytes))) return false;
        return true;
    }
    /** Ordinary text of a retained part's body under ALL its declared Content-Types, or null (see charsetAccepts). */
    static String declaredText(Part part, byte[] body) {
        String text = utf8Text(body);
        return text != null && typeAccepts(part.headers, part.typeUnknown, body) ? text : null;
    }
}
