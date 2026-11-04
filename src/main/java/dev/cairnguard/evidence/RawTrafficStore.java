package dev.cairnguard.evidence;

import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Human-local, unmasked inspection copies. NEVER serialize this store or feed its getters to
 * export, incident, policy, status or logging code. No native objects are retained. Removing a
 * row releases all store-owned raw references (Java Strings are not guaranteed zeroizable).
 * EvidenceStore owns synchronization and project/epoch lifecycle; independent limits also apply.
 */
final class RawTrafficStore {
    private static final String LABEL = "UNMASKED_INSPECTION_COPY_NOT_WIRE_PROOF";
    private static final String PREFIX = "[Unmasked inspection copy; NOT wire proof]\n";
    private static final String OMITTED = "[OMITTED: capture unavailable]";
    private final int maxEntries;
    private final long maxBytes;
    private final int partBytes;
    private final LinkedHashMap<String, Capture> entries = new LinkedHashMap<>();
    private String project;
    private boolean projectBound;
    private long retainedBytes;

    private static final class Capture {
        String url;
        String request;
        String response;
        String intent;
        String run;
        List<String> warnings;
        boolean headersComplete;
        boolean bodyComplete;
        boolean requestTruncated;
        boolean requestOmitted;
        boolean responseHeadersComplete;
        boolean responseBodyComplete;
        boolean responseTruncated;
        boolean responseOmitted;
        String requestBodyDisplay;
        String responseBodyDisplay = "UNAVAILABLE";
        long bytes;
    }
    private record Display(String text, boolean truncated, boolean omitted, String bodyDisplay) {}

    RawTrafficStore(int maxEntries, long maxBytes, int partBytes) {
        this.maxEntries = maxEntries;
        this.maxBytes = maxBytes;
        this.partBytes = partBytes;
    }

    void begin(String projectId, String id, RequestData request, RequestAttribution attribution, List<String> warnings) {
        // Project identifiers originate in the controller, but must not become an unaccounted,
        // unbounded raw reference if a malformed in-process caller supplies one.
        if (projectId != null && projectId.length() > 512) { clear(); return; }
        if (projectBound && !Objects.equals(project, projectId)) clear();
        project = projectId;
        projectBound = true;
        Capture capture = new Capture();
        capture.url = Redactor.limit(request.url() == null ? "" : request.url(), Math.min(8192, partBytes / 2));
        capture.intent = attribution.intentId();
        capture.run = attribution.runId();
        capture.warnings = List.copyOf(warnings);
        capture.headersComplete = request.headersComplete();
        capture.bodyComplete = request.bodyComplete();
        boolean oversized = request.bodyLength() > RequestData.MAX_INSPECT_BYTES;
        byte[] body = oversized ? new byte[0] : request.body();
        Display display = display(Redactor.limit(String.valueOf(request.method()), 256) + " " + capture.url + " HTTP/1.1", request.headers(), body,
                request.headersComplete(), request.bodyComplete() && !oversized);
        capture.request = display.text();
        capture.requestTruncated = display.truncated() || !capture.url.equals(request.url());
        capture.requestOmitted = display.omitted();
        capture.requestBodyDisplay = display.bodyDisplay();
        entries.put(id, capture);
        update(capture);
    }

    void response(String id, int status, List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        Capture capture = entries.get(id);
        // A late callback must not resurrect data cleared by an epoch change or raw-only eviction.
        if (capture == null) return;
        boolean oversized = body.length > RequestData.MAX_INSPECT_BYTES;
        Display display = display("HTTP/1.1 " + (status >= 100 && status <= 599 ? status : "unknown"),
                headers, oversized ? new byte[0] : body, headersComplete, bodyComplete && !oversized);
        capture.response = display.text();
        capture.responseHeadersComplete = headersComplete;
        capture.responseBodyComplete = bodyComplete && !oversized;
        capture.responseTruncated = display.truncated();
        capture.responseOmitted = display.omitted();
        capture.responseBodyDisplay = display.bodyDisplay();
        update(capture);
    }

    String request(String id) { Capture c = entries.get(id); return c == null ? null : c.request; }
    String response(String id) { Capture c = entries.get(id); return c == null ? null : c.response; }
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
        info.put("requestTruncated", c.requestTruncated);
        info.put("responseTruncated", c.responseTruncated);
        info.put("requestOmitted", c.requestOmitted);
        info.put("responseOmitted", c.response == null || c.responseOmitted);
        info.put("headersComplete", c.headersComplete);
        info.put("bodyComplete", c.bodyComplete);
        info.put("responseHeadersComplete", c.responseHeadersComplete);
        info.put("responseBodyComplete", c.responseBodyComplete);
        info.put("requestBodyDisplay", c.requestBodyDisplay);
        info.put("responseBodyDisplay", c.responseBodyDisplay);
        info.put("intentId", c.intent);
        info.put("runId", c.run);
        info.put("inspectionWarnings", c.warnings);
        return Map.copyOf(info);
    }
    void remove(String id) {
        Capture removed = entries.remove(id);
        if (removed != null) retainedBytes -= removed.bytes;
    }
    void clear() {
        entries.clear();
        retainedBytes = 0;
        project = null;
        projectBound = false;
    }
    int size() { return entries.size(); }
    long retainedBytes() { return retainedBytes; }

    private void update(Capture c) {
        retainedBytes -= c.bytes;
        c.bytes = 1024 + cost(c.url) + cost(c.request) + cost(c.response) + cost(c.intent) + cost(c.run);
        for (String warning : c.warnings) c.bytes += cost(warning);
        retainedBytes += c.bytes;
        while (entries.size() > maxEntries || retainedBytes > maxBytes) remove(entries.keySet().iterator().next());
    }
    private static long cost(String value) { return value == null ? 0 : 48L + Math.max(2L * value.length(), Redactor.bytes(value)); }

    private Display display(String firstLine, List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        // Reserve enough space for a visible completeness label even after a full prefix.
        int contentBudget = Math.max(0, partBytes - 192);
        BoundedText out = new BoundedText(contentBudget);
        out.append(PREFIX);
        boolean firstComplete = out.append(firstLine + "\n");
        boolean cut = !firstComplete || !headersComplete || !bodyComplete || headers.size() > 256;
        String contentType = "";
        for (Header header : headers.subList(0, Math.min(256, headers.size()))) {
            if (header.name() == null || header.value() == null) { cut = true; continue; }
            if (header.name().equalsIgnoreCase("Content-Type")) contentType = Redactor.limit(header.value(), 1024);
            String name = Redactor.limit(header.name(), partBytes);
            String value = Redactor.limit(header.value(), partBytes);
            if (!name.equals(header.name()) || !value.equals(header.value())) cut = true;
            if (!out.append(name + ": " + value + "\n")) { cut = true; break; }
        }
        out.append("\n");
        boolean omitted = body.length == 0 && !bodyComplete;
        String bodyDisplay = "EMPTY";
        if (omitted) out.append(OMITTED);
        else if (body.length > 0) {
            int remaining = out.remaining();
            // Decode only a bounded prefix. Unknown charsets, controls or binary use lossless hex,
            // never replacement characters or invented bytes. Raw byte prefixes remain explicit.
            int prefixLength = Math.min(body.length, remaining);
            byte[] prefix = Arrays.copyOf(body, prefixLength);
            String text = utf8Text(prefix);
            boolean declaredUtf8 = utf8Charset(contentType);
            if (text != null && declaredUtf8) {
                bodyDisplay = "UTF8_TEXT";
                if (!out.append(text)) cut = true;
                if (prefixLength < body.length) cut = true;
            } else {
                bodyDisplay = "HEX";
                out.append("[HEX: captured bytes; charset unsupported or non-text]\n");
                for (int i = 0; i < prefix.length; i++) {
                    int value = prefix[i] & 255;
                    String hex = "0123456789abcdef";
                    String item = "" + hex.charAt(value >>> 4) + hex.charAt(value & 15) + (i % 16 == 15 ? '\n' : ' ');
                    if (!out.append(item)) { cut = true; break; }
                }
                if (prefixLength < body.length) cut = true;
            }
            if (remaining == 0) omitted = true;
        }
        StringBuilder result = out.value;
        if (cut) result.append("\n[TRUNCATED / incomplete capture: displayed prefix only]");
        if (!headersComplete) result.append("\n[Headers incomplete or omitted]");
        if (!bodyComplete) result.append("\n[Body incomplete or omitted]");
        return new Display(Redactor.limit(result.toString(), partBytes), cut, omitted, bodyDisplay);
    }
    private static final class BoundedText {
        final StringBuilder value = new StringBuilder();
        final int budget;
        int used;
        BoundedText(int budget) { this.budget = budget; }
        int remaining() { return Math.max(0, budget - used); }
        boolean append(String text) {
            String prefix = Redactor.limit(text, remaining());
            value.append(prefix);
            used += Redactor.bytes(prefix);
            return prefix.equals(text);
        }
    }
    private static String utf8Text(byte[] bytes) {
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
    private static boolean utf8Charset(String contentType) {
        if (contentType.length() > 1024) return false;
        String lower = contentType.toLowerCase(java.util.Locale.ROOT).replace(" ", "").replace("\"", "");
        int start = lower.indexOf("charset=");
        if (start < 0) return true;
        String charset = lower.substring(start + 8);
        int end = charset.indexOf(';');
        if (end >= 0) charset = charset.substring(0, end);
        return charset.equals("utf-8") || charset.equals("utf8") || charset.equals("us-ascii");
    }
}
