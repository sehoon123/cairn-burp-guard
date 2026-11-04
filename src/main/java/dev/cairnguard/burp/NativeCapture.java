package dev.cairnguard.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.util.ArrayList;
import java.util.List;

/** Bounded inspection copies only. Never parses/normalizes a native target or replaces native data. */
final class NativeCapture {
    static final int MAX_URL = 16_384;
    static final int MAX_HEADERS = 256;
    static final int MAX_HEAD_CHARS = 65_536;
    static final int MAX_BODY = RequestData.MAX_INSPECT_BYTES;
    private static final byte[] EMPTY = new byte[0];

    private NativeCapture() {}

    static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String category;
        Rejected(String category) { super(category, null, false, false); this.category = category; }
        String category() { return category; }
    }
    private record Headers(List<Header> values, int chars, boolean complete) {}
    private record Body(byte[] values, boolean complete) {}
    /** Actual scalars are observed even when optional response capture has no slot. -1 means unknown. */
    record Observation(int status, ByteArray nativeBody, long actualBytes) {}
    record Response(int status, List<Header> headers, byte[] body, long actualBytes,
                    boolean headersComplete, boolean bodyComplete) {}

    static RequestData request(HttpRequestToBeSent request) { return request(request, true); }

    static RequestData request(HttpRequestToBeSent request, boolean contentSlot) {
        String method = bounded(request.method(), 32);
        HttpService service = request.httpService();
        if (service == null) throw reject("CAPTURE_FAILED");
        String host = bounded(service.host(), 255);
        int port = service.port();
        boolean secure = service.secure();
        if (port < 1 || port > 65_535) throw reject("CAPTURE_FAILED");
        // request.url() can reflect a deliberately fuzzed Host/:authority. Only the actual service
        // and the untouched request.path() establish scope. No URI parser, percent decoder or
        // normalization barrier is allowed here (including malformed-percent pentest targets).
        // The bounded untouched target is preserved SEPARATELY (RequestData.nativeTarget): policy must
        // never re-derive it from the synthetic URL, or a non-origin-form target ("admin/x", "*",
        // "@h/x") would silently lose its prefix. The URL below is display/inspection metadata only.
        String path = inspectionTarget(request.path());
        String authority = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        String url = (secure ? "https://" : "http://") + authority + ":" + port + path;
        Headers headers = contentSlot ? requestHeaders(request, method.length() + url.length()) : missingHeaders();
        ByteArray nativeBody = null;
        long length = -1;
        try {
            nativeBody = request.body();
            if (nativeBody != null) length = nativeBody.length();
        } catch (RuntimeException | LinkageError ignored) { /* Optional capture, not scope failure. */ }
        // An independently verified EMPTY body remains known even without a copy slot. Unknown or
        // nonempty omitted bodies must never accidentally become health-probe passthroughs.
        Body body = copyBody(nativeBody, length, MAX_BODY - method.length() - url.length() - headers.chars(), contentSlot);
        return new RequestData(method, url, host, port, secure, headers.values(), body.values(),
                headers.complete(), body.complete(), path);
    }

    static Observation observe(HttpResponseReceived response) {
        int status = 0;
        ByteArray body = null;
        long size = -1;
        try { status = response.statusCode(); }
        catch (RuntimeException | LinkageError ignored) { /* Keep independent size observation. */ }
        try {
            body = response.body();
            if (body != null) size = body.length();
            if (size < 0) size = -1;
        } catch (RuntimeException | LinkageError ignored) { size = -1; }
        return new Observation(status, body, size);
    }

    static Response response(HttpResponseReceived response) { return response(response, observe(response), true); }
    static Response response(HttpResponseReceived response, Observation observed, boolean contentSlot) {
        Headers headers = contentSlot ? responseHeaders(response) : missingHeaders();
        Body body = copyBody(observed.nativeBody(), observed.actualBytes(), MAX_BODY - headers.chars(), contentSlot);
        // No oversized zero-filled sentinel: omitted bytes are explicitly absent, never "original".
        return new Response(observed.status(), headers.values(), body.values(), observed.actualBytes(), headers.complete(), body.complete());
    }

    private static Headers requestHeaders(HttpRequestToBeSent request, int initial) {
        try { return headers(request.headers(), initial); }
        catch (RuntimeException | LinkageError ignored) { return missingHeaders(); }
    }
    private static Headers responseHeaders(HttpResponseReceived response) {
        try { return headers(response.headers(), 0); }
        catch (RuntimeException | LinkageError ignored) { return missingHeaders(); }
    }
    private static Headers missingHeaders() { return new Headers(List.of(), 0, false); }
    private static Headers headers(List<HttpHeader> nativeHeaders, int initial) {
        if (nativeHeaders == null) return missingHeaders();
        int count = nativeHeaders.size();
        if (count > MAX_HEADERS || count < 0) return missingHeaders();
        List<Header> copy = new ArrayList<>(count);
        long total = initial;
        // Index only the bounded advertised size. Preserve even fuzzed/duplicate/pseudo fields in
        // the inspection copy; explicit rules report unavailable inspection when not interpretable.
        for (int i = 0; i < count; i++) {
            HttpHeader h = nativeHeaders.get(i);
            if (h == null) return missingHeaders();
            String name = h.name(), value = h.value();
            if (name == null || value == null || name.length() > 256 || value.length() > MAX_HEAD_CHARS)
                return missingHeaders();
            total += (long) name.length() + value.length();
            if (total > MAX_HEAD_CHARS) return missingHeaders();
            copy.add(new Header(name, value));
        }
        return new Headers(List.copyOf(copy), (int) total - initial, true);
    }
    private static Body copyBody(ByteArray body, long size, int budget, boolean contentSlot) {
        if (size == 0 && !contentSlot) return new Body(EMPTY, true);
        if (!contentSlot || body == null || size < 0 || size > Math.max(0, budget)) return new Body(EMPTY, false);
        try {
            byte[] copy = body.getBytes();
            if (copy != null && copy.length == size && body.length() == size) return new Body(copy, true);
        } catch (RuntimeException | LinkageError ignored) { /* Never echo native exception text. */ }
        // A failed optional zero-byte copy does not erase independently verified EMPTY metadata.
        if (size == 0 && body != null) {
            try { if (body.length() == 0) return new Body(EMPTY, true); }
            catch (RuntimeException | LinkageError ignored) { /* Unknown, not a health probe. */ }
        }
        return new Body(EMPTY, false);
    }
    private static String inspectionTarget(String target) {
        if (target == null) throw reject("CAPTURE_FAILED");
        int question = -1;
        // Scope-essential PATH is bounded; optional oversized QUERY is not an automatic451. Keep
        // one byte beyond the policy query bound so it is explicitly unavailable, never a partial
        // successful rule match. The raw UI's own shorter bound labels this as truncated. This
        // bounded inspection string is NEVER used for native continuation/transmission.
        for (int i = 0; i < Math.min(target.length(), MAX_URL + 1); i++) {
            if (target.charAt(i) == '?') { question = i; break; }
        }
        if (question < 0) return bounded(target, MAX_URL);
        return target.length() - question - 1 > MAX_URL
                ? target.substring(0, question + 1 + MAX_URL + 1) : target;
    }
    private static String bounded(String text, int limit) {
        if (text == null) throw reject("CAPTURE_FAILED");
        if (text.length() > limit) throw reject("CAPTURE_LIMIT");
        return text;
    }
    private static Rejected reject(String category) { return new Rejected(category); }
}
