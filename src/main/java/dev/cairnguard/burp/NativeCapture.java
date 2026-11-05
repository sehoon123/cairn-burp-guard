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

/**
 * Complete original copies of the supplied native message (no capture quota). Never parses/normalizes a
 * native target or replaces native data. Policy applies its own inspection bounds to these copies.
 */
final class NativeCapture {
    private static final byte[] EMPTY = new byte[0];

    private NativeCapture() {}

    static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String category;
        Rejected(String category) { super(category, null, false, false); this.category = category; }
        String category() { return category; }
    }
    private record Headers(List<Header> values, boolean complete) {}
    private record Body(byte[] values, boolean complete) {}
    /** Actual scalars are observed independently of the content copy. -1 means unknown. */
    record Observation(int status, ByteArray nativeBody, long actualBytes) {}
    record Response(int status, List<Header> headers, byte[] body, long actualBytes,
                    boolean headersComplete, boolean bodyComplete) {}

    static RequestData request(HttpRequestToBeSent request) {
        String method = required(request.method());
        HttpService service = request.httpService();
        if (service == null) throw reject("CAPTURE_FAILED");
        String host = required(service.host());
        int port = service.port();
        boolean secure = service.secure();
        if (port < 1 || port > 65_535) throw reject("CAPTURE_FAILED");
        // request.url() can reflect a deliberately fuzzed Host/:authority. Only the actual service
        // and the untouched request.path() establish scope. No URI parser, percent decoder or
        // normalization barrier is allowed here (including malformed-percent pentest targets).
        // The complete untouched target is preserved SEPARATELY (RequestData.nativeTarget): policy must
        // never re-derive it from the synthetic URL, or a non-origin-form target ("admin/x", "*",
        // "@h/x") would silently lose its prefix. The URL below is display/inspection metadata only.
        String path = required(request.path());
        String authority = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        String url = (secure ? "https://" : "http://") + authority + ":" + port + path;
        Headers headers = requestHeaders(request);
        ByteArray nativeBody = null;
        long length = -1;
        try {
            nativeBody = request.body();
            if (nativeBody != null) length = nativeBody.length();
        } catch (RuntimeException | LinkageError ignored) { /* Unavailable copy, not scope failure. */ }
        // Unknown bodies must never accidentally become health-probe passthroughs.
        Body body = copyBody(nativeBody, length);
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

    static Response response(HttpResponseReceived response) { return response(response, observe(response)); }
    static Response response(HttpResponseReceived response, Observation observed) {
        Headers headers = responseHeaders(response);
        Body body = copyBody(observed.nativeBody(), observed.actualBytes());
        // No zero-filled sentinel: unavailable bytes are explicitly absent, never "original".
        return new Response(observed.status(), headers.values(), body.values(), observed.actualBytes(), headers.complete(), body.complete());
    }

    private static Headers requestHeaders(HttpRequestToBeSent request) {
        try { return headers(request.headers()); }
        catch (RuntimeException | LinkageError ignored) { return missingHeaders(); }
    }
    private static Headers responseHeaders(HttpResponseReceived response) {
        try { return headers(response.headers()); }
        catch (RuntimeException | LinkageError ignored) { return missingHeaders(); }
    }
    private static Headers missingHeaders() { return new Headers(List.of(), false); }
    private static Headers headers(List<HttpHeader> nativeHeaders) {
        if (nativeHeaders == null) return missingHeaders();
        List<Header> copy = new ArrayList<>(nativeHeaders.size());
        // Preserve even fuzzed/duplicate/pseudo fields; explicit rules report unavailable inspection
        // when policy cannot interpret them.
        for (HttpHeader h : nativeHeaders) {
            if (h == null || h.name() == null || h.value() == null) return missingHeaders();
            copy.add(new Header(h.name(), h.value()));
        }
        return new Headers(List.copyOf(copy), true);
    }
    private static Body copyBody(ByteArray body, long size) {
        if (body == null || size < 0) return new Body(EMPTY, false);
        try {
            byte[] copy = body.getBytes();
            if (copy != null && copy.length == size && body.length() == size) return new Body(copy, true);
        } catch (RuntimeException | LinkageError ignored) { /* Never echo native exception text. */ }
        // A failed zero-byte copy does not erase independently verified EMPTY metadata.
        if (size == 0) {
            try { if (body.length() == 0) return new Body(EMPTY, true); }
            catch (RuntimeException | LinkageError ignored) { /* Unknown, not a health probe. */ }
        }
        return new Body(EMPTY, false);
    }
    private static String required(String text) {
        if (text == null) throw reject("CAPTURE_FAILED");
        return text;
    }
    private static Rejected reject(String category) { return new Rejected(category); }
}
