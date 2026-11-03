package dev.cairnguard.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import dev.cairnguard.policy.PolicyEngine;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded, transient inspection copies, never native replacements or partial/truncated raw captures. */
final class NativeCapture {
    static final int MAX_URL = 16_384;
    static final int MAX_HEADERS = 256;
    static final int MAX_HEAD_CHARS = 65_536;
    static final int MAX_BODY = RequestData.MAX_INSPECT_BYTES;
    private static final Set<String> PSEUDO = Set.of(":method", ":path", ":scheme", ":authority");
    // A constant zero-filled oversized input triggers Redactor's omission/uncertainty path, NOT raw truncation.
    private static final byte[] OMITTED_BODY = new byte[MAX_BODY + 1];
    private static final List<Header> OMITTED_HEADERS = List.of(new Header("X-Cairn-Guard-Capture", "OMITTED"));

    private NativeCapture() {}

    static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String category;
        Rejected(String category) { super(category, null, false, false); this.category = category; }
        String category() { return category; }
    }
    record Response(int status, List<Header> headers, byte[] body) {}

    static RequestData request(HttpRequestToBeSent request) {
        String method = bounded(request.method(), 32);
        String url = bounded(request.url(), MAX_URL);
        HttpService service = request.httpService();
        if (service == null) throw reject("CAPTURE_FAILED");
        String host = bounded(service.host(), 255);
        int port = service.port();
        boolean secure = service.secure();
        String version = bounded(request.httpVersion(), 16);
        boolean http2 = version.equals("HTTP/2") || version.equals("HTTP/2.0");
        if (!http2 && !version.equals("HTTP/1.0") && !version.equals("HTTP/1.1"))
            throw reject("UNSUPPORTED_HTTP_VERSION");
        List<Header> observed = headers(request.headers(), method.length() + url.length());
        List<Header> normalized = normalize(request, observed, method, url, host, port, secure, http2);
        // Check every metadata bound before asking the native byte array for a body copy.
        int head = method.length() + url.length();
        for (Header header : normalized) head = addHead(head, header.name(), header.value());
        byte[] body = body(request.body(), Math.min(MAX_BODY, MAX_BODY - head));
        return new RequestData(method, url, host, port, secure, normalized, body);
    }

    static Response response(HttpResponseReceived response) {
        int status = response.statusCode();
        try {
            List<Header> headers = headers(response.headers(), 0);
            ByteArray body = response.body();
            if (body == null) return omitted(status);
            int length = body.length();
            if (length < 0 || length > MAX_BODY) return new Response(status, headers, OMITTED_BODY);
            return new Response(status, headers, body(body, MAX_BODY));
        } catch (RuntimeException | LinkageError e) { return omitted(status); }
    }

    static Response omitted(int status) { return new Response(status, OMITTED_HEADERS, OMITTED_BODY); }

    private static String bounded(String text, int limit) {
        if (text == null) throw reject("CAPTURE_FAILED");
        if (text.length() > limit) throw reject("CAPTURE_LIMIT");
        return text;
    }

    private static int addHead(int total, String name, String value) {
        long next = (long) total + name.length() + value.length();
        if (next > MAX_HEAD_CHARS) throw reject("CAPTURE_LIMIT");
        return (int) next;
    }

    private static List<Header> headers(List<HttpHeader> nativeHeaders, int initial) {
        if (nativeHeaders == null) throw reject("CAPTURE_FAILED");
        int count = nativeHeaders.size();
        if (count > MAX_HEADERS || count < 0) throw reject("CAPTURE_LIMIT");
        List<Header> copy = new ArrayList<>(count);
        int total = initial;
        // Index the bounded advertised size; never traverse an unexpectedly unbounded iterator.
        for (int i = 0; i < count; i++) {
            HttpHeader h = nativeHeaders.get(i);
            if (h == null) throw reject("CAPTURE_FAILED");
            String name = bounded(h.name(), 256);
            String value = bounded(h.value(), MAX_HEAD_CHARS);
            total = addHead(total, name, value);
            copy.add(new Header(name, value));
        }
        return copy;
    }

    private static byte[] body(ByteArray nativeBody, int budget) {
        if (nativeBody == null) throw reject("CAPTURE_FAILED");
        int size = nativeBody.length();
        if (size < 0 || size > budget) throw reject("CAPTURE_LIMIT");
        byte[] copy = nativeBody.getBytes();
        if (copy == null || copy.length != size || nativeBody.length() != size) throw reject("CAPTURE_FAILED");
        return copy;
    }

    private static List<Header> normalize(HttpRequestToBeSent request, List<Header> observed, String method,
                                          String url, String host, int port, boolean secure, boolean http2) {
        Map<String, String> pseudo = new HashMap<>();
        List<Header> copy = new ArrayList<>(observed.size());
        boolean regularSeen = false;
        for (Header header : observed) {
            if (header.name().startsWith(":")) {
                if (!http2 || regularSeen || !PSEUDO.contains(header.name())
                        || pseudo.putIfAbsent(header.name(), header.value()) != null)
                    throw reject("HTTP2_INCONSISTENT");
            } else {
                regularSeen = true;
                copy.add(header);
            }
        }
        // Montoya can expose HTTP/2 with its pseudo fields already normalized away. In that case
        // the policy still checks URL/service/Host consistency. A partially exposed set is NOT OK.
        if (pseudo.isEmpty()) return copy;
        if (pseudo.size() != PSEUDO.size()) throw reject("HTTP2_INCONSISTENT");
        try {
            URI uri = new URI(url);
            String scheme = secure ? "https" : "http";
            if (uri.isOpaque() || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                    || !scheme.equals(uri.getScheme()) || !scheme.equals(pseudo.get(":scheme"))
                    || !method.equals(pseudo.get(":method"))) throw reject("HTTP2_INCONSISTENT");
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            if (!path.startsWith("/") || !path.equals(pseudo.get(":path"))
                    || !path.equals(bounded(request.path(), MAX_URL))) throw reject("HTTP2_INCONSISTENT");
            Authority expected = new Authority(PolicyEngine.canonicalHost(host), port);
            int defaultPort = secure ? 443 : 80;
            if (!expected.equals(authority(uri.getRawAuthority(), defaultPort))
                    || !expected.equals(authority(pseudo.get(":authority"), defaultPort)))
                throw reject("HTTP2_INCONSISTENT");
            boolean hostSeen = false;
            for (Header header : copy) if (header.name().equalsIgnoreCase("host")) {
                if (hostSeen || !expected.equals(authority(header.value(), defaultPort))) throw reject("HTTP2_INCONSISTENT");
                hostSeen = true;
            }
            if (!hostSeen) copy.add(new Header("Host", pseudo.get(":authority")));
            if (copy.size() > MAX_HEADERS) throw reject("CAPTURE_LIMIT");
            return copy;
        } catch (URISyntaxException | IllegalArgumentException e) { throw reject("HTTP2_INCONSISTENT"); }
    }

    private record Authority(String host, int port) {}
    private static Authority authority(String input, int defaultPort) {
        if (input == null || input.isEmpty() || input.length() > 320) throw reject("HTTP2_INCONSISTENT");
        String host;
        String port = null;
        if (input.startsWith("[")) {
            int end = input.indexOf(']');
            if (end < 0) throw reject("HTTP2_INCONSISTENT");
            host = input.substring(0, end + 1);
            if (end + 1 < input.length()) {
                if (input.charAt(end + 1) != ':') throw reject("HTTP2_INCONSISTENT");
                port = input.substring(end + 2);
            }
        } else {
            int colon = input.indexOf(':');
            if (colon != input.lastIndexOf(':')) throw reject("HTTP2_INCONSISTENT");
            host = colon < 0 ? input : input.substring(0, colon);
            if (colon >= 0) port = input.substring(colon + 1);
        }
        int number = defaultPort;
        if (port != null) {
            if (port.isEmpty() || port.length() > 5) throw reject("HTTP2_INCONSISTENT");
            number = 0;
            for (int i = 0; i < port.length(); i++) {
                char c = port.charAt(i);
                if (c < '0' || c > '9') throw reject("HTTP2_INCONSISTENT");
                number = number * 10 + c - '0';
            }
        }
        if (number < 1 || number > 65_535) throw reject("HTTP2_INCONSISTENT");
        return new Authority(PolicyEngine.canonicalHost(host), number);
    }
    private static Rejected reject(String category) { return new Rejected(category); }
}
