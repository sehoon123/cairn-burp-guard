package dev.cairnguard.model;

import java.util.List;

/**
 * Immutable bounded inspection copy, never a replacement for a native Burp request.
 * host/port/secure describe the actual transport destination, NOT Host/:authority.
 * url is a synthetic display/inspection URL (actual service + native target). nativeTarget, when
 * present, is the bounded untouched native request-target (Montoya {@code request.path()}, including
 * any query) and is the AUTHORITATIVE routing input; it is never re-derived from url, so a
 * non-origin-form target (no leading '/') keeps its full prefix. null means a legacy caller that only
 * supplied url (policy then derives the target from url as before).
 * Incomplete optional captures are not scope failures and must not be treated as complete payloads.
 */
public record RequestData(String method, String url, String host, int port, boolean secure,
                          List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete,
                          String nativeTarget) {
    public static final int MAX_INSPECT_BYTES = 1_048_576;
    public record Header(String name, String value) {}
    public RequestData {
        headers = List.copyOf(headers);
        body = body.clone();
    }
    /** Original nine-argument constructor: no separately preserved native target. */
    public RequestData(String method, String url, String host, int port, boolean secure,
                       List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        this(method, url, host, port, secure, headers, body, headersComplete, bodyComplete, null);
    }
    /** The original seven-argument constructor denotes a complete inspection copy. */
    public RequestData(String method, String url, String host, int port, boolean secure,
                       List<Header> headers, byte[] body) {
        this(method, url, host, port, secure, headers, body, true, true, null);
    }
    @Override public byte[] body() { return body.clone(); }
    /** Scalar metadata avoids a potentially unnecessary defensive copy during optional inspection. */
    public int bodyLength() { return body.length; }
    public String header(String name) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(name))
                .map(Header::value).findFirst().orElse("");
    }
}
