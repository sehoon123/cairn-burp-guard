package dev.cairnguard.model;

import java.util.List;

/**
 * Immutable bounded inspection copy, never a replacement for a native Burp request.
 * host/port/secure describe the actual transport destination, NOT Host/:authority.
 * url supplies the native request-target path/query; policy URL views use that actual service.
 * Incomplete optional captures are not scope failures and must not be treated as complete payloads.
 */
public record RequestData(String method, String url, String host, int port, boolean secure,
                          List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
    public static final int MAX_INSPECT_BYTES = 1_048_576;
    public record Header(String name, String value) {}
    public RequestData {
        headers = List.copyOf(headers);
        body = body.clone();
    }
    /** The original seven-argument constructor denotes a complete inspection copy. */
    public RequestData(String method, String url, String host, int port, boolean secure,
                       List<Header> headers, byte[] body) {
        this(method, url, host, port, secure, headers, body, true, true);
    }
    @Override public byte[] body() { return body.clone(); }
    /** Scalar metadata avoids a potentially unnecessary defensive copy during optional inspection. */
    public int bodyLength() { return body.length; }
    public String header(String name) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(name))
                .map(Header::value).findFirst().orElse("");
    }
}
