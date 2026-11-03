package dev.cairnguard.model;

import java.util.List;

/** Immutable inspection copy, never a replacement for a native Burp request. */
public record RequestData(String method, String url, String host, int port, boolean secure,
                          List<Header> headers, byte[] body) {
    public static final int MAX_INSPECT_BYTES = 1_048_576;
    public record Header(String name, String value) {}
    public RequestData {
        headers = List.copyOf(headers);
        body = body.clone();
    }
    @Override public byte[] body() { return body.clone(); }
    public String header(String name) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(name))
                .map(Header::value).findFirst().orElse("");
    }
}
