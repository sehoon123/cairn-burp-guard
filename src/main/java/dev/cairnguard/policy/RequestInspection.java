package dev.cairnguard.policy;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import static dev.cairnguard.policy.PolicySupport.*;

/** A transient, completely inspected copy. Nothing in this type is logged or retained by the engine. */
final class RequestInspection {
    private static final JsonFactory JSON_FACTORY = Json.MAPPER.getFactory().copy();

    record Target(String scheme, Authority authority, List<String> paths, String url,
                  String query, boolean hasQuery, String method, List<Header> headers, int headChars) {}
    record Named(List<String> names, List<String> values) {}
    record JsonMember(List<String> names, JsonValue value) {}

    record JsonValue(Map<String, JsonValue> aliases, List<JsonMember> members,
                     List<JsonValue> elements, List<String> scalar) {
        static JsonValue empty() { return new JsonValue(Map.of(), List.of(), List.of(), List.of()); }

        JsonValue select(List<String> pointer) {
            JsonValue current = this;
            for (String segment : pointer) {
                JsonValue next = current.aliases.get(segment);
                if (next == null && !current.elements.isEmpty()) {
                    int index = arrayIndex(segment, current.elements.size());
                    if (index >= 0) next = current.elements.get(index);
                }
                if (next == null) return empty();
                current = next;
            }
            return current;
        }

        private static int arrayIndex(String value, int size) {
            if (value.isEmpty() || value.length() > 6 || value.length() > 1 && value.charAt(0) == '0') return -1;
            int index = 0;
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c < '0' || c > '9') return -1;
                index = index * 10 + c - '0';
            }
            return index < size ? index : -1;
        }

        boolean matches(Predicate<String> test) {
            for (String value : scalar) if (test.test(value)) return true;
            for (JsonMember member : members) {
                for (String key : member.names) if (test.test(key)) return true;
                if (member.value.matches(test)) return true;
            }
            for (JsonValue value : elements) if (value.matches(test)) return true;
            return false;
        }

        void flatten(List<String> out) {
            out.addAll(scalar);
            for (JsonMember member : members) {
                out.addAll(member.names);
                member.value.flatten(out);
            }
            for (JsonValue value : elements) value.flatten(out);
        }
    }

    final List<String> method;
    final List<String> url;
    final List<String> path;
    final List<Named> query;
    final List<Named> headers;
    final List<String> body;
    final JsonValue json;
    final List<Named> form;
    final List<String> any;

    private RequestInspection(List<String> method, List<String> url, List<String> path,
                              List<Named> query, List<Named> headers, List<String> body,
                              JsonValue json, List<Named> form) {
        this.method = method;
        this.url = url;
        this.path = path;
        this.query = query;
        this.headers = headers;
        this.body = body;
        this.json = json;
        this.form = form;
        List<String> all = new ArrayList<>();
        all.addAll(method);
        all.addAll(url);
        all.addAll(path);
        addNamed(all, query);
        addNamed(all, headers);
        all.addAll(body);
        json.flatten(all);
        addNamed(all, form);
        any = List.copyOf(all);
    }

    private static void addNamed(List<String> out, List<Named> named) {
        for (Named value : named) {
            out.addAll(value.names);
            out.addAll(value.values);
        }
    }

    /** Authority and scope paths are inspected before any body matching or decoding. */
    static Target target(RequestData request, Budget budget) {
        if (request == null) throw fail("INVALID_REQUEST");
        if (request.method() == null || request.method().length() > 32 || !token(request.method()))
            throw fail("INVALID_METHOD");
        String url = request.url();
        if (url == null || url.length() > MAX_URL || !cleanUnicode(url, false)) throw fail("INVALID_URI");
        URI uri;
        try { uri = new URI(url); }
        catch (URISyntaxException e) { throw fail("INVALID_URI"); }
        if (uri.isOpaque() || uri.getScheme() == null || uri.getRawFragment() != null
                || uri.getRawUserInfo() != null) throw fail("INVALID_URI");
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw fail("UNSUPPORTED_SCHEME");
        int defaultPort = scheme.equals("https") ? 443 : 80;
        Authority authority = authority(uri.getRawAuthority(), defaultPort);
        if (!authority.host().equals(host(request.host())) || request.port() != authority.port()
                || request.secure() != scheme.equals("https")) throw fail("AUTHORITY_MISMATCH");
        if (request.port() < 1 || request.port() > 65_535) throw fail("INVALID_AUTHORITY");

        List<Header> headers = request.headers();
        if (headers == null || headers.size() > MAX_HEADERS) throw fail("INVALID_HEADERS");
        int headChars = url.length() + request.method().length();
        int hosts = 0;
        Set<String> unique = new HashSet<>();
        for (Header header : headers) {
            if (header == null || header.name() == null || header.name().length() > 256 || !token(header.name())
                    || header.value() == null || header.value().length() > MAX_HEADER_CHARS
                    || !cleanUnicode(header.value(), true)
                    || header.value().indexOf('\r') >= 0 || header.value().indexOf('\n') >= 0)
                throw fail("INVALID_HEADERS");
            headChars += header.name().length() + header.value().length();
            if (headChars > MAX_HEADER_CHARS) throw fail("REQUEST_TOO_LARGE");
            String name = header.name().toLowerCase(Locale.ROOT);
            if (name.equals("host")) {
                if (++hosts > 1) throw fail("INVALID_HEADERS");
                Authority observed = authority(header.value(), defaultPort);
                if (!observed.equals(authority)) throw fail("AUTHORITY_MISMATCH");
            }
            if (name.equals("content-type") || name.equals("content-encoding") || name.equals("content-length")
                    || name.equals("transfer-encoding")) {
                if (!unique.add(name)) throw fail("INVALID_HEADERS");
            }
            if (name.equals("upgrade") || name.startsWith("sec-websocket-")) throw fail("WEBSOCKET_UNSUPPORTED");
            if (name.equals("connection")) {
                for (String part : parts(header.value(), ',')) {
                    if (part.trim().equalsIgnoreCase("upgrade")) throw fail("WEBSOCKET_UNSUPPORTED");
                }
            }
            if (name.equals("content-encoding") && !header.value().trim().equalsIgnoreCase("identity"))
                throw fail("UNSUPPORTED_CONTENT_ENCODING");
            // There is no raw transfer-decoder in this inspection-copy API.
            if (name.equals("transfer-encoding")) throw fail("UNSUPPORTED_TRANSFER_ENCODING");
        }

        String rawPath = uri.getRawPath();
        if (rawPath == null || rawPath.isEmpty()) rawPath = "/";
        List<String> paths = views(rawPath, false, false, budget);
        for (String path : paths) {
            if (!path.startsWith("/") || path.indexOf('\\') >= 0 || path.indexOf('?') >= 0
                    || path.indexOf('#') >= 0 || path.indexOf(';') >= 0)
                throw fail("AMBIGUOUS_PATH");
            for (String segment : parts(path, '/')) {
                if (segment.equals(".") || segment.equals("..")) throw fail("AMBIGUOUS_PATH");
            }
        }
        return new Target(scheme, authority, paths, url,
                uri.getRawQuery() == null ? "" : uri.getRawQuery(), uri.getRawQuery() != null,
                request.method(), headers, headChars);
    }

    static RequestInspection inspect(Target target, RequestData request, Budget budget) {
        byte[] bytes = request.body(); // exactly one defensive body copy, after the hard scope gate
        if (bytes.length > RequestData.MAX_INSPECT_BYTES
                || (long) bytes.length + target.headChars > RequestData.MAX_INSPECT_BYTES)
            throw fail("REQUEST_TOO_LARGE");
        String contentType = null;
        List<Named> headers = new ArrayList<>();
        for (Header header : target.headers) {
            List<String> values = views(header.value(), false, true, budget);
            for (String value : values) {
                if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) throw fail("INVALID_HEADERS");
            }
            headers.add(new Named(views(header.name(), false, false, budget), values));
            if (header.name().equalsIgnoreCase("content-type")) contentType = header.value();
            if (header.name().equalsIgnoreCase("content-length")) contentLength(header.value(), bytes.length);
        }
        Media media = mediaType(contentType);
        List<String> body = List.of();
        JsonValue json = JsonValue.empty();
        List<Named> form = List.of();
        if (bytes.length > 0) {
            String type = media.name;
            boolean isJson = type.equals("application/json") || type.equals("text/json")
                    || (type.startsWith("application/") || type.startsWith("text/")) && type.endsWith("+json");
            boolean isForm = type.equals("application/x-www-form-urlencoded");
            if (!(type.isEmpty() || type.startsWith("text/") || isJson || isForm)) throw fail("UNSUPPORTED_BODY");
            if (media.ascii) for (byte b : bytes) if (b < 0) throw fail("INVALID_TEXT_ENCODING");
            String text = utf8(bytes);
            body = views(text, isForm, true, budget);
            // Avoid bypassing Unicode-unescaping by merely omitting/mislabeling a JSON content type.
            if (isJson || !isForm && looksJson(text)) json = json(text, budget);
            if (isForm) form = parameters(text, budget);
        }
        return new RequestInspection(views(target.method, false, false, budget),
                urlViews(target, budget), target.paths, parameters(target.query, budget),
                List.copyOf(headers), body, json, form);
    }

    private static List<String> urlViews(Target target, Budget budget) {
        Set<String> result = new LinkedHashSet<>(views(target.url, false, false, budget));
        if (target.hasQuery) {
            String base = target.url.substring(0, target.url.indexOf('?'));
            List<String> bases = views(base, false, false, budget);
            List<String> queries = views(target.query, true, false, budget);
            for (String prefix : bases) {
                for (String query : queries) {
                    String combined = prefix + "?" + query;
                    if (result.add(combined)) budget.text(combined);
                }
            }
        }
        return List.copyOf(result);
    }

    private static void contentLength(String value, int actual) {
        if (value.isEmpty() || value.length() > 10) throw fail("INVALID_CONTENT_LENGTH");
        long length = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') throw fail("INVALID_CONTENT_LENGTH");
            length = length * 10 + c - '0';
        }
        if (length != actual) throw fail("INVALID_CONTENT_LENGTH");
    }

    private record Media(String name, boolean ascii) {}

    private static boolean looksJson(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || i == 0 && c == '\ufeff') continue;
            return c == '{' || c == '[' || c == '"';
        }
        return false;
    }

    /** Only UTF-8 (or its ASCII subset) is supported; duplicate/ambiguous parameters are rejected. */
    private static Media mediaType(String value) {
        if (value == null) return new Media("", false);
        if (value.isEmpty() || value.length() > 1_024) throw fail("MALFORMED_CONTENT_TYPE");
        List<String> parts = parts(value, ';');
        String media = parts.getFirst().trim().toLowerCase(Locale.ROOT);
        int slash = media.indexOf('/');
        if (slash < 1 || slash != media.lastIndexOf('/') || !token(media.substring(0, slash))
                || !token(media.substring(slash + 1))) throw fail("MALFORMED_CONTENT_TYPE");
        Set<String> seen = new HashSet<>();
        boolean ascii = false;
        for (int i = 1; i < parts.size(); i++) {
            String part = parts.get(i).trim();
            int equals = part.indexOf('=');
            if (equals < 1) throw fail("MALFORMED_CONTENT_TYPE");
            String name = part.substring(0, equals).trim().toLowerCase(Locale.ROOT);
            String parameter = part.substring(equals + 1).trim();
            if (!token(name) || !seen.add(name) || parameter.isEmpty()) throw fail("MALFORMED_CONTENT_TYPE");
            if (parameter.startsWith("\"") && parameter.endsWith("\"") && parameter.length() >= 2) {
                parameter = parameter.substring(1, parameter.length() - 1);
                if (parameter.indexOf('"') >= 0 || parameter.indexOf('\\') >= 0) throw fail("MALFORMED_CONTENT_TYPE");
            } else if (!token(parameter)) throw fail("MALFORMED_CONTENT_TYPE");
            if (name.equals("charset")) {
                if (!parameter.equalsIgnoreCase("utf-8") && !parameter.equalsIgnoreCase("us-ascii"))
                    throw fail("UNSUPPORTED_CHARSET");
                ascii = parameter.equalsIgnoreCase("us-ascii");
            }
        }
        return new Media(media, ascii);
    }

    /** Inspect both components and separator-revealing decoded views. '+' is a space here only. */
    private static List<Named> parameters(String raw, Budget budget) {
        if (raw.isEmpty()) return List.of();
        Set<Named> result = new LinkedHashSet<>();
        for (String view : views(raw, true, false, budget)) {
            int start = 0;
            int count = 0;
            for (int i = 0; i <= view.length(); i++) {
                if (i == view.length() || view.charAt(i) == '&' || view.charAt(i) == ';') {
                    if (++count > MAX_PAIRS) throw fail("INSPECTION_LIMIT");
                    String pair = view.substring(start, i);
                    start = i + 1;
                    if (pair.isEmpty()) continue;
                    int equals = pair.indexOf('=');
                    String name = equals < 0 ? pair : pair.substring(0, equals);
                    String value = equals < 0 ? "" : pair.substring(equals + 1);
                    result.add(new Named(views(name, true, false, budget), views(value, true, false, budget)));
                    if (result.size() > MAX_PAIRS) throw fail("INSPECTION_LIMIT");
                }
            }
        }
        return List.copyOf(result);
    }

    private static JsonValue json(String raw, Budget budget) {
        // Streaming construction checks node/depth limits before allocating an unbounded tree.
        try (JsonParser parser = JSON_FACTORY.createParser(raw)) {
            if (parser.nextToken() == null) throw fail("MALFORMED_JSON");
            JsonValue value = jsonValue(parser, 0, new int[1], budget);
            if (parser.nextToken() != null) throw fail("MALFORMED_JSON");
            return value;
        } catch (IOException e) {
            // Jackson messages/cause chains can contain credential-bearing source text: discard them.
            throw fail("MALFORMED_JSON");
        }
    }

    private static JsonValue jsonValue(JsonParser parser, int depth, int[] count, Budget budget) throws IOException {
        if (depth > MAX_JSON_DEPTH || ++count[0] > MAX_JSON_NODES) throw fail("INSPECTION_LIMIT");
        JsonToken token = parser.currentToken();
        if (token == JsonToken.START_OBJECT) {
            Map<String, JsonValue> aliases = new HashMap<>();
            List<JsonMember> members = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) throw fail("MALFORMED_JSON");
                if (++count[0] > MAX_JSON_NODES) throw fail("INSPECTION_LIMIT");
                List<String> names = views(parser.currentName(), false, true, budget);
                if (parser.nextToken() == null) throw fail("MALFORMED_JSON");
                JsonValue value = jsonValue(parser, depth + 1, count, budget);
                for (String name : names) {
                    if (aliases.putIfAbsent(name, value) != null) throw fail("AMBIGUOUS_JSON_KEYS");
                }
                members.add(new JsonMember(names, value));
            }
            return new JsonValue(Map.copyOf(aliases), List.copyOf(members), List.of(), List.of());
        }
        if (token == JsonToken.START_ARRAY) {
            List<JsonValue> elements = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (parser.currentToken() == null) throw fail("MALFORMED_JSON");
                elements.add(jsonValue(parser, depth + 1, count, budget));
            }
            return new JsonValue(Map.of(), List.of(), List.copyOf(elements), List.of());
        }
        if (token == null || !token.isScalarValue() || token == JsonToken.VALUE_EMBEDDED_OBJECT)
            throw fail("MALFORMED_JSON");
        return new JsonValue(Map.of(), List.of(), List.of(), views(parser.getText(), false, true, budget));
    }
}
