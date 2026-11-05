package dev.cairnguard.policy;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import static dev.cairnguard.policy.PolicySupport.*;

/** Transient, demand-driven inspection. Unavailable optional fields are never represented as evaluated. */
final class RequestInspection {
    private static final JsonFactory JSON_FACTORY = Json.MAPPER.getFactory().copy();

    /** service is the canonical actual scheme://host[:non-default-port]; paths[0] is the raw native target path. */
    record Target(String scheme, Authority authority, List<String> paths, String url,
                  String query, boolean hasQuery, String method, List<Header> headers,
                  boolean routingComplete, String service) {}
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
    List<String> url = List.of();
    final List<String> path;
    List<Named> query = List.of();
    List<Named> headers = List.of();
    List<String> body = List.of();
    JsonValue json = JsonValue.empty();
    List<Named> form = List.of();
    List<String> any = List.of();
    private final Set<Field> available = EnumSet.of(Field.METHOD, Field.PATH);
    private final Set<String> warnings = new LinkedHashSet<>();
    private final Budget routingWork = new Budget();
    private final Budget contentWork = new Budget();

    /** ANY components other than PATH/URL routing views (privileged ANY treats routing per view set). */
    List<String> anyContent = List.of();

    private RequestInspection(Target target) {
        method = List.of(target.method);
        path = target.paths;
        if (!target.routingComplete) {
            available.remove(Field.PATH);
            warnings.add("PATH_INTERPRETATION_INCOMPLETE");
        }
    }

    boolean available(Field field) { return available.contains(field); }
    List<String> warnings() { return List.copyOf(warnings); }
    Budget workBudget(Field field) {
        return field == Field.METHOD || field == Field.PATH ? routingWork : contentWork;
    }
    void unavailable(Field field, String category) {
        available.remove(field);
        available.remove(Field.ANY);
        warnings.add(field.name() + "_INSPECTION_UNAVAILABLE_" + category);
    }
    private void optional(Field field, Runnable inspection) {
        try {
            inspection.run();
            available.add(field);
        } catch (Failure e) { unavailable(field, e.getMessage()); }
        catch (RuntimeException e) { unavailable(field, "INSPECTION_ERROR"); }
    }

    private static void addNamed(List<String> out, List<Named> named) {
        for (Named value : named) {
            out.addAll(value.names);
            out.addAll(value.values);
        }
    }

    /** Only actual service metadata and routing path views are mandatory scope inputs. */
    static Target target(RequestData request, Budget budget) {
        if (request == null) throw fail("INVALID_REQUEST");
        if (request.method() == null || request.method().length() > 32 || !token(request.method()))
            throw fail("INVALID_METHOD");
        if (request.port() < 1 || request.port() > 65_535) throw fail("INVALID_AUTHORITY");
        String scheme = request.secure() ? "https" : "http";
        Authority authority = new Authority(host(request.host()), request.port());
        String target = request.nativeTarget() != null ? request.nativeTarget() : legacyTarget(request.url());
        int question = target.indexOf('?');
        String rawPath = question < 0 ? target : target.substring(0, question);
        if (rawPath.length() > MAX_URL) throw fail("INVALID_URI");
        // Non-origin-form, raw-control and undecodable targets are INCOMPLETE routing, not denials.
        RoutingPaths routing = routingPaths(rawPath, budget);
        boolean hasQuery = question >= 0;
        // Oversized optional query data is unavailable, not a scope denial or a truncated match.
        String query = hasQuery && target.length() - question - 1 > MAX_URL ? null
                : hasQuery ? target.substring(question + 1) : "";
        String service = scheme + "://" + authority.host()
                + (authority.port() == (request.secure() ? 443 : 80) ? "" : ":" + authority.port());
        String actualUrl = service + rawPath + (hasQuery && query != null ? "?" + query : "");
        return new Target(scheme, authority, routing.paths(), actualUrl, query, hasQuery,
                request.method(), request.headers(), routing.complete(), service);
    }

    /**
     * Legacy callers without RequestData.nativeTarget: derive path+query from the supplied URL as
     * before (its authority is ignored). Native capture always supplies nativeTarget instead.
     */
    private static String legacyTarget(String suppliedUrl) {
        if (suppliedUrl == null) throw fail("INVALID_URI");
        int question = suppliedUrl.indexOf('?');
        String base = question < 0 ? suppliedUrl : suppliedUrl.substring(0, question);
        if (base.length() > MAX_URL) throw fail("INVALID_URI");
        int separator = base.indexOf("://");
        if (separator <= 0) throw fail("INVALID_URI");
        String suppliedScheme = base.substring(0, separator);
        if (!suppliedScheme.equalsIgnoreCase("http") && !suppliedScheme.equalsIgnoreCase("https"))
            throw fail("UNSUPPORTED_SCHEME");
        // This is an HTTP request target, not a URL being navigated by this extension. A generic URI
        // parser would ban malformed-percent pentest targets (and interpret # as a fragment).
        int authorityStart = separator + 3;
        int slash = base.indexOf('/', authorityStart);
        if (authorityStart == base.length() || slash == authorityStart) throw fail("INVALID_URI");
        String rawPath = slash < 0 ? "/" : base.substring(slash);
        return rawPath + (question < 0 ? "" : suppliedUrl.substring(question));
    }

    static RequestInspection inspect(Target target, RequestData request, Set<Field> demand) {
        return inspect(target, request, demand, true);
    }

    /**
     * contentInspectionAvailable=false (bounded inspection capacity) skips optional HEADER/BODY/JSON/FORM
     * parsing and reports it unavailable; it never changes the copy's completeness or routing/scope work.
     */
    static RequestInspection inspect(Target target, RequestData request, Set<Field> demand, boolean contentInspectionAvailable) {
        RequestInspection input = new RequestInspection(target);
        if (!request.headersComplete()) input.warnings.add("HEADERS_INCOMPLETE");
        if (!request.bodyComplete()) input.warnings.add("BODY_INCOMPLETE");
        boolean any = demand.contains(Field.ANY);
        if (any || demand.contains(Field.URL)) inspectUrl(input, target);
        if (any || demand.contains(Field.QUERY)) input.optional(Field.QUERY, () -> {
            if (target.query == null) throw fail("REQUEST_TOO_LARGE");
            input.query = parameters(target.query, new Budget());
        });
        if ((any || demand.contains(Field.HEADER)) && !contentInspectionAvailable) input.unavailable(Field.HEADER, "INSPECTION_CAPACITY");
        else if (any || demand.contains(Field.HEADER)) input.optional(Field.HEADER, () -> {
            validateHeaders(target.headers, request.headersComplete());
            List<Named> headers = new ArrayList<>();
            Budget budget = new Budget();
            for (Header header : target.headers) {
                headers.add(new Named(views(header.name(), false, false, budget),
                        views(header.value(), false, true, budget)));
            }
            input.headers = List.copyOf(headers);
        });
        boolean bodyWanted = any || demand.contains(Field.BODY) || demand.contains(Field.JSON) || demand.contains(Field.FORM);
        if (bodyWanted && !contentInspectionAvailable) {
            for (Field field : List.of(Field.BODY, Field.JSON, Field.FORM))
                if (any || demand.contains(field)) input.unavailable(field, "INSPECTION_CAPACITY");
        } else if (bodyWanted) inspectBody(input, target, request, demand, any);
        if (any) {
            // ANY can preserve positive matches in an inspectable component. Its completeness is
            // tracked separately so incomplete ANY (or any other field) can NEVER grant EXEMPT.
            List<String> content = new ArrayList<>();
            content.addAll(input.method);
            if (input.available(Field.QUERY)) addNamed(content, input.query);
            if (input.available(Field.HEADER)) addNamed(content, input.headers);
            if (input.available(Field.BODY)) content.addAll(input.body);
            if (input.available(Field.JSON)) input.json.flatten(content);
            if (input.available(Field.FORM)) addNamed(content, input.form);
            input.anyContent = List.copyOf(content);
            List<String> all = new ArrayList<>(content);
            // URL/PATH views are kept for ordinary positives even when routing is incomplete.
            all.addAll(input.url);
            all.addAll(input.path);
            input.any = List.copyOf(all);
            if (input.available.containsAll(EnumSet.complementOf(EnumSet.of(Field.ANY)))) input.available.add(Field.ANY);
        }
        return input;
    }

    private static void validateHeaders(List<Header> headers, boolean complete) {
        if (!complete) throw fail("CAPTURE_INCOMPLETE");
        if (headers == null || headers.size() > MAX_HEADERS) throw fail("INVALID_HEADERS");
        long chars = 0;
        for (Header header : headers) {
            if (header == null || header.name() == null || header.name().length() > 256
                    || !cleanUnicode(header.name(), false) || header.value() == null
                    || !cleanUnicode(header.value(), true)) throw fail("INVALID_HEADERS");
            chars += (long) header.name().length() + header.value().length();
            if (chars > MAX_HEADER_CHARS) throw fail("REQUEST_TOO_LARGE");
        }
    }

    private static void inspectBody(RequestInspection input, Target target, RequestData request,
                                    Set<Field> demand, boolean any) {
        List<Field> wanted = new ArrayList<>();
        for (Field field : List.of(Field.BODY, Field.JSON, Field.FORM))
            if (any || demand.contains(field)) wanted.add(field);
        byte[] bytes;
        Media media;
        String text;
        boolean isJson;
        boolean isForm;
        try {
            if (!request.bodyComplete()) throw fail("CAPTURE_INCOMPLETE");
            // Check size BEFORE the defensive copy, including adversarial old Java fixtures.
            if (request.bodyLength() > RequestData.MAX_INSPECT_BYTES) throw fail("REQUEST_TOO_LARGE");
            bytes = request.body();
            if (bytes.length == 0) {
                input.available.addAll(wanted);
                return;
            }
            validateHeaders(target.headers, request.headersComplete());
            String contentType = null;
            Set<String> seen = new HashSet<>();
            for (Header header : target.headers) {
                String name = header.name().toLowerCase(Locale.ROOT);
                if (name.equals("content-type") || name.equals("content-encoding") || name.equals("transfer-encoding")) {
                    if (!seen.add(name)) throw fail("INVALID_HEADERS");
                    if (name.equals("content-type")) contentType = header.value();
                    if (name.equals("content-encoding") && !header.value().trim().equalsIgnoreCase("identity"))
                        throw fail("UNSUPPORTED_CONTENT_ENCODING");
                    if (name.equals("transfer-encoding")) throw fail("UNSUPPORTED_TRANSFER_ENCODING");
                }
            }
            media = mediaType(contentType);
            String type = media.name;
            isJson = type.equals("application/json") || type.equals("text/json")
                    || (type.startsWith("application/") || type.startsWith("text/")) && type.endsWith("+json");
            isForm = type.equals("application/x-www-form-urlencoded");
            if (!(type.isEmpty() || type.startsWith("text/") || isJson || isForm)) throw fail("UNSUPPORTED_BODY");
            if (media.ascii) for (byte b : bytes) if (b < 0) throw fail("INVALID_TEXT_ENCODING");
            text = utf8(bytes);
        } catch (Failure e) {
            for (Field field : wanted) input.unavailable(field, e.getMessage());
            return;
        } catch (RuntimeException e) {
            for (Field field : wanted) input.unavailable(field, "INSPECTION_ERROR");
            return;
        }
        if (wanted.contains(Field.BODY)) input.optional(Field.BODY, () -> input.body = views(text, isForm, true, new Budget()));
        if (wanted.contains(Field.JSON)) input.optional(Field.JSON, () -> {
            if (isJson || !isForm && looksJson(text)) input.json = json(text, new Budget());
        });
        if (wanted.contains(Field.FORM)) input.optional(Field.FORM, () -> {
            if (isForm) input.form = parameters(text, new Budget());
        });
    }

    /**
     * URL views = actual service + EVERY bounded routing path view (raw, decoded, dot/semicolon/
     * repeated-slash normalized) x (raw + decoded query). So an exact-URL BLOCK catches /./, ;param,
     * //, /x/../ and percent aliases without rewriting the native request. A non-origin-form raw
     * target contributes only through its '/'-rooted alias (never glued onto the authority).
     * URL is privilege-available ONLY when routing and query interpretation are complete; otherwise
     * its views still serve ordinary BLOCK/ASK positives.
     */
    private static void inspectUrl(RequestInspection input, Target target) {
        try {
            if (target.query == null) throw fail("REQUEST_TOO_LARGE");
            Budget budget = new Budget();
            boolean complete = target.routingComplete;
            List<String> queries = List.of();
            if (target.hasQuery) {
                LinkedHashSet<String> all = new LinkedHashSet<>();
                all.add(target.query);
                try { all.addAll(views(target.query, true, false, budget)); }
                catch (Failure e) {
                    // Raw query view still serves ordinary positives; report, never pretend complete.
                    complete = false;
                    input.warnings.add("URL_INSPECTION_UNAVAILABLE_" + e.getMessage());
                }
                queries = List.copyOf(all);
            }
            Set<String> result = new LinkedHashSet<>();
            for (String path : target.paths) {
                if (!path.startsWith("/")) continue;
                String base = target.service + path;
                if (!target.hasQuery) {
                    if (result.add(base)) budget.text(base);
                    continue;
                }
                for (String query : queries) {
                    String combined = base + "?" + query;
                    if (result.add(combined)) budget.text(combined);
                }
            }
            input.url = List.copyOf(result);
            if (complete && !input.url.isEmpty()) input.available.add(Field.URL);
            else input.available.remove(Field.ANY);
        } catch (Failure e) { input.unavailable(Field.URL, e.getMessage()); }
        catch (RuntimeException e) { input.unavailable(Field.URL, "INSPECTION_ERROR"); }
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
