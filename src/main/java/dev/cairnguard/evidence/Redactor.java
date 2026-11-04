package dev.cairnguard.evidence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Conservative two-pass redaction. All parsers operate on bounded, transient copies. */
public final class Redactor {
    public static final String REDACTED = "[REDACTED]";
    public static final String OMITTED = "[OMITTED: UNSAFE_OR_UNSUPPORTED_BODY]";
    public static final String TRUNCATED = "[TRUNCATED]";
    static final String REDACTED_URL = "https://redacted.invalid/";
    static final int MAX_INPUT = RequestData.MAX_INSPECT_BYTES;
    private static final int MAX_HEADERS = 256;
    private static final int MAX_NODES = 8192;
    private static final int MAX_DEPTH = 32;
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
            "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK");
    private static final String SECRET_WORDS = "authorization|proxy-authorization|password|passwd|pwd|"
            + "secret|client[_-]?secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|"
            + "id[_-]?token|token|credential|session(?:id)?|csrf|xsrf|cookie|private[_-]?key|otp|pin|signature|code";
    private static final Pattern ASSIGNMENT = Pattern.compile("(?i)([\"']?(?:" + SECRET_WORDS
            + ")[\"']?)\\s*[:=]\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s&;,<>]+))");
    private static final Pattern AUTH = Pattern.compile("(?i)\\b(bearer|basic)\\s+([^\\s,;<>]+)");

    public Redactor() {}

    /** Standalone convenience API; includes header/body and cross-field request reflection checks. */
    public String redactRequest(RequestData request) {
        Prepared prepared = prepare(request, List.of());
        SecretFingerprints secrets = prepared.builder.build();
        TrafficEntry.Message message = render(prepared.message, secrets, 65_536);
        return method(request.method(), secrets) + " " + url(request.url(), secrets) + "\n" + message.text();
    }

    static final class Prepared {
        final SecretFingerprints.Builder builder;
        final RawMessage message;
        Prepared(SecretFingerprints.Builder builder, RawMessage message) {
            this.builder = builder;
            this.message = message;
        }
    }
    private record Pair(String name, String value) {}
    private record RawBody(String kind, JsonNode json, List<Pair> form) {}
    static final class RawMessage {
        final List<Header> headers;
        final RawBody body;
        final String mime;
        final boolean omitted;
        final boolean inputLimited;
        RawMessage(List<Header> headers, RawBody body, String mime, boolean omitted, boolean inputLimited) {
            this.headers = headers;
            this.body = body;
            this.mime = mime;
            this.omitted = omitted;
            this.inputLimited = inputLimited;
        }
    }

    static Prepared prepare(RequestData request, List<String> metadata) {
        SecretFingerprints.Builder builder = SecretFingerprints.builder();
        discoverUrl(request.url(), builder);
        for (String value : metadata) discoverText(value, builder, 0);
        RawMessage message = prepareMessage(request.headers(), request.body(), builder);
        return new Prepared(builder, message);
    }

    static RawMessage prepareMessage(List<Header> headers, byte[] bytes, SecretFingerprints.Builder builder) {
        boolean limited = headers.size() > MAX_HEADERS;
        long headerSize = 0;
        for (Header header : limited ? List.<Header>of() : headers) {
            if (header.name() == null || header.value() == null) { limited = true; break; }
            headerSize += (long) header.name().length() + header.value().length();
            if (headerSize > MAX_INPUT) { limited = true; break; }
        }
        List<Header> safeInput = limited ? List.of() : headers;
        if (limited) builder.uncertain();
        String contentType = "";
        boolean encoding = false;
        for (Header header : safeInput) {
            String name;
            try { name = normalize(header.name(), false); }
            catch (UnsafeInput ignored) { builder.uncertain(); continue; }
            if (sensitive(name)) collectCredential(header.value(), builder);
            if (name.toLowerCase(Locale.ROOT).contains("cookie")) collectCookies(header.value(), builder);
            discoverText(header.value(), builder, 0);
            if (name.equalsIgnoreCase("content-type")) {
                if (!contentType.isEmpty() && !contentType.equalsIgnoreCase(header.value())) encoding = true;
                contentType = header.value();
            }
            if (name.equalsIgnoreCase("content-encoding") && !header.value().trim().equalsIgnoreCase("identity")) encoding = true;
        }
        String mime = mime(contentType);
        if (bytes.length == 0) return new RawMessage(safeInput, new RawBody("empty", null, List.of()), mime, false, limited);
        if (bytes.length > MAX_INPUT || limited || encoding || !supportedCharset(contentType)) {
            builder.uncertain();
            return new RawMessage(safeInput, null, mime, true, limited || bytes.length > MAX_INPUT);
        }
        try {
            String text = utf8(bytes);
            if (contentType.toLowerCase(Locale.ROOT).contains("us-ascii")) {
                for (byte value : bytes) if (value < 0) throw new UnsafeInput();
            }
            if (mime.equals("application/json") || mime.endsWith("+json")) {
                JsonNode node = parseJson(text);
                discoverJson(node, builder, 0, new int[1], 0);
                return new RawMessage(safeInput, new RawBody("json", node, List.of()), mime, false, limited);
            }
            if (mime.equals("application/x-www-form-urlencoded")) {
                List<Pair> form = parseForm(text);
                discoverPairs(form, builder, 0);
                return new RawMessage(safeInput, new RawBody("form", null, form), mime, false, limited);
            }
            // HTML, free text, XML, binary and multipart cannot be reliably credential-masked.
            builder.uncertain();
            return new RawMessage(safeInput, null, mime, true, limited);
        } catch (UnsafeInput | RuntimeException ignored) {
            builder.uncertain();
            return new RawMessage(safeInput, null, mime, true, limited);
        }
    }

    static TrafficEntry.Message render(RawMessage raw, SecretFingerprints secrets, int budget) {
        List<Header> headers = new ArrayList<>();
        for (Header header : raw.headers) {
            String name = text(header.name(), secrets);
            if (!headerName(name)) name = "X-Omitted-Header";
            String value = sensitive(header.name()) ? REDACTED : text(header.value(), secrets);
            headers.add(new Header(name, value));
        }
        String body = "";
        if (raw.omitted) body = OMITTED;
        else if (raw.body.kind.equals("json")) body = jsonString(scrubJson(raw.body.json, secrets, 0));
        else if (raw.body.kind.equals("form")) body = renderPairs(raw.body.form, secrets);
        String mime = secrets.mask(raw.mime).equals(raw.mime) && !secrets.opaque() ? raw.mime : "application/octet-stream";
        return bound(new TrafficEntry.Message(headers, body, mime, raw.omitted, raw.inputLimited, true), budget);
    }

    /** Re-scrub already masked copies when new response credentials are discovered. */
    static TrafficEntry.Message remask(TrafficEntry.Message old, SecretFingerprints secrets, int budget) {
        if (!old.present()) return old;
        List<Header> headers = new ArrayList<>();
        for (Header h : old.headers()) {
            String name = text(h.name(), secrets);
            headers.add(new Header(headerName(name) ? name : "X-Omitted-Header",
                    sensitive(h.name()) ? REDACTED : text(h.value(), secrets)));
        }
        String body = old.body();
        boolean omitted = old.bodyOmitted();
        if (!body.isEmpty() && !omitted) {
            if (old.truncated()) { body = OMITTED; omitted = true; }
            else if (secrets.opaque()) body = REDACTED;
            else try {
                if (old.mimeType().equals("application/json") || old.mimeType().endsWith("+json")) body = jsonString(scrubJson(parseJson(body), secrets, 0));
                else if (old.mimeType().equals("application/x-www-form-urlencoded")) body = renderPairs(parseForm(body), secrets);
                else body = secrets.mask(body);
            } catch (UnsafeInput ignored) { body = OMITTED; omitted = true; }
        }
        String mime = secrets.mask(old.mimeType()).equals(old.mimeType()) && !secrets.opaque() ? old.mimeType() : "application/octet-stream";
        return bound(new TrafficEntry.Message(headers, body, mime, omitted, old.truncated(), true), budget);
    }

    static String method(String value, SecretFingerprints secrets) {
        if (value == null || value.length() > 32) return REDACTED;
        String upper = value.toUpperCase(Locale.ROOT);
        return METHODS.contains(upper) && secrets.mask(upper).equals(upper) ? upper : REDACTED;
    }

    static String text(String value, SecretFingerprints secrets) { return text(value, secrets, true); }

    private static String text(String value, SecretFingerprints secrets, boolean singleLine) {
        if (value == null || value.isEmpty()) return "";
        if (value.equals(REDACTED) || value.equals(OMITTED)) return value;
        try {
            String normalized = normalize(value, false);
            if (normalized.contains("://")) return url(normalized, secrets);
            normalized = inlineMask(normalized, ASSIGNMENT);
            normalized = inlineMask(normalized, AUTH);
            String masked = secrets.mask(normalized);
            return singleLine ? display(masked) : masked;
        } catch (UnsafeInput ignored) { return REDACTED; }
    }

    static String url(String value, SecretFingerprints secrets) {
        if (secrets.opaque()) return REDACTED_URL;
        try {
            URI uri = parseUrl(value);
            String host = secrets.mask(uri.getHost());
            if (!host.equals(uri.getHost())) return REDACTED_URL;
            String rawPath = uri.getRawPath() == null ? "" : uri.getRawPath();
            List<String> segments = parts(rawPath, "/", MAX_NODES);
            StringBuilder path = new StringBuilder();
            boolean previousSecret = false;
            for (int i = 0; i < segments.size(); i++) {
                if (i > 0) path.append('/');
                String normalized = normalize(segments.get(i), false);
                String masked = previousSecret && !normalized.isEmpty() ? REDACTED : text(normalized, secrets);
                path.append(component(masked));
                previousSecret = sensitive(normalized);
            }
            String query = uri.getRawQuery() == null ? "" : "?" + renderPairs(parseForm(uri.getRawQuery()), secrets);
            String authority = uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
            // User info and fragment are never retained, even if they look harmless.
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + authority + path + query;
        } catch (UnsafeInput | IllegalArgumentException ignored) { return REDACTED_URL; }
    }

    private static void discoverUrl(String value, SecretFingerprints.Builder builder) {
        try {
            URI uri = parseUrl(value);
            if (uri.getRawUserInfo() != null) collectCredential(normalize(uri.getRawUserInfo(), false), builder);
            discoverPairs(parseForm(uri.getRawQuery() == null ? "" : uri.getRawQuery()), builder, 0);
            List<String> segments = parts(uri.getRawPath() == null ? "" : uri.getRawPath(), "/", MAX_NODES);
            boolean previousSecret = false;
            for (String segment : segments) {
                String decoded = normalize(segment, false);
                if (previousSecret) collectCredential(decoded, builder);
                discoverText(decoded, builder, 0);
                previousSecret = sensitive(decoded);
            }
            // Fragments are omitted, but their credentials can also be reflected elsewhere.
            if (uri.getRawFragment() != null) collectCredential(normalize(uri.getRawFragment(), false), builder);
        } catch (UnsafeInput | IllegalArgumentException ignored) { builder.uncertain(); }
    }

    private static void discoverPairs(List<Pair> pairs, SecretFingerprints.Builder builder, int depth) throws UnsafeInput {
        if (depth > 3) throw new UnsafeInput();
        for (Pair pair : pairs) {
            if (sensitive(pair.name)) collectCredential(pair.value, builder);
            discoverText(pair.name, builder, depth);
            discoverText(pair.value, builder, depth);
        }
    }

    private static void discoverJson(JsonNode node, SecretFingerprints.Builder builder, int depth, int[] nodes, int embeddedDepth) throws UnsafeInput {
        if (depth > MAX_DEPTH || ++nodes[0] > MAX_NODES) throw new UnsafeInput();
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
            while (fields.hasNext()) {
                var field = fields.next();
                String name = normalize(field.getKey(), false);
                discoverText(name, builder, embeddedDepth);
                if (sensitive(name)) collectTree(field.getValue(), builder, depth + 1, new int[1]);
                discoverJson(field.getValue(), builder, depth + 1, nodes, embeddedDepth);
            }
        } else if (node.isArray()) {
            for (JsonNode item : node) discoverJson(item, builder, depth + 1, nodes, embeddedDepth);
        } else if (node.isTextual()) discoverText(node.textValue(), builder, embeddedDepth);
    }

    private static void collectTree(JsonNode node, SecretFingerprints.Builder builder, int depth, int[] nodes) throws UnsafeInput {
        if (depth > MAX_DEPTH || ++nodes[0] > MAX_NODES) throw new UnsafeInput();
        if (node.isContainerNode()) {
            for (JsonNode child : node) collectTree(child, builder, depth + 1, nodes);
        } else if (!node.isNull()) collectCredential(node.asText(), builder);
    }

    private static void collectCredential(String value, SecretFingerprints.Builder builder) {
        if (value == null || value.isEmpty()) return;
        builder.add(value);
        try {
            String decoded = normalize(value, false);
            builder.add(decoded);
            encodedVariants(decoded, builder);
            String displayed = display(decoded);
            if (!displayed.equals(decoded)) { builder.add(displayed); encodedVariants(displayed, builder); }
            String trimmed = decoded.trim();
            builder.add(trimmed);
            Matcher auth = AUTH.matcher(decoded);
            while (auth.find()) {
                String credential = unquote(auth.group(2));
                builder.add(auth.group(2));
                builder.add(credential);
                encodedVariants(credential, builder);
                if (auth.group(1).equalsIgnoreCase("basic")) {
                    try { collectParts(utf8(Base64.getDecoder().decode(auth.group(2))), builder); }
                    catch (UnsafeInput | IllegalArgumentException ignored) { builder.uncertain(); }
                }
            }
            collectParts(decoded, builder);
        } catch (UnsafeInput ignored) { builder.uncertain(); }
    }

    private static String display(String value) { return value.replace('\r', ' ').replace('\n', ' ').replace('\0', ' '); }

    private static String unquote(String value) throws UnsafeInput {
        if (value.isEmpty()) return value;
        char quote = value.charAt(0);
        if (quote != '\"' && quote != '\'') return value;
        if (value.length() < 2 || value.charAt(value.length() - 1) != quote) throw new UnsafeInput();
        StringBuilder result = new StringBuilder();
        for (int i = 1; i < value.length() - 1; i++) {
            char ch = value.charAt(i);
            if (ch == '\\') {
                if (++i >= value.length() - 1) throw new UnsafeInput();
                ch = value.charAt(i);
                if (ch != '\\' && ch != quote) throw new UnsafeInput();
            } else if (ch == quote) throw new UnsafeInput();
            result.append(ch);
        }
        return result.toString();
    }

    private static void collectCookies(String value, SecretFingerprints.Builder builder) {
        // Treat quoted/escaped cookie values as one unit; malformed quoting suppresses capture.
        boolean quoted = false;
        boolean escaped = false;
        int start = 0;
        int count = 0;
        try {
            for (int i = 0; i <= value.length(); i++) {
                char ch = i == value.length() ? ';' : value.charAt(i);
                if (escaped) { escaped = false; continue; }
                if (quoted && ch == '\\') { escaped = true; continue; }
                if (ch == '\"') quoted = !quoted;
                if (ch == ';' && !quoted) {
                    if (++count > MAX_NODES) throw new UnsafeInput();
                    String part = value.substring(start, i);
                    int equals = part.indexOf('=');
                    if (equals >= 0) collectCredential(unquote(part.substring(equals + 1).trim()), builder);
                    start = i + 1;
                }
            }
            if (quoted || escaped) throw new UnsafeInput();
        } catch (UnsafeInput ignored) { builder.uncertain(); }
    }

    private static void encodedVariants(String value, SecretFingerprints.Builder builder) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        builder.add(Base64.getEncoder().encodeToString(bytes));
        builder.add(Base64.getEncoder().withoutPadding().encodeToString(bytes));
        builder.add(Base64.getUrlEncoder().encodeToString(bytes));
        builder.add(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        try {
            String decoded = utf8(Base64.getDecoder().decode(value));
            if (!decoded.isEmpty() && decoded.chars().allMatch(c -> c >= 32 && c != 127)) {
                builder.add(decoded);
                collectParts(decoded, builder);
            }
        } catch (UnsafeInput | IllegalArgumentException ignored) { /* Not a supported textual encoding. */ }
    }

    private static void collectParts(String value, SecretFingerprints.Builder builder) {
        // Cookie pairs and Basic user:password, including quoted cookie values.
        final List<String> cookieParts;
        try { cookieParts = parts(value, ";\r\n", MAX_NODES); }
        catch (UnsafeInput ignored) { builder.uncertain(); return; }
        for (String part : cookieParts) {
            int eq = part.indexOf('=');
            if (eq >= 0) {
                String item = part.substring(eq + 1).trim();
                if (item.length() > 1 && item.startsWith("\"") && item.endsWith("\"")) item = item.substring(1, item.length() - 1);
                builder.add(item);
                encodedVariants(item, builder);
            }
        }
        int colon = value.indexOf(':');
        if (colon >= 0) {
            String user = value.substring(0, colon);
            String password = value.substring(colon + 1);
            builder.add(user);
            builder.add(password);
            encodedVariants(user, builder);
            encodedVariants(password, builder);
        }
    }

    private static void discoverText(String value, SecretFingerprints.Builder builder, int depth) {
        if (value == null || value.isEmpty() || value.equals(REDACTED)) return;
        try {
            if (depth > 3) throw new UnsafeInput();
            String decoded = normalize(value, false);
            if (decoded.contains("://")) { discoverUrl(decoded, builder); return; }
            Matcher assignment = ASSIGNMENT.matcher(decoded);
            while (assignment.find()) {
                String secret = assignment.group(2) != null ? assignment.group(2)
                        : assignment.group(3) != null ? assignment.group(3) : assignment.group(4);
                collectCredential(secret, builder);
            }
            Matcher auth = AUTH.matcher(decoded);
            while (auth.find()) collectCredential(auth.group(), builder);
            String trimmed = decoded.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                if (depth >= 3) throw new UnsafeInput();
                discoverJson(parseJson(trimmed), builder, 0, new int[1], depth + 1);
            } else if (decoded.indexOf('=') >= 0) {
                // Embedded form data is interpreted too; no silently partial nested parsing.
                if (depth >= 3) throw new UnsafeInput();
                discoverPairs(parseForm(decoded), builder, depth + 1);
            }
        } catch (UnsafeInput | RuntimeException ignored) { builder.uncertain(); }
    }

    private static JsonNode scrubJson(JsonNode node, SecretFingerprints secrets, int depth) {
        if (depth > MAX_DEPTH) return TextNode.valueOf(OMITTED);
        if (node.isObject()) {
            ObjectNode out = Json.MAPPER.createObjectNode();
            node.properties().forEach(field -> out.set(text(field.getKey(), secrets), sensitive(field.getKey())
                    ? TextNode.valueOf(REDACTED) : scrubJson(field.getValue(), secrets, depth + 1)));
            return out;
        }
        if (node.isArray()) {
            ArrayNode out = Json.MAPPER.createArrayNode();
            for (JsonNode item : node) out.add(scrubJson(item, secrets, depth + 1));
            return out;
        }
        if (node.isTextual()) return TextNode.valueOf(scrubScalar(node.textValue(), secrets, depth));
        if (!node.isNull() && !secrets.mask(node.asText()).equals(node.asText())) return TextNode.valueOf(REDACTED);
        return node.deepCopy();
    }

    private static String scrubScalar(String value, SecretFingerprints secrets, int depth) {
        if (value.equals(REDACTED)) return value;
        try {
            String normalized = normalize(value, false);
            String trimmed = normalized.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) return jsonString(scrubJson(parseJson(trimmed), secrets, depth + 1));
            if (normalized.indexOf('=') >= 0) return renderPairs(parseForm(normalized), secrets);
            return text(normalized, secrets, false);
        } catch (UnsafeInput | RuntimeException ignored) { return OMITTED; }
    }

    private static String renderPairs(List<Pair> pairs, SecretFingerprints secrets) {
        StringBuilder out = new StringBuilder();
        for (Pair pair : pairs) {
            if (!out.isEmpty()) out.append('&');
            out.append(component(text(pair.name, secrets))).append('=');
            out.append(component(sensitive(pair.name) ? REDACTED : scrubScalar(pair.value, secrets, 0)));
        }
        return out.toString();
    }

    static boolean sensitive(String name) {
        if (name == null) return true;
        final String normalized;
        try { normalized = normalize(name, false).toLowerCase(Locale.ROOT); }
        catch (UnsafeInput ignored) { return true; }
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < normalized.length(); i++) {
            char ch = normalized.charAt(i);
            if (ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') key.append(ch);
        }
        String k = key.toString();
        for (String word : List.of("auth", "cookie", "token", "jwt", "nonce", "password", "passwd", "secret", "apikey",
                "accesskey", "credential", "session", "csrf", "xsrf", "privatekey", "signature", "otp", "grant")) {
            if (k.contains(word)) return true;
        }
        return k.equals("pwd") || k.equals("key") || k.equals("pin") || k.equals("code") || k.equals("sig")
                || k.endsWith("pwd") || k.endsWith("pin") || k.endsWith("code") || k.endsWith("key");
    }

    private static JsonNode parseJson(String text) throws UnsafeInput {
        try {
            if (text.length() > MAX_INPUT) throw new UnsafeInput();
            JsonNode node = Json.MAPPER.readTree(text);
            if (node == null) throw new UnsafeInput();
            return node;
        } catch (Exception ignored) { throw new UnsafeInput(); }
    }
    private static String jsonString(JsonNode node) {
        try { return Json.MAPPER.writeValueAsString(node); }
        catch (Exception ignored) { return OMITTED; }
    }
    private static List<Pair> parseForm(String text) throws UnsafeInput {
        if (text.length() > MAX_INPUT) throw new UnsafeInput();
        List<Pair> result = new ArrayList<>();
        if (text.isEmpty()) return result;
        for (String part : parts(text, "&", MAX_NODES)) {
            if (result.size() >= MAX_NODES || part.isEmpty()) throw new UnsafeInput();
            int equals = part.indexOf('=');
            result.add(new Pair(normalize(equals < 0 ? part : part.substring(0, equals), true),
                    normalize(equals < 0 ? "" : part.substring(equals + 1), true)));
        }
        return result;
    }
    private static List<String> parts(String value, String delimiters, int maximum) throws UnsafeInput {
        List<String> result = new ArrayList<>();
        int start = 0;
        for (int i = 0; i <= value.length(); i++) {
            if (i == value.length() || delimiters.indexOf(value.charAt(i)) >= 0) {
                if (result.size() >= maximum) throw new UnsafeInput();
                result.add(value.substring(start, i));
                start = i + 1;
            }
        }
        return result;
    }
    private static String first(String value, char separator) {
        int end = value.indexOf(separator);
        return end < 0 ? value : value.substring(0, end);
    }
    private static URI parseUrl(String value) throws UnsafeInput {
        if (value == null || value.length() > MAX_INPUT) throw new UnsafeInput();
        try {
            URI uri = URI.create(value);
            if (uri.getHost() == null || !(uri.getScheme().equalsIgnoreCase("https") || uri.getScheme().equalsIgnoreCase("http"))
                    || uri.getPort() > 65535 || uri.getPort() < -1) throw new UnsafeInput();
            return uri;
        } catch (IllegalArgumentException | NullPointerException ignored) { throw new UnsafeInput(); }
    }
    private static String component(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
    private static boolean headerName(String name) {
        if (name.isEmpty() || name.length() > 128) return false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) return false;
        }
        return true;
    }
    private static String mime(String contentType) {
        String value = first(contentType, ';').trim().toLowerCase(Locale.ROOT);
        if (value.length() > 128 || !value.chars().allMatch(c -> c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || "/.+-".indexOf(c) >= 0)) return "application/octet-stream";
        return value.isEmpty() ? "application/octet-stream" : value;
    }
    private static boolean supportedCharset(String contentType) {
        String lower = contentType.toLowerCase(Locale.ROOT).replace(" ", "").replace("\"", "");
        int start = lower.indexOf("charset=");
        if (start < 0) return true;
        if (lower.indexOf("charset=", start + 8) >= 0) return false;
        String charset = first(lower.substring(start + 8), ';');
        return charset.equals("utf-8") || charset.equals("utf8") || charset.equals("us-ascii");
    }
    private static String inlineMask(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        StringBuilder out = new StringBuilder();
        int previous = 0;
        while (matcher.find()) {
            out.append(text, previous, matcher.start()).append(matcher.group(1)).append('=').append(REDACTED);
            previous = matcher.end();
        }
        return previous == 0 ? text : out.append(text, previous, text.length()).toString();
    }

    /** At most three strict percent/Unicode escape decoding rounds; never partial decoding. */
    private static String normalize(String value, boolean plusSpace) throws UnsafeInput {
        if (value.length() > MAX_INPUT) throw new UnsafeInput();
        String current = value;
        for (int round = 0; round < 3; round++) {
            String next = unicode(percent(current, plusSpace));
            if (next.equals(current)) return current;
            current = next;
        }
        if (current.indexOf('%') >= 0 || current.contains("\\u")) throw new UnsafeInput();
        return current;
    }
    private static String percent(String value, boolean plusSpace) throws UnsafeInput {
        if (value.indexOf('%') < 0 && (!plusSpace || value.indexOf('+') < 0)) return value;
        byte[] input = value.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(input.length);
        for (int i = 0; i < input.length; i++) {
            int c = input[i] & 255;
            if (c == '%') {
                if (i + 2 >= input.length) throw new UnsafeInput();
                int hi = Character.digit((char) input[++i], 16);
                int lo = Character.digit((char) input[++i], 16);
                if (hi < 0 || lo < 0) throw new UnsafeInput();
                out.write(hi * 16 + lo);
            } else out.write(plusSpace && c == '+' ? ' ' : c);
        }
        return utf8(out.toByteArray());
    }
    private static String unicode(String value) throws UnsafeInput {
        if (!value.contains("\\u")) return value;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '\\' && i + 1 < value.length() && value.charAt(i + 1) == 'u') {
                if (i + 5 >= value.length()) throw new UnsafeInput();
                int code = 0;
                for (int j = 0; j < 4; j++) {
                    int digit = Character.digit(value.charAt(i + 2 + j), 16);
                    if (digit < 0) throw new UnsafeInput();
                    code = code * 16 + digit;
                }
                out.append((char) code);
                i += 5;
            } else out.append(value.charAt(i));
        }
        return out.toString();
    }
    private static String utf8(byte[] bytes) throws UnsafeInput {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ignored) { throw new UnsafeInput(); }
    }

    static TrafficEntry.Message bound(TrafficEntry.Message message, int budget) {
        List<Header> headers = new ArrayList<>();
        int used = 1;
        boolean cut = message.truncated();
        for (Header header : message.headers()) {
            int size = bytes(header.name()) + bytes(header.value()) + 3;
            if (used + size + bytes(TRUNCATED) > budget) { cut = true; break; }
            used += size;
            headers.add(header);
        }
        String body = limit(message.body(), Math.max(0, budget - used));
        if (!body.equals(message.body())) cut = true;
        return new TrafficEntry.Message(headers, body, message.mimeType(), message.bodyOmitted(), cut, message.present());
    }
    static String limit(String value, int byteBudget) {
        if (bytes(value) <= byteBudget) return value;
        if (byteBudget < bytes(TRUNCATED)) return "";
        int budget = byteBudget - bytes(TRUNCATED);
        int used = 0;
        int end = 0;
        while (end < value.length()) {
            int code = value.codePointAt(end);
            int size = code <= 0x7f ? 1 : code <= 0x7ff ? 2 : code <= 0xffff ? 3 : 4;
            if (used + size > budget) break;
            used += size;
            end += Character.charCount(code);
        }
        return value.substring(0, end) + TRUNCATED;
    }
    static int bytes(String text) { return text.getBytes(StandardCharsets.UTF_8).length; }
    private static final class UnsafeInput extends Exception {
        private static final long serialVersionUID = 1L;
    }
}
