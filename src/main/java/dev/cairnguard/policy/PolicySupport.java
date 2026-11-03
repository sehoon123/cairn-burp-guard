package dev.cairnguard.policy;

import java.io.ByteArrayOutputStream;
import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/** Package-private, network-free bounds and canonicalization helpers. */
final class PolicySupport {
    static final int MAX_URL = 16_384;
    static final int MAX_HEADERS = 256;
    static final int MAX_HEADER_CHARS = 65_536;
    static final int MAX_PAIRS = 1_024;
    static final int MAX_JSON_NODES = 4_096;
    static final int MAX_JSON_DEPTH = 32;
    static final int MAX_DECODE_ROUNDS = 3;
    static final int MAX_PATTERN = 2_048;
    static final int MAX_PROGRAM = 4_096;

    private PolicySupport() {}

    static final class Failure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Failure(String category) { super(category, null, false, false); }
    }

    static Failure fail(String category) { return new Failure(category); }

    /** Bounds aggregate expanded text as well as aggregate rule/scope matching work. */
    static final class Budget {
        private long text;
        private int views;
        private long work;

        void text(String value) {
            text += value.length();
            if (++views > 32_768 || text > 16L * 1_048_576) throw fail("INSPECTION_LIMIT");
        }

        void work(int length, int weight) {
            work += (long) Math.max(1, length) * Math.max(1, weight);
            if (work > 64L * 1_048_576) throw fail("INSPECTION_LIMIT");
        }
    }

    static boolean token(String value) {
        if (value == null || value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) return false;
        }
        return true;
    }

    static boolean cleanUnicode(String value, boolean multiline) {
        if (value == null) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x7f && c <= 0x9f || c < 0x20 && !(multiline && (c == '\n' || c == '\r' || c == '\t')))
                return false;
            if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) return false;
            } else if (Character.isLowSurrogate(c)) return false;
        }
        return true;
    }

    static String utf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw fail("INVALID_TEXT_ENCODING");
        }
    }

    /** Strict recursive UTF-8 percent decoding. A remaining/invalid escape is never silently ignored. */
    static List<String> views(String raw, boolean plusSpace, boolean multiline, Budget budget) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        String current = raw;
        for (int round = 0; ; round++) {
            if (!cleanUnicode(current, multiline)) throw fail("INVALID_TEXT_ENCODING");
            if (result.add(current)) budget.text(current);
            if (current.indexOf('%') < 0 && (!plusSpace || current.indexOf('+') < 0)) break;
            if (round == MAX_DECODE_ROUNDS) throw fail("ENCODING_DEPTH_EXCEEDED");
            current = decode(current, plusSpace);
        }
        return List.copyOf(result);
    }

    private static String decode(String value, boolean plusSpace) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length();) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 >= value.length()) throw fail("MALFORMED_PERCENT_ENCODING");
                int hi = hex(value.charAt(i + 1)), lo = hex(value.charAt(i + 2));
                if (hi < 0 || lo < 0) throw fail("MALFORMED_PERCENT_ENCODING");
                int first = hi * 16 + lo;
                if (first < 0x80) {
                    out.append((char) first);
                    i += 3;
                    continue;
                }
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                while (i < value.length() && value.charAt(i) == '%') {
                    if (i + 2 >= value.length()) throw fail("MALFORMED_PERCENT_ENCODING");
                    hi = hex(value.charAt(i + 1));
                    lo = hex(value.charAt(i + 2));
                    if (hi < 0 || lo < 0) throw fail("MALFORMED_PERCENT_ENCODING");
                    bytes.write(hi * 16 + lo);
                    i += 3;
                }
                out.append(utf8(bytes.toByteArray()));
            } else {
                out.append(c == '+' && plusSpace ? ' ' : c);
                i++;
            }
        }
        return out.toString();
    }

    static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static List<String> parts(String input, char separator) {
        List<String> result = new ArrayList<>();
        int start = 0;
        for (int i = 0; i <= input.length(); i++) {
            if (i == input.length() || input.charAt(i) == separator) {
                result.add(input.substring(start, i));
                start = i + 1;
            }
        }
        return result;
    }

    static int port(String value) {
        if (value.isEmpty() || value.length() > 5) throw fail("INVALID_AUTHORITY");
        int result = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') throw fail("INVALID_AUTHORITY");
            result = result * 10 + c - '0';
        }
        if (result < 1 || result > 65_535) throw fail("INVALID_AUTHORITY");
        return result;
    }

    record Authority(String host, int port) {}

    static Authority authority(String input, int defaultPort) {
        if (input == null || input.isEmpty() || input.length() > 320) throw fail("INVALID_AUTHORITY");
        String host;
        int port = defaultPort;
        if (input.charAt(0) == '[') {
            int end = input.indexOf(']');
            if (end < 0) throw fail("INVALID_AUTHORITY");
            host = input.substring(0, end + 1);
            if (end + 1 < input.length()) {
                if (input.charAt(end + 1) != ':') throw fail("INVALID_AUTHORITY");
                port = port(input.substring(end + 2));
            }
        } else {
            int colon = input.indexOf(':');
            if (colon != input.lastIndexOf(':')) throw fail("INVALID_AUTHORITY");
            host = colon < 0 ? input : input.substring(0, colon);
            if (colon >= 0) port = port(input.substring(colon + 1));
        }
        return new Authority(host(host), port);
    }

    /** Canonicalizes IDNs and numeric addresses without DNS or InetAddress calls. */
    static String host(String input) {
        if (input == null || input.isEmpty() || input.length() > 255 || !cleanUnicode(input, false))
            throw fail("INVALID_HOST");
        String host = input;
        if (host.startsWith("[")) {
            if (!host.endsWith("]")) throw fail("INVALID_HOST");
            host = host.substring(1, host.length() - 1);
            if (host.indexOf(':') < 0) throw fail("INVALID_HOST");
        }
        if (host.indexOf(':') >= 0) return ipv6(host);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || host.endsWith(".")) throw fail("INVALID_HOST");
        String ascii;
        try { ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException e) { throw fail("INVALID_HOST"); }
        if (ascii.isEmpty() || ascii.length() > 253) throw fail("INVALID_HOST");
        boolean numeric = true;
        for (int i = 0; i < ascii.length(); i++) {
            char c = ascii.charAt(i);
            if (!(c >= '0' && c <= '9' || c == '.')) numeric = false;
        }
        if (numeric) {
            ipv4(ascii);
            return ascii;
        }
        for (String label : parts(ascii, '.')) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-"))
                throw fail("INVALID_HOST");
            // IDN maps some Unicode separators; verify every resulting ASCII label explicitly.
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')) throw fail("INVALID_HOST");
            }
        }
        // Reject inet_aton-style hexadecimal/short IPv4 aliases, including mixed dotted forms.
        boolean numericAlias = true;
        for (String label : parts(ascii, '.')) {
            int start = label.startsWith("0x") ? 2 : 0;
            if (start == label.length()) { numericAlias = false; break; }
            for (int i = start; i < label.length(); i++) {
                char c = label.charAt(i);
                if (start == 2 ? hex(c) < 0 : c < '0' || c > '9') numericAlias = false;
            }
        }
        if (numericAlias) throw fail("INVALID_HOST");
        return ascii;
    }

    private static int[] ipv4(String value) {
        List<String> parts = parts(value, '.');
        if (parts.size() != 4) throw fail("INVALID_HOST");
        int[] bytes = new int[4];
        for (int i = 0; i < 4; i++) {
            String part = parts.get(i);
            if (part.isEmpty() || part.length() > 3 || part.length() > 1 && part.charAt(0) == '0')
                throw fail("INVALID_HOST");
            int n = 0;
            for (int j = 0; j < part.length(); j++) {
                char c = part.charAt(j);
                if (c < '0' || c > '9') throw fail("INVALID_HOST");
                n = n * 10 + c - '0';
            }
            if (n > 255) throw fail("INVALID_HOST");
            bytes[i] = n;
        }
        return bytes;
    }

    private static String ipv6(String value) {
        if (value.indexOf('%') >= 0 || value.indexOf('[') >= 0 || value.indexOf(']') >= 0)
            throw fail("INVALID_HOST");
        int doubleColon = value.indexOf("::");
        if (doubleColon != value.lastIndexOf("::")) throw fail("INVALID_HOST");
        String left = doubleColon < 0 ? value : value.substring(0, doubleColon);
        String right = doubleColon < 0 ? "" : value.substring(doubleColon + 2);
        List<Integer> before = groups(left, doubleColon < 0);
        List<Integer> after = groups(right, true);
        int count = before.size() + after.size();
        if (doubleColon < 0 ? count != 8 : count >= 8) throw fail("INVALID_HOST");
        List<Integer> all = new ArrayList<>(before);
        if (doubleColon >= 0) for (int i = count; i < 8; i++) all.add(0);
        all.addAll(after);
        StringBuilder canonical = new StringBuilder("[");
        for (int i = 0; i < all.size(); i++) {
            if (i > 0) canonical.append(':');
            canonical.append(Integer.toHexString(all.get(i)));
        }
        return canonical.append(']').toString();
    }

    private static List<Integer> groups(String value, boolean mayEndIpv4) {
        List<Integer> groups = new ArrayList<>();
        if (value.isEmpty()) return groups;
        List<String> tokens = parts(value, ':');
        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i);
            if (token.indexOf('.') >= 0) {
                if (!mayEndIpv4 || i != tokens.size() - 1) throw fail("INVALID_HOST");
                int[] bytes = ipv4(token);
                groups.add(bytes[0] * 256 + bytes[1]);
                groups.add(bytes[2] * 256 + bytes[3]);
            } else {
                if (token.isEmpty() || token.length() > 4) throw fail("INVALID_HOST");
                int n = 0;
                for (int j = 0; j < token.length(); j++) {
                    int digit = hex(token.charAt(j));
                    if (digit < 0) throw fail("INVALID_HOST");
                    n = n * 16 + digit;
                }
                groups.add(n);
            }
        }
        return groups;
    }
}
