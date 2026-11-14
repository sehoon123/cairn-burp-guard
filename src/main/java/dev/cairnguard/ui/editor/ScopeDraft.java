package dev.cairnguard.ui.editor;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.policy.PolicyEngine;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Authoring preserves a relation of tuple occurrences, never independent legacy port/path unions. */
final class ScopeDraft {
    static final int MAX_URL = 16_384;
    static final int MAX_HOST = 257;
    static final int MAX_PATTERN = 2_048;
    private static final int MAX_PROGRAM = 4_096;
    static final int MAX_PORT_TEXT = 2_048;
    static final int MAX_PATH_TEXT = 66_048;
    private static final String EXACT_END = "\\z";
    private static final String PREFIX_END = "(?:/.*)?\\z";
    private static final String SLASH_PREFIX_END = ".*\\z";

    enum PathMode {
        EXACT("정확히 이 경로만"), PREFIX("이 경로와 하위 경로"), ALL("모든 경로"), REGEX("고급: RE2 정규식");
        private final String label;
        PathMode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    record Input(boolean enabled, String host, String scheme, boolean allPorts, String portText,
                 PathMode pathMode, String pathText, String regexText) {}
    /** sourceIndex identifies the original occurrence; -1 is an explicitly new cell. */
    record Member(int sourceIndex, ScopeEntry entry) {}
    private final List<ScopeEntry> original;
    private final List<Integer> indices;
    private final List<Member> members;

    ScopeDraft(List<ScopeEntry> originalSection, List<Integer> selectedIndices) {
        original = List.copyOf(originalSection);
        Set<Integer> unique = new HashSet<>();
        for (Integer index : selectedIndices)
            if (index == null || index < 0 || index >= original.size() || !unique.add(index))
                throw invalid("편집할 대상 선택을 다시 확인하세요.");
        indices = selectedIndices.stream().sorted().toList();
        members = indices.stream().map(index -> new Member(index, original.get(index))).toList();
    }

    List<Member> members() { return members; }

    Optional<Input> compactInput() {
        if (members.isEmpty()) return Optional.of(new Input(true, "", "https", false, "443", PathMode.EXACT, "/", ""));
        Input first = input(members.getFirst().entry());
        if (members.size() == 1) return Optional.of(first);
        if (first.pathMode() == PathMode.REGEX) return Optional.empty();
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        LinkedHashSet<String> expressions = new LinkedHashSet<>();
        List<String> paths = new ArrayList<>();
        ScopeEntry head = members.getFirst().entry();
        for (Member member : members) {
            ScopeEntry entry = member.entry();
            Input next = input(entry);
            if (entry.enabled() != head.enabled() || !entry.host().equals(head.host()) || !entry.scheme().equals(head.scheme())
                    || next.pathMode() != first.pathMode()) return Optional.empty();
            ports.add(entry.port());
            if (expressions.add(entry.pathRegex())) paths.add(next.pathText());
        }
        if (ports.contains(0) && ports.size() != 1 || (long) ports.size() * expressions.size() != members.size()) return Optional.empty();
        int position = 0;
        for (int port : ports) for (String expression : expressions) {
            ScopeEntry expected = new ScopeEntry(head.enabled(), head.host(), head.scheme(), port, expression);
            if (!expected.equals(members.get(position++).entry())) return Optional.empty();
        }
        return Optional.of(new Input(first.enabled(), first.host(), first.scheme(), first.allPorts(),
                String.join(",", ports.stream().filter(port -> port != 0).map(String::valueOf).toList()),
                first.pathMode(), String.join("\n", paths), first.regexText()));
    }

    static Input input(ScopeEntry entry) {
        if (entry.host() == null || entry.scheme() == null || entry.pathRegex() == null
                || entry.host().length() > MAX_HOST || entry.pathRegex().length() > MAX_PATTERN)
            throw invalid("저장된 대상의 길이나 형식을 확인한 뒤 다시 여세요. 입력을 자동으로 자르지 않습니다.");
        String scheme = entry.scheme().toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https") || scheme.equals("any")) || entry.port() < 0 || entry.port() > 65_535)
            throw invalid("저장된 대상의 연결 방식과 포트를 확인한 뒤 다시 여세요.");
        LiteralPath literal = decodeLiteral(entry.pathRegex());
        PathMode mode = entry.pathRegex().isEmpty() ? PathMode.ALL : literal == null ? PathMode.REGEX : literal.mode();
        return new Input(entry.enabled(), entry.host(), entry.scheme(), entry.port() == 0,
                entry.port() == 0 ? "" : Integer.toString(entry.port()), mode,
                literal == null ? "/" : literal.path(), literal == null ? entry.pathRegex() : "");
    }

    List<Member> product(Input input) {
        if (compactInput().isEmpty()) throw invalid("기존 항목의 포트·경로 짝은 개별 항목에서 편집하세요.");
        List<Integer> ports = input.allPorts() ? List.of(0) : parsePorts(input.portText());
        List<String> expressions = expressions(input);
        checkCapacity((long) ports.size() * expressions.size());
        List<Member> result = new ArrayList<>();
        for (int port : ports) for (String expression : expressions) {
            int sourceIndex = -1;
            for (Member old : members) if (old.entry().port() == port && old.entry().pathRegex().equals(expression)) {
                sourceIndex = old.sourceIndex(); break;
            }
            result.add(new Member(sourceIndex, new ScopeEntry(input.enabled(), input.host(), input.scheme(), port, expression)));
        }
        return List.copyOf(result);
    }

    Member member(int sourceIndex, Input input) {
        if (!indices.contains(sourceIndex)) throw invalid("편집할 원래 항목을 다시 선택하세요.");
        List<Integer> ports = input.allPorts() ? List.of(0) : parsePorts(input.portText());
        List<String> expressions = expressions(input);
        if (ports.size() != 1 || expressions.size() != 1)
            throw invalid("개별 항목에는 포트 하나와 경로 조건 하나만 입력하세요. 기존 포트·경로 짝을 합치지 않습니다.");
        return new Member(sourceIndex, new ScopeEntry(input.enabled(), input.host(), input.scheme(), ports.getFirst(), expressions.getFirst()));
    }

    List<ScopeEntry> section(List<Member> proposed) {
        checkCapacity(proposed.size());
        Set<Integer> seen = new HashSet<>();
        for (Member member : proposed) {
            if (member == null || member.entry() == null || member.sourceIndex() < -1
                    || member.sourceIndex() >= 0 && (!indices.contains(member.sourceIndex()) || !seen.add(member.sourceIndex())))
                throw invalid("원래 대상의 위치가 중복되거나 바뀌었습니다. 창을 닫고 다시 선택하세요.");
        }
        List<ScopeEntry> result = new ArrayList<>();
        for (int index = 0; index < original.size(); index++) {
            if (!indices.contains(index)) result.add(original.get(index));
            else for (Member member : proposed) if (member.sourceIndex() == index) result.add(member.entry());
        }
        for (Member member : proposed) if (member.sourceIndex() == -1) result.add(member.entry());
        return List.copyOf(result);
    }

    private void checkCapacity(long count) {
        if (count + original.size() - indices.size() > 256)
            throw invalid("포트 × 경로 조합과 남는 항목을 합쳐 대상 목록마다 256개 이내로 줄이세요. 일부만 저장하지 않습니다.");
    }

    private static List<String> expressions(Input input) {
        validateHost(input.host());
        String scheme = input.scheme() == null ? "" : input.scheme().toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https") || scheme.equals("any")))
            throw invalid("연결 방식을 명시적으로 선택하세요.");
        if (input.pathMode() == null) throw invalid("경로 방식을 명시적으로 선택하세요.");
        List<String> expressions;
        if (input.pathMode() == PathMode.ALL) expressions = List.of("");
        else if (input.pathMode() == PathMode.REGEX) {
            if (input.regexText() == null || input.regexText().isEmpty())
                throw invalid("고급 정규식을 입력하세요. 경로 제한을 없애려면 ‘모든 경로’를 명시적으로 선택하세요.");
            expressions = List.of(input.regexText());
        } else expressions = parsePaths(input.pathText()).stream().map(path -> input.pathMode() == PathMode.EXACT ? exact(path) : prefix(path)).toList();
        for (String expression : expressions) validateRegex(expression);
        return expressions;
    }

    static List<Integer> parsePorts(String text) {
        if (text == null || text.isEmpty() || text.length() > MAX_PORT_TEXT)
            throw invalid("포트 목록을 쉼표로 구분해 입력하세요. 모든 포트는 별도로 선택해야 합니다.");
        String[] tokens = text.split(",", -1);
        List<Integer> result = new ArrayList<>();
        Set<Integer> unique = new HashSet<>();
        for (int index = 0; index < tokens.length; index++) {
            String token = tokens[index];
            int start = 0, end = token.length();
            while (start < end && (token.charAt(start) == ' ' || token.charAt(start) == '\t')) start++;
            while (end > start && (token.charAt(end - 1) == ' ' || token.charAt(end - 1) == '\t')) end--;
            int port;
            try { port = parsePort(token.substring(start, end)); }
            catch (FormValidationException error) { throw invalid("포트 " + (index + 1) + "번째 항목에 1~65535의 ASCII 숫자만 입력하세요. 빈 항목·범위·줄바꿈은 사용할 수 없습니다."); }
            if (!unique.add(port)) throw invalid("포트 " + (index + 1) + "번째 항목이 중복됩니다. 같은 숫자는 한 번만 입력하세요.");
            result.add(port);
        }
        return List.copyOf(result);
    }

    static List<String> parsePaths(String text) {
        if (text == null || text.isEmpty() || text.length() > MAX_PATH_TEXT)
            throw invalid("경로를 한 줄에 하나씩 입력하세요. 모든 경로는 별도로 선택해야 합니다.");
        for (int index = 0; index < text.length(); index++) if (text.charAt(index) == '\r') {
            if (index + 1 >= text.length() || text.charAt(index + 1) != '\n') throw invalid("경로 줄바꿈은 LF 또는 CRLF로 입력하세요. 단독 CR은 사용할 수 없습니다.");
            index++;
        }
        String lines = text.replace("\r\n", "\n");
        if (lines.endsWith("\n")) lines = lines.substring(0, lines.length() - 1);
        String[] tokens = lines.split("\n", -1);
        Set<String> unique = new HashSet<>();
        for (int index = 0; index < tokens.length; index++) {
            try { validateLiteralPath(tokens[index]); }
            catch (FormValidationException error) { throw invalid("경로 " + (index + 1) + "번째 줄: " + error.getMessage()); }
            if (!unique.add(tokens[index])) throw invalid("경로 " + (index + 1) + "번째 줄이 중복됩니다. 같은 경로는 한 번만 입력하세요.");
        }
        return List.of(tokens);
    }

    static ScopeEntry parseUrl(String input, boolean enabled) {
        if (input.isBlank() || input.length() > MAX_URL || !clean(input, false))
            throw invalid("공백 없는 http:// 또는 https:// 전체 주소를 입력하고 다시 반영하세요.");
        URI uri;
        try { uri = new URI(input); }
        catch (URISyntaxException error) { throw invalid("URL 형식을 확인하세요. 공백과 잘못된 %인코딩을 수정한 뒤 다시 반영하세요."); }
        if (uri.getRawUserInfo() != null || uri.getRawAuthority() != null && uri.getRawAuthority().indexOf('@') >= 0)
            throw invalid("사용자 정보가 있는 URL은 변환하지 않습니다. 사용자 정보를 직접 제거한 뒤 범위를 확인하세요.");
        if (uri.getRawQuery() != null)
            throw invalid("쿼리가 있는 URL은 변환하지 않습니다. 쿼리는 범위에 저장할 수 없으므로 직접 제거하거나 별도 규칙을 만드세요.");
        if (uri.getRawFragment() != null)
            throw invalid("#조각이 있는 URL은 변환하지 않습니다. 조각을 직접 제거한 뒤 필요한 경로인지 확인하세요.");
        String protocol = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.isOpaque() || !(protocol.equals("http") || protocol.equals("https")) || uri.getRawAuthority() == null)
            throw invalid("http:// 또는 https://로 시작하는 전체 주소를 입력하세요.");
        String authority = uri.getRawAuthority();
        String targetHost;
        String explicitPort = null;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) throw invalid("IPv6 주소를 [주소] 형식으로 입력하세요.");
            targetHost = authority.substring(0, close + 1);
            if (close + 1 < authority.length()) {
                if (authority.charAt(close + 1) != ':') throw invalid("URL의 호스트와 포트 형식을 확인하세요.");
                explicitPort = authority.substring(close + 2);
            }
        } else {
            int colon = authority.indexOf(':');
            if (colon != authority.lastIndexOf(':')) throw invalid("IPv6 주소를 [주소] 형식으로 입력하세요.");
            targetHost = colon < 0 ? authority : authority.substring(0, colon);
            if (colon >= 0) explicitPort = authority.substring(colon + 1);
        }
        if (targetHost.indexOf('*') >= 0) throw invalid("URL에는 와일드카드를 사용할 수 없습니다. 호스트 폼에서 범위를 명시적으로 선택하세요.");
        validateHost(targetHost);
        int targetPort = explicitPort == null ? protocol.equals("https") ? 443 : 80 : parsePort(explicitPort);
        String targetPath = uri.getRawPath();
        if (targetPath == null || targetPath.isEmpty()) targetPath = "/";
        validateLiteralPath(targetPath);
        String expression = exact(targetPath); // Raw spelling is never decoded, normalized, or replaced with a prefix.
        validateRegex(expression);
        return new ScopeEntry(enabled, targetHost, protocol, targetPort, expression);
    }

    static String validateHost(String value) {
        if (value == null || value.length() > MAX_HOST) throw invalid("호스트를 257자 이내로 입력하세요.");
        boolean wildcard = value.startsWith("*.");
        String canonical;
        try { canonical = PolicyEngine.canonicalHost(wildcard ? value.substring(2) : value); }
        catch (IllegalArgumentException error) { throw invalid("호스트만 입력하세요. URL·경로·포트·공백은 빼고, 하위 도메인은 *.example.test 형식으로 입력하세요."); }
        if (wildcard) {
            boolean numeric = true;
            for (int i = 0; i < canonical.length(); i++) {
                char c = canonical.charAt(i);
                if (!(c >= '0' && c <= '9' || c == '.')) numeric = false;
            }
            if (canonical.startsWith("[") || numeric) throw invalid("IP 주소에는 *.를 사용할 수 없습니다. 정확한 IP 주소를 입력하세요.");
        }
        return canonical;
    }

    private static int parsePort(String value) {
        if (value == null || value.isEmpty() || value.length() > 5) throw invalid("포트를 1~65535로 입력하거나 ‘모든 포트’를 직접 선택하세요.");
        int result = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') throw invalid("포트에는 1~65535의 정수만 입력하세요.");
            result = result * 10 + c - '0';
        }
        if (result < 1 || result > 65_535) throw invalid("포트를 1~65535로 입력하거나 ‘모든 포트’를 직접 선택하세요.");
        return result;
    }

    private static void validateLiteralPath(String value) {
        if (value == null || value.isEmpty() || !value.startsWith("/") || !clean(value, false))
            throw invalid("경로를 /로 시작하도록 입력하세요. 제어 문자 없이 실제 경로만 입력하세요.");
        if (value.length() > MAX_PATTERN) throw invalid("경로는 2,048자 이내로 줄여 다시 입력하세요.");
        if (value.indexOf('?') >= 0 || value.indexOf('#') >= 0 || value.indexOf('\\') >= 0 || value.indexOf(';') >= 0)
            throw invalid("경로에는 쿼리·#조각·역슬래시·세미콜론을 넣지 마세요. 경로만 확인해 입력하세요.");
        int start = 0;
        for (int i = 0; i <= value.length(); i++) {
            if (i != value.length() && value.charAt(i) != '/') continue;
            int length = i - start;
            if (length == 1 && value.charAt(start) == '.' || length == 2 && value.charAt(start) == '.' && value.charAt(start + 1) == '.')
                throw invalid(". 또는 .. 경로는 모호해서 사용할 수 없습니다. 실제 경로를 확인해 직접 입력하세요.");
            start = i + 1;
        }
        try { new URI("https://example.test" + value); }
        catch (URISyntaxException error) { throw invalid("공백이나 잘못된 %인코딩이 없는 실제 URL 경로를 입력하세요."); }
    }

    private static void validateRegex(String expression) {
        if (expression.length() > MAX_PATTERN || !clean(expression, true))
            throw invalid("저장할 경로 식이 너무 길거나 제어 문자가 있습니다. 경로·정규식을 줄여 다시 입력하세요.");
        if (expression.isEmpty()) return;
        try {
            if (Pattern.compile(expression).programSize() > MAX_PROGRAM)
                throw invalid("정규식이 너무 복잡합니다. 반복과 선택을 줄이거나 일반 경로 방식을 사용하세요.");
        } catch (FormValidationException error) { throw error; }
        catch (PatternSyntaxException | IllegalArgumentException error) {
            throw invalid("RE2 정규식을 확인하세요. 역참조·전후방 탐색은 지원하지 않습니다. 일반 경로 방식도 사용할 수 있습니다.");
        }
    }

    // RE2/J's Pattern.quote escapes individual characters; use a recognizable, reversible quoted block instead.
    private static String quote(String value) { return "\\Q" + value.replace("\\E", "\\E\\\\E\\Q") + "\\E"; }
    private static String exact(String value) { return "\\A" + quote(value) + EXACT_END; }
    private static String prefix(String value) { return "\\A" + quote(value) + (value.endsWith("/") ? SLASH_PREFIX_END : PREFIX_END); }
    record LiteralPath(PathMode mode, String path) {}

    static LiteralPath decodeLiteral(String expression) {
        if (expression == null || expression.length() > MAX_PATTERN || !expression.startsWith("\\A")) return null;
        for (String end : new String[]{PREFIX_END, SLASH_PREFIX_END, EXACT_END}) {
            if (!expression.endsWith(end) || expression.length() < end.length() + 6) continue;
            String quoted = expression.substring(2, expression.length() - end.length());
            if (!quoted.startsWith("\\Q") || !quoted.endsWith("\\E")) continue;
            String candidate = quoted.substring(2, quoted.length() - 2).replace("\\E\\\\E\\Q", "\\E");
            PathMode mode = end.equals(EXACT_END) ? PathMode.EXACT : PathMode.PREFIX;
            if (!(mode == PathMode.EXACT ? exact(candidate) : prefix(candidate)).equals(expression)) continue;
            try { validateLiteralPath(candidate); }
            catch (FormValidationException error) { continue; }
            return new LiteralPath(mode, candidate);
        }
        return null;
    }

    private static boolean clean(String value, boolean multiline) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x7f && c <= 0x9f || c < 0x20 && !(multiline && (c == '\n' || c == '\r' || c == '\t'))) return false;
            if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) return false;
            } else if (Character.isLowSurrogate(c)) return false;
        }
        return true;
    }

    private static FormValidationException invalid(String message) { return new FormValidationException(message); }
}
