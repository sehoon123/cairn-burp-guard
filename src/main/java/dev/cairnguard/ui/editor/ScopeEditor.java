package dev.cairnguard.ui.editor;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.policy.PolicyEngine;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Local, EDT-only scope form. A pasted URL changes nothing until the user chooses to fill the form. */
public final class ScopeEditor implements EditorForm<ScopeEntry> {
    private static final int MAX_URL = 16_384;
    private static final int MAX_HOST = 257; // The policy permits a 255-character host after the optional "*.".
    private static final int MAX_PATTERN = 2_048;
    private static final int MAX_PROGRAM = 4_096;
    private static final String EXACT_END = "\\z";
    private static final String PREFIX_END = "(?:/.*)?\\z";
    private static final String SLASH_PREFIX_END = ".*\\z";

    private enum Scheme {
        HTTPS("https", "HTTPS — 암호화 연결"), HTTP("http", "HTTP — 암호화하지 않는 연결"),
        ANY("any", "HTTP와 HTTPS 모두");
        final String value;
        final String label;
        Scheme(String value, String label) { this.value = value; this.label = label; }
        @Override public String toString() { return label; }
    }

    private enum PathMode {
        EXACT("정확히 이 경로만"), PREFIX("이 경로와 하위 경로"), ALL("모든 경로"), REGEX("고급: RE2 정규식");
        final String label;
        PathMode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    private final Map<String, String> rejectedInputs = new LinkedHashMap<>();
    private final FormPanel form;
    private final JScrollPane component;
    private final JTextField url;
    private final JButton fillUrl;
    private final JCheckBox enabled;
    private final JTextField host;
    private final JComboBox<Scheme> scheme;
    private final JCheckBox anyPort;
    private final JTextField port;
    private final JComboBox<PathMode> pathMode;
    private final JTextField path;
    private final JTextArea regex;
    private final JPanel pathCards;
    private final JLabel pathLabel;
    private final JTextArea pathGuidance;
    private final JTextArea preview;
    private final JTextArea message;
    private boolean loading = true;
    private String appliedUrl = "";
    private String loadedScheme = "https";

    public ScopeEditor(ScopeEntry initial) {
        requireEdt();
        form = named(new FormPanel(), "scope.form", "대상 범위 입력 폼");
        form.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        component = named(new JScrollPane(form), "scope.editor", "대상 범위 편집");
        component.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        component.setBorder(BorderFactory.createEmptyBorder());

        url = textField("scope.url", "붙여넣을 URL", MAX_URL, "URL은 16,384자 이내로 줄여 다시 입력하거나 ‘URL 비우기’를 누르세요.");
        fillUrl = named(new JButton(), "scope.fillUrl", "URL을 폼에 반영");
        fillUrl.putClientProperty("html.disable", Boolean.TRUE);
        fillUrl.setText("폼에 반영");
        JButton clearUrl = named(new JButton(), "scope.clearUrl", "URL 입력만 비우기 (대상 폼은 유지)");
        clearUrl.putClientProperty("html.disable", Boolean.TRUE);
        clearUrl.setText("URL 비우기");
        enabled = checkBox("scope.enabled", "이 대상 사용");
        host = textField("scope.host", "호스트 또는 명시적인 하위 도메인 패턴", MAX_HOST,
                "호스트는 257자 이내로 줄여 다시 입력하세요.");
        scheme = named(new JComboBox<>(Scheme.values()), "scope.scheme", "허용할 연결 방식");
        scheme.setRenderer(new LiteralRenderer());
        anyPort = checkBox("scope.anyPort", "모든 포트 (범위가 넓어짐)");
        port = textField("scope.port", "포트 번호 (1~65535)", 5, "포트는 1~65535의 숫자로 다시 입력하세요.");
        pathMode = named(new JComboBox<>(PathMode.values()), "scope.pathMode", "경로 비교 방식");
        pathMode.setRenderer(new LiteralRenderer());
        path = textField("scope.path", "정확한 경로 또는 하위 경로의 기준", MAX_PATTERN,
                "경로는 2,048자 이내로 줄여 다시 입력하세요.");
        regex = named(new JTextArea(3, 24), "scope.regex", "고급 RE2 경로 정규식");
        regex.setLineWrap(true);
        bound(regex, MAX_PATTERN, "정규식은 2,048자 이내로 줄여 다시 입력하세요.");
        pathCards = named(new JPanel(new CardLayout()), "scope.pathCards", "선택한 경로 입력");
        pathCards.add(path, "literal");
        pathCards.add(named(new JScrollPane(regex), "scope.regexScroll", "RE2 정규식 입력 영역"), "regex");
        pathCards.add(note("scope.allPaths", "모든 경로를 포함합니다. 경로 제한이 사라지므로 범위를 확인하세요."), "all");
        pathLabel = label("scope.path.label", "경로", path);
        pathGuidance = note("scope.pathGuidance", "");
        pathGuidance.getAccessibleContext().setAccessibleName("선택한 경로 방식 안내");
        pathGuidance.getAccessibleContext().setAccessibleDescription("경로 방식별 포함 및 제외 안내");
        preview = note("scope.preview", "");
        preview.getAccessibleContext().setAccessibleName("저장할 실제 대상 범위");
        preview.getAccessibleContext().setAccessibleDescription("호스트, 연결 방식, 포트, 경로와 저장할 정규식 전체");
        preview.setRows(7);
        preview.setFocusable(true); // The actual-scope preview remains selectable/copyable.
        preview.setOpaque(true);
        preview.setBackground(UIManager.getColor("TextArea.background"));
        preview.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        message = note("scope.message", "");
        message.setRows(2);
        message.getAccessibleContext().setAccessibleName("입력 확인 및 다음 행동");
        message.getAccessibleContext().setAccessibleDescription("입력 오류를 수정하거나 미리보기를 확인한 뒤 저장하세요.");

        addWide(0, note("scope.intro", "주소를 붙여넣고 ‘폼에 반영’을 누르거나, 아래 항목을 직접 입력하세요. 저장 전 실제 범위를 확인하세요."));
        JPanel urlRow = named(new JPanel(new BorderLayout(8, 0)), "scope.urlRow", "URL과 반영 버튼");
        urlRow.add(url, BorderLayout.CENTER);
        JPanel urlActions = named(new JPanel(new GridLayout(1, 2, 8, 0)), "scope.urlActions", "URL 반영 및 비우기");
        urlActions.add(fillUrl);
        urlActions.add(clearUrl);
        urlRow.add(urlActions, BorderLayout.LINE_END);
        addRow(1, label("scope.url.label", "URL (선택)", url), urlRow);
        addWide(2, note("scope.urlGuidance", "예: https://api.example.test/api/items — Enter로도 폼에 반영할 수 있습니다 (정책 저장 아님). 사용자 정보·?쿼리·#조각은 직접 제거해야 합니다."));
        addWide(3, message);
        addWide(4, enabled);
        addRow(5, label("scope.host.label", "호스트", host), host);
        addWide(6, note("scope.hostGuidance", "example.test는 그 호스트만 포함합니다. *.example.test는 하위 도메인만 포함하며 example.test 자체는 제외합니다. IP도 입력할 수 있습니다."));
        addRow(7, label("scope.scheme.label", "연결 방식", scheme), scheme);
        JPanel portRow = named(new JPanel(new GridBagLayout()), "scope.portRow", "포트 제한");
        GridBagConstraints p = constraints(0, 0);
        p.weightx = 1;
        portRow.add(port, p);
        p = constraints(1, 0);
        p.insets = new Insets(0, 8, 0, 0);
        portRow.add(anyPort, p);
        addRow(8, label("scope.port.label", "포트", port), portRow);
        addRow(9, label("scope.pathMode.label", "경로 범위", pathMode), pathMode);
        addRow(10, pathLabel, pathCards);
        addWide(11, pathGuidance);
        addWide(12, label("scope.preview.label", "저장될 실제 범위 미리보기", preview));
        addWide(13, named(new JScrollPane(preview), "scope.previewScroll", "실제 범위 미리보기 영역"));
        form.add(new JPanel(), filler(14));

        fillUrl.addActionListener(event -> fillFromUrl());
        url.addActionListener(event -> fillFromUrl()); // Consume Enter as explicit fill, never the dialog's Save.
        clearUrl.addActionListener(event -> {
            rejectedInputs.remove("scope.url");
            appliedUrl = "";
            url.setText("");
            refreshPreview();
        });
        enabled.addActionListener(event -> refreshPreview());
        scheme.addActionListener(event -> refreshPreview());
        anyPort.addActionListener(event -> { port.setEnabled(!anyPort.isSelected()); refreshPreview(); });
        pathMode.addActionListener(event -> { showPathMode(); refreshPreview(); });
        load(initial == null ? new ScopeEntry(true, "", "https", 443, exact("/")) : initial);
        loading = false;
        refreshPreview();
        int line = form.getFontMetrics(form.getFont()).getHeight();
        component.setPreferredSize(new Dimension(Math.min(880, Math.max(640, line * 36)), Math.min(620, line * 28)));
    }

    @Override public JComponent component() { requireEdt(); return component; }

    @Override public ScopeEntry value() {
        requireEdt();
        checkPendingInput();
        return formValue();
    }

    /** A bounded, plain-text list summary; the editor preview always shows the full stored expression. */
    public static String pathSummary(ScopeEntry entry) {
        if (entry == null) return "대상 없음";
        LiteralPath literal = decodeLiteral(entry.pathRegex());
        if (entry.pathRegex() != null && entry.pathRegex().isEmpty()) return "모든 경로";
        if (literal != null) return (literal.mode == PathMode.EXACT ? "정확한 경로 " : "하위 경로 ") + compact(literal.path, 64);
        return "고급 RE2 경로 (편집에서 전체 확인)";
    }

    public static String summary(ScopeEntry entry) {
        if (entry == null) return "대상 없음";
        String protocol = "any".equalsIgnoreCase(entry.scheme()) ? "HTTP·HTTPS" : compact(entry.scheme(), 5).toUpperCase(Locale.ROOT);
        return (entry.enabled() ? "켬" : "끔") + " · " + protocol + " · " + compact(entry.host(), 88)
                + " · " + (entry.port() == 0 ? "모든 포트" : "포트 " + entry.port()) + " · " + pathSummary(entry);
    }

    private void load(ScopeEntry entry) {
        if (entry.host() == null || entry.scheme() == null || entry.pathRegex() == null
                || entry.host().length() > MAX_HOST || entry.pathRegex().length() > MAX_PATTERN)
            throw invalid("저장된 대상의 길이나 형식을 확인한 뒤 다시 여세요. 입력을 자동으로 자르지 않습니다.");
        Scheme choice = null;
        for (Scheme candidate : Scheme.values()) if (candidate.value.equals(entry.scheme().toLowerCase(Locale.ROOT))) choice = candidate;
        if (choice == null || entry.port() < 0 || entry.port() > 65_535)
            throw invalid("저장된 대상의 연결 방식과 포트를 확인한 뒤 다시 여세요.");
        loadedScheme = entry.scheme();
        enabled.setSelected(entry.enabled());
        host.setText(entry.host());
        scheme.setSelectedItem(choice);
        anyPort.setSelected(entry.port() == 0);
        port.setText(entry.port() == 0 ? "" : Integer.toString(entry.port()));
        port.setEnabled(entry.port() != 0);
        LiteralPath literal = decodeLiteral(entry.pathRegex());
        path.setText(literal == null ? "/" : literal.path);
        regex.setText(literal == null ? entry.pathRegex() : "");
        pathMode.setSelectedItem(entry.pathRegex().isEmpty() ? PathMode.ALL : literal == null ? PathMode.REGEX : literal.mode);
        showPathMode();
    }

    private void fillFromUrl() {
        requireEdt();
        try {
            String rejected = rejectedInputs.get("scope.url");
            if (rejected != null) throw invalid(rejected);
            ScopeEntry next = parseUrl(url.getText(), enabled.isSelected());
            loading = true;
            rejectedInputs.clear();
            load(next);
            appliedUrl = url.getText();
            loading = false;
            refreshPreview();
        } catch (FormValidationException error) {
            loading = false;
            message.setText(error.getMessage());
        }
    }

    private static ScopeEntry parseUrl(String input, boolean enabled) {
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

    private ScopeEntry formValue() {
        String targetHost = host.getText();
        validateHost(targetHost);
        Scheme choice = (Scheme) scheme.getSelectedItem();
        String protocol = choice.value.equals(loadedScheme.toLowerCase(Locale.ROOT)) ? loadedScheme : choice.value;
        int targetPort = anyPort.isSelected() ? 0 : parsePort(port.getText());
        PathMode mode = (PathMode) pathMode.getSelectedItem();
        String expression;
        if (mode == PathMode.ALL) expression = "";
        else if (mode == PathMode.REGEX) {
            expression = regex.getText();
            if (expression.isEmpty()) throw invalid("고급 정규식을 입력하세요. 경로 제한을 없애려면 ‘모든 경로’를 명시적으로 선택하세요.");
        } else {
            validateLiteralPath(path.getText());
            expression = mode == PathMode.EXACT ? exact(path.getText()) : prefix(path.getText());
        }
        validateRegex(expression);
        return new ScopeEntry(enabled.isSelected(), targetHost, protocol, targetPort, expression);
    }

    private void checkPendingInput() {
        if (!rejectedInputs.isEmpty()) throw invalid(rejectedInputs.values().iterator().next());
        if (!url.getText().isEmpty() && !url.getText().equals(appliedUrl))
            throw invalid("붙여넣은 URL이 아직 반영되지 않았습니다. ‘폼에 반영’을 누르거나 URL 입력을 지우세요.");
    }

    private void showPathMode() {
        PathMode mode = (PathMode) pathMode.getSelectedItem();
        ((CardLayout) pathCards.getLayout()).show(pathCards, mode == PathMode.REGEX ? "regex" : mode == PathMode.ALL ? "all" : "literal");
        pathLabel.setLabelFor(mode == PathMode.REGEX ? regex : path);
        pathLabel.setText(mode == PathMode.REGEX ? "RE2 식" : "경로");
        pathGuidance.setText(switch (mode) {
            case EXACT -> "예: /api/items → 같은 경로만 범위 일치. /api/items/1, /api/items-old는 제외합니다. URL 반영의 기본값이며 /와 %인코딩은 그대로 유지합니다.";
            case PREFIX -> "예: /api → /api와 /api/items는 범위 일치, /apix는 제외합니다. /api/는 /api를 포함하지 않습니다. 입력 경로와 /로 구분된 하위 경로만 포함합니다.";
            case ALL -> "예: /items와 /admin 모두 경로 범위에 포함됩니다. 호스트·연결 방식·포트 제한과 다른 차단 규칙은 유지됩니다. 필요한 경로만 허용하려면 다른 방식을 선택하세요.";
            case REGEX -> "예: ^/admin(?:/.*)?$ → /admin과 /admin/users는 일치, /administrator는 제외합니다. RE2 전체 경로 일치이며 기존 식은 그대로 보존합니다.";
        });
        pathCards.revalidate();
    }

    private void refreshPreview() {
        if (loading) return;
        try {
            ScopeEntry entry = formValue();
            String canonical = validateHost(entry.host());
            String hostDescription = entry.host().startsWith("*.")
                    ? "*." + canonical + " — 하위 도메인만, 기본 도메인 제외" : canonical + " — 이 호스트만";
            PathMode mode = (PathMode) pathMode.getSelectedItem();
            String pathDescription = switch (mode) {
                case ALL -> "모든 경로 (제한 없음)";
                case EXACT -> "정확히 일치: " + path.getText();
                case PREFIX -> "경로와 하위 경로: " + path.getText() + " (끝의 /도 구분)";
                case REGEX -> "고급 RE2: 경로 전체 일치";
            };
            preview.setText("상태: " + (entry.enabled() ? "사용" : "사용 안 함 — 이 대상은 검사에서 제외")
                    + "\n호스트: " + hostDescription
                    + "\n연결: " + (entry.scheme().equalsIgnoreCase("any") ? "HTTP와 HTTPS 모두" : entry.scheme().toUpperCase(Locale.ROOT))
                    + " / 포트: " + (entry.port() == 0 ? "모든 포트" : entry.port())
                    + "\n경로: " + pathDescription + "\n저장할 경로 RE2: " + (entry.pathRegex().isEmpty() ? "없음 (모든 경로)" : entry.pathRegex())
                    + "\n허용 대상은 원문과 디코딩된 모든 경로가 맞아야 하며, 차단 대상은 하나만 맞아도 차단합니다. 다른 안전 차단은 계속 적용됩니다.");
            preview.setCaretPosition(0);
            checkPendingInput();
            message.setText("미리보기를 확인한 뒤 저장하세요. URL이나 경로를 자동으로 넓히지 않습니다.");
        } catch (FormValidationException error) {
            preview.setText("입력이 아직 완성되지 않았습니다. 아래 안내에 따라 수정하면 실제 범위가 표시됩니다.");
            message.setText(error.getMessage());
        }
    }

    private static String validateHost(String value) {
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
    private record LiteralPath(PathMode mode, String path) {}

    private static LiteralPath decodeLiteral(String expression) {
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

    private static String compact(String value, int maximum) {
        if (value == null) return "미지정";
        StringBuilder result = new StringBuilder();
        int offset = 0;
        while (offset < value.length()) {
            int cp = value.codePointAt(offset);
            int width = Character.charCount(cp);
            if (result.length() + width > maximum) break;
            if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT) result.append(' ');
            else if (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE) result.append('\uFFFD');
            else result.appendCodePoint(cp);
            offset += width;
        }
        return offset < value.length() ? result + "…" : result.toString();
    }

    private JTextField textField(String name, String description, int maximum, String error) {
        JTextField field = named(new JTextField(24), name, description);
        // Unlike JTextField's default document, preserve pasted newlines so validation can reject them rather than remove them.
        field.getDocument().putProperty("filterNewlines", Boolean.FALSE);
        field.setMinimumSize(new Dimension(0, field.getPreferredSize().height));
        bound(field, maximum, error);
        return field;
    }

    private void bound(javax.swing.text.JTextComponent field, int maximum, String error) {
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override public void insertString(FilterBypass bypass, int offset, String text, AttributeSet attributes) throws BadLocationException {
                replace(bypass, offset, 0, text, attributes);
            }
            @Override public void remove(FilterBypass bypass, int offset, int length) throws BadLocationException {
                replace(bypass, offset, length, "", null);
            }
            @Override public void replace(FilterBypass bypass, int offset, int length, String text, AttributeSet attributes) throws BadLocationException {
                if ((long) bypass.getDocument().getLength() - length + (text == null ? 0 : text.length()) > maximum) {
                    rejectedInputs.put(field.getName(), error);
                    refreshPreview();
                    return;
                }
                rejectedInputs.remove(field.getName());
                super.replace(bypass, offset, length, text, attributes);
            }
        });
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { refreshPreview(); }
            @Override public void removeUpdate(DocumentEvent event) { refreshPreview(); }
            @Override public void changedUpdate(DocumentEvent event) { refreshPreview(); }
        });
    }

    private static JCheckBox checkBox(String name, String text) {
        JCheckBox box = named(new JCheckBox(), name, text);
        box.putClientProperty("html.disable", Boolean.TRUE);
        box.setText(text);
        return box;
    }

    private static JLabel label(String name, String text, JComponent target) {
        JLabel label = named(new JLabel(), name, text);
        label.putClientProperty("html.disable", Boolean.TRUE);
        label.setText(text);
        label.setLabelFor(target);
        return label;
    }

    private static JTextArea note(String name, String text) {
        JTextArea area = named(new JTextArea(text), name, text.isEmpty() ? name : text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setCaret(new dev.cairnguard.ui.NonScrollingCaret());
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(UIManager.getFont("Label.font"));
        area.setMinimumSize(new Dimension(0, area.getPreferredSize().height));
        return area;
    }

    private static <T extends JComponent> T named(T control, String name, String description) {
        control.setName(name);
        control.getAccessibleContext().setAccessibleName(description);
        control.getAccessibleContext().setAccessibleDescription(description);
        return control;
    }

    private void addRow(int row, JLabel label, JComponent control) {
        GridBagConstraints left = constraints(0, row);
        left.insets = new Insets(4, 0, 4, 12);
        form.add(label, left);
        GridBagConstraints right = constraints(1, row);
        right.weightx = 1;
        right.insets = new Insets(4, 0, 4, 0);
        form.add(control, right);
    }

    private void addWide(int row, JComponent control) {
        GridBagConstraints constraints = constraints(0, row);
        constraints.gridwidth = 2;
        constraints.weightx = 1;
        constraints.insets = new Insets(4, 0, 4, 0);
        form.add(control, constraints);
    }

    private static GridBagConstraints constraints(int column, int row) {
        GridBagConstraints result = new GridBagConstraints();
        result.gridx = column;
        result.gridy = row;
        result.fill = GridBagConstraints.HORIZONTAL;
        result.anchor = GridBagConstraints.FIRST_LINE_START;
        return result;
    }

    private static GridBagConstraints filler(int row) {
        GridBagConstraints result = constraints(0, row);
        result.gridwidth = 2;
        result.weighty = 1;
        return result;
    }

    private static FormValidationException invalid(String message) { return new FormValidationException(message); }
    private static void requireEdt() { if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("ScopeEditor requires EDT"); }

    private static final class LiteralRenderer extends DefaultListCellRenderer {
        private static final long serialVersionUID = 1L;
        @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
            putClientProperty("html.disable", Boolean.TRUE);
            return super.getListCellRendererComponent(list, value, index, selected, focus);
        }
    }

    private static final class FormPanel extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;
        FormPanel() { super(new GridBagLayout()); }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return getFontMetrics(getFont()).getHeight(); }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return Math.max(1, visible.height - getFontMetrics(getFont()).getHeight()); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
