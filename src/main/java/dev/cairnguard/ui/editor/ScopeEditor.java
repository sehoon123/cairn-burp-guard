package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.ui.WrappingFlowLayout;
import dev.cairnguard.ui.editor.ScopeDraft.Input;
import dev.cairnguard.ui.editor.ScopeDraft.Member;
import dev.cairnguard.ui.editor.ScopeDraft.PathMode;
import dev.cairnguard.ui.editor.ScopeDraft.LiteralPath;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
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
import java.awt.FlowLayout;
import java.awt.KeyboardFocusManager;
import java.awt.event.KeyEvent;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import static dev.cairnguard.ui.editor.ScopeDraft.*;

/** Local, EDT-only scope form. A pasted URL changes nothing until the user chooses to fill the form. */
public final class ScopeEditor implements EditorForm<List<ScopeEntry>> {
    private final ScopeDraft draft;
    private final boolean compact;
    private final int originalCount;
    private List<Member> members;
    private final MemberModel memberModel = new MemberModel();
    private JTable memberTable;
    private record MemberSelection(int row, Input applied) {}
    private MemberSelection memberSelection;

    private enum Scheme {
        HTTPS("https", "HTTPS — 암호화 연결"), HTTP("http", "HTTP — 암호화하지 않는 연결"),
        ANY("any", "HTTP와 HTTPS 모두");
        final String value;
        final String label;
        Scheme(String value, String label) { this.value = value; this.label = label; }
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
    private final JTextArea path;
    private final JTextArea regex;
    private final JPanel pathCards;
    private final JLabel pathLabel;
    private final JTextArea pathGuidance;
    private final JTextArea preview;
    private final JTextArea message;
    private boolean loading = true;
    private String appliedUrl = "";
    private String loadedScheme = "https";

    public ScopeEditor(List<ScopeEntry> originalSection, List<Integer> selectedIndices) {
        requireEdt();
        draft = new ScopeDraft(originalSection, selectedIndices);
        originalCount = originalSection.size();
        members = draft.members();
        var initial = draft.compactInput();
        compact = initial.isPresent();
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
        port = textField("scope.port", "목적지 서버 포트 목록 (예: 80,443)", MAX_PORT_TEXT, "포트 목록은 2,048자 이내로 줄여 다시 입력하세요.");
        pathMode = named(new JComboBox<>(PathMode.values()), "scope.pathMode", "경로 비교 방식");
        pathMode.setRenderer(new LiteralRenderer());
        path = named(new JTextArea(3, 24), "scope.path", "경로 목록, 한 줄에 하나 (Enter로 줄바꿈, Tab으로 다음 항목)");
        path.setLineWrap(true);
        path.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, Set.of(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0)));
        path.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, Set.of(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, KeyEvent.SHIFT_DOWN_MASK)));
        bound(path, MAX_PATH_TEXT, "경로 목록은 66,048자 이내로 줄여 다시 입력하세요. 일부만 반영하지 않습니다.");
        regex = named(new JTextArea(3, 24), "scope.regex", "고급 RE2 경로 정규식");
        regex.setLineWrap(true);
        bound(regex, MAX_PATTERN, "정규식은 2,048자 이내로 줄여 다시 입력하세요.");
        pathCards = named(new JPanel(new CardLayout()), "scope.pathCards", "선택한 경로 입력");
        pathCards.add(named(new JScrollPane(path), "scope.pathScroll", "경로 목록 입력 영역"), "literal");
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

        if (!compact) installMembers();
        addWide(note("scope.intro", compact
                ? "한 호스트의 포트는 쉼표로, 경로는 한 줄에 하나씩 입력하세요. 선택한 포트 × 경로의 모든 짝을 별도 항목으로 저장합니다."
                : "기존 포트·경로 짝을 보존합니다. 위 표에서 한 항목씩 고치고 ‘선택 항목에 반영’을 누른 뒤 마지막에 한 번 저장하세요."));
        JPanel urlRow = named(new JPanel(new BorderLayout(0, 4)), "scope.urlRow", "URL과 반영 버튼");
        urlRow.add(url, BorderLayout.CENTER);
        JPanel urlActions = named(new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 6, 3)), "scope.urlActions", "URL 반영 및 비우기");
        urlActions.add(fillUrl);
        urlActions.add(clearUrl);
        urlRow.add(urlActions, BorderLayout.SOUTH);
        addRow(label("scope.url.label", "URL (선택)", url), urlRow);
        addWide(note("scope.urlGuidance", "예: https://api.example.test/api/items. URL Enter도 현재 초안을 한 쌍으로 교체합니다 (정책 저장 아님). 개별 편집에서는 선택 항목만 채웁니다. 사용자 정보·?쿼리·#조각은 직접 제거해야 합니다."));
        addWide(message);
        addWide(enabled);
        addRow(label("scope.host.label", "호스트", host), host);
        addWide(note("scope.hostGuidance", "example.test는 그 호스트만 포함합니다. *.example.test는 하위 도메인만 포함하며 example.test 자체는 제외합니다. IP도 입력할 수 있습니다."));
        addRow(label("scope.scheme.label", "연결 방식", scheme), scheme);
        JPanel portRow = named(new JPanel(new BorderLayout(0, 4)), "scope.portRow", "목적지 서버 포트 제한");
        portRow.add(port, BorderLayout.CENTER);
        portRow.add(anyPort, BorderLayout.SOUTH);
        addRow(label("scope.port.label", "목적지 포트", port), portRow);
        addRow(label("scope.pathMode.label", "경로 범위", pathMode), pathMode);
        addRow(pathLabel, pathCards);
        addWide(pathGuidance);
        addWide(label("scope.preview.label", "저장될 실제 범위 미리보기", preview));
        addWide(named(new JScrollPane(preview), "scope.previewScroll", "실제 범위 미리보기 영역"));

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
        load(initial.orElseGet(() -> ScopeDraft.input(members.getFirst().entry())));
        if (!compact) {
            memberSelection = new MemberSelection(0, formInput());
            memberTable.setRowSelectionInterval(0, 0);
        }
        loading = false;
        refreshPreview();
        int line = form.getFontMetrics(form.getFont()).getHeight();
        component.setPreferredSize(new Dimension(Math.min(880, Math.max(640, line * 36)), Math.min(620, line * 28)));
    }

    @Override public JComponent component() { requireEdt(); return component; }

    @Override public List<ScopeEntry> value() {
        requireEdt();
        return draft.section(proposed());
    }

    /** A bounded, plain-text list summary; the editor preview always shows the full stored expression. */
    public static String pathSummary(ScopeEntry entry) {
        if (entry == null) return "대상 없음";
        LiteralPath literal = decodeLiteral(entry.pathRegex());
        if (entry.pathRegex() != null && entry.pathRegex().isEmpty()) return "모든 경로";
        if (literal != null) return (literal.mode() == PathMode.EXACT ? "정확한 경로 " : "하위 경로 ") + compact(literal.path(), 64);
        return "고급 RE2 경로 (편집에서 전체 확인)";
    }

    public static String summary(ScopeEntry entry) {
        if (entry == null) return "대상 없음";
        String protocol = "any".equalsIgnoreCase(entry.scheme()) ? "HTTP·HTTPS" : compact(entry.scheme(), 5).toUpperCase(Locale.ROOT);
        return (entry.enabled() ? "켬" : "끔") + " · " + protocol + " · " + compact(entry.host(), 88)
                + " · " + (entry.port() == 0 ? "모든 포트" : "포트 " + entry.port()) + " · " + pathSummary(entry);
    }

    private void load(Input input) {
        loadedScheme = input.scheme();
        enabled.setSelected(input.enabled());
        host.setText(input.host());
        for (Scheme choice : Scheme.values()) if (choice.value.equals(input.scheme().toLowerCase(Locale.ROOT))) scheme.setSelectedItem(choice);
        anyPort.setSelected(input.allPorts());
        port.setText(input.portText());
        port.setEnabled(!input.allPorts());
        path.setText(input.pathText());
        regex.setText(input.regexText());
        pathMode.setSelectedItem(input.pathMode());
        showPathMode();
    }

    private Input formInput() {
        Scheme choice = (Scheme) scheme.getSelectedItem();
        String protocol = choice.value.equals(loadedScheme.toLowerCase(Locale.ROOT)) ? loadedScheme : choice.value;
        return new Input(enabled.isSelected(), host.getText(), protocol, anyPort.isSelected(), port.getText(),
                (PathMode) pathMode.getSelectedItem(), path.getText(), regex.getText());
    }

    private List<Member> proposed() {
        checkPendingInput();
        if (compact) return draft.product(formInput());
        if (!formInput().equals(memberSelection.applied()))
            throw invalid("선택 항목의 수정이 아직 초안에 반영되지 않았습니다. ‘선택 항목에 반영’ 또는 ‘수정 되돌리기’를 누르세요.");
        return members;
    }

    private void installMembers() {
        memberTable = named(new JTable(memberModel), "scope.members.table", "원래 위치와 포트·경로 짝을 유지하는 개별 항목");
        memberTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        memberTable.getTableHeader().setReorderingAllowed(false);
        DefaultTableCellRenderer plain = new DefaultTableCellRenderer();
        plain.putClientProperty("html.disable", Boolean.TRUE);
        memberTable.setDefaultRenderer(Object.class, plain);
        if (memberTable.getTableHeader().getDefaultRenderer() instanceof JComponent renderer) renderer.putClientProperty("html.disable", Boolean.TRUE);
        memberTable.addPropertyChangeListener("font", event -> sizeMembers());
        sizeMembers();
        memberTable.getSelectionModel().addListSelectionListener(event -> {
            if (loading || event.getValueIsAdjusting() || memberSelection == null) return;
            int row = memberTable.getSelectedRow();
            if (row < 0) {
                loading = true;
                memberTable.setRowSelectionInterval(memberSelection.row(), memberSelection.row());
                loading = false;
                return;
            }
            if (row == memberSelection.row()) return;
            try { proposed(); }
            catch (FormValidationException error) {
                loading = true;
                memberTable.setRowSelectionInterval(memberSelection.row(), memberSelection.row());
                loading = false;
                message.setText(error.getMessage());
                return;
            }
            loadMember(row);
        });
        JButton apply = named(new JButton("선택 항목에 반영 (초안만)"), "scope.member.apply", "현재 항목의 수정만 초안에 반영");
        JButton reset = named(new JButton("수정 되돌리기"), "scope.member.reset", "현재 항목의 미반영 수정을 명시적으로 버리기");
        for (JButton button : List.of(apply, reset)) button.putClientProperty("html.disable", Boolean.TRUE);
        apply.addActionListener(event -> {
            try {
                checkPendingInput();
                int row = memberSelection.row();
                Member next = draft.member(members.get(row).sourceIndex(), formInput());
                List<Member> revised = new ArrayList<>(members);
                revised.set(row, next);
                members = List.copyOf(revised);
                memberSelection = new MemberSelection(row, formInput());
                memberModel.fireTableRowsUpdated(row, row);
                refreshPreview();
            } catch (FormValidationException error) { message.setText(error.getMessage()); }
        });
        reset.addActionListener(event -> loadMember(memberSelection.row()));
        JPanel controls = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 6, 3));
        controls.add(apply); controls.add(reset);
        JPanel section = named(new JPanel(new BorderLayout(0, 4)), "scope.members", "기존 개별 항목 편집");
        section.add(note("scope.members.help", "짝을 자동으로 합치지 않습니다. 표의 원래 위치는 저장된 목록 기준입니다. 미반영·잘못된 입력은 항목 전환과 저장을 막습니다."), BorderLayout.NORTH);
        section.add(named(new JScrollPane(memberTable), "scope.members.scroll", "개별 항목 목록"), BorderLayout.CENTER);
        section.add(controls, BorderLayout.SOUTH);
        addWide(section);
    }

    private void sizeMembers() {
        memberTable.setRowHeight(memberTable.getFontMetrics(memberTable.getFont()).getHeight() + 10);
        memberTable.setPreferredScrollableViewportSize(new Dimension(0, memberTable.getRowHeight() * Math.min(4, members.size())));
    }

    private void loadMember(int row) {
        loading = true;
        rejectedInputs.clear();
        appliedUrl = "";
        url.setText("");
        load(ScopeDraft.input(members.get(row).entry()));
        memberSelection = new MemberSelection(row, formInput());
        loading = false;
        refreshPreview();
    }

    private final class MemberModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private final String[] columns = {"원래 위치", "사용", "호스트 원문", "연결 원문", "포트", "경로 조건"};
        @Override public int getRowCount() { return members == null ? 0 : members.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int column) {
            Member member = members.get(row);
            ScopeEntry entry = member.entry();
            return switch (column) {
                case 0 -> Integer.toString(member.sourceIndex() + 1);
                case 1 -> entry.enabled() ? "사용" : "중지";
                case 2 -> entry.host();
                case 3 -> entry.scheme();
                case 4 -> entry.port() == 0 ? "모든 포트" : Integer.toString(entry.port());
                default -> pathSummary(entry);
            };
        }
    }

    private void fillFromUrl() {
        requireEdt();
        try {
            String rejected = rejectedInputs.get("scope.url");
            if (rejected != null) throw invalid(rejected);
            ScopeEntry next = parseUrl(url.getText(), enabled.isSelected());
            loading = true;
            rejectedInputs.clear();
            load(ScopeDraft.input(next));
            appliedUrl = url.getText();
            loading = false;
            refreshPreview();
        } catch (FormValidationException error) {
            loading = false;
            message.setText(error.getMessage());
        }
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
            case EXACT -> "한 줄에 경로 하나, 쉼표는 경로의 일부입니다. 마지막 줄바꿈 하나만 허용합니다. 예: /api/items → 같은 경로만 범위 일치. /api/items/1, /api/items-old는 제외합니다. URL 반영의 기본값이며 /와 %인코딩은 그대로 유지합니다.";
            case PREFIX -> "한 줄에 기준 경로 하나를 입력하세요. 예: /api → /api와 /api/items는 범위 일치, /apix는 제외합니다. /api/는 /api를 포함하지 않습니다. 입력 경로와 /로 구분된 하위 경로만 포함합니다.";
            case ALL -> "예: /items와 /admin 모두 경로 범위에 포함됩니다. 호스트·연결 방식·포트 제한과 다른 차단 규칙은 유지됩니다. 필요한 경로만 허용하려면 다른 방식을 선택하세요.";
            case REGEX -> "예: ^/admin(?:/.*)?$ → /admin과 /admin/users는 일치, /administrator는 제외합니다. RE2 전체 경로 일치이며 기존 식은 그대로 보존합니다.";
        });
        pathCards.revalidate();
    }

    private void refreshPreview() {
        if (loading) return;
        try {
            List<Member> proposed = proposed();
            List<ScopeEntry> section = draft.section(proposed);
            StringBuilder text = new StringBuilder();
            if (compact) text.append("명시한 포트 ").append(proposed.stream().map(m -> m.entry().port()).distinct().count())
                    .append("개 × 경로 조건 ").append(proposed.stream().map(m -> m.entry().pathRegex()).distinct().count())
                    .append("개 = 모든 ").append(proposed.size()).append("쌍을 각각 저장합니다.\n");
            else text.append("기존 개별 항목 ").append(proposed.size()).append("개의 짝을 유지합니다.\n");
            text.append("연결 방식은 포트와 독립적입니다. HTTP와 HTTPS 모두를 선택하면 각 포트에 두 방식이 모두 적용됩니다. 80=HTTP, 443=HTTPS로 추정하지 않습니다.\n");
            text.append("전체 목록: ").append(originalCount).append("개 → ").append(section.size()).append("개 확장 항목\n");
            for (Member member : proposed) text.append("\n").append(member.sourceIndex() < 0 ? "새 항목" : "원래 위치 #" + (member.sourceIndex() + 1))
                    .append("\n").append(fullEntry(member.entry()));
            List<Member> removed = draft.members().stream().filter(old -> proposed.stream().noneMatch(old::equals)).toList();
            List<Member> added = proposed.stream().filter(next -> !draft.members().contains(next)).toList();
            text.append("\n추가·교체 ").append(added.size()).append("개 / 제거·교체 ").append(removed.size()).append("개\n");
            for (Member member : removed) text.append("- 원래 위치 #").append(member.sourceIndex() + 1).append("\n").append(fullEntry(member.entry()));
            for (Member member : added) text.append("+ ").append(member.sourceIndex() < 0 ? "새 항목" : "원래 위치 #" + (member.sourceIndex() + 1)).append("\n");
            text.append("\n허용 대상은 원문과 디코딩된 모든 경로가 한 항목에 맞아야 하며, 차단 대상은 하나만 맞아도 차단합니다. 다른 안전 차단과 전체 정책 검증은 계속 적용됩니다.");
            preview.setText(text.toString());
            preview.setCaretPosition(0);
            message.setText("전체 짝과 추가·제거를 확인한 뒤 저장하세요. URL이나 경로를 자동으로 넓히지 않습니다.");
        } catch (FormValidationException error) {
            preview.setText("입력이 아직 완성되지 않았습니다. 아래 안내에 따라 수정하면 실제 범위가 표시됩니다.");
            message.setText(error.getMessage());
        }
    }

    private static String fullEntry(ScopeEntry entry) {
        String canonical = validateHost(entry.host());
        String authority = entry.host().startsWith("*.") ? "*." + canonical + " — 하위 도메인만, 기본 도메인 제외" : canonical + " — 이 호스트만";
        Input input = ScopeDraft.input(entry);
        String description = switch (input.pathMode()) {
            case ALL -> "모든 경로 (제한 없음)";
            case EXACT -> "정확히 일치: " + input.pathText();
            case PREFIX -> "경로와 하위 경로: " + input.pathText() + " (끝의 /도 구분)";
            case REGEX -> "고급 RE2: 경로 전체 일치";
        };
        return "상태: " + (entry.enabled() ? "사용" : "사용 안 함") + "\n호스트 원문: " + entry.host() + "\n호스트 판정: " + authority
                + "\n연결: " + (entry.scheme().equalsIgnoreCase("any") ? "HTTP와 HTTPS 모두 (" + entry.scheme() + ")" : entry.scheme())
                + " / 포트: " + (entry.port() == 0 ? "모든 포트" : entry.port()) + "\n경로: " + description
                + "\n저장할 경로 RE2: " + (entry.pathRegex().isEmpty() ? "없음 (모든 경로)" : entry.pathRegex()) + "\n";
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
        return area;
    }

    private static <T extends JComponent> T named(T control, String name, String description) {
        control.setName(name);
        control.getAccessibleContext().setAccessibleName(description);
        control.getAccessibleContext().setAccessibleDescription(description);
        return control;
    }

    private void addRow(JLabel label, JComponent control) {
        FormRow row = new FormRow();
        row.add(label, BorderLayout.NORTH);
        row.add(control, BorderLayout.CENTER);
        form.addRow(row);
    }

    private void addWide(JComponent control) {
        FormRow row = new FormRow();
        row.add(control, BorderLayout.CENTER);
        form.addRow(row);
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

    private static final class FormRow extends JPanel {
        private static final long serialVersionUID = 1L;
        FormRow() {
            super(new BorderLayout(0, 4));
            setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        }
        // The viewport may narrow a row, but must scroll its current native height instead of squeezing it.
        @Override public Dimension getMinimumSize() { return new Dimension(0, getPreferredSize().height); }
    }

    private static final class FormPanel extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;
        FormPanel() { super(new GridBagLayout()); }
        void addRow(FormRow row) {
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.gridx = 0;
            constraints.gridy = GridBagConstraints.RELATIVE;
            constraints.gridwidth = GridBagConstraints.REMAINDER;
            constraints.weightx = 1;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.anchor = GridBagConstraints.FIRST_LINE_START;
            add(row, constraints);
        }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return getFontMetrics(getFont()).getHeight(); }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return Math.max(1, visible.height - getFontMetrics(getFont()).getHeight()); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
