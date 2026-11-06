package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import java.util.UUID;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.text.AbstractDocument;

/** Human-authored rule form. It returns an immutable draft; the caller owns saving and revisions. */
public final class RuleEditor implements EditorForm<Rule> {
    private final RuleFormPanel panel = new RuleFormPanel();
    private final javax.swing.JScrollPane scroll = new javax.swing.JScrollPane(panel);
    private final JTextField name = new JTextField(28);
    private final JCheckBox enabled = new JCheckBox("이 규칙 사용");
    private final JComboBox<Mode> mode = new JComboBox<>(Mode.values());
    private final JComboBox<Preset> preset = new JComboBox<>(Preset.values());
    private final JButton applyPreset = new JButton("예제로 폼 채우기");
    private final JTextArea presetHelp = ConditionEditor.information("rule.presetHint", "예제의 동작과 일치·불일치 예시");
    private final JPanel conditionHost = new JPanel(new BorderLayout());
    private final JTextArea status = ConditionEditor.information("rule.status", "규칙 편집 상태");
    private final JTextArea exemption = ConditionEditor.information("rule.exemptWarning", "EXEMPT 예외 경고");
    private final String id;
    private ConditionEditor conditions;
    private final boolean invalidLoadedName;
    private final boolean missingLoadedCondition;

    /** null creates a rule with a fresh stable ID. Existing IDs and untouched condition fields survive. */
    public RuleEditor(Rule initial) {
        ConditionEditor.requireEdt();
        id = initial == null ? "rule-" + UUID.randomUUID() : initial.id();
        invalidLoadedName = initial != null && initial.name() != null && initial.name().length() > 256;
        missingLoadedCondition = initial != null && initial.condition() == null;
        ConditionEditor.name(panel, "rule.editor", "요청 규칙 편집기");
        ConditionEditor.name(scroll, "rule.scroll", "규칙 폼 스크롤 영역");
        scroll.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(Math.max(16, panel.getFontMetrics(panel.getFont()).getHeight()));
        ConditionEditor.name(name, "rule.name", "규칙 이름");
        name.setText(initial == null ? "DELETE 요청 차단" : invalidLoadedName ? "" : initial.name());
        ConditionEditor.name(enabled, "rule.enabled", "이 규칙 사용");
        enabled.setSelected(initial == null || initial.enabled());
        ConditionEditor.name(mode, "rule.mode", "조건이 맞을 때의 동작");
        mode.setRenderer(new ConditionEditor.ChoiceRenderer(value -> modeLabel((Mode) value)));
        mode.setSelectedItem(initial == null ? Mode.BLOCK : initial.mode());
        mode.addActionListener(e -> updateExemption());
        exemption.setForeground(new java.awt.Color(180, 65, 0));
        updateExemption();
        ConditionEditor.name(preset, "rule.preset", "빠른 규칙 예제");
        preset.setRenderer(new ConditionEditor.ChoiceRenderer(value -> value instanceof Preset item ? item.label : "예제를 선택하세요"));
        ConditionEditor.name(applyPreset, "rule.applyPreset", "선택한 규칙 예제 적용");
        applyPreset.setEnabled(false);
        preset.addActionListener(event -> {
            applyPreset.setEnabled(preset.getSelectedItem() instanceof Preset selected && selected != Preset.NONE);
            updatePresetHelp();
        });
        applyPreset.addActionListener(event -> applyPreset());
        updatePresetHelp();
        ((AbstractDocument) name.getDocument()).setDocumentFilter(new ConditionEditor.LengthFilter(256,
                () -> status.setText("규칙 이름은 256자 이내로 입력하세요. 기존 이름을 자르지 않았습니다.")));

        JPanel header = new JPanel(new GridBagLayout());
        header.setName("rule.header");
        row(header, 0, ConditionEditor.label("규칙 이름", name, "rule.nameLabel"), name);
        row(header, 1, ConditionEditor.label("일치할 때", mode, "rule.modeLabel"), mode);
        GridBagConstraints toggle = constraints(1, 2);
        header.add(enabled, toggle);
        JPanel examples = new JPanel(new BorderLayout(4, 0));
        examples.setName("rule.examples");
        examples.add(preset, BorderLayout.CENTER);
        examples.add(applyPreset, BorderLayout.EAST);
        row(header, 3, ConditionEditor.label("빠른 시작", preset, "rule.presetLabel"), examples);
        presetHelp.setRows(3);
        GridBagConstraints help = constraints(0, 4);
        help.gridwidth = 2;
        header.add(presetHelp, help);
        panel.add(header, BorderLayout.NORTH);

        conditionHost.setName("rule.conditionHost");
        conditions = new ConditionEditor(initial == null ? null : initial.condition());
        conditionHost.add(conditions.component(), BorderLayout.CENTER);
        panel.add(conditionHost, BorderLayout.CENTER);
        JPanel footer = new JPanel(new BorderLayout(4, 4));
        footer.setName("rule.footer");
        JTextArea priority = ConditionEditor.information("rule.priorityHint", "규칙 우선순위 안내");
        priority.setText("EXEMPT 예외 > 차단 > 승인 요청 > 허용 순서로 적용됩니다. ‘기록만’은 다른 동작을 덮어쓰지 않습니다. EXEMPT도 실제 대상 범위·유효성·운영자 일시중지·명시 속도·태그 예산·수명 검사를 우회하지 못합니다.");
        JPanel warnings = new JPanel(new java.awt.GridLayout(0, 1));
        warnings.add(priority); warnings.add(exemption);
        footer.add(warnings, BorderLayout.NORTH);
        status.setRows(1);
        if (invalidLoadedName) status.setText("가져온 규칙 이름이 256자를 넘습니다. 취소 후 원래 설정에서 이름을 줄여 다시 여세요. 잘라서 저장하지 않습니다.");
        else if (missingLoadedCondition) status.setText("가져온 규칙에 조건이 없습니다. 취소 후 원래 설정을 확인하세요. 예제 조건으로 바꾸어 저장하지 않습니다.");
        footer.add(status, BorderLayout.CENTER);
        panel.add(footer, BorderLayout.SOUTH);
    }

    @Override public JComponent component() { ConditionEditor.requireEdt(); return scroll; }

    @Override public Rule value() {
        ConditionEditor.requireEdt();
        if (invalidLoadedName) throw new FormValidationException("가져온 규칙 이름이 256자를 넘습니다. 취소 후 원래 설정에서 이름을 줄여 다시 여세요.");
        if (missingLoadedCondition) throw new FormValidationException("가져온 규칙에 조건이 없습니다. 취소 후 원래 설정을 확인하거나 새 규칙으로 다시 만드세요.");
        Rule result = new Rule(id, name.getText(), enabled.isSelected(), (Mode) mode.getSelectedItem(), conditions.value());
        ConditionEditor.validateRule(result);
        return result;
    }

    /** Bounded plain text for tables and labels. Callers must also use literal (non-HTML) renderers. */
    public static String summary(Condition condition) {
        String result = ConditionEditor.describe(condition);
        if (condition != null && condition.logic() != Logic.LEAF && !condition.children().isEmpty()) {
            StringBuilder details = new StringBuilder(result).append(" — ");
            int visible = Math.min(condition.children().size(), 2);
            for (int i = 0; i < visible; i++) {
                if (i > 0) details.append(" / ");
                details.append(ConditionEditor.describe(condition.children().get(i)));
            }
            if (condition.children().size() > visible) details.append(" / …");
            result = details.toString();
        }
        return ConditionEditor.excerpt(result, 240);
    }

    private void applyPreset() {
        Preset selected = (Preset) preset.getSelectedItem();
        if (selected == null || selected == Preset.NONE) return;
        Condition condition = switch (selected) {
            case HEALTH_EXEMPT -> Condition.and(Condition.leaf(Field.METHOD, Match.EXACT, "GET"),
                    Condition.leaf(Field.PATH, Match.EXACT, "/health"));
            case DELETE_METHOD -> Condition.leaf(Field.METHOD, Match.EXACT, "DELETE");
            case CHANGE_METHODS -> new Condition(Logic.OR, null, null, null, null, false, List.of(
                    Condition.leaf(Field.METHOD, Match.EXACT, "POST"),
                    Condition.leaf(Field.METHOD, Match.EXACT, "PUT"),
                    Condition.leaf(Field.METHOD, Match.EXACT, "PATCH"),
                    Condition.leaf(Field.METHOD, Match.EXACT, "DELETE")));
            case ADMIN_PATH -> Condition.leaf(Field.PATH, Match.REGEX, "^/admin(?:/.*)?$");
            case JSON_REVIEW -> new Condition(Logic.LEAF, Field.JSON, "/action", Match.EXACT, "review", false, List.of());
            case POST_PATH -> new Condition(Logic.AND, null, null, null, null, false, List.of(
                    Condition.leaf(Field.METHOD, Match.EXACT, "POST"),
                    Condition.leaf(Field.PATH, Match.EXACT, "/api/items")));
            case QUERY_PURGE -> new Condition(Logic.LEAF, Field.QUERY, "operation", Match.EXACT, "purge", false, List.of());
            case NONE -> throw new IllegalStateException("NO_PRESET");
        };
        name.setText(selected.ruleName);
        mode.setSelectedItem(selected.mode);
        conditions = new ConditionEditor(condition);
        conditionHost.removeAll();
        conditionHost.add(conditions.component(), BorderLayout.CENTER);
        conditionHost.revalidate();
        conditionHost.repaint();
        status.setText("예제의 이름·동작·조건을 폼에 반영했습니다. 내용을 확인한 뒤 저장하세요. 아직 적용된 정책은 바뀌지 않았습니다.");
    }

    private void updateExemption() {
        exemption.setText(mode.getSelectedItem() == Mode.EXEMPT
                ? "경고: EXEMPT는 같은 요청에 일치하는 일반 BLOCK·ASK를 무시합니다. 정확한 메서드+경로 등 최소 조건으로 제한하세요. 기본 예외는 없으며 저장 시 별도 확인이 필요합니다."
                : "EXEMPT는 일반 차단 규칙을 무시하는 고위험 예외입니다. 필요한 경우에만 선택하고 최소 조건으로 제한하세요.");
    }

    private void updatePresetHelp() {
        Preset selected = preset.getSelectedItem() instanceof Preset item ? item : Preset.NONE;
        presetHelp.setText(selected.help + "\n‘예제로 폼 채우기’는 이름·동작·조건만 바꿉니다. ID·사용 여부는 유지하며 정책 저장은 별도입니다.");
    }

    private enum Preset {
        NONE("예제를 선택하세요", "", Mode.BLOCK,
                "예제를 선택하면 동작과 일치·불일치 예를 먼저 볼 수 있습니다. 선택만으로 기존 폼은 바뀌지 않습니다."),
        DELETE_METHOD("DELETE 요청 차단", "DELETE 요청 차단", Mode.BLOCK,
                "일치: DELETE /items → 차단. 불일치: GET /items. 이미 기본 규칙에 포함되어 있어 추가가 필요하지 않을 수 있습니다."),
        CHANGE_METHODS("변경 메서드 묶음 차단", "변경 메서드 요청 차단", Mode.BLOCK,
                "일치: POST·PUT·PATCH·DELETE → 차단 (OR 묶음). 불일치: GET·HEAD. 정상 수정 요청도 차단하므로 범위를 확인하세요."),
        ADMIN_PATH("관리 경로 승인 요청", "관리 경로 승인 요청", Mode.ASK,
                "일치: /admin, /admin/users → 승인 요청. 불일치: /administrator. 허용 범위와 다른 차단 규칙이 우선합니다."),
        JSON_REVIEW("JSON action=review 승인 요청", "JSON 작업 확인", Mode.ASK,
                "일치 본문: {\"action\":\"review\"} → 승인 요청. 불일치: {\"other\":\"review\"}. 기본 delete 차단은 그대로 유지됩니다."),
        POST_PATH("POST /api/items 승인 요청", "POST API 작업 확인", Mode.ASK,
                "일치: POST /api/items → 승인 요청 (AND 묶음). 불일치: GET /api/items, POST /api/items/1. 대상 범위도 등록해야 합니다."),
        QUERY_PURGE("쿼리 operation=purge 차단", "특정 쿼리 작업 차단", Mode.BLOCK,
                "일치: ?operation=purge → 차단. 불일치: ?operation=view, ?other=purge. 이름과 값을 구분해 비교합니다."),
        HEALTH_EXEMPT("GET /health 일반 규칙 예외 (주의)", "GET 상태 확인 일반 규칙 예외", Mode.EXEMPT,
                "일치: GET /health → 일반 BLOCK·ASK 무시. 불일치: POST /health, GET /health/admin. 범위·운영자 일시중지·명시 속도·태그 예산·수명 검사는 유지됩니다. GET도 부작용이 있을 수 있습니다. 자동 적용하지 않습니다.");
        private final String label;
        private final String ruleName;
        private final Mode mode;
        private final String help;
        Preset(String label, String ruleName, Mode mode, String help) {
            this.label = label; this.ruleName = ruleName; this.mode = mode; this.help = help;
        }
    }
    private static String modeLabel(Mode mode) {
        if (mode == null) return "동작을 선택하세요";
        return switch (mode) {
            case EXEMPT -> "EXEMPT 예외 — 일반 BLOCK·ASK 무시 (주의)";
            case BLOCK -> "차단 — 요청을 보내지 않음";
            case ASK -> "승인 요청 — 사람이 승인할 때까지 대기";
            case ALLOW -> "허용 — 안전 범위 안에서만 전송";
            case MONITOR -> "기록만 — 다른 규칙·기본 동작 유지";
        };
    }
    /** The complete form scrolls; fixed headers/toolbars must never squeeze the condition editor to zero. */
    private static final class RuleFormPanel extends JPanel implements javax.swing.Scrollable {
        private static final long serialVersionUID = 1L;
        RuleFormPanel() { super(new BorderLayout(8, 8)); }
        @Override public java.awt.Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction) { return getFontMetrics(getFont()).getHeight(); }
        @Override public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction) { return Math.max(1, visible.height - getFontMetrics(getFont()).getHeight()); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    private static GridBagConstraints constraints(int x, int y) {
        GridBagConstraints result = new GridBagConstraints();
        result.gridx = x;
        result.gridy = y;
        result.insets = new Insets(3, 3, 3, 3);
        result.anchor = GridBagConstraints.NORTHWEST;
        result.fill = GridBagConstraints.HORIZONTAL;
        result.weightx = x == 1 ? 1 : 0;
        return result;
    }
    private static void row(JPanel panel, int row, JComponent label, JComponent control) {
        panel.add(label, constraints(0, row));
        panel.add(control, constraints(1, row));
    }
}
