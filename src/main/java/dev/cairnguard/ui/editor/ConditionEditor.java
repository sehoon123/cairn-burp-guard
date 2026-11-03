package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.policy.PolicyEngine;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
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
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

/** A visual, EDT-only condition tree. No JSON, persistence, traffic, or native Burp access. */
public final class ConditionEditor implements EditorForm<Condition> {
    // The policy's root is depth zero. These limits also bound construction and every tree action.
    private static final int MAX_NODES = 2_048;
    private static final int MAX_DEPTH = 16;
    private static final int MAX_CHILDREN = 64;
    private static final String TREE_LIMIT = "조건은 최대 2,048개, 묶음당 64개, 중첩 깊이 16단계까지 사용할 수 있습니다. 조건 수나 깊이를 줄이세요.";
    private static final String TEXT_LIMIT = "이름은 512자, 비교 값은 4,096자 이내로 입력하세요. 정규식은 2,048자 이내여야 합니다.";

    private final JPanel panel = new JPanel(new BorderLayout(8, 8));
    private final JComboBox<Field> field = new JComboBox<>(Field.values());
    private final JTextField selector = new JTextField(24);
    private final JLabel selectorLabel = new JLabel("이름 (선택)");
    private final JComboBox<Match> match = new JComboBox<>(Match.values());
    private final JTextArea text = new JTextArea(4, 24);
    private final JCheckBox caseSensitive = new JCheckBox("대소문자 구분");
    private final JComboBox<Logic> logic = new JComboBox<>(new Logic[] {Logic.AND, Logic.OR});
    private final JTextArea hint = information("condition.hint", "조건 입력 도움말");
    private final JTextArea status = information("condition.status", "조건 편집 상태");
    private final JPanel details = new JPanel(new CardLayout());
    private final JButton addLeaf = button("condition.addLeaf", "조건 추가");
    private final JButton addAnd = button("condition.addAnd", "모두 묶음 추가 (AND)");
    private final JButton addOr = button("condition.addOr", "하나라도 묶음 추가 (OR)");
    private final JButton wrapAnd = button("condition.wrapAnd", "선택을 모두 묶기 (AND)");
    private final JButton wrapOr = button("condition.wrapOr", "선택을 하나라도 묶기 (OR)");
    private final JButton remove = button("condition.remove", "선택 삭제");
    private final DefaultTreeModel model;
    private final JTree tree;
    private final String loadFailure;
    private boolean loading;

    /** null starts with a synthetic DELETE-method condition. Loaded fields are never normalized. */
    public ConditionEditor(Condition initial) {
        requireEdt();
        Condition source = initial == null ? defaultLeaf() : initial;
        loadFailure = boundsFailure(source);
        model = new DefaultTreeModel(makeNode(loadFailure == null ? source : defaultLeaf()));
        tree = new JTree(model);
        buildUi();
        bindEdits();
        tree.setSelectionPath(new TreePath(root().getPath()));
        if (loadFailure != null) {
            for (JComponent control : List.of(tree, field, selector, match, text, caseSensitive, logic,
                    addLeaf, addAnd, addOr, wrapAnd, wrapOr, remove)) control.setEnabled(false);
            status.setText(loadFailure + " 취소 후 가져온 설정을 확인하세요. 조건을 잘라서 저장하지 않습니다.");
        }
    }

    @Override public JComponent component() { requireEdt(); return panel; }

    @Override public Condition value() {
        requireEdt();
        if (loadFailure != null) throw new FormValidationException(loadFailure);
        Condition result = collect(root());
        validateRule(new Rule("condition-validation", "조건 검사", true, Mode.BLOCK, result));
        return result;
    }

    private void buildUi() {
        name(panel, "condition.editor", "요청 조건 편집기");
        JTextArea introduction = information("condition.instructions", "조건 트리 사용 방법");
        introduction.setText("왼쪽에서 조건을 선택해 편집하세요. 묶음을 선택하면 조건을 추가할 수 있습니다. 단일 조건은 아래의 ‘선택을 묶기’로 중첩하세요.");
        panel.add(introduction, BorderLayout.NORTH);
        name(tree, "condition.tree", "요청 조건 트리");
        tree.getAccessibleContext().setAccessibleDescription("모두 충족은 AND, 하나라도 충족은 OR입니다. 선택한 항목의 상세를 오른쪽에서 편집합니다.");
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setCellRenderer(new LiteralTreeRenderer());
        tree.setRootVisible(true);
        tree.setShowsRootHandles(true);
        tree.setRowHeight(0);
        JScrollPane treeScroll = new JScrollPane(tree);
        treeScroll.setName("condition.treeScroll");
        treeScroll.setMinimumSize(new Dimension(170, 180));
        treeScroll.setPreferredSize(new Dimension(290, 260));

        JPanel leafPanel = new JPanel(new GridBagLayout());
        leafPanel.setName("condition.leafDetails");
        name(field, "condition.field", "비교할 요청 항목");
        field.setRenderer(new ChoiceRenderer(value -> fieldLabel((Field) value)));
        name(selector, "condition.selector", "이름 또는 JSON 선택 경로");
        name(match, "condition.match", "비교 방법");
        match.setRenderer(new ChoiceRenderer(value -> matchLabel((Match) value)));
        name(text, "condition.value", "비교 값 또는 RE2 정규식");
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        name(caseSensitive, "condition.caseSensitive", "대소문자 구분");
        selectorLabel.setName("condition.selectorLabel");
        selectorLabel.putClientProperty("html.disable", Boolean.TRUE);
        selectorLabel.setLabelFor(selector);
        row(leafPanel, 0, label("비교 항목", field, "condition.fieldLabel"), field);
        row(leafPanel, 1, selectorLabel, selector);
        row(leafPanel, 2, label("비교 방법", match, "condition.matchLabel"), match);
        JScrollPane valueScroll = new JScrollPane(text);
        valueScroll.setName("condition.valueScroll");
        row(leafPanel, 3, label("비교 값", text, "condition.valueLabel"), valueScroll);
        GridBagConstraints extra = constraints(0, 4);
        extra.gridwidth = 2;
        leafPanel.add(caseSensitive, extra);
        extra = constraints(0, 5);
        extra.gridwidth = 2;
        extra.weighty = 1;
        extra.fill = GridBagConstraints.BOTH;
        hint.setRows(6);
        leafPanel.add(hint, extra);

        JPanel groupPanel = new JPanel(new BorderLayout(8, 8));
        groupPanel.setName("condition.groupDetails");
        JPanel groupChoice = new JPanel(new BorderLayout(8, 8));
        groupChoice.setName("condition.groupChoice");
        name(logic, "condition.logic", "묶음의 결합 방법");
        logic.setRenderer(new ChoiceRenderer(value -> logicLabel((Logic) value)));
        groupChoice.add(label("묶음 방법", logic, "condition.logicLabel"), BorderLayout.NORTH);
        groupChoice.add(logic, BorderLayout.CENTER);
        groupPanel.add(groupChoice, BorderLayout.NORTH);
        JTextArea groupHint = information("condition.groupHint", "묶음 도움말");
        groupHint.setText("모두 충족 (AND): 모든 하위 조건이 맞아야 합니다.\n\n하나라도 충족 (OR): 하위 조건 중 하나만 맞으면 됩니다.\n\n아래에서 조건이나 새 묶음을 추가하세요. 묶음마다 조건이 하나 이상 필요합니다. 기존 조건을 묶어 여러 단계로 중첩할 수도 있습니다.");
        groupPanel.add(groupHint, BorderLayout.CENTER);
        details.setName("condition.details");
        details.add(leafPanel, "leaf");
        details.add(groupPanel, "group");
        details.setMinimumSize(new Dimension(270, 180));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, details);
        split.setName("condition.split");
        split.setResizeWeight(0.4);
        split.setBorder(BorderFactory.createEmptyBorder());
        panel.add(split, BorderLayout.CENTER);

        JPanel commands = new JPanel(new BorderLayout(4, 4));
        commands.setName("condition.commands");
        // Two columns avoid FlowLayout's clipped second row at larger Burp fonts.
        JPanel actions = new JPanel(new GridLayout(3, 2, 4, 4));
        actions.setName("condition.actions");
        actions.add(addLeaf);
        actions.add(remove);
        actions.add(addAnd);
        actions.add(addOr);
        actions.add(wrapAnd);
        actions.add(wrapOr);
        commands.add(actions, BorderLayout.CENTER);
        status.setRows(2);
        commands.add(status, BorderLayout.SOUTH);
        panel.add(commands, BorderLayout.SOUTH);
    }

    private void bindEdits() {
        tree.addTreeSelectionListener(event -> loadSelection());
        field.addActionListener(event -> {
            if (loading) return;
            changeLeaf(old -> copy(old, (Field) field.getSelectedItem(), old.name(), old.match(), old.value(), old.caseSensitive()));
        });
        onEdit(selector, () -> changeLeaf(old -> copy(old, old.field(), selector.getText(), old.match(), old.value(), old.caseSensitive())));
        match.addActionListener(event -> {
            if (loading) return;
            changeLeaf(old -> copy(old, old.field(), old.name(), (Match) match.getSelectedItem(), old.value(), old.caseSensitive()));
        });
        onEdit(text, () -> changeLeaf(old -> copy(old, old.field(), old.name(), old.match(), text.getText(), old.caseSensitive())));
        caseSensitive.addActionListener(event -> changeLeaf(old -> copy(old, old.field(), old.name(), old.match(), old.value(), caseSensitive.isSelected())));
        logic.addActionListener(event -> {
            Node node = selected();
            if (loading || node == null || node.data.logic() == Logic.LEAF) return;
            Condition old = node.data;
            node.data = new Condition((Logic) logic.getSelectedItem(), old.field(), old.name(), old.match(), old.value(), old.caseSensitive(), old.children());
            model.nodeChanged(node);
        });
        ((AbstractDocument) selector.getDocument()).setDocumentFilter(new LengthFilter(512, () -> status.setText(TEXT_LIMIT)));
        ((AbstractDocument) text.getDocument()).setDocumentFilter(new LengthFilter(4_096, () -> status.setText(TEXT_LIMIT)));
        addLeaf.addActionListener(event -> add(null));
        addAnd.addActionListener(event -> add(Logic.AND));
        addOr.addActionListener(event -> add(Logic.OR));
        wrapAnd.addActionListener(event -> wrap(Logic.AND));
        wrapOr.addActionListener(event -> wrap(Logic.OR));
        remove.addActionListener(event -> {
            Node node = selected();
            if (node == null || node.getParent() == null) return;
            Node parent = (Node) node.getParent();
            model.removeNodeFromParent(node);
            select(parent);
            status.setText("선택한 조건을 삭제했습니다. 빈 묶음에는 조건을 추가하세요.");
        });
    }

    private void loadSelection() {
        Node node = selected();
        if (node == null) return;
        loading = true;
        try {
            Condition data = node.data;
            if (data.logic() == Logic.LEAF) {
                field.setSelectedItem(data.field());
                selector.setText(data.name() == null ? "" : data.name());
                match.setSelectedItem(data.match());
                text.setText(data.value() == null ? "" : data.value());
                caseSensitive.setSelected(data.caseSensitive());
                ((CardLayout) details.getLayout()).show(details, "leaf");
                updateHelp();
            } else {
                logic.setSelectedItem(data.logic());
                ((CardLayout) details.getLayout()).show(details, "group");
            }
        } finally { loading = false; }
        updateActions();
    }

    private void changeLeaf(Function<Condition, Condition> change) {
        Node node = selected();
        if (loading || node == null || node.data.logic() != Logic.LEAF) return;
        node.data = change.apply(node.data);
        model.nodeChanged(node);
        updateHelp();
    }

    private void updateHelp() {
        Field selectedField = (Field) field.getSelectedItem();
        boolean named = selectedField == Field.QUERY || selectedField == Field.HEADER || selectedField == Field.JSON || selectedField == Field.FORM;
        // Do not discard a selector when the field changes. Leave it editable until explicitly cleared.
        selector.setEnabled(loadFailure == null && (named || !selector.getText().isEmpty()));
        selectorLabel.setText(selectedField == Field.JSON ? "JSON 선택 경로 (선택)" : "이름 (선택)");
        String context = selectedField == null ? "비교할 요청 항목을 선택하세요." : switch (selectedField) {
            case METHOD -> "HTTP 메서드만 비교합니다. 예: DELETE 또는 POST.";
            case URL -> "전체 URL을 비교합니다. 예: https://api.example.test/items/1";
            case PATH -> "URL의 경로를 비교합니다. 예: /admin 또는 /items/1";
            case QUERY -> "이름이 비어 있으면 모든 쿼리 이름·값을 비교합니다. 예: 이름 action, 값 delete. 이름에도 대소문자 옵션이 적용됩니다.";
            case HEADER -> "이름이 비어 있으면 모든 헤더 이름·값을 비교합니다. 예: 이름 X-Operation, 값 delete. 헤더 이름은 항상 대소문자를 구분하지 않습니다.";
            case BODY -> "본문 텍스트를 비교합니다. 예: operation=delete. 해석할 수 없는 요청은 별도로 차단됩니다.";
            case JSON -> "비우면 JSON 전체의 키·값을, 지정하면 해당 위치와 하위 키·값을 비교합니다. 예: /action 또는 /items/0/name. 선택 경로의 키는 대소문자를 구분하며 ~는 ~0, /는 ~1로 씁니다.";
            case FORM -> "이름이 비어 있으면 모든 폼 이름·값을 비교합니다. 예: 이름 action, 값 delete. 이름에도 대소문자 옵션이 적용됩니다.";
            case ANY -> "메서드·URL·헤더·본문 등의 검사 가능한 값을 넓게 비교합니다. 예: delete. 원치 않는 일치가 없는지 확인하세요.";
        };
        if (!named && !selector.getText().isEmpty()) context += " 이 항목은 이름을 사용하지 않습니다. 이름 입력을 비워 주세요.";
        Match selectedMatch = (Match) match.getSelectedItem();
        context += selectedMatch == Match.REGEX
                ? "\nRE2 정규식은 2,048자 이내입니다. 예: ^/admin(?:/.*)?$ . 전방·후방 탐색과 역참조는 지원하지 않습니다."
                : "\n포함·정확히 일치는 일반 문자열 비교입니다. . * 같은 문자도 그대로 비교합니다. 비교 값은 4,096자 이내입니다.";
        if (text.getText().isEmpty()) context += "\n빈 비교 값은 매우 넓게 일치할 수 있으니 의도를 확인하세요.";
        hint.setText(context);
        hint.setCaretPosition(0);
    }

    private void updateActions() {
        Node node = selected();
        boolean group = node != null && node.data.logic() != Logic.LEAF;
        int count = countNodes();
        boolean room = group && node.getChildCount() < MAX_CHILDREN;
        addLeaf.setEnabled(room && count < MAX_NODES && node.getLevel() < MAX_DEPTH);
        boolean groupRoom = room && count + 2 <= MAX_NODES && node.getLevel() + 2 <= MAX_DEPTH;
        addAnd.setEnabled(groupRoom);
        addOr.setEnabled(groupRoom);
        boolean canWrap = node != null && count < MAX_NODES && node.getLevel() + node.getDepth() < MAX_DEPTH;
        wrapAnd.setEnabled(canWrap);
        wrapOr.setEnabled(canWrap);
        remove.setEnabled(node != null && node.getParent() != null);
        status.setText("조건 " + count + " / 2,048개 · 묶음당 최대 64개 · 중첩 깊이 최대 16 (처음 조건은 0). 추가는 묶음을 선택하세요.");
    }

    private void add(Logic groupLogic) {
        Node parent = selected();
        int added = groupLogic == null ? 1 : 2;
        int depth = groupLogic == null ? 1 : 2;
        if (parent == null || parent.data.logic() == Logic.LEAF) {
            status.setText("먼저 묶음을 선택하세요. 단일 조건은 ‘선택을 모두 묶기’ 또는 ‘선택을 하나라도 묶기’로 묶으세요.");
            return;
        }
        if (countNodes() + added > MAX_NODES || parent.getChildCount() >= MAX_CHILDREN || parent.getLevel() + depth > MAX_DEPTH) {
            status.setText(TREE_LIMIT);
            return;
        }
        Node child = makeNode(groupLogic == null ? defaultLeaf() : group(groupLogic, List.of(defaultLeaf())));
        model.insertNodeInto(child, parent, parent.getChildCount());
        tree.expandPath(new TreePath(parent.getPath()));
        select(child);
    }

    private void wrap(Logic groupLogic) {
        Node node = selected();
        if (node == null) return;
        if (countNodes() >= MAX_NODES || node.getLevel() + node.getDepth() >= MAX_DEPTH) {
            status.setText(TREE_LIMIT);
            return;
        }
        Node parent = (Node) node.getParent();
        Node wrapper = new Node(group(groupLogic, List.of()));
        if (parent == null) {
            wrapper.add(node);
            model.setRoot(wrapper);
        } else {
            int index = parent.getIndex(node);
            model.removeNodeFromParent(node);
            model.insertNodeInto(wrapper, parent, index);
            model.insertNodeInto(node, wrapper, 0);
        }
        select(wrapper);
        tree.expandPath(new TreePath(wrapper.getPath()));
    }

    private void select(Node node) {
        TreePath path = new TreePath(node.getPath());
        tree.setSelectionPath(path);
        tree.scrollPathToVisible(path);
    }

    private Node selected() { return (Node) tree.getLastSelectedPathComponent(); }
    private Node root() { return (Node) model.getRoot(); }
    private int countNodes() {
        int count = 0;
        var nodes = root().preorderEnumeration();
        while (nodes.hasMoreElements()) { nodes.nextElement(); count++; }
        return count;
    }

    private static Node makeNode(Condition condition) {
        Node result = new Node(condition);
        for (Condition child : condition.children()) result.add(makeNode(child));
        return result;
    }

    private static Condition collect(Node node) {
        List<Condition> children = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) children.add(collect((Node) node.getChildAt(i)));
        Condition old = node.data;
        return new Condition(old.logic(), old.field(), old.name(), old.match(), old.value(), old.caseSensitive(), children);
    }

    private record Pending(Condition condition, int depth) {}
    private static String boundsFailure(Condition source) {
        ArrayDeque<Pending> pending = new ArrayDeque<>();
        pending.push(new Pending(source, 0));
        int count = 0;
        while (!pending.isEmpty()) {
            Pending item = pending.pop();
            Condition condition = item.condition();
            if (condition == null || condition.logic() == null || item.depth() > MAX_DEPTH || ++count > MAX_NODES
                    || condition.children().size() > MAX_CHILDREN) return TREE_LIMIT;
            if (condition.name() != null && condition.name().length() > 512
                    || condition.value() != null && condition.value().length() > 4_096) return TEXT_LIMIT;
            for (Condition child : condition.children()) pending.push(new Pending(child, item.depth() + 1));
        }
        return null;
    }

    private static Condition copy(Condition old, Field field, String name, Match match, String value, boolean caseSensitive) {
        return new Condition(old.logic(), field, name, match, value, caseSensitive, old.children());
    }
    private static Condition group(Logic logic, List<Condition> children) {
        return new Condition(logic, null, null, null, null, false, children);
    }
    private static Condition defaultLeaf() { return Condition.leaf(Field.METHOD, Match.EXACT, "DELETE"); }

    static void validateRule(Rule rule) {
        try {
            new PolicyEngine().validate(new GuardConfig(1, List.of(), List.of(), List.of(rule), Mode.BLOCK, GuardConfig.defaults().limits()));
        } catch (IllegalArgumentException error) {
            // Only known categories are inspected. Never surface the original text, value, or cause.
            String message = switch (error.getMessage() == null ? "" : error.getMessage()) {
                case "INVALID_RULE_ID" -> "규칙 식별자를 사용할 수 없습니다. 취소 후 새 규칙으로 만들거나 가져온 설정을 확인하세요.";
                case "INVALID_RULE" -> "규칙 이름을 1~256자로 입력하고 줄바꿈·제어 문자를 제거하세요. 규칙 동작도 선택하세요.";
                case "INVALID_PATTERN", "PATTERN_LIMIT" -> "정규식을 RE2 문법으로 수정하세요. 2,048자 이내로 입력하고 전방·후방 탐색이나 역참조는 사용하지 마세요.";
                case "INVALID_SELECTOR" -> "이름은 512자 이내로 쿼리·헤더·JSON·폼에만 입력하세요. 다른 항목의 이름은 비우고, 헤더 이름의 공백·제어 문자는 제거하세요.";
                case "INVALID_JSON_POINTER" -> "JSON 선택 경로는 /action처럼 /로 시작하세요. ~는 ~0, /는 ~1로 쓰고 경로 깊이는 32단계 이내로 줄이세요.";
                case "CONFIG_PATTERN_LIMIT" -> "전체 비교 값과 정규식이 너무 큽니다. 조건 수나 비교 값·정규식의 길이를 줄여 다시 저장하세요.";
                default -> "각 묶음에 조건을 하나 이상 추가하세요. 비교 값은 4,096자 이내로 입력하고 제어 문자를 제거하세요. 조건 수와 중첩 제한도 확인하세요.";
            };
            throw new FormValidationException(message);
        }
    }

    static String fieldLabel(Field field) {
        if (field == null) return "항목을 선택하세요";
        return switch (field) {
            case METHOD -> "HTTP 메서드";
            case URL -> "전체 URL";
            case PATH -> "URL 경로";
            case QUERY -> "쿼리 매개변수";
            case HEADER -> "요청 헤더";
            case BODY -> "요청 본문 텍스트";
            case JSON -> "JSON 값";
            case FORM -> "폼 매개변수";
            case ANY -> "검사 가능한 모든 항목";
        };
    }
    static String matchLabel(Match match) {
        if (match == null) return "비교 방법을 선택하세요";
        return switch (match) {
            case CONTAINS -> "문자열 포함";
            case EXACT -> "정확히 일치";
            case REGEX -> "정규식 (RE2)";
        };
    }
    private static String logicLabel(Logic logic) {
        return logic == Logic.AND ? "모두 충족 (AND)" : logic == Logic.OR ? "하나라도 충족 (OR)" : "단일 조건";
    }
    static String describe(Condition condition) {
        if (condition == null) return "조건을 설정하세요";
        if (condition.logic() != Logic.LEAF) return logicLabel(condition.logic()) + " · " + condition.children().size() + "개 하위 조건";
        String selected = condition.name() == null || condition.name().isEmpty() ? "" : " [" + excerpt(condition.name(), 40) + "]";
        return fieldLabel(condition.field()) + selected + " · " + matchLabel(condition.match()) + " ‘" + excerpt(condition.value(), 64) + "’"
                + (condition.caseSensitive() ? " · 대소문자 구분" : "");
    }
    static String excerpt(String value, int limit) {
        if (value == null) return "";
        int end = Math.min(value.length(), limit);
        if (end > 0 && end < value.length() && Character.isHighSurrogate(value.charAt(end - 1))) end--;
        StringBuilder result = new StringBuilder(end + 1);
        for (int i = 0; i < end; i++) result.append(Character.isISOControl(value.charAt(i)) ? ' ' : value.charAt(i));
        if (end < value.length()) result.append('…');
        return result.toString();
    }

    private static final class Node extends DefaultMutableTreeNode {
        private static final long serialVersionUID = 1L;
        private transient Condition data;
        Node(Condition data) { this.data = data; }
        @Override public String toString() {
            return data.logic() == Logic.LEAF ? describe(data) : logicLabel(data.logic()) + " · " + getChildCount() + "개 하위 조건";
        }
    }
    private static final class LiteralTreeRenderer extends DefaultTreeCellRenderer {
        private static final long serialVersionUID = 1L;
        LiteralTreeRenderer() { putClientProperty("html.disable", Boolean.TRUE); setName("condition.treeRenderer"); }
        @Override public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected,
                boolean expanded, boolean leaf, int row, boolean focus) {
            putClientProperty("html.disable", Boolean.TRUE);
            return super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, focus);
        }
    }
    static final class ChoiceRenderer extends DefaultListCellRenderer {
        private static final long serialVersionUID = 1L;
        private final transient Function<Object, String> label;
        ChoiceRenderer(Function<Object, String> label) { this.label = label; putClientProperty("html.disable", Boolean.TRUE); }
        @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
            super.getListCellRendererComponent(list, "", index, selected, focus);
            setText(label.apply(value));
            return this;
        }
    }
    static final class LengthFilter extends DocumentFilter {
        private final int limit;
        private final Runnable rejected;
        LengthFilter(int limit, Runnable rejected) { this.limit = limit; this.rejected = rejected; }
        @Override public void insertString(FilterBypass bypass, int offset, String text, AttributeSet attributes) throws BadLocationException {
            replace(bypass, offset, 0, text, attributes);
        }
        @Override public void replace(FilterBypass bypass, int offset, int length, String text, AttributeSet attributes) throws BadLocationException {
            if ((long) bypass.getDocument().getLength() - length + (text == null ? 0 : text.length()) > limit) rejected.run();
            else bypass.replace(offset, length, text, attributes);
        }
    }
    private static void onEdit(javax.swing.text.JTextComponent component, Runnable changed) {
        component.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { changed.run(); }
            @Override public void removeUpdate(DocumentEvent event) { changed.run(); }
            @Override public void changedUpdate(DocumentEvent event) { changed.run(); }
        });
    }
    static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("EDT_REQUIRED");
    }
    static void name(JComponent component, String name, String accessibleName) {
        component.setName(name);
        component.getAccessibleContext().setAccessibleName(accessibleName);
    }
    static JTextArea information(String name, String accessibleName) {
        JTextArea result = new JTextArea();
        name(result, name, accessibleName);
        result.setEditable(false);
        result.setCaret(new dev.cairnguard.ui.NonScrollingCaret());
        result.setLineWrap(true);
        result.setWrapStyleWord(true);
        result.setOpaque(false);
        result.setFocusable(false);
        result.setFont(javax.swing.UIManager.getFont("Label.font"));
        return result;
    }
    private static JButton button(String name, String text) {
        JButton result = new JButton(text);
        name(result, name, text);
        return result;
    }
    static JLabel label(String text, JComponent control, String name) {
        JLabel result = new JLabel(text);
        result.putClientProperty("html.disable", Boolean.TRUE);
        result.setName(name);
        result.setLabelFor(control);
        return result;
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
    private static void row(JPanel panel, int row, JLabel label, JComponent control) {
        panel.add(label, constraints(0, row));
        panel.add(control, constraints(1, row));
    }
}
