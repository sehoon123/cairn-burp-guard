package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.awt.Component;
import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class ConditionEditorTest {
    @Test void everyFieldAndNestedMetadataRoundTripsWithoutNormalization() throws Exception {
        Condition nested = group(Logic.AND, "", "", true, List.of(
                new Condition(Logic.LEAF, Field.METHOD, null, Match.EXACT, "DELETE", true, List.of()),
                group(Logic.OR, null, null, false, List.of(
                        leaf(Field.URL, "", Match.REGEX, "https://api\\.example\\.test/.*", false),
                        leaf(Field.PATH, "", Match.CONTAINS, "/items", true),
                        leaf(Field.QUERY, "Action", Match.EXACT, "Delete", true),
                        leaf(Field.HEADER, "X-Operation", Match.EXACT, "delete", false),
                        leaf(Field.BODY, null, Match.CONTAINS, "operation=delete\n\t", false),
                        leaf(Field.JSON, "/items/0/a~1b~0c", Match.EXACT, "delete", true),
                        leaf(Field.FORM, "", Match.CONTAINS, "delete", false),
                        leaf(Field.ANY, null, Match.CONTAINS, "", false)))));
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(nested);
            assertEquals(nested, editor.value());
            JTree tree = get(editor, "condition.tree", JTree.class);
            var nodes = ((DefaultMutableTreeNode) tree.getModel().getRoot()).preorderEnumeration();
            while (nodes.hasMoreElements()) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
                tree.setSelectionPath(new TreePath(node.getPath()));
            }
            assertEquals(nested, editor.value(), "visiting nodes must not turn null into empty or reset case/patterns");
            tree.setSelectionRow(0);
            get(editor, "condition.logic", JComboBox.class).setSelectedItem(Logic.OR);
            Condition changed = editor.value();
            assertEquals(Logic.OR, changed.logic());
            assertEquals(nested.children(), changed.children());
            assertEquals("", changed.name());
            assertEquals("", changed.value());
            assertTrue(changed.caseSensitive(), "ignored legacy group metadata is preserved too");
            return null;
        });
    }

    @Test void editingValueDoesNotMutateAnUntouchedNullSelector() throws Exception {
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(leaf(Field.PATH, null, Match.EXACT, "/old", true));
            get(editor, "condition.value", JTextArea.class).setText("/new");
            assertNull(editor.value().name());
            assertTrue(editor.value().caseSensitive());
            assertEquals("/new", editor.value().value());
            return null;
        });
    }

    @Test void allNineFieldsHaveHumanLabelsSelectorsAndCaseControls() throws Exception {
        edt(() -> {
            for (Field field : Field.values()) {
                ConditionEditor editor = new ConditionEditor(null);
                JComboBox<?> fields = get(editor, "condition.field", JComboBox.class);
                assertEquals(9, fields.getItemCount());
                fields.setSelectedItem(field);
                JTextField selector = get(editor, "condition.selector", JTextField.class);
                String name = switch (field) {
                    case QUERY, FORM -> "Action";
                    case HEADER -> "X-Operation";
                    case JSON -> "/Action";
                    default -> "";
                };
                assertEquals(!name.isEmpty(), selector.isEnabled());
                if (!name.isEmpty()) selector.setText(name);
                get(editor, "condition.match", JComboBox.class).setSelectedItem(Match.CONTAINS);
                get(editor, "condition.value", JTextArea.class).setText("DeLeTe");
                get(editor, "condition.caseSensitive", JCheckBox.class).doClick();
                assertEquals(leaf(field, name, Match.CONTAINS, "DeLeTe", true), editor.value());
                assertFalse(get(editor, "condition.hint", JTextArea.class).getText().isBlank());
                assertEquals(fields, get(editor, "condition.fieldLabel", JLabel.class).getLabelFor());
                assertNotNull(fields.getAccessibleContext().getAccessibleName());
            }
            return null;
        });
    }

    @Test void selectorAndCaseControlsKeepTheRealQueryHeaderJsonAndFormSemantics() throws Exception {
        edt(() -> {
            for (Field field : List.of(Field.QUERY, Field.HEADER, Field.JSON, Field.FORM)) {
                String selector = field == Field.HEADER ? "X-Operation" : field == Field.JSON ? "/Action" : "Action";
                ConditionEditor editor = new ConditionEditor(leaf(field, selector, Match.EXACT, "DELETE", false));
                Condition insensitive = editor.value();
                RequestData matching = switch (field) {
                    case QUERY -> request("/items?action=delete", List.of(), "");
                    case HEADER -> request("/items", List.of(new RequestData.Header("x-operation", "delete")), "");
                    case JSON -> request("/items", List.of(new RequestData.Header("Content-Type", "application/json")), "{\"Action\":\"delete\"}");
                    case FORM -> request("/items", List.of(new RequestData.Header("Content-Type", "application/x-www-form-urlencoded")), "action=delete");
                    default -> throw new AssertionError();
                };
                assertEquals(Mode.BLOCK, evaluate(insensitive, matching));
                get(editor, "condition.caseSensitive", JCheckBox.class).doClick();
                assertEquals(Mode.ALLOW, evaluate(editor.value(), matching), "case option must affect the actual comparison");
                if (field == Field.HEADER) {
                    RequestData sameValue = request("/items", List.of(new RequestData.Header("x-operation", "DELETE")), "");
                    assertEquals(Mode.BLOCK, evaluate(editor.value(), sameValue), "header selector names always ignore case");
                }
                if (field == Field.JSON) {
                    RequestData wrongKey = request("/items", List.of(new RequestData.Header("Content-Type", "application/json")), "{\"action\":\"DELETE\"}");
                    assertEquals(Mode.ALLOW, evaluate(insensitive, wrongKey), "JSON pointer keys always distinguish case");
                }
            }
            return null;
        });
    }

    @Test void changingFieldNeverSilentlyDiscardsAnExistingSelector() throws Exception {
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(leaf(Field.QUERY, "synthetic-selector", Match.EXACT, "delete", true));
            get(editor, "condition.field", JComboBox.class).setSelectedItem(Field.PATH);
            JTextField selector = get(editor, "condition.selector", JTextField.class);
            assertEquals("synthetic-selector", selector.getText());
            assertTrue(selector.isEnabled(), "the user must still be able to clear the incompatible selector");
            FormValidationException error = assertThrows(FormValidationException.class, editor::value);
            assertFalse(error.getMessage().contains("synthetic-selector"));
            assertTrue(error.getMessage().contains("비우"));
            selector.setText("");
            assertEquals(Field.PATH, editor.value().field());
            assertEquals("", editor.value().name());
            assertFalse(selector.isEnabled());
            return null;
        });
    }

    @Test void visualActionsAddNestEditAndRemoveLeavesAndBothKindsOfGroups() throws Exception {
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(null);
            assertFalse(get(editor, "condition.addLeaf", JButton.class).isEnabled());
            click(editor, "condition.wrapAnd");
            assertEquals(Logic.AND, editor.value().logic());
            click(editor, "condition.addLeaf");
            get(editor, "condition.field", JComboBox.class).setSelectedItem(Field.PATH);
            get(editor, "condition.match", JComboBox.class).setSelectedItem(Match.REGEX);
            get(editor, "condition.value", JTextArea.class).setText("^/items/.*$");
            JTree tree = get(editor, "condition.tree", JTree.class);
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
            select(tree, (DefaultMutableTreeNode) root.getChildAt(0));
            click(editor, "condition.wrapOr");
            click(editor, "condition.addLeaf");
            get(editor, "condition.value", JTextArea.class).setText("PATCH");
            select(tree, root);
            click(editor, "condition.addAnd");
            assertEquals(Logic.AND, editor.value().children().get(2).logic());
            select(tree, root);
            click(editor, "condition.addOr");
            Condition result = editor.value();
            assertEquals(4, result.children().size());
            assertEquals(Logic.OR, result.children().get(0).logic());
            assertEquals(List.of("DELETE", "PATCH"), result.children().get(0).children().stream().map(Condition::value).toList());
            assertEquals("^/items/.*$", result.children().get(1).value());
            assertEquals(Logic.OR, result.children().get(3).logic());
            // New groups have one editable child, not a hidden always-true/false empty group.
            DefaultMutableTreeNode last = (DefaultMutableTreeNode) root.getChildAt(3);
            select(tree, (DefaultMutableTreeNode) last.getChildAt(0));
            click(editor, "condition.remove");
            assertThrows(FormValidationException.class, editor::value);
            click(editor, "condition.addLeaf");
            assertDoesNotThrow(editor::value);
            select(tree, last);
            get(editor, "condition.logic", JComboBox.class).setSelectedItem(Logic.AND);
            assertEquals(Logic.AND, editor.value().children().get(3).logic());
            click(editor, "condition.remove");
            assertEquals(3, editor.value().children().size());
            assertFalse(get(editor, "condition.remove", JButton.class).isEnabled(), "root cannot be removed");
            return null;
        });
    }

    @ParameterizedTest @ValueSource(strings = {"[", "(?=synthetic-private-pattern)", "(a)\\1", "a{1001}", "a{1000}b{1000}c{1000}d{1000}e{1000}"})
    void invalidRegexErrorsAreFixedKoreanAndNeverEchoInputOrCause(String pattern) throws Exception {
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(leaf(Field.BODY, "", Match.REGEX, pattern, false));
            FormValidationException error = assertThrows(FormValidationException.class, editor::value);
            assertTrue(error.getMessage().startsWith("정규식을 RE2 문법으로 수정하세요."));
            assertFalse(error.getMessage().contains(pattern));
            assertNull(error.getCause());
            return null;
        });
    }

    @Test void selectorsPointersAndUnicodeUseTheSamePolicyValidation() throws Exception {
        edt(() -> {
            for (Condition invalid : List.of(
                    leaf(Field.HEADER, "bad name", Match.EXACT, "x", false),
                    leaf(Field.METHOD, "synthetic-selector", Match.EXACT, "x", false),
                    leaf(Field.JSON, "action", Match.EXACT, "x", false),
                    leaf(Field.JSON, "/a~2b", Match.EXACT, "x", false),
                    leaf(Field.JSON, "/a".repeat(33), Match.EXACT, "x", false),
                    leaf(Field.BODY, "", Match.EXACT, "synthetic\u0000private", false),
                    leaf(Field.BODY, "", Match.EXACT, "\ud800", false))) {
                FormValidationException error = assertThrows(FormValidationException.class, () -> new ConditionEditor(invalid).value());
                assertNull(error.getCause());
                assertFalse(error.getMessage().contains("synthetic"));
                assertFalse(error.getMessage().contains("~2"));
            }
            return null;
        });
    }

    @Test void textLimitsRejectWholeChangesWithoutTruncatingOrDroppingExistingValues() throws Exception {
        edt(() -> {
            ConditionEditor editor = new ConditionEditor(leaf(Field.QUERY, "action", Match.EXACT, "original", false));
            JTextArea value = get(editor, "condition.value", JTextArea.class);
            value.setText("x".repeat(4_096));
            assertEquals(4_096, editor.value().value().length());
            value.setText("private-overflow".repeat(400));
            assertEquals("x".repeat(4_096), value.getText());
            assertEquals("x".repeat(4_096), editor.value().value());
            assertFalse(get(editor, "condition.status", JTextArea.class).getText().contains("private-overflow"));
            JTextField selector = get(editor, "condition.selector", JTextField.class);
            selector.setText("s".repeat(512));
            assertEquals(512, editor.value().name().length());
            selector.setText("s".repeat(513));
            assertEquals(512, editor.value().name().length());
            get(editor, "condition.match", JComboBox.class).setSelectedItem(Match.REGEX);
            value.setText("x".repeat(2_048));
            assertDoesNotThrow(editor::value);
            value.setText("x".repeat(2_049));
            assertThrows(FormValidationException.class, editor::value);
            assertEquals(2_049, value.getText().length(), "switching modes or validating must not trim patterns");
            return null;
        });
    }

    @Test void initialOversizeShapesAreExplicitlyRejectedWithoutUnboundedRecursion() throws Exception {
        Condition deep = Condition.leaf(Field.ANY, Match.EXACT, "x");
        for (int i = 0; i < 10_000; i++) deep = group(Logic.AND, null, null, false, List.of(deep));
        Condition tooDeep = deep;
        edt(() -> {
            for (Condition invalid : List.of(tooDeep,
                    group(Logic.AND, null, null, false, Collections.nCopies(65, Condition.leaf(Field.ANY, Match.EXACT, "x"))),
                    leaf(Field.ANY, "", Match.EXACT, "x".repeat(4_097), false),
                    leaf(Field.QUERY, "s".repeat(513), Match.EXACT, "x", false))) {
                ConditionEditor editor = new ConditionEditor(invalid);
                assertThrows(FormValidationException.class, editor::value);
                assertFalse(get(editor, "condition.tree", JTree.class).isEnabled());
                assertTrue(get(editor, "condition.status", JTextArea.class).getText().contains("취소"));
            }
            return null;
        });
    }

    @Test void exactDepthChildAndNodeBoundsAreUsableAndActionsCannotExceedThem() throws Exception {
        Condition deep = Condition.leaf(Field.ANY, Match.EXACT, "x");
        for (int i = 0; i < 16; i++) deep = group(Logic.AND, null, null, false, List.of(deep));
        Condition atDepth = deep;
        Condition leaf = Condition.leaf(Field.ANY, Match.EXACT, "x");
        List<Condition> groups = new ArrayList<>();
        for (int i = 0; i < 31; i++) groups.add(group(Logic.OR, null, null, false, Collections.nCopies(64, leaf)));
        groups.add(group(Logic.AND, null, null, false, Collections.nCopies(31, leaf)));
        Condition atNodes = group(Logic.AND, null, null, false, groups); // 1 + 32 + 2015 = 2048
        edt(() -> {
            ConditionEditor depthEditor = new ConditionEditor(atDepth);
            assertEquals(atDepth, depthEditor.value());
            assertFalse(get(depthEditor, "condition.wrapAnd", JButton.class).isEnabled());
            ConditionEditor nodeEditor = new ConditionEditor(atNodes);
            assertEquals(atNodes, nodeEditor.value());
            assertFalse(get(nodeEditor, "condition.addLeaf", JButton.class).isEnabled());
            assertFalse(get(nodeEditor, "condition.wrapOr", JButton.class).isEnabled());
            JTree tree = get(nodeEditor, "condition.tree", JTree.class);
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
            select(tree, (DefaultMutableTreeNode) root.getChildAt(0));
            assertFalse(get(nodeEditor, "condition.addLeaf", JButton.class).isEnabled());
            assertFalse(get(nodeEditor, "condition.addAnd", JButton.class).isEnabled());
            List<Condition> excessive = new ArrayList<>(groups);
            excessive.set(31, group(Logic.AND, null, null, false, Collections.nCopies(32, leaf)));
            assertThrows(FormValidationException.class, () -> new ConditionEditor(group(Logic.AND, null, null, false, excessive)).value());
            return null;
        });
    }

    @Test void aggregatePatternBudgetIsValidatedEvenWhenEveryLeafIsWithinItsOwnLimit() throws Exception {
        edt(() -> {
            Condition large = group(Logic.OR, null, null, false, Collections.nCopies(17, Condition.leaf(Field.BODY, Match.EXACT, "x".repeat(4_096))));
            FormValidationException error = assertThrows(FormValidationException.class, () -> new ConditionEditor(large).value());
            assertTrue(error.getMessage().contains("전체 비교 값"));
            return null;
        });
    }

    @Test void dynamicTreeRendererIsLiteralAndSummariesAreBounded() throws Exception {
        edt(() -> {
            String markup = "<html><b>synthetic</b><img src='file:///not-a-real-fixture'></html>";
            Condition condition = leaf(Field.QUERY, markup, Match.EXACT, markup, true);
            ConditionEditor editor = new ConditionEditor(condition);
            JTree tree = get(editor, "condition.tree", JTree.class);
            Component rendered = tree.getCellRenderer().getTreeCellRendererComponent(tree, markup, false, false, true, 0, false);
            assertInstanceOf(JLabel.class, rendered);
            assertEquals(markup, ((JLabel) rendered).getText());
            assertNull(((JComponent) rendered).getClientProperty(BasicHTML.propertyKey));
            assertEquals(Boolean.TRUE, ((JComponent) rendered).getClientProperty("html.disable"));
            assertEquals(condition, editor.value());
            String summary = RuleEditor.summary(group(Logic.AND, null, null, false, Collections.nCopies(64, condition)));
            assertTrue(summary.contains("모두 충족"));
            assertTrue(summary.length() <= 241);
            assertFalse(summary.contains("\n"));
            return null;
        });
    }

    @Test void lifecycleIsEdtOnly() throws Exception {
        assertThrows(IllegalStateException.class, () -> new ConditionEditor(null));
        ConditionEditor editor = edt(() -> new ConditionEditor(null));
        assertThrows(IllegalStateException.class, editor::value);
        assertThrows(IllegalStateException.class, editor::component);
    }

    private static Mode evaluate(Condition condition, RequestData request) {
        GuardConfig config = new GuardConfig(1, List.of(new ScopeEntry(true, "api.example.test", "https", 443, "")), List.of(),
                List.of(new Rule("test-rule", "조건 동작 검사", true, Mode.BLOCK, condition)), Mode.ALLOW, GuardConfig.defaults().limits());
        return new PolicyEngine().evaluate(config, request).mode();
    }
    private static RequestData request(String path, List<RequestData.Header> headers, String body) {
        return new RequestData("POST", "https://api.example.test" + path, "api.example.test", 443, true, headers, body.getBytes(StandardCharsets.UTF_8));
    }
    private static Condition leaf(Field field, String name, Match match, String value, boolean caseSensitive) {
        return new Condition(Logic.LEAF, field, name, match, value, caseSensitive, List.of());
    }
    private static Condition group(Logic logic, String name, String value, boolean caseSensitive, List<Condition> children) {
        return new Condition(logic, null, name, null, value, caseSensitive, children);
    }
    private static void select(JTree tree, DefaultMutableTreeNode node) { tree.setSelectionPath(new TreePath(node.getPath())); }
    private static void click(ConditionEditor editor, String name) { get(editor, name, JButton.class).doClick(); }
    private static <T extends Component> T get(ConditionEditor editor, String name, Class<T> type) {
        Component found = find(editor.component(), name);
        assertNotNull(found, name);
        assertInstanceOf(type, found);
        return type.cast(found);
    }
    private static Component find(Component root, String name) {
        if (name.equals(root.getName())) return root;
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            Component found = find(child, name);
            if (found != null) return found;
        }
        return null;
    }
    private static <T> T edt(Callable<T> action) throws Exception {
        FutureTask<T> task = new FutureTask<>(action);
        SwingUtilities.invokeAndWait(task);
        return task.get();
    }
}
