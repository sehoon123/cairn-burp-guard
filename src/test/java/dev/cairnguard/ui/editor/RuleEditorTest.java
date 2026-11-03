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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.plaf.basic.BasicHTML;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RuleEditorTest {
    @Test void smallOrLargeFontWindowScrollsTheWholeFormInsteadOfCollapsingConditions() throws Exception {
        edt(() -> {
            for (float fontSize : new float[]{14f, 28f}) {
                RuleEditor editor = new RuleEditor(null);
                javax.swing.JScrollPane root = assertInstanceOf(javax.swing.JScrollPane.class, editor.component());
                setFontDeep(root, fontSize);
                root.setSize(900, 480);
                layoutDeep(root);
                Component view = root.getViewport().getView();
                javax.swing.Scrollable scrolling = assertInstanceOf(javax.swing.Scrollable.class, view);
                assertTrue(scrolling.getScrollableTracksViewportWidth()); assertFalse(scrolling.getScrollableTracksViewportHeight());
                assertTrue(view.getHeight() > root.getViewport().getHeight(), "complete form must scroll at " + fontSize);
                assertTrue(get(editor, "condition.tree", javax.swing.JTree.class).getHeight() >= 150, "tree must remain usable");
                assertTrue(get(editor, "condition.field", JComboBox.class).getHeight() >= 20, "field must not disappear");
                assertTrue(get(editor, "condition.value", JTextArea.class).getHeight() >= 50, "comparison input must not disappear");
                assertEquals("DELETE", editor.value().condition().value());
            }
            return null;
        });
    }
    private static void setFontDeep(Component component, float size) {
        component.setFont(component.getFont().deriveFont(size));
        if (component instanceof Container parent) for (Component child : parent.getComponents()) setFontDeep(child, size);
    }
    private static void layoutDeep(Component component) {
        if (component instanceof Container parent) { parent.doLayout(); for (Component child : parent.getComponents()) layoutDeep(child); }
    }

    @Test void existingIdsNamesModesEnabledAndNestedFieldsRoundTripExactly() throws Exception {
        Condition nested = new Condition(Logic.AND, null, "", null, null, true, List.of(
                new Condition(Logic.LEAF, Field.HEADER, "X-Operation", Match.REGEX, "(?i)delete|remove", true, List.of()),
                new Condition(Logic.OR, null, null, null, "", false, List.of(
                        new Condition(Logic.LEAF, Field.JSON, "/a~1b/0", Match.EXACT, "delete", true, List.of()),
                        new Condition(Logic.LEAF, Field.PATH, null, Match.CONTAINS, "/items", false, List.of())))));
        edt(() -> {
            for (Mode mode : Mode.values()) for (boolean enabled : List.of(true, false)) {
                Rule source = new Rule("existing.id_1", "  기존 이름 그대로  ", enabled, mode, nested);
                RuleEditor editor = new RuleEditor(source);
                assertEquals(source, editor.value());
                assertEquals(source, editor.value(), "reading twice cannot mutate the loaded draft");
                get(editor, "rule.name", JTextField.class).setText("변경한 이름");
                get(editor, "rule.mode", JComboBox.class).setSelectedItem(Mode.ASK);
                get(editor, "rule.enabled", JCheckBox.class).doClick();
                Rule result = editor.value();
                assertEquals(source.id(), result.id());
                assertEquals(source.condition(), result.condition());
                assertEquals("변경한 이름", result.name());
                assertEquals(Mode.ASK, result.mode());
                assertEquals(!enabled, result.enabled());
            }
            return null;
        });
    }

    @Test void newIdsAreUniqueStableAndPolicyCompatibleWithoutAnyExternalAccess() throws Exception {
        edt(() -> {
            RuleEditor first = new RuleEditor(null);
            RuleEditor second = new RuleEditor(null);
            Rule firstValue = first.value();
            assertTrue(firstValue.id().startsWith("rule-"));
            assertEquals(41, firstValue.id().length());
            assertEquals(firstValue.id(), first.value().id());
            assertNotEquals(firstValue.id(), second.value().id());
            assertTrue(firstValue.enabled());
            assertEquals(Mode.BLOCK, firstValue.mode());
            assertEquals(Condition.leaf(Field.METHOD, Match.EXACT, "DELETE"), firstValue.condition());
            return null;
        });
    }

    @Test void quickPresetsOnlyReplaceFieldsAfterExplicitApplyAndKeepIdAndEnabled() throws Exception {
        edt(() -> {
            Rule source = new Rule("keep-this-id", "기존 규칙", false, Mode.MONITOR,
                    new Condition(Logic.LEAF, Field.QUERY, "action", Match.EXACT, "existing", true, List.of()));
            RuleEditor editor = new RuleEditor(source);
            JComboBox<?> presets = get(editor, "rule.preset", JComboBox.class);
            JButton apply = get(editor, "rule.applyPreset", JButton.class);
            assertFalse(apply.isEnabled());
            for (int index = 1; index < presets.getItemCount(); index++) {
                Rule beforeSelection = editor.value();
                presets.setSelectedIndex(index);
                assertEquals(beforeSelection, editor.value(), "selecting an example is not a destructive action");
                apply.doClick();
                Rule value = editor.value();
                assertEquals("keep-this-id", value.id());
                assertFalse(value.enabled());
                assertEquals(index <= 2 ? Mode.BLOCK : Mode.ASK, value.mode());
                switch (index) {
                    case 1 -> assertEquals(Condition.leaf(Field.METHOD, Match.EXACT, "DELETE"), value.condition());
                    case 2 -> {
                        assertEquals(Logic.OR, value.condition().logic());
                        assertEquals(List.of("POST", "PUT", "PATCH", "DELETE"), value.condition().children().stream().map(Condition::value).toList());
                    }
                    case 3 -> {
                        assertEquals(Field.PATH, value.condition().field());
                        assertEquals(Match.REGEX, value.condition().match());
                        assertEquals("^/admin(?:/.*)?$", value.condition().value());
                    }
                    case 4 -> {
                        assertEquals(Field.JSON, value.condition().field());
                        assertEquals("/action", value.condition().name());
                        assertEquals("delete", value.condition().value());
                    }
                    default -> fail("unexpected preset");
                }
                assertNotNull(get(editor, "condition.tree", javax.swing.JTree.class));
                assertTrue(get(editor, "rule.status", JTextArea.class).getText().contains("아직"));
            }
            return null;
        });
    }

    @Test void presetsHaveUsefulNarrowPolicySemanticsOnSyntheticRequests() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(null);
            JComboBox<?> presets = get(editor, "rule.preset", JComboBox.class);
            for (int index = 1; index <= 4; index++) {
                presets.setSelectedIndex(index);
                get(editor, "rule.applyPreset", JButton.class).doClick();
                Rule rule = editor.value();
                switch (index) {
                    case 1 -> {
                        assertEquals(Mode.BLOCK, evaluate(rule, "DELETE", "/items", "", ""));
                        assertEquals(Mode.ALLOW, evaluate(rule, "GET", "/items", "", ""));
                    }
                    case 2 -> {
                        assertEquals(Mode.BLOCK, evaluate(rule, "PATCH", "/items", "", ""));
                        assertEquals(Mode.ALLOW, evaluate(rule, "GET", "/items", "", ""));
                    }
                    case 3 -> {
                        assertEquals(Mode.ASK, evaluate(rule, "GET", "/admin/items", "", ""));
                        assertEquals(Mode.ALLOW, evaluate(rule, "GET", "/administrator", "", ""));
                    }
                    case 4 -> {
                        assertEquals(Mode.ASK, evaluate(rule, "POST", "/items", "application/json", "{\"action\":\"delete\"}"));
                        assertEquals(Mode.ALLOW, evaluate(rule, "POST", "/items", "application/json", "{\"other\":\"delete\"}"));
                    }
                    default -> fail("unexpected preset");
                }
            }
            return null;
        });
    }

    @Test void emptyNamesBadIdsAndUnselectedModesUseFixedActionableErrors() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(null);
            JTextField name = get(editor, "rule.name", JTextField.class);
            for (String invalid : List.of("", "   ", "synthetic-secret\nname", "synthetic\u0000secret")) {
                name.setText(invalid);
                FormValidationException error = assertThrows(FormValidationException.class, editor::value);
                assertTrue(error.getMessage().contains("규칙 이름"));
                assertFalse(error.getMessage().contains("synthetic"));
                assertNull(error.getCause());
            }
            name.setText("좋은 이름");
            get(editor, "rule.mode", JComboBox.class).setSelectedItem(null);
            assertThrows(FormValidationException.class, editor::value);
            RuleEditor badId = new RuleEditor(new Rule("synthetic-private bad id", "좋은 이름", true, Mode.BLOCK,
                    Condition.leaf(Field.METHOD, Match.EXACT, "DELETE")));
            FormValidationException error = assertThrows(FormValidationException.class, badId::value);
            assertTrue(error.getMessage().contains("식별자"));
            assertFalse(error.getMessage().contains("synthetic"));
            assertNull(error.getCause());
            return null;
        });
    }

    @Test void namesAreBoundedWithoutSilentTruncationAndInvalidLoadedNamesAreNotReplaced() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(null);
            JTextField name = get(editor, "rule.name", JTextField.class);
            name.setText("가".repeat(256));
            assertEquals(256, editor.value().name().length());
            name.setText("synthetic-private".repeat(100));
            assertEquals("가".repeat(256), name.getText());
            assertEquals(name.getText(), editor.value().name());
            assertFalse(get(editor, "rule.status", JTextArea.class).getText().contains("synthetic-private"));
            RuleEditor oversized = new RuleEditor(new Rule("id", "가".repeat(257), true, Mode.BLOCK,
                    Condition.leaf(Field.METHOD, Match.EXACT, "DELETE")));
            assertThrows(FormValidationException.class, oversized::value);
            assertTrue(get(oversized, "rule.status", JTextArea.class).getText().contains("취소"));
            return null;
        });
    }

    @Test void missingLoadedConditionCannotBeSilentlyReplacedByTheNewRuleDefault() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(new Rule("missing", "조건 없는 규칙", true, Mode.BLOCK, null));
            FormValidationException error = assertThrows(FormValidationException.class, editor::value);
            assertTrue(error.getMessage().contains("조건이 없습니다"));
            assertTrue(get(editor, "rule.status", JTextArea.class).getText().contains("취소"));
            return null;
        });
    }

    @Test void disabledRulesStillValidateConditionsAndNeverExposeRawPatternErrors() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(new Rule("disabled", "사용 안 하는 규칙", false, Mode.BLOCK,
                    Condition.leaf(Field.BODY, Match.REGEX, "(?=synthetic-private-pattern)")));
            FormValidationException error = assertThrows(FormValidationException.class, editor::value);
            assertTrue(error.getMessage().contains("RE2"));
            assertFalse(error.getMessage().contains("synthetic-private-pattern"));
            assertNull(error.getCause());
            return null;
        });
    }

    @Test void controlsAreAccessibleUniquelyNamedAndHumanRenderersNeverInterpretHtml() throws Exception {
        edt(() -> {
            RuleEditor editor = new RuleEditor(null);
            assertUniqueNames(editor.component(), new HashSet<>());
            for (String control : List.of("rule.name", "rule.enabled", "rule.mode", "rule.preset", "rule.applyPreset",
                    "condition.tree", "condition.field", "condition.selector", "condition.match", "condition.value", "condition.caseSensitive")) {
                JComponent found = get(editor, control, JComponent.class);
                assertNotNull(found.getAccessibleContext().getAccessibleName(), control);
                assertFalse(found.getAccessibleContext().getAccessibleName().isBlank(), control);
            }
            JComboBox<?> modes = get(editor, "rule.mode", JComboBox.class);
            assertEquals(4, modes.getItemCount());
            for (int i = 0; i < modes.getItemCount(); i++) {
                JLabel label = render(modes, modes.getItemAt(i));
                assertTrue(label.getText().contains("—"));
                assertNull(label.getClientProperty(BasicHTML.propertyKey));
            }
            assertEquals(get(editor, "rule.name", JTextField.class), get(editor, "rule.nameLabel", JLabel.class).getLabelFor());
            assertEquals("조건을 설정하세요", RuleEditor.summary(null));
            return null;
        });
    }

    @Test void lifecycleIsEdtOnly() throws Exception {
        assertThrows(IllegalStateException.class, () -> new RuleEditor(null));
        RuleEditor editor = edt(() -> new RuleEditor(null));
        assertThrows(IllegalStateException.class, editor::component);
        assertThrows(IllegalStateException.class, editor::value);
    }

    private static Mode evaluate(Rule rule, String method, String path, String contentType, String body) {
        GuardConfig config = new GuardConfig(1, List.of(new ScopeEntry(true, "api.example.test", "https", 443, "")),
                List.of(), List.of(rule), Mode.ALLOW, GuardConfig.defaults().limits());
        List<RequestData.Header> headers = contentType.isEmpty() ? List.of() : List.of(new RequestData.Header("Content-Type", contentType));
        return new PolicyEngine().evaluate(config, new RequestData(method, "https://api.example.test" + path,
                "api.example.test", 443, true, headers, body.getBytes(StandardCharsets.UTF_8))).mode();
    }
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static JLabel render(JComboBox<?> combo, Object item) {
        return (JLabel) ((javax.swing.ListCellRenderer) combo.getRenderer()).getListCellRendererComponent(new JList<>(), item, 0, false, false);
    }
    private static void assertUniqueNames(Component root, Set<String> names) {
        if (root.getName() != null) assertTrue(names.add(root.getName()), "duplicate name: " + root.getName());
        if (root instanceof Container parent) for (Component child : parent.getComponents()) assertUniqueNames(child, names);
    }
    private static <T extends Component> T get(RuleEditor editor, String name, Class<T> type) {
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
