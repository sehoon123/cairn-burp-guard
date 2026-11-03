package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.policy.PolicyEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.basic.BasicHTML;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.math.BigDecimal;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SettingsEditorTest {
    private static final String SECRET = "synthetic-secret-never-echo";
    private static final List<String> INTEGER_FIELDS = List.of("globalRps", "perHostRps", "maxConcurrent", "maxQueued");
    private static final List<String> TIME_FIELDS = List.of("queueTimeoutSeconds", "approvalTimeoutSeconds", "requestTimeoutSeconds");

    @Test void defaultsAreReadableAccessibleAndRoundTripWithoutOpeningAdvanced() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
            assertEquals(new SettingsEditor.Value(GuardConfig.defaults().defaultMode(), GuardConfig.defaults().limits()), editor.value());
            assertEquals("settings.editor", editor.component().getName());
            assertFalse(get(editor, "settings.advanced", JPanel.class).isVisible());
            assertFalse(get(editor, "settings.advanced.toggle", JCheckBox.class).isSelected());
            assertTrue(get(editor, "settings.guidance", JTextArea.class).getText().contains("세션 갱신 기능은 없습니다"));
            Set<String> names = new HashSet<>();
            for (String field : Stream.concat(INTEGER_FIELDS.stream(), TIME_FIELDS.stream()).toList()) {
                JSpinner spinner = spinner(editor, field);
                assertTrue(names.add(spinner.getName()));
                assertFalse(spinner.getAccessibleContext().getAccessibleName().isBlank());
                JLabel label = get(editor, spinner.getName() + ".label", JLabel.class);
                assertSame(spinner, label.getLabelFor());
                assertFalse(label.getText().contains("Millis"));
                assertEquals(JFormattedTextField.PERSIST, text(editor, field).getFocusLostBehavior());
                assertEquals(spinner.getName() + ".text", text(editor, field).getName());
            }
            JCheckBox disclosure = get(editor, "settings.advanced.toggle", JCheckBox.class);
            disclosure.doClick();
            assertTrue(get(editor, "settings.advanced", JPanel.class).isVisible());
            disclosure.doClick();
            assertFalse(get(editor, "settings.advanced", JPanel.class).isVisible());
            assertEquals(GuardConfig.defaults().limits(), editor.value().limits());
            assertFalse(get(editor, "settings.hostRps.remove", JButton.class).isEnabled());
            assertEquals(0, table(editor).getRowCount());
            return null;
        });
    }

    @Test void millisecondFractionsAndExistingCanonicalOrAliasKeysRoundTripExactly() throws Exception {
        edt(() -> {
            for (Map<String, Integer> overrides : List.of(
                    Map.of("example.test", 7, "xn--bcher-kva.test", 13, "[0:0:0:0:0:0:0:1]", 2),
                    Map.of("Example.TEST.", 7, "bücher.test", 13, "::1", 2))) {
                Limits limits = new Limits(1_000, 1, overrides, 100, 10_000, 1, 123_457, 599_999);
                GuardConfig initial = config(limits);
                new PolicyEngine().validate(initial);
                SettingsEditor editor = new SettingsEditor(initial);
                assertEquals("0.001", text(editor, "queueTimeoutSeconds").getText());
                assertEquals("123.457", text(editor, "approvalTimeoutSeconds").getText());
                assertEquals("599.999", text(editor, "requestTimeoutSeconds").getText());
                assertEquals(new SettingsEditor.Value(initial.defaultMode(), limits), editor.value());
                assertEquals(overrides, editor.value().limits().hostRps());
            }
            String longHost = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61) + ".";
            GuardConfig initial = config(withHosts(Map.of(longHost, 1_000)));
            SettingsEditor editor = new SettingsEditor(initial);
            assertEquals(longHost, table(editor).getValueAt(0, 0));
            assertEquals(initial.limits(), editor.value().limits());
            return null;
        });
    }

    @Test void typedSpinnerAndActiveHostCellEditsAreCommittedOnlyIntoTheReturnedDraft() throws Exception {
        edt(() -> {
            GuardConfig initial = GuardConfig.defaults();
            SettingsEditor editor = new SettingsEditor(initial);
            text(editor, "globalRps").setText("7");
            text(editor, "perHostRps").setText("4");
            text(editor, "maxConcurrent").setText("3");
            text(editor, "maxQueued").setText("0");
            text(editor, "queueTimeoutSeconds").setText("2.001");
            text(editor, "approvalTimeoutSeconds").setText("3.009");
            text(editor, "requestTimeoutSeconds").setText("4.999");
            assertEquals(5, spinner(editor, "globalRps").getValue());
            get(editor, "settings.defaultMode", JComboBox.class).setSelectedItem(Mode.ASK);
            get(editor, "settings.hostRps.add", JButton.class).doClick();
            JTable hosts = table(editor);
            assertTrue(hosts.isEditing());
            ((JTextField) hosts.getEditorComponent()).setText("api.example.test");
            assertEquals("", hosts.getValueAt(0, 0));
            SettingsEditor.Value result = editor.value();
            assertFalse(hosts.isEditing());
            assertEquals(Mode.ASK, result.defaultMode());
            assertEquals(new Limits(7, 4, Map.of("api.example.test", 5), 3, 0, 2_001, 3_009, 4_999), result.limits());
            assertEquals(GuardConfig.defaults(), initial);
            assertThrows(UnsupportedOperationException.class, () -> result.limits().hostRps().put("other.example.test", 1));
            return null;
        });
    }

    @ParameterizedTest @EnumSource(Mode.class)
    void everyExistingDefaultModeRoundTripsAndAnEmptySelectionFails(Mode mode) throws Exception {
        edt(() -> {
            GuardConfig defaults = GuardConfig.defaults();
            GuardConfig initial = new GuardConfig(defaults.schemaVersion(), defaults.allowScope(), defaults.blockScope(), defaults.rules(), mode, defaults.limits());
            SettingsEditor editor = new SettingsEditor(initial);
            assertEquals(mode, editor.value().defaultMode());
            JComboBox<?> modes = get(editor, "settings.defaultMode", JComboBox.class);
            modes.setSelectedIndex(-1);
            assertTrue(safeError(editor).getMessage().contains("기본 동작"));
            modes.setSelectedItem(mode);
            assertEquals(mode, editor.value().defaultMode());
            return null;
        });
    }

    @Test void activeRateCellIsCommittedWithoutRoundingAndAddRemoveAlsoCommitEdits() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("one.example.test", 2))));
            JTable hosts = table(editor);
            assertTrue(hosts.editCellAt(0, 1));
            ((JTextField) hosts.getEditorComponent()).setText("9");
            assertEquals("2", hosts.getValueAt(0, 1));
            assertEquals(Map.of("one.example.test", 9), editor.value().limits().hostRps());
            assertTrue(hosts.editCellAt(0, 0));
            ((JTextField) hosts.getEditorComponent()).setText("changed.example.test");
            get(editor, "settings.hostRps.add", JButton.class).doClick();
            assertEquals("changed.example.test", hosts.getValueAt(0, 0));
            assertEquals(2, hosts.getRowCount());
            ((JTextField) hosts.getEditorComponent()).setText("two.example.test");
            get(editor, "settings.hostRps.remove", JButton.class).doClick();
            assertEquals(1, hosts.getRowCount());
            assertEquals(Map.of("changed.example.test", 9), editor.value().limits().hostRps());
            return null;
        });
    }

    @Test void numericBoundsAndSpinnerSteppingUseExactMilliseconds() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
            spinner(editor, "globalRps").setValue(1_000);
            spinner(editor, "perHostRps").setValue(1);
            spinner(editor, "maxConcurrent").setValue(100);
            spinner(editor, "maxQueued").setValue(10_000);
            spinner(editor, "queueTimeoutSeconds").setValue(new BigDecimal("0.001"));
            spinner(editor, "approvalTimeoutSeconds").setValue(new BigDecimal("600"));
            spinner(editor, "requestTimeoutSeconds").setValue(new BigDecimal("0.009"));
            assertNull(spinner(editor, "globalRps").getNextValue());
            assertNull(spinner(editor, "perHostRps").getPreviousValue());
            assertNull(spinner(editor, "maxConcurrent").getNextValue());
            assertNull(spinner(editor, "maxQueued").getNextValue());
            assertNull(spinner(editor, "queueTimeoutSeconds").getPreviousValue());
            assertEquals(new BigDecimal("0.002"), spinner(editor, "queueTimeoutSeconds").getNextValue());
            assertNull(spinner(editor, "approvalTimeoutSeconds").getNextValue());
            spinner(editor, "requestTimeoutSeconds").setValue(spinner(editor, "requestTimeoutSeconds").getNextValue());
            Limits result = editor.value().limits();
            assertEquals(1, result.queueTimeoutMillis());
            assertEquals(600_000, result.approvalTimeoutMillis());
            assertEquals(10, result.requestTimeoutMillis());
            text(editor, "queueTimeoutSeconds").setText("0.001000000000000000000");
            assertEquals(1, editor.value().limits().queueTimeoutMillis());
            spinner(editor, "maxQueued").setValue(0);
            assertNull(spinner(editor, "maxQueued").getPreviousValue());
            assertEquals(0, editor.value().limits().maxQueued());
            return null;
        });
    }

    static Stream<Arguments> invalidNumbers() {
        return Stream.concat(
                Stream.of(Arguments.of("globalRps", 0), Arguments.of("globalRps", 1_001),
                        Arguments.of("perHostRps", -1), Arguments.of("perHostRps", 1_001),
                        Arguments.of("maxConcurrent", 0), Arguments.of("maxConcurrent", 101),
                        Arguments.of("maxQueued", -1), Arguments.of("maxQueued", 10_001)),
                Stream.concat(INTEGER_FIELDS.stream(), TIME_FIELDS.stream()).flatMap(field -> Stream.of(
                        Arguments.of(field, Double.NaN), Arguments.of(field, Double.POSITIVE_INFINITY),
                        Arguments.of(field, Double.NEGATIVE_INFINITY), Arguments.of(field, new BigDecimal("999999999999999999999999999999")),
                        Arguments.of(field, new BigDecimal("1E+1000000")))));
    }

    @ParameterizedTest @MethodSource("invalidNumbers")
    void programmaticOutOfBoundsNonFiniteAndHugeNumbersCannotSave(String field, Number invalid) throws Exception {
        edt(() -> {
            GuardConfig initial = GuardConfig.defaults();
            SettingsEditor editor = new SettingsEditor(initial);
            spinner(editor, field).setValue(invalid);
            safeError(editor);
            assertEquals(GuardConfig.defaults(), initial);
            return null;
        });
    }

    @ParameterizedTest @ValueSource(strings = {"globalRps", "perHostRps", "maxConcurrent", "maxQueued"})
    void fractionalIntegerFieldsNeverRoundOrRevertOnCommit(String field) throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
            text(editor, field).setText("5.9");
            safeError(editor);
            assertEquals("5.9", text(editor, field).getText());
            text(editor, field).setText(SECRET);
            safeError(editor);
            return null;
        });
    }

    static Stream<Arguments> invalidTimes() {
        return TIME_FIELDS.stream().flatMap(field -> Stream.of("0", "600.001", "0.0001", "30.0009", "600.00000000000000000001", "0.00099999999999999999999999", "NaN", "Infinity", "1e2", "30,5", " 1 ", "", SECRET)
                .map(value -> Arguments.of(field, value)));
    }

    @ParameterizedTest @MethodSource("invalidTimes")
    void invalidTimeTextCannotRoundToAMillisecondOrRevertToTheOldValue(String field, String input) throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
            text(editor, field).setText(input);
            safeError(editor);
            assertTrue(get(editor, "settings.advanced", JPanel.class).isVisible());
            assertTrue(get(editor, "settings.advanced.toggle", JCheckBox.class).isSelected());
            return null;
        });
    }

    static Stream<Arguments> duplicateHosts() {
        return Stream.of(Arguments.of("Example.test", "example.test."),
                Arguments.of("bücher.test", "xn--bcher-kva.test"),
                Arguments.of("::1", "[0:0:0:0:0:0:0:1]"));
    }

    @ParameterizedTest @MethodSource("duplicateHosts")
    void canonicalAliasesFailInsteadOfSilentlyDroppingOneOverride(String first, String second) throws Exception {
        edt(() -> {
            GuardConfig initial = config(withHosts(Map.of("one.example.test", 3, "two.example.test", 4)));
            SettingsEditor editor = new SettingsEditor(initial);
            table(editor).setValueAt(first, 0, 0);
            table(editor).setValueAt(second, 1, 0);
            FormValidationException error = safeError(editor);
            assertTrue(error.getMessage().contains("중복"));
            assertEquals(2, table(editor).getRowCount());
            assertEquals(Map.of("one.example.test", 3, "two.example.test", 4), initial.limits().hostRps());
            return null;
        });
    }

    @ParameterizedTest @ValueSource(strings = {"", "*.example.test", "https://example.test", "example.test:443", "secret@example.test", "example.test/path", " example.test", "example.test..", "127.1", "0177.0.0.1", "[not-ipv6]", "<html>synthetic-secret-never-echo</html>", "example.test\n"})
    void invalidHostNamesAreRejectedWithFixedActionableMessages(String input) throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("example.test", 2))));
            table(editor).setValueAt(input, 0, 0);
            assertTrue(safeError(editor).getMessage().contains("호스트"));
            return null;
        });
    }

    @ParameterizedTest @ValueSource(strings = {"0", "1001", "4.5", "NaN", "1e2", "", SECRET})
    void invalidOverrideRatesNeverRevertToTheExistingRate(String input) throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("example.test", 2))));
            JTable hosts = table(editor);
            assertTrue(hosts.editCellAt(0, 1));
            ((JTextField) hosts.getEditorComponent()).setText(input);
            assertTrue(safeError(editor).getMessage().contains("정수"));
            assertEquals(input, hosts.getValueAt(0, 1));
            return null;
        });
    }

    @Test void tableRefusingToCommitLeavesTheEditIntactAndDoesNotProduceAValue() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("example.test", 2))));
            JTable hosts = table(editor);
            assertEquals(Boolean.FALSE, hosts.getClientProperty("terminateEditOnFocusLost"));
            hosts.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JTextField()) {
                @Override public boolean stopCellEditing() { return false; }
            });
            assertTrue(hosts.editCellAt(0, 0));
            ((JTextField) hosts.getEditorComponent()).setText("changed.example.test");
            assertTrue(safeError(editor).getMessage().contains("편집"));
            assertTrue(hosts.isEditing());
            assertEquals("example.test", hosts.getValueAt(0, 0));
            get(editor, "settings.hostRps.add", JButton.class).doClick();
            assertEquals(1, hosts.getRowCount());
            assertTrue(hosts.isEditing());
            hosts.getCellEditor().cancelCellEditing();
            assertEquals(Map.of("example.test", 2), editor.value().limits().hostRps());
            hosts.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JTextField()) {
                @Override public boolean stopCellEditing() { throw new IllegalStateException(SECRET); }
            });
            assertTrue(hosts.editCellAt(0, 0));
            safeError(editor);
            hosts.getCellEditor().cancelCellEditing();
            hosts.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JTextField()) {
                @Override public boolean stopCellEditing() { return true; } // Broken editor that never reports editingStopped.
            });
            assertTrue(hosts.editCellAt(0, 0));
            safeError(editor);
            assertTrue(hosts.isEditing());
            hosts.getCellEditor().cancelCellEditing();
            return null;
        });
    }

    @Test void hostRowsAreBoundedWithoutDroppingExistingEntries() throws Exception {
        edt(() -> {
            Map<String, Integer> overrides = new LinkedHashMap<>();
            for (int i = 0; i < 256; i++) overrides.put("host" + i + ".example.test", i % 1_000 + 1);
            GuardConfig initial = config(withHosts(overrides));
            SettingsEditor editor = new SettingsEditor(initial);
            JTable hosts = table(editor);
            JButton add = get(editor, "settings.hostRps.add", JButton.class);
            assertEquals(256, hosts.getRowCount());
            assertFalse(add.isEnabled());
            add.doClick();
            assertEquals(initial.limits(), editor.value().limits());
            hosts.setRowSelectionInterval(0, 0);
            String removed = (String) hosts.getValueAt(0, 0);
            get(editor, "settings.hostRps.remove", JButton.class).doClick();
            assertTrue(add.isEnabled());
            add.doClick();
            assertFalse(add.isEnabled());
            ((JTextField) hosts.getEditorComponent()).setText("replacement.example.test");
            Map<String, Integer> result = editor.value().limits().hostRps();
            assertEquals(256, result.size());
            assertFalse(result.containsKey(removed));
            assertTrue(result.containsKey("replacement.example.test"));
            assertEquals(overrides, initial.limits().hostRps());
            return null;
        });
    }

    @Test void oversizedFieldAndModelEditsAreRejectedNotTruncatedOrSilentlyIgnored() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("example.test", 2))));
            text(editor, "globalRps").setText("1".repeat(33));
            assertTrue(text(editor, "globalRps").getDocument().getLength() <= 32);
            safeError(editor);
            text(editor, "globalRps").setText("5");
            JTable hosts = table(editor);
            assertTrue(hosts.editCellAt(0, 0));
            JTextField field = (JTextField) hosts.getEditorComponent();
            field.setText("a".repeat(256));
            assertTrue(field.getDocument().getLength() <= 255);
            safeError(editor);
            assertTrue(hosts.isEditing());
            field.setText("changed.example.test");
            assertEquals(Map.of("changed.example.test", 2), editor.value().limits().hostRps());
            hosts.setValueAt("1".repeat(33), 0, 1);
            safeError(editor);
            assertEquals("2", hosts.getValueAt(0, 1));
            hosts.setValueAt("3", 0, 1);
            hosts.setValueAt("a".repeat(256), 0, 0);
            safeError(editor);
            hosts.setValueAt("other.example.test", 0, 0);
            assertEquals(Map.of("other.example.test", 3), editor.value().limits().hostRps());
            return null;
        });
    }

    @Test void cancellingADraftAndDiscardingAnActiveEditCannotMutateTheInitialPolicy() throws Exception {
        edt(() -> {
            GuardConfig initial = config(withHosts(Map.of("example.test", 2)));
            GuardConfig snapshot = config(withHosts(Map.of("example.test", 2)));
            SettingsEditor cancelled = new SettingsEditor(initial);
            spinner(cancelled, "globalRps").setValue(9);
            get(cancelled, "settings.defaultMode", JComboBox.class).setSelectedItem(Mode.BLOCK);
            table(cancelled).setValueAt("changed.example.test", 0, 0);
            assertTrue(table(cancelled).editCellAt(0, 1));
            ((JTextField) table(cancelled).getEditorComponent()).setText("5.5");
            // The modal owner discards this form on Cancel; there is no persistence callback to invoke.
            assertEquals(snapshot, initial);
            SettingsEditor reopened = new SettingsEditor(initial);
            assertEquals(new SettingsEditor.Value(initial.defaultMode(), initial.limits()), reopened.value());
            assertEquals(snapshot, initial);
            return null;
        });
    }

    @Test void renderersTreatHostAndUnexpectedComboValuesAsLiteralText() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(config(withHosts(Map.of("example.test", 2))));
            JTable hosts = table(editor);
            String html = "<html><b>synthetic</b></html>";
            hosts.setValueAt(html, 0, 0);
            JLabel rendered = (JLabel) hosts.prepareRenderer(hosts.getCellRenderer(0, 0), 0, 0);
            assertEquals(html, rendered.getText());
            assertEquals(Boolean.TRUE, rendered.getClientProperty("html.disable"));
            assertNull(rendered.getClientProperty(BasicHTML.propertyKey));
            JComboBox<?> modes = get(editor, "settings.defaultMode", JComboBox.class);
            JLabel mode = (JLabel) modes.getRenderer().getListCellRendererComponent(new JList<>(), null, 0, false, false);
            assertEquals(Boolean.TRUE, mode.getClientProperty("html.disable"));
            assertNull(mode.getClientProperty(BasicHTML.propertyKey));
            safeError(editor);
            return null;
        });
    }

    @Test void largeFontsKeepScrollableFormsAndFontRelativeHostRows() throws Exception {
        edt(() -> {
            List<String> keys = List.of("Label.font", "Table.font", "TableHeader.font", "TextField.font", "FormattedTextField.font", "CheckBox.font", "Button.font", "ComboBox.font", "TitledBorder.font");
            Map<String, Object> old = new LinkedHashMap<>();
            try {
                for (String key : keys) {
                    old.put(key, UIManager.get(key));
                    Font font = UIManager.getFont(key);
                    UIManager.put(key, (font == null ? new Font(Font.DIALOG, Font.PLAIN, 12) : font).deriveFont(24f));
                }
                SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
                get(editor, "settings.advanced.toggle", JCheckBox.class).doClick();
                JScrollPane root = (JScrollPane) editor.component();
                root.setSize(1_000, 640);
                layout(root);
                layout(root);
                assertEquals(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER, root.getHorizontalScrollBarPolicy());
                assertTrue(root.getVerticalScrollBar().getMaximum() > root.getVerticalScrollBar().getVisibleAmount());
                JTable hosts = table(editor);
                assertTrue(hosts.getFont().getSize() >= 24);
                assertTrue(hosts.getRowHeight() >= hosts.getFontMetrics(hosts.getFont()).getHeight() + 6);
                assertTrue(spinner(editor, "globalRps").getWidth() >= 80);
                assertEquals(GuardConfig.defaults().limits(), editor.value().limits());
                hosts.setFont(hosts.getFont().deriveFont(32f));
                assertTrue(hosts.getRowHeight() >= hosts.getFontMetrics(hosts.getFont()).getHeight() + 6);
                get(editor, "settings.hostRps.add", JButton.class).doClick();
                assertEquals(hosts.getFont(), hosts.getEditorComponent().getFont());
                hosts.getCellEditor().cancelCellEditing();
            } finally { old.forEach(UIManager::put); }
            return null;
        });
    }

    @Test void constructorComponentAndValueAreEdtOnlyAndInvalidLoadedPoliciesFailClosed() throws Exception {
        assertThrows(IllegalStateException.class, () -> new SettingsEditor(GuardConfig.defaults()));
        SettingsEditor editor = edt(() -> new SettingsEditor(GuardConfig.defaults()));
        assertThrows(IllegalStateException.class, editor::component);
        assertThrows(IllegalStateException.class, editor::value);
        edt(() -> {
            assertSafe(assertThrows(FormValidationException.class, () -> new SettingsEditor(null)));
            Limits base = GuardConfig.defaults().limits();
            Limits invalid = new Limits(0, base.perHostRps(), Map.of(), base.maxConcurrent(), base.maxQueued(), 1, 1, 1);
            assertSafe(assertThrows(FormValidationException.class, () -> new SettingsEditor(config(invalid))));
            assertSafe(assertThrows(FormValidationException.class, () -> new SettingsEditor(config(withHosts(Map.of("EXAMPLE.test", 2, "example.test.", 3))))));
            Map<String, Integer> tooMany = new LinkedHashMap<>();
            for (int i = 0; i < 257; i++) tooMany.put("host" + i + ".example.test", 2);
            assertSafe(assertThrows(FormValidationException.class, () -> new SettingsEditor(config(withHosts(tooMany)))));
            return null;
        });
    }

    private static Limits withHosts(Map<String, Integer> hosts) {
        Limits d = GuardConfig.defaults().limits();
        return new Limits(d.globalRps(), d.perHostRps(), hosts, d.maxConcurrent(), d.maxQueued(), d.queueTimeoutMillis(), d.approvalTimeoutMillis(), d.requestTimeoutMillis());
    }

    private static GuardConfig config(Limits limits) {
        GuardConfig d = GuardConfig.defaults();
        return new GuardConfig(d.schemaVersion(), d.allowScope(), d.blockScope(), d.rules(), d.defaultMode(), limits);
    }

    private static FormValidationException safeError(SettingsEditor editor) {
        FormValidationException error = assertThrows(FormValidationException.class, editor::value);
        assertSafe(error);
        return error;
    }

    private static void assertSafe(FormValidationException error) {
        assertNull(error.getCause());
        assertFalse(error.getMessage().contains(SECRET));
        assertFalse(error.getMessage().contains("Exception"));
        assertFalse(error.getMessage().contains("INVALID_"));
        assertTrue(error.getMessage().codePoints().anyMatch(c -> c >= 0xac00 && c <= 0xd7a3));
        assertTrue(error.getMessage().length() < 300);
    }

    private static JSpinner spinner(SettingsEditor editor, String field) { return get(editor, "settings." + field, JSpinner.class); }
    private static JFormattedTextField text(SettingsEditor editor, String field) { return ((JSpinner.DefaultEditor) spinner(editor, field).getEditor()).getTextField(); }
    private static JTable table(SettingsEditor editor) { return get(editor, "settings.hostRps.table", JTable.class); }
    private static <T extends Component> T get(SettingsEditor editor, String name, Class<T> type) {
        Component found = find(editor.component(), name);
        assertNotNull(found, name);
        return type.cast(found);
    }
    private static Component find(Component root, String name) {
        if (name.equals(root.getName())) return root;
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                Component found = find(child, name);
                if (found != null) return found;
            }
        }
        return null;
    }
    private static void layout(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) if (child instanceof Container nested) layout(nested);
    }
    private static <T> T edt(Callable<T> action) throws Exception {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { result.set(action.call()); }
            catch (Throwable e) { error.set(e); }
        });
        if (error.get() instanceof Exception e) throw e;
        if (error.get() instanceof Error e) throw e;
        return result.get();
    }
}
