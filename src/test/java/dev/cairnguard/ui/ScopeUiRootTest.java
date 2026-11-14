package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import dev.cairnguard.ui.editor.EditorForm;
import dev.cairnguard.ui.editor.FormValidationException;
import dev.cairnguard.ui.editor.ScopeEditor;
import org.junit.jupiter.api.Test;

import javax.swing.Action;
import javax.swing.ActionMap;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JComboBox;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.Component;
import java.awt.Container;
import java.awt.KeyboardFocusManager;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

import static org.junit.jupiter.api.Assertions.*;

class ScopeUiRootTest {
    @Test void scopeListsRecordsInstalledKeyActionsWithoutSaving() throws Exception {
        edt(() -> {
            Access access = new Access();
            GuardPanel panel = new GuardPanel(access, new Human(), false);
            try {
                JTabbedPane lists = find(panel, "scope.lists", JTabbedPane.class);
                assertEquals(3, lists.getTabCount());
                assertEquals(0, lists.getSelectedIndex());
                Map<String, Object> facts = new LinkedHashMap<>();
                facts.put("java", Map.of("version", System.getProperty("java.version"),
                        "runtimeVersion", System.getProperty("java.runtime.version"), "vendor", System.getProperty("java.vendor")));
                facts.put("lookAndFeelClass", UIManager.getLookAndFeel().getClass().getName());
                facts.put("uiClass", lists.getUI().getClass().getName());
                facts.put("component", lists.getName());
                facts.put("tabLayoutPolicy", lists.getTabLayoutPolicy());
                facts.put("tabPlacement", lists.getTabPlacement());
                facts.put("leftToRight", lists.getComponentOrientation().isLeftToRight());
                facts.put("selectionFollowsFocus", UIManager.get("TabbedPane.selectionFollowsFocus"));
                facts.put("focusTraversalKeysEnabled", lists.getFocusTraversalKeysEnabled());
                facts.put("forwardTraversalKeys", lists.getFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS).stream().map(Object::toString).toList());
                facts.put("backwardTraversalKeys", lists.getFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS).stream().map(Object::toString).toList());
                Map<String, KeyStroke> strokes = new LinkedHashMap<>();
                strokes.put("END", KeyStroke.getKeyStroke(KeyEvent.VK_END, 0));
                strokes.put("RIGHT", KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0));
                strokes.put("CTRL_TAB", KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK));
                List<Map<String, Object>> scopes = new ArrayList<>();
                for (int condition : List.of(JComponent.WHEN_FOCUSED, JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT, JComponent.WHEN_IN_FOCUSED_WINDOW)) {
                    Map<String, Object> scope = new LinkedHashMap<>();
                    scope.put("condition", condition);
                    List<Map<String, Object>> chain = new ArrayList<>();
                    for (InputMap map = lists.getInputMap(condition); map != null; map = map.getParent()) {
                        Map<String, Object> layer = new LinkedHashMap<>();
                        layer.put("class", map.getClass().getName());
                        layer.put("identity", identity(map));
                        List<Map<String, Object>> bindings = new ArrayList<>();
                        for (var stroke : strokes.entrySet()) {
                            Map<String, Object> binding = new LinkedHashMap<>();
                            Object key = map.get(stroke.getValue());
                            binding.put("key", stroke.getKey());
                            binding.put("keyStroke", stroke.getValue().toString());
                            binding.put("local", contains(map.keys(), stroke.getValue()));
                            binding.put("effectiveActionKey", key);
                            binding.put("resolvedAction", action(key == null ? null : lists.getActionMap().get(key)));
                            bindings.add(binding);
                        }
                        layer.put("bindings", bindings);
                        chain.add(layer);
                    }
                    scope.put("inputMapChain", chain);
                    scopes.add(scope);
                }
                facts.put("inputScopes", scopes);
                List<Map<String, Object>> actions = new ArrayList<>();
                for (ActionMap map = lists.getActionMap(); map != null; map = map.getParent()) {
                    Map<String, Object> layer = new LinkedHashMap<>();
                    layer.put("class", map.getClass().getName());
                    layer.put("identity", identity(map));
                    List<Map<String, Object>> bindings = new ArrayList<>();
                    for (var stroke : strokes.entrySet()) {
                        Map<String, Object> binding = new LinkedHashMap<>();
                        Object key = lists.getInputMap(JComponent.WHEN_FOCUSED).get(stroke.getValue());
                        binding.put("key", stroke.getKey());
                        binding.put("actionKey", key);
                        binding.put("local", contains(map.keys(), key));
                        binding.put("resolvedAction", action(key == null ? null : map.get(key)));
                        bindings.add(binding);
                    }
                    layer.put("bindings", bindings);
                    actions.add(layer);
                }
                facts.put("actionMapChain", actions);
                assertEquals(0, lists.getSelectedIndex(), "observation must not invoke an action or synthesize a tab selection");
                assertSame(access.policy, access.config());
                assertEquals(0, access.writes);
                System.out.println("SCOPE_KEYMAP_JSON " + Json.MAPPER.writeValueAsString(facts));
            } finally {
                panel.close();
            }
            return null;
        });
    }

    @Test void scopeEditorTextMinimumFollowsFontAppliedAfterConstruction() throws Exception {
        edt(() -> {
            ScopeEntry original = new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/api\\E\\z");
            ScopeEditor editor = new ScopeEditor(List.of(original), List.of(0));
            JTextField host = find(editor.component(), "scope.host", JTextField.class);
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("construction", metrics(host));
            fonts(editor.component(), 14);
            facts.put("current14", metrics(host));
            fonts(editor.component(), 28);
            facts.put("current28", metrics(host));
            JTextField ordinary = new JTextField(host.getText(), host.getColumns());
            ordinary.setBorder(host.getBorder());
            ordinary.setFont(host.getFont());
            facts.put("ordinarySameFontAndBorder", metrics(ordinary));
            int currentLine = host.getFontMetrics(host.getFont()).getHeight();
            int required = currentLine + host.getInsets().top + host.getInsets().bottom;
            assertTrue(ordinary.getMinimumSize().height >= required, "ordinary current-font native sizing positive control");
            assertEquals(List.of(original), editor.value());
            System.out.println("SCOPE_ROOT_METRICS_JSON " + Json.MAPPER.writeValueAsString(facts));
            assertTrue(host.getMinimumSize().height >= required,
                    "scope.host minimum must fit a complete current-font line plus insets: minimum="
                            + host.getMinimumSize().height + ", required=" + required + ", glyphLine=" + currentLine);
            return null;
        });
    }

    @Test void scopeEditorWrappedRowsKeepNaturalHeightAtViewportWidth() throws Exception {
        edt(() -> {
            List<ScopeEntry> compact = List.of(
                    new ScopeEntry(true, "example.test", "https", 80, "\\A\\Q/api\\E\\z"),
                    new ScopeEntry(true, "example.test", "https", 80, "\\A\\Q/manager\\E\\z"),
                    new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/api\\E\\z"),
                    new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/manager\\E\\z"));
            List<ScopeEntry> irregular = List.of(compact.get(0), compact.get(3),
                    new ScopeEntry(false, "*.Example.test.", "AnY", 0, "(?i)/line\n\r\t"),
                    new ScopeEntry(false, "[2001:db8::1]", "HTTPS", 443, "\\A\\Q/a\\E.*\\Q/b\\E\\z"));
            for (int font : List.of(14, 28)) for (List<ScopeEntry> original : List.of(compact, irregular)) {
                ScopeEditor editor = new ScopeEditor(original, java.util.stream.IntStream.range(0, original.size()).boxed().toList());
                JScrollPane root = (JScrollPane) editor.component();
                String shape = original == compact ? "compact" : "irregular";
                JTable members = find(root, "scope.members.table", JTable.class);
                JScrollPane memberPane = members == null ? null : (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, members);
                javax.swing.table.JTableHeader memberHeader = members == null ? null : members.getTableHeader();
                if (members != null) {
                    assertNotNull(memberPane, "member table retains its owned scroll pane");
                    assertNotNull(memberHeader, "member table retains its native header");
                    assertSame(members, memberPane.getViewport().getView());
                    assertSame(members, memberHeader.getTable());
                    observeHeadlessHeader("before-attachment", shape, font, members, memberPane);
                    memberPane.setColumnHeaderView(memberHeader);
                    assertSame(memberHeader, memberPane.getColumnHeader().getView());
                    assertSame(memberPane.getColumnHeader(), memberHeader.getParent());
                    assertTrue(SwingUtilities.isDescendingFrom(memberHeader, root), "normal fixture traversal owns the header before fonts");
                    observeHeadlessHeader("attached-before-font", shape, font, members, memberPane);
                }
                fonts(root, font);
                if (members != null) {
                    assertSame(memberHeader, members.getTableHeader());
                    assertEquals(font, memberHeader.getFont().getSize(), "normal fixture font traversal reaches the attached native header");
                    observeHeadlessHeader("after-font-before-layout", shape, font, members, memberPane);
                }
                for (int width : List.of(600, 900, 600)) {
                    layoutViewport(root, width);
                    if (members != null) {
                        assertSame(members, memberPane.getViewport().getView());
                        assertSame(memberHeader, members.getTableHeader());
                        assertSame(memberHeader, memberPane.getColumnHeader().getView());
                        assertSame(memberPane.getColumnHeader(), memberHeader.getParent());
                        assertEquals(font, memberHeader.getFont().getSize());
                        observeHeadlessHeader("after-layout", shape, font, members, memberPane);
                    }
                    assertNaturalScopeLayout(root);
                    assertEquals(original, editor.value());
                }
                JComboBox<?> mode = find(root, "scope.pathMode", JComboBox.class);
                int initialMode = mode.getSelectedIndex();
                JTextArea regex = find(root, "scope.regex", JTextArea.class);
                String initialRegex = regex.getText();
                mode.setSelectedIndex(2);
                layoutViewport(root, 600);
                assertNaturalScopeLayout(root);
                mode.setSelectedIndex(3);
                regex.setText("[");
                assertThrows(FormValidationException.class, editor::value);
                layoutViewport(root, 600);
                assertNaturalScopeLayout(root);
                regex.setText(initialRegex);
                mode.setSelectedIndex(initialMode);
                JTextField port = find(root, "scope.port", JTextField.class);
                String initialPorts = port.getText();
                port.setText("80,,443");
                assertThrows(FormValidationException.class, editor::value);
                layoutViewport(root, 600);
                assertNaturalScopeLayout(root);
                port.setText(initialPorts);
                assertEquals(original, editor.value());
            }
            return null;
        });
    }

    private static void layoutViewport(JScrollPane root, int width) {
        root.setSize(width, 400);
        // Fixed headless fixture passes: assign viewport width, then consume native wrapped preferred heights.
        layout(root);
        layout(root);
    }

    private static void layout(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) if (child instanceof Container nested) layout(nested);
    }

    private static void assertNaturalScopeLayout(JScrollPane root) {
        JComponent form = find(root, "scope.form", JComponent.class);
        assertTrue(form.getHeight() > root.getViewport().getHeight(), "excess natural height scrolls rather than compressing rows");
        int bottom = form.getInsets().top;
        for (Component row : form.getComponents()) {
            assertTrue(row.getY() >= bottom, "scope rows must not overlap");
            assertTrue(row.getHeight() >= row.getPreferredSize().height, "each row keeps its current native preferred height");
            bottom = row.getY() + row.getHeight();
        }
        for (String name : List.of("scope.url", "scope.host", "scope.port")) {
            JTextField field = find(root, name, JTextField.class);
            int line = field.getFontMetrics(field.getFont()).getHeight();
            assertTrue(field.getHeight() - field.getInsets().top - field.getInsets().bottom >= line, name + " complete current-font glyph line");
            assertTrue(field.getWidth() - field.getInsets().left - field.getInsets().right >= field.getFontMetrics(field.getFont()).stringWidth(field.getText()), name + " actual short input width");
        }
        for (String name : List.of("scope.intro", "scope.urlGuidance", "scope.hostGuidance", "scope.pathGuidance", "scope.message", "scope.members.help", "scope.allPaths")) {
            JTextArea note = find(root, name, JTextArea.class);
            if (note == null || !note.isVisible()) continue;
            int span = (int) Math.ceil(note.getUI().getRootView(note).getPreferredSpan(javax.swing.text.View.Y_AXIS));
            assertTrue(note.getWidth() > 0);
            assertTrue(note.getHeight() - note.getInsets().top - note.getInsets().bottom >= span, name + " full current wrapped text span");
        }
        for (String name : List.of("scope.pathScroll", "scope.regexScroll", "scope.previewScroll")) {
            JScrollPane scroll = find(root, name, JScrollPane.class);
            if (!scroll.isVisible()) continue;
            JTextArea area = (JTextArea) scroll.getViewport().getView();
            int line = area.getFontMetrics(area.getFont()).getHeight();
            assertTrue(scroll.getViewport().getExtentSize().height >= line + area.getInsets().top + area.getInsets().bottom, name + " complete native line viewport");
        }
        JTable members = find(root, "scope.members.table", JTable.class);
        if (members != null) {
            assertTrue(members.getRowHeight() >= members.getFontMetrics(members.getFont()).getHeight());
            assertEquals(members.getRowHeight() * Math.min(4, members.getRowCount()), members.getPreferredScrollableViewportSize().height);
            JScrollPane scroll = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, members);
            assertTrue(scroll.getViewport().getExtentSize().height >= members.getRowHeight(), "complete native member row");
            assertTrue(members.getTableHeader().getHeight() >= members.getTableHeader().getFontMetrics(members.getTableHeader().getFont()).getHeight(), "complete current-font header");
        }
    }

    private static void observeHeadlessHeader(String phase, String shape, int font, JTable members, JScrollPane pane) throws Exception {
        javax.swing.table.JTableHeader header = members.getTableHeader();
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("phase", phase); facts.put("shape", shape); facts.put("fontParameter", font);
        facts.put("headerIdentity", identity(header)); facts.put("parentClass", header.getParent() == null ? "null" : header.getParent().getClass().getName());
        facts.put("parentIdentity", header.getParent() == null ? "null" : identity(header.getParent()));
        facts.put("attachedToOwnPane", pane.getColumnHeader() != null && pane.getColumnHeader().getView() == header);
        facts.put("tableIsOwnViewportView", pane.getViewport().getView() == members);
        facts.put("headerFont", header.getFont().toString()); facts.put("headerFontSize", header.getFont().getSize());
        facts.put("bounds", header.getBounds().toString()); facts.put("preferred", header.getPreferredSize().toString());
        facts.put("glyphLine", header.getFontMetrics(header.getFont()).getHeight());
        System.out.println("SCOPE_HEADLESS_HEADER_FIXTURE_JSON " + Json.MAPPER.writeValueAsString(facts));
    }

    private static boolean contains(Object[] keys, Object key) {
        return keys != null && Arrays.asList(keys).contains(key);
    }

    private static String identity(Object value) { return Integer.toHexString(System.identityHashCode(value)); }

    private static Map<String, Object> action(Action action) {
        if (action == null) return Map.of();
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("class", action.getClass().getName());
        facts.put("name", action.getValue(Action.NAME));
        facts.put("enabled", action.isEnabled());
        facts.put("identity", identity(action));
        return facts;
    }

    private static Map<String, Object> metrics(JTextField field) {
        return Map.of("fontName", field.getFont().getName(), "fontStyle", field.getFont().getStyle(), "fontSize", field.getFont().getSize(),
                "glyphLine", field.getFontMetrics(field.getFont()).getHeight(), "minimumHeight", field.getMinimumSize().height,
                "preferredHeight", field.getPreferredSize().height, "insetsTop", field.getInsets().top, "insetsBottom", field.getInsets().bottom);
    }

    private static void fonts(Component component, int size) {
        if (component.getFont() != null) component.setFont(component.getFont().deriveFont((float) size));
        if (component instanceof Container container) for (Component child : container.getComponents()) fonts(child, size);
    }

    private static <T extends Component> T find(Component root, String name, Class<T> type) {
        if (name.equals(root.getName())) return type.cast(root);
        if (root instanceof Container container) for (Component child : container.getComponents()) {
            T found = find(child, name, type);
            if (found != null) return found;
        }
        return null;
    }

    private static <T> T edt(Callable<T> call) throws Exception {
        FutureTask<T> task = new FutureTask<>(call);
        SwingUtilities.invokeAndWait(task);
        try { return task.get(); }
        catch (ExecutionException error) {
            if (error.getCause() instanceof Error failure) throw failure;
            if (error.getCause() instanceof Exception failure) throw failure;
            throw error;
        }
    }

    private static final class Human implements GuardPanel.Dialogs {
        @Override public boolean confirm(Component parent, String message) { throw new AssertionError("unexpected confirmation"); }
        @Override public Path chooseExport(Component parent, String extension) { throw new AssertionError("unexpected export"); }
        @Override public void error(Component parent, String message) { throw new AssertionError(message); }
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, java.util.function.Consumer<GuardPanel.SubmitConfirmation> save) { throw new AssertionError("unexpected editor"); }
    }

    private static final class Access implements GuardUiAccess {
        final GuardConfig policy = GuardConfig.defaults();
        int writes;
        @Override public GuardConfig config() { return policy; }
        @Override public Map<String, Object> status() { return Map.of("projectId", "ui-root-synthetic", "revision", 1L, "closed", false, "paused", false, "passthrough", false, "guardState", "PROTECTED"); }
        @Override public List<TrafficEntry> traffic() { return List.of(); }
        @Override public List<Pending> approvals() { return List.of(); }
        @Override public void refreshProject() {}
        @Override public void updateConfig(GuardConfig config, String project, long revision) { writes++; throw new AssertionError("observation must not save"); }
        @Override public boolean decideApproval(String id, boolean allow) { throw new AssertionError("unexpected approval"); }
        @Override public void bookmark(String id, boolean value) { throw new AssertionError("unexpected bookmark"); }
        @Override public String exportJson(List<TrafficEntry> entries) { throw new AssertionError("unexpected export"); }
        @Override public String exportHar(List<TrafficEntry> entries) { throw new AssertionError("unexpected export"); }
        @Override public void clearEvidence() { throw new AssertionError("unexpected clear"); }
        @Override public void pause(boolean paused) { throw new AssertionError("unexpected pause"); }
        @Override public void passthrough(boolean enabled, String project, long revision) { throw new AssertionError("unexpected protection change"); }
    }
}
