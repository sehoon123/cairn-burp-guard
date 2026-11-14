package dev.cairnguard.ui;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.ui.editor.EditorForm;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.awt.Window;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;
import static org.junit.jupiter.api.Assertions.*;

/** Real isolated-display modal lifecycles with synthetic actions/CAS, NOT native Burp validation. */
@Tag("desktop") @Timeout(30)
class GuardPanelV2DesktopTest {
    @ParameterizedTest @ValueSource(ints={14,28})
    void safetyFormIsScrollableAndCancelReopenKeepsEveryAuthoredSetting(int font) throws Exception {
        try(View v=new View(false)) {
            v.open("settings.edit");JDialog editor=await("editor.dialog");
            edt(()->{
                fonts(editor.getContentPane(),font);editor.setSize(640,600);editor.validate();
                assertTrue(editor.isModal());assertTrue(editor.isResizable());
                JScrollPane scroll=get(editor,"settings.editor",JScrollPane.class);
                assertTrue(scroll.getVerticalScrollBar().isVisible());
                JTextField listener=get(editor,"settings.listenerPorts",JTextField.class);assertFalse(listener.isEditable());
                listener.scrollRectToVisible(new Rectangle(0,0,listener.getWidth(),listener.getHeight()));
                get(editor,"settings.globalRps",JSpinner.class).setValue(8);listener.setText("8080");
                assertEquals(0,v.access.updates);get(editor,"editor.cancel",JButton.class).doClick(0);return null;
            });
            awaitClosed(editor);assertEquals(0,v.access.updates);
            v.open("settings.edit");JDialog reopened=await("editor.dialog");
            edt(()->{assertEquals(0,((Number)get(reopened,"settings.globalRps",JSpinner.class).getValue()).intValue());assertEquals("",get(reopened,"settings.listenerPorts",JTextField.class).getText());get(reopened,"editor.cancel",JButton.class).doClick(0);return null;});awaitClosed(reopened);
            assertEquals(0,v.access.updates);assertEquals(GuardConfig.defaults(),v.access.policy);
        }
    }

    @Test void allRatesOffIsOnlyADraftUntilExplicitModalSaveAndReopensAsZero() throws Exception {
        try(View v=new View(false)) {
            edt(()-> {
                var d=v.access.policy; var old=d.limits();
                var l=new GuardConfig.Limits(7,3,java.util.Map.of("Example.TEST.",2),old.maxConcurrent(),old.maxQueued(),
                        old.queueTimeoutMillis(),old.approvalTimeoutMillis(),old.requestTimeoutMillis());
                v.access.policy=new GuardConfig(2,d.allowScope(),d.blockScope(),d.rules(),d.defaultMode(),l);
                v.panel.refreshNow(); return null;
            });
            var initial=v.access.policy;
            for(boolean save:List.of(false,true)) {
                v.open("settings.edit");var editor=await("editor.dialog");
                edt(()-> {
                    var off=get(editor,"settings.rates.off",JButton.class);
                    assertNotNull(off.getAccessibleContext().getAccessibleName()); off.doClick(0);
                    assertEquals(0,v.access.updates); assertEquals(initial,v.access.policy);
                    assertEquals(0,((Number)get(editor,"settings.globalRps",JSpinner.class).getValue()).intValue());
                    assertEquals(0,((Number)get(editor,"settings.perHostRps",JSpinner.class).getValue()).intValue());
                    var hosts=get(editor,"settings.hostRps.table",JTable.class);
                    assertEquals("Example.TEST.",hosts.getValueAt(0,0)); assertEquals("0",hosts.getValueAt(0,1));
                    get(editor,save?"editor.save":"editor.cancel",JButton.class).doClick(0); return null;
                });
                awaitClosed(editor); assertEquals(save?1:0,v.access.updates);
            }
            assertEquals(java.util.Map.of("Example.TEST.",0),v.access.policy.limits().hostRps());
            assertEquals(initial.limits().requestTimeoutMillis(),v.access.policy.limits().requestTimeoutMillis());
            v.open("settings.edit");var reopened=await("editor.dialog");
            edt(()-> {assertEquals(0,((Number)get(reopened,"settings.globalRps",JSpinner.class).getValue()).intValue());
                get(reopened,"editor.cancel",JButton.class).doClick(0);return null;}); awaitClosed(reopened);
            assertEquals("p",v.access.casProject); assertEquals(7,v.access.casRevision); assertTrue(v.dialogs.errors.isEmpty());
        }
    }

    @ParameterizedTest @ValueSource(strings={"listener-clear","probe"})
    void legacyListenerClearAndHealthGetRequireASecondSafeCancelDefaultConfirmation(String kind) throws Exception {
        try(View v=new View(false)) {
            if(kind.equals("listener-clear"))edt(()->{GuardConfig d=v.access.policy;v.access.policy=new GuardConfig(d.schemaVersion(),d.allowScope(),d.blockScope(),d.rules(),d.defaultMode(),d.limits(),List.of(8080));v.panel.refreshNow();return null;});
            for(boolean accept:List.of(false,true)) {
                v.open("settings.edit");JDialog editor=await("editor.dialog");
                edt(()->{if(kind.equals("listener-clear")){JTextField ports=get(editor,"settings.listenerPorts",JTextField.class);assertTrue(ports.isEditable());assertEquals("8080",ports.getText());ports.setText("");}else {
                    get(editor,"settings.probes.enabled",JCheckBox.class).setSelected(true);get(editor,"settings.probes.add",JButton.class).doClick(0);
                    JTable routes=get(editor,"settings.probes.table",JTable.class);routes.setValueAt("example.test",0,1);routes.setValueAt("/health",0,3);
                }return null;});
                asyncClick(editor,"editor.save");JDialog warning=await("message.dialog");
                edt(()->{assertEquals("dialog.cancel",warning.getRootPane().getDefaultButton().getName());String text=get(warning,"dialog.body",JTextArea.class).getText();assertTrue(text.contains(kind.equals("listener-clear")?"모든 Proxy":"부작용"));assertEquals(0,v.access.updates);get(warning,accept?"dialog.confirm":"dialog.cancel",JButton.class).doClick(0);return null;});
                awaitClosed(warning);awaitClosed(editor);
                assertEquals(accept?1:0,v.access.updates);
            }
            if(kind.equals("listener-clear"))assertTrue(v.access.policy.guardListenerPorts().isEmpty());else assertTrue(v.access.policy.limits().healthProbePassthrough());
            assertEquals("p",v.access.casProject);assertEquals(7,v.access.casRevision);assertTrue(v.dialogs.errors.isEmpty());
        }
    }

    @ParameterizedTest @ValueSource(ints={14,28})
    void migrationDiffOptionalRemovalCancelAndExplicitSaveAreRealModalActions(int font) throws Exception {
        try(View v=new View(true)) {
            v.open("migration.review");JDialog editor=await("editor.dialog");
            edt(()->{fonts(editor.getContentPane(),font);editor.setSize(640,600);editor.validate();assertFalse(get(editor,"migration.removeLegacy",JCheckBox.class).isSelected());assertEquals(v.access.original,get(editor,"migration.original",JTextArea.class).getText());get(editor,"migration.removeLegacy",JCheckBox.class).doClick(0);get(editor,"editor.cancel",JButton.class).doClick(0);return null;});awaitClosed(editor);
            assertEquals(0,v.access.updates);v.open("migration.review");JDialog second=await("editor.dialog");
            edt(()->{assertFalse(get(second,"migration.removeLegacy",JCheckBox.class).isSelected());return null;});
            asyncClick(second,"editor.save");JDialog confirm=await("message.dialog");
            edt(()->{assertEquals(0,v.access.updates);assertEquals("dialog.cancel",confirm.getRootPane().getDefaultButton().getName());get(confirm,"dialog.confirm",JButton.class).doClick(0);return null;});awaitClosed(confirm);awaitClosed(second);
            assertEquals(1,v.access.updates);assertEquals(2,v.access.policy.rules().size());assertFalse(v.access.pendingMigration);assertTrue(v.dialogs.errors.isEmpty());
        }
    }

    @Test
    void forcedJvmUiScaleMatchesTheGraphicsTransformAndTheTrafficViewerShowsAnOriginalBeyondTheEditorLimitInFull() throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless(), "actual isolated nonheadless Swing is required");
        String forced=System.getProperty("sun.java2d.uiScale");
        double transform=edt(()->java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration().getDefaultTransform().getScaleX());
        assertNotNull(forced,"the desktopTest task must force the Java UI scale");
        assertEquals(Double.parseDouble(forced),transform,0.0001,"actual graphics transform must follow the forced uiScale");
        try(View v=new View(false)) {
            String big="C".repeat(GuardPanel.MAX_EDITOR_CHARS+2048)+"-DESKTOP-END";
            edt(()->{v.access.store.begin("p","Synthetic",new dev.cairnguard.model.RequestData("POST","https://example.test/large","example.test",443,true,List.of(new dev.cairnguard.model.RequestData.Header("Content-Type","text/plain; charset=UTF-8")),big.getBytes(java.nio.charset.StandardCharsets.UTF_8)),new dev.cairnguard.model.Decision(GuardConfig.Mode.ALLOW,"DEFAULT_ALLOW",List.of()),7);v.panel.refreshNow();
                JTable t=get(v.panel,"traffic.table",JTable.class);t.setRowSelectionInterval(0,0);return null;});
            v.open("traffic.detail");JDialog detail=await("editor.dialog");
            GuardPanelTrafficViewTest.await(()->get(detail,"traffic.request",JTextArea.class).getText().endsWith(big));
            edt(()->{JTextArea request=get(detail,"traffic.request",JTextArea.class);
                assertFalse(request.isEditable());assertTrue(request.getText().endsWith(big),"complete original, selectable and scrollable");
                request.select(0,5);assertEquals(5,request.getSelectedText().length());
                assertNotNull(SwingUtilities.getAncestorOfClass(JScrollPane.class,request));
                for(Window w:Window.getWindows())if(w instanceof JDialog d&&d.isShowing())d.dispose();return null;});
        }
    }

    @Test void loggerHistoryInlineFilterPreviewCurrentOrderPopoutAndResizeAreRealSwing() throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless());
        try (View v = new View(false)) {
            edt(() -> {
                for (String path : List.of("/c", "/a", "/b")) {
                    String id = v.access.store.begin("p", "Synthetic", new dev.cairnguard.model.RequestData("POST", "https://example.test" + path, "example.test", 443, true,
                            List.of(new dev.cairnguard.model.RequestData.Header("Content-Type", "text/plain; charset=UTF-8")), "desktop-body-literal".getBytes(java.nio.charset.StandardCharsets.UTF_8)), new dev.cairnguard.model.Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
                    v.access.store.response(id, 200, List.of(new dev.cairnguard.model.RequestData.Header("Content-Type", "text/html")), ("<h1>Static " + path + "</h1><table><tr><td>one</td><td>two</td></tr></table>").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
                v.panel.refreshNow(); get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(3);
                get(v.panel, "traffic.search", JTextField.class).setText("DESKTOP-body-literal"); return null;
            });
            GuardPanelTrafficViewTest.await(() -> !get(v.panel, "traffic.count", JLabel.class).getText().contains("pending"));
            edt(() -> { JTable t = get(v.panel, "traffic.table", JTable.class); assertEquals(3, t.getRowCount());
                t.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING))); t.setRowSelectionInterval(0, 0); return null; });
            GuardPanelTrafficViewTest.await(() -> get(v.panel, "traffic.request", JTextArea.class).getText().contains("/a"));
            edt(() -> {
                assertTrue(v.frame.isShowing()); assertTrue(get(v.panel, "traffic.request", JTextArea.class).isShowing()); assertTrue(get(v.panel, "traffic.response", JTextArea.class).isShowing());
                get(v.panel, "traffic.next", JButton.class).doClick(0); return null;
            });
            GuardPanelTrafficViewTest.await(() -> get(v.panel, "traffic.request", JTextArea.class).getText().contains("/b"));
            edt(() -> { get(v.panel, "traffic.responseTabs", JTabbedPane.class).setSelectedIndex(3); return null; });
            GuardPanelTrafficViewTest.await(() -> GuardPanelV2Test.find(v.panel, "traffic.preview.table") != null);
            JTextArea inline = edt(() -> get(v.panel, "traffic.request", JTextArea.class));
            v.open("traffic.detail"); JDialog detail = await("editor.dialog");
            GuardPanelTrafficViewTest.await(() -> get(detail, "traffic.request", JTextArea.class).getText().contains("/b"));
            JTextArea retainedPopout = edt(() -> get(detail, "traffic.request", JTextArea.class));
            edt(() -> {
                assertNotSame(inline, retainedPopout); assertNotSame(inline.getDocument(), retainedPopout.getDocument()); assertTrue(inline.isShowing());
                get(detail, "traffic.next", JButton.class).doClick(0); return null;
            });
            GuardPanelTrafficViewTest.await(() -> retainedPopout.getText().contains("/c") && inline.getText().contains("/c"));
            edt(() -> { get(detail, "editor.save", JButton.class).doClick(0); return null; }); awaitClosed(detail);
            edt(() -> {
                assertEquals("", retainedPopout.getText(), "disposed window loses retained plaintext even with a held widget reference"); assertTrue(inline.getText().contains("/c"));
                v.frame.setSize(720, 560); v.frame.validate();
                JSplitPane history = get(v.panel, "traffic.history", JSplitPane.class), pair = get(v.panel, "traffic.pair", JSplitPane.class);
                history.setDividerLocation(0.40); pair.setDividerLocation(0.50); v.frame.validate();
                assertTrue(history.getHeight() > 80, "small/high-DPI history remains resizable: " + history.getSize());
                assertTrue(pair.getLeftComponent().getWidth() > 20); assertTrue(pair.getRightComponent().getWidth() > 20);
                history.setDividerLocation(1.0); history.setDividerLocation(0.4); v.frame.validate(); assertTrue(pair.isShowing());
                v.panel.close(); assertEquals("", inline.getText()); return null;
            });
            assertTrue(v.dialogs.errors.isEmpty()); assertEquals(0, v.access.updates);
        }
    }

    @ParameterizedTest @ValueSource(ints={14,28})
    void scopedSearchControlsErrorAndResetRemainReachableByKeyboardInSmallWindows(int font) throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless());
        try (View v = new View(false)) {
            edt(() -> {
                v.access.addRaw("synthetic-intent", "synthetic-run", "forwarded"); v.panel.refreshNow();
                get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(3);
                fonts(v.panel, font); v.frame.setSize(720, 560); v.frame.validate();
                assertFalse(get(v.panel, "traffic.more", JCheckBox.class).isSelected());
                return null;
            });
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            JComboBox<?> mode = edt(() -> get(v.panel, "traffic.searchMode", JComboBox.class));
            JComboBox<?> location = edt(() -> get(v.panel, "traffic.searchLocation", JComboBox.class));
            JTextField search = edt(() -> get(v.panel, "traffic.search", JTextField.class));
            JButton reset = edt(() -> get(v.panel, "traffic.reset", JButton.class));
            for (JComponent control : List.of(search, location, mode, reset)) {
                reachable(v.frame, control);
                edt(() -> {
                    assertTrue(control.isFocusable()); assertNotNull(control.getAccessibleContext().getAccessibleName(), control.getName());
                    if (!(control instanceof JButton)) assertSame(control, get(v.panel, control.getName() + ".label", JLabel.class).getLabelFor());
                    assertEquals(Boolean.TRUE, control.getClientProperty("html.disable")); return null;
                });
            }
            reachable(v.frame, location); edt(() -> { assertTrue(location.requestFocusInWindow()); return null; });
            GuardPanelTrafficViewTest.await(location::isFocusOwner);
            press(robot, java.awt.event.KeyEvent.VK_END);
            GuardPanelTrafficViewTest.await(() -> location.getSelectedItem() == TrafficSearch.Location.RESPONSE_BODY);
            press(robot, java.awt.event.KeyEvent.VK_HOME);
            GuardPanelTrafficViewTest.await(() -> location.getSelectedItem() == TrafficSearch.Location.ALL);
            reachable(v.frame, mode); edt(() -> { assertTrue(mode.requestFocusInWindow()); return null; });
            GuardPanelTrafficViewTest.await(mode::isFocusOwner); press(robot, java.awt.event.KeyEvent.VK_END);
            GuardPanelTrafficViewTest.await(() -> mode.getSelectedItem() == TrafficSearch.MatchMode.RE2);
            reachable(v.frame, search); edt(() -> { assertTrue(search.requestFocusInWindow()); return null; });
            GuardPanelTrafficViewTest.await(search::isFocusOwner); press(robot, java.awt.event.KeyEvent.VK_OPEN_BRACKET);
            JTextArea error = edt(() -> get(v.panel, "traffic.searchError", JTextArea.class));
            GuardPanelTrafficViewTest.await(() -> error.isVisible() && error.getText().contains("BAD_RE2")); reachable(v.frame, error);
            edt(() -> { assertTrue(error.getLineWrap()); assertTrue(error.getWrapStyleWord()); assertFalse(error.isEditable());
                assertEquals(0, get(v.panel, "traffic.table", JTable.class).getRowCount()); v.panel.refreshNow(); assertTrue(error.getText().contains("BAD_RE2"));
                System.out.printf("SCOPED_SEARCH_UI scale=%s font=%d window=%dx%d error=%s location=%s mode=%s%n", System.getProperty("sun.java2d.uiScale"), font,
                        v.frame.getWidth(), v.frame.getHeight(), error.getBounds(), location.getBounds(), mode.getBounds()); return null; });
            reachable(v.frame, reset); edt(() -> { assertTrue(reset.requestFocusInWindow()); return null; });
            GuardPanelTrafficViewTest.await(reset::isFocusOwner); press(robot, java.awt.event.KeyEvent.VK_SPACE);
            GuardPanelTrafficViewTest.await(() -> !error.isVisible() && search.getText().isEmpty());
            edt(() -> { assertEquals(TrafficSearch.Location.ALL, location.getSelectedItem()); assertEquals(TrafficSearch.MatchMode.LITERAL, mode.getSelectedItem());
                assertEquals(1, get(v.panel, "traffic.table", JTable.class).getRowCount()); assertEquals(0, v.access.updates); assertEquals(0, v.access.runtimeCalls); return null; });
            assertTrue(v.dialogs.errors.isEmpty());
        }
    }
    @ParameterizedTest @ValueSource(ints={14,28})
    void scopeUxAddPreviewSaveAndReopenExactPortsAndPaths(int font) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
            var parent = scopeParentSetup(v, font, robot, "add-edit");
            v.open("scope.allow.add"); JDialog editor = await("editor.dialog"); scopeSize(v, editor, font);
            scopePaste(robot, editor, get(editor, "scope.host", JTextField.class), "example.test");
            scopeCapture(robot, v, editor, "add-host", font, parent);
            scopePaste(robot, editor, get(editor, "scope.port", JTextField.class), "80,443");
            scopeCapture(robot, v, editor, "add-port", font, parent);
            JTextArea paths = get(editor, "scope.path", JTextArea.class);
            scopePaste(robot, editor, paths, "/api"); press(robot, java.awt.event.KeyEvent.VK_ENTER); scopeInsert(robot, "/manager");
            GuardPanelTrafficViewTest.await(() -> paths.getText().equals("/api\n/manager"));
            scopeCapture(robot, v, editor, "add-path", font, parent);
            assertEquals(0, v.access.updates); assertTrue(edt(editor::isShowing), "path Enter inserts a line, never saves");
            press(robot, java.awt.event.KeyEvent.VK_TAB); GuardPanelTrafficViewTest.await(() -> !paths.isFocusOwner());
            robot.keyPress(java.awt.event.KeyEvent.VK_SHIFT); press(robot, java.awt.event.KeyEvent.VK_TAB); robot.keyRelease(java.awt.event.KeyEvent.VK_SHIFT); robot.waitForIdle();
            GuardPanelTrafficViewTest.await(paths::isFocusOwner);
            JComboBox<?> scheme = get(editor, "scope.scheme", JComboBox.class);
            scopeChoose(robot, editor, scheme, 2);
            assertTrue(edt(() -> get(editor, "scope.preview", JTextArea.class).getText().contains("각 포트에 두 방식")));
            scopeChoose(robot, editor, scheme, 0);
            scopeActivate(robot, editor, get(editor, "scope.anyPort", JCheckBox.class));
            assertTrue(edt(() -> get(editor, "scope.preview", JTextArea.class).getText().contains("모든 포트")));
            scopeActivate(robot, editor, get(editor, "scope.anyPort", JCheckBox.class));
            scopeChoose(robot, editor, get(editor, "scope.pathMode", JComboBox.class), 2);
            assertTrue(edt(() -> get(editor, "scope.preview", JTextArea.class).getText().contains("모든 경로 (제한 없음)")));
            scopeChoose(robot, editor, get(editor, "scope.pathMode", JComboBox.class), 0);
            String preview = scopeCopyPreview(robot, editor);
            assertTrue(preview.contains("모든 4쌍"));
            for (String path : List.of("/api", "/manager")) assertTrue(preview.contains("\\A\\Q" + path + "\\E\\z"));
            scopeCapture(robot, v, editor, "add", font, parent);
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class)); awaitClosed(editor);
            assertEquals(1, v.access.updates); scopePolicy(v.access.policy, "/manager");
            edt(() -> {
                v.access.policy = dev.cairnguard.model.PolicyCodec.decode(dev.cairnguard.model.PolicyCodec.encode(v.access.policy)).config();
                v.panel.refreshNow(); get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(1);
                JTable table = get(v.panel, "scope.allow.table", JTable.class); table.getRowSorter().toggleSortOrder(3); return null;
            });
            scopeOpenAll(robot, v); JDialog reopened = await("editor.dialog"); scopeSize(v, reopened, font);
            assertEquals("80,443", edt(() -> get(reopened, "scope.port", JTextField.class).getText()));
            assertEquals("/api\n/manager", edt(() -> get(reopened, "scope.path", JTextArea.class).getText()));
            scopePaste(robot, reopened, get(reopened, "scope.path", JTextArea.class), "/api\n/manager2");
            scopeCapture(robot, v, reopened, "edit-path", font, parent);
            assertTrue(scopeCopyPreview(robot, reopened).contains("제거·교체 2개"));
            scopeCapture(robot, v, reopened, "edit", font, parent);
            scopeActivate(robot, reopened, get(reopened, "editor.save", JButton.class)); awaitClosed(reopened);
            assertEquals(2, v.access.updates); scopePolicy(v.access.policy, "/manager2");
            scopeSaved(v, "add-edit", font);
            assertTrue(v.dialogs.errors.isEmpty());
                    } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "add-edit", failure); }
                catch (Throwable captureFailure) { failure.addSuppressed(captureFailure); }
                throw failure;
            }
}
    }

    @ParameterizedTest @ValueSource(ints={14,28})
    void scopeUxIrregularMembersKeepPairsAndLegacyExpressions(int font) throws Exception {
        try (View v = new View(false)) {
            List<GuardConfig.ScopeEntry> original = List.of(scopeEntry(80, "/api"), scopeEntry(443, "/manager"),
                    new GuardConfig.ScopeEntry(false, "*.Example.test.", "AnY", 0, "(?i)/line\n\r\t"),
                    new GuardConfig.ScopeEntry(false, "[2001:db8::1]", "HTTPS", 443, "\\A\\Q/a\\E.*\\Q/b\\E\\z"));
            edt(() -> { GuardConfig d = v.access.policy; v.access.policy = new GuardConfig(2, original, d.blockScope(), d.rules(), d.defaultMode(), d.limits()); v.panel.refreshNow();
                get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(1); return null; });
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
            var parent = scopeParentSetup(v, font, robot, "members");
            scopeOpenAll(robot, v); JDialog noOp = await("editor.dialog"); scopeSize(v, noOp, font);
            scopeCapture(robot, v, noOp, "members-open", font, parent);
            assertEquals(4, edt(() -> get(noOp, "scope.members.table", JTable.class).getRowCount()));
            scopeActivate(robot, noOp, get(noOp, "editor.save", JButton.class)); awaitClosed(noOp);
            assertEquals(0, v.access.updates); assertEquals(original, v.access.policy.allowScope());
            scopeOpenAll(robot, v); JDialog editor = await("editor.dialog"); scopeSize(v, editor, font);
            JTable members = get(editor, "scope.members.table", JTable.class);
            scopePaste(robot, editor, get(editor, "scope.port", JTextField.class), "8080");
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
            assertTrue(edt(editor::isShowing)); assertEquals(0, v.access.updates);
            assertTrue(edt(() -> get(editor, "editor.feedback", JTextArea.class).getText().contains("반영")));
            scopeFocus(editor, members); press(robot, java.awt.event.KeyEvent.VK_DOWN);
            assertEquals(0, edt(members::getSelectedRow), "dirty switching must retain the selected occurrence");
            scopeActivate(robot, editor, get(editor, "scope.member.apply", JButton.class));
            assertEquals(0, v.access.updates);
            scopeFocus(editor, members); press(robot, java.awt.event.KeyEvent.VK_DOWN);
            assertEquals(1, edt(members::getSelectedRow));
            scopePaste(robot, editor, get(editor, "scope.path", JTextArea.class), "/manager2");
            scopeActivate(robot, editor, get(editor, "scope.member.apply", JButton.class));
            scopeFocus(editor, members); press(robot, java.awt.event.KeyEvent.VK_DOWN);
            assertEquals(original.get(2).pathRegex(), edt(() -> get(editor, "scope.regex", JTextArea.class).getText()));
            scopeFocus(editor, members); press(robot, java.awt.event.KeyEvent.VK_DOWN);
            assertEquals(original.get(3).host(), edt(() -> get(editor, "scope.host", JTextField.class).getText()));
            assertFalse(edt(() -> get(editor, "scope.enabled", JCheckBox.class).isSelected()));
            scopePaste(robot, editor, get(editor, "scope.host", JTextField.class), "cancelled.test");
            scopeActivate(robot, editor, get(editor, "scope.member.reset", JButton.class));
            assertEquals(original.get(3).host(), edt(() -> get(editor, "scope.host", JTextField.class).getText()));
            String preview = scopeCopyPreview(robot, editor);
            assertTrue(preview.contains(original.get(2).pathRegex()) && preview.contains(original.get(3).pathRegex()));
            assertFalse(preview.contains("모든 4쌍"));
            scopeCapture(robot, v, editor, "members", font, parent);
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class)); awaitClosed(editor);
            assertEquals(1, v.access.updates);
            assertEquals(List.of(scopeEntry(8080, "/api"), scopeEntry(443, "/manager2"), original.get(2), original.get(3)), v.access.policy.allowScope());
            for (int port : List.of(8080, 443)) for (String path : List.of("/api", "/manager2"))
                assertEquals(port == 8080 && path.equals("/api") || port == 443 && path.equals("/manager2") ? GuardConfig.Mode.ALLOW : GuardConfig.Mode.BLOCK,
                        scopeEvaluate(v.access.policy, "example.test", port, true, path));
            scopeOpenAll(robot, v); JDialog cancelled = await("editor.dialog"); scopeSize(v, cancelled, font);
            scopePaste(robot, cancelled, get(cancelled, "scope.port", JTextField.class), "9999"); press(robot, java.awt.event.KeyEvent.VK_ESCAPE); awaitClosed(cancelled);
            assertEquals(1, v.access.updates); scopeSaved(v, "members", font); assertTrue(v.dialogs.errors.isEmpty());
                    } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "members", failure); }
                catch (Throwable captureFailure) { failure.addSuppressed(captureFailure); }
                throw failure;
            }
}
    }

    @ParameterizedTest @ValueSource(ints={14,28})
    void scopeUxInvalidPasteCancelAndStaleSnapshotNeverWrite(int font) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
            var parent = scopeParentSetup(v, font, robot, "invalid-stale");
            v.open("scope.allow.add"); JDialog editor = await("editor.dialog"); scopeSize(v, editor, font);
            scopePaste(robot, editor, get(editor, "scope.host", JTextField.class), "example.test");
            JTextField ports = get(editor, "scope.port", JTextField.class);
            scopePaste(robot, editor, ports, "80,443");
            scopePaste(robot, editor, get(editor, "scope.path", JTextArea.class), "/api\n/manager");
            scopeFocus(editor, ports); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); press(robot, java.awt.event.KeyEvent.VK_BACK_SPACE);
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
            assertTrue(edt(editor::isShowing)); assertEquals(0, v.access.updates);
            assertFalse(edt(() -> get(editor, "scope.anyPort", JCheckBox.class).isSelected()));
            scopePaste(robot, editor, ports, "80,443");
            JTextArea paths = get(editor, "scope.path", JTextArea.class);
            scopeFocus(editor, paths); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); press(robot, java.awt.event.KeyEvent.VK_BACK_SPACE);
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
            assertEquals(0, v.access.updates); assertEquals(0, edt(() -> get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex()));
            scopePaste(robot, editor, paths, "/api\n/manager");
            scopeFocus(editor, ports); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); scopeInsert(robot, "x".repeat(2049));
            assertEquals("80,443", edt(ports::getText));
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
            assertEquals(0, v.access.updates);
            assertTrue(edt(() -> get(editor, "editor.feedback", JTextArea.class).getText().contains("2,048")));
            scopePaste(robot, editor, ports, "80,,443");
            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class)); assertEquals(0, v.access.updates);
            scopeActivate(robot, editor, get(editor, "editor.cancel", JButton.class)); awaitClosed(editor);
            v.open("scope.allow.add"); JDialog escaped = await("editor.dialog"); scopeSize(v, escaped, font);
            scopePaste(robot, escaped, get(escaped, "scope.host", JTextField.class), "example.test"); press(robot, java.awt.event.KeyEvent.VK_ESCAPE); awaitClosed(escaped);
            v.open("scope.allow.add"); JDialog stale = await("editor.dialog"); scopeSize(v, stale, font);
            scopePaste(robot, stale, get(stale, "scope.host", JTextField.class), "example.test");
            scopePaste(robot, stale, get(stale, "scope.port", JTextField.class), "80,443");
            scopePaste(robot, stale, get(stale, "scope.path", JTextArea.class), "/api\n/manager");
            edt(() -> { v.access.project = "new-project"; v.access.revision++; v.panel.refreshNow(); return null; });
            scopeActivate(robot, stale, get(stale, "editor.save", JButton.class));
            assertEquals(UiText.error("STALE_POLICY"), edt(() -> get(stale, "editor.feedback", JTextArea.class).getText()));
            assertTrue(edt(stale::isShowing)); assertEquals(0, v.access.updateAttempts); assertEquals(GuardConfig.defaults(), v.access.policy);
            scopeCapture(robot, v, stale, "invalid-stale", font, parent);
            edt(() -> { stale.dispatchEvent(new java.awt.event.WindowEvent(stale, java.awt.event.WindowEvent.WINDOW_CLOSING)); return null; }); awaitClosed(stale);
            assertEquals(0, v.access.updates); scopeSaved(v, "invalid-stale", font); assertTrue(v.dialogs.errors.isEmpty());
                    } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "invalid-stale", failure); }
                catch (Throwable captureFailure) { failure.addSuppressed(captureFailure); }
                throw failure;
            }
}
    }

    @ParameterizedTest(name = "R1-font{0}-{1}")
    @org.junit.jupiter.params.provider.CsvSource({"14,defaultEnter", "14,escape", "28,defaultEnter", "28,escape"})
    void submittingEditorRetiresBeforeItsDeclinedConfirmation(int font, String cancel) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            String row = "submit-decline-order-" + cancel;
            try {
                scopeParentSetup(v, font, robot, row);
                destinationGuide(robot, v);
                scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                JDialog editor = await("editor.dialog"); destinationSize(editor, font, true);
                scopeChoose(robot, editor, get(editor, "scope.mode.choice", JComboBox.class), 1);
                assertEquals(0, v.access.updates);
                scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                JDialog confirmation = await("message.dialog"); destinationSize(confirmation, font, false);
                assertEquals("dialog.cancel", edt(() -> confirmation.getRootPane().getDefaultButton().getName()));
                assertEquals(java.awt.Dialog.ModalityType.APPLICATION_MODAL, edt(confirmation::getModalityType));
                GuardPanelTrafficViewTest.await(confirmation::isFocused);
                var observation = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Object>>();
                java.awt.event.HierarchyListener listener = event -> {
                    if ((event.getChangeFlags() & java.awt.event.HierarchyEvent.DISPLAYABILITY_CHANGED) != 0 && !editor.isDisplayable()) {
                        java.util.Map<String, Object> state = new java.util.LinkedHashMap<>();
                        state.put("onEdt", SwingUtilities.isEventDispatchThread());
                        state.put("eventSourceIdentity", System.identityHashCode(event.getComponent()));
                        state.put("editorIdentity", System.identityHashCode(editor));
                        state.put("confirmationIdentity", System.identityHashCode(confirmation));
                        state.put("editorShowing", editor.isShowing()); state.put("editorDisplayable", editor.isDisplayable());
                        state.put("confirmationShowing", confirmation.isShowing()); state.put("confirmationDisplayable", confirmation.isDisplayable());
                        state.put("confirmationApplicationModal", confirmation.getModalityType() == java.awt.Dialog.ModalityType.APPLICATION_MODAL);
                        state.put("epochMillis", System.currentTimeMillis()); state.put("javaNanoTime", System.nanoTime());
                        observation.compareAndSet(null, java.util.Map.copyOf(state));
                    }
                };
                edt(() -> { editor.addHierarchyListener(listener); return null; });
                try {
                    destinationCapture(robot, v, confirmation, row, font);
                    press(robot, cancel.equals("defaultEnter") ? java.awt.event.KeyEvent.VK_ENTER : java.awt.event.KeyEvent.VK_ESCAPE);
                    awaitClosed(confirmation); awaitClosed(editor);
                    assertEquals(0, v.access.updateAttempts); assertEquals(0, v.access.updates);
                    assertEquals(GuardConfig.defaults(), v.access.policy); assertTrue(v.dialogs.errors.isEmpty());
                    scopeSaved(v, row, font);
                    java.util.Map<String, Object> state = observation.get();
                    assertNotNull(state, "R1_MISSING_SYNCHRONOUS_DISPOSAL_OBSERVATION");
                    assertFalse(SwingUtilities.isEventDispatchThread(), "R1_ASSERTIONS_REQUIRE_TEST_THREAD");
                    assertEquals(Boolean.TRUE, state.get("onEdt"), "R1_DISPOSAL_OBSERVATION_REQUIRES_EDT");
                    assertEquals(Integer.valueOf(System.identityHashCode(editor)), state.get("eventSourceIdentity"), "R1_WRONG_DISPOSAL_EVENT_SOURCE");
                    assertEquals(Integer.valueOf(System.identityHashCode(editor)), state.get("editorIdentity"));
                    assertEquals(Integer.valueOf(System.identityHashCode(confirmation)), state.get("confirmationIdentity"));
                    assertEquals(Boolean.FALSE, state.get("editorDisplayable"));
                    assertEquals(Boolean.TRUE, state.get("confirmationApplicationModal"));
                    java.util.Map<String, Object> witness = new java.util.LinkedHashMap<>();
                    witness.put("font", font); witness.put("cancel", cancel); witness.put("observation", state);
                    witness.put("updateAttempts", v.access.updateAttempts); witness.put("updates", v.access.updates);
                    witness.put("originalPolicyPreserved", GuardConfig.defaults().equals(v.access.policy));
                    System.out.println("R1_SUBMIT_DECLINE_ORDER " + dev.cairnguard.model.Json.MAPPER.writeValueAsString(witness));
                    assertTrue(Boolean.TRUE.equals(state.get("confirmationShowing")) && Boolean.TRUE.equals(state.get("confirmationDisplayable")),
                            "R1_EDITOR_RETIRED_BEFORE_CONFIRMATION expected=true");
                } finally { edt(() -> { editor.removeHierarchyListener(listener); return null; }); }
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, row, failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
    }

    @ParameterizedTest @ValueSource(ints = {14, 28})
    void destinationModeGuideAndCancelDefaultUseRealKeysWithoutSaving(int font) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
                scopeParentSetup(v, font, robot, "mode-cancel");
                destinationGuide(robot, v);
                for (String cancel : List.of("enter", "escape", "window")) {
                    scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                    JDialog editor = await("editor.dialog"); destinationSize(editor, font, true);
                    scopeChoose(robot, editor, get(editor, "scope.mode.choice", JComboBox.class), 1);
                    assertEquals(0, v.access.updates);
                    scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                    JDialog confirmation = await("message.dialog"); destinationSize(confirmation, font, false);
                    assertEquals("dialog.cancel", edt(() -> confirmation.getRootPane().getDefaultButton().getName()));
                    GuardPanelTrafficViewTest.await(confirmation::isFocused);
                    destinationCapture(robot, v, confirmation, "mode-cancel-" + cancel, font);
                    if (cancel.equals("window")) edt(() -> { confirmation.dispatchEvent(new java.awt.event.WindowEvent(confirmation, java.awt.event.WindowEvent.WINDOW_CLOSING)); return null; });
                    else press(robot, cancel.equals("enter") ? java.awt.event.KeyEvent.VK_ENTER : java.awt.event.KeyEvent.VK_ESCAPE);
                    awaitClosed(confirmation); awaitClosed(editor);
                    assertEquals(0, v.access.updates); assertEquals(GuardConfig.defaults(), v.access.policy);
                }
                scopeSaved(v, "mode-cancel", font); assertTrue(v.dialogs.errors.isEmpty());
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "mode-cancel", failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
    }

    @ParameterizedTest @ValueSource(ints = {14, 28})
    void destinationModeSaveAndJsonSwitchBackKeepFixedGeometryAndOriginalSnapshot(int font) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
                scopeParentSetup(v, font, robot, "mode-save"); destinationGuide(robot, v);
                scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                JDialog editor = await("editor.dialog"); destinationSize(editor, font, true);
                scopeChoose(robot, editor, get(editor, "scope.mode.choice", JComboBox.class), 1);
                destinationCapture(robot, v, editor, "mode-draft-all", font);
                scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                JDialog confirmation = await("message.dialog"); destinationSize(confirmation, font, false);
                scopeActivate(robot, confirmation, get(confirmation, "dialog.confirm", JButton.class)); awaitClosed(confirmation); awaitClosed(editor);
                assertEquals(1, v.access.updates); assertEquals(GuardConfig.DestinationScopeMode.ALL_DESTINATIONS, v.access.policy.destinationScopeMode());
                edt(() -> { get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(5); return null; });
                v.open("settings.policyJson"); JDialog json = await("editor.dialog"); destinationSize(json, font, false);
                scopePaste(robot, json, get(json, "advanced.policyJson", JTextArea.class), dev.cairnguard.model.PolicyCodec.encode(GuardConfig.defaults()));
                scopeActivate(robot, json, get(json, "editor.save", JButton.class));
                JDialog back = await("message.dialog"); destinationSize(back, font, false);
                assertTrue(edt(() -> get(back, "dialog.body", JTextArea.class).getText().contains("모든 새 Proxy 요청을 차단")));
                assertEquals("dialog.cancel", edt(() -> back.getRootPane().getDefaultButton().getName()));
                destinationCapture(robot, v, back, "mode-json-back", font);
                scopeActivate(robot, back, get(back, "dialog.confirm", JButton.class)); awaitClosed(back); awaitClosed(json);
                assertEquals(2, v.access.updates); assertEquals(GuardConfig.defaults(), v.access.policy);
                edt(() -> { get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(1); return null; }); destinationGuide(robot, v);
                scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                JDialog stale = await("editor.dialog"); destinationSize(stale, font, true);
                assertEquals(0, edt(() -> get(stale, "scope.mode.choice", JComboBox.class).getSelectedIndex()));
                scopeChoose(robot, stale, get(stale, "scope.mode.choice", JComboBox.class), 1);
                edt(() -> { v.access.project = "mode-new-project"; v.access.revision++; v.panel.refreshNow(); return null; });
                scopeActivate(robot, stale, get(stale, "editor.save", JButton.class));
                assertEquals(2, v.access.updates); assertEquals(2, v.access.updateAttempts);
                assertEquals(UiText.error("STALE_POLICY"), edt(() -> get(stale, "editor.feedback", JTextArea.class).getText()));
                destinationCapture(robot, v, stale, "mode-stale", font);
                press(robot, java.awt.event.KeyEvent.VK_ESCAPE); awaitClosed(stale);
                scopeSaved(v, "mode-save", font); assertTrue(v.dialogs.errors.isEmpty());
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "mode-save", failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
    }

    private static void destinationGuide(java.awt.Robot robot, View v) throws Exception {
        JTabbedPane lists = get(v.panel, "scope.lists", JTabbedPane.class);
        scopeFocus(v.frame, lists);
        int count = edt(lists::getTabCount), selected = edt(lists::getSelectedIndex);
        assertEquals(3, count); assertTrue(selected >= 0 && selected < count);
        int presses = (2 - selected + count) % count;
        for (int step = 0; step < presses; step++) {
            press(robot, java.awt.event.KeyEvent.VK_RIGHT);
            int expected = (selected + step + 1) % count;
            GuardPanelTrafficViewTest.await(() -> lists.getSelectedIndex() == expected);
        }
        GuardPanelTrafficViewTest.await(() -> lists.getSelectedIndex() == 2);
        edt(() -> { lists.putClientProperty("scope.operatorKeyNavigation", java.util.Map.of("startIndex", selected, "tabCount", count, "key", "RIGHT", "presses", presses, "actualFinalIndex", lists.getSelectedIndex())); return null; });
        JTextArea guide = get(v.panel, "scope.help", JTextArea.class);
        scopeFocus(v.frame, guide); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); scopeShortcut(robot, java.awt.event.KeyEvent.VK_C);
        String copied = (String) java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
        assertEquals(edt(guide::getText), copied); assertFalse(edt(guide::isEditable));
        for (String text : List.of("Drop all out-of-scope requests", "X-Cairn-Guard 로컬 451", "각 행은 확장된", "실제 목적지·raw/경로뷰 · 차단우선 · 별도허가", "ALL_DESTINATIONS", "현재 상태", "OOM")) assertTrue(copied.contains(text), text);
    }

    private static void destinationSize(JDialog dialog, int font, boolean modeEditor) throws Exception {
        edt(() -> {
            fonts(dialog.getContentPane(), font); dialog.setSize(640, 600); dialog.validate();
            assertEquals(Double.parseDouble(System.getProperty("sun.java2d.uiScale")), dialog.getGraphicsConfiguration().getDefaultTransform().getScaleX(), 0.0001);
            assertTrue(dialog.isModal()); assertTrue(dialog.isResizable());
            if (modeEditor) {
                JComboBox<?> choice = get(dialog, "scope.mode.choice", JComboBox.class);
                assertEquals(font, choice.getFont().getSize()); assertSame(choice, get(dialog, "scope.mode.choice.label", JLabel.class).getLabelFor());
                assertFalse(get(dialog, "scope.mode.help", JTextArea.class).isEditable());
            }
            return null;
        });
    }

    private static void destinationCapture(java.awt.Robot robot, View v, JDialog dialog, String row, int font) throws Exception {
        java.util.Map<String, Object> facts = edt(() -> {
            java.util.Map<String, Object> result = new java.util.LinkedHashMap<>();
            Rectangle client = new Rectangle(dialog.getContentPane().getLocationOnScreen(), dialog.getContentPane().getSize());
            result.put("client", client.toString()); result.put("window", dialog.getBounds().toString()); result.put("font", font);
            result.put("actualTransform", dialog.getGraphicsConfiguration().getDefaultTransform().getScaleX());
            result.put("savedPolicy", dev.cairnguard.model.PolicyCodec.encode(v.access.policy)); result.put("updates", v.access.updates);
            java.util.Map<String, Object> controls = new java.util.LinkedHashMap<>();
            for (String name : List.of("scope.mode.choice", "scope.mode.help", "editor.save", "editor.cancel", "dialog.body", "dialog.cancel", "dialog.confirm")) {
                Component found = GuardPanelV2Test.find(dialog, name);
                if (!(found instanceof JComponent control)) continue;
                java.util.Map<String, Object> actual = new java.util.LinkedHashMap<>(); actual.put("font", control.getFont().getSize()); actual.put("bounds", control.getBounds().toString()); actual.put("visibleRect", control.getVisibleRect().toString());
                if (control instanceof AbstractButton button && control.isShowing()) {
                    assertEquals(font, control.getFont().getSize()); assertTrue(control.getWidth() >= control.getPreferredSize().width, name + " caption");
                    assertTrue(client.contains(new Rectangle(control.getLocationOnScreen(), control.getSize())), name + " client");
                    assertTrue(control.getVisibleRect().contains(new Rectangle(0, 0, control.getWidth(), control.getHeight())), name + " clipped"); actual.put("text", button.getText());
                }
                if (control instanceof JTextArea text) actual.put("fullText", text.getText());
                if (control instanceof JComboBox<?> choice) actual.put("selected", String.valueOf(choice.getSelectedItem()));
                if (control.getClientProperty("scope.operatorNavigation") != null) actual.put("operatorNavigation", control.getClientProperty("scope.operatorNavigation"));
                controls.put(name, actual);
            }
            result.put("controls", controls);
            result.put("readability", scopeReadabilityFacts(dialog));
            result.put("actualGuideKeyNavigation", get(v.panel, "scope.lists", JTabbedPane.class).getClientProperty("scope.operatorKeyNavigation"));
            return result;
        });
        Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence")); java.nio.file.Files.createDirectories(directory);
        String prefix = row + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale");
        Rectangle bounds = edt(() -> new Rectangle(dialog.getLocationOnScreen(), dialog.getSize()));
        assertTrue(javax.imageio.ImageIO.write(robot.createScreenCapture(bounds), "png", directory.resolve(prefix + ".png").toFile()));
        java.nio.file.Files.writeString(directory.resolve(prefix + ".json"), dev.cairnguard.model.Json.write(facts));
    }

    /** Passive post-original-action failure state; never settles, focuses, resizes or repairs a window. */
    private static void scopeFailureSnapshot(java.awt.Robot robot, View v, int font, String row, AssertionError failure) throws Exception {
        List<Window> owned = edt(() -> {
            List<Window> result = new ArrayList<>(); result.add(v.frame);
            for (Window candidate : Window.getWindows()) {
                if (candidate == v.frame) continue;
                Window owner = candidate.getOwner();
                while (owner != null && owner != v.frame) owner = owner.getOwner();
                if (owner == v.frame) result.add(candidate);
            }
            return result;
        });
        java.util.Map<String, Object> snapshot = edt(() -> {
            java.util.Map<String, Object> facts = new java.util.LinkedHashMap<>();
            facts.put("checkpoint", "natural post-original-action first AssertionError, before owned View.close");
            facts.put("case", row); facts.put("fontParameter", font); facts.put("scale", System.getProperty("sun.java2d.uiScale"));
            java.awt.KeyboardFocusManager focus = java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager();
            facts.put("actualFocusOwner", String.valueOf(focus.getFocusOwner())); facts.put("actualFocusedWindow", String.valueOf(focus.getFocusedWindow()));
            facts.put("actualActiveWindow", String.valueOf(focus.getActiveWindow()));
            java.io.StringWriter stack = new java.io.StringWriter(); failure.printStackTrace(new java.io.PrintWriter(stack)); facts.put("originalFailure", stack.toString());
            List<java.util.Map<String, Object>> windows = new ArrayList<>();
            for (Window window : owned) {
                java.util.Map<String, Object> state = new java.util.LinkedHashMap<>();
                state.put("class", window.getClass().getName()); state.put("name", String.valueOf(window.getName()));
                state.put("bounds", window.getBounds().toString()); state.put("insets", window.getInsets().toString());
                state.put("showing", window.isShowing()); state.put("visible", window.isVisible()); state.put("displayable", window.isDisplayable());
                state.put("active", window.isActive()); state.put("focused", window.isFocused()); state.put("focusableWindow", window.isFocusableWindow());
                state.put("windowFocusOwner", String.valueOf(window.getFocusOwner()));
                Container client = window instanceof JFrame frame ? frame.getContentPane() : window instanceof JDialog dialog ? dialog.getContentPane() : window;
                state.put("clientBounds", client.getBounds().toString());
                if (client.isShowing()) state.put("clientScreenLocation", client.getLocationOnScreen().toString());
                java.util.Map<String, Object> controls = new java.util.LinkedHashMap<>();
                for (String name : List.of("scope.allow.add", "scope.allow.edit", "scope.allow.table", "scope.state", "scope.help", "scope.host", "scope.port", "scope.path", "scope.url", "scope.scheme", "scope.pathMode", "scope.preview", "scope.message", "editor.save", "editor.cancel")) {
                    Component found = GuardPanelV2Test.find(window, name);
                    if (!(found instanceof JComponent control)) continue;
                    java.util.Map<String, Object> data = new java.util.LinkedHashMap<>();
                    data.put("class", control.getClass().getName()); data.put("bounds", control.getBounds().toString());
                    data.put("visibleRect", control.getVisibleRect().toString()); data.put("showing", control.isShowing()); data.put("visible", control.isVisible());
                    data.put("enabled", control.isEnabled()); data.put("focusable", control.isFocusable()); data.put("focusOwner", control.isFocusOwner());
                    data.put("font", String.valueOf(control.getFont()));
                    if (control.isShowing()) data.put("screenLocation", control.getLocationOnScreen().toString());
                    if (control instanceof javax.swing.text.JTextComponent text) data.put("text", text.getText());
                    if (control instanceof AbstractButton button) data.put("text", button.getText());
                    if (control instanceof JLabel label) data.put("text", label.getText());
                    if (control.getClientProperty("scope.operatorNavigation") != null) data.put("operatorNavigation", control.getClientProperty("scope.operatorNavigation"));
                    controls.put(name, data);
                }
                state.put("controls", controls); windows.add(state);
            }
            facts.put("ownedWindows", windows); facts.put("policyAtFailure", dev.cairnguard.model.PolicyCodec.encode(v.access.policy));
            facts.put("updatesAtFailure", v.access.updates); return facts;
        });
        Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence")); java.nio.file.Files.createDirectories(directory);
        String prefix = "failure-" + row + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale");
        java.nio.file.Files.writeString(directory.resolve(prefix + ".json"), dev.cairnguard.model.Json.write(snapshot));
        for (int index = 0; index < owned.size(); index++) {
            Window window = owned.get(index);
            Rectangle bounds = edt(() -> window.isShowing() ? new Rectangle(window.getLocationOnScreen(), window.getSize()) : null);
            if (bounds != null && bounds.width > 0 && bounds.height > 0)
                javax.imageio.ImageIO.write(robot.createScreenCapture(bounds), "png", directory.resolve(prefix + "-window" + index + ".png").toFile());
        }
    }

    private static java.util.Map<String, Object> scopeParentSetup(View v, int font, java.awt.Robot robot, String row) throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless());
        java.util.Map<String, Object> facts = edt(() -> {
            fonts(v.frame, font); v.frame.setSize(720, 560);
            get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(1); v.frame.validate();
            Rectangle client = new Rectangle(v.frame.getContentPane().getLocationOnScreen(), v.frame.getContentPane().getSize());
            java.util.Map<String, Object> bounds = new java.util.LinkedHashMap<>();
            for (String name : List.of("scope.allow.add", "scope.allow.edit", "scope.allow.toggle", "scope.allow.delete", "scope.state")) {
                JComponent control = get(v.panel, name, JComponent.class);
                assertEquals(font, control.getFont().getSize(), name);
                Rectangle actual = new Rectangle(control.getLocationOnScreen(), control.getSize());
                assertTrue(control.isShowing() && control.getWidth() > 0 && control.getHeight() > 0, name);
                assertTrue(client.contains(actual), name + " outside actual parent client: " + actual + " / " + client);
                assertTrue(control.getVisibleRect().contains(new Rectangle(0, 0, control.getWidth(), control.getHeight())), name + " clipped");
                if (control instanceof AbstractButton || control instanceof JLabel) assertTrue(control.getWidth() >= control.getPreferredSize().width, name + " caption");
                bounds.put(name, actual.toString());
            }
            JTable table = get(v.panel, "scope.allow.table", JTable.class);
            assertEquals(font, table.getFont().getSize()); assertTrue(table.isShowing());
            assertTrue(table.getVisibleRect().height >= table.getRowHeight(), "the scope table must show at least one real-font row");
            JScrollPane scroll = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, table);
            Rectangle tableClient = new Rectangle(scroll.getViewport().getLocationOnScreen(), scroll.getViewport().getSize());
            assertTrue(client.contains(tableClient)); bounds.put("scope.allow.table.viewport", tableClient.toString());
            double transform = v.frame.getGraphicsConfiguration().getDefaultTransform().getScaleX();
            assertEquals(Double.parseDouble(System.getProperty("sun.java2d.uiScale")), transform, 0.0001);
            java.util.Map<String, Object> observation = new java.util.LinkedHashMap<>();
            observation.put("rootFont", v.panel.getFont().getSize()); observation.put("scopeFont", table.getFont().getSize());
            observation.put("actualTransform", transform); observation.put("parentBounds", v.frame.getBounds().toString());
            observation.put("parentClientBounds", client.toString()); observation.put("reachableActualBounds", bounds);
            JButton initial = get(v.panel, "scope.allow.add", JButton.class);
            if (!initial.isFocusOwner()) initial.requestFocusInWindow();
            return observation;
        });
        robot.waitForIdle();
        GuardPanelTrafficViewTest.await(() -> get(v.panel, "scope.allow.add", JButton.class).isFocusOwner());
        for (String name : List.of("scope.allow.edit", "scope.allow.toggle", "scope.allow.delete")) {
            press(robot, java.awt.event.KeyEvent.VK_TAB);
            GuardPanelTrafficViewTest.await(() -> get(v.panel, name, JButton.class).isFocusOwner());
        }
        for (String name : List.of("scope.allow.toggle", "scope.allow.edit", "scope.allow.add")) {
            robot.keyPress(java.awt.event.KeyEvent.VK_SHIFT); press(robot, java.awt.event.KeyEvent.VK_TAB); robot.keyRelease(java.awt.event.KeyEvent.VK_SHIFT); robot.waitForIdle();
            GuardPanelTrafficViewTest.await(() -> get(v.panel, name, JButton.class).isFocusOwner());
        }
        facts.put("actualTabAndShiftTabParentActions", true);
        Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence")); java.nio.file.Files.createDirectories(directory);
        String name = row + "-parent-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale");
        Rectangle actual = edt(() -> new Rectangle(v.frame.getLocationOnScreen(), v.frame.getSize()));
        java.awt.image.BufferedImage pixels = robot.createScreenCapture(actual);
        assertTrue(javax.imageio.ImageIO.write(pixels, "png", directory.resolve(name + ".png").toFile()));
        facts.put("pixelWidth", pixels.getWidth()); facts.put("pixelHeight", pixels.getHeight());
        java.nio.file.Files.writeString(directory.resolve(name + ".json"), dev.cairnguard.model.Json.write(facts));
        return facts;
    }

    private static void scopeSize(View v, JDialog dialog, int font) throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless());
        edt(() -> {
            double actual = dialog.getGraphicsConfiguration().getDefaultTransform().getScaleX();
            assertEquals(Double.parseDouble(System.getProperty("sun.java2d.uiScale")), actual, 0.0001);
            v.frame.setSize(720, 560); fonts(dialog.getContentPane(), font); dialog.setSize(640, 600); dialog.validate();
            assertEquals(font, get(dialog, "scope.path", JTextArea.class).getFont().getSize());
            for (String name : List.of("scope.host", "scope.port", "scope.path", "scope.scheme", "scope.pathMode")) {
                JComponent control = get(dialog, name, JComponent.class);
                assertNotNull(control.getAccessibleContext().getAccessibleName());
                assertSame(control, get(dialog, name + ".label", JLabel.class).getLabelFor());
            }
            assertTrue(dialog.isModal()); assertTrue(dialog.isResizable()); return null;
        });
    }
    private static void scopeOpenAll(java.awt.Robot robot, View v) throws Exception {
        JTable table = edt(() -> get(v.panel, "scope.allow.table", JTable.class));
        scopeFocus(v.frame, table); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A);
        assertEquals(table.getRowCount(), edt(table::getSelectedRowCount)); press(robot, java.awt.event.KeyEvent.VK_ENTER);
    }
    private static void scopeFocus(Window window, JComponent control) throws Exception {
        edt(() -> {
            assertSame(window, SwingUtilities.getWindowAncestor(control));
            Rectangle target = new Rectangle(0, 0, Math.max(1, control.getWidth()), Math.min(control.getHeight(), control.getFontMetrics(control.getFont()).getHeight() * 2));
            List<JViewport> owners = new ArrayList<>();
            for (Container parent = control.getParent(); parent != null && parent != window; parent = parent.getParent())
                if (parent instanceof JViewport viewport && !owners.contains(viewport)) owners.add(viewport);
            List<java.util.Map<String, Object>> navigation = new ArrayList<>();
            for (JViewport owner : owners) {
                JComponent view = assertInstanceOf(JComponent.class, owner.getView());
                Rectangle converted = SwingUtilities.convertRectangle(control, target, view);
                assertTrue(control == view || SwingUtilities.isDescendingFrom(control, view));
                java.util.Map<String, Object> actual = new java.util.LinkedHashMap<>();
                actual.put("order", navigation.size()); actual.put("viewport", String.valueOf(owner.getName()));
                actual.put("viewportIdentity", Integer.toHexString(System.identityHashCode(owner)));
                actual.put("view", String.valueOf(view.getName())); actual.put("viewClass", view.getClass().getName());
                actual.put("converted", converted.toString()); actual.put("before", owner.getViewPosition().toString());
                actual.put("controlBoundsBefore", SwingUtilities.convertRectangle(control, new Rectangle(0, 0, control.getWidth(), control.getHeight()), view).toString());
                actual.put("viewportBoundsBefore", owner.getBounds().toString()); actual.put("extentBefore", owner.getExtentSize().toString());
                actual.put("viewBoundsBefore", view.getBounds().toString());
                view.scrollRectToVisible(converted);
                actual.put("after", owner.getViewPosition().toString());
                actual.put("convertedAfter", SwingUtilities.convertRectangle(control, target, view).toString());
                actual.put("viewportBoundsAfter", owner.getBounds().toString()); actual.put("extentAfter", owner.getExtentSize().toString());
                actual.put("viewBoundsAfter", view.getBounds().toString());
                navigation.add(actual);
            }
            control.putClientProperty("scope.operatorNavigation", List.copyOf(navigation));
            assertTrue(control.isShowing()); assertTrue(control.getVisibleRect().width > 0 && control.getVisibleRect().height > 0, control.getName());
            scopeReadable(control, true);
            if (!control.isFocusOwner()) control.requestFocusInWindow(); return null;
        });
        GuardPanelTrafficViewTest.await(control::isFocusOwner);
    }
    private static void scopeReadable(JComponent control, boolean visibleLine) {
        int line = control.getFontMetrics(control.getFont()).getHeight();
        java.awt.Insets insets = control.getInsets();
        if (control instanceof javax.swing.text.JTextComponent text && (!text.getText().isEmpty() || text instanceof JTextField)) {
            int needed = line + insets.top + insets.bottom;
            assertTrue(control.getHeight() >= needed, control.getName() + " allocated current-font line");
            if (visibleLine) assertTrue(control.getVisibleRect().height >= needed, control.getName() + " visible complete current-font line");
            assertTrue(control.getWidth() - insets.left - insets.right >= control.getFontMetrics(control.getFont()).charWidth('M'), control.getName() + " glyph width");
            if (text instanceof JTextField && List.of("scope.url", "scope.host", "scope.port").contains(control.getName()))
                assertTrue(control.getWidth() - insets.left - insets.right >= control.getFontMetrics(control.getFont()).stringWidth(text.getText()), control.getName() + " complete actual short input");
            if (text instanceof JTextArea area && area.getLineWrap() && !(area.getParent() instanceof JViewport)) {
                int wrapped = (int) Math.ceil(area.getUI().getRootView(area).getPreferredSpan(javax.swing.text.View.Y_AXIS));
                assertTrue(area.getHeight() - insets.top - insets.bottom >= wrapped, control.getName() + " full current wrapped span");
            }
        }
        if (control instanceof AbstractButton || control instanceof JLabel || control instanceof JComboBox<?>) {
            assertTrue(control.getHeight() >= control.getPreferredSize().height, control.getName() + " native caption height");
            assertTrue(control.getWidth() >= control.getPreferredSize().width, control.getName() + " native caption width");
        }
        if (control instanceof JTable table) {
            assertTrue(table.getRowHeight() >= line, control.getName() + " native row height");
            if (visibleLine) assertTrue(table.getVisibleRect().height >= table.getRowHeight(), control.getName() + " complete visible native row");
        }
    }

    private static java.util.Map<String, Object> scopeReadabilityFacts(Window window) {
        java.util.Map<String, Object> facts = new java.util.LinkedHashMap<>();
        for (String name : List.of("scope.url", "scope.host", "scope.port", "scope.scheme", "scope.pathMode", "scope.path", "scope.regex", "scope.preview", "scope.message",
                "scope.intro", "scope.urlGuidance", "scope.hostGuidance", "scope.pathGuidance", "scope.allPaths", "scope.members.help", "scope.members.table",
                "scope.url.label", "scope.host.label", "scope.port.label", "scope.path.label", "scope.preview.label", "scope.mode.choice", "scope.mode.help", "dialog.body", "editor.save", "editor.cancel", "dialog.confirm", "dialog.cancel")) {
            Component found = GuardPanelV2Test.find(window, name);
            if (!(found instanceof JComponent control)) continue;
            java.util.Map<String, Object> actual = new java.util.LinkedHashMap<>();
            actual.put("showing", control.isShowing()); actual.put("font", control.getFont().toString());
            actual.put("glyphLine", control.getFontMetrics(control.getFont()).getHeight()); actual.put("insets", control.getInsets().toString());
            actual.put("bounds", control.getBounds().toString()); actual.put("visibleRect", control.getVisibleRect().toString());
            actual.put("minimum", control.getMinimumSize().toString()); actual.put("preferred", control.getPreferredSize().toString());
            if (control instanceof javax.swing.text.JTextComponent text) actual.put("fullText", text.getText());
            if (control instanceof JTextArea area) actual.put("nativeWrappedSpan", area.getUI().getRootView(area).getPreferredSpan(javax.swing.text.View.Y_AXIS));
            if (control.isShowing()) scopeReadable(control, false);
            facts.put(name, actual);
        }
        Component found = GuardPanelV2Test.find(window, "scope.form");
        if (found instanceof JComponent form) {
            int bottom = form.getInsets().top;
            List<String> rows = new ArrayList<>();
            for (Component row : form.getComponents()) {
                assertTrue(row.getY() >= bottom, "natural scope rows must not overlap");
                assertTrue(row.getHeight() >= row.getPreferredSize().height, "natural scope row must not be squeezed");
                rows.add(row.getBounds().toString()); bottom = row.getY() + row.getHeight();
            }
            facts.put("actualNonOverlappingRows", rows);
        }
        return facts;
    }

    private static void scopeShortcut(java.awt.Robot robot, int key) {
        robot.keyPress(java.awt.event.KeyEvent.VK_CONTROL); robot.keyPress(key); robot.keyRelease(key); robot.keyRelease(java.awt.event.KeyEvent.VK_CONTROL); robot.waitForIdle();
    }
    private static void scopeInsert(java.awt.Robot robot, String text) {
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(text), null);
        scopeShortcut(robot, java.awt.event.KeyEvent.VK_V);
    }
    private static void scopePaste(java.awt.Robot robot, Window window, javax.swing.text.JTextComponent control, String text) throws Exception {
        scopeFocus(window, control); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); scopeInsert(robot, text);
        GuardPanelTrafficViewTest.await(() -> control.getText().equals(text));
    }
    private static void scopeActivate(java.awt.Robot robot, Window window, AbstractButton control) throws Exception {
        scopeFocus(window, control);
        edt(() -> { assertTrue(control.isEnabled()); assertTrue(control.getWidth() >= control.getPreferredSize().width, control.getName()); return null; });
        press(robot, java.awt.event.KeyEvent.VK_SPACE);
    }
    private static void scopeChoose(java.awt.Robot robot, Window window, JComboBox<?> control, int index) throws Exception {
        scopeFocus(window, control);
        robot.keyPress(java.awt.event.KeyEvent.VK_ALT); press(robot, java.awt.event.KeyEvent.VK_DOWN); robot.keyRelease(java.awt.event.KeyEvent.VK_ALT); robot.waitForIdle();
        GuardPanelTrafficViewTest.await(control::isPopupVisible);
        press(robot, java.awt.event.KeyEvent.VK_HOME);
        for (int i = 0; i < index; i++) press(robot, java.awt.event.KeyEvent.VK_DOWN);
        press(robot, java.awt.event.KeyEvent.VK_ENTER);
        GuardPanelTrafficViewTest.await(() -> control.getSelectedIndex() == index && !control.isPopupVisible());
    }
    private static String scopeCopyPreview(java.awt.Robot robot, JDialog dialog) throws Exception {
        JTextArea preview = get(dialog, "scope.preview", JTextArea.class);
        scopeFocus(dialog, preview); scopeShortcut(robot, java.awt.event.KeyEvent.VK_A); scopeShortcut(robot, java.awt.event.KeyEvent.VK_C);
        String copied = (String) java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
        assertEquals(edt(preview::getText), copied); assertFalse(edt(preview::isEditable)); return copied;
    }
    private static void scopeCapture(java.awt.Robot robot, View v, JDialog dialog, String row, int font, java.util.Map<String, Object> parent) throws Exception {
        Rectangle bounds = edt(() -> new Rectangle(dialog.getLocationOnScreen(), dialog.getSize())); robot.waitForIdle();
        java.awt.image.BufferedImage pixels = robot.createScreenCapture(bounds);
        Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence")); java.nio.file.Files.createDirectories(directory);
        String name = row + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale");
        assertTrue(javax.imageio.ImageIO.write(pixels, "png", directory.resolve(name + ".png").toFile()));
        java.util.Map<String, Object> observation = edt(() -> {
            java.util.Map<String, Object> facts = new java.util.LinkedHashMap<>();
            facts.put("case", row); facts.put("font", font); facts.put("parentWhenActive", parent); facts.put("forcedScale", System.getProperty("sun.java2d.uiScale"));
            facts.put("actualTransform", dialog.getGraphicsConfiguration().getDefaultTransform().getScaleX());
            facts.put("dialogBounds", bounds.toString()); facts.put("pixelWidth", pixels.getWidth()); facts.put("pixelHeight", pixels.getHeight());
            facts.put("preview", get(dialog, "scope.preview", JTextArea.class).getText()); facts.put("updatesSoFar", v.access.updates);
            if (row.equals("members-open")) {
                JTable members = get(dialog, "scope.members.table", JTable.class);
                assertTrue(members.getVisibleRect().height >= members.getRowHeight(), "member opening shows a complete native row");
                assertTrue(members.getTableHeader().getVisibleRect().height >= members.getTableHeader().getFontMetrics(members.getTableHeader().getFont()).getHeight(), "member opening shows the complete current-font header");
            }
            java.util.Map<String, Object> navigation = new java.util.LinkedHashMap<>();
            for (String controlName : List.of("scope.host", "scope.port", "scope.path", "scope.scheme", "scope.pathMode", "scope.members.table", "scope.preview", "editor.save", "editor.cancel")) {
                Component found = GuardPanelV2Test.find(dialog, controlName);
                if (found instanceof JComponent control && control.getClientProperty("scope.operatorNavigation") != null) navigation.put(controlName, control.getClientProperty("scope.operatorNavigation"));
            }
            facts.put("actualViewportOperatorNavigation", navigation);
            facts.put("readability", scopeReadabilityFacts(dialog));
            return facts;
        });
        java.nio.file.Files.writeString(directory.resolve(name + ".json"), dev.cairnguard.model.Json.write(observation));
        System.out.println("SCOPE_UX_PIXELS " + name + " actual=" + observation.get("actualTransform") + " pixels=" + pixels.getWidth() + "x" + pixels.getHeight());
    }
    private static void scopeSaved(View v, String row, int font) throws Exception {
        Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence")); java.nio.file.Files.createDirectories(directory);
        java.nio.file.Files.writeString(directory.resolve(row + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale") + "-saved-policy.json"), dev.cairnguard.model.PolicyCodec.encode(v.access.policy));
    }
    private static GuardConfig.ScopeEntry scopeEntry(int port, String path) { return new GuardConfig.ScopeEntry(true, "example.test", "https", port, "\\A\\Q" + path + "\\E\\z"); }
    private static GuardConfig.Mode scopeEvaluate(GuardConfig policy, String host, int port, boolean secure, String path) {
        return new dev.cairnguard.policy.PolicyEngine().evaluate(policy, new dev.cairnguard.model.RequestData("GET", "https://display.invalid/", host, port, secure,
                List.of(new dev.cairnguard.model.RequestData.Header("Host", "fuzzed.invalid")), new byte[0], true, true, path)).mode();
    }
    private static void scopePolicy(GuardConfig policy, String manager) {
        assertEquals(4, policy.allowScope().size()); assertTrue(policy.allowScope().stream().allMatch(entry -> entry.scheme().equals("https")));
        for (int port : List.of(80, 443)) {
            for (String path : List.of("/api", manager)) assertEquals(GuardConfig.Mode.ALLOW, scopeEvaluate(policy, "example.test", port, true, path));
            for (String path : List.of("/admin", "/apix", "/api/child", manager + "/child")) assertEquals(GuardConfig.Mode.BLOCK, scopeEvaluate(policy, "example.test", port, true, path));
            assertEquals(GuardConfig.Mode.BLOCK, scopeEvaluate(policy, "example.test", port, false, "/api"));
        }
        assertEquals(GuardConfig.Mode.BLOCK, scopeEvaluate(policy, "example.test", 8080, true, "/api"));
        assertEquals(GuardConfig.Mode.BLOCK, scopeEvaluate(policy, "outside.test", 443, true, "/api"));
    }

    private static void press(java.awt.Robot robot, int key) { robot.keyPress(key); robot.keyRelease(key); robot.waitForIdle(); }
    private static void reachable(JFrame frame, JComponent control) throws Exception {
        edt(() -> { control.scrollRectToVisible(new Rectangle(0, 0, control.getWidth(), control.getHeight())); frame.validate(); return null; });
        edt(() -> {
            Rectangle visible = control.getVisibleRect();
            assertTrue(control.isShowing(), control.getName());
            assertTrue(control.getWidth() > 0 && control.getHeight() > 0 && visible.contains(new Rectangle(0, 0, control.getWidth(), control.getHeight())),
                    control.getName() + " is clipped " + control.getBounds() + " visible=" + visible);
            return null;
        });
    }

    @ParameterizedTest @ValueSource(ints = {14, 28})
    void submitConfirmationPreservesAcceptedErrorsAndSequentialConsent(int font) throws Exception {
        for (String scenario : List.of("validation-stale", "runtime", "sequential-decline", "sequential-accept")) {
            boolean sequential = scenario.startsWith("sequential-");
            try (View v = new View(sequential)) {
                java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
                String row = "submit-association-" + scenario;
                try {
                    scopeParentSetup(v, font, robot, row); destinationGuide(robot, v);
                    GuardConfig original = v.access.policy;
                    JDialog editor;
                    if (sequential) {
                        edt(() -> { get(v.panel, "tabs", JTabbedPane.class).setSelectedIndex(5); return null; });
                        v.open("settings.policyJson"); editor = await("editor.dialog"); destinationSize(editor, font, false);
                        GuardConfig candidate = new GuardConfig(original.schemaVersion(), original.allowScope(), original.blockScope(), original.rules(), original.defaultMode(), original.limits(), original.guardListenerPorts(), GuardConfig.DestinationScopeMode.ALL_DESTINATIONS);
                        scopePaste(robot, editor, get(editor, "advanced.policyJson", JTextArea.class), dev.cairnguard.model.PolicyCodec.encode(candidate));
                        scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                        JDialog first = await("message.dialog"); destinationSize(first, font, false);
                        scopeActivate(robot, first, get(first, "dialog.confirm", JButton.class)); awaitClosed(first);
                        JDialog second = await("message.dialog"); destinationSize(second, font, false);
                        assertTrue(edt(editor::isShowing)); assertTrue(edt(editor::isDisplayable));
                        assertTrue(edt(() -> get(second, "dialog.body", JTextArea.class).getText().contains("전체 목적지")));
                        var observation = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Boolean>>();
                        java.awt.event.HierarchyListener listener = submitRetirementObserver(editor, second, observation);
                        edt(() -> { editor.addHierarchyListener(listener); return null; });
                        try {
                            if (scenario.equals("sequential-decline")) {
                                assertEquals("dialog.cancel", edt(() -> second.getRootPane().getDefaultButton().getName()));
                                GuardPanelTrafficViewTest.await(second::isFocused); press(robot, java.awt.event.KeyEvent.VK_ESCAPE);
                            } else scopeActivate(robot, second, get(second, "dialog.confirm", JButton.class));
                            awaitClosed(second); awaitClosed(editor);
                            if (scenario.equals("sequential-decline")) {
                                assertSubmitRetirement(observation.get(), true);
                                assertEquals(0, v.access.updateAttempts); assertEquals(0, v.access.updates); assertEquals(original, v.access.policy);
                            } else {
                                assertSubmitRetirement(observation.get(), false);
                                assertEquals(1, v.access.updateAttempts); assertEquals(1, v.access.updates); assertEquals(candidate, v.access.policy);
                                assertEquals("p", v.access.casProject); assertEquals(7, v.access.casRevision);
                            }
                        } finally { edt(() -> { editor.removeHierarchyListener(listener); return null; }); }
                    } else {
                        scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                        editor = await("editor.dialog"); destinationSize(editor, font, true);
                        if (scenario.equals("validation-stale")) {
                            edt(() -> { get(editor, "scope.mode.choice", JComboBox.class).setSelectedItem(null); return null; });
                            scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                            assertTrue(edt(editor::isShowing)); assertTrue(edt(editor::isDisplayable)); assertEquals(0, v.access.updateAttempts);
                            assertTrue(edt(() -> get(editor, "editor.feedback", JTextArea.class).getText().contains("방식")));
                        } else edt(() -> { v.access.updateFailure = new UnsupportedOperationException("synthetic submit failure"); return null; });
                        scopeChoose(robot, editor, get(editor, "scope.mode.choice", JComboBox.class), 1);
                        scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                        JDialog prompt = await("message.dialog"); destinationSize(prompt, font, false);
                        var observation = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Boolean>>();
                        java.awt.event.HierarchyListener listener = submitRetirementObserver(editor, prompt, observation);
                        edt(() -> { editor.addHierarchyListener(listener); return null; });
                        try {
                            if (scenario.equals("validation-stale")) edt(() -> { v.access.project = "submit-stale-project"; v.access.revision++; v.panel.refreshNow(); return null; });
                            scopeActivate(robot, prompt, get(prompt, "dialog.confirm", JButton.class)); awaitClosed(prompt);
                            assertTrue(edt(editor::isShowing)); assertTrue(edt(editor::isDisplayable)); assertNull(observation.get(), "accepted consent/error must not retire the editor");
                            assertEquals(UiText.error(scenario.equals("validation-stale") ? "STALE_POLICY" : "ACTION_FAILED"), edt(() -> get(editor, "editor.feedback", JTextArea.class).getText()));
                            assertEquals(scenario.equals("validation-stale") ? 0 : 1, v.access.updateAttempts); assertEquals(0, v.access.updates); assertEquals(original, v.access.policy);
                            destinationCapture(robot, v, editor, row, font);
                            edt(() -> { get(editor, "editor.cancel", JButton.class).doClick(0); return null; }); awaitClosed(editor);
                        } finally { edt(() -> { editor.removeHierarchyListener(listener); return null; }); }
                    }
                    assertTrue(v.dialogs.errors.isEmpty()); scopeSaved(v, row, font);
                } catch (AssertionError failure) {
                    try { scopeFailureSnapshot(robot, v, font, row, failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                    throw failure;
                }
            }
        }
    }

    @ParameterizedTest @ValueSource(ints = {14, 28})
    void submitCapabilitiesDoNotEscapeToNestedRawSecondEditorOrShutdown(int font) throws Exception {
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            String row = "submit-nested-isolation";
            try {
                scopeParentSetup(v, font, robot, row); destinationGuide(robot, v);
                scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                JDialog firstEditor = await("editor.dialog"); destinationSize(firstEditor, font, true);
                scopeChoose(robot, firstEditor, get(firstEditor, "scope.mode.choice", JComboBox.class), 1);
                scopeActivate(robot, firstEditor, get(firstEditor, "editor.save", JButton.class));
                JDialog firstPrompt = await("message.dialog"); destinationSize(firstPrompt, font, false);
                java.util.Set<Window> beforeRaw = edt(() -> new java.util.HashSet<>(List.of(Window.getWindows())));
                var rawResult = new java.util.concurrent.CompletableFuture<Boolean>();
                // Deliberate nested EDT stimuli test capability isolation, not keyboard restoration.
                SwingUtilities.invokeLater(() -> { try { rawResult.complete(v.dialogs.real.confirm(v.panel, "Synthetic unrelated raw consent", "확인")); } catch (Throwable failure) { rawResult.completeExceptionally(failure); } });
                JDialog raw = awaitAddedDialog(beforeRaw, "message.dialog"); destinationSize(raw, font, false);
                edt(() -> { get(raw, "dialog.cancel", JButton.class).doClick(0); return null; }); awaitClosed(raw);
                assertFalse(rawResult.get(5, TimeUnit.SECONDS)); assertTrue(edt(firstEditor::isShowing)); assertTrue(edt(firstPrompt::isShowing));
                java.util.Set<Window> beforeSecond = edt(() -> new java.util.HashSet<>(List.of(Window.getWindows())));
                var secondDone = new java.util.concurrent.CompletableFuture<Void>();
                var secondAccepts = new java.util.concurrent.atomic.AtomicInteger();
                SwingUtilities.invokeLater(() -> {
                    try {
                        EditorForm<?> form = new dev.cairnguard.ui.editor.ScopeEditor(List.of(), List.of());
                        v.dialogs.real.edit(v.panel, "Synthetic second editor", "저장", form, confirmation -> { if (confirmation.confirm("Synthetic second submit consent", "확인")) secondAccepts.incrementAndGet(); });
                        secondDone.complete(null);
                    } catch (Throwable failure) { secondDone.completeExceptionally(failure); }
                });
                JDialog secondEditor = awaitAddedDialog(beforeSecond, "editor.dialog"); destinationSize(secondEditor, font, false);
                java.util.Set<Window> beforeSecondPrompt = edt(() -> new java.util.HashSet<>(List.of(Window.getWindows())));
                asyncClick(secondEditor, "editor.save");
                JDialog secondPrompt = awaitAddedDialog(beforeSecondPrompt, "message.dialog"); destinationSize(secondPrompt, font, false);
                var secondObservation = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Boolean>>();
                java.awt.event.HierarchyListener secondListener = submitRetirementObserver(secondEditor, secondPrompt, secondObservation);
                edt(() -> { secondEditor.addHierarchyListener(secondListener); get(secondPrompt, "dialog.cancel", JButton.class).doClick(0); return null; });
                awaitClosed(secondPrompt); awaitClosed(secondEditor); secondDone.get(5, TimeUnit.SECONDS);
                assertSubmitRetirement(secondObservation.get(), true); assertEquals(0, secondAccepts.get());
                assertTrue(edt(firstEditor::isShowing)); assertTrue(edt(firstEditor::isDisplayable)); assertTrue(edt(firstPrompt::isShowing));
                var firstObservation = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Boolean>>();
                java.awt.event.HierarchyListener firstListener = submitRetirementObserver(firstEditor, firstPrompt, firstObservation);
                edt(() -> { firstEditor.addHierarchyListener(firstListener); get(firstPrompt, "dialog.cancel", JButton.class).doClick(0); return null; });
                awaitClosed(firstPrompt); awaitClosed(firstEditor); assertSubmitRetirement(firstObservation.get(), true);
                edt(() -> { firstEditor.removeHierarchyListener(firstListener); secondEditor.removeHierarchyListener(secondListener); return null; });
                assertEquals(0, v.access.updateAttempts); assertEquals(0, v.access.updates); assertEquals(GuardConfig.defaults(), v.access.policy); assertTrue(v.dialogs.errors.isEmpty());
                scopeSaved(v, row, font);
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, row, failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
        try (View v = new View(false)) {
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            try {
                scopeParentSetup(v, font, robot, "submit-shutdown"); destinationGuide(robot, v);
                scopeActivate(robot, v.frame, get(v.panel, "scope.mode.edit", JButton.class));
                JDialog editor = await("editor.dialog"); destinationSize(editor, font, true);
                scopeChoose(robot, editor, get(editor, "scope.mode.choice", JComboBox.class), 1);
                scopeActivate(robot, editor, get(editor, "editor.save", JButton.class));
                JDialog prompt = await("message.dialog"); destinationSize(prompt, font, false);
                edt(() -> { v.panel.close(); return null; }); awaitClosed(prompt); awaitClosed(editor);
                assertFalse(edt(prompt::isDisplayable)); assertFalse(edt(editor::isDisplayable));
                assertEquals(0, v.access.updateAttempts); assertEquals(0, v.access.updates); assertEquals(GuardConfig.defaults(), v.access.policy);
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, "submit-shutdown", failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
    }

    private static java.awt.event.HierarchyListener submitRetirementObserver(JDialog editor, JDialog prompt,
            java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Boolean>> observation) {
        return event -> {
            if ((event.getChangeFlags() & java.awt.event.HierarchyEvent.DISPLAYABILITY_CHANGED) != 0 && !editor.isDisplayable())
                observation.compareAndSet(null, java.util.Map.of("onEdt", SwingUtilities.isEventDispatchThread(), "exactEditor", event.getComponent() == editor,
                        "confirmationShowing", prompt.isShowing(), "confirmationDisplayable", prompt.isDisplayable(),
                        "applicationModal", prompt.getModalityType() == java.awt.Dialog.ModalityType.APPLICATION_MODAL));
        };
    }

    private static void assertSubmitRetirement(java.util.Map<String, Boolean> observation, boolean promptStillShowing) {
        assertFalse(SwingUtilities.isEventDispatchThread()); assertNotNull(observation);
        assertEquals(Boolean.TRUE, observation.get("onEdt")); assertEquals(Boolean.TRUE, observation.get("exactEditor"));
        assertEquals(Boolean.TRUE, observation.get("applicationModal"));
        assertEquals(Boolean.valueOf(promptStillShowing), observation.get("confirmationShowing"));
        assertEquals(Boolean.valueOf(promptStillShowing), observation.get("confirmationDisplayable"));
    }

    private static JDialog awaitAddedDialog(java.util.Set<Window> before, String name) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            JDialog dialog = edt(() -> {
                for (Window window : Window.getWindows()) if (!before.contains(window) && window instanceof JDialog candidate && candidate.isShowing() && name.equals(candidate.getName())) return candidate;
                return null;
            });
            if (dialog != null) return dialog;
            Thread.sleep(10);
        }
        throw new AssertionError("new owned modal did not open: " + name);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"14, false", "28, false", "14, true", "28, true"})
    void persistentHeaderAndLegacyScopeKeepNativeCaptionsAndRealRowAtFixedGeometry(int font, boolean legacy) throws Exception {
        try (View v = new View(legacy)) {
            GuardConfig original = v.access.policy;
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(20);
            String row = "persistent-header-scope-" + (legacy ? "legacy" : "current");
            try {
                scopeParentSetup(v, font, robot, row);
                java.util.Map<String, Object> facts = edt(() -> {
                    Rectangle client = new Rectangle(v.frame.getContentPane().getLocationOnScreen(), v.frame.getContentPane().getSize());
                    List<String> names = new ArrayList<>(List.of("policy.version", "protection.state", "protection.passthroughCount",
                            "protection.passthrough", "help.examples", "policy.refresh"));
                    assertEquals(legacy, get(v.panel, "migration.banner", JPanel.class).isVisible());
                    if (legacy) names.addAll(List.of("migration.notice", "migration.review", "migration.exportOriginal"));
                    java.util.Map<String, Object> controls = new java.util.LinkedHashMap<>();
                    for (String name : names) {
                        JComponent control = get(v.panel, name, JComponent.class);
                        assertEquals(font, control.getFont().getSize(), name);
                        assertTrue(control.isShowing() && control.isEnabled(), name + " available");
                        assertTrue(client.contains(new Rectangle(control.getLocationOnScreen(), control.getSize())), name + " actual client");
                        assertTrue(control.getVisibleRect().contains(new Rectangle(0, 0, control.getWidth(), control.getHeight())), name + " fully visible");
                        scopeReadable(control, true);
                        String text = control instanceof AbstractButton button ? button.getText() : control instanceof JLabel label ? label.getText()
                                : assertInstanceOf(JTextArea.class, control).getText();
                        assertFalse(text.isBlank(), name + " persistent meaning");
                        java.util.Map<String, Object> actual = new java.util.LinkedHashMap<>();
                        actual.put("text", text); actual.put("bounds", control.getBounds().toString()); actual.put("visibleRect", control.getVisibleRect().toString());
                        actual.put("font", control.getFont().toString()); actual.put("preferred", control.getPreferredSize().toString());
                        if (control instanceof JTextArea note) {
                            assertFalse(note.isEditable()); assertTrue(note.getLineWrap());
                            actual.put("nativeWrappedSpan", note.getUI().getRootView(note).getPreferredSpan(javax.swing.text.View.Y_AXIS));
                        }
                        controls.put(name, actual);
                    }
                    JTabbedPane outer = get(v.panel, "tabs", JTabbedPane.class);
                    assertEquals(7, outer.getTabCount()); assertEquals(font, outer.getFont().getSize());
                    List<java.util.Map<String, Object>> navigation = new ArrayList<>();
                    for (int index = 0; index < outer.getTabCount(); index++) {
                        Rectangle tab = outer.getBoundsAt(index);
                        assertFalse(outer.getTitleAt(index).isBlank()); assertTrue(outer.isEnabledAt(index));
                        assertTrue(outer.getVisibleRect().contains(tab), "all seven native tab destinations visible");
                        Rectangle screenTab = new Rectangle(tab); java.awt.Point tabOrigin = outer.getLocationOnScreen();
                        screenTab.translate(tabOrigin.x, tabOrigin.y); assertTrue(client.contains(screenTab), "tab actual client");
                        assertTrue(tab.width >= outer.getFontMetrics(outer.getFont()).stringWidth(outer.getTitleAt(index)), "full tab glyphs");
                        assertTrue(tab.height >= outer.getFontMetrics(outer.getFont()).getHeight(), "native tab line");
                        navigation.add(java.util.Map.of("index", index, "title", outer.getTitleAt(index), "bounds", tab.toString()));
                    }
                    JTable table = get(v.panel, "scope.allow.table", JTable.class);
                    assertEquals(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 10), table.getRowHeight(), "original current-font row floor");
                    javax.swing.table.JTableHeader header = table.getTableHeader();
                    assertTrue(header.isShowing()); assertEquals(font, header.getFont().getSize());
                    assertTrue(header.getHeight() >= header.getPreferredSize().height, "native table header allocated");
                    Rectangle columnUnion = null;
                    for (int index = 0; index < table.getColumnCount(); index++) {
                        Rectangle column = header.getHeaderRect(index);
                        columnUnion = columnUnion == null ? new Rectangle(column) : columnUnion.union(column);
                        assertTrue(header.getVisibleRect().contains(column), "all native scope column captions visible");
                        Rectangle screenColumn = new Rectangle(column); java.awt.Point headerOrigin = header.getLocationOnScreen();
                        screenColumn.translate(headerOrigin.x, headerOrigin.y); assertTrue(client.contains(screenColumn), "native header cell actual client");
                        String title = String.valueOf(table.getColumnModel().getColumn(index).getHeaderValue());
                        assertTrue(column.width >= header.getFontMetrics(header.getFont()).stringWidth(title), title + " full current-font glyphs");
                    }
                    assertNotNull(columnUnion);
                    assertTrue(header.getVisibleRect().contains(columnUnion), "all actual native header cells fully visible");
                    JScrollPane scroll = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, table);
                    assertTrue(scroll.getViewport().getExtentSize().height >= table.getRowHeight(), "viewport must show one original-font real row even when empty");
                    assertTrue(table.getVisibleRect().height >= table.getRowHeight(), "one visible native row");
                    java.util.Map<String, Object> result = new java.util.LinkedHashMap<>();
                    result.put("font", font); result.put("legacy", legacy); result.put("actualClient", client.toString()); result.put("controls", controls);
                    result.put("allSevenNativeTabs", navigation); result.put("tableHeaderBounds", header.getBounds().toString());
                    result.put("tableHeaderVisibleRect", header.getVisibleRect().toString()); result.put("nativeRowHeight", table.getRowHeight());
                    result.put("viewportExtent", scroll.getViewport().getExtentSize().toString());
                    assertEquals(0, v.access.updates); assertEquals(0, v.access.updateAttempts); assertEquals(original, v.access.policy);
                    return result;
                });
                Path directory = Path.of(System.getProperty("cairn.scopeUx.evidence", "build/scope-ux-evidence"));
                java.nio.file.Files.writeString(directory.resolve(row + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale") + "-header.json"),
                        dev.cairnguard.model.Json.write(facts));
                assertEquals(0, v.access.updates); assertEquals(0, v.access.updateAttempts); assertEquals(original, v.access.policy);
                assertTrue(v.dialogs.errors.isEmpty());
            } catch (AssertionError failure) {
                try { scopeFailureSnapshot(robot, v, font, row, failure); } catch (Throwable capture) { failure.addSuppressed(capture); }
                throw failure;
            }
        }
    }

    private static final class View implements AutoCloseable {
        final GuardPanelV2Test.Access access=new GuardPanelV2Test.Access();final Modal dialogs=new Modal();final GuardPanel panel;final JFrame frame;
        View(boolean legacy)throws Exception{if(legacy)access.legacy();panel=edt(()->new GuardPanel(access,dialogs,false));frame=edt(()->{JFrame f=new JFrame("Synthetic isolated v2 human UI");f.setContentPane(panel);f.setSize(1000,760);f.setVisible(true);return f;});}
        void open(String name)throws Exception{asyncClick(panel,name);}
        @Override public void close(){
            try { edt(()->{panel.close();frame.dispose();return null;}); }
            catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError("owned UI cleanup interrupted",e);}
            catch(Exception e){throw new AssertionError("owned UI cleanup failed",e);}
        }
    }
    private static final class Modal implements GuardPanel.Dialogs {
        final GuardPanel.SwingDialogs real=new GuardPanel.SwingDialogs();final List<String> errors=new ArrayList<>();
        @Override public boolean confirm(Component p,String text){return real.confirm(p,text);}
        @Override public boolean confirm(Component p,String text,String label){return real.confirm(p,text,label);}
        @Override public Path chooseExport(Component p,String extension){fail("not an export test");return null;}
        @Override public void error(Component p,String text){errors.add(text);}
        @Override public void edit(Component p,String title,String label,EditorForm<?> form,java.util.function.Consumer<GuardPanel.SubmitConfirmation> save){real.edit(p,title,label,form,save);}
        @Override public void closeEditors(){real.closeEditors();}
    }
    private static void asyncClick(Component root,String name)throws Exception{JButton button=edt(()->get(root,name,JButton.class));SwingUtilities.invokeLater(()->button.doClick(0));}
    private static JDialog await(String name)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(System.nanoTime()<until){JDialog dialog=edt(()->{for(Window w:Window.getWindows())if(w instanceof JDialog d&&d.isShowing()&&name.equals(d.getName()))return d;return null;});if(dialog!=null)return dialog;Thread.sleep(10);}throw new AssertionError("owned modal did not open: "+name);}
    private static void awaitClosed(JDialog d)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(System.nanoTime()<until){if(!edt(d::isShowing))return;Thread.sleep(10);}fail("owned modal did not close");}
    private static <T>T get(Component c,String name,Class<T> type){return type.cast(java.util.Objects.requireNonNull(GuardPanelV2Test.find(c,name),name));}
    private static void fonts(Component c,int size){if(c.getFont()!=null)c.setFont(c.getFont().deriveFont((float)size));if(c instanceof Container p)for(Component child:p.getComponents())fonts(child,size);}

    @ParameterizedTest(name = "{0}")
    @MethodSource("originalPolicyDesktopCases")
    void originalPolicyExportUsesRealChooserPlaintextConsentAndLateRefusal(String row, boolean review, boolean existing, boolean accept, boolean late, @TempDir Path directory) throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless(), "these rows require actual isolated Swing");
        PolicyExportModal consent = new PolicyExportModal();
        var reviewEditor = new java.util.concurrent.atomic.AtomicReference<JDialog>();
        try (GuardPanelV2Test.PolicyExportFixture f = new GuardPanelV2Test.PolicyExportFixture(directory, existing, consent)) {
            JFrame frame = edt(() -> {
                JFrame view = new JFrame("Synthetic original-policy export");
                view.setContentPane(f.panel); view.setSize(1000, 760); view.setVisible(true); return view;
            });
            try {
                if (late) f.access.late = GuardPanelV2Test.PolicyTransition.PROJECT;
                if (review) {
                    asyncClick(f.panel, "migration.review");
                    JDialog editor = await("editor.dialog"); reviewEditor.set(editor);
                    edt(() -> {
                        JTextArea original = get(editor, "migration.original", JTextArea.class);
                        assertEquals(f.original, original.getText(), "review export retains the captured original, not a later project");
                        assertFalse(original.isEditable());
                        assertFalse(get(editor, "migration.removeLegacy", JCheckBox.class).isSelected());
                        return null;
                    });
                    asyncClick(editor, "migration.exportInReview");
                } else asyncClick(f.panel, "migration.exportOriginal");
                JDialog chooserDialog = awaitPolicyChooser();
                JButton save = edt(() -> {
                    JFileChooser chooser = policyChooser(chooserDialog);
                    assertNotNull(chooser); chooser.setSelectedFile(f.target.toFile());
                    JButton button = policyButtonWithText(chooser, chooser.getUI().getApproveButtonText(chooser));
                    assertNotNull(button, "the actual chooser Save button must be reachable");
                    assertTrue(button.isEnabled()); assertNotNull(button.getAccessibleContext().getAccessibleName());
                    return button;
                });
                SwingUtilities.invokeLater(() -> save.doClick(0));
                awaitClosed(chooserDialog);
                JDialog prompt = awaitPolicyPromptOrResult(f, consent);
                if (prompt != null) {
                    edt(() -> {
                        assertTrue(prompt.isModal());
                        JButton cancel = get(prompt, "dialog.cancel", JButton.class), confirm = get(prompt, "dialog.confirm", JButton.class);
                        assertSame(cancel, prompt.getRootPane().getDefaultButton(), "Cancel is the safe default for every selected file");
                        for (JButton button : List.of(cancel, confirm)) {
                            assertTrue(button.isEnabled()); assertTrue(button.isShowing());
                            assertNotNull(button.getAccessibleContext().getAccessibleName());
                        }
                        (accept ? confirm : cancel).doClick(0); return null;
                    });
                    awaitClosed(prompt);
                }
                if (accept || prompt == null) f.awaitResult(consent.errors);
                else assertFalse(f.inProgress(), "actual plaintext Cancel must not start publication");
                if (late) {
                    assertNull(f.access.transitionFailure, "the late fixture must be valid");
                    assertTrue(f.access.transitionReached, "the real controller transition must be reached before publication assertions");
                }
                if (review) { assertTrue(edt(reviewEditor.get()::isShowing)); assertTrue(edt(reviewEditor.get()::isDisplayable)); }
                f.assertProtectedState();
                System.out.printf("POLICY_EXPORT_DESKTOP %s scale=%s realChooser=true prompts=%d intendedAccept=%s transitionReached=%s completed=%s%n", row, System.getProperty("sun.java2d.uiScale"), consent.confirmations.size(), accept, f.access.transitionReached, f.completed());
                assertAll(() -> f.assertTarget(accept && !late), () -> GuardPanelV2Test.assertPolicyConsent(consent.confirmations, existing));
            } finally {
                edt(() -> { frame.dispose(); return null; });
            }
        }
    }

    static Stream<Arguments> originalPolicyDesktopCases() {
        return Stream.of(Arguments.of("D1", false, false, false, false), Arguments.of("D2", true, false, true, false),
                Arguments.of("D3", false, true, true, false), Arguments.of("D4", true, true, false, false),
                Arguments.of("D5", false, false, true, true), Arguments.of("D6", true, true, true, true));
    }

    private static JDialog awaitPolicyChooser() throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            JDialog dialog = edt(() -> {
                for (Window window : Window.getWindows())
                    if (window instanceof JDialog candidate && candidate.isShowing() && policyChooser(candidate) != null) return candidate;
                return null;
            });
            if (dialog != null) return dialog;
            Thread.sleep(10);
        }
        throw new AssertionError("the actual original-policy chooser did not open; this is not a behavioral red");
    }

    private static JDialog awaitPolicyPromptOrResult(GuardPanelV2Test.PolicyExportFixture fixture, PolicyExportModal consent) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (System.nanoTime() < until) {
            JDialog prompt = edt(() -> {
                for (Window window : Window.getWindows())
                    if (window instanceof JDialog candidate && candidate.isShowing() && "message.dialog".equals(candidate.getName())) return candidate;
                return null;
            });
            if (prompt != null) return prompt;
            if (fixture.completed() || edt(() -> !consent.errors.isEmpty())) return null;
            Thread.sleep(10);
        }
        throw new AssertionError("neither an actual prompt nor a completed export/error was observed; this is not a behavioral red");
    }

    private static JFileChooser policyChooser(Component root) {
        if (root instanceof JFileChooser chooser) return chooser;
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            JFileChooser chooser = policyChooser(child); if (chooser != null) return chooser;
        }
        return null;
    }

    private static JButton policyButtonWithText(Component root, String text) {
        if (root instanceof JButton button && text.equals(button.getText())) return button;
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            JButton button = policyButtonWithText(child, text); if (button != null) return button;
        }
        return null;
    }

    private static final class PolicyExportModal implements GuardPanel.Dialogs {
        final GuardPanel.SwingDialogs real = new GuardPanel.SwingDialogs();
        final List<String> confirmations = new ArrayList<>(), errors = new ArrayList<>();
        @Override public Path chooseExport(Component parent, String extension) { return real.chooseExport(parent, extension); }
        @Override public boolean confirm(Component parent, String text) { confirmations.add(text); return real.confirm(parent, text); }
        @Override public boolean confirm(Component parent, String text, String label) { confirmations.add(text); return real.confirm(parent, text, label); }
        @Override public void error(Component parent, String text) { errors.add(text); }
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, java.util.function.Consumer<GuardPanel.SubmitConfirmation> save) { real.edit(parent, title, label, form, confirmation -> save.accept((text, confirmLabel) -> { confirmations.add(text); return confirmation.confirm(text, confirmLabel); })); }
        @Override public void closeEditors() { real.closeEditors(); }
    }

    @ParameterizedTest(name = "D01-font{0}") @ValueSource(ints = {14, 28})
    void messageFindKeysTargetExactFieldAndKeepCurrentHighlightVisible(int font) throws Exception {
        findActualScale();
        try (View v = new View(false)) {
            seedFindView(v, "banana\n" + "scroll-line\n".repeat(180) + "needle needle");
            TrafficInspector inline = TrafficInspectorFindTest.inspector(v.panel);
            edt(() -> { TrafficInspectorFindTest.entry(inline, "requestRaw"); fonts(v.panel, font); v.frame.validate(); return null; });
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(15);
            for (boolean popout : List.of(false, true)) {
                JDialog dialog = null;
                if (popout) { v.open("traffic.detail"); dialog = await("editor.dialog"); }
                Component root = popout ? dialog : v.panel;
                TrafficInspector owner = TrafficInspectorFindTest.inspector(root);
                Window window = popout ? dialog : v.frame;
                edt(() -> { fonts(window, font); window.validate(); return null; });
                for (String field : TrafficInspectorFindTest.FIELDS) {
                    JTextArea area = TrafficInspectorFindTest.area(owner, field);
                    edt(() -> { TrafficInspectorFindTest.selectField(owner, field); area.select(0, 3); return null; });
                    findFocus(window, area);
                    findChord(robot, java.awt.event.KeyEvent.VK_CONTROL, java.awt.event.KeyEvent.VK_F);
                    JTextArea query = edt(() -> TrafficInspectorFindTest.query(owner));
                    GuardPanelTrafficViewTest.await(query::isFocusOwner);
                    edt(() -> {
                        assertNotNull(area.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, java.awt.event.InputEvent.CTRL_DOWN_MASK)));
                        assertNotNull(area.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, java.awt.event.InputEvent.META_DOWN_MASK)));
                        query.setText("needle"); return null;
                    });
                    TrafficInspectorFindTest.settled(owner);
                    int first = TrafficInspectorFindTest.needleOffset(owner, field);
                    TrafficInspectorFindTest.assertRange(area, first, 6);
                    press(robot, java.awt.event.KeyEvent.VK_ENTER); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(area, first + 7, 6);
                    findChord(robot, java.awt.event.KeyEvent.VK_SHIFT, java.awt.event.KeyEvent.VK_ENTER); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(area, first, 6);
                    edt(() -> {
                        assertTrue(query.isFocusOwner()); assertEquals(0, area.getSelectionStart()); assertEquals(3, area.getSelectionEnd());
                        var rectangle = area.modelToView2D(first); assertNotNull(rectangle);
                        assertTrue(area.getVisibleRect().intersects(rectangle.getBounds()), field + " current occurrence must actually be visible");
                        assertEquals(1, get(v.panel, "traffic.table", JTable.class).getSelectedRowCount()); assertEquals("", get(v.panel, "traffic.search", JTextField.class).getText()); return null;
                    });
                }
                findScreenshot(robot, window, "D01-" + (popout ? "popout" : "inline"), font);
                if (dialog != null) { final JDialog current = dialog; edt(() -> { get(current, "editor.save", JButton.class).doClick(0); return null; }); awaitClosed(dialog); }
            }
            assertTrue(v.dialogs.errors.isEmpty());
            System.out.printf("FIND_KEYS scale=%s font=%d roots=2 fields=12 robotCtrlF=true enterAndShiftEnter=true actualFocusAndRangeAndViewport=true%n", System.getProperty("sun.java2d.uiScale"), font);
        }
    }

    @ParameterizedTest(name = "D02-font{0}") @ValueSource(ints = {14, 28})
    void pendingKeysNeverCloseRestartOrReplayAndFooterEscapeDismissesFirst(int font) throws Exception {
        findActualScale();
        try (View v = new View(false)) {
            seedFindView(v, "banana needle needle"); v.open("traffic.detail"); JDialog dialog = await("editor.dialog");
            TrafficInspector owner = TrafficInspectorFindTest.inspector(dialog);
            edt(() -> { TrafficInspectorFindTest.entry(owner, "requestRaw"); fonts(dialog, font); dialog.validate(); return null; });
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(15);
            TrafficInspectorFindTest.search(owner, "requestBody", "needle");
            JButton next = edt(() -> get(owner, "traffic.find.next", JButton.class));
            findFocus(dialog, next);
            JButton defaultClose = edt(() -> dialog.getRootPane().getDefaultButton());
            try (var hold = TrafficInspectorFindTest.HeldWork.start(owner, "needle", false)) {
                JTextArea query = edt(() -> TrafficInspectorFindTest.query(owner));
                GuardPanelTrafficViewTest.await(query::isFocusOwner);
                long generation = TrafficInspectorFindTest.pumpGeneration(hold.pump);
                for (int i = 0; i < 4; i++) { press(robot, java.awt.event.KeyEvent.VK_ENTER); findChord(robot, java.awt.event.KeyEvent.VK_SHIFT, java.awt.event.KeyEvent.VK_ENTER); }
                edt(() -> { assertTrue(dialog.isShowing()); assertSame(defaultClose, dialog.getRootPane().getDefaultButton()); assertFalse(next.isEnabled());
                    assertTrue(TrafficInspectorFindTest.status(owner).contains("Searching")); assertEquals(generation, TrafficInspectorFindTest.pumpGeneration(hold.pump));
                    for (String button : List.of("previous", "next", "close")) {
                        JComponent control = get(owner, "traffic.find." + button, JComponent.class);
                        Object key = control.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0)); assertNotNull(key); assertTrue(control.getActionMap().get(key).isEnabled());
                    }
                    return null;
                });
                hold.release(); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(TrafficInspectorFindTest.area(owner, "requestBody"), 7, 6); assertEquals(1, hold.executions.get());
            }
            findFocus(dialog, next); press(robot, java.awt.event.KeyEvent.VK_SPACE); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(TrafficInspectorFindTest.area(owner, "requestBody"), 14, 6);
            JButton previous = edt(() -> get(owner, "traffic.find.previous", JButton.class));
            findFocus(dialog, previous); press(robot, java.awt.event.KeyEvent.VK_SPACE); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(TrafficInspectorFindTest.area(owner, "requestBody"), 7, 6);
            JButton closeFind = edt(() -> get(owner, "traffic.find.close", JButton.class));
            findFocus(dialog, closeFind); press(robot, java.awt.event.KeyEvent.VK_ENTER); TrafficInspectorFindTest.settled(owner); TrafficInspectorFindTest.assertRange(TrafficInspectorFindTest.area(owner, "requestBody"), 14, 6);
            findFocus(dialog, closeFind); press(robot, java.awt.event.KeyEvent.VK_SPACE);
            GuardPanelTrafficViewTest.await(() -> !TrafficInspectorFindTest.bar(owner).isVisible()); assertTrue(edt(dialog::isShowing));
            TrafficInspectorFindTest.search(owner, "requestBody", "needle"); findFocus(dialog, defaultClose);
            press(robot, java.awt.event.KeyEvent.VK_ESCAPE);
            edt(() -> { assertTrue(dialog.isShowing(), "footer first Escape dismisses Find, not the modal"); assertFalse(TrafficInspectorFindTest.bar(owner).isVisible()); assertEquals("", TrafficInspectorFindTest.query(owner).getText()); assertSame(defaultClose, dialog.getRootPane().getDefaultButton()); return null; });
            press(robot, java.awt.event.KeyEvent.VK_ESCAPE); awaitClosed(dialog);
            v.open("traffic.detail"); JDialog reopened = await("editor.dialog");
            findFocus(reopened, edt(() -> get(reopened, "editor.save", JButton.class))); press(robot, java.awt.event.KeyEvent.VK_ENTER); awaitClosed(reopened);
            v.open("settings.edit"); JDialog unrelated = await("editor.dialog");
            findFocus(unrelated, edt(() -> get(unrelated, "editor.cancel", JButton.class))); press(robot, java.awt.event.KeyEvent.VK_ESCAPE); awaitClosed(unrelated);
            assertEquals(0, v.access.updates); assertTrue(v.dialogs.errors.isEmpty());
            System.out.printf("FIND_PENDING_KEYS scale=%s font=%d realTask=true noRestartOrReplay=true spaceSemantics=true footerFirstEscape=true secondEscape=true unchangedDefaultAndOtherDialog=true%n", System.getProperty("sun.java2d.uiScale"), font);
        }
    }

    @ParameterizedTest(name = "D03-font{0}") @ValueSource(ints = {14, 28})
    void findControlsRemainReachableAndFrameRetirementNeverRestoresState(int font) throws Exception {
        findActualScale();
        try (View v = new View(false)) {
            seedFindView(v, "banana needle needle"); TrafficInspector owner = TrafficInspectorFindTest.inspector(v.panel);
            edt(() -> { TrafficInspectorFindTest.entry(owner, "requestRaw"); fonts(v.panel, font); v.frame.setSize(720, 540); v.frame.validate(); return null; });
            java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(15);
            for (boolean popout : List.of(false, true)) {
                JDialog dialog = null;
                if (popout) { v.open("traffic.detail"); dialog = await("editor.dialog"); }
                TrafficInspector current = popout ? TrafficInspectorFindTest.inspector(dialog) : owner; Window window = popout ? dialog : v.frame;
                edt(() -> { fonts(window, font); window.setSize(700, 520); window.validate(); return null; });
                for (String side : List.of("requestRaw", "responseRaw")) {
                    JButton entry = edt(() -> TrafficInspectorFindTest.entry(current, side)); findFocus(window, entry); press(robot, java.awt.event.KeyEvent.VK_ENTER);
                    GuardPanelTrafficViewTest.await(() -> TrafficInspectorFindTest.query(current).isFocusOwner());
                    for (String control : List.of("traffic.find.target", "traffic.find.query", "traffic.find.status", "traffic.find.previous", "traffic.find.next", "traffic.find.close")) {
                        JComponent component = edt(() -> get(current, control, JComponent.class)); findReachable(window, component);
                        edt(() -> { assertNotNull(component.getAccessibleContext().getAccessibleName(), control); assertEquals(Boolean.TRUE, component.getClientProperty("html.disable")); return null; });
                    }
                    edt(() -> { assertSame(TrafficInspectorFindTest.query(current), get(current, "traffic.find.query.label", JLabel.class).getLabelFor()); return null; });
                }
                edt(() -> {
                    JSplitPane pair = get(current, "traffic.pair", JSplitPane.class); pair.setDividerLocation(0.0); window.validate(); pair.setDividerLocation(0.5); window.validate();
                    if (!popout) { JSplitPane history = get(v.panel, "traffic.history", JSplitPane.class); history.setDividerLocation(1.0); history.setDividerLocation(0.4); }
                    window.setSize(740, 540); window.validate(); return null;
                });
                findReachable(window, edt(() -> TrafficInspectorFindTest.entry(current, "requestRaw"))); findReachable(window, edt(() -> TrafficInspectorFindTest.entry(current, "responseRaw")));
                findScreenshot(robot, window, "D03-" + (popout ? "popout" : "inline"), font);
                if (dialog != null) { final JDialog closing = dialog; edt(() -> { get(closing, "editor.save", JButton.class).doClick(0); return null; }); awaitClosed(dialog); }
            }
            TrafficInspectorFindTest.search(owner, "requestBody", "needle");
            try (var hold = TrafficInspectorFindTest.HeldWork.start(owner, "needle", false)) {
                edt(() -> { v.frame.setVisible(false); assertEquals("", TrafficInspectorFindTest.query(owner).getText()); assertFalse(TrafficInspectorFindTest.bar(owner).isVisible()); v.frame.setVisible(true); return null; });
                hold.release(); edt(() -> { assertEquals("", TrafficInspectorFindTest.query(owner).getText()); return null; });
            }
            TrafficInspectorFindTest.search(owner, "requestBody", "needle");
            edt(() -> { v.frame.setContentPane(new JPanel()); v.frame.setContentPane(v.panel); v.frame.validate(); assertEquals("", TrafficInspectorFindTest.query(owner).getText()); return null; });
            v.open("traffic.detail"); JDialog nested = await("editor.dialog"); TrafficInspector popout = TrafficInspectorFindTest.inspector(nested);
            TrafficInspectorFindTest.search(popout, "responseBody", "needle"); var documents = edt(() -> TrafficInspectorFindTest.documents(popout));
            try (var hold = TrafficInspectorFindTest.HeldWork.start(popout, "needle", false)) {
                edt(() -> { v.panel.close(); for (var document : documents) assertEquals(0, document.getLength()); return null; });
                awaitClosed(nested); hold.release(); assertTrue(hold.pump.awaitExit(5000)); assertFalse(hold.pump.retainsPending());
            }
            assertEquals(0, v.access.updates); assertTrue(v.dialogs.errors.isEmpty());
            System.out.printf("FIND_LAYOUT scale=%s font=%d roots=2 reachable=true resizedAndCollapsed=true actualHideAndRemovalRetire=true nestedPanelCloseBlanks=true laneExited=true%n", System.getProperty("sun.java2d.uiScale"), font);
        }
    }

    private static void seedFindView(View view, String body) throws Exception {
        edt(() -> { TrafficInspectorFindTest.addRow(view.access, "/find-desktop", body); view.panel.refreshNow(); get(view.panel, "tabs", JTabbedPane.class).setSelectedIndex(3);
            get(view.panel, "traffic.table", JTable.class).setRowSelectionInterval(0, 0); return null; });
        GuardPanelTrafficViewTest.await(() -> get(view.panel, "traffic.request", JTextArea.class).getDocument().getLength() > 0);
    }
    private static void findActualScale() throws Exception {
        assertFalse(java.awt.GraphicsEnvironment.isHeadless());
        double scale = edt(() -> java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration().getDefaultTransform().getScaleX());
        assertEquals(Double.parseDouble(System.getProperty("sun.java2d.uiScale")), scale, 0.0001);
    }
    private static void findChord(java.awt.Robot robot, int modifier, int key) { robot.keyPress(modifier); robot.keyPress(key); robot.keyRelease(key); robot.keyRelease(modifier); robot.waitForIdle(); }
    private static void findFocus(Window window, JComponent control) throws Exception {
        findReachable(window, control);
        edt(() -> { window.toFront(); return null; });
        GuardPanelTrafficViewTest.await(window::isFocused);
        edt(() -> { assertTrue(control.isFocusOwner() || control.requestFocusInWindow(), control.getName()); return null; });
        GuardPanelTrafficViewTest.await(control::isFocusOwner);
    }
    private static void findReachable(Window window, JComponent control) throws Exception {
        edt(() -> {
            TrafficInspector owner = (TrafficInspector) SwingUtilities.getAncestorOfClass(TrafficInspector.class, control);
            String field = switch (control.getName() == null ? "" : control.getName()) {
                case "traffic.request" -> "request"; case "traffic.request.headers" -> "requestHeaders"; case "traffic.request.body" -> "requestBody";
                case "traffic.response" -> "response"; case "traffic.response.headers" -> "responseHeaders"; case "traffic.response.body" -> "responseBody";
                default -> "";
            };
            if (control instanceof JTextArea && owner != null && !field.isEmpty() && control == TrafficInspectorFindTest.field(owner, field)) {
                JTabbedPane tabs = field.startsWith("request") ? owner.requestTabs : owner.responseTabs;
                JScrollPane scroll = (JScrollPane) tabs.getComponentAt(field.endsWith("Headers") ? 1 : field.endsWith("Body") ? 2 : 0);
                assertTrue(control.getParent() instanceof JViewport, control.getName());
                JViewport viewport = (JViewport) control.getParent();
                assertSame(scroll.getViewport(), viewport, control.getName()); assertSame(control, viewport.getView(), control.getName());
                scroll.scrollRectToVisible(new Rectangle(0, 0, scroll.getWidth(), scroll.getHeight())); window.validate();
                Rectangle extent = new Rectangle(0, 0, viewport.getWidth(), viewport.getHeight());
                assertTrue(control.isShowing(), control.getName());
                assertTrue(viewport.getExtentSize().width > 0 && viewport.getExtentSize().height > 0 && viewport.getVisibleRect().contains(extent),
                        control.getName() + " viewport clipped " + viewport.getBounds() + " visible " + viewport.getVisibleRect());
                Rectangle visible = viewport.getViewRect().intersection(new Rectangle(0, 0, control.getWidth(), control.getHeight()));
                assertTrue(visible.width > 0 && visible.height > 0, control.getName()); assertEquals(visible, control.getVisibleRect(), control.getName());
                return null;
            }
            control.scrollRectToVisible(new Rectangle(0, 0, control.getWidth(), control.getHeight())); window.validate();
            assertTrue(control.isShowing(), control.getName()); assertTrue(control.getWidth() > 0 && control.getHeight() > 0 && control.getVisibleRect().contains(new Rectangle(0, 0, control.getWidth(), control.getHeight())), control.getName() + " clipped " + control.getBounds() + " visible " + control.getVisibleRect()); return null; });
    }
    private static void findScreenshot(java.awt.Robot robot, Window window, String name, int font) throws Exception {
        String evidence = System.getProperty("cairn.find.evidence");
        if (evidence != null) {
            java.nio.file.Path directory = java.nio.file.Path.of(evidence); java.nio.file.Files.createDirectories(directory);
            java.awt.Rectangle bounds = edt(window::getBounds);
            assertTrue(javax.imageio.ImageIO.write(robot.createScreenCapture(bounds), "png", directory.resolve(name + "-font" + font + "-scale" + System.getProperty("sun.java2d.uiScale") + ".png").toFile()));
        }
    }
}
