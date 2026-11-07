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
        @Override public void edit(Component p,String title,String label,EditorForm<?> form,Runnable save){real.edit(p,title,label,form,save);}
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
        try (GuardPanelV2Test.PolicyExportFixture f = new GuardPanelV2Test.PolicyExportFixture(directory, existing, consent)) {
            JFrame frame = edt(() -> {
                JFrame view = new JFrame("Synthetic original-policy export");
                view.setContentPane(f.panel); view.setSize(1000, 760); view.setVisible(true); return view;
            });
            try {
                if (late) f.access.late = GuardPanelV2Test.PolicyTransition.PROJECT;
                if (review) {
                    asyncClick(f.panel, "migration.review");
                    JDialog editor = await("editor.dialog");
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
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, Runnable save) { real.edit(parent, title, label, form, save); }
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
        findReachable(window, control); edt(() -> { window.toFront(); assertTrue(control.requestFocusInWindow(), control.getName()); return null; }); GuardPanelTrafficViewTest.await(control::isFocusOwner);
    }
    private static void findReachable(Window window, JComponent control) throws Exception {
        edt(() -> { control.scrollRectToVisible(new Rectangle(0, 0, control.getWidth(), control.getHeight())); window.validate();
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
