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
                get(editor,"settings.heavyMiB",JTextField.class).setText("8");listener.setText("8080");
                assertEquals(0,v.access.updates);get(editor,"editor.cancel",JButton.class).doClick(0);return null;
            });
            awaitClosed(editor);assertEquals(0,v.access.updates);
            v.open("settings.edit");JDialog reopened=await("editor.dialog");
            edt(()->{assertEquals("5",get(reopened,"settings.heavyMiB",JTextField.class).getText());assertEquals("",get(reopened,"settings.listenerPorts",JTextField.class).getText());get(reopened,"editor.cancel",JButton.class).doClick(0);return null;});awaitClosed(reopened);
            assertEquals(0,v.access.updates);assertEquals(GuardConfig.defaults(),v.access.policy);
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

    @Test void candidateThresholdIsAnUnsavedDraftUntilFirstResponseWarningIsConfirmed() throws Exception {
        try(View v=new View(false)) {
            edt(()->{v.access.candidates=new ArrayList<>(List.of(GuardPanelV2Test.candidate("large","https://example.test/large",900)));v.panel.refreshNow();get(v.panel,"tabs",JTabbedPane.class).setSelectedIndex(7);get(v.panel,"candidates.table",JTable.class).setRowSelectionInterval(0,0);return null;});
            v.open("candidates.threshold");JDialog editor=await("editor.dialog");
            edt(()->{get(editor,"candidates.thresholdMiB",JTextField.class).setText("2.5");assertTrue(get(editor,"candidates.thresholdNotice",JTextArea.class).getText().contains("첫"));assertEquals(0,v.access.updates);return null;});
            asyncClick(editor,"editor.save");JDialog confirm=await("message.dialog");
            edt(()->{assertEquals(0,v.access.updates);assertEquals("dialog.cancel",confirm.getRootPane().getDefaultButton().getName());get(confirm,"dialog.confirm",JButton.class).doClick(0);return null;});awaitClosed(confirm);awaitClosed(editor);
            assertEquals(1,v.access.updates);assertEquals(2621440,v.access.policy.limits().heavyPathLimits().getFirst().maxBytes());assertTrue(v.access.policy.blockScope().isEmpty());assertTrue(v.dialogs.errors.isEmpty());
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
        @Override public void edit(Component p,String title,String label,EditorForm<?> form,Runnable save){real.edit(p,title,label,form,save);}
        @Override public void closeEditors(){real.closeEditors();}
    }
    private static void asyncClick(Component root,String name)throws Exception{JButton button=edt(()->get(root,name,JButton.class));SwingUtilities.invokeLater(()->button.doClick(0));}
    private static JDialog await(String name)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(System.nanoTime()<until){JDialog dialog=edt(()->{for(Window w:Window.getWindows())if(w instanceof JDialog d&&d.isShowing()&&name.equals(d.getName()))return d;return null;});if(dialog!=null)return dialog;Thread.sleep(10);}throw new AssertionError("owned modal did not open: "+name);}
    private static void awaitClosed(JDialog d)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(System.nanoTime()<until){if(!edt(d::isShowing))return;Thread.sleep(10);}fail("owned modal did not close");}
    private static <T>T get(Component c,String name,Class<T> type){return type.cast(java.util.Objects.requireNonNull(GuardPanelV2Test.find(c,name),name));}
    private static void fonts(Component c,int size){if(c.getFont()!=null)c.setFont(c.getFont().deriveFont((float)size));if(c instanceof Container p)for(Component child:p.getComponents())fonts(child,size);}
}
