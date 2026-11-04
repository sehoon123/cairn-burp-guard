package dev.cairnguard.ui;

import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.ui.editor.RuleEditor;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real mouse click -> new editable condition -> explicit save -> form roundtrip. NOT native Burp. */
@Tag("desktop") @Timeout(20)
class RuleEditorDesktopTest {
    @ParameterizedTest @CsvSource({"14,AND", "28,AND", "14,OR", "28,OR"})
    void addConditionWorksFromInitialLeafWithRealClicksAndDoesNotSaveUntilRequested(int font, String groupKind) throws Exception {
        GuardPanel.SwingDialogs dialogs = new GuardPanel.SwingDialogs();
        RuleEditor editor = edt(() -> new RuleEditor(null));
        AtomicReference<Rule> saved = new AtomicReference<>();
        JFrame frame = edt(() -> { JFrame parent = new JFrame("Synthetic rule dialog test"); parent.setSize(1000, 800); parent.setVisible(true); return parent; });
        CompletableFuture<Void> finished = new CompletableFuture<>();
        try {
            SwingUtilities.invokeLater(() -> {
                try { dialogs.edit(frame.getContentPane(), "규칙 만들기", "저장하고 적용", editor, () -> saved.set(editor.value())); finished.complete(null); }
                catch (Throwable e) { finished.completeExceptionally(e); }
            });
            JDialog dialog = awaitDialog();
            edt(() -> {
                setFontDeep(editor.component(), font); dialog.validate();
                find(dialog, "condition.value", JTextArea.class).setText("GET"); return null;
            });
            JButton add = edt(() -> find(dialog, "condition.addLeaf", JButton.class));
            click(add); awaitValueFocus(dialog);
            edt(() -> {
                for (Component action : add.getParent().getComponents())
                    assertTrue(action.getWidth() >= action.getPreferredSize().width, "condition action captions must not be clipped");
                return null;
            });
            edt(() -> {
                assertNull(saved.get(), "adding a condition edits the draft only");
                assertEquals(2, editor.value().condition().children().size());
                assertEquals(3, find(dialog, "condition.tree", JTree.class).getRowCount());
                find(dialog, "condition.field", JComboBox.class).setSelectedItem(Field.PATH);
                find(dialog, "condition.value", JTextArea.class).setText("/items");
                return null;
            });
            click(add); // New leaf is still selected: a second click must add a sibling, not silently disable.
            edt(() -> {
                find(dialog, "condition.field", JComboBox.class).setSelectedItem(Field.HEADER);
                find(dialog, "condition.selector", javax.swing.JTextField.class).setText("X-Operation");
                find(dialog, "condition.value", JTextArea.class).setText("review");
                assertNull(saved.get()); find(dialog, "condition.tree", JTree.class).setSelectionRow(0); return null;
            });
            click(edt(() -> find(dialog, groupKind.equals("AND") ? "condition.addAnd" : "condition.addOr", JButton.class)));
            awaitValueFocus(dialog);
            edt(() -> { find(dialog, "condition.value", JTextArea.class).setText("GET"); return null; });
            click(add);
            edt(() -> {
                find(dialog, "condition.value", JTextArea.class).setText("HEAD");
                dialog.setSize(640, Math.min(620, dialog.getHeight())); dialog.validate(); return null;
            });
            new Robot().waitForIdle();
            awaitActionBounds(add.getParent());
            edt(() -> {
                for (Component action : add.getParent().getComponents()) {
                    assertTrue(action.getX() >= 0 && action.getY() >= 0);
                    assertTrue(action.getX() + action.getWidth() <= add.getParent().getWidth());
                    assertTrue(action.getY() + action.getHeight() <= add.getParent().getHeight(), "wrapped actions must settle after one native resize without another user edit");
                }
                return null;
            });
            click(edt(() -> find(dialog, "editor.save", JButton.class)));
            finished.get(5, TimeUnit.SECONDS);
            Rule result = saved.get(); assertNotNull(result);
            assertEquals(Logic.AND, result.condition().logic()); assertEquals(4, result.condition().children().size());
            assertEquals("/items", result.condition().children().get(1).value());
            assertEquals("review", result.condition().children().get(2).value());
            assertEquals(Logic.valueOf(groupKind), result.condition().children().get(3).logic());
            assertEquals("GET", result.condition().children().get(3).children().getFirst().value());
            assertEquals("HEAD", result.condition().children().get(3).children().getLast().value());
            assertEquals(result, edt(() -> new RuleEditor(result).value()));
        } finally { edt(() -> { dialogs.closeEditors(); frame.dispose(); return null; }); }
    }
    private static void awaitActionBounds(Container parent) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < until) {
            if (edt(() -> {
                if (parent.getHeight() <= 0) return false;
                for (Component c : parent.getComponents())
                    if (c.getX() < 0 || c.getY() < 0 || c.getX() + c.getWidth() > parent.getWidth()
                            || c.getY() + c.getHeight() > parent.getHeight()) return false;
                return true;
            })) return;
            Thread.sleep(5); // Wait for native resize/revalidation, never request a second layout ourselves.
        }
        fail("wrapped action bounds did not settle after a native resize");
    }
    private static void awaitValueFocus(JDialog dialog) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < until) {
            if (edt(() -> find(dialog, "condition.value", JTextArea.class).isFocusOwner())) return;
            Thread.sleep(5);
        }
        fail("new condition value must receive real keyboard focus");
    }
    private static void click(JButton button) throws Exception {
        edt(() -> {
            assertTrue(button.isEnabled()); button.scrollRectToVisible(new Rectangle(0, 0, button.getWidth(), button.getHeight()));
            return null;
        });
        Robot robot = new Robot(); robot.setAutoDelay(30); robot.waitForIdle();
        Point point = stableButtonCenter(button);
        robot.mouseMove(point.x, point.y);
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK); robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK); robot.waitForIdle();
    }
    private static Point stableButtonCenter(JButton button) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        Rectangle previous = null;
        long stableSince = System.nanoTime();
        while (System.nanoTime() < until) {
            Rectangle bounds = edt(() -> {
                assertTrue(button.isShowing());
                return new Rectangle(button.getLocationOnScreen(), button.getSize());
            });
            long now = System.nanoTime();
            if (!bounds.equals(previous)) { previous = bounds; stableSince = now; }
            else if (now - stableSince >= TimeUnit.MILLISECONDS.toNanos(80))
                return new Point(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
            // Group-card switches and wrapped captions can move buttons after the first EDT pass.
            // Wait for the real click target, not for/retry the action or its focus assertion.
            Thread.sleep(10);
        }
        throw new AssertionError("condition action bounds did not settle before native click");
    }
    private static JDialog awaitDialog() throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            JDialog found = edt(() -> {
                for (Window w : Window.getWindows()) if (w instanceof JDialog d && d.isShowing() && "editor.dialog".equals(d.getName())) return d;
                return null;
            });
            if (found != null) return found;
            Thread.sleep(5);
        }
        throw new AssertionError("rule editor did not open on the isolated display");
    }
    private static void setFontDeep(Component component, int size) {
        component.setFont(component.getFont().deriveFont((float) size));
        if (component instanceof Container parent) for (Component child : parent.getComponents()) setFontDeep(child, size);
    }
    private static <T> T find(Component root, String name, Class<T> type) {
        if (name.equals(root.getName())) return type.cast(root);
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            T found = find(child, name, type); if (found != null) return found;
        }
        return null;
    }
    private static <T> T edt(Callable<T> task) throws Exception {
        AtomicReference<T> value = new AtomicReference<>(); AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> { try { value.set(task.call()); } catch (Throwable e) { failure.set(e); } });
        if (failure.get() instanceof Exception e) throw e;
        if (failure.get() instanceof Error e) throw e;
        return value.get();
    }
}
