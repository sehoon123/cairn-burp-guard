package dev.cairnguard.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.awt.event.WindowEvent;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real native-window Swing tests, intentionally excluded from headless tests. NOT a Burp run. */
@Tag("desktop") @Timeout(20)
class MessageDialogDesktopTest {
    private static final String MESSAGE = "모두 통과 전 확인\n\n" + "보호 범위와 승인·속도 제한을 적용하지 않습니다.\n".repeat(45) + "마지막 경고까지 확인";

    @ParameterizedTest @CsvSource({"14,CANCEL", "28,CANCEL", "14,DEFAULT", "28,DEFAULT", "14,ESCAPE", "28,ESCAPE",
            "14,CLOSE_OWNED", "28,CLOSE_OWNED", "14,WINDOW", "28,WINDOW", "14,CONFIRM", "28,CONFIRM", "14,KEYBOARD_CONFIRM", "28,KEYBOARD_CONFIRM"})
    void realModalWrapsScrollsResizesAndOnlyExplicitConfirmAccepts(int font, String exit) throws Exception {
        Object labelFont = UIManager.get("Label.font"), buttonFont = UIManager.get("Button.font");
        GuardPanel.SwingDialogs dialogs = new GuardPanel.SwingDialogs();
        JFrame frame = edt(() -> {
            UIManager.put("Label.font", new Font(Font.DIALOG, Font.PLAIN, font));
            UIManager.put("Button.font", new Font(Font.DIALOG, Font.PLAIN, font));
            JFrame parent = new JFrame("Synthetic isolated dialog tests");
            parent.setSize(800, 500); parent.setLocation(10, 10); parent.setVisible(true); return parent;
        });
        CompletableFuture<Boolean> result = new CompletableFuture<>();
        try {
            SwingUtilities.invokeLater(() -> {
                try { result.complete(dialogs.confirm(frame.getContentPane(), MESSAGE, "모두 통과")); }
                catch (Throwable e) { result.completeExceptionally(e); }
            });
            JDialog dialog = awaitDialog();
            edt(() -> {
                assertTrue(dialog.isModal()); assertTrue(dialog.isResizable());
                assertEquals("dialog.cancel", dialog.getRootPane().getDefaultButton().getName());
                Rectangle screen = new Rectangle(dialog.getGraphicsConfiguration().getBounds());
                var insets = java.awt.Toolkit.getDefaultToolkit().getScreenInsets(dialog.getGraphicsConfiguration());
                screen.x += insets.left; screen.y += insets.top;
                screen.width -= insets.left + insets.right; screen.height -= insets.top + insets.bottom;
                assertTrue(screen.contains(dialog.getBounds()), "initial packed size and placement must fit the work area");
                dialog.setSize(360, 260); dialog.validate(); return null;
            });
            awaitTextLayout(dialog);
            edt(() -> {
                JTextArea body = find(dialog, "dialog.body", JTextArea.class);
                JScrollPane scroll = find(dialog, "dialog.scroll", JScrollPane.class);
                assertEquals(MESSAGE, body.getText()); assertEquals(font, body.getFont().getSize());
                assertTrue(scroll.getVerticalScrollBar().isVisible());
                scroll.getVerticalScrollBar().setValue(scroll.getVerticalScrollBar().getMaximum());
                return null;
            });
            edt(() -> {
                JTextArea body = find(dialog, "dialog.body", JTextArea.class);
                JScrollPane scroll = find(dialog, "dialog.scroll", JScrollPane.class);
                Rectangle last = body.modelToView2D(body.getDocument().getLength()).getBounds();
                Rectangle visible = scroll.getViewport().getViewRect();
                assertTrue(last.y >= visible.y && last.y + last.height <= visible.y + visible.height + 2,
                        () -> "last message line reachable " + last + " in " + visible);
                for (String name : new String[]{"dialog.cancel", "dialog.confirm"}) {
                    JButton button = find(dialog, name, JButton.class);
                    Rectangle bounds = SwingUtilities.convertRectangle(button.getParent(), button.getBounds(), dialog.getContentPane());
                    assertTrue(bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= dialog.getContentPane().getWidth()
                            && bounds.y + bounds.height <= dialog.getContentPane().getHeight());
                }
                switch (exit) {
                    case "CANCEL" -> find(dialog, "dialog.cancel", JButton.class).doClick(0);
                    case "DEFAULT", "ESCAPE", "KEYBOARD_CONFIRM" -> { /* Real Robot key events below, off EDT. */ }
                    case "CLOSE_OWNED" -> dialogs.closeEditors();
                    case "WINDOW" -> dialog.dispatchEvent(new WindowEvent(dialog, WindowEvent.WINDOW_CLOSING));
                    case "CONFIRM" -> find(dialog, "dialog.confirm", JButton.class).doClick(0);
                    default -> fail(exit);
                }
                return null;
            });
            if (exit.equals("DEFAULT") || exit.equals("ESCAPE") || exit.equals("KEYBOARD_CONFIRM")) {
                java.awt.Robot robot = new java.awt.Robot(); robot.setAutoDelay(30);
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (!edt(() -> java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusedWindow() == dialog)
                        && System.nanoTime() < until) Thread.sleep(10);
                assertTrue(edt(() -> java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusedWindow() == dialog));
                int key = exit.equals("ESCAPE") ? KeyEvent.VK_ESCAPE : KeyEvent.VK_ENTER;
                if (exit.equals("KEYBOARD_CONFIRM")) {
                    JButton confirm = edt(() -> find(dialog, "dialog.confirm", JButton.class));
                    for (int i = 0; i < 10 && !edt(confirm::isFocusOwner); i++) {
                        robot.keyPress(KeyEvent.VK_TAB); robot.keyRelease(KeyEvent.VK_TAB); robot.waitForIdle();
                    }
                    assertTrue(edt(confirm::isFocusOwner), "affirmative action must be keyboard reachable without a mouse");
                    key = KeyEvent.VK_SPACE; // Explicit focused-button activation, not an accidental initial Enter.
                }
                robot.keyPress(key); robot.keyRelease(key); robot.waitForIdle();
            }
            assertEquals(exit.equals("CONFIRM") || exit.equals("KEYBOARD_CONFIRM"), result.get(5, TimeUnit.SECONDS));
            assertFalse(edt(dialog::isShowing));
        } finally {
            edt(() -> { dialogs.closeEditors(); frame.dispose(); UIManager.put("Label.font", labelFont); UIManager.put("Button.font", buttonFont); return null; });
        }
    }

    @ParameterizedTest @ValueSource(ints = {14, 28})
    void realErrorModalIsScrollableAndIncludedInOwnedWindowCleanup(int font) throws Exception {
        GuardPanel.SwingDialogs dialogs = new GuardPanel.SwingDialogs();
        JFrame frame = edt(() -> { JFrame parent = new JFrame("Synthetic error dialog tests"); parent.setSize(640, 400); parent.setVisible(true); return parent; });
        CompletableFuture<Void> result = new CompletableFuture<>();
        try {
            SwingUtilities.invokeLater(() -> { try { dialogs.error(frame.getContentPane(), MESSAGE); result.complete(null); } catch (Throwable e) { result.completeExceptionally(e); } });
            JDialog dialog = awaitDialog();
            edt(() -> {
                find(dialog, "dialog.body", JTextArea.class).setFont(new Font(Font.DIALOG, Font.PLAIN, font));
                dialog.setSize(360, 260); dialog.validate(); return null;
            });
            edt(() -> {
                assertTrue(find(dialog, "dialog.scroll", JScrollPane.class).getVerticalScrollBar().isVisible());
                assertEquals("dialog.close", dialog.getRootPane().getDefaultButton().getName());
                dialogs.closeEditors(); return null;
            });
            result.get(5, TimeUnit.SECONDS);
            assertFalse(edt(dialog::isShowing));
        } finally { edt(() -> { dialogs.closeEditors(); frame.dispose(); return null; }); }
    }

    private static void awaitTextLayout(JDialog dialog) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < until) {
            if (edt(() -> {
                JTextArea body = find(dialog, "dialog.body", JTextArea.class);
                JScrollPane scroll = find(dialog, "dialog.scroll", JScrollPane.class);
                var end = body.modelToView2D(body.getDocument().getLength()).getBounds();
                return end.y + end.height <= scroll.getVerticalScrollBar().getMaximum() + 1;
            })) return;
            Thread.sleep(5); // Native resize/paint and wrapped-view revalidation are asynchronous.
        }
        fail("wrapped text scroll model did not settle after native resize");
    }

    private static JDialog awaitDialog() throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            JDialog found = edt(() -> {
                for (Window window : Window.getWindows()) if (window instanceof JDialog dialog && window.isShowing() && "message.dialog".equals(window.getName())) return dialog;
                return null;
            });
            if (found != null) return found;
            Thread.sleep(5);
        }
        throw new AssertionError("isolated message dialog did not open");
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
