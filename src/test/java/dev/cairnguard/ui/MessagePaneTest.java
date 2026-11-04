package dev.cairnguard.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Rectangle;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.RepaintManager;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/** Headless layout/scroll regressions only; real JDialog lifecycle is covered separately. */
class MessagePaneTest {
    @ParameterizedTest @CsvSource({"320,220,14", "360,260,28", "640,360,28", "760,520,14", "360,300,14", "520,260,28"})
    void longKoreanAndUnbrokenPlainTextCanReachItsLastLineWithoutHidingActions(int width, int height, int font) throws Exception {
        onEdt(() -> {
            JButton cancel = new JButton("취소"), confirm = new JButton("모두 통과");
            String message = "<html>는 표시할 일반 문자열입니다.\n\n" + "확인해야 하는 긴 한국어 경고와 연결된 URL입니다. ".repeat(100)
                    + "\n" + "synthetic-long-token-".repeat(100) + "\n마지막 경고까지 확인";
            MessagePane pane = new MessagePane(message, cancel, confirm);
            setFonts(pane, new Font(Font.DIALOG, Font.PLAIN, font));
            pane.setSize(width, height); layout(pane); layout(pane);
            // Non-displayable headless components have no repaint/validation event loop.
            // Painting lays out WrappedPlainView at its final post-scrollbar viewport width.
            var image = new java.awt.image.BufferedImage(width, height, java.awt.image.BufferedImage.TYPE_INT_ARGB);
            var graphics = image.createGraphics();
            try { pane.paint(graphics); } finally { graphics.dispose(); }
            layout(pane); layout(pane);
            JScrollPane scroll = find(pane, "dialog.scroll", JScrollPane.class);
            JTextArea body = find(pane, "dialog.body", JTextArea.class);
            assertEquals(message, body.getText()); assertFalse(body.isEditable()); assertTrue(body.isFocusable());
            assertTrue(body.getLineWrap()); assertTrue(body.getWrapStyleWord());
            assertEquals(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER, scroll.getHorizontalScrollBarPolicy());
            assertTrue(scroll.getVerticalScrollBar().isVisible());
            assertTrue(scroll.getViewport().getExtentSize().height > 20);
            assertEquals(scroll.getViewport().getExtentSize().width, body.getWidth());
            assertTrue(scroll.getVerticalScrollBar().getMaximum() > scroll.getVerticalScrollBar().getVisibleAmount());
            scroll.getVerticalScrollBar().setValue(scroll.getVerticalScrollBar().getMaximum());
            Rectangle end = body.modelToView2D(body.getDocument().getLength()).getBounds();
            Rectangle visible = scroll.getViewport().getViewRect();
            assertTrue(end.y >= visible.y && end.y + end.height <= visible.y + visible.height + 2,
                    () -> "last line must be reachable: end=" + end + " visible=" + visible);
            for (JButton button : new JButton[]{cancel, confirm}) {
                Rectangle bounds = SwingUtilities.convertRectangle(button.getParent(), button.getBounds(), pane);
                assertTrue(bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= width && bounds.y + bounds.height <= height,
                        () -> "visible action " + bounds);
                assertTrue(button.getWidth() >= button.getPreferredSize().width);
            }
        });
    }

    @Test void actionRowsGrowTheirPreferredHeightWhenTheWindowNarrowsOrFontsGrow() throws Exception {
        onEdt(() -> {
            JPanel parent = new JPanel(); parent.setSize(360, 500);
            JPanel buttons = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 6, 3));
            for (int i = 0; i < 4; i++) buttons.add(new JButton("조작 버튼 " + i));
            parent.add(buttons);
            buttons.setSize(900, 50); // Stale width from before the window shrank.
            Dimension small = buttons.getPreferredSize();
            assertTrue(small.height > buttons.getComponent(0).getPreferredSize().height + 6);
            buttons.setSize(350, small.height); buttons.doLayout();
            for (Component child : buttons.getComponents()) assertTrue(child.getY() + child.getHeight() <= buttons.getHeight());
            setFonts(buttons, new Font(Font.DIALOG, Font.PLAIN, 28));
            Dimension largeFont = buttons.getPreferredSize();
            assertTrue(largeFont.height > small.height);
            buttons.setSize(350, largeFont.height); buttons.doLayout();
            for (Component child : buttons.getComponents()) assertTrue(child.getY() + child.getHeight() <= buttons.getHeight());
        });
    }

    @Test void lineEndToolbarUnwrapsAgainAfterNarrowThenWideResize() throws Exception {
        onEdt(() -> {
            JPanel parent = new JPanel(new java.awt.BorderLayout());
            JPanel actions = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 6, 3));
            for (int i = 0; i < 3; i++) actions.add(new JButton("조작 " + i));
            parent.add(new javax.swing.JTextField(), java.awt.BorderLayout.CENTER);
            parent.add(actions, java.awt.BorderLayout.LINE_END);
            parent.setSize(1400, 300); layout(parent); layout(parent);
            Dimension wide = actions.getPreferredSize();
            parent.setSize(160, 300); layout(parent); layout(parent);
            assertTrue(actions.getPreferredSize().height > wide.height);
            parent.setSize(1400, 300); layout(parent); layout(parent);
            assertEquals(wide, actions.getPreferredSize(), "a LINE_END child must not keep its own narrow preferred width forever");
        });
    }

    @Test void parentRevalidationRunsAfterTheLayoutPassAndOnlyOnceForTheSameWidth() throws Exception {
        var revalidations = new java.util.concurrent.atomic.AtomicInteger();
        onEdt(() -> {
            JPanel parent = new JPanel() {
                @Override public void revalidate() { revalidations.incrementAndGet(); }
            };
            JPanel buttons = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 4, 4)) {
                @Override public boolean isDisplayable() { return true; }
            };
            buttons.add(new JButton("Synthetic action")); parent.add(buttons);
            buttons.setSize(500, 100); revalidations.set(0);
            buttons.doLayout(); buttons.doLayout();
            assertEquals(0, revalidations.get(), "do not revalidate the parent inside its ongoing validation pass");
        });
        onEdt(() -> assertEquals(1, revalidations.get(), "one deferred revalidation per actual width change"));
    }

    @ParameterizedTest @CsvSource({"14", "28"})
    void wrappedFooterSettlesAfterOneResizeWithoutIncidentalViewportEvents(int font) throws Exception {
        AtomicReference<RepaintManager> previous = new AtomicReference<>();
        AtomicReference<JPanel> root = new AtomicReference<>(), actions = new AtomicReference<>();
        try {
            onEdt(() -> {
                previous.set(RepaintManager.currentManager(new JPanel()));
                // Match Swing's deferred validate-root contract without native windows or scroll panes.
                RepaintManager.setCurrentManager(new RepaintManager() {
                    @Override public synchronized void addInvalidComponent(javax.swing.JComponent component) {
                        Container validateRoot = component;
                        while (validateRoot.getParent() != null && !validateRoot.isValidateRoot())
                            validateRoot = validateRoot.getParent();
                        Container target = validateRoot;
                        SwingUtilities.invokeLater(target::validate);
                    }
                });
                JPanel buttons = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 4, 4));
                for (int i = 0; i < 6; i++) buttons.add(new JButton("Synthetic action " + i));
                setFonts(buttons, new Font(Font.DIALOG, Font.PLAIN, font));
                JPanel commands = new JPanel(new java.awt.BorderLayout());
                commands.add(buttons, java.awt.BorderLayout.CENTER);
                JPanel parent = new JPanel(new java.awt.BorderLayout());
                parent.add(new JPanel(), java.awt.BorderLayout.CENTER);
                parent.add(commands, java.awt.BorderLayout.SOUTH);
                root.set(parent); actions.set(buttons);
                parent.addNotify(); parent.setSize(1400, 600); parent.validate();
            });
            for (int i = 0; i < 8; i++) onEdt(() -> {});
            onEdt(() -> {
                actions.get().getPreferredSize(); // Prime the cached measurement, as real layouts/painting do.
                root.get().setSize(500, 600); root.get().validate();
            });
            // Observe queued validation only: no second resize, user edit or manual relayout.
            for (int i = 0; i < 8; i++) onEdt(() -> {});
            onEdt(() -> {
                JPanel buttons = actions.get();
                assertTrue(buttons.getPreferredSize().height > buttons.getComponent(0).getPreferredSize().height + 8);
                for (Component child : buttons.getComponents())
                    assertTrue(child.getY() >= 0 && child.getY() + child.getHeight() <= buttons.getHeight(),
                            "footer must settle after validation completes, not rely on a viewport resize event");
            });
        } finally {
            onEdt(() -> {
                if (root.get() != null) root.get().removeNotify();
                if (previous.get() != null) RepaintManager.setCurrentManager(previous.get());
            });
        }
    }

    private static void setFonts(Component component, Font font) {
        component.setFont(font);
        if (component instanceof Container parent) for (Component child : parent.getComponents()) setFonts(child, font);
    }
    private static void layout(Container parent) {
        parent.doLayout();
        for (Component child : parent.getComponents()) if (child instanceof Container nested) layout(nested);
    }
    private static <T> T find(Component root, String name, Class<T> type) {
        if (name.equals(root.getName())) return type.cast(root);
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            T found = find(child, name, type); if (found != null) return found;
        }
        return null;
    }
    private static void onEdt(Checked task) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> { try { task.run(); } catch (Throwable e) { failure.set(e); } });
        if (failure.get() instanceof Exception e) throw e;
        if (failure.get() instanceof Error e) throw e;
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
}
