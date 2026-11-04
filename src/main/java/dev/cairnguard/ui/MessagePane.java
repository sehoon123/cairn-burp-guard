package dev.cairnguard.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.text.DefaultCaret;

/** Plain, selectable, wrapping message with real scrolling; actions never scroll with the body. */
@SuppressWarnings("serial")
final class MessagePane extends JPanel {
    private final JTextArea body;
    private final JPanel footer;
    private final JScrollPane scroll;

    MessagePane(String message, JButton... actions) {
        super(new BorderLayout(10, 10));
        setName("dialog.message");
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        body = new JTextArea(message, 9, 48);
        body.setName("dialog.body"); body.setEditable(false);
        body.setLineWrap(true); body.setWrapStyleWord(true);
        body.putClientProperty("html.disable", Boolean.TRUE);
        Font font = UIManager.getFont("Label.font");
        if (font != null) body.setFont(font);
        ((DefaultCaret) body.getCaret()).setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        body.setCaretPosition(0);
        body.getAccessibleContext().setAccessibleName("확인할 내용");
        body.getAccessibleContext().setAccessibleDescription("전체 내용을 스크롤하거나 선택하여 복사할 수 있습니다.");
        scroll = new JScrollPane(body, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setName("dialog.scroll"); scroll.setMinimumSize(new Dimension(0, 0));
        add(scroll, BorderLayout.CENTER);
        footer = new JPanel(new WrappingFlowLayout(FlowLayout.TRAILING, 6, 3));
        footer.setName("dialog.actions");
        for (JButton action : actions) footer.add(action);
        add(footer, BorderLayout.SOUTH);
    }

    /** Measure wrapped content after bounded initial pack; show more than a fixed nine-line slice. */
    int heightForWidth(int width) {
        body.setRows(0);
        var outer = getInsets(); var border = scroll.getInsets(); var textInsets = body.getInsets();
        int textWidth = Math.max(1, width - outer.left - outer.right - border.left - border.right
                - scroll.getVerticalScrollBar().getPreferredSize().width - textInsets.left - textInsets.right);
        var view = body.getUI().getRootView(body);
        view.setSize(textWidth, Float.MAX_VALUE);
        long textHeight = (long) Math.ceil(view.getPreferredSpan(javax.swing.text.View.Y_AXIS)) + textInsets.top + textInsets.bottom;
        return (int) Math.min(Integer.MAX_VALUE, textHeight + border.top + border.bottom
                + footer.getPreferredSize().height + outer.top + outer.bottom + ((BorderLayout) getLayout()).getVgap());
    }
}
