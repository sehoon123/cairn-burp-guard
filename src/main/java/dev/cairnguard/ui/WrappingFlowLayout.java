package dev.cairnguard.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

/** FlowLayout whose preferred HEIGHT includes wrapped rows, including while its window shrinks. */
@SuppressWarnings("serial")
public final class WrappingFlowLayout extends FlowLayout {
    public WrappingFlowLayout(int alignment, int hgap, int vgap) { super(alignment, hgap, vgap); }

    @Override public Dimension preferredLayoutSize(Container target) { return size(target, false); }
    @Override public Dimension minimumLayoutSize(Container target) { return size(target, true); }

    private static final String WIDTH_KEY = WrappingFlowLayout.class.getName() + ".lastLayoutWidth";
    @Override public void layoutContainer(Container target) {
        super.layoutContainer(target);
        if (target instanceof javax.swing.JComponent panel) {
            Integer width = panel.getWidth();
            if (!width.equals(panel.getClientProperty(WIDTH_KEY))) {
                panel.putClientProperty(WIDTH_KEY, width);
                // The parent may still cache the pre-resize row height. Queue its invalidation
                // AFTER this validation pass, which otherwise marks the ancestors valid again.
                // Width deduplication and stale-parent/width checks prevent relayout loops.
                if (panel.isDisplayable() && panel.getParent() instanceof javax.swing.JComponent parent) {
                    panel.invalidate();
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        if (panel.isDisplayable() && panel.getParent() == parent && panel.getWidth() == width)
                            parent.revalidate();
                    });
                }
            }
        }
    }

    private Dimension size(Container target, boolean minimum) {
        synchronized (target.getTreeLock()) {
            Container parent = target.getParent();
            Object constraint = parent != null && parent.getLayout() instanceof java.awt.BorderLayout border
                    ? border.getConstraints(target) : null;
            boolean widthFromPreference = java.awt.BorderLayout.EAST.equals(constraint) || java.awt.BorderLayout.WEST.equals(constraint)
                    || java.awt.BorderLayout.LINE_START.equals(constraint) || java.awt.BorderLayout.LINE_END.equals(constraint);
            // Sidebars get their width FROM this preferred size; seeding with their old width
            // creates a narrow->wide ratchet. Stretched/explicitly constrained panels still need
            // their actual width, which can be smaller than their parent's width.
            int width = !widthFromPreference && target.getWidth() > 0 ? target.getWidth() : Integer.MAX_VALUE;
            // Use the tightest known ancestor too: the child can still have its OLD width during
            // BorderLayout's first pass after resize. No cached pixel/font measurements.
            for (Container c = target.getParent(); c != null; c = c.getParent()) {
                Insets insets = c.getInsets();
                int available = c.getWidth() - insets.left - insets.right;
                if (available > 0) width = Math.min(width, available);
            }
            Insets insets = target.getInsets();
            int available = Math.max(1, width - insets.left - insets.right - getHgap() * 2);
            int rowWidth = 0, rowHeight = 0, contentWidth = 0, contentHeight = 0;
            for (Component child : target.getComponents()) {
                if (!child.isVisible()) continue;
                Dimension d = minimum ? child.getMinimumSize() : child.getPreferredSize();
                int gap = rowWidth == 0 ? 0 : getHgap();
                if (rowWidth > 0 && (long) rowWidth + gap + d.width > available) {
                    contentWidth = Math.max(contentWidth, rowWidth);
                    contentHeight += rowHeight + getVgap();
                    rowWidth = 0; rowHeight = 0; gap = 0;
                }
                rowWidth += gap + d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }
            contentWidth = Math.max(contentWidth, rowWidth);
            contentHeight += rowHeight;
            return new Dimension(contentWidth + insets.left + insets.right + getHgap() * 2,
                    contentHeight + insets.top + insets.bottom + getVgap() * 2);
        }
    }
}
