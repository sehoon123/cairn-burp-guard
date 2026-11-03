package dev.cairnguard.ui;

import java.awt.Rectangle;
import javax.swing.text.DefaultCaret;

/** Read-only wrapping guidance must not scroll its ancestor form when its document changes. */
public final class NonScrollingCaret extends DefaultCaret {
    private static final long serialVersionUID = 1L;
    public NonScrollingCaret() { setUpdatePolicy(NEVER_UPDATE); }
    @Override protected void adjustVisibility(Rectangle rectangle) {
        // Preserve selection/copy support, but leave scrolling to the human and the enclosing viewport.
    }
}
