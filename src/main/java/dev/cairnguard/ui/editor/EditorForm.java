package dev.cairnguard.ui.editor;

import javax.swing.JComponent;

/** Human modal form, not an API exposed to agents. Implementations are EDT-only. */
public interface EditorForm<T> {
    JComponent component();
    /** Return a validated immutable value. Never silently widen scope or discard loaded conditions. */
    T value();
}
