package dev.cairnguard.ui.editor;

/** A deliberately authored, actionable Korean form message. Never include request/secret/exception text. */
public final class FormValidationException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;
    public FormValidationException(String userMessage) { super(userMessage); }
}
