package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry.Message;
import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeListener;
import java.util.List;
import java.util.function.BooleanSupplier;

/** One owned view tree per inline/popout inspector; exports never read these inspection projections. */
@SuppressWarnings("serial")
final class TrafficInspector extends JPanel {
    final JTextArea request = viewer("traffic.request"), response = viewer("traffic.response"), metadata = viewer("traffic.metadata");
    private final JTextArea reason = viewer("traffic.reason");
    final JTabbedPane details = named(new JTabbedPane(), "traffic.details");
    final JTabbedPane requestTabs, responseTabs;
    private final JTextArea requestHeaders = viewer("traffic.request.headers"), requestBody = viewer("traffic.request.body");
    private final JTextArea responseHeaders = viewer("traffic.response.headers"), responseBody = viewer("traffic.response.body");
    private final JPanel preview = named(new JPanel(new BorderLayout()), "traffic.preview");
    private final JButton previous = named(new JButton("이전"), "traffic.previous"), next = named(new JButton("다음"), "traffic.next");
    private final JButton requestFind = named(new JButton("찾기 (Find)"), "traffic.request.find.open"), responseFind = named(new JButton("찾기 (Find)"), "traffic.response.find.open");
    private final Runnable reconcileSource;
    private HtmlPreview.Projection installedPreview;
    private Content installedContent;
    private boolean changingDisplay, closed;
    private enum Side { REQUEST, RESPONSE }
    private enum Field { RAW, HEADERS, BODY }
    private enum Step { FIRST, NEXT, PREVIOUS }
    private record Target(Side side, Field field, JTextArea area, JScrollPane tab) {}
    private record MessageView(String raw, String headers, String body, boolean present, String bodyEncoding) {}
    record Content(MessageView request, MessageView response) {}
    private record Binding(Target target, Document document, Content source) {}
    private record Found(int start, int end, boolean wrapped) {}
    private record Mark(Found found, Highlighter owner, Object tag) {}
    private record ScanInput(String text, String query, Step step, int currentStart) {}
    private final List<Target> targets;
    private final Find find = new Find();
    private final DocumentListener messageEdits = new DocumentListener() {
        @Override public void insertUpdate(DocumentEvent e) { messageEdited(); }
        @Override public void removeUpdate(DocumentEvent e) { messageEdited(); }
        @Override public void changedUpdate(DocumentEvent e) { messageEdited(); }
    };
    private final PropertyChangeListener messageDocument = e -> {
        if (!e.getPropertyName().equals("document")) return;
        Document old = (Document) e.getOldValue();
        old.removeDocumentListener(messageEdits);
        installedContent = null; find.retire();
        ((Document) e.getNewValue()).addDocumentListener(messageEdits); updateEntries();
    };
    private final FocusListener targetFocus = new FocusAdapter() {
        @Override public void focusGained(FocusEvent e) {
            if (find.active == null) return;
            for (Target target : targets) if (target.area() == e.getComponent()) { find.bind(target, false); return; }
            find.retire();
        }
    };
    private final ChangeListener tabChanged = e -> {
        updateEntries();
        if (find.active == null) return;
        Target active = find.active.target();
        if (details.getSelectedIndex() != 0) find.retire();
        else if (e.getSource() == tabs(active.side())) find.bind(selected(active.side()), false);
        else if (!visible(active)) find.retire();
    };
    private final HierarchyListener visibilityChanged = e -> {
        if ((e.getChangeFlags() & (HierarchyEvent.SHOWING_CHANGED | HierarchyEvent.PARENT_CHANGED)) != 0) {
            if (!isShowing()) find.retire();
            updateEntries();
        }
    };

    TrafficInspector(Runnable back, Runnable forward, Runnable previewChanged, Runnable reconcileSource) {
        super(new BorderLayout(4, 4));
        this.reconcileSource = reconcileSource;
        targets = List.of(target(Side.REQUEST, Field.RAW, request), target(Side.REQUEST, Field.HEADERS, requestHeaders), target(Side.REQUEST, Field.BODY, requestBody),
                target(Side.RESPONSE, Field.RAW, response), target(Side.RESPONSE, Field.HEADERS, responseHeaders), target(Side.RESPONSE, Field.BODY, responseBody));
        previous.addActionListener(e -> { if (!closed) back.run(); }); next.addActionListener(e -> { if (!closed) forward.run(); });
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEADING, 4, 0)); actions.add(previous); actions.add(next);
        JLabel label = named(new JLabel("검사 사본 · synthetic first line / inspection projection, not original wire transcript"), "traffic.projectionNotice");
        actions.add(label);
        reason.setRows(1); reason.setLineWrap(true); reason.setWrapStyleWord(true);
        JPanel strip = new JPanel(new BorderLayout()); strip.add(actions, BorderLayout.NORTH); strip.add(new JScrollPane(reason), BorderLayout.CENTER);
        add(strip, BorderLayout.NORTH);
        requestTabs = messageTabs(Side.REQUEST, "traffic.requestTabs");
        responseTabs = messageTabs(Side.RESPONSE, "traffic.responseTabs");
        responseTabs.addTab("Static HTML preview", preview);
        responseTabs.addChangeListener(e -> { if (!closed) previewChanged.run(); });
        JSplitPane pair = named(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, titled("요청", requestTabs, requestFind), titled("응답", responseTabs, responseFind)), "traffic.pair");
        pair.setResizeWeight(0.5); pair.setOneTouchExpandable(true); pair.setContinuousLayout(true);
        details.addTab("요청 · 응답", pair); details.addTab("결과와 메타데이터", new JScrollPane(metadata));
        details.addChangeListener(e -> { if (!closed) previewChanged.run(); });
        add(details, BorderLayout.CENTER); add(find.bar, BorderLayout.SOUTH); setMinimumSize(new Dimension(80, 60));
        requestTabs.addChangeListener(tabChanged); responseTabs.addChangeListener(tabChanged); details.addChangeListener(tabChanged);
        for (Target target : targets) {
            target.area().getDocument().addDocumentListener(messageEdits);
            target.area().addPropertyChangeListener("document", messageDocument);
            target.area().addFocusListener(targetFocus);
            action(target.area(), "traffic.find.open", () -> find.bind(target, true), KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK, InputEvent.META_DOWN_MASK);
            escape(target.area());
        }
        metadata.addFocusListener(targetFocus); reason.addFocusListener(targetFocus);
        requestFind.addActionListener(e -> find.bind(selected(Side.REQUEST), true)); responseFind.addActionListener(e -> find.bind(selected(Side.RESPONSE), true));
        for (JButton entry : List.of(requestFind, responseFind)) {
            entry.setDefaultCapable(false); entry.getAccessibleContext().setAccessibleName(entry == requestFind ? "Find in visible request field" : "Find in visible response field");
            action(entry, "traffic.find.launch", entry == requestFind ? () -> find.bind(selected(Side.REQUEST), true) : () -> find.bind(selected(Side.RESPONSE), true), KeyEvent.VK_ENTER, 0);
        }
        addHierarchyListener(visibilityChanged);
        previewMessage("Select this tab to build a static inspection projection. " + HtmlPreview.LIMITS); updateEntries();
    }
    private static Target target(Side side, Field field, JTextArea area) { return new Target(side, field, area, new JScrollPane(area)); }
    private static JPanel titled(String title, JComponent child, JButton entry) {
        JPanel p = new JPanel(new BorderLayout()); JPanel heading = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 4, 0));
        heading.add(named(new JLabel(title), null)); heading.add(entry); p.add(heading, BorderLayout.NORTH); p.add(child, BorderLayout.CENTER); p.setMinimumSize(new Dimension(32, 32)); return p;
    }
    private JTabbedPane messageTabs(Side side, String name) {
        JTabbedPane tabs = named(new JTabbedPane(), name);
        for (Target target : targets) if (target.side() == side) tabs.addTab(fieldLabel(target.field()), target.tab());
        tabs.setMinimumSize(new Dimension(32, 32)); return tabs;
    }
    private static String fieldLabel(Field field) { return switch (field) { case RAW -> "Raw inspection"; case HEADERS -> "Headers"; case BODY -> "Body / HEX"; }; }
    private JTabbedPane tabs(Side side) { return side == Side.REQUEST ? requestTabs : responseTabs; }
    private Target selected(Side side) { for (Target target : targets) if (target.side() == side && tabs(side).getSelectedComponent() == target.tab()) return target; return null; }
    private boolean visible(Target target) {
        if (target == null || details.getSelectedIndex() != 0 || tabs(target.side()).getSelectedComponent() != target.tab()) return false;
        for (Component component = this; component != null; component = component.getParent()) if (!component.isVisible()) return false;
        return true;
    }
    private boolean eligible(Content source, Target target) {
        if (source == null || target == null) return false;
        MessageView message = target.side() == Side.REQUEST ? source.request() : source.response();
        return message.present() && (target.field() != Field.BODY || !message.bodyEncoding().equals("UNAVAILABLE"));
    }
    private static String text(Content source, Target target) {
        MessageView message = target.side() == Side.REQUEST ? source.request() : source.response();
        return switch (target.field()) { case RAW -> message.raw(); case HEADERS -> message.headers(); case BODY -> message.body(); };
    }
    private void updateEntries() {
        if (targets == null) return;
        requestFind.setEnabled(!closed && visible(selected(Side.REQUEST)) && eligible(installedContent, selected(Side.REQUEST)));
        responseFind.setEnabled(!closed && visible(selected(Side.RESPONSE)) && eligible(installedContent, selected(Side.RESPONSE)));
    }
    private void messageEdited() {
        if (changingDisplay || closed) return;
        installedContent = null; find.retire(); updateEntries();
    }
    boolean wantsPreview() { return !closed && responseTabs.getSelectedIndex() == 3 && details.getSelectedIndex() == 0; }
    void navigation(boolean back, boolean forward) { if (!closed) { previous.setEnabled(back); next.setEnabled(forward); } }
    void metadata(String text) { if (!closed) set(metadata, text); }
    void reason(String text) { if (!closed) set(reason, text); }
    void install(Content content) {
        if (closed || installedContent == content) return;
        installedContent = null; find.retire(); changingDisplay = true;
        try {
            for (Target target : targets) set(target.area(), text(content, target));
            installedContent = content;
        } finally { changingDisplay = false; updateEntries(); }
    }
    void preview(HtmlPreview.Projection projection) {
        if (closed || installedPreview == projection) return;
        installedPreview = projection; clearPreview();
        JTextArea notice = viewer("traffic.preview.notice"); notice.setLineWrap(true); notice.setWrapStyleWord(true); notice.setText(HtmlPreview.LIMITS);
        notice.setRows(2); preview.add(notice, BorderLayout.NORTH); preview.add(new JScrollPane(HtmlPreview.component(projection)), BorderLayout.CENTER); preview.revalidate(); preview.repaint();
    }
    void previewMessage(String reason) {
        if (closed) return;
        installedPreview = null; clearPreview(); JTextArea area = viewer("traffic.preview.reason"); area.setLineWrap(true); area.setWrapStyleWord(true); area.setText(reason); preview.add(new JScrollPane(area), BorderLayout.CENTER); preview.revalidate(); preview.repaint();
    }
    private void clearPreview() {
        java.util.ArrayDeque<Component> pending = new java.util.ArrayDeque<>(); pending.add(preview);
        while (!pending.isEmpty()) {
            Component component = pending.removeFirst();
            if (component instanceof javax.swing.text.JTextComponent text) text.setText("");
            if (component instanceof Container container) for (Component child : container.getComponents()) pending.addLast(child);
        }
        preview.removeAll();
    }
    void clear(String reason) { if (!closed) clearOwned(reason); }
    private void clearOwned(String reason) {
        installedContent = null; find.retire(); changingDisplay = true;
        try { for (Target target : targets) set(target.area(), ""); set(metadata, ""); set(this.reason, ""); }
        finally { changingDisplay = false; }
        installedPreview = null; clearPreview();
        if (!closed) previewMessage(reason);
        previous.setEnabled(false); next.setEnabled(false); updateEntries();
    }
    void unavailable() {
        if (closed) return;
        clear("원문 없음/지움/미수집 · No retained original; preview unavailable.");
        changingDisplay = true;
        try { set(request, "[원문 없음/지움/미수집]"); set(response, "[원문 없음/지움/미수집]"); }
        finally { changingDisplay = false; }
    }
    boolean dismissFind() { if (find.active == null) return false; find.retire(); return true; }
    void close() {
        closed = true; clearOwned("");
        for (Target target : targets) {
            target.area().getDocument().removeDocumentListener(messageEdits); target.area().removePropertyChangeListener("document", messageDocument); target.area().removeFocusListener(targetFocus);
            removeKeys(target.area(), KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK, InputEvent.META_DOWN_MASK); removeKeys(target.area(), KeyEvent.VK_ESCAPE, 0);
            target.area().getActionMap().remove("traffic.find.open"); target.area().getActionMap().remove("traffic.find.escape");
        }
        metadata.removeFocusListener(targetFocus); reason.removeFocusListener(targetFocus);
        requestTabs.removeChangeListener(tabChanged); responseTabs.removeChangeListener(tabChanged); details.removeChangeListener(tabChanged); removeHierarchyListener(visibilityChanged);
        for (JButton entry : List.of(requestFind, responseFind)) { entry.setEnabled(false); for (ActionListener listener : entry.getActionListeners()) entry.removeActionListener(listener); removeKeys(entry, KeyEvent.VK_ENTER, 0); entry.getActionMap().remove("traffic.find.launch"); }
        find.close();
    }

    private final class Find {
        private final JPanel bar = named(new JPanel(new BorderLayout(4, 2)), "traffic.find.bar");
        private final JLabel targetLabel = named(new JLabel(), "traffic.find.target"), status = named(new JLabel(), "traffic.find.status");
        private final JTextArea query = named(ownedArea(1, 18), "traffic.find.query");
        private final JButton previous = named(new JButton("Previous occurrence"), "traffic.find.previous"), next = named(new JButton("Next occurrence"), "traffic.find.next"), close = named(new JButton("Close Find"), "traffic.find.close");
        private Binding active;
        private Mark marked;
        private long generation;
        private boolean pending, changingQuery;
        private TrafficSearch.Pump pump;
        private final DocumentListener edits = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { queryEdited(); }
            @Override public void removeUpdate(DocumentEvent e) { queryEdited(); }
            @Override public void changedUpdate(DocumentEvent e) { queryEdited(); }
        };
        private final PropertyChangeListener documentChanged = e -> {
            Document old = (Document) e.getOldValue(); old.removeDocumentListener(edits);
            retire(); ((Document) e.getNewValue()).addDocumentListener(edits);
        };
        Find() {
            query.getAccessibleContext().setAccessibleName("Literal occurrence query");
            JLabel label = named(new JLabel("Find literal"), "traffic.find.query.label"); label.setLabelFor(query);
            JPanel input = new JPanel(new BorderLayout(4, 0)); input.add(label, BorderLayout.WEST); input.add(new JScrollPane(query), BorderLayout.CENTER);
            JPanel actions = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 4, 2));
            for (JButton button : List.of(previous, next, close)) { button.setDefaultCapable(false); button.getAccessibleContext().setAccessibleName(button.getText()); actions.add(button); }
            actions.add(status); bar.add(targetLabel, BorderLayout.NORTH); bar.add(input, BorderLayout.CENTER); bar.add(actions, BorderLayout.SOUTH);
            targetLabel.getAccessibleContext().setAccessibleName("Selected Find target"); feedback("");
            previous.addActionListener(e -> step(Step.PREVIOUS)); next.addActionListener(e -> step(Step.NEXT)); close.addActionListener(e -> dismissFind());
            for (JComponent component : List.of(query, previous, next, close)) {
                action(component, "traffic.find.next", () -> step(Step.NEXT), KeyEvent.VK_ENTER, 0);
                action(component, "traffic.find.previous", () -> step(Step.PREVIOUS), KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK);
                escape(component);
            }
            query.getDocument().addDocumentListener(edits); query.addPropertyChangeListener("document", documentChanged);
            navigation(false); bar.setVisible(false);
        }
        private void bind(Target target, boolean focusQuery) {
            if (closed) return;
            if (!visible(target) || !eligible(installedContent, target)) { retire(); return; }
            if (active == null || active.target() != target || !valid(active)) {
                retire(); active = new Binding(target, target.area().getDocument(), installedContent);
                targetLabel.setText((target.side() == Side.REQUEST ? "Request" : "Response") + " · " + fieldLabel(target.field()) + (target.field() == Field.RAW ? " · display projection" : ""));
                bar.setVisible(true); bar.revalidate(); TrafficInspector.this.revalidate();
            }
            if (focusQuery) query.requestFocusInWindow();
        }
        private boolean valid(Binding expected) {
            return !closed && expected != null && active == expected && installedContent == expected.source()
                    && expected.document() == expected.target().area().getDocument() && visible(expected.target()) && eligible(installedContent, expected.target());
        }
        private boolean current(long submittedGeneration, Binding expected) { return generation == submittedGeneration && pending && valid(expected); }
        private void queryEdited() {
            if (changingQuery || closed) return;
            if (!valid(active)) { retire(); return; }
            submit(Step.FIRST, -1);
        }
        private void step(Step step) {
            if (closed || pending || marked == null || !valid(active)) return;
            submit(step, marked.found().start());
        }
        private void invalidate() {
            generation++; pending = false; if (pump != null) pump.cancel();
            if (marked != null) { marked.owner().removeHighlight(marked.tag()); marked = null; }
            navigation(false);
        }
        private void submit(Step step, int anchor) {
            invalidate();
            String needle = query.getText();
            if (needle.isEmpty()) { feedback(""); return; }
            // shortcut: snapshots mirror owner-installed unfiltered Documents, revisit if the renderer starts transforming text.
            ScanInput input = new ScanInput(text(installedContent, active.target()), needle, step, anchor);
            pending = true; feedback("Searching");
            if (pump == null) pump = new TrafficSearch.Pump("cairn-message-find");
            long version = generation;
            pump.submit(cancelled -> scan(input, cancelled), result -> accept(version, result));
        }
        private void accept(long version, TrafficSearch.Pump.Result result) {
            Binding expected = active;
            if (!current(version, expected)) return;
            reconcileSource.run();
            if (!current(version, expected)) return;
            pending = false;
            if (result.failed()) { feedback("Search failed"); navigation(false); return; }
            Found found = (Found) result.value();
            if (found == null) { feedback("No match"); navigation(false); return; }
            if (found.start() < 0 || found.end() <= found.start() || found.end() > expected.document().getLength()) { feedback("Search failed"); navigation(false); return; }
            JTextArea area = expected.target().area(); Highlighter highlighter = area.getHighlighter();
            try {
                Object tag = highlighter.addHighlight(found.start(), found.end(), new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 210, 80)));
                marked = new Mark(found, highlighter, tag);
                feedback(found.wrapped() ? "Found · wrapped" : "Found"); navigation(true);
                java.awt.geom.Rectangle2D rectangle = area.modelToView2D(found.start());
                if (rectangle != null) area.scrollRectToVisible(rectangle.getBounds());
            } catch (BadLocationException failure) { feedback("Search failed"); navigation(false); }
        }
        private void navigation(boolean enabled) {
            if (!enabled && (previous.isFocusOwner() || next.isFocusOwner())) query.requestFocusInWindow();
            previous.setEnabled(enabled); next.setEnabled(enabled);
        }
        private void feedback(String text) { status.setText(text); status.getAccessibleContext().setAccessibleName(text.isEmpty() ? "Find status" : text); }
        private void retire() {
            active = null; invalidate(); changingQuery = true;
            try { query.setText(""); } finally { changingQuery = false; }
            feedback(""); targetLabel.setText(""); bar.setVisible(false); TrafficInspector.this.revalidate();
        }
        private void close() {
            query.getDocument().removeDocumentListener(edits); query.removePropertyChangeListener("document", documentChanged);
            for (JComponent component : List.of(query, previous, next, close)) {
                removeKeys(component, KeyEvent.VK_ENTER, 0, InputEvent.SHIFT_DOWN_MASK); removeKeys(component, KeyEvent.VK_ESCAPE, 0);
                for (String name : List.of("traffic.find.next", "traffic.find.previous", "traffic.find.escape", "traffic.find.release")) component.getActionMap().remove(name);
                component.setEnabled(false);
            }
            for (JButton button : List.of(previous, next, close)) for (ActionListener listener : button.getActionListeners()) button.removeActionListener(listener);
            if (pump != null) pump.close();
        }
    }
    private void escape(JComponent component) { action(component, "traffic.find.escape", this::dismissFind, KeyEvent.VK_ESCAPE, 0); }
    private static void action(JComponent component, String name, Runnable run, int key, int... modifiers) {
        component.getActionMap().put(name, new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { run.run(); } });
        component.getActionMap().put("traffic.find.release", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { } });
        for (int modifier : modifiers) {
            component.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key, modifier), name);
            component.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key, modifier, true), "traffic.find.release");
        }
    }
    private static void removeKeys(JComponent component, int key, int... modifiers) {
        for (int modifier : modifiers) { component.getInputMap(JComponent.WHEN_FOCUSED).remove(KeyStroke.getKeyStroke(key, modifier)); component.getInputMap(JComponent.WHEN_FOCUSED).remove(KeyStroke.getKeyStroke(key, modifier, true)); }
    }
    private static void blank(Document document) { try { document.remove(0, document.getLength()); } catch (BadLocationException failure) { throw new IllegalStateException(failure); } }
    private static Found scan(ScanInput input, BooleanSupplier cancelled) {
        TrafficSearch.Work work = new TrafficSearch.Work(cancelled); work.check();
        int last = input.text().length() - input.query().length();
        if (last < 0) { work.check(); return null; }
        if (input.step() == Step.FIRST) return scanRange(input, work, 0, last, 1, false);
        Found found = input.step() == Step.NEXT ? scanRange(input, work, input.currentStart() + 1, last, 1, false)
                : scanRange(input, work, input.currentStart() - 1, 0, -1, false);
        if (found != null) { work.check(); return found; }
        return input.step() == Step.NEXT ? scanRange(input, work, 0, input.currentStart(), 1, true)
                : scanRange(input, work, last, input.currentStart(), -1, true);
    }
    private static Found scanRange(ScanInput input, TrafficSearch.Work work, int first, int last, int direction, boolean wrapped) {
        work.check();
        for (int start = first; direction > 0 ? start <= last : start >= last; start += direction) {
            int offset = 0;
            while (offset < input.query().length()) { work.unit(); if (input.text().charAt(start + offset) != input.query().charAt(offset)) break; offset++; }
            if (offset == input.query().length()) { work.check(); return new Found(start, start + offset, wrapped); }
        }
        work.check(); return null;
    }
    static Content project(Message request, Message response, String firstRequest, String firstResponse, BooleanSupplier cancelled) {
        TrafficSearch.Work work = new TrafficSearch.Work(cancelled);
        return new Content(project(request, firstRequest, work), project(response, firstResponse, work));
    }
    private static MessageView project(Message message, String first, TrafficSearch.Work work) {
        StringBuilder headers = new StringBuilder();
        for (var h : message.headers()) { append(headers, String.valueOf(h.name()), work); headers.append(": "); append(headers, String.valueOf(h.value()), work); headers.append('\n'); }
        String flags = "평문 원문 · 민감정보 포함 · synthetic first line / inspection projection, not original wire transcript\n"
                + "present=" + message.present() + " · omitted=" + message.bodyOmitted() + " · incomplete=" + message.truncated() + " · display=" + message.bodyEncoding() + "\n";
        String body = message.bodyEncoding().equals("UNAVAILABLE") ? "[원문 없음 / body unavailable]" : message.body();
        StringBuilder raw = new StringBuilder(flags); append(raw, first, work); raw.append('\n'); append(raw, headers, work); raw.append('\n');
        if (message.bodyEncoding().equals("HEX")) raw.append("[HEX: contiguous retained bytes; no charset guessing]\n");
        append(raw, body, work); work.check(); return new MessageView(raw.toString(), headers.toString(), body, message.present(), message.bodyEncoding());
    }
    private static void append(StringBuilder out, CharSequence text, TrafficSearch.Work work) { for (int i = 0; i < text.length(); i++) { work.unit(); out.append(text.charAt(i)); } }
    private static JTextArea ownedArea(int rows, int columns) {
        return new JTextArea(rows, columns) {
            @Override public void setDocument(Document document) {
                Document old = getDocument();
                super.setDocument(document);
                // Swing holds the old Document's read lock during the property notification.
                if (old != null && old != document) blank(old);
            }
        };
    }
    private static JTextArea viewer(String name) { JTextArea area = named(ownedArea(6, 20), name); area.setEditable(false); area.setLineWrap(false); return area; }
    private static void set(JTextArea area, String value) { if (value.isEmpty() ? area.getDocument().getLength() != 0 : !area.getText().equals(value)) { area.setText(value); area.setCaretPosition(0); } }
    private static <T extends JComponent> T named(T component, String name) { component.setName(name); component.putClientProperty("html.disable", true); return component; }
}
