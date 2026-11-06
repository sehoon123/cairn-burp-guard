package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry.Message;
import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.BooleanSupplier;

/** One owned view tree per inline/popout inspector; exports never read these inspection projections. */
@SuppressWarnings("serial")
final class TrafficInspector extends JPanel {
    final JTextArea request = viewer("traffic.request"), response = viewer("traffic.response"), metadata = viewer("traffic.metadata");
    private final JTextArea reason = viewer("traffic.reason");
    final JTabbedPane details = named(new JTabbedPane(), "traffic.details");
    final JTabbedPane responseTabs;
    private final JTextArea requestHeaders = viewer("traffic.request.headers"), requestBody = viewer("traffic.request.body");
    private final JTextArea responseHeaders = viewer("traffic.response.headers"), responseBody = viewer("traffic.response.body");
    private final JPanel preview = named(new JPanel(new BorderLayout()), "traffic.preview");
    private final JButton previous = named(new JButton("이전"), "traffic.previous"), next = named(new JButton("다음"), "traffic.next");
    private HtmlPreview.Projection installedPreview;
    private Content installedContent;
    record MessageView(String raw, String headers, String body) {}
    record Content(MessageView request, MessageView response) {}

    TrafficInspector(Runnable back, Runnable forward, Runnable previewChanged) {
        super(new BorderLayout(4, 4));
        previous.addActionListener(e -> back.run()); next.addActionListener(e -> forward.run());
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEADING, 4, 0)); actions.add(previous); actions.add(next);
        JLabel label = named(new JLabel("검사 사본 · synthetic first line / inspection projection, not original wire transcript"), "traffic.projectionNotice");
        actions.add(label);
        reason.setRows(1); reason.setLineWrap(true); reason.setWrapStyleWord(true);
        JPanel strip = new JPanel(new BorderLayout()); strip.add(actions, BorderLayout.NORTH); strip.add(new JScrollPane(reason), BorderLayout.CENTER);
        add(strip, BorderLayout.NORTH);
        JTabbedPane requestTabs = messageTabs("traffic.requestTabs", request, requestHeaders, requestBody);
        responseTabs = messageTabs("traffic.responseTabs", response, responseHeaders, responseBody);
        responseTabs.addTab("Static HTML preview", preview);
        responseTabs.addChangeListener(e -> previewChanged.run());
        JSplitPane pair = named(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, titled("요청", requestTabs), titled("응답", responseTabs)), "traffic.pair");
        pair.setResizeWeight(0.5); pair.setOneTouchExpandable(true); pair.setContinuousLayout(true);
        details.addTab("요청 · 응답", pair); details.addTab("결과와 메타데이터", new JScrollPane(metadata));
        details.addChangeListener(e -> previewChanged.run());
        add(details, BorderLayout.CENTER); setMinimumSize(new Dimension(80, 60));
        previewMessage("Select this tab to build a static inspection projection. " + HtmlPreview.LIMITS);
    }
    private static JPanel titled(String title, JComponent child) {
        JPanel p = new JPanel(new BorderLayout()); JLabel label = named(new JLabel(title), null); p.add(label, BorderLayout.NORTH); p.add(child, BorderLayout.CENTER); p.setMinimumSize(new Dimension(32, 32)); return p;
    }
    private static JTabbedPane messageTabs(String name, JTextArea raw, JTextArea headers, JTextArea body) {
        JTabbedPane tabs = named(new JTabbedPane(), name);
        tabs.addTab("Raw inspection", new JScrollPane(raw)); tabs.addTab("Headers", new JScrollPane(headers)); tabs.addTab("Body / HEX", new JScrollPane(body));
        tabs.setMinimumSize(new Dimension(32, 32)); return tabs;
    }
    boolean wantsPreview() { return responseTabs.getSelectedIndex() == 3 && details.getSelectedIndex() == 0; }
    void navigation(boolean back, boolean forward) { previous.setEnabled(back); next.setEnabled(forward); }
    void metadata(String text) { set(metadata, text); }
    void reason(String text) { set(reason, text); }
    void install(Content content) {
        if (installedContent == content) return;
        installedContent = content;
        set(request, content.request().raw()); set(requestHeaders, content.request().headers()); set(requestBody, content.request().body());
        set(response, content.response().raw()); set(responseHeaders, content.response().headers()); set(responseBody, content.response().body());
    }
    void preview(HtmlPreview.Projection projection) {
        if (installedPreview == projection) return;
        installedPreview = projection; clearPreview();
        JTextArea notice = viewer("traffic.preview.notice"); notice.setLineWrap(true); notice.setWrapStyleWord(true); notice.setText(HtmlPreview.LIMITS);
        notice.setRows(2); preview.add(notice, BorderLayout.NORTH); preview.add(new JScrollPane(HtmlPreview.component(projection)), BorderLayout.CENTER); preview.revalidate(); preview.repaint();
    }
    void previewMessage(String reason) {
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
    void clear(String reason) {
        installedContent = null;
        for (JTextArea area : List.of(request, response, metadata, this.reason, requestHeaders, requestBody, responseHeaders, responseBody)) set(area, "");
        previewMessage(reason); navigation(false, false);
    }
    void unavailable() {
        clear("원문 없음/지움/미수집 · No retained original; preview unavailable.");
        set(request, "[원문 없음/지움/미수집]"); set(response, "[원문 없음/지움/미수집]");
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
        append(raw, body, work); work.check(); return new MessageView(raw.toString(), headers.toString(), body);
    }
    private static void append(StringBuilder out, CharSequence text, TrafficSearch.Work work) { for (int i = 0; i < text.length(); i++) { work.unit(); out.append(text.charAt(i)); } }
    private static JTextArea viewer(String name) { JTextArea area = named(new JTextArea(6, 20), name); area.setEditable(false); area.setLineWrap(false); return area; }
    private static void set(JTextArea area, String value) { if (value.isEmpty() ? area.getDocument().getLength() != 0 : !area.getText().equals(value)) { area.setText(value); area.setCaretPosition(0); } }
    private static <T extends JComponent> T named(T component, String name) { component.setName(name); component.putClientProperty("html.disable", true); return component; }
}
