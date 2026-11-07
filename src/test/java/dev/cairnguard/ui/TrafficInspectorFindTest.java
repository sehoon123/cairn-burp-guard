package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.evidence.TrafficEntry.Message;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.RequestData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.text.*;
import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;
import static org.junit.jupiter.api.Assertions.*;

/** Selected display copies and in-process Swing only, not native Burp or wire evidence. */
class TrafficInspectorFindTest {
    static final String[] FIELDS = {"requestRaw", "requestHeaders", "requestBody", "responseRaw", "responseHeaders", "responseBody"};
    static final Set<String> FORBIDDEN = Set.of("updateConfig", "decideApproval", "bookmark", "clearEvidence", "pause", "passthrough",
            "resetIntentBudgets", "exportJson", "exportHar", "exportIncident", "humanExport", "humanIncident", "humanExportCurrent", "rawRequest", "rawResponse");

    @ParameterizedTest(name = "C01-{0}")
    @ValueSource(strings = {"requestRaw", "requestHeaders", "requestBody", "responseRaw", "responseHeaders", "responseBody"})
    void sideEntriesTargetOnlyOwnVisibleField(String field) throws Exception {
        try (Fixture f = new Fixture()) {
            edt(() -> {
                JButton entry = entry(f.inspector, field);
                assertTrue(entry.isEnabled());
                selectField(f.inspector, field); entry.doClick(0);
                assertTrue(bar(f.inspector).isVisible());
                assertEquals(2, namedCount(f.inspector, ".find.open"));
                assertEquals(1, namedCount(f.inspector, "traffic.find.bar"));
                assertEquals(0, descendants(bar(f.inspector)).stream().filter(JComboBox.class::isInstance).count());
                JLabel target = ui(f.inspector, "traffic.find.target", JLabel.class);
                assertTrue(target.getText().toLowerCase(java.util.Locale.ROOT).contains(field.startsWith("request") ? "request" : "response"));
                assertTrue(target.getText().toLowerCase(java.util.Locale.ROOT).contains(field.endsWith("Raw") ? "raw" : field.endsWith("Headers") ? "headers" : "body"));
                query(f.inspector).setText("needle"); return null;
            });
            settled(f.inspector); assertRange(area(f.inspector, field), needleOffset(f.inspector, field), 6);
            edt(() -> {
                assertEquals(1, f.table().getSelectedRowCount()); assertEquals("", ui(f.panel, "traffic.search", JTextField.class).getText());
                for (String other : FIELDS) if (!other.equals(field)) assertEquals(0, area(f.inspector, other).getHighlighter().getHighlights().length, other);
                assertNull(uiOrNull(f.inspector, "traffic.find.selector"));
                return null;
            });
        }
    }

    @Test void literalInputPreservesCaseWhitespacePunctuationRedactedAndNewlines() throws Exception {
        String text = "AbC abc .*[x] [REDACTED]  spaced  \nline-one\nline-two\r\n끝";
        Message message = new Message(List.of(new RequestData.Header("Duplicate", "one"), new RequestData.Header("Duplicate", "TWO.[x]")), text, "text/plain", false, false, true, "UTF8_TEXT");
        try (Fixture f = new Fixture(message, message)) {
            for (String needle : List.of("AbC", "abc", ".*[x]", "[REDACTED]", "  spaced  ", "line-one\nline-two", "line-two\r\n끝")) {
                search(f.inspector, "requestBody", needle); assertRange(area(f.inspector, "requestBody"), text.indexOf(needle), needle.length());
                assertEquals(needle, edt(() -> query(f.inspector).getText()));
            }
            search(f.inspector, "requestBody", "ABC"); assertNoMatch(f.inspector);
            search(f.inspector, "requestHeaders", "one\nDuplicate: TWO.[x]");
            assertRange(area(f.inspector, "requestHeaders"), "Duplicate: ".length(), "one\nDuplicate: TWO.[x]".length());
            edt(() -> {
                assertNull(((AbstractDocument) query(f.inspector).getDocument()).getDocumentFilter());
                query(f.inspector).setText("q".repeat(8_193)); assertEquals(8_193, query(f.inspector).getDocument().getLength());
                assertTrue(query(f.inspector).isEditable()); return null;
            });
            settled(f.inspector); assertNoMatch(f.inspector);
            assertEquals(text, edt(() -> area(f.inspector, "requestBody").getText()));
        }
    }

    @Test void supplementaryUnicodeFullTailAndOddHexUseDisplayOffsets() throws Exception {
        String body = "😀앞" + "a".repeat(2_200_000) + "끝😀한글-FULL-END";
        try (Fixture f = new Fixture(message(body, "UTF8_TEXT"), message("01abcdef", "HEX"))) {
            search(f.inspector, "requestBody", "끝😀한글-FULL-END"); assertRange(area(f.inspector, "requestBody"), 2_200_003, 14);
            assertEquals(body.length(), edt(() -> area(f.inspector, "requestBody").getDocument().getLength()));
            search(f.inspector, "requestRaw", "끝😀한글-FULL-END");
            int rawStart = edt(() -> area(f.inspector, "requestRaw").getText().indexOf("끝😀한글-FULL-END"));
            assertTrue(rawStart > 2_200_000); assertRange(area(f.inspector, "requestRaw"), rawStart, 14);
            search(f.inspector, "responseBody", "1abc"); assertRange(area(f.inspector, "responseBody"), 1, 4);
            search(f.inspector, "responseBody", "1ABC"); assertNoMatch(f.inspector);
            search(f.inspector, "responseBody", "secret"); assertNoMatch(f.inspector);
        }
    }

    @Test void overlapWrapEmptyAndNoMatchKeepOnlyCurrentOccurrence() throws Exception {
        try (Fixture f = new Fixture(message("banana", "UTF8_TEXT"), message("x", "UTF8_TEXT"))) {
            JTextArea area = area(f.inspector, "requestBody");
            var foreign = new DefaultHighlighter.DefaultHighlightPainter(java.awt.Color.MAGENTA);
            edt(() -> { area.select(0, 2); area.getHighlighter().addHighlight(0, 1, foreign); return null; });
            search(f.inspector, "requestBody", "ana"); assertOwnedRange(area, 1, 4, foreign);
            move(f.inspector, "next"); assertOwnedRange(area, 3, 6, foreign);
            move(f.inspector, "next"); assertOwnedRange(area, 1, 4, foreign); assertTrue(edt(() -> status(f.inspector).contains("wrap")));
            move(f.inspector, "previous"); assertOwnedRange(area, 3, 6, foreign); assertTrue(edt(() -> status(f.inspector).contains("wrap")));
            edt(() -> { assertEquals(0, area.getSelectionStart()); assertEquals(2, area.getSelectionEnd()); query(f.inspector).setText("");
                assertEquals(1, area.getHighlighter().getHighlights().length); assertFalse(pending(f.inspector)); return null; });
            search(f.inspector, "responseBody", "x"); assertRange(area(f.inspector, "responseBody"), 0, 1);
            move(f.inspector, "next"); assertRange(area(f.inspector, "responseBody"), 0, 1); assertTrue(edt(() -> status(f.inspector).contains("wrap")));
            search(f.inspector, "responseBody", "longer"); assertNoMatch(f.inspector);
            search(f.inspector, "requestBody", "banana"); assertOwnedRange(area, 0, 6, foreign);
            edt(() -> { ui(f.inspector, "traffic.find.close", JButton.class).doClick(0); assertEquals(1, area.getHighlighter().getHighlights().length); return null; });
        }
    }

    @Test void eligibilityUsesMessageFactsRatherThanMarkerText() throws Exception {
        List<Message[]> cases = List.of(new Message[]{Message.EMPTY, message("response-only", "UTF8_TEXT")},
                new Message[]{message("request-only", "UTF8_TEXT"), Message.EMPTY},
                new Message[]{new Message(List.of(new RequestData.Header("Retained", "needle")), "", "", true, false, true, "UNAVAILABLE"), message("", "EMPTY")},
                new Message[]{new Message(List.of(), "", "", false, false, true, "EMPTY"), message("", "EMPTY")},
                new Message[]{new Message(List.of(new RequestData.Header("Known", "needle")), "partial needle", "text/plain", true, true, true, "UTF8_TEXT"), message("[원문 없음 / body unavailable] [REDACTED]", "UTF8_TEXT")});
        for (Message[] pair : cases) try (Fixture f = new Fixture(pair[0], pair[1])) {
            for (int side = 0; side < 2; side++) {
                String prefix = side == 0 ? "request" : "response"; Message m = pair[side];
                for (String suffix : List.of("Raw", "Headers", "Body")) {
                    String field = prefix + suffix;
                    boolean eligible = m.present() && (!suffix.equals("Body") || !m.bodyEncoding().equals("UNAVAILABLE"));
                    edt(() -> { selectField(f.inspector, field); assertEquals(eligible, entry(f.inspector, field).isEnabled(), field + " " + m.bodyEncoding()); return null; });
                    if (eligible) {
                        search(f.inspector, field, suffix.equals("Raw") ? "inspection projection" : "needle");
                        if (suffix.equals("Raw")) assertTrue(edt(() -> area(f.inspector, field).getHighlighter().getHighlights().length == 1));
                        else if (m.bodyEncoding().equals("EMPTY")) assertNoMatch(f.inspector);
                    }
                }
            }
            if (pair[1].body().startsWith("[원문")) {
                search(f.inspector, "responseBody", "[원문 없음 / body unavailable]"); assertRange(area(f.inspector, "responseBody"), 0, "[원문 없음 / body unavailable]".length());
                assertTrue(edt(() -> area(f.inspector, "requestRaw").getText().contains("incomplete=true")));
            }
        }
    }

    @Test void sameContentPreservesButEqualReplacementRetires() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle");
            Object source = edt(() -> field(f.panel, "presentedContent"));
            JTextArea area = area(f.inspector, "requestBody");
            edt(() -> {
                area.select(0, 3); JScrollPane scroll = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, area);
                scroll.getViewport().setViewPosition(new java.awt.Point(0, 0)); Rectangle view = scroll.getViewport().getViewRect();
                Object mark = area.getHighlighter().getHighlights()[0];
                f.inspector.install((TrafficInspector.Content) source); f.panel.refreshNow();
                assertEquals("needle", query(f.inspector).getText()); assertSame(mark, area.getHighlighter().getHighlights()[0]);
                assertEquals(0, area.getSelectionStart()); assertEquals(3, area.getSelectionEnd()); assertEquals(view, scroll.getViewport().getViewRect());
                var equal = TrafficInspector.project(f.access.rows().getFirst().requestCapture(), f.access.rows().getFirst().responseCapture(),
                        "POST https://example.test/find-a HTTP/1.1 (inspection copy)", "HTTP/1.1 200 (inspection copy)", () -> false);
                assertEquals(source, equal); f.inspector.install(equal); assertNotSame(source, equal); assertEquals("", query(f.inspector).getText()); assertFalse(bar(f.inspector).isVisible());
                return null;
            });
            edt(() -> { f.panel.refreshNow(); return null; });
            NotificationDocument replacement = new NotificationDocument(new AtomicBoolean());
            edt(() -> { area.setDocument(replacement); f.inspector.install((TrafficInspector.Content) source); openTarget(f.inspector, "requestBody"); replacement.forbidStringReads = true; query(f.inspector).setText("needle"); return null; });
            settled(f.inspector); assertRange(area, 7, 6);
        }
    }

    @Test void documentReplacementAndUnexpectedEditRevokeAndBlankOldDocument() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle");
            JTextArea area = area(f.inspector, "requestBody"); Document old = edt(area::getDocument);
            NotificationDocument replacement = new NotificationDocument(new AtomicBoolean());
            edt(() -> {
                area.setDocument(replacement); assertEquals(0, old.getLength()); assertFalse(bar(f.inspector).isVisible()); assertEquals("", query(f.inspector).getText());
                assertFalse(entry(f.inspector, "requestBody").isEnabled());
                f.inspector.install((TrafficInspector.Content) field(f.panel, "presentedContent"));
                assertTrue(entry(f.inspector, "requestBody").isEnabled()); return null;
            });
            search(f.inspector, "requestBody", "needle");
            edt(() -> { replacement.insertString(0, "unexpected-", null); assertTrue(area.getText().startsWith("unexpected-"));
                assertFalse(bar(f.inspector).isVisible()); assertFalse(entry(f.inspector, "requestBody").isEnabled());
                assertEquals(0, replacement.mutationsDuringNotification); return null; });
        }
    }

    @Test void queryNotificationsNeverRefreshOrMutateTheirNotifyingDocument() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle");
            NotificationDocument document = new NotificationDocument(f.inNotification);
            edt(() -> { query(f.inspector).setDocument(document); openTarget(f.inspector, "requestBody"); return null; });
            int before = f.reads.get();
            try (HeldWork hold = HeldWork.start(f.inspector, "needle", false)) {
                assertEquals(before, f.reads.get(), "query notification must not reconcile the source");
                assertEquals(0, document.mutationsDuringNotification);
                hold.release(); settled(f.inspector); assertTrue(f.reads.get() > before, "deferred current completion must reconcile on EDT");
                assertEquals("needle", edt(() -> query(f.inspector).getText()));
            }
        }
    }

    @Test void queryDocumentReplacementRetiresAndBlanksHeldOldQuery() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle"); Document old = edt(() -> query(f.inspector).getDocument());
            try (HeldWork hold = HeldWork.start(f.inspector, "banana", false)) {
                edt(() -> { query(f.inspector).setDocument(new PlainDocument()); assertEquals(0, old.getLength()); assertFalse(bar(f.inspector).isVisible());
                    assertEquals(0, area(f.inspector, "requestBody").getHighlighter().getHighlights().length); openTarget(f.inspector, "requestBody");
                    assertEquals("", query(f.inspector).getText()); return null; });
                hold.release(); edt(() -> { assertEquals("", query(f.inspector).getText()); return null; });
            }
        }
    }

    @Test void pendingNavigationNeverSubmitsRestartsQueuesOrReplays() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle");
            try (HeldWork hold = HeldWork.start(f.inspector, "needle", false)) {
                long generation = pumpGeneration(hold.pump);
                edt(() -> {
                    assertTrue(status(f.inspector).contains("Searching"));
                    assertTrue(ui(f.inspector, "traffic.find.status", JLabel.class).getAccessibleContext().getAccessibleName().contains("Searching"));
                    for (String name : List.of("previous", "next")) {
                        JButton button = ui(f.inspector, "traffic.find." + name, JButton.class); assertFalse(button.isEnabled());
                        for (int i = 0; i < 20; i++) button.doClick(0);
                    }
                    for (int i = 0; i < 20; i++) { keyAction(query(f.inspector), java.awt.event.KeyEvent.VK_ENTER, 0); keyAction(query(f.inspector), java.awt.event.KeyEvent.VK_ENTER, java.awt.event.InputEvent.SHIFT_DOWN_MASK); }
                    assertTrue(query(f.inspector).isEditable()); assertEquals(generation, pumpGeneration(hold.pump)); return null;
                });
                hold.release(); settled(f.inspector); assertRange(area(f.inspector, "requestBody"), 7, 6); assertEquals(1, hold.executions.get());
            }
            for (String change : List.of("query", "close", "target", "clear")) {
                search(f.inspector, "requestBody", "needle");
                try (HeldWork hold = HeldWork.start(f.inspector, "needle", false)) {
                    edt(() -> {
                        switch (change) {
                            case "query" -> query(f.inspector).setText("banana");
                            case "close" -> keyAction(query(f.inspector), java.awt.event.KeyEvent.VK_ESCAPE, 0);
                            case "target" -> { selectField(f.inspector, "requestHeaders"); assertEquals("", query(f.inspector).getText()); }
                            case "clear" -> f.inspector.clear("");
                            default -> throw new AssertionError(change);
                        }
                        return null;
                    });
                    hold.release();
                    if (change.equals("query")) { settled(f.inspector); assertRange(area(f.inspector, "requestBody"), 0, 6); }
                    else edt(() -> { assertEquals("", query(f.inspector).getText()); return null; });
                }
                edt(() -> { f.panel.refreshNow(); return null; });
            }
        }
    }

    @Test void clearUnavailableAndPanelCloseSeparateReusableAndPermanentLifetime() throws Exception {
        GuardPanel unused = edt(() -> new GuardPanel(new GuardPanelV2Test.Access(), new GuardPanelV2Test.Human(), false));
        edt(() -> { TrafficInspector owner = inspector(unused); entry(owner, "requestRaw"); assertNull(field(findState(owner), "pump")); unused.close(); return null; });
        try (Fixture f = new Fixture()) {
            for (boolean unavailable : List.of(false, true)) {
                search(f.inspector, "requestBody", "needle");
                edt(() -> { if (unavailable) f.inspector.unavailable(); else f.inspector.clear("");
                    assertEquals("", query(f.inspector).getText()); assertFalse(entry(f.inspector, "requestRaw").isEnabled());
                    assertEquals("", area(f.inspector, "requestHeaders").getText());
                    f.panel.refreshNow(); return null; });
                search(f.inspector, "requestBody", "needle"); assertRange(area(f.inspector, "requestBody"), 7, 6);
            }
            edt(() -> { f.inspector.preview(HtmlPreview.scan("<h1>owned-secret</h1>", () -> false)); f.inspector.metadata("metadata-secret"); f.inspector.reason("reason-secret"); return null; });
            List<Document> documents = edt(() -> documents(f.inspector)); Object content = edt(() -> field(f.panel, "presentedContent"));
            TrafficSearch.Pump pump;
            try (HeldWork hold = HeldWork.start(f.inspector, "needle", false)) {
                pump = hold.pump;
                edt(() -> { f.panel.close(); f.panel.close(); for (Document d : documents) assertEquals(0, d.getLength());
                    f.inspector.install((TrafficInspector.Content) content); f.inspector.metadata("late"); f.inspector.reason("late"); f.inspector.unavailable();
                    f.inspector.preview(HtmlPreview.scan("<p>late</p>", () -> false)); f.inspector.previewMessage("late");
                    entry(f.inspector, "requestRaw").doClick(0); for (Document d : documents) assertEquals(0, d.getLength());
                    assertTrue(descendants(f.inspector).stream().filter(JTextComponent.class::isInstance).map(JTextComponent.class::cast).allMatch(t -> t.getDocument().getLength() == 0)); return null; });
                hold.release();
            }
            assertTrue(pump.awaitExit(5_000)); assertFalse(pump.retainsPending());
        }
    }

    @Test void currentWorkerFailureIsFixedEditableAndNotRetriedByRefresh() throws Exception {
        try (Fixture f = new Fixture()) {
            search(f.inspector, "requestBody", "needle");
            try (HeldWork hold = HeldWork.start(f.inspector, "needle", true)) {
                hold.release(); settled(f.inspector);
                long generation = pumpGeneration(hold.pump);
                edt(() -> { String feedback = status(f.inspector); assertTrue(feedback.contains("failed")); assertFalse(feedback.contains("No match"));
                    assertFalse(feedback.contains("synthetic-failure")); assertFalse(feedback.contains("needle")); assertTrue(query(f.inspector).isEditable());
                    assertEquals("needle", query(f.inspector).getText()); assertFalse(ui(f.inspector, "traffic.find.next", JButton.class).isEnabled());
                    f.panel.refreshNow(); f.panel.refreshNow(); assertEquals(feedback, status(f.inspector)); assertEquals(generation, pumpGeneration(hold.pump)); return null; });
                assertEquals(1, hold.executions.get());
            }
            search(f.inspector, "requestBody", "banana"); assertRange(area(f.inspector, "requestBody"), 0, 6);
        }
    }

    static Message message(String text, String encoding) { return new Message(List.of(new RequestData.Header("X-Find", "needle needle")), text, "text/plain; charset=UTF-8", false, false, true, encoding); }
    static String addRow(GuardPanelV2Test.Access access, String path, String body) {
        String id = access.store.begin("p", "Synthetic", new RequestData("POST", "https://example.test" + path, "example.test", 443, true,
                List.of(new RequestData.Header("X-Find", "needle needle"), new RequestData.Header("Content-Type", "text/plain; charset=UTF-8")), body.getBytes(StandardCharsets.UTF_8)),
                new Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
        access.store.response(id, 200, List.of(new RequestData.Header("X-Find", "needle needle"), new RequestData.Header("Content-Type", "text/html; charset=UTF-8")), body.getBytes(StandardCharsets.UTF_8)); return id;
    }

    static final class Fixture implements AutoCloseable {
        final GuardPanelV2Test.Access access = new GuardPanelV2Test.Access();
        final GuardPanelV2Test.Human dialogs = new GuardPanelV2Test.Human();
        final AtomicInteger reads = new AtomicInteger();
        final AtomicBoolean inNotification = new AtomicBoolean(), action = new AtomicBoolean();
        final AtomicReference<String> urlOverride = new AtomicReference<>();
        final List<String> calls = new ArrayList<>();
        final GuardUiAccess checked;
        final GuardPanel panel;
        final TrafficInspector inspector;
        final String id;
        Fixture() throws Exception { this(null, null); }
        Fixture(Message request, Message response) throws Exception {
            id = addRow(access, "/find-a", "banana needle needle");
            List<TrafficEntry> supplied;
            if (request == null) supplied = null;
            else supplied = List.of(new TrafficEntry("find-source", "p", "Synthetic", "2026-01-01T00:00:00Z", "POST", "https://example.test/find-a", "ALLOW", "FORWARDED", "DEFAULT_ALLOW", 200,
                    List.of(), 7, false, request, response, false, ""));
            checked = (GuardUiAccess) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{GuardUiAccess.class}, (proxy, method, args) -> {
                assertTrue(SwingUtilities.isEventDispatchThread(), "Find access off EDT: " + method.getName());
                assertFalse(inNotification.get(), "source read inside query notification: " + method.getName());
                if (action.get()) assertFalse(FORBIDDEN.contains(method.getName()), "Find has no authority: " + method.getName());
                reads.incrementAndGet(); calls.add(method.getName());
                if (method.getName().equals("rawUrl") && urlOverride.get() != null) return urlOverride.get();
                if (supplied != null) {
                    if (method.getName().equals("traffic")) return supplied;
                    if (method.getName().equals("rawCaptureInfo")) return Map.of("available", true);
                    if (method.getName().equals("rawUrl")) return "https://example.test/find-a";
                }
                try { return method.invoke(access, args); } catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
            panel = edt(() -> { GuardPanel p = new GuardPanel(checked, dialogs, false); ui(p, "tabs", JTabbedPane.class).setSelectedIndex(3); ui(p, "traffic.table", JTable.class).setRowSelectionInterval(0, 0); return p; });
            inspector = inspector(panel);
            GuardPanelTrafficViewTest.await(() -> area(inspector, "requestRaw").getDocument().getLength() > 0);
        }
        JTable table() { return ui(panel, "traffic.table", JTable.class); }
        @Override public void close() throws Exception { edt(() -> { panel.close(); return null; }); }
    }

    static final class Popout implements AutoCloseable {
        final Fixture fixture;
        final java.awt.SecondaryLoop loop = java.awt.Toolkit.getDefaultToolkit().getSystemEventQueue().createSecondaryLoop();
        final AtomicReference<TrafficInspector> root = new AtomicReference<>();
        Popout(Fixture fixture) throws Exception {
            this.fixture = fixture;
            edt(() -> { fixture.dialogs.edit = (form, save) -> { root.set((TrafficInspector) form.component()); assertTrue(loop.enter()); }; return null; });
            SwingUtilities.invokeLater(() -> ui(fixture.panel, "traffic.detail", JButton.class).doClick(0));
            GuardPanelTrafficViewTest.await(() -> root.get() != null);
        }
        TrafficInspector inspector() { return root.get(); }
        @Override public void close() throws Exception { edt(() -> { loop.exit(); return null; }); GuardPanelTrafficViewTest.await(() -> field(fixture.panel, "popoutInspector") == null); }
    }

    static final class HeldWork implements AutoCloseable {
        final TrafficSearch.Pump pump;
        final CountDownLatch released = new CountDownLatch(1), entered = new CountDownLatch(1);
        final AtomicInteger executions = new AtomicInteger();
        Consumer<TrafficSearch.Pump.Result> accept;
        HeldWork(TrafficSearch.Pump pump) { this.pump = pump; }
        static HeldWork start(TrafficInspector root, String text, boolean failed) throws Exception {
            TrafficSearch.Pump pump = edt(() -> pump(root));
            assertNotNull(pump, "warm the real Find lane before holding its next input");
            HeldWork hold = new HeldWork(pump);
            CountDownLatch laneEntered = new CountDownLatch(1), laneReleased = new CountDownLatch(1);
            pump.submit(cancelled -> { laneEntered.countDown(); waitIgnoringInterrupts(laneReleased); return null; }, result -> fail("obsolete blocker publication"));
            assertTrue(laneEntered.await(5, TimeUnit.SECONDS));
            try {
                edt(() -> {
                    query(root).setText(""); query(root).setText(text);
                    synchronized (pump) {
                        Object job = field(pump, "pending"); assertNotNull(job, "the actual query must submit work");
                        TrafficSearch.Pump.Task task = (TrafficSearch.Pump.Task) recordValue(job, "task");
                        @SuppressWarnings("unchecked") Consumer<TrafficSearch.Pump.Result> consumer = (Consumer<TrafficSearch.Pump.Result>) recordValue(job, "accept");
                        hold.accept = consumer;
                        TrafficSearch.Pump.Task wrapped = cancelled -> {
                            hold.executions.incrementAndGet(); hold.entered.countDown(); waitIgnoringInterrupts(hold.released);
                            if (failed) throw new IllegalStateException("synthetic-failure-needle-must-not-escape");
                            return task.run(cancelled);
                        };
                        replaceJob(pump, job, wrapped, consumer);
                    }
                    assertTrue(pending(root)); return null;
                });
            } finally { laneReleased.countDown(); }
            assertTrue(hold.entered.await(5, TimeUnit.SECONDS), "the actual wrapped Find task must run");
            return hold;
        }
        void release() { released.countDown(); }
        void atPhase(String phase, Runnable transition) throws Exception {
            edt(() -> { if (phase.equals("actualQueuedEdtDelivery")) { release(); awaitDelivery(pump); } else assertEquals(1, released.getCount()); transition.run(); return null; });
        }
        @Override public void close() { release(); }
    }

    static void replaceJob(TrafficSearch.Pump pump, Object job, TrafficSearch.Pump.Task task, Consumer<TrafficSearch.Pump.Result> accept) throws Exception {
        var constructor = job.getClass().getDeclaredConstructors()[0]; constructor.setAccessible(true);
        setField(pump, "pending", constructor.newInstance(recordValue(job, "generation"), task, accept));
    }
    static void awaitDelivery(TrafficSearch.Pump pump) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) { synchronized (pump) { if (field(pump, "delivery") != null) return; } Thread.sleep(1); }
        fail("the actual task did not queue its EDT delivery");
    }
    static void waitIgnoringInterrupts(CountDownLatch latch) { while (latch.getCount() > 0) try { latch.await(); } catch (InterruptedException ignored) { } }
    static Object recordValue(Object value, String accessor) throws Exception { var method = value.getClass().getDeclaredMethod(accessor); method.setAccessible(true); return method.invoke(value); }
    static Object field(Object object, String name) throws Exception { var field = object.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(object); }
    static void setField(Object object, String name, Object value) throws Exception { var field = object.getClass().getDeclaredField(name); field.setAccessible(true); field.set(object, value); }
    static Object findState(TrafficInspector root) throws Exception { return field(root, "find"); }
    static TrafficSearch.Pump pump(TrafficInspector root) throws Exception { return (TrafficSearch.Pump) field(findState(root), "pump"); }
    static boolean pending(TrafficInspector root) throws Exception { return (boolean) field(findState(root), "pending"); }
    static long pumpGeneration(TrafficSearch.Pump pump) throws Exception { synchronized (pump) { return (long) field(pump, "generation"); } }
    static TrafficInspector inspector(Component root) { return (TrafficInspector) SwingUtilities.getAncestorOfClass(TrafficInspector.class, ui(root, "traffic.request", JTextArea.class)); }
    static Object uiOrNull(Component root, String name) { return GuardPanelV2Test.find(root, name); }
    static <T> T ui(Component root, String name, Class<T> type) { return type.cast(assertNotNullComponent(root, name)); }
    static Component assertNotNullComponent(Component root, String name) { Component found = GuardPanelV2Test.find(root, name); assertNotNull(found, "Selected-message Find control is missing: " + name); return found; }
    static JButton entry(TrafficInspector root, String field) { return ui(root, field.startsWith("request") ? "traffic.request.find.open" : "traffic.response.find.open", JButton.class); }
    static JTextArea area(Component root, String field) {
        String side = field.startsWith("request") ? "request" : "response";
        return ui(root, "traffic." + side + (field.endsWith("Raw") ? "" : field.endsWith("Headers") ? ".headers" : ".body"), JTextArea.class);
    }
    static void selectField(Component root, String field) {
        ui(root, "traffic.details", JTabbedPane.class).setSelectedIndex(0);
        ui(root, field.startsWith("request") ? "traffic.requestTabs" : "traffic.responseTabs", JTabbedPane.class).setSelectedIndex(field.endsWith("Raw") ? 0 : field.endsWith("Headers") ? 1 : 2);
    }
    static void openTarget(TrafficInspector root, String field) { selectField(root, field); entry(root, field).doClick(0); assertTrue(bar(root).isVisible()); }
    static JComponent bar(Component root) { return ui(root, "traffic.find.bar", JComponent.class); }
    static JTextArea query(Component root) { return ui(root, "traffic.find.query", JTextArea.class); }
    static String status(Component root) { return ui(root, "traffic.find.status", JLabel.class).getText(); }
    static void search(TrafficInspector root, String field, String text) throws Exception {
        edt(() -> { openTarget(root, field); query(root).setText(""); query(root).setText(text); return null; }); settled(root);
    }
    static void settled(TrafficInspector root) throws Exception { GuardPanelTrafficViewTest.await(() -> !status(root).contains("Searching")); }
    static void move(TrafficInspector root, String direction) throws Exception { edt(() -> { ui(root, "traffic.find." + direction, JButton.class).doClick(0); return null; }); settled(root); }
    static int needleOffset(TrafficInspector root, String field) throws Exception { return edt(() -> area(root, field).getText().indexOf("needle")); }
    static void assertRange(JTextArea area, int start, int length) throws Exception {
        edt(() -> { Highlighter.Highlight[] hits = area.getHighlighter().getHighlights(); assertEquals(1, hits.length, area.getName()); assertEquals(start, hits[0].getStartOffset()); assertEquals(start + length, hits[0].getEndOffset()); return null; });
    }
    static void assertOwnedRange(JTextArea area, int start, int end, Highlighter.HighlightPainter foreign) throws Exception {
        edt(() -> { var hits = java.util.Arrays.stream(area.getHighlighter().getHighlights()).filter(h -> h.getPainter() != foreign).toList();
            assertEquals(1, hits.size()); assertEquals(start, hits.getFirst().getStartOffset()); assertEquals(end, hits.getFirst().getEndOffset());
            assertEquals(1, java.util.Arrays.stream(area.getHighlighter().getHighlights()).filter(h -> h.getPainter() == foreign).count()); return null; });
    }
    static void assertNoMatch(TrafficInspector root) throws Exception { edt(() -> { assertTrue(status(root).contains("No match"), status(root)); assertFalse(ui(root, "traffic.find.next", JButton.class).isEnabled()); return null; }); }
    static void keyAction(JComponent component, int key, int modifiers) {
        Object binding = component.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(key, modifiers)); assertNotNull(binding);
        Action action = component.getActionMap().get(binding); assertNotNull(action); assertTrue(action.isEnabled()); action.actionPerformed(new java.awt.event.ActionEvent(component, 0, "test-local-key"));
    }
    static List<Component> descendants(Component root) { List<Component> all = new ArrayList<>(); all.add(root); if (root instanceof Container parent) for (Component c : parent.getComponents()) all.addAll(descendants(c)); return all; }
    static long namedCount(Component root, String name) { return descendants(root).stream().filter(c -> c.getName() != null && (name.startsWith(".") ? c.getName().endsWith(name) : c.getName().equals(name))).count(); }
    static List<Document> documents(Component root) { return descendants(root).stream().filter(JTextComponent.class::isInstance).map(JTextComponent.class::cast).map(JTextComponent::getDocument).distinct().toList(); }

    @SuppressWarnings("serial")
    static final class NotificationDocument extends PlainDocument {
        final AtomicBoolean notifying;
        boolean forbidStringReads;
        int mutationsDuringNotification;
        NotificationDocument(AtomicBoolean notifying) { this.notifying = notifying; }
        @Override protected void fireInsertUpdate(DocumentEvent event) { notifying.set(true); try { super.fireInsertUpdate(event); } finally { notifying.set(false); } }
        @Override protected void fireRemoveUpdate(DocumentEvent event) { notifying.set(true); try { super.fireRemoveUpdate(event); } finally { notifying.set(false); } }
        @Override public void insertString(int offset, String text, AttributeSet attributes) throws BadLocationException { if (notifying.get()) mutationsDuringNotification++; super.insertString(offset, text, attributes); }
        @Override public void remove(int offset, int length) throws BadLocationException { if (notifying.get()) mutationsDuringNotification++; super.remove(offset, length); }
        @Override public String getText(int offset, int length) throws BadLocationException { assertFalse(forbidStringReads, "query edit must use the installed String, not copy the traffic Document"); return super.getText(offset, length); }
    }
}
