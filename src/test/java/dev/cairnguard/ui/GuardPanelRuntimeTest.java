package dev.cairnguard.ui;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.runtime.GuardController;
import dev.cairnguard.runtime.ProjectAccess;
import dev.cairnguard.ui.editor.EditorForm;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import static org.junit.jupiter.api.Assertions.*;

/** Real in-process controller/queue/UI integration, no native Burp or network execution. */
class GuardPanelRuntimeTest {
    @Test void actualApprovalAndRateQueueStatesAreVisibleFilterableAndHumanDecidable() throws Exception {
        GuardConfig config = new GuardConfig(1, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), List.of(),
                List.of(new Rule("ask", "승인 연습", true, Mode.ASK, Condition.leaf(Field.PATH, Match.EXACT, "/ask"))), Mode.ALLOW,
                new GuardConfig.Limits(1, 0, Map.of(), 1, 10, 30_000, 30_000, 60_000));
        GuardController controller = new GuardController(new ProjectAccess() {
            private String document = Json.write(config);
            @Override public Ref current() { return new Ref("synthetic-project", "Synthetic"); }
            @Override public String load() { return document; }
            @Override public void save(String value) { document = value; }
        });
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        AtomicReference<GuardPanel> panel = new AtomicReference<>();
        GuardController.Admission held = null;
        try {
            GuardController.Prepared first = controller.prepare(request("/hold"));
            held = controller.authorize(first); assertTrue(held.allowed()); assertTrue(controller.commit(first));
            GuardController.Prepared queued = controller.prepare(request("/queued"));
            Future<GuardController.Admission> queuedResult = workers.submit(() -> controller.authorize(queued));
            await(() -> controller.traffic().stream().anyMatch(e -> e.id().equals(queued.evidenceId()) && e.disposition().equals("QUEUED")));
            GuardController.Prepared ask = controller.prepare(request("/ask"));
            Future<GuardController.Admission> askResult = workers.submit(() -> controller.authorize(ask));
            await(() -> !controller.approvals().isEmpty());
            edt(() -> {
                panel.set(new GuardPanel(controller, new NoModalDialogs(), false));
                JComboBox<?> outcome = get(panel.get(), "traffic.outcome", JComboBox.class);
                outcome.setSelectedIndex(3);
                JTable table = get(panel.get(), "traffic.table", JTable.class);
                assertEquals(2, table.getRowCount());
                assertEquals(Set.of("승인 대기", "전송 대기"), Set.of(table.getValueAt(0, 4), table.getValueAt(1, 4)));
                JTable approval = get(panel.get(), "approval.table", JTable.class);
                assertEquals("GET", approval.getValueAt(0, 0)); assertEquals("승인 연습", approval.getValueAt(0, 2));
                approval.setRowSelectionInterval(0, 0);
                assertTrue(get(panel.get(), "approval.approve", JButton.class).isEnabled());
                get(panel.get(), "approval.deny", JButton.class).doClick(0);
                return null;
            });
            assertFalse(askResult.get(5, TimeUnit.SECONDS).allowed());
            assertEquals("DENIED", controller.traffic().stream().filter(e -> e.id().equals(ask.evidenceId())).findFirst().orElseThrow().reason());
            held = null;
            GuardController.Admission admitted = queuedResult.get(5, TimeUnit.SECONDS);
            assertTrue(admitted.allowed());
        } finally {
            if (panel.get() != null) edt(() -> { panel.get().close(); return null; });
            controller.close(); workers.close();
        }
    }
    private static RequestData request(String path) { return new RequestData("GET", "https://example.test" + path, "example.test", 443, true, List.of(), new byte[0]); }
    private static void await(BooleanSupplier condition) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < until) Thread.sleep(5);
        assertTrue(condition.getAsBoolean(), "bounded synthetic runtime wait");
    }
    private static <T> T edt(Callable<T> task) throws Exception {
        AtomicReference<T> value = new AtomicReference<>(); AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> { try { value.set(task.call()); } catch (Throwable e) { failure.set(e); } });
        if (failure.get() instanceof Exception e) throw e;
        if (failure.get() instanceof Error e) throw e;
        return value.get();
    }
    private static <T> T get(Component root, String name, Class<T> type) {
        if (name.equals(root.getName())) return type.cast(root);
        if (root instanceof Container parent) for (Component child : parent.getComponents()) {
            T result = get(child, name, type); if (result != null) return result;
        }
        return null;
    }
    private static final class NoModalDialogs implements GuardPanel.Dialogs {
        @Override public boolean confirm(Component parent, String text) { fail("unexpected confirmation"); return false; }
        @Override public Path chooseExport(Component parent, String extension) { fail("unexpected chooser"); return null; }
        @Override public void error(Component parent, String text) { fail(text); }
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, Runnable save) { fail("unexpected editor"); }
    }

    @Test void findLeavesPendingAskPacingIntentPauseAndOffFactsUnchanged() throws Exception {
        GuardConfig.Limits defaults = GuardConfig.defaults().limits();
        GuardConfig.Limits limits = new GuardConfig.Limits(1, 0, Map.of(), 1, 10, 30_000, 30_000, 60_000,
                defaults.perPathMaxResponseBytes(), defaults.autoBlockMillis(), null, null, 10, false, List.of(), List.of(), List.of(), true, List.of());
        GuardConfig policy = new GuardConfig(2, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), List.of(),
                List.of(new Rule("find-ask", "Synthetic ASK", true, Mode.ASK, Condition.leaf(Field.PATH, Match.EXACT, "/ask"))), Mode.ALLOW, limits);
        for (String mode : List.of("protected", "paused", "off")) {
            var clock = new java.util.concurrent.atomic.AtomicLong(1_000_000_000L);
            var gateConstructor = dev.cairnguard.runtime.RateGate.class.getDeclaredConstructor(GuardConfig.Limits.class, java.util.function.LongSupplier.class, int.class); gateConstructor.setAccessible(true);
            var gate = gateConstructor.newInstance(limits, (java.util.function.LongSupplier) clock::get, 4096);
            ProjectAccess project = new ProjectAccess() {
                @Override public Ref current() { return new Ref("find-runtime", "Synthetic"); }
                @Override public String load() { return Json.write(policy); }
                @Override public void save(String value) { fail("Find cannot save policy"); }
            };
            var constructor = GuardController.class.getDeclaredConstructor(ProjectAccess.class, dev.cairnguard.runtime.ResponseWatcher.class,
                    dev.cairnguard.runtime.IntentBudget.class, dev.cairnguard.runtime.RateGate.class, dev.cairnguard.runtime.ListenerRegistry.class); constructor.setAccessible(true);
            GuardController controller = constructor.newInstance(project, new dev.cairnguard.runtime.ResponseWatcher(limits), new dev.cairnguard.runtime.IntentBudget(), gate, new dev.cairnguard.runtime.ListenerRegistry());
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            AtomicReference<GuardPanel> panel = new AtomicReference<>();
            Future<GuardController.Admission> queued = null, ask = null;
            try {
                RequestData original = findRuntimeRequest("/hold"); byte[] body = original.body().clone(); var headers = List.copyOf(original.headers());
                GuardController.Prepared admitted = controller.prepare(original); assertTrue(controller.authorize(admitted).allowed()); assertTrue(controller.commit(admitted));
                if (mode.equals("protected")) {
                    GuardController.Prepared paced = controller.prepare(findRuntimeRequest("/queued")); queued = workers.submit(() -> controller.authorize(paced));
                    await(() -> ((Number) ((Map<?, ?>) controller.status().get("gate")).get("queued")).intValue() == 1);
                    GuardController.Prepared approval = controller.prepare(findRuntimeRequest("/ask")); ask = workers.submit(() -> controller.authorize(approval));
                    await(() -> controller.approvals().size() == 1);
                } else if (mode.equals("paused")) controller.pause(true);
                else { var status = controller.status(); controller.passthrough(true, status.get("projectId").toString(), ((Number) status.get("revision")).longValue()); }
                var approvals = List.copyOf(controller.approvals()); var rows = controller.traffic(); var facts = findRuntimeFacts(controller);
                String raw = controller.rawRequest(admitted.evidenceId());
                AtomicReference<Integer> reads = new AtomicReference<>(0);
                GuardUiAccess checked = (GuardUiAccess) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{GuardUiAccess.class}, (proxy, method, args) -> {
                    assertTrue(SwingUtilities.isEventDispatchThread(), "Find cannot use controller off EDT: " + method.getName());
                    assertFalse(TrafficInspectorFindTest.FORBIDDEN.contains(method.getName()), "Find cannot control/export/read whole raw: " + method.getName()); reads.set(reads.get() + 1);
                    try { return method.invoke(controller, args); } catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
                edt(() -> {
                    panel.set(new GuardPanel(checked, new NoModalDialogs(), false));
                    get(panel.get(), "tabs", JTabbedPane.class).setSelectedIndex(3); JTable table = get(panel.get(), "traffic.table", JTable.class);
                    for (int row = 0; row < table.getRowCount(); row++) if (table.getValueAt(row, 3).toString().endsWith("/hold")) table.setRowSelectionInterval(row, row); return null;
                });
                GuardPanelTrafficViewTest.await(() -> get(panel.get(), "traffic.request", JTextArea.class).getDocument().getLength() > 0);
                TrafficInspector owner = TrafficInspectorFindTest.inspector(panel.get());
                TrafficInspectorFindTest.search(owner, "requestBody", "needle"); TrafficInspectorFindTest.move(owner, "next"); TrafficInspectorFindTest.move(owner, "previous");
                edt(() -> { TrafficInspectorFindTest.query(owner).setText(""); TrafficInspectorFindTest.ui(owner, "traffic.find.close", JButton.class).doClick(0); return null; });
                assertTrue(reads.get() > 0); assertEquals(policy, controller.config()); assertEquals(facts, findRuntimeFacts(controller)); assertEquals(approvals, controller.approvals()); assertEquals(rows, controller.traffic());
                assertArrayEquals(body, original.body()); assertEquals(headers, original.headers()); assertEquals(raw, controller.rawRequest(admitted.evidenceId()));
                if (mode.equals("protected")) { assertFalse(queued.isDone()); assertFalse(ask.isDone()); assertEquals(1, controller.approvals().size());
                    assertTrue(((Number) ((Map<?, ?>) controller.status().get("intents")).get("consumed")).longValue() > 0); }
                if (mode.equals("paused")) assertEquals(true, controller.status().get("paused"));
                if (mode.equals("off")) assertEquals(true, controller.status().get("passthrough"));
                System.out.println("FIND_RUNTIME mode=" + mode + " actualController=true stableFactsAndOriginalBytes=true waitsUnresolved=" + mode.equals("protected"));
            } finally {
                if (panel.get() != null) edt(() -> { panel.get().close(); return null; });
                controller.close(); workers.close();
            }
        }
    }

    private static RequestData findRuntimeRequest(String path) {
        return new RequestData("POST", "https://example.test" + path, "example.test", 443, true,
                List.of(new RequestData.Header("Content-Type", "text/plain; charset=UTF-8"), new RequestData.Header("X-Cairn-Intent", "find-intent"), new RequestData.Header("X-Cairn-Run", "find-run")), "banana needle needle".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    private static Map<String, Object> findRuntimeFacts(GuardController controller) {
        var status = controller.status(); var facts = new java.util.LinkedHashMap<String, Object>();
        for (String key : List.of("projectId", "revision", "guardState", "paused", "operatorPaused", "passthrough", "passthroughCount", "intents", "gate", "approvalCount")) facts.put(key, status.get(key));
        return Map.copyOf(facts);
    }
}
