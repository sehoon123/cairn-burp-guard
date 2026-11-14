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
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, java.util.function.Consumer<GuardPanel.SubmitConfirmation> save) { fail("unexpected editor"); }
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

    @Test void scopeDraftNoOpCancelAndInvalidPreserveRealWaitsPacingIntentPauseAndOffUntilOneSave() throws Exception {
        GuardConfig.Limits d = GuardConfig.defaults().limits();
        GuardConfig.Limits limits = new GuardConfig.Limits(1, 0, Map.of(), 1, 10, 30_000, 30_000, 60_000,
                d.perPathMaxResponseBytes(), d.autoBlockMillis(), null, null, 10, false, List.of(), List.of(), List.of(), true, List.of());
        GuardConfig policy = new GuardConfig(2, List.of(new ScopeEntry(true, "example.test", "https", 443, "")), List.of(),
                List.of(new Rule("scope-ask", "Synthetic ASK", true, Mode.ASK, Condition.leaf(Field.PATH, Match.EXACT, "/ask"))), Mode.ALLOW, limits);
        for (String mode : List.of("protected", "paused", "off")) {
            var clock = new java.util.concurrent.atomic.AtomicLong(1_000_000_000L);
            var gateConstructor = dev.cairnguard.runtime.RateGate.class.getDeclaredConstructor(GuardConfig.Limits.class, java.util.function.LongSupplier.class, int.class);
            gateConstructor.setAccessible(true);
            var gate = gateConstructor.newInstance(limits, (java.util.function.LongSupplier) clock::get, 4096);
            var document = new AtomicReference<>(Json.write(policy));
            var writes = new java.util.concurrent.atomic.AtomicInteger();
            ProjectAccess project = new ProjectAccess() {
                @Override public Ref current() { return new Ref("scope-runtime", "Synthetic"); }
                @Override public String load() { return document.get(); }
                @Override public void save(String value) { document.set(value); writes.incrementAndGet(); }
            };
            var constructor = GuardController.class.getDeclaredConstructor(ProjectAccess.class, dev.cairnguard.runtime.ResponseWatcher.class,
                    dev.cairnguard.runtime.IntentBudget.class, dev.cairnguard.runtime.RateGate.class, dev.cairnguard.runtime.ListenerRegistry.class);
            constructor.setAccessible(true);
            GuardController controller = constructor.newInstance(project, new dev.cairnguard.runtime.ResponseWatcher(limits), new dev.cairnguard.runtime.IntentBudget(), gate, new dev.cairnguard.runtime.ListenerRegistry());
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            AtomicReference<GuardPanel> panel = new AtomicReference<>();
            Future<GuardController.Admission> queued = null, ask = null;
            ScopeDialogs dialogs = new ScopeDialogs();
            try {
                GuardController.Prepared first = controller.prepare(scopeRuntimeRequest("/hold"));
                assertTrue(controller.authorize(first).allowed()); assertTrue(controller.commit(first));
                if (mode.equals("protected")) {
                    var paced = controller.prepare(scopeRuntimeRequest("/queued")); queued = workers.submit(() -> controller.authorize(paced));
                    await(() -> ((Number) ((Map<?, ?>) controller.status().get("gate")).get("queued")).intValue() == 1);
                    var approval = controller.prepare(scopeRuntimeRequest("/ask")); ask = workers.submit(() -> controller.authorize(approval));
                    await(() -> controller.approvals().size() == 1);
                } else if (mode.equals("paused")) controller.pause(true);
                else { var current = controller.status(); controller.passthrough(true, current.get("projectId").toString(), ((Number) current.get("revision")).longValue()); }
                Map<String, Object> before = findRuntimeFacts(controller);
                var pending = List.copyOf(controller.approvals());
                edt(() -> { panel.set(new GuardPanel(controller, dialogs, false)); return null; });
                for (String action : List.of("no-op", "cancel", "invalid")) {
                    dialogs.script = (form, save) -> {
                        if (!action.equals("no-op")) get(form.component(), "scope.port", JTextField.class).setText(action.equals("invalid") ? "80,,443" : "80,443");
                        if (!action.equals("cancel")) save.run();
                    };
                    edt(() -> {
                        get(panel.get(), "scope.allow.table", JTable.class).setRowSelectionInterval(0, 0);
                        get(panel.get(), "scope.allow.edit", JButton.class).doClick(0); return null;
                    });
                    assertEquals(0, writes.get()); assertEquals(policy, controller.config());
                    assertEquals(before, findRuntimeFacts(controller)); assertEquals(pending, controller.approvals());
                }
                assertEquals(1, dialogs.errors.size());
                dialogs.script = (form, save) -> {
                    get(form.component(), "scope.port", JTextField.class).setText("80,443");
                    get(form.component(), "scope.pathMode", JComboBox.class).setSelectedIndex(0);
                    get(form.component(), "scope.path", JTextArea.class).setText("/api\n/manager");
                    save.run();
                };
                edt(() -> { get(panel.get(), "scope.allow.edit", JButton.class).doClick(0); return null; });
                assertEquals(1, writes.get()); assertEquals(4, controller.config().allowScope().size());
                assertEquals(limits, controller.config().limits()); assertEquals(policy.rules(), controller.config().rules());
                assertEquals(((Number) before.get("revision")).longValue() + 1, ((Number) controller.status().get("revision")).longValue());
                assertEquals(before.get("paused"), controller.status().get("paused"));
                assertEquals(before.get("passthrough"), controller.status().get("passthrough"));
                assertEquals(before.get("intents"), controller.status().get("intents"));
                assertTrue(controller.approvals().isEmpty());
                if (queued != null) { assertFalse(queued.get(5, TimeUnit.SECONDS).allowed()); assertFalse(ask.get(5, TimeUnit.SECONDS).allowed()); }
                System.out.println("SCOPE_RUNTIME mode=" + mode + " unchangedDraftFacts=true oneSave=true waitsCancelledNotApproved=true");
            } finally {
                if (panel.get() != null) edt(() -> { panel.get().close(); return null; });
                controller.close(); workers.close();
            }
        }
    }

    @Test void destinationModeDraftAndBothSavesPreserveRealWaitsDebtPauseOffAndOriginals() throws Exception {
        GuardConfig.Limits d = GuardConfig.defaults().limits();
        GuardConfig.Limits limits = new GuardConfig.Limits(1, 0, Map.of(), 1, 10, 30_000, 30_000, 60_000,
                d.perPathMaxResponseBytes(), d.autoBlockMillis(), null, null, 10, false, List.of(), List.of(), List.of(), true, List.of());
        GuardConfig initial = new GuardConfig(2, List.of(new ScopeEntry(true, "example.test", "https", 443, "")), List.of(),
                List.of(new Rule("mode-ask", "Synthetic mode ASK", true, Mode.ASK, Condition.leaf(Field.PATH, Match.EXACT, "/ask"))), Mode.ALLOW, limits);
        for (String state : List.of("protected", "paused", "off")) {
            var clock = new java.util.concurrent.atomic.AtomicLong(1_000_000_000L);
            var gateConstructor = dev.cairnguard.runtime.RateGate.class.getDeclaredConstructor(GuardConfig.Limits.class, java.util.function.LongSupplier.class, int.class); gateConstructor.setAccessible(true);
            var gate = gateConstructor.newInstance(limits, (java.util.function.LongSupplier) clock::get, 4096);
            var document = new AtomicReference<>(Json.write(initial)); var writes = new java.util.concurrent.atomic.AtomicInteger();
            ProjectAccess project = new ProjectAccess() {
                @Override public Ref current() { return new Ref("destination-mode-runtime", "Synthetic"); }
                @Override public String load() { return document.get(); }
                @Override public void save(String value) { document.set(value); writes.incrementAndGet(); }
            };
            var constructor = GuardController.class.getDeclaredConstructor(ProjectAccess.class, dev.cairnguard.runtime.ResponseWatcher.class,
                    dev.cairnguard.runtime.IntentBudget.class, dev.cairnguard.runtime.RateGate.class, dev.cairnguard.runtime.ListenerRegistry.class); constructor.setAccessible(true);
            GuardController controller = constructor.newInstance(project, new dev.cairnguard.runtime.ResponseWatcher(limits), new dev.cairnguard.runtime.IntentBudget(), gate, new dev.cairnguard.runtime.ListenerRegistry());
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor(); AtomicReference<GuardPanel> panel = new AtomicReference<>();
            DestinationDialogs dialogs = new DestinationDialogs();
            Future<GuardController.Admission> queued = null, ask = null, laterQueue = null;
            try {
                GuardController.Prepared first = controller.prepare(scopeRuntimeRequest("/hold"));
                assertTrue(controller.authorize(first).allowed()); assertTrue(controller.commit(first));
                String original = controller.rawRequest(first.evidenceId());
                GuardController.Prepared oldPrepared = null;
                if (state.equals("protected")) {
                    oldPrepared = controller.prepare(scopeRuntimeRequest("/uncommitted"));
                    var paced = controller.prepare(scopeRuntimeRequest("/queued")); queued = workers.submit(() -> controller.authorize(paced));
                    await(() -> ((Number) ((Map<?, ?>) controller.status().get("gate")).get("queued")).intValue() == 1);
                    var approval = controller.prepare(scopeRuntimeRequest("/ask")); ask = workers.submit(() -> controller.authorize(approval));
                    await(() -> controller.approvals().size() == 1);
                } else {
                    controller.pause(true);
                    if (state.equals("off")) { var status = controller.status(); controller.passthrough(true, status.get("projectId").toString(), ((Number) status.get("revision")).longValue()); }
                }
                Map<String, Object> before = findRuntimeFacts(controller); var pending = List.copyOf(controller.approvals());
                edt(() -> { panel.set(new GuardPanel(controller, dialogs, false)); return null; });
                for (String action : List.of("no-op", "cancel", "invalid")) {
                    dialogs.script = (form, save) -> {
                        JComboBox<?> choice = get(form.component(), "scope.mode.choice", JComboBox.class);
                        if (!action.equals("no-op")) choice.setSelectedItem(action.equals("invalid") ? null : GuardConfig.DestinationScopeMode.ALL_DESTINATIONS);
                        if (!action.equals("cancel")) save.run();
                    };
                    edt(() -> { get(panel.get(), "scope.mode.edit", JButton.class).doClick(0); return null; });
                    assertEquals(0, writes.get()); assertEquals(initial, controller.config());
                    assertEquals(before, findRuntimeFacts(controller)); assertEquals(pending, controller.approvals());
                }
                assertEquals(1, dialogs.errors.size());
                dialogs.script = (form, save) -> { get(form.component(), "scope.mode.choice", JComboBox.class).setSelectedItem(GuardConfig.DestinationScopeMode.ALL_DESTINATIONS); save.run(); };
                edt(() -> { get(panel.get(), "scope.mode.edit", JButton.class).doClick(0); return null; });
                assertEquals(1, writes.get()); assertEquals("ALL_DESTINATIONS", controller.status().get("destinationScopeMode"));
                assertEquals(initial.allowScope(), controller.config().allowScope()); assertEquals(limits, controller.config().limits());
                assertEquals(before.get("paused"), controller.status().get("paused")); assertEquals(before.get("operatorPaused"), controller.status().get("operatorPaused"));
                assertEquals(before.get("passthrough"), controller.status().get("passthrough")); assertEquals(before.get("intents"), controller.status().get("intents"));
                assertEquals(original, controller.rawRequest(first.evidenceId()));
                if (queued != null) {
                    assertFalse(queued.get(5, TimeUnit.SECONDS).allowed()); assertFalse(ask.get(5, TimeUnit.SECONDS).allowed());
                    assertFalse(controller.authorize(oldPrepared).allowed());
                    var probe = controller.prepare(scopeRuntimeRequest("/rate-debt")); laterQueue = workers.submit(() -> controller.authorize(probe));
                    await(() -> ((Number) ((Map<?, ?>) controller.status().get("gate")).get("queued")).intValue() == 1);
                    assertFalse(laterQueue.isDone(), "saving mode must not erase existing positive rate debt");
                }
                dialogs.script = (form, save) -> { get(form.component(), "scope.mode.choice", JComboBox.class).setSelectedItem(GuardConfig.DestinationScopeMode.ALLOWLIST); save.run(); };
                edt(() -> { get(panel.get(), "scope.mode.edit", JButton.class).doClick(0); return null; });
                assertEquals(2, writes.get()); assertEquals(initial, controller.config());
                assertEquals(before.get("paused"), controller.status().get("paused")); assertEquals(before.get("passthrough"), controller.status().get("passthrough"));
                assertEquals(before.get("intents"), controller.status().get("intents")); assertTrue(controller.approvals().isEmpty());
                if (laterQueue != null) assertFalse(laterQueue.get(5, TimeUnit.SECONDS).allowed());
                controller.response(first.evidenceId(), 200, List.of(new RequestData.Header("Set-Cookie", "synthetic-mode-response")), "complete response".getBytes(java.nio.charset.StandardCharsets.UTF_8), 17);
                assertTrue(controller.rawResponse(first.evidenceId()).contains("synthetic-mode-response"));
                assertEquals(original, controller.rawRequest(first.evidenceId()));
            } finally {
                if (panel.get() != null) edt(() -> { panel.get().close(); return null; });
                controller.close(); workers.close();
            }
        }
    }

    private static final class DestinationDialogs implements GuardPanel.Dialogs {
        final java.util.List<String> errors = new java.util.ArrayList<>();
        java.util.function.BiConsumer<EditorForm<?>, Runnable> script = (form, save) -> fail("unexpected editor");
        @Override public boolean confirm(Component parent, String text) { return true; }
        @Override public Path chooseExport(Component parent, String extension) { fail("not an export test"); return null; }
        @Override public void error(Component parent, String text) { errors.add(text); }
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, java.util.function.Consumer<GuardPanel.SubmitConfirmation> save) { script.accept(form, () -> save.accept((text, confirmLabel) -> confirm(parent, text, confirmLabel))); }
    }

    private static RequestData scopeRuntimeRequest(String path) {
        return new RequestData("GET", "https://example.test" + path, "example.test", 443, true,
                List.of(new RequestData.Header("X-Cairn-Intent", "scope-intent"), new RequestData.Header("X-Cairn-Run", "scope-run")), new byte[0]);
    }

    private static final class ScopeDialogs implements GuardPanel.Dialogs {
        final java.util.List<String> errors = new java.util.ArrayList<>();
        java.util.function.BiConsumer<EditorForm<?>, Runnable> script = (form, save) -> fail("unexpected editor");
        @Override public boolean confirm(Component parent, String text) { fail("unexpected confirmation"); return false; }
        @Override public Path chooseExport(Component parent, String extension) { fail("unexpected chooser"); return null; }
        @Override public void error(Component parent, String text) { errors.add(text); }
        @Override public void edit(Component parent, String title, String label, EditorForm<?> form, java.util.function.Consumer<GuardPanel.SubmitConfirmation> save) { script.accept(form, () -> save.accept((text, confirmLabel) -> confirm(parent, text, confirmLabel))); }
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
