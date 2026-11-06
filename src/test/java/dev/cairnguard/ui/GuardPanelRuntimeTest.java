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
}
