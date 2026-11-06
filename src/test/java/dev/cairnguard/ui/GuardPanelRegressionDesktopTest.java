package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.swing.*;
import javax.swing.text.Document;
import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static dev.cairnguard.ui.GuardPanelTrafficViewTest.await;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;
import static dev.cairnguard.ui.TrafficSearch.Location.*;
import static dev.cairnguard.ui.TrafficSearch.MatchMode.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic originals on an actual isolated Swing display, never native Burp. */
@Tag("desktop") @Timeout(30)
class GuardPanelRegressionDesktopTest {
    @ParameterizedTest @ValueSource(strings = {"metadata-literal", "body-re2", "metadata-re2"})
    void bookmarkingKeepsTheMatchingSelectedRequestInspectable(String searchKind) throws Exception {
        try (View view = new View()) {
            String id = edt(() -> {
                String added = view.source.addRaw("synthetic-intent", "synthetic-run", "forwarded");
                view.panel.refreshNow(); view.get("tabs", JTabbedPane.class).setSelectedIndex(3);
                view.get("traffic.searchLocation", JComboBox.class).setSelectedItem(searchKind.equals("body-re2") ? REQUEST_BODY : METADATA);
                view.get("traffic.searchMode", JComboBox.class).setSelectedItem(searchKind.equals("metadata-literal") ? LITERAL : RE2);
                view.get("traffic.search", JTextField.class).setText(switch (searchKind) {
                    case "metadata-literal" -> "example.test/x?token=";
                    case "body-re2" -> GuardPanelV2Test.SECRET;
                    case "metadata-re2" -> "^https://example[.]test/x[?]token=";
                    default -> throw new AssertionError(searchKind);
                });
                return added;
            });
            await(() -> view.table().getRowCount() == 1 && !view.pending());
            TrafficEntry before = edt(() -> {
                assertTrue(view.frame.isShowing()); assertTrue(view.table().isShowing());
                assertOrdinaryFiltersOff(view);
                view.table().setRowSelectionInterval(0, 0);
                return view.source.rows().getFirst();
            });
            await(() -> view.get("traffic.request", JTextArea.class).getText().contains(GuardPanelV2Test.SECRET));
            edt(() -> {
                assertTrue(view.get("traffic.request", JTextArea.class).isShowing());
                view.get("traffic.bookmark", JButton.class).doClick(0);
                System.out.printf("C9-L1 intermediate kind=%s displayed=%d selected=%d pending=%s%n", searchKind,
                        view.table().getRowCount(), view.table().getSelectedRowCount(), view.pending());
                return null;
            });
            await(() -> view.table().getRowCount() == 1 && !view.pending()
                    && (view.table().getSelectedRowCount() == 0 || view.get("traffic.request", JTextArea.class).getText().contains(GuardPanelV2Test.SECRET)));
            edt(() -> {
                TrafficEntry after = view.source.rows().getFirst();
                String request = view.get("traffic.request", JTextArea.class).getText();
                System.out.printf("C9-L1 final kind=%s id=%s sameId=%s metadataUnchanged=%s entryReplaced=%s requestIdentityUnchanged=%s responseIdentityUnchanged=%s bookmarked=%s displayed=%d selected=%d requestChars=%d hasOriginal=%s pending=%s%n",
                        searchKind, id, id.equals(after.id()), searchableMetadata(before).equals(searchableMetadata(after)), before != after,
                        before.requestCapture() == after.requestCapture(), before.responseCapture() == after.responseCapture(), after.bookmarked(),
                        view.table().getRowCount(), view.table().getSelectedRowCount(), request.length(), request.contains(GuardPanelV2Test.SECRET), view.pending());
                assertOrdinaryFiltersOff(view);
                assertAll(
                        () -> assertEquals(id, after.id()),
                        () -> assertEquals(searchableMetadata(before), searchableMetadata(after)),
                        () -> assertTrue(after.bookmarked(), "the bookmark action itself must succeed"),
                        () -> assertEquals(0, view.source.updates),
                        () -> assertEquals(0, view.source.runtimeCalls),
                        () -> assertEquals(1, view.table().getSelectedRowCount(), "the unchanged final matching evidence must remain selected after bookmarking"),
                        () -> assertTrue(request.contains(GuardPanelV2Test.SECRET), "the final selected request must remain inspectable after bookmarking"));
                return null;
            });
        }
    }

    @ParameterizedTest @ValueSource(strings = {"clear", "project"})
    void literalMetadataEditCannotRepublishSourceRetiredRows(String transition) throws Exception {
        try (View view = new View()) {
            edt(() -> {
                String id = view.addRequest("https://example.test/x?token=retired-needle", Mode.ALLOW);
                view.panel.refreshNow(); view.get("tabs", JTabbedPane.class).setSelectedIndex(3);
                view.get("traffic.searchLocation", JComboBox.class).setSelectedItem(METADATA);
                view.get("traffic.search", JTextField.class).setText("no-match");
                assertEquals(0, view.table().getRowCount()); assertFalse(view.pending());
                if (transition.equals("project")) view.source.project = "next-synthetic-project";
                view.source.store.clear();
                assertEquals(0, view.source.rows().size());
                assertFalse(Boolean.TRUE.equals(view.source.rawCaptureInfo(id).get("available")));
                assertNull(view.source.rawUrl(id));
                System.out.printf("SEARCH-S1 before-edit transition=%s backendRows=0 rawAvailable=false rawUrl=null displayed=0 project=%s%n", transition, view.source.project);
                view.reads.clear();
                view.get("traffic.search", JTextField.class).setText("retired-needle");
                int published = view.table().getRowCount();
                String method = published == 0 ? "" : view.table().getValueAt(0, 2).toString();
                String url = published == 0 ? "" : view.table().getValueAt(0, 3).toString();
                System.out.printf("SEARCH-S1 after-edit transition=%s backendRows=%d displayed=%d method=%s url=%s reads=%s pending=%s%n",
                        transition, view.source.rows().size(), published, method, url, view.reads, view.pending());
                assertFalse(view.pending(), "Metadata/Literal needs no eventual worker publication");
                assertOrdinaryFiltersOff(view);
                view.panel.refreshNow();
                System.out.printf("SEARCH-S1 manual-refresh transition=%s displayed=%d%n", transition, view.table().getRowCount());
                assertEquals(0, view.table().getRowCount(), "manual refresh is the source-membership control");
                assertEquals(0, published, "a new literal filter event must not republish a row after its source membership and raw original are gone");
                return null;
            });
        }
    }

    @Test void sourcePresentRowsRemainMetadataSearchableWhenOnlyRawIsUnavailable() throws Exception {
        try (View view = new View()) {
            edt(() -> {
                String id = view.addRequest("https://example.test/x?token=retired-needle", Mode.ALLOW);
                view.panel.refreshNow(); view.get("tabs", JTabbedPane.class).setSelectedIndex(3);
                view.get("traffic.searchLocation", JComboBox.class).setSelectedItem(METADATA);
                view.get("traffic.search", JTextField.class).setText("no-match");
                assertEquals(0, view.table().getRowCount());
                view.source.rawUnavailable = true;
                view.get("traffic.search", JTextField.class).setText("retired-needle");
                assertEquals(1, view.source.rows().size()); assertEquals(id, view.source.rows().getFirst().id());
                assertFalse(Boolean.TRUE.equals(view.source.rawCaptureInfo(id).get("available")));
                assertEquals(1, view.table().getRowCount(), "raw unavailability alone must not suppress a retained metadata row");
                assertTrue(view.table().getValueAt(0, 3).toString().contains("retired-needle"));
                assertFalse(view.pending());
                System.out.printf("SEARCH-S1 positive-control backendRows=1 rawAvailable=false displayed=%d url=%s%n", view.table().getRowCount(), view.table().getValueAt(0, 3));
                return null;
            });
        }
    }

    @Test void closeBlanksTheActualApprovalDocumentAfterDisposingItsVisibleModal() throws Exception {
        try (View view = new View()) {
            edt(() -> {
                String id = view.addRequest("https://example.test/ask?token=" + GuardPanelV2Test.SECRET, Mode.ASK);
                view.approvals.add(new Pending("synthetic-pending", id, "p", Instant.now().toString(), Instant.now().plusSeconds(120).toString()));
                view.panel.refreshNow(); view.get("tabs", JTabbedPane.class).setSelectedIndex(4);
                view.get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
                assertTrue(view.get("approval.approve", JButton.class).isEnabled());
                SwingUtilities.invokeLater(() -> view.get("approval.review", JButton.class).doClick(0));
                return null;
            });
            await(() -> view.modal() != null);
            JDialog modal = edt(view::modal);
            JTextArea owned = edt(() -> find(modal, "approval.detail", JTextArea.class));
            Document document = edt(owned::getDocument);
            edt(() -> {
                assertTrue(modal.isModal()); assertTrue(modal.isShowing()); assertTrue(owned.isShowing());
                assertTrue(document.getText(0, document.getLength()).contains(GuardPanelV2Test.SECRET));
                System.out.printf("C9-L2 before-close modalShowing=true documentChars=%d hasOriginal=true%n", document.getLength());
                view.panel.close(); return null;
            });
            await(() -> !modal.isShowing() && !modal.isDisplayable());
            edt(() -> {
                System.out.printf("C9-L2 after-close modalShowing=%s modalDisplayable=%s sameDocument=%s documentChars=%d hasOriginal=%s%n",
                        modal.isShowing(), modal.isDisplayable(), document == owned.getDocument(), document.getLength(), document.getText(0, document.getLength()).contains(GuardPanelV2Test.SECRET));
                assertEquals(0, view.source.updates); assertEquals(0, view.source.runtimeCalls);
                assertEquals(0, document.getLength(), "panel close must blank its owned approval document after disposing the review modal");
                return null;
            });
        }
    }

    private static List<String> searchableMetadata(TrafficEntry entry) {
        return List.of(entry.url(), entry.method(), entry.timestamp(), String.valueOf(entry.statusCode()), entry.reason(), entry.id());
    }

    private static void assertOrdinaryFiltersOff(View view) {
        for (String name : List.of("traffic.method", "traffic.status", "traffic.time", "traffic.intent", "traffic.run", "traffic.guardState"))
            assertEquals("", view.get(name, JTextField.class).getText(), name);
        assertEquals(0, view.get("traffic.outcome", JComboBox.class).getSelectedIndex());
        assertEquals(0, view.get("traffic.project", JComboBox.class).getSelectedIndex());
        assertFalse(view.get("traffic.bookmarked", JCheckBox.class).isSelected());
    }

    private static <T> T find(Component root, String name, Class<T> type) {
        return type.cast(java.util.Objects.requireNonNull(GuardPanelV2Test.find(root, name), name));
    }

    private static final class View implements AutoCloseable {
        final GuardPanelV2Test.Access source = new GuardPanelV2Test.Access();
        final List<Pending> approvals = new ArrayList<>();
        final List<String> reads = new ArrayList<>();
        final GuardPanel panel;
        final JFrame frame;

        View() throws Exception {
            assertFalse(GraphicsEnvironment.isHeadless(), "an actual isolated Swing display is required");
            GuardUiAccess observed = (GuardUiAccess) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{GuardUiAccess.class}, (proxy, method, args) -> {
                assertTrue(SwingUtilities.isEventDispatchThread(), method.getName());
                if (method.getName().equals("approvals")) return List.copyOf(approvals);
                if (method.getName().equals("decideApproval")) throw new AssertionError("inspection must never decide an approval");
                Object result;
                try { result = method.invoke(source, args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
                switch (method.getName()) {
                    case "traffic" -> reads.add("traffic=" + ((List<?>) result).size());
                    case "rawCaptureInfo" -> reads.add("rawCaptureInfo=" + ((Map<?, ?>) result).get("available"));
                    case "rawUrl" -> reads.add("rawUrl=" + result);
                    default -> { }
                }
                return result;
            });
            panel = edt(() -> new GuardPanel(observed, new GuardPanel.SwingDialogs(), false));
            frame = edt(() -> {
                JFrame window = new JFrame("Cairn synthetic regression inspection");
                window.setContentPane(panel); window.setSize(1000, 760); window.setVisible(true); return window;
            });
        }

        String addRequest(String url, Mode mode) {
            return source.store.begin("p", "Synthetic", new RequestData("POST", url, "example.test", 443, true,
                    List.of(new RequestData.Header("Authorization", "Bearer " + GuardPanelV2Test.SECRET), new RequestData.Header("Content-Type", "text/plain; charset=UTF-8")),
                    ("synthetic-body " + GuardPanelV2Test.SECRET).getBytes(StandardCharsets.UTF_8)), new Decision(mode, mode == Mode.ASK ? "ASK" : "DEFAULT_ALLOW", List.of()), 7);
        }

        <T> T get(String name, Class<T> type) { return find(panel, name, type); }
        JTable table() { return get("traffic.table", JTable.class); }
        boolean pending() { return get("traffic.count", JLabel.class).getText().contains("pending"); }
        JDialog modal() {
            for (Window window : frame.getOwnedWindows())
                if (window instanceof JDialog dialog && dialog.isShowing() && "editor.dialog".equals(dialog.getName())) return dialog;
            return null;
        }
        @Override public void close() {
            try { edt(() -> { panel.close(); frame.dispose(); return null; }); }
            catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError("owned Swing cleanup interrupted", failure); }
            catch (Exception failure) { throw new AssertionError("owned Swing cleanup failed", failure); }
        }
    }
}
