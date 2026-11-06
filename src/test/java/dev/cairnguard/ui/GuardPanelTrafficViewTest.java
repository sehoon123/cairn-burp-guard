package dev.cairnguard.ui;

import dev.cairnguard.model.*;
import static dev.cairnguard.ui.TrafficSearch.Location.*;
import static dev.cairnguard.ui.TrafficSearch.MatchMode.*;
import org.junit.jupiter.api.*;
import javax.swing.*;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Callable;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;
import static org.junit.jupiter.api.Assertions.*;

/** Retained synthetic originals only; no native Burp or production desktop. */
class GuardPanelTrafficViewTest {
    final GuardPanelV2Test.Access access = new GuardPanelV2Test.Access();
    final GuardPanelV2Test.Human dialogs = new GuardPanelV2Test.Human();
    GuardPanel panel;
    @AfterEach void close() throws Exception { if (panel != null) edt(() -> { panel.close(); return null; }); }
    void open() throws Exception { edt(() -> { panel = new GuardPanel(access, dialogs, false); return null; }); }
    <T> T get(String name, Class<T> type) { return type.cast(GuardPanelV2Test.find(panel, name)); }
    String add(String type, byte[] body) {
        return access.store.begin("p", "Synthetic", new RequestData("POST", "https://example.test/plain", "example.test", 443, true,
                List.of(new RequestData.Header("X-Only-Header", "Header.[Literal]"), new RequestData.Header("Content-Type", type)), body),
                new Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
    }
    @Test void literalRetainedHeadersTextAndDisplayedHexAreSearchable() throws Exception {
        add("text/plain; charset=UTF-8", "body-only-한글.[Literal]".getBytes(StandardCharsets.UTF_8));
        add("application/octet-stream", new byte[]{0x01, (byte)0xab, (byte)0xcd});
        open();
        for (var test : List.of(java.util.Map.entry("header.[literal]", 2), java.util.Map.entry("BODY-only-한글.[literal]", 1),
                java.util.Map.entry("1AbC", 1), java.util.Map.entry("body-only-.*", 0))) {
            edt(() -> { get("traffic.search", JTextField.class).setText(test.getKey()); return null; });
            await(() -> !get("traffic.count", JLabel.class).getText().contains("검색 중"));
            assertEquals(test.getValue(), edt(() -> get("traffic.table", JTable.class).getRowCount()), test.getKey());
        }
    }
    @Test void defaultLiteralMetadataIsImmediateAndRefreshDoesNotRecompileInput() throws Exception {
        add("text/plain", "content".getBytes(StandardCharsets.UTF_8)); open();
        edt(() -> {
            get("traffic.search", JTextField.class).setText("PLAIN");
            assertEquals(1, get("traffic.table", JTable.class).getRowCount(), "default displayed metadata stays immediate");
            Object input = field("searchInput");
            panel.refreshNow(); assertSame(input, field("searchInput"));
            get("traffic.method", JTextField.class).setText("NO-MATCH");
            assertSame(input, field("searchInput")); assertEquals(0, get("traffic.table", JTable.class).getRowCount());
            get("traffic.method", JTextField.class).setText("post"); assertEquals(1, get("traffic.table", JTable.class).getRowCount());
            return null;
        });
    }
    @Test void tableHasInlinePairedResizableInspectorsAndStaticPreviewTab() throws Exception {
        add("text/plain", new byte[0]); open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            assertInstanceOf(JSplitPane.class, SwingUtilities.getAncestorOfClass(JSplitPane.class, table));
            assertNotNull(get("traffic.pair", JSplitPane.class));
            assertNotNull(get("traffic.responseTabs", JTabbedPane.class));
            assertNotNull(get("traffic.preview", JPanel.class));
            assertTrue(table.getColumnCount() > 11); assertTrue(table.getTableHeader().getReorderingAllowed());
            return null;
        });
    }
    @Test void failedRefreshCannotResurrectRetainedPlaintextByTyping() throws Exception {
        access.addRaw("i", "r", "forwarded"); open();
        edt(() -> {
            access.failStatus = true; panel.refreshNow();
            assertEquals(0, get("traffic.table", JTable.class).getRowCount());
            get("traffic.search", JTextField.class).setText("example");
            assertEquals(0, get("traffic.table", JTable.class).getRowCount(), "unavailable source cannot revive old rows");
            return null;
        });
    }
    @Test void identityResponseUpdateLazyPreviewAndUnchangedTicksReuseProjection() throws Exception {
        String id = add("text/plain; charset=UTF-8", "request-original".getBytes(StandardCharsets.UTF_8));
        access.store.response(id, 200, List.of(new RequestData.Header("Content-Type", "text/html")), "<h1>FIRST-RESPONSE</h1>".getBytes(StandardCharsets.UTF_8));
        open(); edt(() -> { get("traffic.table", JTable.class).setRowSelectionInterval(0, 0); return null; });
        await(() -> get("traffic.response", JTextArea.class).getText().contains("FIRST-RESPONSE"));
        Object firstContent = edt(() -> field("presentedContent"));
        edt(() -> { panel.refreshNow(); assertSame(firstContent, field("presentedContent")); assertNull(field("presentedPreview"), "preview is lazy");
            get("traffic.responseTabs", JTabbedPane.class).setSelectedIndex(3); return null; });
        await(() -> get("traffic.preview.document", JPanel.class) != null);
        edt(() -> { Object preview = field("presentedPreview"); panel.refreshNow(); assertSame(preview, field("presentedPreview"));
            access.store.response(id, 200, List.of(new RequestData.Header("Content-Type", "text/html; charset=UTF-8")), "<h1>LATEST-RESPONSE</h1>".getBytes(StandardCharsets.UTF_8)); panel.refreshNow(); return null; });
        await(() -> get("traffic.preview.document", JPanel.class) != null && HtmlPreviewTest.allText(get("traffic.preview.document", JPanel.class)).contains("LATEST-RESPONSE"));
        edt(() -> { assertFalse(get("traffic.response", JTextArea.class).getText().contains("FIRST-RESPONSE")); assertNotSame(firstContent, field("presentedContent")); return null; });
    }
    @Test void currentSortedFilteredViewOrderSteppingAndIndependentPopoutDisposal() throws Exception {
        for (String path : List.of("/c", "/a", "/b")) access.store.begin("p", "Synthetic", new RequestData("GET", "https://example.test" + path, "example.test", 443, true, List.of(new RequestData.Header("X-Secret", path)), new byte[0]), new Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
        open();
        edt(() -> { JTable table = get("traffic.table", JTable.class); table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING))); table.setRowSelectionInterval(0, 0); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("/a"));
        final TrafficInspector[] owned = new TrafficInspector[1];
        dialogs.edit = (form, save) -> {
            TrafficInspector popout = (TrafficInspector) form.component(); owned[0] = popout;
            assertNotSame(get("traffic.request", JTextArea.class), popout.request); assertNotSame(get("traffic.request", JTextArea.class).getDocument(), popout.request.getDocument());
            assertTrue(popout.request.getText().contains("/a"));
            ((JButton) GuardPanelV2Test.find(popout, "traffic.next")).doClick(0);
            assertTrue(get("traffic.table", JTable.class).getValueAt(1, 3).toString().endsWith("/b"));
            get("traffic.table", JTable.class).getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.DESCENDING)));
            ((JButton) GuardPanelV2Test.find(popout, "traffic.next")).doClick(0);
            assertTrue(get("traffic.table", JTable.class).getValueAt(get("traffic.table", JTable.class).getSelectedRow(), 3).toString().endsWith("/a"));
        };
        edt(() -> { get("traffic.detail", JButton.class).doClick(0); assertEquals("", owned[0].request.getText()); assertNull(owned[0].getParent()); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("/a"));
        edt(() -> { get("traffic.method", JTextField.class).setText("NO-MATCH"); assertEquals("", get("traffic.request", JTextArea.class).getText()); assertFalse(get("traffic.next", JButton.class).isEnabled()); return null; });
    }
    private void addAnchorRows() {
        for (String path : List.of("/a", "/b", "/c")) {
            String id = access.store.begin("p", "Synthetic", new RequestData("GET", "https://example.test" + path, "example.test", 443, true,
                    List.of(new RequestData.Header("Content-Type", "text/plain")), ("anchor-original-" + path).getBytes(StandardCharsets.UTF_8)), new Decision(GuardConfig.Mode.BLOCK, "RULE_BLOCK", List.of()), 7);
            access.store.outcome(id, "BLOCKED", path.equals("/c") ? "SCOPE_NOT_ALLOWED" : "RULE_BLOCK", 451);
        }
    }
    @Test void multiselectedLeadIsTheDisplayedPopoutResolveAndNavigationAnchor() throws Exception {
        addAnchorRows(); open();
        edt(() -> { JTable table = get("traffic.table", JTable.class); table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING)));
            table.setRowSelectionInterval(0, 0); table.addRowSelectionInterval(2, 2); assertEquals(2, table.getSelectionModel().getLeadSelectionIndex()); return null; });
        await(() -> get("traffic.request", JTextArea.class).getDocument().getLength() > 0);
        edt(() -> {
            String id = access.rows().stream().filter(e -> e.url().endsWith("/c")).findFirst().orElseThrow().id();
            assertTrue(get("traffic.request", JTextArea.class).getText().contains("anchor-original-/c"));
            assertTrue(get("traffic.metadata", JTextArea.class).getText().contains(id));
            assertTrue(get("traffic.previous", JButton.class).isEnabled()); assertFalse(get("traffic.next", JButton.class).isEnabled());
            dialogs.edit = (form, save) -> assertTrue(((TrafficInspector) form.component()).request.getText().contains("anchor-original-/c"));
            get("traffic.detail", JButton.class).doClick(0); get("traffic.resolve", JButton.class).doClick(0);
            assertEquals(1, get("tabs", JTabbedPane.class).getSelectedIndex(), "resolve must use the same scope-denied lead, not the first rule-denied selection");
            assertArrayEquals(new int[]{0, 2}, get("traffic.table", JTable.class).getSelectedRows());
            get("traffic.previous", JButton.class).doClick(0); assertArrayEquals(new int[]{1}, get("traffic.table", JTable.class).getSelectedRows()); return null;
        });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("anchor-original-/b"));
    }
    @Test void multiselectedLeadIdentitySurvivesRefreshSortAndBookmarkMembership() throws Exception {
        addAnchorRows(); open();
        edt(() -> { JTable table = get("traffic.table", JTable.class); table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING)));
            table.setRowSelectionInterval(0, 0); table.addRowSelectionInterval(2, 2); get("traffic.bookmark", JButton.class).doClick(0);
            assertEquals(2, table.getSelectedRowCount()); assertEquals(2, table.getSelectionModel().getLeadSelectionIndex());
            assertEquals(2, access.rows().stream().filter(e -> e.bookmarked()).count());
            table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.DESCENDING))); panel.refreshNow();
            assertEquals(0, table.getSelectionModel().getLeadSelectionIndex(), "lead /c must survive in descending current order"); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("anchor-original-/c"));
        edt(() -> { assertFalse(get("traffic.previous", JButton.class).isEnabled()); assertTrue(get("traffic.next", JButton.class).isEnabled()); get("traffic.next", JButton.class).doClick(0); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("anchor-original-/b"));
    }
    @Test void latestSelectionClearProjectFailureAndCloseCannotPublishRetiredWork() throws Exception {
        for (String transition : List.of("selection", "clear", "external-clear", "project", "failure", "close")) {
            access.failStatus = false; access.project = "p"; access.store.clear();
            String first = access.addRaw("i", "r", "forwarded"); open();
            TrafficSearch.Pump pump = edt(() -> (TrafficSearch.Pump) field("presentation"));
            var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
            pump.submit(cancelled -> { entered.countDown(); while (release.getCount() > 0) try { release.await(); } catch (InterruptedException ignored) {} return "obsolete"; }, r -> fail("retired publication"));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            try {
                edt(() -> { get("traffic.table", JTable.class).setRowSelectionInterval(0, 0);
                    switch (transition) {
                        case "selection" -> { access.store.begin("p", "Synthetic", new RequestData("GET", "https://example.test/new-selected", "example.test", 443, true, List.of(), new byte[0]), new Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7); panel.refreshNow(); get("traffic.table", JTable.class).setRowSelectionInterval(0, 0); }
                        case "clear" -> get("settings.clear", JButton.class).doClick(0);
                        case "external-clear" -> access.store.clear(); // no refresh: publication must re-read the source
                        case "project" -> { access.project = "new-project"; access.store.clear(); }
                        case "failure" -> access.failStatus = true;
                        case "close" -> panel.close();
                        default -> throw new AssertionError();
                    } return null; });
            } finally { release.countDown(); }
            if (transition.equals("selection")) await(() -> get("traffic.request", JTextArea.class).getText().contains("new-selected"));
            else if (!transition.equals("close")) await(() -> get("traffic.table", JTable.class).getRowCount() == 0);
            edt(() -> { assertFalse(get("traffic.request", JTextArea.class).getText().contains(GuardPanelV2Test.SECRET), transition); panel.close(); return null; });
            assertTrue(pump.awaitExit(5000)); assertFalse(pump.retainsPending());
            TrafficSearch.Session session = edt(() -> (TrafficSearch.Session) field("contentSearch")); assertTrue(session.awaitExit(5000));
        }
    }
    @Test void pendingQueryCoalescesAndExportConsentKeepsClickTimeIncompleteNotice() throws Exception {
        add("text/plain; charset=UTF-8", "last-query-only".getBytes(StandardCharsets.UTF_8)); open();
        var session = edt(() -> (TrafficSearch.Session) field("contentSearch"));
        var pf = TrafficSearch.Session.class.getDeclaredField("pump"); pf.setAccessible(true); TrafficSearch.Pump pump = (TrafficSearch.Pump) pf.get(session);
        var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
        pump.submit(c -> { entered.countDown(); while (release.getCount() > 0) try { release.await(); } catch (InterruptedException ignored) {} return null; }, r -> fail("stale"));
        assertTrue(entered.await(5, TimeUnit.SECONDS));
        try {
            edt(() -> { for (String query : List.of("old-query", "last-query-only", "plain")) get("traffic.search", JTextField.class).setText(query);
                assertTrue(get("traffic.count", JLabel.class).getText().contains("pending")); assertEquals(1, get("traffic.table", JTable.class).getRowCount()); return null; });
            dialogs.target = java.nio.file.Files.createTempFile("cairn-owned-export-", ".json");
            try {
                edt(() -> { get("traffic.export", JButton.class).doClick(0); assertTrue(dialogs.confirmations.getLast().contains("results incomplete")); return null; });
                release.countDown(); await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
                await(() -> field("exportWorker") == null);
                edt(() -> { get("traffic.search", JTextField.class).setText("last-query-only"); return null; });
                await(() -> !get("traffic.count", JLabel.class).getText().contains("pending")); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
            } finally { java.nio.file.Files.deleteIfExists(dialogs.target); }
        } finally { release.countDown(); }
    }
    @Test void historyNeverCallsWholeRawGettersOrAccessOffEdtAndColumnsAreTyped() throws Exception {
        String id = access.addRaw("i", "r", "forwarded");
        GuardUiAccess checked = (GuardUiAccess) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{GuardUiAccess.class}, (proxy, method, args) -> {
            assertTrue(SwingUtilities.isEventDispatchThread(), method.getName());
            assertFalse(method.getName().equals("rawRequest") || method.getName().equals("rawResponse"), "history must use immutable Messages");
            try { return method.invoke(access, args); } catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
        });
        edt(() -> { panel = new GuardPanel(checked, dialogs, false); get("traffic.table", JTable.class).setRowSelectionInterval(0, 0); get("traffic.search", JTextField.class).setText("response"); return null; });
        await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
        edt(() -> { JTable table = get("traffic.table", JTable.class); assertEquals(Long.class, table.getColumnClass(11)); assertInstanceOf(Long.class, table.getValueAt(0, 11)); assertTrue(table.getValueAt(0, 15).toString().contains("UTF8_TEXT")); panel.refreshNow(); return null; });
        assertEquals(id, access.rows().getFirst().id());
        search("response", RESPONSE_BODY, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        search("example", METADATA, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
    }
    @Test void clearingOrReplacingPreviewBlanksDetachedDocumentsHeldByAWindowObserver() throws Exception {
        var projection = HtmlPreview.scan("<h1>synthetic-preview-plaintext</h1><table><tr><td>cell-secret</td></tr></table>", () -> false);
        edt(() -> {
            TrafficInspector inspector = new TrafficInspector(() -> {}, () -> {}, () -> {});
            inspector.preview(projection);
            JPanel oldRoot = (JPanel) GuardPanelV2Test.find(inspector, "traffic.preview.document");
            JTextPane retainedHeading = (JTextPane) GuardPanelV2Test.find(oldRoot, "traffic.preview.h1");
            assertTrue(retainedHeading.getText().contains("synthetic-preview-plaintext"));
            inspector.previewMessage("source unavailable");
            assertEquals("", retainedHeading.getText(), "a detached preview document must not retain disposed-window plaintext");
            inspector.preview(projection);
            JPanel clearRoot = (JPanel) GuardPanelV2Test.find(inspector, "traffic.preview.document");
            JTextPane retainedCell = (JTextPane) GuardPanelV2Test.find(clearRoot, "traffic.preview.p");
            assertTrue(retainedCell.getText().contains("cell-secret")); inspector.clear("");
            assertEquals("", retainedCell.getText()); return null;
        });
    }
    void search(String text, TrafficSearch.Location location, TrafficSearch.MatchMode mode) throws Exception {
        edt(() -> {
            get("traffic.searchLocation", JComboBox.class).setSelectedItem(location);
            get("traffic.searchMode", JComboBox.class).setSelectedItem(mode);
            get("traffic.search", JTextField.class).setText(text); return null;
        });
        await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
    }
    String row(String path, String header, String body) {
        return access.store.begin("p", "Synthetic", new RequestData("POST", "https://example.test" + path, "example.test", 443, true,
                List.of(new RequestData.Header("X-Search", header), new RequestData.Header("Content-Type", "text/plain; charset=UTF-8")), body.getBytes(StandardCharsets.UTF_8)),
                new Decision(GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
    }
    @Test void selectorsCoverAllLocationsAndModesWithLiteralAndFiltersAndAccessibleLabels() throws Exception {
        for (int i = 0; i < 5; i++) {
            String id = row(i == 0 ? "/needle-metadata-end" : "/case-" + i, i == 1 ? "needle-header-end" : "other-header", i == 2 ? "needle-request-end" : "other-body");
            access.store.response(id, 200, List.of(new RequestData.Header("X-Response", i == 3 ? "needle-header-end" : "other-response")),
                    (i == 4 ? "needle-response-end" : "other-response-body").getBytes(StandardCharsets.UTF_8));
        }
        open();
        edt(() -> {
            assertFalse(get("traffic.more", JCheckBox.class).isSelected());
            for (String name : List.of("traffic.search", "traffic.searchLocation", "traffic.searchMode")) {
                JComponent control = get(name, JComponent.class); assertTrue(control.isVisible()); assertTrue(control.isFocusable());
                assertSame(control, get(name + ".label", JLabel.class).getLabelFor()); assertEquals(Boolean.TRUE, control.getClientProperty("html.disable"));
            }
            assertEquals(ALL, get("traffic.searchLocation", JComboBox.class).getSelectedItem()); assertEquals(LITERAL, get("traffic.searchMode", JComboBox.class).getSelectedItem()); return null;
        });
        for (var mode : TrafficSearch.MatchMode.values()) for (var location : TrafficSearch.Location.values()) {
            search("needle", location, mode);
            assertEquals(location == ALL ? 5 : 1, edt(() -> get("traffic.table", JTable.class).getRowCount()), location + " " + mode);
        }
        search("needle.*end", REQUEST_BODY, LITERAL); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        search("needle.*end", REQUEST_BODY, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        edt(() -> { get("traffic.method", JTextField.class).setText("P.*"); assertEquals(0, get("traffic.table", JTable.class).getRowCount(), "dedicated filters never become regex");
            get("traffic.method", JTextField.class).setText("post"); assertEquals(1, get("traffic.table", JTable.class).getRowCount()); return null; });
        search(" needle", REQUEST_BODY, LITERAL); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()), "whitespace is query data");
        edt(() -> { get("traffic.reset", JButton.class).doClick(0); assertEquals("", get("traffic.search", JTextField.class).getText());
            assertEquals(ALL, get("traffic.searchLocation", JComboBox.class).getSelectedItem()); assertEquals(LITERAL, get("traffic.searchMode", JComboBox.class).getSelectedItem());
            assertEquals(5, get("traffic.table", JTable.class).getRowCount()); assertFalse(get("traffic.searchError", JTextArea.class).isVisible()); return null; });
    }
    @Test void metadataModeKeepsTheExistingValuesAndDoesNotSearchOtherDisplayedFields() throws Exception {
        String id = access.addRaw("unique-intent", "unique-run", "forwarded"); open();
        for (String text : List.of("unique-intent", "unique-run", "PROTECTED", "UNSUPPORTED_CHARSET", "inspection copy", "HUMAN_ORIGINAL")) {
            search(text, METADATA, LITERAL); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()), text);
        }
        for (String text : List.of(GuardPanelV2Test.SECRET, "POST", "200", "NATIVE_RELEASED", UiText.reason("NATIVE_RELEASED"), id)) {
            search(text, METADATA, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()), text);
        }
        edt(() -> { access.rawUnavailable = true; panel.refreshNow(); return null; });
        search("원문 없음", METADATA, LITERAL); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
    }
    @Test void invalidRe2ClearsRowsSelectionPlaintextAndExportWithoutFallbackOrRawDiagnostics() throws Exception {
        access.addRaw("i", "r", "forwarded"); open();
        edt(() -> { get("traffic.table", JTable.class).setRowSelectionInterval(0, 0); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains(GuardPanelV2Test.SECRET));
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("cairn-invalid-search-"); dialogs.target = directory.resolve("must-not-exist.json");
        try {
            String fixed = null;
            for (String pattern : List.of("[", "(?=synthetic-pattern-must-not-escape)", "(a)\\1")) {
                search(pattern, ALL, RE2);
                String error = edt(() -> get("traffic.searchError", JTextArea.class).getText());
                if (fixed == null) fixed = error; else assertEquals(fixed, error);
                assertTrue(error.contains("BAD_RE2")); assertFalse(error.contains("synthetic-pattern"));
                edt(() -> {
                    assertTrue(get("traffic.searchError", JTextArea.class).isVisible()); assertTrue(get("traffic.searchError", JTextArea.class).getLineWrap());
                    assertEquals(0, get("traffic.table", JTable.class).getRowCount()); assertEquals(0, get("traffic.table", JTable.class).getSelectedRowCount());
                    for (String name : List.of("traffic.request", "traffic.response", "traffic.metadata")) assertEquals("", get(name, JTextArea.class).getText());
                    assertFalse(((TrafficSearch.Session) field("contentSearch")).pending()); Object input = field("searchInput");
                    panel.refreshNow(); assertSame(input, field("searchInput")); assertEquals(0, get("traffic.table", JTable.class).getRowCount());
                    int confirmations = dialogs.confirmations.size(); get("traffic.export", JButton.class).doClick(0); assertEquals(confirmations, dialogs.confirmations.size()); return null;
                });
                assertFalse(java.nio.file.Files.exists(dialogs.target)); assertEquals(1, access.rows().size(), "search never clears retained originals");
            }
            search("(abc){1000}", ALL, RE2); assertTrue(edt(() -> get("traffic.searchError", JTextArea.class).getText().contains("TOO_COMPLEX")));
            search("synthetic", REQUEST_BODY, LITERAL); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
            assertEquals("", edt(() -> get("traffic.searchError", JTextArea.class).getText())); assertEquals(0, access.updates); assertEquals(0, access.runtimeCalls);
        } finally { java.nio.file.Files.deleteIfExists(dialogs.target); java.nio.file.Files.delete(directory); }
    }
    @Test void oversizedRejectedEditStaysInvalidAcrossRefreshUntilAnActualEditSelectorChangeOrReset() throws Exception {
        add("text/plain", "body".getBytes(StandardCharsets.UTF_8)); open(); search("plain", ALL, LITERAL);
        edt(() -> {
            JTextField input = get("traffic.search", JTextField.class); input.getDocument().insertString(input.getDocument().getLength(), "a".repeat(4097), null);
            assertEquals("plain", input.getText(), "rejection must not truncate the attempted edit");
            assertSame(TrafficSearch.Invalid.TOO_LONG, field("searchInput")); assertTrue(get("traffic.searchError", JTextArea.class).getText().contains("TOO_LONG"));
            panel.refreshNow(); get("traffic.method", JTextField.class).setText("POST"); panel.refreshNow();
            get("traffic.searchLocation", JComboBox.class).setSelectedItem(ALL); get("traffic.searchMode", JComboBox.class).setSelectedItem(LITERAL);
            assertSame(TrafficSearch.Invalid.TOO_LONG, field("searchInput")); assertEquals(0, get("traffic.table", JTable.class).getRowCount());
            get("traffic.searchLocation", JComboBox.class).setSelectedItem(METADATA); assertEquals(1, get("traffic.table", JTable.class).getRowCount());
            input.getDocument().insertString(0, "a".repeat(4097), null); input.getDocument().remove(0, 1);
            assertInstanceOf(TrafficSearch.CompiledQuery.class, field("searchInput")); assertEquals("lain", input.getText());
            get("traffic.reset", JButton.class).doClick(0); input.getDocument().insertString(0, "a".repeat(4097), null);
            assertEquals("", input.getText()); assertSame(TrafficSearch.Invalid.TOO_LONG, field("searchInput"));
            get("traffic.reset", JButton.class).doClick(0); assertEquals(ALL, get("traffic.searchLocation", JComboBox.class).getSelectedItem());
            assertEquals(LITERAL, get("traffic.searchMode", JComboBox.class).getSelectedItem()); assertEquals(1, get("traffic.table", JTable.class).getRowCount());
            assertEquals("", get("traffic.searchError", JTextArea.class).getText());
            input.setText("a".repeat(4096)); assertEquals(4096, input.getText().length()); assertInstanceOf(TrafficSearch.CompiledQuery.class, field("searchInput"));
            access.failStatus = true; panel.refreshNow(); input.getDocument().insertString(0, "too long", null);
            get("traffic.searchMode", JComboBox.class).setSelectedItem(RE2); assertEquals(0, get("traffic.table", JTable.class).getRowCount());
            panel.close(); input.setText("plain"); get("traffic.searchLocation", JComboBox.class).setSelectedItem(ALL); assertEquals(0, get("traffic.table", JTable.class).getRowCount()); return null;
        });
    }
    private record SearchHold(TrafficSearch.Pump pump, java.util.concurrent.CountDownLatch release) implements AutoCloseable {
        @Override public void close() { release.countDown(); }
    }
    SearchHold holdSearch() throws Exception {
        var session = edt(() -> (TrafficSearch.Session) field("contentSearch"));
        var f = TrafficSearch.Session.class.getDeclaredField("pump"); f.setAccessible(true); var pump = (TrafficSearch.Pump) f.get(session);
        var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
        pump.submit(c -> { entered.countDown(); while (release.getCount() > 0) try { release.await(); } catch (InterruptedException ignored) {} return null; }, r -> fail("retired search publication"));
        assertTrue(entered.await(5, TimeUnit.SECONDS)); return new SearchHold(pump, release);
    }
    @Test void advancedMetadataRunsInTheExistingWorkerAndRapidSelectorsPublishOnlyTheLatestQuery() throws Exception {
        row("/metadata-hit", "header-only", "body-only"); open();
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                get("traffic.search", JTextField.class).setText("metadata-hit"); assertEquals(1, get("traffic.table", JTable.class).getRowCount(), "literal metadata is immediate");
                get("traffic.searchLocation", JComboBox.class).setSelectedItem(METADATA); assertFalse(((TrafficSearch.Session) field("contentSearch")).pending(), "metadata-only literal search has no content-pending state");
                get("traffic.searchMode", JComboBox.class).setSelectedItem(RE2); assertEquals(0, get("traffic.table", JTable.class).getRowCount(), "RE2 metadata waits for the existing Pump, never EDT matching");
                assertTrue(get("traffic.count", JLabel.class).getText().contains("pending"));
                for (var location : TrafficSearch.Location.values()) get("traffic.searchLocation", JComboBox.class).setSelectedItem(location);
                get("traffic.searchLocation", JComboBox.class).setSelectedItem(REQUEST_BODY); get("traffic.search", JTextField.class).setText("body-only"); return null;
            });
        }
        await(() -> !get("traffic.count", JLabel.class).getText().contains("pending")); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        edt(() -> { assertEquals(REQUEST_BODY, get("traffic.searchLocation", JComboBox.class).getSelectedItem()); assertEquals("body-only", get("traffic.search", JTextField.class).getText()); return null; });
    }
    @Test void re2NeverJoinsMetadataHeadersBodiesOrRequestResponseAndUnpairedRowsHaveNoRequestBody() throws Exception {
        String source = row("/boundary", "request-start", "request-body-start");
        access.store.response(source, 200, List.of(new RequestData.Header("Duplicate", "one"), new RequestData.Header("Duplicate", "two")), "response-end".getBytes(StandardCharsets.UTF_8));
        access.store.unpairedResponse(source, 200, List.of(new RequestData.Header("X-Unpaired", "retained")), "response-only".getBytes(StandardCharsets.UTF_8), 13, true, true);
        open();
        for (String pattern : List.of("(?s)request-start.*request-body-start", "(?s)request-body-start.*response-end", "(?s)one.*Duplicate")) {
            search(pattern, ALL, RE2); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()), pattern);
        }
        search("(?s)example.test.*POST", METADATA, RE2); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        search("response-only", REQUEST_BODY, RE2); assertEquals(0, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        search("response-only", RESPONSE_BODY, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        search("^", REQUEST_BODY, RE2); assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()), "zero width is not proof of the unpaired row's missing request");
    }
    @Test void scopedSearchCannotRestoreRetiredRowsOrPlaintextAcrossSourceAndLifecycleTransitions() throws Exception {
        for (String transition : List.of("clear", "external-clear", "project", "revision", "raw-loss", "failure", "close")) {
            access.failStatus = false; access.rawUnavailable = false; access.project = "p"; access.store.clear(); row("/source", "old-header", "retired-body"); open();
            TrafficSearch.Session session = edt(() -> (TrafficSearch.Session) field("contentSearch"));
            SearchHold hold = holdSearch();
            try {
                edt(() -> {
                    get("traffic.searchLocation", JComboBox.class).setSelectedItem(REQUEST_BODY); get("traffic.searchMode", JComboBox.class).setSelectedItem(RE2);
                    get("traffic.search", JTextField.class).setText("retired-body"); assertTrue(session.pending());
                    switch (transition) {
                        case "clear" -> get("settings.clear", JButton.class).doClick(0);
                        case "external-clear" -> access.store.clear();
                        case "project" -> { access.project = "next-project"; access.store.clear(); }
                        case "revision" -> { access.revision++; access.store.clear(); }
                        case "raw-loss" -> access.rawUnavailable = true;
                        case "failure" -> access.failStatus = true;
                        case "close" -> panel.close();
                        default -> throw new AssertionError();
                    } return null;
                });
            } finally { hold.close(); }
            if (!transition.equals("close")) await(() -> !session.pending() && get("traffic.table", JTable.class).getRowCount() == 0);
            edt(() -> { assertEquals(0, get("traffic.table", JTable.class).getRowCount(), transition); assertEquals("", get("traffic.request", JTextArea.class).getText()); panel.close(); return null; });
            assertTrue(session.awaitExit(5000)); assertFalse(hold.pump().retainsPending());
        }
    }
    @Test void failedUnchangedSearchKeepsOnlyKnownSameQueryHitsAndDoesNotRetryOnTimer() throws Exception {
        row("/first", "header", "hit-first"); open(); search("hit", REQUEST_BODY, RE2);
        assertEquals(1, edt(() -> get("traffic.table", JTable.class).getRowCount()));
        com.google.re2j.Pattern broken = org.mockito.Mockito.mock(com.google.re2j.Pattern.class);
        org.mockito.Mockito.when(broken.matcher(org.mockito.ArgumentMatchers.any(CharSequence.class))).thenThrow(new IllegalStateException("synthetic-error-must-not-escape"));
        edt(() -> {
            var pattern = TrafficSearch.CompiledQuery.class.getDeclaredField("pattern"); pattern.setAccessible(true); pattern.set(field("searchInput"), broken);
            row("/second", "header", "hit-second"); panel.refreshNow(); return null;
        });
        await(() -> get("traffic.count", JLabel.class).getText().contains("search failed"));
        edt(() -> {
            assertEquals(1, get("traffic.table", JTable.class).getRowCount()); panel.refreshNow(); panel.refreshNow();
            assertEquals(1, get("traffic.table", JTable.class).getRowCount()); assertFalse(get("traffic.count", JLabel.class).getText().contains("synthetic-error")); return null;
        });
        org.mockito.Mockito.verify(broken, org.mockito.Mockito.times(1)).matcher(org.mockito.ArgumentMatchers.any(CharSequence.class));
        search("hit", REQUEST_BODY, LITERAL); assertEquals(2, edt(() -> get("traffic.table", JTable.class).getRowCount()));
    }
    static void settleInModalLoop(Callable<Boolean> condition) throws Exception {
        java.awt.SecondaryLoop loop = java.awt.Toolkit.getDefaultToolkit().getSystemEventQueue().createSecondaryLoop();
        var failure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        Timer poll = new Timer(10, e -> { try { if (condition.call()) loop.exit(); } catch (Throwable error) { failure.set(error); loop.exit(); } });
        Timer timeout = new Timer(5000, e -> { failure.set(new AssertionError("owned consent search did not settle")); loop.exit(); }); timeout.setRepeats(false);
        poll.start(); timeout.start();
        try { assertTrue(loop.enter()); } finally { poll.stop(); timeout.stop(); }
        if (failure.get() != null) throw new AssertionError(failure.get()); assertTrue(condition.call());
    }
    @Test void jsonAndHarFreezeVisibleOrSelectedIdsAndIncompleteConsentAcrossCompletionAndSelectorEdits() throws Exception {
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("cairn-frozen-search-export-");
        try {
            for (boolean har : List.of(false, true)) for (boolean selected : List.of(false, true)) for (boolean chooser : List.of(false, true)) {
                access.store.clear(); String a = row("/match-a", "original-a", "original-body-a"), b = row("/match-b", "original-b", "original-body-b");
                row("/eventual", "eventual-header", "match-eventual");
                var onChoose = new java.util.concurrent.atomic.AtomicReference<Runnable>(() -> {});
                GuardPanel.Dialogs wrapped = (GuardPanel.Dialogs) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{GuardPanel.Dialogs.class}, (proxy, method, args) -> {
                    if (method.getName().equals("chooseExport")) onChoose.get().run();
                    try { return method.invoke(dialogs, args); } catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
                });
                edt(() -> { panel = new GuardPanel(access, wrapped, false); return null; });
                try (SearchHold hold = holdSearch()) {
                    edt(() -> {
                        get("traffic.search", JTextField.class).setText("match"); assertEquals(2, get("traffic.table", JTable.class).getRowCount());
                        assertTrue(get("traffic.count", JLabel.class).getText().contains("pending"));
                        JTable table = get("traffic.table", JTable.class); table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING))); table.setRowSelectionInterval(1, 1);
                        get("traffic.exportRange", JComboBox.class).setSelectedIndex(selected ? 1 : 0); get("traffic.exportFormat", JComboBox.class).setSelectedIndex(har ? 1 : 0); return null;
                    });
                    dialogs.target = directory.resolve("frozen-" + har + "-" + selected + "-" + chooser + (har ? ".har" : ".json"));
                    Runnable changeSearch = () -> {
                        try {
                            hold.close(); settleInModalLoop(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
                            assertEquals(3, get("traffic.table", JTable.class).getRowCount(), "completion during consent adds a later match only to the live table");
                            get("traffic.searchLocation", JComboBox.class).setSelectedItem(RESPONSE_BODY); get("traffic.searchMode", JComboBox.class).setSelectedItem(RE2);
                            assertEquals(0, get("traffic.table", JTable.class).getRowCount());
                        } catch (Exception error) { throw new AssertionError(error); }
                    };
                    if (chooser) onChoose.set(changeSearch); else dialogs.onConfirm = changeSearch;
                    edt(() -> { get("traffic.export", JButton.class).doClick(0); return null; });
                    await(() -> field("exportWorker") == null);
                    var json = Json.MAPPER.readTree(java.nio.file.Files.readString(dialogs.target)); var entries = har ? json.path("log").path("entries") : json.path("entries");
                    java.util.Set<String> exported = new java.util.HashSet<>(); entries.forEach(e -> exported.add((har ? e.path("_cairnGuard") : e).path("evidenceId").asText()));
                    assertEquals(selected ? java.util.Set.of(b) : java.util.Set.of(a, b), exported); assertEquals(selected ? 1 : 2, entries.size());
                    String consent = dialogs.confirmations.getLast(); assertTrue(consent.contains("results incomplete")); assertTrue(consent.contains("Authorization") && consent.contains("평문"));
                    String original = java.nio.file.Files.readString(dialogs.target); assertTrue(original.contains("original-b")); assertFalse(original.contains("match-eventual"));
                    assertFalse(access.exportOnEdt); assertTrue(dialogs.errors.isEmpty());
                } finally { dialogs.onConfirm = () -> {}; edt(() -> { panel.close(); return null; }); }
            }
        } finally { try (var files = java.nio.file.Files.list(directory)) { for (var file : files.toList()) java.nio.file.Files.delete(file); } java.nio.file.Files.delete(directory); }
    }
    Object field(String name) throws Exception { var f = GuardPanel.class.getDeclaredField(name); f.setAccessible(true); return f.get(panel); }
    static void await(Callable<Boolean> condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (System.nanoTime() < deadline) { if (edt(condition)) return; Thread.sleep(10); }
        fail("owned asynchronous UI work did not settle");
    }

    String selectMetadataAnchor() throws Exception {
        addAnchorRows(); open(); search("^https://example[.]test/[abc]$", METADATA, RE2);
        return edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING)));
            table.setRowSelectionInterval(2, 2);
            return access.rows().stream().filter(e -> e.url().endsWith("/c")).findFirst().orElseThrow().id();
        });
    }

    @Test void pendingMetadataReplacementRestoresSortedMultiselectionLeadButExportsOnlySelectedVisibleRows() throws Exception {
        String c = selectMetadataAnchor();
        String a = access.rows().stream().filter(e -> e.url().endsWith("/a")).findFirst().orElseThrow().id();
        edt(() -> { JTable table = get("traffic.table", JTable.class); table.setRowSelectionInterval(0, 0); table.addRowSelectionInterval(2, 2); return null; });
        await(() -> get("traffic.request", JTextArea.class).getText().contains("anchor-original-/c"));
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("cairn-pending-selection-");
        dialogs.target = directory.resolve("selected-visible.json");
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                access.store.bookmark(c, true); panel.refreshNow();
                JTable table = get("traffic.table", JTable.class);
                assertEquals(2, table.getRowCount()); assertArrayEquals(new int[]{0}, table.getSelectedRows());
                assertTrue(get("traffic.count", JLabel.class).getText().contains("pending"));
                assertFalse(get("traffic.request", JTextArea.class).getText().contains("anchor-original-/c"), "unverified intent cannot inspect the hidden lead");
                table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.DESCENDING)));
                assertArrayEquals(new int[]{1}, table.getSelectedRows());
                assertEquals(1, table.getSelectionModel().getLeadSelectionIndex());
                assertFalse(get("traffic.next", JButton.class).isEnabled(), "navigation cannot step to the hidden /c intent");
                get("traffic.resolve", JButton.class).doClick(0);
                assertEquals(2, get("tabs", JTabbedPane.class).getSelectedIndex(), "resolve uses the visible rule-denied /a, not the hidden scope-denied /c");
                get("traffic.exportRange", JComboBox.class).setSelectedIndex(1); get("traffic.export", JButton.class).doClick(0); return null;
            });
            await(() -> field("exportWorker") == null);
            var entries = Json.MAPPER.readTree(java.nio.file.Files.readString(dialogs.target)).path("entries");
            assertEquals(1, entries.size()); assertEquals(a, entries.get(0).path("evidenceId").asText());
            assertFalse(java.nio.file.Files.readString(dialogs.target).contains(c));
            assertTrue(dialogs.confirmations.getLast().contains("results incomplete"));
            hold.close();
            await(() -> !get("traffic.count", JLabel.class).getText().contains("pending")
                    && get("traffic.request", JTextArea.class).getText().contains("anchor-original-/c"));
            edt(() -> {
                JTable table = get("traffic.table", JTable.class);
                assertEquals(3, table.getRowCount()); assertArrayEquals(new int[]{0, 2}, table.getSelectedRows());
                assertEquals(0, table.getSelectionModel().getLeadSelectionIndex(), "the original /c lead returns in current descending order");
                assertFalse(get("traffic.previous", JButton.class).isEnabled()); assertTrue(get("traffic.next", JButton.class).isEnabled());
                assertTrue(get("traffic.metadata", JTextArea.class).getText().contains(c)); return null;
            });
            assertTrue(dialogs.errors.isEmpty()); assertEquals(0, access.updates); assertEquals(0, access.runtimeCalls);
        } finally { java.nio.file.Files.deleteIfExists(dialogs.target); java.nio.file.Files.delete(directory); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"selection", "navigation", "deselection", "dedicated-filter", "query-edit", "invalid-input", "bookmark-filter"})
    void newerHumanIntentSupersedesAPendingHiddenSelection(String action) throws Exception {
        String c = selectMetadataAnchor();
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                access.store.bookmark(c, true); panel.refreshNow();
                JTable table = get("traffic.table", JTable.class);
                assertEquals(2, table.getRowCount()); assertEquals(0, table.getSelectedRowCount());
                assertEquals("", get("traffic.request", JTextArea.class).getText());
                assertFalse(get("traffic.resolve", JButton.class).isEnabled()); assertFalse(get("traffic.next", JButton.class).isEnabled());
                switch (action) {
                    case "selection" -> table.setRowSelectionInterval(1, 1);
                    case "navigation" -> { table.setRowSelectionInterval(0, 0); get("traffic.next", JButton.class).doClick(0); }
                    case "deselection" -> { table.setRowSelectionInterval(1, 1); table.clearSelection(); }
                    case "dedicated-filter" -> get("traffic.method", JTextField.class).setText("GET");
                    case "query-edit" -> get("traffic.search", JTextField.class).setText("^https://example[.]test/[abc](?:)$");
                    case "invalid-input" -> {
                        get("traffic.search", JTextField.class).setText("[");
                        assertTrue(get("traffic.searchError", JTextArea.class).getText().contains("BAD_RE2"));
                        assertEquals(0, table.getRowCount());
                        get("traffic.search", JTextField.class).setText("^https://example[.]test/[abc]$");
                    }
                    case "bookmark-filter" -> get("traffic.bookmarked", JCheckBox.class).setSelected(true);
                    default -> throw new AssertionError(action);
                }
                return null;
            });
            hold.close(); await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
            edt(() -> {
                JTable table = get("traffic.table", JTable.class);
                boolean selected = action.equals("selection") || action.equals("navigation");
                assertEquals(selected ? 1 : 0, table.getSelectedRowCount(), action);
                if (selected) assertTrue(table.getValueAt(table.getSelectedRow(), 3).toString().endsWith("/b"));
                else assertEquals("", get("traffic.request", JTextArea.class).getText());
                assertTrue(access.rows().stream().filter(e -> e.id().equals(c)).findFirst().orElseThrow().bookmarked()); return null;
            });
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"clear", "external-clear", "project", "revision", "failure", "close"})
    void retiredLifecycleCannotRestorePendingSelectionEvenWhenTheSameIdsRemain(String transition) throws Exception {
        String c = selectMetadataAnchor();
        TrafficSearch.Session session = edt(() -> (TrafficSearch.Session) field("contentSearch"));
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                access.store.bookmark(c, true); panel.refreshNow();
                assertEquals(0, get("traffic.table", JTable.class).getSelectedRowCount());
                switch (transition) {
                    case "clear" -> get("settings.clear", JButton.class).doClick(0);
                    case "external-clear" -> { access.store.clear(); panel.refreshNow(); }
                    case "project" -> { access.project = "next-project"; panel.refreshNow(); }
                    case "revision" -> { access.revision++; panel.refreshNow(); }
                    case "failure" -> { access.failStatus = true; panel.refreshNow(); access.failStatus = false; panel.refreshNow(); }
                    case "close" -> panel.close();
                    default -> throw new AssertionError(transition);
                }
                return null;
            });
            hold.close();
            if (transition.equals("close")) assertTrue(session.awaitExit(5000));
            else await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
            edt(() -> {
                JTable table = get("traffic.table", JTable.class);
                assertEquals(List.of("project", "revision", "failure").contains(transition) ? 3 : 0, table.getRowCount(), transition);
                assertEquals(0, table.getSelectedRowCount()); assertEquals("", get("traffic.request", JTextArea.class).getText());
                assertFalse(get("traffic.next", JButton.class).isEnabled()); assertFalse(get("traffic.resolve", JButton.class).isEnabled()); return null;
            });
        }
    }

    @Test void aSettledMissDropsSelectionDespiteUnrelatedPendingWorkAndCannotReturnSelected() throws Exception {
        String selected = row("/selected", "header", "body"); access.store.outcome(selected, "FORWARDED", "NATIVE_RELEASED", 200);
        open(); search("NATIVE_RELEASED", METADATA, RE2);
        edt(() -> { assertEquals(1, get("traffic.table", JTable.class).getRowCount()); get("traffic.table", JTable.class).setRowSelectionInterval(0, 0); return null; });
        var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
        var actual = com.google.re2j.Pattern.compile("NATIVE_RELEASED", com.google.re2j.Pattern.CASE_INSENSITIVE);
        com.google.re2j.Pattern controlled = org.mockito.Mockito.mock(com.google.re2j.Pattern.class);
        org.mockito.Mockito.when(controlled.matcher(org.mockito.ArgumentMatchers.any(CharSequence.class))).thenAnswer(call -> {
            CharSequence text = call.getArgument(0);
            if (text.toString().contains("/unrelated")) {
                entered.countDown(); while (release.getCount() > 0) try { release.await(); } catch (InterruptedException ignored) {}
            }
            return actual.matcher(text);
        });
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                var pattern = TrafficSearch.CompiledQuery.class.getDeclaredField("pattern"); pattern.setAccessible(true); pattern.set(field("searchInput"), controlled);
                access.store.outcome(selected, "FORWARDED", "POLICY_CHANGED", 200); panel.refreshNow();
                assertEquals(0, get("traffic.table", JTable.class).getRowCount());
                row("/unrelated", "header", "body"); return null;
            });
            hold.close(); assertTrue(entered.await(5, TimeUnit.SECONDS));
            edt(() -> {
                assertTrue(get("traffic.count", JLabel.class).getText().contains("pending"));
                assertEquals(0, get("traffic.table", JTable.class).getRowCount(), "the selected subject has settled to a miss while only the unrelated subject is scanning");
                access.store.outcome(selected, "FORWARDED", "NATIVE_RELEASED", 200); panel.refreshNow(); return null;
            });
            release.countDown(); await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
            edt(() -> {
                assertEquals(1, get("traffic.table", JTable.class).getRowCount());
                assertEquals(0, get("traffic.table", JTable.class).getSelectedRowCount(), "a later hit cannot revive the selection discarded by a settled miss");
                assertEquals("", get("traffic.request", JTextArea.class).getText()); return null;
            });
        } finally { release.countDown(); }
    }

    @Test void failedMetadataVerificationLeavesNoHiddenSelectionAuthorityOrAutomaticRetry() throws Exception {
        String c = selectMetadataAnchor();
        com.google.re2j.Pattern broken = org.mockito.Mockito.mock(com.google.re2j.Pattern.class);
        org.mockito.Mockito.when(broken.matcher(org.mockito.ArgumentMatchers.any(CharSequence.class))).thenThrow(new IllegalStateException("synthetic-search-failure"));
        edt(() -> {
            var pattern = TrafficSearch.CompiledQuery.class.getDeclaredField("pattern"); pattern.setAccessible(true); pattern.set(field("searchInput"), broken);
            access.store.bookmark(c, true); panel.refreshNow(); return null;
        });
        await(() -> get("traffic.count", JLabel.class).getText().contains("search failed"));
        edt(() -> {
            JTable table = get("traffic.table", JTable.class); assertEquals(2, table.getRowCount()); assertEquals(0, table.getSelectedRowCount());
            assertEquals("", get("traffic.request", JTextArea.class).getText());
            assertFalse(get("traffic.resolve", JButton.class).isEnabled()); assertFalse(get("traffic.next", JButton.class).isEnabled());
            int confirmations = dialogs.confirmations.size(); get("traffic.exportRange", JComboBox.class).setSelectedIndex(1);
            get("traffic.export", JButton.class).doClick(0); assertEquals(confirmations, dialogs.confirmations.size());
            assertNull(field("exportWorker")); panel.refreshNow(); panel.refreshNow(); assertEquals(0, table.getSelectedRowCount()); return null;
        });
        org.mockito.Mockito.verify(broken, org.mockito.Mockito.times(1)).matcher(org.mockito.ArgumentMatchers.any(CharSequence.class));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"search", "method", "status", "time", "intent", "run", "guardState", "project", "outcome", "bookmarked"})
    void everyFilterEditReconcilesRetiredMembershipBeforePublishing(String filter) throws Exception {
        String id = access.addRaw("intent", "run", "forwarded"); access.store.bookmark(id, true); open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class); assertEquals(1, table.getRowCount());
            access.store.clear(); assertTrue(access.rows().isEmpty());
            switch (filter) {
                case "search" -> get("traffic.search", JTextField.class).setText("example");
                case "method" -> get("traffic.method", JTextField.class).setText("POST");
                case "status" -> get("traffic.status", JTextField.class).setText("200");
                case "time" -> get("traffic.time", JTextField.class).setText("20");
                case "intent" -> get("traffic.intent", JTextField.class).setText("intent");
                case "run" -> get("traffic.run", JTextField.class).setText("run");
                case "guardState" -> get("traffic.guardState", JTextField.class).setText("PROTECTED");
                case "project" -> get("traffic.project", JComboBox.class).setSelectedItem("p");
                case "outcome" -> get("traffic.outcome", JComboBox.class).setSelectedIndex(2);
                case "bookmarked" -> get("traffic.bookmarked", JCheckBox.class).setSelected(true);
                default -> throw new AssertionError(filter);
            }
            assertEquals(0, table.getRowCount(), filter); assertEquals(0, table.getSelectedRowCount());
            assertEquals("", get("traffic.request", JTextArea.class).getText()); return null;
        });
    }

    @Test void ordinaryBookmarkFilterExclusionDropsPendingSelectionBeforeTheSameIdMatchesAgain() throws Exception {
        String c = selectMetadataAnchor();
        edt(() -> { get("traffic.bookmark", JButton.class).doClick(0); return null; });
        await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
        edt(() -> { get("traffic.bookmarked", JCheckBox.class).setSelected(true); assertEquals(1, get("traffic.table", JTable.class).getSelectedRowCount()); return null; });
        try (SearchHold hold = holdSearch()) {
            edt(() -> {
                access.store.bookmark(c, false); panel.refreshNow();
                assertEquals(0, get("traffic.table", JTable.class).getRowCount());
                assertTrue(get("traffic.count", JLabel.class).getText().contains("pending"));
                access.store.bookmark(c, true); panel.refreshNow(); return null;
            });
            hold.close(); await(() -> !get("traffic.count", JLabel.class).getText().contains("pending"));
            edt(() -> {
                assertEquals(1, get("traffic.table", JTable.class).getRowCount());
                assertEquals(0, get("traffic.table", JTable.class).getSelectedRowCount(), "ordinary AND exclusion retires intent even if the same ID becomes eligible before verification completes");
                assertEquals("", get("traffic.request", JTextArea.class).getText()); return null;
            });
        }
    }

    @Test void adjustingHumanSelectionSurvivesRefreshAndGestureCompletion() throws Exception {
        access.addRaw("synthetic-one", "synthetic-run", "forwarded");
        access.addRaw("synthetic-two", "synthetic-run", "forwarded");
        open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            assertEquals(2, table.getRowCount());
            String expectedId = access.rows().get(table.convertRowIndexToModel(1)).id();
            table.setRowSelectionInterval(0, 0);
            table.getSelectionModel().setValueIsAdjusting(true);
            table.setRowSelectionInterval(1, 1);
            assertEquals(1, table.getSelectedRow(), "the newer human selection is established before refresh");
            panel.refreshNow();
            int during = table.getSelectedRow();
            table.getSelectionModel().setValueIsAdjusting(false);
            int after = table.getSelectedRow();
            String actualId = after < 0 ? "none" : access.rows().get(table.convertRowIndexToModel(after)).id();
            System.out.printf("C9-R1 beforeRefresh=1 duringRefresh=%d afterGesture=%d expectedRow=1 expectedIdPreserved=%s adjusting=%s rows=%d%n",
                    during, after, expectedId.equals(actualId), table.getSelectionModel().getValueIsAdjusting(), table.getRowCount());
            assertAll(
                    () -> assertEquals(1, during, "refresh must preserve the latest adjusting selection"),
                    () -> assertEquals(1, table.getSelectedRow(), "gesture completion must preserve the latest human selection"),
                    () -> assertEquals(expectedId, actualId, "the same human-selected evidence ID must remain selected"));
            assertFalse(table.getSelectionModel().getValueIsAdjusting());
            assertEquals(2, table.getRowCount()); assertTrue(dialogs.errors.isEmpty()); return null;
        });
    }
}
