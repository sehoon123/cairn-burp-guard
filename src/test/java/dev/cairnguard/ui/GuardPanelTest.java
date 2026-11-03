package dev.cairnguard.ui;

import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.RowSorter.SortKey;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.AbstractDocument;
import java.awt.Component;
import java.awt.Container;
import java.awt.GridLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class GuardPanelTest {
    private static final String SECRET = "synthetic-secret-never-display";
    private final FakeAccess access = new FakeAccess();
    private final HumanDialogs dialogs = new HumanDialogs();
    private GuardPanel panel;
    @TempDir Path temp;

    @AfterEach void close() throws Exception {
        access.serializeRelease.countDown();
        if (panel != null) edt(() -> { panel.close(); return null; });
    }

    @Test void sixNamedTabsReadOnlyDetailsAndEdtLifecycle() throws Exception {
        assertThrows(IllegalStateException.class, () -> new GuardPanel(access));
        open();
        edt(() -> {
            JTabbedPane tabs = get("tabs", JTabbedPane.class);
            assertEquals(List.of("Dashboard", "Rules", "Scope", "Traffic", "Approval", "Settings"),
                    java.util.stream.IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
            for (String name : List.of("dashboard.status", "traffic.request", "traffic.response", "traffic.metadata", "approval.detail"))
                assertFalse(get(name, JTextArea.class).isEditable());
            assertTrue(get("dashboard.status", JTextArea.class).getText().contains("\"gate\""));
            assertTrue(get("dashboard.status", JTextArea.class).getText().contains("\"stalled\""));
            assertTrue(button("draft.apply").isEnabled());
            assertFalse(get("rules.table", JTable.class).isCellEditable(0, 0));
            return null;
        });
        assertThrows(IllegalStateException.class, panel::close);
        edt(() -> { panel.close(); panel.close(); return null; });
        assertFalse(edt(() -> button("draft.apply").isEnabled()));
        int refreshes = access.refreshes;
        edt(() -> { panel.refreshNow(); return null; });
        assertEquals(refreshes, access.refreshes);
    }

    @Test void trafficFiltersStayCompactAndSplitPanesReserveBothViews() throws Exception {
        open();
        edt(() -> {
            JPanel filters = (JPanel) get("traffic.search", JTextField.class).getParent();
            assertEquals(4, ((GridLayout) filters.getLayout()).getColumns());
            assertEquals(12, filters.getComponentCount());
            JSplitPane split = (JSplitPane) SwingUtilities.getAncestorOfClass(JSplitPane.class, get("traffic.table", JTable.class));
            assertEquals(70, split.getTopComponent().getMinimumSize().height);
            assertEquals(70, split.getBottomComponent().getMinimumSize().height);
            assertEquals(.5, split.getResizeWeight());
            return null;
        });
    }

    @Test void publishedNativeSmokePolicyUsesStrictCanonicalJsonAndAppliesAtomically() throws Exception {
        GuardConfig fixture = Json.read(Files.readString(Path.of("templates", "examples", "guard.loopback-smoke.json")), GuardConfig.class);
        new PolicyEngine().validate(fixture);
        open();
        edt(() -> {
            get("rules.json", JTextArea.class).setText(Json.write(fixture.rules()));
            get("scope.allow", JTextArea.class).setText(Json.write(fixture.allowScope()));
            get("scope.block", JTextArea.class).setText(Json.write(fixture.blockScope()));
            click("draft.apply");
            assertEquals(1, access.updates);
            assertEquals(fixture, access.policy);
            return null;
        });
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
    }

    @Test void closeStopsOneSecondRefreshTimer() throws Exception {
        edt(() -> { panel = new GuardPanel(access, dialogs, true); return null; });
        java.lang.reflect.Field timerField = GuardPanel.class.getDeclaredField("timer");
        timerField.setAccessible(true);
        Timer timer = (Timer) timerField.get(panel);
        assertTrue(edt(timer::isRunning));
        edt(() -> { panel.close(); return null; });
        assertFalse(edt(timer::isRunning));
        assertEquals(1_000, timer.getDelay());
    }

    @Test void ruleAddToggleModeDeleteAreLocalAndPreserveNestedConditions() throws Exception {
        open();
        edt(() -> {
            Rule nested = new Rule("nested", "Nested AND / OR", true, Mode.ASK,
                    new Condition(Logic.AND, null, null, null, null, false, List.of(
                            Condition.leaf(Field.METHOD, Match.EXACT, "POST"),
                            new Condition(Logic.OR, null, null, null, null, false, List.of(
                                    Condition.leaf(Field.PATH, Match.EXACT, "/one"),
                                    Condition.leaf(Field.PATH, Match.EXACT, "/two"))))));
            get("rules.json", JTextArea.class).setText(Json.write(List.of(nested)));
            click("rules.preview");
            JTable table = get("rules.table", JTable.class);
            table.setRowSelectionInterval(0, 0);
            click("rules.toggle");
            get("rules.mode", JComboBox.class).setSelectedItem(Mode.MONITOR);
            click("rules.setMode");
            Rule[] draft = Json.read(get("rules.json", JTextArea.class).getText(), Rule[].class);
            assertFalse(draft[0].enabled());
            assertEquals(Mode.MONITOR, draft[0].mode());
            assertEquals(nested.condition(), draft[0].condition());
            click("rules.add");
            draft = Json.read(get("rules.json", JTextArea.class).getText(), Rule[].class);
            assertEquals(2, draft.length);
            assertFalse(draft[1].enabled());
            click("rules.delete");
            assertEquals(1, Json.read(get("rules.json", JTextArea.class).getText(), Rule[].class).length);
            assertEquals(0, access.updates);
            click("draft.apply");
            assertEquals(1, access.updates);
            assertEquals("project-one", access.submittedProject);
            assertEquals(1, access.submittedRevision);
            assertEquals(nested.condition(), access.policy.rules().getFirst().condition());
            return null;
        });
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
    }

    @Test void staleRulePreviewDoesNotMutateAnotherRule() throws Exception {
        open();
        edt(() -> {
            get("rules.table", JTable.class).setRowSelectionInterval(0, 0);
            get("rules.json", JTextArea.class).setText("[]");
            click("rules.toggle");
            assertEquals("[]", get("rules.json", JTextArea.class).getText());
            assertEquals(0, access.updates);
            return null;
        });
        assertEquals(List.of("RULE_SELECTION_STALE_PARSE_AGAIN"), dialogs.errors);
    }

    @Test void scopePresetsAreDisabledExactAndAtomicSaveIncludesAllSections() throws Exception {
        open();
        edt(() -> {
            click("scope.addAllow");
            click("scope.addBlock");
            ScopeEntry entry = Json.read(get("scope.allow", JTextArea.class).getText(), ScopeEntry[].class)[0];
            assertEquals(new ScopeEntry(false, "example.test", "https", 443, "/"), entry);
            assertEquals(entry, Json.read(get("scope.block", JTextArea.class).getText(), ScopeEntry[].class)[0]);
            get("scope.allow", JTextArea.class).setText(Json.write(List.of(new ScopeEntry(true, "example.test", "https", 443, "/safe.*"))));
            get("settings.globalRps", JSpinner.class).setValue(2);
            get("settings.perHostRps", JSpinner.class).setValue(1);
            get("settings.maxConcurrent", JSpinner.class).setValue(3);
            get("settings.maxQueued", JSpinner.class).setValue(0);
            get("settings.queueTimeoutMillis", JSpinner.class).setValue(2_000);
            get("settings.approvalTimeoutMillis", JSpinner.class).setValue(3_000);
            get("settings.requestTimeoutMillis", JSpinner.class).setValue(4_000);
            get("settings.hostRps", JTextArea.class).setText("{\"hostRps\":{\"example.test\":2}}");
            get("settings.defaultMode", JComboBox.class).setSelectedItem(Mode.ASK);
            click("draft.apply");
            assertEquals(1, access.updates);
            assertEquals(GuardConfig.defaults().rules(), access.policy.rules());
            assertEquals(1, access.policy.allowScope().size());
            assertEquals(1, access.policy.blockScope().size());
            assertEquals(Mode.ASK, access.policy.defaultMode());
            assertEquals(new GuardConfig.Limits(2, 1, Map.of("example.test", 2), 3, 0, 2_000, 3_000, 4_000), access.policy.limits());
            assertTrue(get("message", JLabel.class).getText().startsWith("POLICY_APPLIED"));
            return null;
        });
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
    }

    @Test void badJsonDuplicateUnknownAndTrailingInputAreAtomicCategoricalErrors() throws Exception {
        open();
        for (String invalid : List.of("[{", "null", "[null]", "[] true", "[{\"unknown\":true}]")) {
            edt(() -> { get("rules.json", JTextArea.class).setText(invalid); click("draft.apply"); return null; });
            assertEquals(0, access.updates);
            assertEquals(GuardConfig.defaults(), access.policy);
        }
        edt(() -> {
            get("rules.json", JTextArea.class).setText("[]");
            get("settings.hostRps", JTextArea.class).setText("{\"hostRps\":{},\"hostRps\":{}}");
            click("draft.apply");
            get("settings.hostRps", JTextArea.class).setText("{\"hostRps\":{\"example.test\":0}}");
            click("draft.apply");
            return null;
        });
        assertTrue(dialogs.errors.contains("INVALID_POLICY"));
        assertTrue(dialogs.errors.stream().allMatch(s -> s.matches("[A-Z_]+")));
        assertEquals(0, access.updates);
    }

    @Test void nullMissingAndFractionalPortsCannotBecomeAnAccidentalAnyPortScope() throws Exception {
        open();
        for (String port : List.of("null", "443.9", "missing")) {
            edt(() -> {
                String json = "[{\"enabled\":true,\"host\":\"example.test\",\"scheme\":\"https\","
                        + (port.equals("missing") ? "" : "\"port\":" + port + ",") + "\"pathRegex\":\"/\"}]";
                get("scope.allow", JTextArea.class).setText(json);
                click("draft.apply");
                assertEquals(0, access.updateAttempts);
                assertTrue(access.policy.allowScope().isEmpty());
                return null;
            });
        }
        assertEquals(List.of("INVALID_BOUNDED_JSON", "INVALID_BOUNDED_JSON", "INVALID_BOUNDED_JSON"), dialogs.errors);
    }

    @Test void malformedHostOverridesNeverCoerceFractionalOrNullRates() throws Exception {
        open();
        edt(() -> {
            get("settings.hostRps", JTextArea.class).setText("{\"hostRps\":{\"example.test\":1.5}}");
            click("draft.apply");
            get("settings.hostRps", JTextArea.class).setText("{\"hostRps\":{\"example.test\":null}}");
            click("draft.apply");
            assertEquals(0, access.updateAttempts);
            return null;
        });
        assertEquals(List.of("INVALID_BOUNDED_JSON", "INVALID_SETTINGS_JSON"), dialogs.errors);
    }

    @Test void policyRowCountsAreBoundedBeforePreviewOrApply() throws Exception {
        open();
        edt(() -> {
            List<Rule> rules = java.util.stream.IntStream.range(0, 257).mapToObj(i -> new Rule("r" + i, "Disabled", false,
                    Mode.BLOCK, Condition.leaf(Field.PATH, Match.EXACT, "/"))).toList();
            get("rules.json", JTextArea.class).setText(Json.write(rules));
            click("rules.preview");
            assertEquals(2, get("rules.table", JTable.class).getRowCount());
            click("draft.apply");
            assertEquals(0, access.updateAttempts);
            return null;
        });
        assertEquals(List.of("POLICY_ROW_LIMIT", "POLICY_ROW_LIMIT"), dialogs.errors);
    }

    @Test void projectSwitchNeverRebasesOrAppliesOldDraftAndReloadIsExplicit() throws Exception {
        open();
        edt(() -> {
            get("rules.json", JTextArea.class).setText("[]");
            access.project = "project-two";
            access.revision = 6;
            access.policy = policyWithAllow();
            click("draft.apply");
            assertEquals(0, access.updateAttempts);
            assertFalse(button("draft.apply").isEnabled());
            assertEquals("[]", get("rules.json", JTextArea.class).getText());
            assertTrue(get("draft.baseline", JLabel.class).getText().contains("STALE"));
            dialogs.confirmed = false;
            click("draft.reload");
            assertEquals("[]", get("rules.json", JTextArea.class).getText());
            assertFalse(button("draft.apply").isEnabled());
            dialogs.confirmed = true;
            click("draft.reload");
            assertTrue(button("draft.apply").isEnabled());
            assertEquals(2, Json.read(get("rules.json", JTextArea.class).getText(), Rule[].class).length);
            click("draft.apply");
            assertEquals("project-two", access.submittedProject);
            assertEquals(6, access.submittedRevision);
            return null;
        });
        assertEquals(List.of("STALE_POLICY_DRAFT_RELOAD_REQUIRED"), dialogs.errors);
    }

    @Test void externalRevisionChangeLeavesEvenCleanDraftStale() throws Exception {
        open();
        edt(() -> {
            access.revision++;
            panel.refreshNow();
            assertFalse(button("draft.apply").isEnabled());
            assertTrue(get("draft.baseline", JLabel.class).getText().startsWith("Draft revision 1"));
            click("draft.reload");
            assertTrue(button("draft.apply").isEnabled());
            click("draft.apply");
            assertEquals(2, access.submittedRevision);
            return null;
        });
    }

    @Test void lastMomentRacePassesOriginalBaselineAndControllerCanReject() throws Exception {
        open();
        edt(() -> {
            access.raceOnUpdate = true;
            click("draft.apply");
            assertEquals(1, access.updateAttempts);
            assertEquals("project-one", access.submittedProject);
            assertEquals(1, access.submittedRevision);
            assertEquals(0, access.updates);
            assertFalse(button("draft.apply").isEnabled());
            return null;
        });
        assertEquals(List.of("POLICY_UPDATE_REJECTED_RELOAD_REQUIRED"), dialogs.errors);
    }

    @Test void inconsistentConfigStatusPairNeverLoadsARebasedDraft() throws Exception {
        access.switchDuringConfig = true;
        open();
        edt(() -> {
            assertFalse(button("draft.apply").isEnabled());
            assertEquals("", get("rules.json", JTextArea.class).getText());
            assertTrue(get("message", JLabel.class).getText().startsWith("REFRESH_UNAVAILABLE"));
            click("draft.reload");
            click("draft.apply");
            assertEquals("project-two", access.submittedProject);
            assertEquals(2, access.submittedRevision);
            return null;
        });
    }

    @Test void refreshRecoveryDoesNotSilentlyReplaceDraftTypedDuringInitialFailure() throws Exception {
        access.failRefresh = true;
        open();
        edt(() -> {
            get("rules.json", JTextArea.class).setText("[]");
            access.failRefresh = false;
            panel.refreshNow();
            assertEquals("[]", get("rules.json", JTextArea.class).getText());
            assertFalse(button("draft.apply").isEnabled());
            dialogs.confirmed = false;
            click("draft.reload");
            assertEquals("[]", get("rules.json", JTextArea.class).getText());
            dialogs.confirmed = true;
            click("draft.reload");
            assertTrue(button("draft.apply").isEnabled());
            assertEquals(2, Json.read(get("rules.json", JTextArea.class).getText(), Rule[].class).length);
            return null;
        });
    }

    @Test void pauseAndEvidenceClearRequireOnlyLocalHumanActions() throws Exception {
        access.rows = fixtures();
        open();
        edt(() -> {
            get("dashboard.paused", JCheckBox.class).doClick();
            assertTrue(access.paused);
            assertFalse(button("draft.apply").isEnabled());
            dialogs.confirmed = false;
            click("dashboard.clear");
            assertEquals(3, access.rows.size());
            dialogs.confirmed = true;
            click("dashboard.clear");
            assertTrue(access.rows.isEmpty());
            assertEquals(1, access.clears);
            return null;
        });
    }

    @Test void editorsRejectOverLimitReplacementWithCategoricalFeedback() throws Exception {
        open();
        edt(() -> {
            for (String name : List.of("rules.json", "scope.allow", "scope.block", "settings.hostRps")) {
                JTextArea editor = get(name, JTextArea.class);
                AbstractDocument doc = (AbstractDocument) editor.getDocument();
                String original = editor.getText();
                doc.replace(0, doc.getLength(), "x".repeat(GuardPanel.MAX_EDITOR_CHARS + 1), null);
                assertEquals(original, editor.getText());
                assertTrue(get("message", JLabel.class).getText().startsWith("EDITOR_LENGTH_LIMIT"));
                doc.replace(0, doc.getLength(), "x".repeat(GuardPanel.MAX_EDITOR_CHARS), null);
                assertEquals(GuardPanel.MAX_EDITOR_CHARS, doc.getLength());
                doc.insertString(doc.getLength(), "x", null);
                assertEquals(GuardPanel.MAX_EDITOR_CHARS, doc.getLength());
            }
            return null;
        });
    }

    @Test void trafficFiltersAreLiteralConjunctiveAndBookmarkProjectAware() throws Exception {
        access.rows = fixtures();
        open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            assertEquals(3, table.getRowCount());
            get("traffic.search", JTextField.class).setText("[");
            assertEquals(0, table.getRowCount()); // No regex compilation / syntax errors.
            get("traffic.search", JTextField.class).setText("a.*");
            assertEquals(0, table.getRowCount()); // A metacharacter is a literal, not a wildcard.
            get("traffic.search", JTextField.class).setText("a.");
            assertEquals(1, table.getRowCount());
            get("traffic.method", JTextField.class).setText("get");
            get("traffic.status", JTextField.class).setText("200");
            get("traffic.time", JTextField.class).setText("2026-11-03T12:00:00Z");
            assertEquals(1, table.getRowCount());
            get("traffic.project", JComboBox.class).setSelectedItem("project-two");
            assertEquals(0, table.getRowCount());
            get("traffic.project", JComboBox.class).setSelectedItem("project-one");
            assertEquals(1, table.getRowCount());
            get("traffic.bookmarked", JCheckBox.class).doClick();
            assertEquals(0, table.getRowCount());
            get("traffic.bookmarked", JCheckBox.class).doClick();
            get("traffic.search", JTextField.class).setText(SECRET);
            assertEquals(0, table.getRowCount());
            get("traffic.search", JTextField.class).setText("%5BREDACTED%5D");
            assertEquals(1, table.getRowCount());
            return null;
        });
    }

    @Test void sortedSelectionBookmarkAndDetailsUseModelIndicesAndSurviveRefresh() throws Exception {
        access.rows = fixtures();
        open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            table.getRowSorter().setSortKeys(List.of(new SortKey(3, SortOrder.DESCENDING)));
            table.setRowSelectionInterval(0, 0);
            String selectedUrl = table.getValueAt(0, 3).toString();
            assertTrue(get("traffic.request", JTextArea.class).getText().contains(selectedUrl));
            String metadata = get("traffic.metadata", JTextArea.class).getText();
            assertTrue(metadata.contains("Policy revision: 7"));
            assertTrue(metadata.contains("Rule hits"));
            assertFalse(metadata.contains(SECRET));
            String selectedId = access.rows.stream().filter(e -> e.url().equals(selectedUrl)).findFirst().orElseThrow().id();
            click("traffic.bookmark");
            assertEquals(selectedId, access.lastBookmarked);
            assertEquals(selectedUrl, table.getValueAt(table.getSelectedRow(), 3));
            assertTrue(get("traffic.metadata", JTextArea.class).getText().contains("Bookmarked: true"));
            panel.refreshNow();
            assertEquals(selectedUrl, table.getValueAt(table.getSelectedRow(), 3));
            assertFalse(get("traffic.request", JTextArea.class).getText().contains(SECRET));
            return null;
        });
    }

    @Test void projectFilterIsNotSilentlyBroadenedWhenItsLastEntryDisappears() throws Exception {
        access.rows = fixtures();
        open();
        edt(() -> {
            get("traffic.project", JComboBox.class).setSelectedItem("project-two");
            access.rows = List.of(access.rows.getFirst());
            panel.refreshNow();
            assertEquals("project-two", get("traffic.project", JComboBox.class).getSelectedItem());
            assertEquals(0, get("traffic.table", JTable.class).getRowCount());
            assertEquals("", get("traffic.request", JTextArea.class).getText());
            return null;
        });
    }

    @Test void disappearingSortedSelectionClearsDetailsWithoutStalingThePolicy() throws Exception {
        access.rows = fixtures();
        open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            table.getRowSorter().setSortKeys(List.of(new SortKey(3, SortOrder.DESCENDING)));
            table.setRowSelectionInterval(2, 2);
            access.rows = List.of();
            panel.refreshNow();
            assertEquals(0, table.getRowCount());
            assertEquals(-1, table.getSelectedRow());
            assertEquals("", get("traffic.request", JTextArea.class).getText());
            assertTrue(button("draft.apply").isEnabled());
            assertFalse(get("message", JLabel.class).getText().startsWith("REFRESH_UNAVAILABLE"));
            return null;
        });
    }

    @Test void trafficRowsAreBoundedAndHtmlIsNotInterpreted() throws Exception {
        List<TrafficEntry> data = new ArrayList<>();
        TrafficEntry entry = fixtures().getFirst();
        for (int i = 0; i < 2_001; i++) data.add(entry);
        access.rows = data;
        open();
        edt(() -> {
            JTable table = get("traffic.table", JTable.class);
            assertEquals(2_000, table.getRowCount());
            JLabel renderer = (JLabel) table.prepareRenderer(table.getCellRenderer(0, 3), 0, 3);
            renderer.setText("<html><b>must remain literal text</b></html>");
            assertEquals(Boolean.TRUE, renderer.getClientProperty("html.disable"));
            assertNull(renderer.getClientProperty(BasicHTML.propertyKey));
            Object projectRenderer = get("traffic.project", JComboBox.class).getRenderer();
            assertEquals(Boolean.TRUE, ((JLabel) projectRenderer).getClientProperty("html.disable"));
            return null;
        });
    }

    @Test void approvalsResolveOnlyMaskedEvidenceAndAreOneShot() throws Exception {
        access.rows = fixtures();
        TrafficEntry evidence = access.rows.getFirst();
        access.pending = new ArrayList<>(List.of(pending("approval-one", evidence.id(), evidence.projectId())));
        open();
        edt(() -> {
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
            String detail = get("approval.detail", JTextArea.class).getText();
            assertTrue(detail.contains("[REDACTED]"));
            assertFalse(detail.contains(SECRET));
            click("approval.approve");
            assertEquals(List.of("approval-one:true"), access.decisions);
            assertEquals(0, get("approval.table", JTable.class).getRowCount());
            click("approval.approve");
            assertEquals(1, access.decisions.size());
            return null;
        });
        assertEquals(List.of("SELECT_PENDING_APPROVAL_FIRST"), dialogs.errors);
    }

    @Test void missingExpiredAndOtherProjectApprovalCannotBypassQueue() throws Exception {
        access.pending = new ArrayList<>(List.of(pending("old", "not-retained", "project-one")));
        open();
        edt(() -> {
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
            assertTrue(get("approval.detail", JTextArea.class).getText().contains("EVIDENCE_NOT_RETAINED"));
            access.pending.clear(); // Decision race/timeout after last refresh.
            click("approval.approve");
            assertTrue(access.decisions.isEmpty());
            access.pending = new ArrayList<>(List.of(pending("other", "not-retained", "project-two")));
            panel.refreshNow();
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
            click("approval.approve");
            assertTrue(access.decisions.isEmpty());
            access.pending = new ArrayList<>(List.of(pending("deny", "not-retained", "project-one")));
            panel.refreshNow();
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
            click("approval.deny");
            assertEquals(List.of("deny:false"), access.decisions);
            return null;
        });
        assertEquals(List.of("APPROVAL_STALE_OR_EXPIRED", "APPROVAL_STALE_OR_EXPIRED"), dialogs.errors);
    }

    @Test void filteredJsonAndSortedSelectedHarAreSerializedOffEdtToHumanPath() throws Exception {
        access.rows = fixtures();
        dialogs.target = temp.resolve("chosen.json");
        open();
        edt(() -> {
            get("traffic.method", JTextField.class).setText("POST");
            click("traffic.filteredJson");
            return null;
        });
        awaitExport();
        assertEquals(1, access.exported.size());
        assertEquals("POST", access.exported.getFirst().method());
        assertFalse(access.exportOnEdt);
        assertEquals("JSON", Files.readString(dialogs.target));
        dialogs.target = temp.resolve("chosen.har");
        edt(() -> {
            get("traffic.method", JTextField.class).setText("");
            JTable table = get("traffic.table", JTable.class);
            table.getRowSorter().setSortKeys(List.of(new SortKey(3, SortOrder.DESCENDING)));
            table.setRowSelectionInterval(0, 1);
            List<String> urls = List.of(table.getValueAt(0, 3).toString(), table.getValueAt(1, 3).toString());
            click("traffic.selectedHar");
            access.expectedExportUrls = urls;
            return null;
        });
        awaitExport();
        assertEquals(access.expectedExportUrls, access.exported.stream().map(TrafficEntry::url).toList());
        assertEquals("HAR", Files.readString(dialogs.target));
        assertEquals(List.of("json", "har"), dialogs.chosenExtensions);
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
    }

    @Test void realRedactedStoreExportsRoundTripThroughUiWorkerAndAtomicWriter() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("project-one", "Synthetic project", new RequestData("GET",
                "https://example.test/safe?token=" + SECRET, "example.test", 443, true,
                List.of(new RequestData.Header("Authorization", "Bearer " + SECRET)), new byte[0]),
                new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", 200);
        store.response(id, 200, List.of(new RequestData.Header("Content-Type", "application/json")),
                ("{\"token\":\"" + SECRET + "\",\"ok\":true}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        access.rows = store.snapshot();
        access.exportStore = store;
        dialogs.target = temp.resolve("actual.json");
        open();
        edt(() -> { click("traffic.filteredJson"); return null; });
        awaitExport();
        String json = Files.readString(dialogs.target);
        assertFalse(json.contains(SECRET));
        assertTrue(json.contains("[REDACTED]"));
        assertEquals(id, Json.MAPPER.readTree(json).path("entries").get(0).path("id").asText());
        dialogs.target = temp.resolve("actual.har");
        edt(() -> { click("traffic.filteredHar"); return null; });
        awaitExport();
        String har = Files.readString(dialogs.target);
        assertFalse(har.contains(SECRET));
        assertEquals("1.2", Json.MAPPER.readTree(har).path("log").path("version").asText());
        assertEquals(1, Json.MAPPER.readTree(har).path("log").path("entries").size());
        assertFalse(access.exportOnEdt);
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
    }

    @Test void exportsRequireRowsAndChooserAndExplicitOverwriteConsent() throws Exception {
        open();
        edt(() -> { click("traffic.filteredJson"); return null; });
        assertEquals(List.of("NO_DISPLAYED_EVIDENCE_TO_EXPORT"), dialogs.errors);
        access.rows = fixtures();
        edt(() -> { panel.refreshNow(); click("traffic.filteredJson"); return null; }); // Cancel chooser.
        assertEquals(0, access.exportCalls);
        dialogs.target = temp.resolve("existing.json");
        Files.writeString(dialogs.target, "original");
        dialogs.confirmed = false;
        edt(() -> { click("traffic.filteredJson"); return null; });
        assertEquals(0, access.exportCalls);
        assertEquals("original", Files.readString(dialogs.target));
        dialogs.confirmed = true;
        edt(() -> { click("traffic.filteredJson"); return null; });
        awaitExport();
        assertEquals("JSON", Files.readString(dialogs.target));
        assertEquals(2, dialogs.confirmations.size());
    }

    @Test void symlinkTargetIsRejectedBeforeSerializationOrWrite() throws Exception {
        access.rows = fixtures();
        Path protectedFile = temp.resolve("protected");
        Files.writeString(protectedFile, "original");
        dialogs.target = temp.resolve("link.json");
        Files.createSymbolicLink(dialogs.target, protectedFile);
        open();
        edt(() -> { click("traffic.filteredJson"); return null; });
        assertEquals(List.of("EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE"), dialogs.errors);
        assertEquals(0, access.exportCalls);
        assertEquals("original", Files.readString(protectedFile));
        assertTrue(Files.isSymbolicLink(dialogs.target));
    }

    @Test void workerFailureAndAccessErrorsExposeOnlyCategories() throws Exception {
        access.rows = fixtures();
        dialogs.target = temp.resolve("failure.json");
        access.failExport = true;
        open();
        edt(() -> { click("traffic.filteredJson"); return null; });
        awaitExport();
        assertEquals(List.of("EXPORT_FAILED"), dialogs.errors);
        assertFalse(Files.exists(dialogs.target));
        edt(() -> {
            access.failPause = true;
            get("dashboard.paused", JCheckBox.class).doClick();
            access.failRefresh = true;
            panel.refreshNow();
            assertFalse(get("message", JLabel.class).getText().contains(SECRET));
            assertFalse(button("draft.apply").isEnabled());
            return null;
        });
        assertEquals(List.of("EXPORT_FAILED", "ACTION_FAILED"), dialogs.errors);
    }

    @Test void exportUsesFrozenDisplayedSnapshotAndRejectsSecondConcurrentExport() throws Exception {
        access.rows = fixtures();
        access.blockExport = true;
        dialogs.target = temp.resolve("snapshot.json");
        open();
        edt(() -> {
            get("traffic.method", JTextField.class).setText("POST");
            click("traffic.filteredJson");
            return null;
        });
        assertTrue(access.serializeStarted.await(5, TimeUnit.SECONDS));
        edt(() -> {
            access.rows = List.of();
            panel.refreshNow();
            click("traffic.filteredJson");
            return null;
        });
        access.serializeRelease.countDown();
        awaitExport();
        assertEquals(1, access.exported.size());
        assertEquals("POST", access.exported.getFirst().method());
        assertEquals(List.of("EXPORT_IN_PROGRESS"), dialogs.errors);
    }

    private void open() throws Exception {
        edt(() -> { panel = new GuardPanel(access, dialogs, false); return null; });
    }

    private void awaitExport() throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            boolean done = edt(() -> !get("message", JLabel.class).getText().startsWith("EXPORT_IN_PROGRESS"));
            // A rejected second click changes the banner; also wait for SwingWorker's done callback.
            java.lang.reflect.Field worker = GuardPanel.class.getDeclaredField("exportWorker");
            worker.setAccessible(true);
            if (done && edt(() -> worker.get(panel) == null)) return;
            Thread.sleep(10);
        }
        fail("Export SwingWorker did not finish");
    }

    private JButton button(String name) { return get(name, JButton.class); }
    private void click(String name) { button(name).doClick(0); }
    private <T> T get(String name, Class<T> type) {
        Component result = find(panel, name);
        assertNotNull(result, name);
        return type.cast(result);
    }
    private static Component find(Component root, String name) {
        if (name.equals(root.getName())) return root;
        if (root instanceof Container container) for (Component child : container.getComponents()) {
            Component found = find(child, name);
            if (found != null) return found;
        }
        return null;
    }
    private static <T> T edt(Callable<T> body) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) return body.call();
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { result.set(body.call()); }
            catch (Throwable t) { error.set(t); }
        });
        if (error.get() instanceof Exception e) throw e;
        if (error.get() instanceof Error e) throw e;
        return result.get();
    }

    private static GuardConfig policyWithAllow() {
        GuardConfig defaults = GuardConfig.defaults();
        return new GuardConfig(1, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")),
                List.of(), defaults.rules(), Mode.ALLOW, defaults.limits());
    }

    private static List<TrafficEntry> fixtures() {
        EvidenceStore store = new EvidenceStore();
        List<TrafficEntry> entries = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            String url = "https://example.test/" + (i == 0 ? "a.pattern" : i == 1 ? "middle" : "z") + "?token=" + SECRET;
            RequestData request = new RequestData(i == 1 ? "POST" : "GET", url, "example.test", 443, true,
                    List.of(new RequestData.Header("Authorization", "Bearer " + SECRET),
                            new RequestData.Header("Content-Type", "application/json")),
                    ("{\"password\":\"" + SECRET + "\",\"item\":\"safe\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String id = store.begin(i == 1 ? "project-two" : "project-one", "Test project", request,
                    new Decision(Mode.ASK, "RULE_MATCH", List.of(new Decision.RuleHit("ask-rule", "Human review", Mode.ASK))), 7);
            store.outcome(id, i == 1 ? "BLOCKED" : "FORWARDED", i == 1 ? "DENIED" : "NATIVE_RELEASED", i == 1 ? 451 : 200);
            TrafficEntry entry = store.snapshot().stream().filter(e -> e.id().equals(id)).findFirst().orElseThrow();
            // Fixed synthetic timestamps keep filtering independent of the machine's date.
            entries.add(new TrafficEntry(entry.id(), entry.projectId(), entry.projectName(), "2026-11-03T12:00:0" + i + "Z",
                    entry.method(), entry.url(), entry.mode(), entry.disposition(), entry.reason(), entry.statusCode(), entry.hits(),
                    entry.revision(), entry.bookmarked(), entry.requestCapture(), entry.responseCapture(), entry.truncated(), entry.provenanceSeal()));
        }
        return List.copyOf(entries);
    }

    private static Pending pending(String id, String evidence, String project) {
        return new Pending(id, evidence, project, "2026-11-03T12:00:00Z", "2026-11-03T12:00:30Z");
    }

    private static final class HumanDialogs implements GuardPanel.Dialogs {
        boolean confirmed = true;
        Path target;
        final List<String> errors = new ArrayList<>();
        final List<String> confirmations = new ArrayList<>();
        final List<String> chosenExtensions = new ArrayList<>();
        @Override public boolean confirm(Component parent, String message) {
            assertTrue(SwingUtilities.isEventDispatchThread());
            confirmations.add(message);
            return confirmed;
        }
        @Override public Path chooseExport(Component parent, String extension) {
            assertTrue(SwingUtilities.isEventDispatchThread());
            chosenExtensions.add(extension);
            return target;
        }
        @Override public void error(Component parent, String category) {
            assertTrue(SwingUtilities.isEventDispatchThread());
            errors.add(category);
        }
    }

    private static final class FakeAccess implements GuardUiAccess {
        GuardConfig policy = GuardConfig.defaults();
        String project = "project-one";
        long revision = 1;
        String submittedProject;
        long submittedRevision;
        int updates;
        int updateAttempts;
        int refreshes;
        int clears;
        boolean paused;
        boolean raceOnUpdate;
        boolean switchDuringConfig;
        boolean failPause;
        boolean failRefresh;
        boolean failExport;
        boolean blockExport;
        boolean exportOnEdt;
        EvidenceStore exportStore;
        int exportCalls;
        String lastBookmarked;
        List<TrafficEntry> rows = List.of();
        List<Pending> pending = new ArrayList<>();
        List<String> decisions = new ArrayList<>();
        volatile List<TrafficEntry> exported = List.of();
        List<String> expectedExportUrls;
        final CountDownLatch serializeStarted = new CountDownLatch(1);
        final CountDownLatch serializeRelease = new CountDownLatch(1);
        private static void onEdt() { assertTrue(SwingUtilities.isEventDispatchThread()); }
        @Override public GuardConfig config() {
            onEdt();
            GuardConfig result = policy;
            if (switchDuringConfig) { switchDuringConfig = false; project = "project-two"; revision++; policy = policyWithAllow(); }
            return result;
        }
        @Override public void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision) {
            onEdt();
            updateAttempts++;
            submittedProject = expectedProjectId;
            submittedRevision = expectedRevision;
            if (raceOnUpdate) { project = "project-two"; revision++; }
            if (!project.equals(expectedProjectId) || revision != expectedRevision) throw new IllegalStateException(SECRET);
            new PolicyEngine().validate(config);
            policy = config;
            revision++;
            updates++;
        }
        @Override public Map<String, Object> status() {
            onEdt();
            return Map.of("projectId", project, "projectName", "Current Burp project", "revision", revision,
                    "paused", paused, "closed", false, "note", "SYNTHETIC", "evidence", Map.of("retained", rows.size()),
                    "gate", Map.of("stalled", 1, "active", 1, "queued", 0), "approvalCount", pending.size());
        }
        @Override public List<TrafficEntry> traffic() { onEdt(); return List.copyOf(rows); }
        @Override public List<Pending> approvals() { onEdt(); return List.copyOf(pending); }
        @Override public boolean decideApproval(String id, boolean allow) {
            onEdt();
            boolean removed = pending.removeIf(p -> p.id().equals(id));
            if (removed) decisions.add(id + ":" + allow);
            return removed;
        }
        @Override public void bookmark(String id, boolean value) {
            onEdt();
            lastBookmarked = id;
            rows = rows.stream().map(e -> e.id().equals(id) ? new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(),
                    e.method(), e.url(), e.mode(), e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), value,
                    e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal()) : e).toList();
        }
        @Override public String exportJson(List<TrafficEntry> entries) { return export(entries, "JSON"); }
        @Override public String exportHar(List<TrafficEntry> entries) { return export(entries, "HAR"); }
        private String export(List<TrafficEntry> entries, String format) {
            exportOnEdt = SwingUtilities.isEventDispatchThread();
            exportCalls++;
            serializeStarted.countDown();
            if (blockExport) try { assertTrue(serializeRelease.await(5, TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(SECRET); }
            if (failExport) throw new IllegalArgumentException(SECRET);
            exported = List.copyOf(entries);
            if (exportStore != null) return format.equals("JSON") ? exportStore.exportJson(entries) : exportStore.exportHar(entries);
            return format;
        }
        @Override public void clearEvidence() { onEdt(); rows = List.of(); clears++; }
        @Override public void pause(boolean value) { onEdt(); if (failPause) throw new IllegalStateException(SECRET); paused = value; revision++; }
        @Override public void refreshProject() { onEdt(); refreshes++; if (failRefresh) throw new IllegalStateException(SECRET); }
    }
}
