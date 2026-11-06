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
import dev.cairnguard.ui.editor.EditorForm;
import dev.cairnguard.ui.editor.RuleEditor;
import dev.cairnguard.ui.editor.ScopeEditor;
import dev.cairnguard.ui.editor.SettingsEditor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.AbstractDocument;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.*;

/** Synthetic human workflows, not an agent control API or native Burp claim. */
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

    @Test void firstRunExplainsBlockAndHasDirectRegistrationWithoutJson() throws Exception {
        assertThrows(IllegalStateException.class, () -> new GuardPanel(access));
        open();
        edt(() -> {
            JTabbedPane tabs = get("tabs", JTabbedPane.class);
            assertEquals(List.of("개요", "대상", "규칙", "요청 기록", "승인 대기", "설정", "사건 내보내기"),
                    java.util.stream.IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
            assertTrue(get("dashboard.state", JLabel.class).getText().contains("모든 요청 차단"));
            assertTrue(get("dashboard.guidance", JTextArea.class).getText().contains("허용 대상 등록"));
            assertTrue(button("dashboard.addTarget").isEnabled());
            for (String old : List.of("rules.json", "scope.allow", "scope.block", "settings.hostRps", "draft.apply", "dashboard.status"))
                assertNull(find(panel, old), old);
            for (String name : List.of("settings.summary"))
                assertFalse(get(name, JTextArea.class).isEditable());
            assertFalse(get("rules.table", JTable.class).isCellEditable(0, 0));
            return null;
        });
    }

    @Test void examplesAreCopyableReadOnlyAndCannotChangePolicyOrResolveApprovals() throws Exception {
        open();
        GuardConfig original = access.policy; int refreshes = access.refreshes;
        dialogs.editScript = (form, close) -> {
            assertEquals(4, get("help.examples.tabs", JTabbedPane.class).getTabCount());
            for (String name : List.of("scope", "rules", "limits")) {
                JTextArea text = get("help.examples." + name, JTextArea.class);
                assertFalse(text.isEditable()); assertTrue(text.isFocusable());
                assertInstanceOf(NonScrollingCaret.class, text.getCaret());
                assertFalse(text.getText().contains(SECRET));
            }
            assertTrue(get("help.examples.rules", JTextArea.class).getText().contains("operation=purge"));
            close.run();
        };
        edt(() -> { click("help.examples"); return null; });
        assertEquals(original, access.policy); assertEquals(refreshes, access.refreshes);
        assertEquals(0, access.updates); assertEquals(0, access.exportCalls); assertTrue(access.decisions.isEmpty());
    }

    @Test void enterAndDoubleClickOpenTheCorrectSortedRowEditorWithoutSaving() throws Exception {
        GuardConfig d = policyWithAllow();
        ScopeEntry block = new ScopeEntry(true, "example.test", "https", 443, "/admin.*");
        access.policy = new GuardConfig(1, d.allowScope(), List.of(block), d.rules(), d.defaultMode(), d.limits());
        open(); List<Object> opened = new ArrayList<>();
        dialogs.editScript = (form, save) -> opened.add(form.value());
        edt(() -> {
            JTable allow = get("scope.allow.table", JTable.class);
            allow.setRowSelectionInterval(0, 0); pressEnter(allow);
            mouseClick(get("scope.block.table", JTable.class), 0, 2, MouseEvent.BUTTON1);
            JTable rules = get("rules.table", JTable.class);
            rules.getRowSorter().toggleSortOrder(1); rules.setRowSelectionInterval(0, 0);
            Rule expected = access.policy.rules().get(rules.convertRowIndexToModel(0));
            pressEnter(rules);
            assertEquals(List.of(d.allowScope().getFirst(), block, expected), opened);
            return null;
        });
        assertEquals(0, access.updateAttempts); assertTrue(dialogs.errors.isEmpty());
    }

    @Test void emptySelectionSingleClickRightClickAndEmptyAreaDoNotOpenEditors() throws Exception {
        access.policy = policyWithAllow(); open();
        edt(() -> {
            JTable table = get("scope.allow.table", JTable.class);
            table.clearSelection(); pressEnter(table);
            mouseClick(table, 0, 1, MouseEvent.BUTTON1);
            mouseClick(table, 0, 2, MouseEvent.BUTTON3);
            table.dispatchEvent(new MouseEvent(table, MouseEvent.MOUSE_CLICKED, 0, 0, 4, table.getRowHeight() * 3, 2, false, MouseEvent.BUTTON1));
            assertEquals(0, dialogs.edits);
            return null;
        });
        assertEquals(0, access.updates); assertTrue(dialogs.errors.isEmpty());
    }

    @Test void trafficUsesRawScreenWhileApprovalUsesMaskedEvidenceAndNeitherShortcutSends() throws Exception {
        access.rows = fixtures(); access.pending.add(pending("ask", access.rows.getFirst().id(), "project-one")); open();
        edt(() -> { trafficTable().setRowSelectionInterval(0, 0); return null; });
        awaitRequest(SECRET);
        edt(() -> {
            pressEnter(trafficTable());
            assertFalse(get("traffic.request", JTextArea.class).isEditable());
            assertTrue(get("traffic.request", JTextArea.class).getText().contains(SECRET));
            mouseClick(get("approval.table", JTable.class), 0, 2, MouseEvent.BUTTON1);
            String approvalText = get("approval.detail", JTextArea.class).getText();
            assertTrue(approvalText.contains("원문") && approvalText.contains(SECRET), "approval shows the retained original request");
            assertFalse(approvalText.contains("마스킹된 요청"));
            assertEquals(2, dialogs.edits);
            panel.close(); pressEnter(trafficTable()); assertEquals(2, dialogs.edits);
            return null;
        });
        assertTrue(access.decisions.isEmpty()); assertEquals(1, access.pending.size());
        assertEquals(0, access.updates); assertNull(access.lastBookmarked); assertEquals(0, access.exportCalls);
    }

    @Test void keyboardEditingCannotBypassTheVisibleSnapshotRevisionGuard() throws Exception {
        access.policy = policyWithAllow(); open();
        edt(() -> {
            JTable table = get("scope.allow.table", JTable.class); table.setRowSelectionInterval(0, 0);
            access.revision++; pressEnter(table);
            assertEquals(0, dialogs.edits); assertFalse(dialogs.errors.isEmpty());
            return null;
        });
        assertEquals(0, access.updateAttempts);
    }

    @Test void targetUrlRegistrationIsExplicitExactAndAppliesOnlyScope() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            assertInstanceOf(ScopeEditor.class, form);
            get("scope.url", JTextField.class).setText("https://example.test/api");
            get("scope.url", JTextField.class).postActionEvent();
            assertEquals(0, access.updates);
            save.run();
        };
        edt(() -> { click("dashboard.addTarget"); return null; });
        assertEquals(1, access.updates);
        assertEquals("project-one", access.submittedProject);
        assertEquals(7, access.submittedRevision);
        assertEquals(GuardConfig.defaults().rules(), access.policy.rules());
        ScopeEntry added = access.policy.allowScope().getFirst();
        assertTrue(added.enabled()); assertEquals("example.test", added.host()); assertEquals(443, added.port());
        assertEquals("https", added.scheme());
        assertEquals(Mode.ALLOW, new PolicyEngine().evaluate(access.policy, request("/api")).mode());
        assertEquals(Mode.BLOCK, new PolicyEngine().evaluate(access.policy, request("/api/child")).mode());
        assertEquals(Mode.BLOCK, new PolicyEngine().evaluate(access.policy, request("/apix")).mode());
        assertTrue(dialogs.errors.isEmpty(), dialogs.errors.toString());
        assertTrue(edt(() -> get("dashboard.state", JLabel.class).getText().contains("보호 중")));
    }

    @Test void cancelTargetFormChangesNothingAndQueryIsNotSilentlyDiscarded() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            get("scope.url", JTextField.class).setText("https://example.test/api?token=" + SECRET);
            click("scope.fillUrl");
            assertTrue(get("scope.message", JTextArea.class).getText().contains("쿼리"));
            assertFalse(get("scope.message", JTextArea.class).getText().contains(SECRET));
        };
        edt(() -> { click("scope.allow.add"); return null; });
        assertEquals(0, access.updates); assertEquals(GuardConfig.defaults(), access.policy);
    }

    @Test void scopeEditPreservesArbitraryRegexAndCancelToggleDeleteRequireConsent() throws Exception {
        access.policy = policyWithAllow(); open();
        edt(() -> { get("scope.allow.table", JTable.class).setRowSelectionInterval(0, 0); return null; });
        dialogs.editScript = (form, save) -> { assertEquals(access.policy.allowScope().getFirst(), form.value()); save.run(); };
        edt(() -> { click("scope.allow.edit"); return null; });
        assertEquals(0, access.updates, "unchanged form must not cancel approvals or bump revision");
        dialogs.confirmed = false;
        edt(() -> { click("scope.allow.toggle"); return null; });
        assertEquals(0, access.updates);
        assertTrue(dialogs.confirmations.getLast().contains("모든 새 Proxy 요청"));
        dialogs.confirmed = true;
        edt(() -> { click("scope.allow.toggle"); return null; });
        assertFalse(access.policy.allowScope().getFirst().enabled()); assertEquals(1, access.updates);
        edt(() -> { get("scope.allow.table", JTable.class).setRowSelectionInterval(0, 0); click("scope.allow.delete"); return null; });
        assertTrue(access.policy.allowScope().isEmpty()); assertEquals(2, access.updates);
    }

    @Test void blockTargetsAreSeparateAndCannotBeMistakenForAllowTargets() throws Exception {
        access.policy = policyWithAllow(); open();
        dialogs.editScript = (form, save) -> {
            get("scope.url", JTextField.class).setText("https://example.test/admin"); click("scope.fillUrl"); save.run();
        };
        edt(() -> { click("scope.block.add"); return null; });
        assertEquals(1, access.policy.allowScope().size()); assertEquals(1, access.policy.blockScope().size());
        assertEquals("SCOPE_BLOCKED", new PolicyEngine().evaluate(access.policy, request("/admin")).reason());
        assertEquals(Mode.ALLOW, new PolicyEngine().evaluate(access.policy, request("/safe")).mode());
    }

    @Test void newRuleIsVisualAndToggleDeleteSaveOnlyTheIntendedRule() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            assertInstanceOf(RuleEditor.class, form);
            get("rule.name", JTextField.class).setText("위험 메서드 검토");
            get("rule.mode", JComboBox.class).setSelectedItem(Mode.ASK);
            save.run();
        };
        edt(() -> { click("rules.add"); return null; });
        assertEquals(GuardConfig.defaults().rules().size() + 1, access.policy.rules().size());
        Rule added = access.policy.rules().getLast(); assertTrue(added.enabled()); assertEquals(Mode.ASK, added.mode());
        assertEquals(GuardConfig.defaults().allowScope(), access.policy.allowScope());
        edt(() -> { selectRule(added.id()); click("rules.toggle"); return null; });
        assertFalse(access.policy.rules().getLast().enabled());
        assertEquals(added.condition(), access.policy.rules().getLast().condition());
        edt(() -> { selectRule(added.id()); click("rules.delete"); return null; });
        assertEquals(GuardConfig.defaults().rules(), access.policy.rules());
        assertEquals(3, access.updates);
    }

    @Test void nestedRuleEditPreservesIdSelectorsNullsAndCaseWithoutJson() throws Exception {
        Rule nested = new Rule("nested", "조건 묶음", true, Mode.ASK, new Condition(Logic.AND, null, null, null, null, true, List.of(
                Condition.leaf(Field.METHOD, Match.EXACT, "POST"),
                new Condition(Logic.OR, null, "", null, "", false, List.of(
                        new Condition(Logic.LEAF, Field.HEADER, "X-Action", Match.CONTAINS, "Erase", true, List.of()),
                        new Condition(Logic.LEAF, Field.JSON, "/action", Match.EXACT, "erase", false, List.of()))))));
        access.policy = new GuardConfig(1, List.of(), List.of(), List.of(nested), Mode.ALLOW, GuardConfig.defaults().limits()); open();
        dialogs.editScript = (form, save) -> { get("rule.name", JTextField.class).setText("새 이름"); save.run(); };
        edt(() -> { selectRule("nested"); click("rules.edit"); return null; });
        Rule changed = access.policy.rules().getFirst();
        assertEquals(nested.id(), changed.id()); assertEquals(nested.condition(), changed.condition());
        assertEquals("새 이름", changed.name()); assertEquals(1, access.updates);
    }

    @Test void cancelRuleAndSettingsFormsLeaveEverySectionUnchanged() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            if (form instanceof RuleEditor) get("rule.name", JTextField.class).setText("취소할 초안");
            else get("settings.globalRps", JSpinner.class).setValue(1);
        };
        edt(() -> { click("rules.add"); click("settings.edit"); return null; });
        assertEquals(GuardConfig.defaults(), access.policy); assertEquals(0, access.updates);
    }

    @Test void settingsFormUsesSecondsAndSavesOnlySettings() throws Exception {
        access.policy = policyWithAllow(); open(); GuardConfig original = access.policy;
        dialogs.editScript = (form, save) -> {
            assertInstanceOf(SettingsEditor.class, form);
            get("settings.globalRps", JSpinner.class).setValue(2);
            get("settings.queueTimeoutSeconds", JSpinner.class).setValue(new java.math.BigDecimal("1.001"));
            get("settings.defaultMode", JComboBox.class).setSelectedItem(Mode.ASK);
            save.run();
        };
        edt(() -> { click("settings.edit"); return null; });
        assertEquals(2, access.policy.limits().globalRps()); assertEquals(1001, access.policy.limits().queueTimeoutMillis());
        assertEquals(Mode.ASK, access.policy.defaultMode()); assertEquals(original.allowScope(), access.policy.allowScope());
        assertEquals(original.rules(), access.policy.rules()); assertEquals(1, access.updates);
        assertTrue(edt(() -> get("settings.summary", JTextArea.class).getText().contains("1.001초")));
    }

    @Test void staleModalCannotSaveAcrossProjectSwitchEvenAfterLiveUiRefresh() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            get("scope.url", JTextField.class).setText("https://example.test/api"); click("scope.fillUrl");
            access.project = "project-two"; access.revision++; access.policy = policyWithAllow();
            panel.refreshNow(); save.run();
        };
        edt(() -> { click("dashboard.addTarget"); return null; });
        assertEquals(0, access.updateAttempts); assertEquals(policyWithAllow(), access.policy);
        assertEquals(List.of(UiText.error("STALE_POLICY")), dialogs.errors);
    }

    @Test void revisionOrPauseChangeDuringFormRejectsOriginalSnapshot() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            get("settings.globalRps", JSpinner.class).setValue(2); access.revision++; panel.refreshNow(); save.run();
        };
        edt(() -> { click("settings.edit"); return null; });
        assertEquals(0, access.updateAttempts); assertEquals(0, access.policy.limits().globalRps());
        assertEquals(List.of(UiText.error("STALE_POLICY")), dialogs.errors);
    }

    @Test void lateControllerRaceReceivesOriginalBaselineAndNeverLeaksException() throws Exception {
        open(); access.raceOnUpdate = true;
        dialogs.editScript = (form, save) -> { get("settings.globalRps", JSpinner.class).setValue(2); save.run(); };
        edt(() -> { click("settings.edit"); return null; });
        assertEquals(1, access.updateAttempts); assertEquals(0, access.updates);
        assertEquals("project-one", access.submittedProject); assertEquals(7, access.submittedRevision);
        assertEquals(List.of(UiText.error("UPDATE_REJECTED")), dialogs.errors);
        assertFalse(dialogs.errors.toString().contains(SECRET));
    }

    @Test void staleVisibleTableIsNotRebasedBeforeOpeningAnEdit() throws Exception {
        open(); access.project = "project-two"; access.revision++; access.policy = policyWithAllow();
        edt(() -> { click("scope.allow.add"); return null; });
        assertEquals(0, dialogs.edits); assertEquals(0, access.updateAttempts);
        assertEquals(List.of(UiText.error("STALE_POLICY")), dialogs.errors);
    }

    @Test void confirmDialogDoesNotPermitSavingIntoAChangedProject() throws Exception {
        access.policy = policyWithAllow(); open();
        dialogs.onConfirm = () -> { access.project = "project-two"; access.revision++; };
        edt(() -> { get("scope.allow.table", JTable.class).setRowSelectionInterval(0, 0); click("scope.allow.delete"); return null; });
        assertEquals(0, access.updateAttempts); assertEquals(1, access.policy.allowScope().size());
    }

    @Test void inconsistentConfigStatusPairDisablesControlsUntilCoherentReload() throws Exception {
        access.switchDuringConfig = true; open();
        assertFalse(edt(() -> button("settings.edit").isEnabled()));
        assertTrue(edt(() -> get("dashboard.state", JLabel.class).getText().contains("확인할 수 없습니다")));
        edt(() -> { click("policy.refresh"); return null; });
        assertTrue(edt(() -> button("settings.edit").isEnabled())); assertEquals(0, access.updates);
    }

    @Test void refreshFailureIsNonModalAndRecoveryDoesNotReplaceAnOpenDraft() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            get("settings.globalRps", JSpinner.class).setValue(2);
            access.failRefresh = true; panel.refreshNow(); assertTrue(dialogs.errors.isEmpty());
            access.failRefresh = false; panel.refreshNow(); save.run();
        };
        edt(() -> { click("settings.edit"); return null; });
        assertEquals(2, access.policy.limits().globalRps()); assertEquals(1, access.updates);
    }

    @Test void allSelectionErrorsAreActionableAndDoNotMutateAnything() throws Exception {
        open();
        edt(() -> { click("rules.edit"); click("scope.allow.edit"); click("traffic.bookmark"); return null; });
        assertEquals(List.of(UiText.error("SELECT_RULE_FIRST"), UiText.error("SELECT_SCOPE_FIRST"), UiText.error("SELECT_TRAFFIC_FIRST")), dialogs.errors);
        assertEquals(0, access.updates);
    }

    @Test void advancedFullPolicyImportIsOptionalStrictAndSupportsNativeFixture() throws Exception {
        GuardConfig fixture = Json.read(Files.readString(Path.of("templates/examples/guard.loopback-smoke.json")), GuardConfig.class);
        open();
        dialogs.editScript = (form, save) -> { get("advanced.policyJson", JTextArea.class).setText(Json.write(fixture)); save.run(); };
        edt(() -> { click("settings.policyJson"); return null; });
        assertEquals(fixture, access.policy); assertEquals(1, access.updates);
        assertTrue(dialogs.errors.isEmpty());
    }

    @Test void advancedImportRejectsDuplicateUnknownNullFractionalAndTrailingJson() throws Exception {
        open();
        String valid = Json.write(policyWithAllow());
        List<String> invalid = new ArrayList<>(List.of("[{", "null", valid + " true", valid.replace("\"schemaVersion\" : 2", "\"schemaVersion\" : 2, \"unknown\" : true"),
                valid.replace("\"schemaVersion\" : 2", "\"schemaVersion\" : 2, \"schemaVersion\" : 2")));
        for (String port : List.of("null", "443.5")) invalid.add(valid.replace("\"port\" : 443", "\"port\" : " + port));
        invalid.add(valid.replace("\"port\" : 443,", ""));
        for (String rate : List.of("null", "2.5")) invalid.add(valid.replace("\"globalRps\" : 0", "\"globalRps\" : " + rate));
        for (String text : invalid) {
            assertNotEquals(valid, text);
            dialogs.editScript = (form, save) -> { get("advanced.policyJson", JTextArea.class).setText(text); save.run(); };
            edt(() -> { click("settings.policyJson"); return null; });
            assertEquals(0, access.updates, text);
        }
        assertEquals(invalid.size(), dialogs.errors.size());
        assertFalse(dialogs.errors.toString().contains(SECRET));
    }

    @Test void advancedOversizePasteCannotSaveThePreviousOrTruncatedInput() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            JTextArea editor = get("advanced.policyJson", JTextArea.class);
            try { ((AbstractDocument) editor.getDocument()).replace(0, editor.getDocument().getLength(), "x".repeat(GuardPanel.MAX_EDITOR_CHARS + 1), null); }
            catch (Exception e) { throw new AssertionError(e); }
            save.run();
        };
        edt(() -> { click("settings.policyJson"); return null; });
        assertEquals(0, access.updates); assertTrue(dialogs.errors.getFirst().contains("2 MiB"));
    }

    @Test void rulesAndScopesEnforceRowBoundsBeforeOpeningAnotherForm() throws Exception {
        GuardConfig old = GuardConfig.defaults();
        List<ScopeEntry> scopes = java.util.stream.IntStream.range(0, 256).mapToObj(i -> new ScopeEntry(false, "h" + i + ".example.test", "https", 443, "/")).toList();
        List<Rule> rules = java.util.stream.IntStream.range(0, 256).mapToObj(i -> new Rule("r" + i, "규칙 " + i, false, Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "DELETE"))).toList();
        access.policy = new GuardConfig(1, scopes, scopes, rules, Mode.ALLOW, old.limits()); open();
        edt(() -> { click("scope.allow.add"); click("scope.block.add"); click("rules.add"); return null; });
        assertEquals(0, dialogs.edits); assertEquals(3, dialogs.errors.size()); assertEquals(0, access.updates);
    }

    @Test void pauseIsFailClosedResumeWarnsOnEmptyScopeAndFailedResumeRevertsUi() throws Exception {
        open();
        edt(() -> { click("dashboard.pause"); return null; });
        assertTrue(access.paused); assertEquals("보호 재개", edt(() -> button("dashboard.pause").getText()));
        dialogs.confirmed = false;
        edt(() -> { click("dashboard.pause"); return null; }); assertTrue(access.paused);
        dialogs.confirmed = true; access.failPause = true;
        edt(() -> { click("dashboard.pause"); return null; }); assertTrue(access.paused);
        assertEquals("보호 재개", edt(() -> button("dashboard.pause").getText()));
        assertFalse(dialogs.errors.toString().contains(SECRET));
        access.failPause = false;
        edt(() -> { click("dashboard.pause"); return null; }); assertFalse(access.paused);
    }

    @Test void passthroughIsSeparatelyConfirmedAndVisibleOnEveryTabWithoutSavingPolicy() throws Exception {
        open();
        dialogs.confirmed = false;
        edt(() -> { click("protection.passthrough"); return null; });
        assertFalse(access.passthrough); assertEquals(0, access.modeChanges); assertEquals(0, access.updates);
        String warning = dialogs.confirmations.getFirst();
        for (String text : List.of("빈 허용 목록", "자동 승인하지 않고 취소", "수집·기록하지 않고", "프로젝트 전환", "워커")) assertTrue(warning.contains(text), text);
        dialogs.confirmed = true;
        edt(() -> { click("protection.passthrough"); return null; });
        assertTrue(access.passthrough); assertFalse(access.paused); assertEquals(0, access.updates);
        assertTrue(edt(() -> get("dashboard.state", JLabel.class).getText().contains("보호 꺼짐")));
        assertTrue(edt(() -> get("scope.state", JTextArea.class).getText().contains("검사하지 않습니다")));
        edt(() -> {
            JTabbedPane tabs = get("tabs", JTabbedPane.class);
            for (int index = 0; index < tabs.getTabCount(); index++) {
                tabs.setSelectedIndex(index);
                assertTrue(get("protection.state", JLabel.class).getText().contains("전체 통과"));
                assertTrue(button("protection.passthrough").isEnabled());
            }
            click("protection.passthrough"); return null;
        });
        assertFalse(access.passthrough); assertEquals(2, access.modeChanges);
        assertEquals(2, dialogs.confirmations.size(), "restoring protection needs no additional permission to bypass anything");
        assertTrue(edt(() -> get("protection.state", JLabel.class).getText().contains("보호 켜짐")));
    }

    @Test void modeConfirmationCannotApplyToChangedProjectOrPolicyOrRaceAtTheControllerBoundary() throws Exception {
        open();
        dialogs.onConfirm = () -> { access.project = "project-two"; access.revision++; };
        edt(() -> { click("protection.passthrough"); return null; });
        assertFalse(access.passthrough); assertEquals(0, access.modeChanges);
        dialogs.onConfirm = () -> {}; access.raceOnPassthrough = true;
        edt(() -> { click("protection.passthrough"); return null; });
        assertFalse(access.passthrough); assertEquals(0, access.modeChanges);
        assertFalse(dialogs.errors.toString().contains(SECRET));
    }

    @Test void failedModeChangeNeverPretendsProtectionIsOffAndUnavailabilityDisablesControl() throws Exception {
        access.failPassthrough = true; open();
        edt(() -> { click("protection.passthrough"); return null; });
        assertFalse(access.passthrough);
        assertTrue(edt(() -> button("protection.passthrough").getText().contains("보호 끔")));
        assertTrue(edt(() -> get("protection.state", JLabel.class).getText().contains("보호 켜짐")));
        assertFalse(dialogs.errors.toString().contains(SECRET));
        access.failRefresh = true;
        edt(() -> { panel.refreshNow(); assertFalse(button("protection.passthrough").isEnabled()); return null; });
        assertTrue(edt(() -> get("protection.state", JLabel.class).getText().contains("확인 불가")));
        edt(() -> { panel.close(); assertFalse(button("protection.passthrough").isEnabled()); return null; });
    }

    @Test void policySaveWhileOffDoesNotSilentlyEnableProtectionAndBlockButtonDoesBlock() throws Exception {
        access.passthrough = true; open();
        dialogs.editScript = (form, save) -> { get("scope.url", JTextField.class).setText("https://example.test/safe"); get("scope.fillUrl", JButton.class).doClick(0); save.run(); };
        edt(() -> { click("scope.allow.add"); return null; });
        assertEquals(1, access.updates); assertTrue(access.passthrough);
        assertTrue(edt(() -> get("message", JLabel.class).getText().contains("보호를 다시 켜야")));
        edt(() -> { click("dashboard.pause"); return null; });
        assertTrue(access.paused); assertFalse(access.passthrough);
        assertTrue(edt(() -> get("protection.state", JLabel.class).getText().contains("새 요청 차단")));
    }

    @Test void renderingFailureWhileOffKeepsAnEmergencyBlockPathAndCannotResumeFromUnknownState() throws Exception {
        access.passthrough = true; open(); access.failTraffic = true;
        edt(() -> {
            panel.refreshNow();
            assertFalse(button("protection.passthrough").isEnabled());
            assertTrue(button("dashboard.pause").isEnabled());
            assertTrue(get("protection.state", JLabel.class).getText().contains("전체 통과일 수 있음"));
            click("dashboard.pause"); return null;
        });
        assertTrue(access.paused); assertFalse(access.passthrough); assertEquals(0, access.modeChanges);
        edt(() -> { click("dashboard.pause"); return null; });
        assertTrue(access.paused, "the unknown-state action can only request a block, never resume");
    }

    @Test void offCounterPersistsInHeaderAndUnavailablePolicyDoesNotInviteAnOffConfirmation() throws Exception {
        access.passthroughCount = 7; access.modeAvailable = false; open();
        edt(() -> { assertFalse(button("protection.passthrough").isEnabled()); click("protection.passthrough"); return null; });
        assertTrue(dialogs.confirmations.isEmpty());
        assertTrue(edt(() -> get("protection.passthroughCount", JLabel.class).getText().contains("7건")));
        access.modeAvailable = true; access.passthroughEnded = true;
        edt(() -> { panel.refreshNow(); return null; });
        assertTrue(edt(() -> get("protection.state", JLabel.class).getText().contains("자동 종료")));
    }

    @Test void addingAConditionFromANewRuleCanSaveAndReopenWithoutManualGrouping() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            click("condition.addLeaf");
            get("condition.field", JComboBox.class).setSelectedItem(Field.PATH);
            get("condition.value", JTextArea.class).setText("/items"); save.run();
        };
        edt(() -> { click("rules.add"); return null; });
        assertEquals(1, access.updates);
        Rule saved = access.policy.rules().getLast();
        assertEquals(Logic.AND, saved.condition().logic());
        assertEquals(2, saved.condition().children().size());
        assertEquals("/items", saved.condition().children().get(1).value());
        edt(() -> { assertEquals(saved, new RuleEditor(saved).value()); return null; });
    }

    @Test void overviewNeverReportsRetiredNativeStallAsCurrentEnforcement() throws Exception {
        access.policy = policyWithAllow(); access.stalled = 1; open();
        assertFalse(edt(() -> get("dashboard.state", JLabel.class).getText().contains("응답 확인 필요")));
        assertFalse(edt(() -> get("dashboard.guidance", JTextArea.class).getText().contains("격리")));
        assertNull(edt(() -> find(panel, "dashboard.reset")));
    }

    @Test void trafficFiltersAreLiteralConjunctiveAndCountExplainsHiddenFilters() throws Exception {
        access.rows = fixtures(); open();
        edt(() -> {
            get("traffic.search", JTextField.class).setText("a.pattern"); assertEquals(1, trafficTable().getRowCount());
            get("traffic.method", JTextField.class).setText("POST"); assertEquals(0, trafficTable().getRowCount());
            assertTrue(get("traffic.count", JLabel.class).getText().contains("필터 적용 중"));
            click("traffic.reset"); assertEquals(3, trafficTable().getRowCount());
            get("traffic.outcome", JComboBox.class).setSelectedIndex(1); assertEquals(1, trafficTable().getRowCount());
            get("traffic.status", JTextField.class).setText("451"); assertEquals(1, trafficTable().getRowCount());
            get("traffic.time", JTextField.class).setText("12:00:01"); assertEquals(1, trafficTable().getRowCount());
            get("traffic.project", JComboBox.class).setSelectedItem("project-one"); assertEquals(0, trafficTable().getRowCount());
            click("traffic.reset"); assertEquals(3, trafficTable().getRowCount());
            get("traffic.bookmarked", JCheckBox.class).setSelected(true); assertEquals(0, trafficTable().getRowCount());
            return null;
        });
    }

    @Test void sortedSelectionBookmarkAndUnmaskedScreenDetailsUseModelIndicesAcrossRefresh() throws Exception {
        access.rows = fixtures(); open();
        edt(() -> {
            JTable table = trafficTable(); table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.DESCENDING)));
            table.setRowSelectionInterval(0, 0); return null;
        });
        awaitRequest(SECRET);
        edt(() -> {
            JTable table = trafficTable();
            String expected = (String) table.getValueAt(0, 3);
            assertTrue(expected.contains("/z?"));
            click("traffic.detail");
            for (String name : List.of("traffic.metadata", "traffic.request", "traffic.response")) assertFalse(get(name, JTextArea.class).isEditable());
            assertTrue(get("traffic.request", JTextArea.class).getText().contains(SECRET));
            assertTrue(get("traffic.request", JTextArea.class).getText().contains("평문 원문"));
            click("traffic.bookmark");
            assertEquals(access.rows.get(2).id(), access.lastBookmarked);
            assertEquals(expected, table.getValueAt(table.getSelectedRow(), 3));
            assertTrue(get("traffic.metadata", JTextArea.class).getText().contains("대상 도착"));
            access.rows = List.of(); panel.refreshNow();
            assertEquals(-1, table.getSelectedRow()); assertEquals("", get("traffic.request", JTextArea.class).getText());
            assertTrue(button("settings.edit").isEnabled());
            return null;
        });
    }

    @Test void evictedProjectFilterIsNotSilentlyBroadened() throws Exception {
        access.rows = fixtures(); open();
        edt(() -> {
            get("traffic.project", JComboBox.class).setSelectedItem("project-two");
            access.rows = List.of(access.rows.getFirst()); panel.refreshNow();
            assertEquals("project-two", get("traffic.project", JComboBox.class).getSelectedItem()); assertEquals(0, trafficTable().getRowCount());
            return null;
        });
    }

    @Test void trafficAndRuleRenderersNeverInterpretHtmlAndEveryRowIsShown() throws Exception {
        List<TrafficEntry> sample = fixtures(); access.rows = java.util.Collections.nCopies(2_010, sample.getFirst());
        GuardConfig old = GuardConfig.defaults();
        access.policy = new GuardConfig(1, List.of(), List.of(), List.of(new Rule("html", "<html><b>literal</b>", true, Mode.BLOCK, old.rules().getFirst().condition())), Mode.ALLOW, old.limits()); open();
        edt(() -> {
            assertEquals(2_010, trafficTable().getRowCount(), "no 2000-row display clip");
            JTable rules = get("rules.table", JTable.class);
            Component renderer = rules.prepareRenderer(rules.getCellRenderer(0, 1), 0, 1);
            assertNull(((JComponent) renderer).getClientProperty(BasicHTML.propertyKey));
            assertEquals("<html><b>literal</b>", ((JLabel) renderer).getText());
            return null;
        });
    }

    @Test void retainedOriginalLargerThanTheEditorLimitIsShownCompleteAndReadOnly() throws Exception {
        access.rows = fixtures();
        String big = "B".repeat(GuardPanel.MAX_EDITOR_CHARS + 4096) + "-END-OF-ORIGINAL";
        TrafficEntry old = access.rows.getFirst();
        TrafficEntry.Message original = new TrafficEntry.Message(old.requestCapture().headers(), big, "text/plain", false, false, true, "UTF8_TEXT");
        access.rows = List.of(new TrafficEntry(old.id(), old.projectId(), old.projectName(), old.timestamp(), old.method(), old.url(), old.mode(), old.disposition(), old.reason(), old.statusCode(), old.hits(), old.revision(), old.bookmarked(), original, old.responseCapture(), old.truncated(), old.provenanceSeal()));
        open();
        edt(() -> { trafficTable().setRowSelectionInterval(0, 0); return null; });
        awaitRequest("-END-OF-ORIGINAL");
        edt(() -> {
            click("traffic.detail");
            JTextArea request = get("traffic.request", JTextArea.class);
            assertFalse(request.isEditable());
            assertNull(((javax.swing.text.AbstractDocument) request.getDocument()).getDocumentFilter(), "no editor length filter on the traffic viewer");
            assertTrue(request.getText().endsWith(big), "the complete original, nothing cut or labelled as cut");
            assertFalse(request.getText().contains("표시 길이 제한"));
            return null;
        });
    }

    @Test void blockExplanationRoutesToRelevantSettingWithoutHarvestingTrafficIntoPolicy() throws Exception {
        access.rows = fixtures(); open();
        edt(() -> {
            get("traffic.outcome", JComboBox.class).setSelectedIndex(1); trafficTable().setRowSelectionInterval(0, 0);
            click("traffic.detail");
            assertTrue(get("traffic.metadata", JTextArea.class).getText().contains("거절"));
            assertFalse(button("traffic.resolve").isEnabled());
            return null;
        });
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("project-one", "Synthetic", request("/outside"), new Decision(Mode.BLOCK, "SCOPE_NOT_ALLOWED", List.of()), 7);
        store.outcome(id, "BLOCKED", "SCOPE_NOT_ALLOWED", 451); access.rows = store.snapshot();
        edt(() -> {
            click("traffic.reset"); panel.refreshNow(); trafficTable().setRowSelectionInterval(0, 0);
            click("traffic.detail");
            assertTrue(get("traffic.metadata", JTextArea.class).getText().contains("호스트·연결 방식·포트·경로"));
            click("traffic.resolve"); assertEquals(1, get("tabs", JTabbedPane.class).getSelectedIndex());
            return null;
        });
        assertTrue(access.policy.allowScope().isEmpty()); assertEquals(0, access.updates);
    }

    @Test void approvalsShowMethodMaskedUrlReasonAndTimeAndAreOneShot() throws Exception {
        access.rows = fixtures(); access.pending.add(pending("ask-one", access.rows.getFirst().id(), "project-one")); open();
        edt(() -> {
            JTable table = get("approval.table", JTable.class);
            assertEquals("GET", table.getValueAt(0, 0)); assertFalse(((String) table.getValueAt(0, 1)).startsWith("[원문 없음"), "the retained original URL, not a masked substitute");
            assertTrue(((String) table.getValueAt(0, 3)).endsWith("초"));
            assertTrue(get("tabs", JTabbedPane.class).getTitleAt(4).contains("1"));
            table.setRowSelectionInterval(0, 0); assertTrue(button("approval.approve").isEnabled());
            click("approval.review"); assertFalse(get("approval.detail", JTextArea.class).isEditable());
            assertTrue(get("approval.detail", JTextArea.class).getText().contains(SECRET), "original, not a masked substitute");
            click("approval.approve"); assertEquals(List.of("ask-one:true"), access.decisions);
            assertFalse(button("approval.approve").isEnabled()); return null;
        });
    }

    @Test void missingApprovalEvidenceDisablesAllowButAllowsHumanDenial() throws Exception {
        access.pending.add(pending("ask-missing", "gone", "project-one")); open();
        edt(() -> {
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0);
            assertFalse(button("approval.approve").isEnabled()); assertTrue(button("approval.deny").isEnabled());
            click("approval.review");
            assertTrue(get("approval.detail", JTextArea.class).getText().contains("증거가 남아 있지"));
            click("approval.deny"); return null;
        });
        assertEquals(List.of("ask-missing:false"), access.decisions);
    }

    @Test void expiredOtherProjectPausedAndChangedPolicyApprovalsAreNotActionable() throws Exception {
        access.rows = fixtures();
        access.pending.add(new Pending("expired", access.rows.getFirst().id(), "project-one", Instant.now().minusSeconds(60).toString(), Instant.now().minusSeconds(1).toString()));
        access.pending.add(pending("other", access.rows.getFirst().id(), "project-two")); open();
        edt(() -> {
            JTable table = get("approval.table", JTable.class);
            for (int i = 0; i < 2; i++) { table.setRowSelectionInterval(i, i); assertFalse(button("approval.approve").isEnabled()); assertFalse(button("approval.deny").isEnabled()); }
            access.pending.clear(); access.pending.add(pending("live", access.rows.getFirst().id(), "project-one")); panel.refreshNow();
            table.setRowSelectionInterval(0, 0); access.paused = true; panel.refreshNow(); assertFalse(button("approval.approve").isEnabled());
            access.paused = false; access.revision++; panel.refreshNow(); assertFalse(button("approval.approve").isEnabled());
            return null;
        });
        assertTrue(access.decisions.isEmpty());
    }

    @Test void approvalRechecksRetainedEvidenceAtClickNotJustTheLastTimerSnapshot() throws Exception {
        access.rows = fixtures(); access.pending.add(pending("ask", access.rows.getFirst().id(), "project-one")); open();
        edt(() -> {
            get("approval.table", JTable.class).setRowSelectionInterval(0, 0); assertTrue(button("approval.approve").isEnabled());
            access.rows = List.of(); click("approval.approve"); return null;
        });
        assertTrue(access.decisions.isEmpty()); assertEquals(List.of(UiText.error("APPROVAL_EVIDENCE_MISSING")), dialogs.errors);
    }

    @Test void exportsUseOneFlowWithExplicitRangeFormatAndRunOffEdt() throws Exception {
        access.rows = fixtures(); open(); dialogs.target = temp.resolve("masked.json");
        edt(() -> { get("traffic.search", JTextField.class).setText("middle"); click("traffic.export"); return null; });
        awaitExport(); assertFalse(access.exportOnEdt); assertEquals(List.of(access.rows.get(1)), access.exported);
        assertEquals("JSON", Files.readString(dialogs.target));
        dialogs.target = temp.resolve("selected.har");
        edt(() -> {
            click("traffic.reset"); trafficTable().getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.DESCENDING)));
            trafficTable().setRowSelectionInterval(0, 0); get("traffic.exportRange", JComboBox.class).setSelectedIndex(1);
            get("traffic.exportFormat", JComboBox.class).setSelectedIndex(1); click("traffic.export"); return null;
        });
        awaitExport(); assertEquals(List.of(access.rows.getLast()), access.exported);
        assertEquals("HAR", Files.readString(dialogs.target)); assertEquals(List.of("json", "har"), dialogs.chosenExtensions);
    }

    @Test void realStoreHumanExportsAreConsentedPlaintextOriginalsThroughWorkerAndAtomicWriter() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("project-one", "Synthetic", new RequestData("POST", "https://example.test/?token=" + SECRET, "example.test", 443, true,
                List.of(new RequestData.Header("Authorization", "Bearer " + SECRET), new RequestData.Header("Content-Type", "application/json")),
                ("{\"password\":\"" + SECRET + "\",\"safe\":\"yes\"}").getBytes(StandardCharsets.UTF_8)), new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", 200); access.rows = store.snapshot(); access.exportStore = store; open();
        for (boolean har : List.of(false, true)) {
            dialogs.target = temp.resolve(har ? "real.har" : "real.json");
            edt(() -> { get("traffic.exportFormat", JComboBox.class).setSelectedIndex(har ? 1 : 0); click("traffic.export"); return null; });
            awaitExport(); String text = Files.readString(dialogs.target);
            assertTrue(text.contains(SECRET), "explicit human export is plaintext"); assertFalse(text.contains("[REDACTED]"));
            assertTrue(text.contains("HUMAN_ORIGINAL")); assertNotNull(Json.MAPPER.readTree(text));
            assertTrue(dialogs.confirmations.getLast().contains("Authorization") && dialogs.confirmations.getLast().contains("새 파일"), "consent is required even for a NEW file");
            assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(dialogs.target)));
        }
        // the evidence rows of the same store carry the originals too
        assertTrue(store.exportJson(store.snapshot()).contains(SECRET));
    }

    @Test void exportOfRowsClearedFromRealStoreBeforeSerializationFailsCategoricallyWithoutWriting() throws Exception {
        EvidenceStore store = new EvidenceStore();
        store.begin("project-one", "Synthetic", new RequestData("GET", "https://example.test/?token=" + SECRET, "example.test", 443, true,
                List.of(), new byte[0]), new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
        access.rows = store.snapshot(); access.exportStore = store; access.blockExport = true; open();
        // The panel freezes its rows at click time; the store is cleared before the worker serializes them.
        dialogs.target = temp.resolve("blocked.json");
        edt(() -> { click("traffic.export"); return null; }); assertTrue(access.serializeStarted.await(5, TimeUnit.SECONDS));
        store.clear(); access.serializeRelease.countDown(); awaitExport();
        // the final pre-publication checkpoint observed the clear: nothing is published and the temp file is removed
        assertFalse(Files.exists(dialogs.target)); assertEquals(UiText.error("EXPORT_FAILED"), dialogs.errors.getLast());
        for (boolean har : List.of(false, true)) for (boolean existing : List.of(false, true)) {
            dialogs.target = temp.resolve("cleared-" + har + "-" + existing + (har ? ".har" : ".json"));
            if (existing) Files.writeString(dialogs.target, "keep");
            dialogs.errors.clear();
            edt(() -> { get("traffic.exportFormat", JComboBox.class).setSelectedIndex(har ? 1 : 0); click("traffic.export"); return null; });
            awaitExport();
            assertEquals(List.of(UiText.error("EXPORT_FAILED")), dialogs.errors);
            if (existing) assertEquals("keep", Files.readString(dialogs.target)); else assertFalse(Files.exists(dialogs.target));
        }
        assertFalse(dialogs.errors.toString().contains(SECRET));
        try (var files = Files.list(temp)) { assertTrue(files.noneMatch(f -> f.getFileName().toString().endsWith(".tmp"))); }
    }

    @Test void everyHumanExportNeedsPlaintextConsentEvenForANewFileAndDeclineWritesNothing() throws Exception {
        access.rows = fixtures(); open(); dialogs.target = temp.resolve("new.json"); dialogs.confirmed = false;
        edt(() -> { click("traffic.export"); return null; });
        assertEquals(0, access.exportCalls); assertFalse(Files.exists(dialogs.target));
        assertEquals(1, dialogs.confirmations.size()); assertTrue(dialogs.confirmations.getFirst().contains("평문"));
        dialogs.confirmed = true; access.invalidateExport = true;
        edt(() -> { click("traffic.export"); return null; }); awaitExport();
        assertFalse(Files.exists(dialogs.target), "a transition observed at the final checkpoint publishes nothing");
        try (var files = Files.list(temp)) { assertTrue(files.noneMatch(f -> f.getFileName().toString().endsWith(".tmp"))); }
        access.invalidateExport = false;
        edt(() -> { click("traffic.export"); return null; }); awaitExport();
        assertTrue(Files.exists(dialogs.target));
    }

    @Test void exportRequiresRowsChooserAndExplicitOverwriteConsent() throws Exception {
        open(); edt(() -> { click("traffic.export"); return null; });
        assertEquals(0, access.exportCalls); assertTrue(dialogs.chosenExtensions.isEmpty());
        access.rows = fixtures(); edt(() -> { panel.refreshNow(); click("traffic.export"); return null; });
        assertEquals(0, access.exportCalls);
        dialogs.target = temp.resolve("existing.json"); Files.writeString(dialogs.target, "keep"); dialogs.confirmed = false;
        edt(() -> { click("traffic.export"); return null; }); assertEquals("keep", Files.readString(dialogs.target)); assertEquals(0, access.exportCalls);
        edt(() -> { get("traffic.exportRange", JComboBox.class).setSelectedIndex(1); click("traffic.export"); return null; });
        assertEquals(0, access.exportCalls);
    }

    @Test void symlinkTargetIsRejectedBeforeAnySerializationOrWrite() throws Exception {
        access.rows = fixtures(); open(); Path original = temp.resolve("original"); Files.writeString(original, "keep");
        Path link = temp.resolve("link.json"); Files.createSymbolicLink(link, original); dialogs.target = link;
        edt(() -> { click("traffic.export"); return null; });
        assertEquals(0, access.exportCalls); assertEquals("keep", Files.readString(original));
        assertEquals(List.of(UiText.error("EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE")), dialogs.errors);
    }

    @Test void exportUsesFrozenSnapshotRejectsConcurrentStartAndHidesWorkerErrors() throws Exception {
        access.rows = fixtures(); access.blockExport = true; open(); dialogs.target = temp.resolve("frozen.json");
        edt(() -> { click("traffic.export"); return null; }); assertTrue(access.serializeStarted.await(5, TimeUnit.SECONDS));
        List<TrafficEntry> frozen = access.rows;
        edt(() -> { access.rows = List.of(); panel.refreshNow(); click("traffic.export"); return null; });
        assertEquals(UiText.error("EXPORT_IN_PROGRESS"), dialogs.errors.getLast());
        access.serializeRelease.countDown(); awaitExport(); assertEquals(frozen, access.exported);
        access.failExport = true; access.blockExport = false; access.rows = fixtures(); dialogs.target = temp.resolve("fail.json");
        edt(() -> { panel.refreshNow(); click("traffic.export"); return null; }); awaitExport();
        assertFalse(Files.exists(dialogs.target)); assertEquals(UiText.error("EXPORT_FAILED"), dialogs.errors.getLast());
        assertFalse(dialogs.errors.toString().contains(SECRET));
    }

    @Test void clearEvidenceIsConfirmedAndDiagnosticsNeverWritePolicy() throws Exception {
        access.rows = fixtures(); open(); dialogs.confirmed = false;
        edt(() -> { click("settings.clear"); return null; }); assertEquals(0, access.clears);
        dialogs.confirmed = true;
        edt(() -> { click("settings.clear"); return null; }); assertEquals(1, access.clears);
        dialogs.editScript = (form, save) -> {
            assertFalse(get("diagnostics.status", JTextArea.class).isEditable()); save.run();
        };
        edt(() -> { click("settings.diagnostics"); return null; }); assertEquals(0, access.updates);
    }

    @Test void timerAndUnrelatedArrivalsDoNotResetDetailSelectionOrScrollIntent() throws Exception {
        access.rows = fixtures(); access.pending.add(pending("ask", access.rows.getFirst().id(), "project-one")); open();
        edt(() -> { trafficTable().setRowSelectionInterval(0, 0); return null; });
        awaitRequest(SECRET);
        edt(() -> {
            click("traffic.detail");
            JTextArea request = get("traffic.request", JTextArea.class);
            request.select(5, 12); String selectedRequest = request.getSelectedText(); assertNotNull(selectedRequest); assertEquals(7, selectedRequest.length());
            JTable approvals = get("approval.table", JTable.class); approvals.setRowSelectionInterval(0, 0); click("approval.review");
            JTextArea approval = get("approval.detail", JTextArea.class);
            approval.select(5, 12); String selectedApproval = approval.getSelectedText();
            JTextArea settings = get("settings.summary", JTextArea.class);
            settings.select(5, 12); String selectedSettings = settings.getSelectedText();
            panel.refreshNow();
            assertEquals(selectedRequest, request.getSelectedText());
            assertEquals(selectedApproval, approval.getSelectedText());
            assertEquals(selectedSettings, settings.getSelectedText());
            access.rows = List.of(access.rows.get(2), access.rows.getFirst(), access.rows.get(1));
            panel.refreshNow();
            assertEquals(selectedRequest, request.getSelectedText(), "re-sorted rows must not temporarily clear details");
            assertEquals(selectedApproval, approval.getSelectedText());
            assertInstanceOf(NonScrollingCaret.class, get("dashboard.guidance", JTextArea.class).getCaret());
            return null;
        });
    }

    @Test void informationalFormTextDoesNotStealInitialFocusOrAutoScrollTheForm() throws Exception {
        open();
        dialogs.editScript = (form, save) -> {
            JTextArea guidance = get("scope.message", JTextArea.class);
            assertInstanceOf(NonScrollingCaret.class, guidance.getCaret()); assertFalse(guidance.isFocusable());
            assertTrue(get("scope.url", JTextField.class).isFocusable());
            assertTrue(get("scope.preview", JTextArea.class).isFocusable(), "actual scope stays selectable/copyable");
        };
        edt(() -> { click("dashboard.addTarget"); return null; });
        assertEquals(0, access.updates);
    }

    @Test void listAndDetailDoNotCompeteForSmallTabHeightAndLargeFontRowsGrow() throws Exception {
        open();
        edt(() -> {
            JSplitPane history = (JSplitPane) SwingUtilities.getAncestorOfClass(JSplitPane.class, trafficTable());
            assertNotNull(history, "inline paired inspector is explicitly resizable/collapsible");
            assertTrue(history.isOneTouchExpandable()); assertEquals(JSplitPane.VERTICAL_SPLIT, history.getOrientation());
            assertTrue(history.getMinimumSize().height < 150);
            assertNotNull(SwingUtilities.getAncestorOfClass(JScrollPane.class, trafficTable()));
            trafficTable().setFont(trafficTable().getFont().deriveFont(28f));
            assertTrue(trafficTable().getRowHeight() > 28); return null;
        });
    }

    @Test void closeStopsTimerDisablesWritesClosesEditorsAndRejectsHeldModalSave() throws Exception {
        edt(() -> { panel = new GuardPanel(access, dialogs, true); return null; });
        java.lang.reflect.Field field = GuardPanel.class.getDeclaredField("timer"); field.setAccessible(true); Timer timer = (Timer) field.get(panel);
        assertTrue(edt(timer::isRunning)); assertEquals(1000, timer.getDelay());
        assertThrows(IllegalStateException.class, panel::close);
        dialogs.editScript = (form, save) -> { get("settings.globalRps", JSpinner.class).setValue(2); panel.close(); save.run(); };
        edt(() -> { click("settings.edit"); panel.close(); return null; });
        assertFalse(edt(timer::isRunning)); assertEquals(1, dialogs.closedEditors); assertEquals(0, access.updateAttempts);
        assertFalse(edt(() -> button("settings.edit").isEnabled()));
        int refreshes = access.refreshes; edt(() -> { panel.refreshNow(); return null; }); assertEquals(refreshes, access.refreshes);
    }

    private void open() throws Exception { edt(() -> { panel = new GuardPanel(access, dialogs, false); return null; }); }
    private JButton button(String name) { return get(name, JButton.class); }
    private JTable trafficTable() { return get("traffic.table", JTable.class); }
    private void click(String name) { button(name).doClick(0); }
    private static void pressEnter(JTable table) {
        Object key = table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
        assertEquals("guard.openRow", key);
        table.getActionMap().get(key).actionPerformed(new ActionEvent(table, ActionEvent.ACTION_PERFORMED, "Enter"));
    }
    private static void mouseClick(JTable table, int row, int count, int button) {
        table.setSize(900, 220);
        java.awt.Rectangle cell = table.getCellRect(row, 0, true);
        table.dispatchEvent(new MouseEvent(table, MouseEvent.MOUSE_CLICKED, 0, 0, cell.x + 4, cell.y + 4, count, false, button));
    }
    private void selectRule(String id) {
        JTable table = get("rules.table", JTable.class);
        int model = java.util.stream.IntStream.range(0, access.policy.rules().size()).filter(i -> access.policy.rules().get(i).id().equals(id)).findFirst().orElseThrow();
        int view = table.convertRowIndexToView(model); table.setRowSelectionInterval(view, view);
    }
    private <T> T get(String name, Class<T> type) {
        Component found = panel == null ? null : find(panel, name);
        if (found == null && dialogs.form != null) found = find(dialogs.form.component(), name);
        return type.cast(java.util.Objects.requireNonNull(found, name));
    }
    private static Component find(Component root, String name) {
        if (name.equals(root.getName())) return root;
        if (root instanceof Container c) for (Component child : c.getComponents()) { Component found = find(child, name); if (found != null) return found; }
        return null;
    }
    private void awaitRequest(String literal) throws Exception {
        GuardPanelTrafficViewTest.await(() -> get("traffic.request", JTextArea.class).getText().contains(literal));
    }
    private void awaitExport() throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (System.nanoTime() < until) {
            boolean done = edt(() -> {
                java.lang.reflect.Field field = GuardPanel.class.getDeclaredField("exportWorker"); field.setAccessible(true); return field.get(panel) == null;
            });
            if (done) return;
            Thread.sleep(15);
        }
        fail("redacted export did not finish");
    }
    private static <T> T edt(Callable<T> body) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) return body.call();
        AtomicReference<T> result = new AtomicReference<>(); AtomicReference<Throwable> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> { try { result.set(body.call()); } catch (Throwable t) { error.set(t); } });
        if (error.get() instanceof Exception e) throw e;
        if (error.get() instanceof Error e) throw e;
        return result.get();
    }
    private static RequestData request(String path) { return new RequestData("GET", "https://example.test" + path, "example.test", 443, true, List.of(), new byte[0]); }
    private static GuardConfig policyWithAllow() {
        GuardConfig d = GuardConfig.defaults(); return new GuardConfig(2, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), List.of(), d.rules(), Mode.ALLOW, d.limits());
    }
    private static List<TrafficEntry> fixtures() {
        EvidenceStore store = new EvidenceStore(); List<TrafficEntry> rows = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            RequestData r = new RequestData(i == 1 ? "POST" : "GET", "https://example.test/" + (i == 0 ? "a.pattern" : i == 1 ? "middle" : "z") + "?token=" + SECRET,
                    "example.test", 443, true, List.of(new RequestData.Header("Authorization", "Bearer " + SECRET), new RequestData.Header("Content-Type", "application/json")),
                    ("{\"password\":\"" + SECRET + "\",\"item\":\"safe\"}").getBytes(StandardCharsets.UTF_8));
            String id = store.begin(i == 1 ? "project-two" : "project-one", "Synthetic", r, new Decision(Mode.ASK, "RULE_MATCH", List.of(new Decision.RuleHit("ask-rule", "사람 검토", Mode.ASK))), 7);
            store.outcome(id, i == 1 ? "BLOCKED" : "FORWARDED", i == 1 ? "DENIED" : "NATIVE_RELEASED", i == 1 ? 451 : 200);
            TrafficEntry e = store.snapshot().stream().filter(entry -> entry.id().equals(id)).findFirst().orElseThrow();
            rows.add(new TrafficEntry(e.id(), e.projectId(), e.projectName(), "2026-11-03T12:00:0" + i + "Z", e.method(), e.url(), e.mode(), e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal()));
        }
        return List.copyOf(rows);
    }
    private static Pending pending(String id, String evidence, String project) { return new Pending(id, evidence, project, Instant.now().toString(), Instant.now().plusSeconds(120).toString()); }

    private static final class HumanDialogs implements GuardPanel.Dialogs {
        boolean confirmed = true; Path target; EditorForm<?> form; int edits; int closedEditors;
        Runnable onConfirm = () -> {};
        BiConsumer<EditorForm<?>, Runnable> editScript = (form, save) -> {};
        final List<String> errors = new ArrayList<>(); final List<String> confirmations = new ArrayList<>(); final List<String> chosenExtensions = new ArrayList<>();
        @Override public boolean confirm(Component parent, String text) { assertTrue(SwingUtilities.isEventDispatchThread()); confirmations.add(text); onConfirm.run(); return confirmed; }
        @Override public Path chooseExport(Component parent, String extension) { assertTrue(SwingUtilities.isEventDispatchThread()); chosenExtensions.add(extension); return target; }
        @Override public void error(Component parent, String text) { assertTrue(SwingUtilities.isEventDispatchThread()); errors.add(text); }
        @Override public void edit(Component parent, String title, String saveLabel, EditorForm<?> form, Runnable save) { assertTrue(SwingUtilities.isEventDispatchThread()); this.form = form; edits++; editScript.accept(form, save); }
        @Override public void closeEditors() { closedEditors++; }
    }
    private static final class FakeAccess implements GuardUiAccess {
        GuardConfig policy = GuardConfig.defaults(); String project = "project-one"; long revision = 7;
        String submittedProject; long submittedRevision; int updates; int updateAttempts; int refreshes; int clears; int stalled;
        boolean paused; boolean passthrough; boolean failPassthrough; boolean raceOnPassthrough; int modeChanges;
        boolean failTraffic; boolean modeAvailable = true; boolean passthroughEnded; long passthroughCount;
        boolean raceOnUpdate; boolean switchDuringConfig; boolean failPause; boolean failRefresh; boolean failExport; boolean blockExport; boolean exportOnEdt;
        EvidenceStore exportStore; int exportCalls; String lastBookmarked; List<TrafficEntry> rows = List.of(); List<Pending> pending = new ArrayList<>(); List<String> decisions = new ArrayList<>();
        volatile List<TrafficEntry> exported = List.of(); final CountDownLatch serializeStarted = new CountDownLatch(1); final CountDownLatch serializeRelease = new CountDownLatch(1);
        private static void onEdt() { assertTrue(SwingUtilities.isEventDispatchThread()); }
        @Override public GuardConfig config() {
            onEdt(); GuardConfig result = policy;
            if (switchDuringConfig) { switchDuringConfig = false; project = "project-two"; revision++; policy = policyWithAllow(); }
            return result;
        }
        @Override public void updateConfig(GuardConfig config, String expectedProject, long expectedRevision) {
            onEdt(); updateAttempts++; submittedProject = expectedProject; submittedRevision = expectedRevision;
            if (raceOnUpdate) { project = "project-two"; revision++; }
            if (!project.equals(expectedProject) || revision != expectedRevision) throw new IllegalStateException(SECRET);
            new PolicyEngine().validate(config); policy = config; revision++; updates++; pending.clear();
        }
        @Override public Map<String, Object> status() {
            onEdt(); Map<String, Object> result = new java.util.LinkedHashMap<>(Map.of("projectId", project, "projectName", "Current Burp project", "revision", revision, "paused", paused, "closed", false,
                    "note", "SYNTHETIC", "passthrough", passthrough, "evidence", Map.of("retainedEntries", rows.size()),
                    "gate", Map.of("stalled", stalled, "active", stalled, "queued", 0), "approvalCount", pending.size()));
            result.put("passthroughAvailable", modeAvailable); result.put("passthroughEnded", passthroughEnded); result.put("passthroughCount", passthroughCount);
            return Map.copyOf(result);
        }
        @Override public List<TrafficEntry> traffic() { onEdt(); if (failTraffic) throw new IllegalStateException(SECRET); return List.copyOf(rows); }
        @Override public String rawUrl(String id) { return rows.stream().filter(e -> e.id().equals(id)).map(e -> e.url().replace("[REDACTED]", SECRET)).findFirst().orElse(null); }
        @Override public String rawRequest(String id) { return rawUrl(id) == null ? null : "Authorization: Bearer " + SECRET + "\nCookie: session=" + SECRET + "\n"; }
        @Override public String rawResponse(String id) { return rawUrl(id) == null ? null : "HTTP/1.1 200\nsynthetic response"; }
        @Override public Map<String,Object> rawCaptureInfo(String id) {
            TrafficEntry row = rows.stream().filter(e -> e.id().equals(id)).findFirst().orElse(null);
            if (row == null) return Map.of("available", false);
            Map<String,Object> info = new java.util.LinkedHashMap<>();
            info.put("available", true); info.put("method", row.method()); info.put("projectId", row.projectId()); info.put("projectName", row.projectName());
            info.put("hits", row.hits().stream().map(h -> Map.of("id", h.id(), "name", h.name(), "mode", h.mode().name())).toList());
            info.put("metadataOmitted", false);
            return info;
        }
        boolean invalidateExport;
        private final class FakeExport implements HumanExport {
            final List<TrafficEntry> selection; final EvidenceStore.HumanEvidence evidence; final boolean har; final long generation;
            FakeExport(List<TrafficEntry> selection, EvidenceStore.HumanEvidence evidence, boolean har, long generation) { this.selection = selection; this.evidence = evidence; this.har = har; this.generation = generation; }
            @Override public byte[] serialize() {
                exportOnEdt = SwingUtilities.isEventDispatchThread(); exportCalls++; serializeStarted.countDown();
                if (blockExport) try { assertTrue(serializeRelease.await(5, TimeUnit.SECONDS)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(SECRET); }
                if (failExport) throw new IllegalArgumentException(SECRET); exported = List.copyOf(selection);
                if (evidence == null) return (har ? "HAR" : "JSON").getBytes(StandardCharsets.UTF_8);
                return har ? evidence.har(Map.of("projectId", project)) : evidence.json(Map.of("projectId", project));
            }
        }
        @Override public HumanExport humanExport(List<String> ids, boolean har) {
            onEdt();
            List<TrafficEntry> selection = ids.stream().map(id -> rows.stream().filter(e -> e.id().equals(id)).findFirst().orElseThrow(() -> new IllegalArgumentException("INVALID_EVIDENCE_SELECTION"))).toList();
            return new FakeExport(selection, exportStore == null ? null : exportStore.humanEvidence(ids), har, exportStore == null ? 0 : exportStore.rawGeneration());
        }
        @Override public boolean humanExportCurrent(HumanExport export) {
            return !invalidateExport && export instanceof FakeExport f && (exportStore == null || f.generation == exportStore.rawGeneration());
        }
        @Override public List<Pending> approvals() { onEdt(); return List.copyOf(pending); }
        @Override public boolean decideApproval(String id, boolean allow) { onEdt(); boolean removed = pending.removeIf(p -> p.id().equals(id)); if (removed) decisions.add(id + ":" + allow); return removed; }
        @Override public void bookmark(String id, boolean value) {
            onEdt(); lastBookmarked = id; rows = rows.stream().map(e -> e.id().equals(id) ? new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(), e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), value, e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal()) : e).toList();
        }
        @Override public String exportJson(List<TrafficEntry> entries) { return export(entries, "JSON"); }
        @Override public String exportHar(List<TrafficEntry> entries) { return export(entries, "HAR"); }
        private String export(List<TrafficEntry> entries, String format) {
            throw new AssertionError("the human UI must never use the safe masked export methods");
        }
        @Override public void clearEvidence() { onEdt(); rows = List.of(); clears++; }
        @Override public void pause(boolean value) { onEdt(); if (failPause) throw new IllegalStateException(SECRET); passthrough = false; paused = value; revision++; pending.clear(); }
        @Override public void passthrough(boolean enabled, String expectedProjectId, long expectedRevision) {
            onEdt();
            if (raceOnPassthrough) revision++;
            if (failPassthrough || !project.equals(expectedProjectId) || revision != expectedRevision) throw new IllegalStateException(SECRET);
            passthrough = enabled; revision++; pending.clear(); modeChanges++;
        }
        @Override public void refreshProject() { onEdt(); refreshes++; if (failRefresh) throw new IllegalStateException(SECRET); }
    }
}
