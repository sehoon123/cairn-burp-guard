package dev.cairnguard.ui;

import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.*;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import dev.cairnguard.runtime.ResponseWatcher.Candidate;
import dev.cairnguard.runtime.ResponseWatcher.Overlay;
import dev.cairnguard.ui.editor.EditorForm;
import dev.cairnguard.ui.editor.RuleEditor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import static org.junit.jupiter.api.Assertions.*;

/** Human-only v2 synthetic workflows. No Burp/native/network or live desktop session is used. */
class GuardPanelV2Test {
    static final String SECRET = "synthetic-ui-only-credential";
    final Access access = new Access();
    final Human dialogs = new Human();
    GuardPanel panel;
    @TempDir Path directory;
    @AfterEach void close() throws Exception { if(panel!=null) edt(() -> {panel.close();return null;}); }

    @Test void allNewControlsAreDiscoverableWithoutJsonAndDoNotAutosaveOrResetOnRefresh() throws Exception {
        open();
        edt(() -> {
            for(String name:List.of("overlays.release","overlays.releaseAll","candidates.block","candidates.threshold","candidates.ignore","incident.export","dashboard.resetIntent")) assertNotNull(find(panel,name),name);
            click("policy.refresh"); click("dashboard.overlays"); assertEquals(6,get("tabs",JTabbedPane.class).getSelectedIndex());
            dialogs.edit=(form,save)-> {
                for(String name:List.of("settings.heavyMiB","settings.circuit.enabled","settings.fanout.enabled","settings.intent.maxRequests","settings.probes.table","settings.pathLimits.table","settings.listenerPorts")) assertNotNull(find(form.component(),name),name);
                get("settings.heavyMiB",JTextField.class).setText("8");
                get("settings.listenerPorts",JTextField.class).setText("8080");
                panel.refreshNow();
                assertEquals("8",get("settings.heavyMiB",JTextField.class).getText(),"timer must not replace an open draft");
            };
            click("settings.edit");
            return null;
        });
        assertEquals(0,access.updates); assertEquals(0,access.runtimeCalls); assertEquals(GuardConfig.defaults(),access.policy);
    }

    @Test void everyOrdinaryPolicyCopyPreservesLimitsAndListenerSelection() throws Exception {
        access.policy=fullPolicy(); open(); Limits original=access.policy.limits();
        dialogs.edit=(form,save)-> {
            if(form instanceof RuleEditor) get("rule.name",JTextField.class).setText("이름만 변경");
            else get("scope.host",JTextField.class).setText("example.test");
            save.run();
        };
        edt(()->{click("scope.allow.add"); selectRule("delete-method");click("rules.edit");click("rules.toggle");click("rules.delete");return null;});
        assertEquals(4,access.updates); assertEquals(original,access.policy.limits());assertEquals(List.of(8080),access.policy.guardListenerPorts());
        dialogs.edit=(form,save)->{ get("settings.globalRps",JSpinner.class).setValue(2);save.run(); };
        edt(()->{click("settings.edit");return null;});
        Limits l=access.policy.limits();assertEquals(original.perPathMaxResponseBytes(),l.perPathMaxResponseBytes());
        assertEquals(original.circuit5xx(),l.circuit5xx());assertEquals(original.fanout(),l.fanout());assertEquals(original.healthProbePaths(),l.healthProbePaths());assertEquals(original.heavyPathLimits(),l.heavyPathLimits());
        assertEquals(original.perIntentMaxRequests(),l.perIntentMaxRequests());assertEquals(List.of(8080),access.policy.guardListenerPorts());
    }

    @Test void exemptPinnedAboveAllSortsButPolicyOrderUntouchedAndRiskySaveRequiresConsent() throws Exception {
        Rule ex=new Rule("ex","ZZ exception",true,Mode.EXEMPT,Condition.and(Condition.leaf(Field.METHOD,Match.EXACT,"GET"),Condition.leaf(Field.PATH,Match.EXACT,"/health")));
        List<Rule> authored=List.of(GuardConfig.defaults().rules().getFirst(),ex,new Rule("b","AA block",true,Mode.BLOCK,Condition.leaf(Field.PATH,Match.EXACT,"/health")));
        access.policy=new GuardConfig(2,List.of(new ScopeEntry(true,"example.test","https",443,"")),List.of(),authored,Mode.ALLOW,GuardConfig.defaults().limits());open();
        edt(()->{
            JTable table=get("rules.table",JTable.class);
            for(int col=0;col<4;col++)for(int direction=0;direction<2;direction++){
                table.getRowSorter().toggleSortOrder(col);assertEquals("ZZ exception",table.getValueAt(0,1));
                JLabel renderer=(JLabel)table.prepareRenderer(table.getCellRenderer(0,1),0,1);assertNotEquals(table.getForeground(),renderer.getForeground());
            }
            return null;
        });
        assertEquals(authored,access.policy.rules());assertEquals(0,access.updates);
        dialogs.confirmed=false;
        dialogs.edit=(form,save)->{get("rule.name",JTextField.class).setText("변경한 예외");save.run();};
        edt(()->{selectRule("ex");click("rules.edit");return null;});
        assertEquals(0,access.updates);assertTrue(dialogs.confirmations.getLast().contains("BLOCK·ASK"));
        dialogs.confirmed=true;edt(()->{click("rules.edit");return null;});assertEquals(1,access.updates);assertEquals("변경한 예외",access.policy.rules().get(1).name());
    }

    @Test void listenerNarrowingAndProbeEnableEachRequireExplicitConfirmationAndUseOriginalCas() throws Exception {
        open(); dialogs.confirmed=false;
        dialogs.edit=(form,save)->{get("settings.listenerPorts",JTextField.class).setText("8080");save.run();};
        edt(()->{click("settings.edit");return null;});assertEquals(0,access.updates);assertTrue(dialogs.confirmations.getLast().contains("실제 인바운드"));assertTrue(dialogs.confirmations.getLast().contains("미지원"));assertTrue(dialogs.confirmations.getLast().contains("LISTENER_UNVERIFIED"));assertTrue(dialogs.confirmations.getLast().contains("선택·미선택 모두"));
        dialogs.confirmed=true;edt(()->{click("settings.edit");return null;});assertEquals(List.of(8080),access.policy.guardListenerPorts());assertEquals(1,access.updates);
        dialogs.confirmed=false;
        dialogs.edit=(form,save)->{
            get("settings.probes.enabled",JCheckBox.class).setSelected(true);click("settings.probes.add");
            JTable t=get("settings.probes.table",JTable.class);t.setValueAt("example.test",0,1);t.setValueAt("/health",0,3);save.run();
        };
        edt(()->{click("settings.edit");return null;});assertFalse(access.policy.limits().healthProbePassthrough());assertTrue(dialogs.confirmations.getLast().contains("GET도 부작용"));
        dialogs.confirmed=true;dialogs.onConfirm=()->access.project="new-project";
        edt(()->{click("settings.edit");return null;});assertEquals(1,access.updates);assertFalse(access.policy.limits().healthProbePassthrough());
        assertTrue(dialogs.errors.contains(UiText.error("STALE_POLICY")));assertEquals(1,access.updateAttempts);
    }

    @Test void overlaysExposeExpiryAndReleaseOneAllAreCasBoundMemoryOnlyActions() throws Exception {
        access.overlays=new ArrayList<>(List.of(overlay("one",5000),overlay("two",10000)));open();
        edt(()->{
            JTable t=get("overlays.table",JTable.class);assertEquals(2,t.getRowCount());assertTrue(((String)t.getValueAt(0,4)).endsWith("Z"));assertTrue((Long)t.getValueAt(0,5)>0);
            t.setRowSelectionInterval(0,0);dialogs.confirmed=false;click("overlays.release");assertEquals(0,access.runtimeCalls);
            dialogs.confirmed=true;click("overlays.release");assertEquals(1,t.getRowCount());assertEquals("p",access.casProject);assertEquals(7,access.casRevision);
            click("overlays.releaseAll");assertEquals(0,t.getRowCount());return null;
        });
        assertEquals(2,access.runtimeCalls);assertEquals(0,access.updates);
    }

    @Test void expiredOrReplacedOverlayIsNotMistakenForAReplacementAndStaleConfirmationCannotRelease() throws Exception {
        access.overlays=new ArrayList<>(List.of(overlay("old",5000)));open();
        edt(()->{
            get("overlays.table",JTable.class).setRowSelectionInterval(0,0);
            dialogs.onConfirm=()->access.overlays=new ArrayList<>(List.of(overlay("new",5000)));
            click("overlays.release");assertEquals("new",access.overlays.getFirst().id());assertTrue(get("message",JLabel.class).getText().contains("만료·교체"));
            get("overlays.table",JTable.class).setRowSelectionInterval(0,0);
            dialogs.onConfirm=()->access.revision++;
            click("overlays.releaseAll");return null;
        });assertEquals(1,access.runtimeCalls);assertEquals(0,access.updates);
    }

    @Test void candidateStatsDefaultMaxDescendingAndSafeUrlOnlyCreatesAnUnsavedOrdinaryAnchoredRule() throws Exception {
        access.candidates=new ArrayList<>(List.of(candidate("small","https://example.test/a",10),candidate("large","https://example.test/z",900)));open();
        dialogs.edit=(form,save)->{
            Rule draft=((RuleEditor)form).value();assertEquals(Mode.BLOCK,draft.mode());assertEquals(Field.URL,draft.condition().field());assertEquals(Match.REGEX,draft.condition().match());
            assertTrue(draft.condition().value().startsWith("^"));assertTrue(draft.condition().value().endsWith("$"));assertEquals(0,access.updates);
            GuardConfig p=new GuardConfig(2,List.of(new ScopeEntry(true,"example.test","https",443,"")),List.of(),List.of(draft),Mode.ALLOW,GuardConfig.defaults().limits());
            assertEquals(Mode.BLOCK,new PolicyEngine().evaluate(p,request("/z?x=1")).mode());assertEquals(Mode.ALLOW,new PolicyEngine().evaluate(p,request("/zz")).mode());
        };
        edt(()->{JTable t=get("candidates.table",JTable.class);assertEquals(900L,t.getValueAt(0,2));assertEquals(70L,t.getValueAt(0,3));assertEquals(3L,t.getValueAt(0,4));assertEquals(1L,t.getValueAt(0,5));t.setRowSelectionInterval(0,0);click("candidates.block");return null;});
        assertEquals(0,access.updates);assertTrue(access.policy.blockScope().isEmpty());
        dialogs.edit=(form,save)->save.run();edt(()->{click("candidates.block");return null;});assertEquals(1,access.updates);assertTrue(access.policy.blockScope().isEmpty());assertEquals(Mode.BLOCK,access.policy.rules().getLast().mode());
    }

    @Test void maskedCandidatesNeverHarvestRawDisplayIntoPolicyOrThresholdsAndIgnoreIsRuntimeOnly() throws Exception {
        access.candidates=new ArrayList<>(List.of(candidate("hidden","",900)));open();
        edt(()->{
            get("candidates.table",JTable.class).setRowSelectionInterval(0,0);
            assertFalse(get("candidates.block",JButton.class).isEnabled());assertFalse(get("candidates.threshold",JButton.class).isEnabled());assertTrue(get("candidates.ignore",JButton.class).isEnabled());
            click("candidates.ignore");return null;
        });assertEquals(0,access.updates);assertEquals(1,access.runtimeCalls);assertTrue(access.candidates.isEmpty());assertEquals(0,access.rawReads);
    }

    @Test void thresholdIsAnExplicitPolicySaveWithFirstResponseWarningAndPreservesAllOtherSettings() throws Exception {
        access.policy=fullPolicy();access.candidates=new ArrayList<>(List.of(candidate("large","https://example.test/z",900)));open();GuardConfig original=access.policy;
        dialogs.edit=(form,save)->{assertTrue(get("candidates.thresholdNotice",JTextArea.class).getText().contains("첫"));get("candidates.thresholdMiB",JTextField.class).setText("2.5");};
        edt(()->{get("candidates.table",JTable.class).setRowSelectionInterval(0,0);click("candidates.threshold");return null;});assertEquals(0,access.updates);
        dialogs.edit=(form,save)->{get("candidates.thresholdMiB",JTextField.class).setText("2.5");save.run();};dialogs.confirmed=false;
        edt(()->{click("candidates.threshold");return null;});assertEquals(0,access.updates);
        dialogs.confirmed=true;edt(()->{click("candidates.threshold");return null;});
        assertEquals(1,access.updates);Limits l=access.policy.limits();assertEquals(new PathByteLimit("https","example.test",443,"/z",2621440),l.heavyPathLimits().getLast());
        assertEquals(original.rules(),access.policy.rules());assertEquals(original.limits().circuit5xx(),l.circuit5xx());assertEquals(original.guardListenerPorts(),access.policy.guardListenerPorts());
        assertEquals(0,access.runtimeCalls);
    }

    @Test void candidateChangedByResponseRedactionDuringDraftCannotBeSaved() throws Exception {
        access.candidates=new ArrayList<>(List.of(candidate("large","https://example.test/z",900)));open();
        dialogs.edit=(form,save)->{access.candidates=new ArrayList<>(List.of(candidate("large","",900)));save.run();};
        edt(()->{get("candidates.table",JTable.class).setRowSelectionInterval(0,0);click("candidates.block");return null;});assertEquals(0,access.updates);assertTrue(dialogs.errors.contains(UiText.error("CANDIDATE_UNSAFE")));
    }

    @Test void rawUnmaskedRequestResponseUrlAndTagsAreOnlyOnScreenAndInspectionWarningsAreHonest() throws Exception {
        String id=access.addRaw("intent1","run1","exempt");open();
        edt(()->{
            JTable t=get("traffic.table",JTable.class);assertTrue(((String)t.getValueAt(0,3)).contains(SECRET));assertEquals("intent1",t.getValueAt(0,7));assertEquals("run1",t.getValueAt(0,8));
            t.setRowSelectionInterval(0,0);click("traffic.detail");
            for(String name:List.of("traffic.request","traffic.response")){String text=get(name,JTextArea.class).getText();assertTrue(text.contains(SECRET));assertTrue(text.contains("화면 전용"));assertFalse(get(name,JTextArea.class).isEditable());}
            String meta=get("traffic.metadata",JTextArea.class).getText();assertTrue(meta.contains("UNSUPPORTED_CHARSET"));assertTrue(meta.contains("PATH_INTERPRETATION_INCOMPLETE"));assertTrue(meta.contains("평가하지" )||meta.contains("검사 가능"));
            return null;
        });
        for(boolean har:List.of(false,true)){
            dialogs.target=directory.resolve(har?"safe.har":"safe.json");
            edt(()->{get("traffic.exportFormat",JComboBox.class).setSelectedIndex(har?1:0);click("traffic.export");return null;});awaitExport();
            String text=Files.readString(dialogs.target);assertFalse(text.contains(SECRET));assertTrue(text.contains("[REDACTED]"));assertFalse(access.exportOnEdt);
        }
        assertEquals(id,access.rows().getFirst().id());assertEquals(0,access.updates);
    }

    @Test void intentRunOutcomeAndGuardStateFiltersAreConjunctiveSortableAndResettable() throws Exception {
        access.addRaw("intent1","run1","exempt");access.addRaw("intent2","run2","probe_allowed");open();
        edt(()->{
            JTable t=get("traffic.table",JTable.class);t.getRowSorter().toggleSortOrder(7);assertEquals("intent1",t.getValueAt(0,7));
            get("traffic.intent",JTextField.class).setText("intent1");assertEquals(1,t.getRowCount());
            get("traffic.run",JTextField.class).setText("run2");assertEquals(0,t.getRowCount());click("traffic.reset");
            get("traffic.outcome",JComboBox.class).setSelectedIndex(4);assertEquals(1,t.getRowCount());
            get("traffic.guardState",JTextField.class).setText("PROTECTED");assertEquals(1,t.getRowCount());
            get("traffic.guardState",JTextField.class).setText("CIRCUIT_OPEN");assertEquals(0,t.getRowCount());click("traffic.reset");assertEquals(2,t.getRowCount());return null;
        });
    }

    @Test void rawEvictionClearProjectFailureAndCloseRemoveSensitiveScreenText() throws Exception {
        access.addRaw("i","r","forwarded");open();
        edt(()->{
            get("traffic.table",JTable.class).setRowSelectionInterval(0,0);click("traffic.detail");assertTrue(get("traffic.request",JTextArea.class).getText().contains(SECRET));
            access.rawUnavailable=true;panel.refreshNow();assertFalse(get("traffic.request",JTextArea.class).getText().contains(SECRET));assertTrue(get("traffic.request",JTextArea.class).getText().contains("생략"));
            access.rawUnavailable=false;panel.refreshNow();access.failStatus=true;panel.refreshNow();assertFalse(get("traffic.request",JTextArea.class).getText().contains(SECRET));assertEquals(0,get("traffic.table",JTable.class).getRowCount());
            access.failStatus=false;panel.refreshNow();click("settings.clear");assertEquals(0,get("traffic.table",JTable.class).getRowCount());panel.close();assertEquals("",get("traffic.request",JTextArea.class).getText());return null;
        });
    }

    @Test void overviewUsesTypedDiagnosisAndReasonCountersAndIntentResetIsConfirmedCasNotPolicyWrite() throws Exception {
        access.watcher=Map.of("fanoutWarnings",1,"automaticPause",true,"overlays",1,"circuits",1);access.guard="OVERLAY_BLOCK";open();
        edt(()->{
            assertTrue(get("dashboard.diagnosis",JTextArea.class).getText().contains("local=true"));assertTrue(get("dashboard.warning",JTextArea.class).getText().contains("전체 자동 차단"));assertTrue(get("dashboard.reasonCounters",JTextArea.class).getText().contains("CIRCUIT_OPEN"));
            dialogs.confirmed=false;click("dashboard.resetIntent");assertEquals(0,access.runtimeCalls);
            dialogs.confirmed=true;click("dashboard.resetIntent");assertEquals("p",access.casProject);assertEquals(7,access.casRevision);return null;
        });assertEquals(1,access.runtimeCalls);assertEquals(0,access.updates);
        dialogs.onConfirm=()->access.revision++;edt(()->{click("dashboard.resetIntent");return null;});assertEquals(1,access.runtimeCalls);
    }

    @Test void offWarningPreservesOperatorPauseAndNoNewScreenCaptureIsRequested() throws Exception {
        access.paused=true;open();
        edt(()->{
            click("protection.passthrough");assertTrue(access.off);assertTrue(access.paused);assertTrue(dialogs.confirmations.getFirst().contains("일시중지를 보존"));
            click("protection.passthrough");assertFalse(access.off);assertTrue(access.paused);assertTrue(get("protection.state",JLabel.class).getText().contains("새 요청 차단"));return null;
        });assertEquals(0,access.rawReads);assertEquals(0,access.updates);
    }

    @Test void migrationIsVisibleExactDiffReadOnlyUncheckedOptionalRemovalAndCancelNeverWrites() throws Exception {
        access.legacy();open();GuardConfig original=access.policy;
        dialogs.edit=(form,save)->{
            assertFalse(get("migration.removeLegacy",JCheckBox.class).isSelected());assertFalse(get("migration.original",JTextArea.class).isEditable());assertFalse(get("migration.migrated",JTextArea.class).isEditable());
            assertEquals(access.original,get("migration.original",JTextArea.class).getText());assertTrue(get("migration.diff",JTextArea.class).getText().contains("+ "));assertEquals(original,form.value());
            get("migration.removeLegacy",JCheckBox.class).doClick(0);assertEquals(1,((GuardConfig)form.value()).rules().size());assertFalse(get("migration.migrated",JTextArea.class).getText().contains("delete-string"));
        };
        edt(()->{assertTrue(get("migration.banner",JPanel.class).isVisible());click("migration.review");panel.refreshNow();return null;});
        assertEquals(0,access.updates);assertEquals(original,access.policy);assertTrue(access.pendingMigration);
    }

    @Test void migrationExplicitSaveDoesNotRemoveLegacyUnlessCheckedAndReopensAsV2() throws Exception {
        access.legacy();open();dialogs.edit=(form,save)->save.run();
        edt(()->{click("migration.review");return null;});assertEquals(1,access.updates);assertEquals(2,access.policy.rules().size());assertFalse(access.pendingMigration);
        assertEquals(access.policy,PolicyCodec.decode(access.persisted).config());assertFalse(PolicyCodec.decode(access.persisted).migrationPending());
        edt(()->{assertFalse(get("migration.banner",JPanel.class).isVisible());panel.close();panel=new GuardPanel(access,dialogs,false);return null;});assertEquals(1,access.updates);
    }

    @Test void migrationRemovalMatchesOnlyExactOriginalAndSavingAgainstAChangedProjectFails() throws Exception {
        access.legacy();Rule original=access.policy.rules().getLast();
        Rule customized=new Rule("custom","custom delete",true,Mode.BLOCK,original.condition());
        access.policy=new GuardConfig(2,List.of(),List.of(),List.of(access.policy.rules().getFirst(),original,customized),Mode.ALLOW,access.policy.limits());open();
        dialogs.edit=(form,save)->{get("migration.removeLegacy",JCheckBox.class).doClick(0);assertTrue(((GuardConfig)form.value()).rules().contains(customized));save.run();};
        dialogs.onConfirm=()->access.project="other";edt(()->{click("migration.review");return null;});assertEquals(0,access.updates);
        dialogs.onConfirm=()->{};edt(()->{click("migration.review");return null;});assertEquals(1,access.updates);assertEquals(List.of(access.policy.rules().getFirst(),customized),access.policy.rules());
    }

    @Test void ordinaryEditDuringPendingMigrationAlsoRequiresExplicitV2ReplacementConsent() throws Exception {
        access.legacy();open();dialogs.confirmed=false;
        dialogs.edit=(form,save)->{get("settings.globalRps",JSpinner.class).setValue(2);save.run();};
        edt(()->{click("settings.edit");return null;});assertEquals(0,access.updates);assertTrue(access.pendingMigration);assertEquals(5,access.policy.limits().globalRps());
        assertTrue(dialogs.confirmations.getLast().contains("v2 전체 정책"));
        dialogs.confirmed=true;edt(()->{click("settings.edit");return null;});assertEquals(1,access.updates);assertFalse(access.pendingMigration);assertEquals(2,access.policy.limits().globalRps());assertEquals(2,access.policy.rules().size());
    }

    @Test void pastedV1UsesStrictCodecAndOnlyExplicitSaveMigratesWithoutImplicitRuleRemoval() throws Exception {
        access.legacy();String legacy=access.original;access.pendingMigration=false;access.policy=GuardConfig.defaults();open();
        dialogs.edit=(form,save)->{get("advanced.policyJson",JTextArea.class).setText(legacy);assertEquals(0,access.updates);};
        edt(()->{click("settings.policyJson");return null;});assertEquals(0,access.updates);
        dialogs.edit=(form,save)->{get("advanced.policyJson",JTextArea.class).setText(legacy);save.run();};
        edt(()->{click("settings.policyJson");return null;});assertEquals(1,access.updates);assertEquals(2,access.policy.schemaVersion());assertEquals(2,access.policy.rules().size());assertEquals(0,access.policy.limits().perPathMaxResponseBytes());
        assertTrue(dialogs.confirmations.getLast().contains("v1"));
    }

    @Test void originalsExportUsesExactOriginalAndOwnerOnlySafePublicationWithoutSaving() throws Exception {
        access.legacy();open();dialogs.target=directory.resolve("original.json");
        edt(()->{click("migration.exportOriginal");return null;});awaitExport();assertEquals(access.original,Files.readString(dialogs.target));assertEquals(0,access.updates);assertTrue(access.pendingMigration);
        if(Files.getFileStore(directory).supportsFileAttributeView("posix"))assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(dialogs.target));
    }

    @Test void incidentExportValidatesUtcWindowAndUsesMaskedIncidentOnlyOffEdt() throws Exception {
        access.addRaw("i","r","forwarded");open();dialogs.target=directory.resolve("incident.json");
        edt(()->{get("incident.from",JTextField.class).setText("2026-01-01T00:00:00Z");get("incident.to",JTextField.class).setText("2026-01-01T01:00:00Z");click("incident.export");return null;});awaitExport();
        assertEquals(1767225600000L,access.incidentFrom);assertEquals(1767229200000L,access.incidentTo);assertFalse(access.exportOnEdt);
        assertEquals("{\"events\":[{\"path\":\"/[REDACTED]\"}]}",Files.readString(dialogs.target));assertFalse(Files.readString(dialogs.target).contains(SECRET));assertEquals(0,access.updates);
        int before=access.incidentCalls;
        for(String to:List.of("2026-01-01T00:00:00Z","2026-01-02T00:00:00.001Z","2026-01-01T01:00:00+00:00","2026-01-01T00:00:00.000000001Z")) {
            edt(()->{get("incident.to",JTextField.class).setText(to);click("incident.export");return null;});
        }
        assertEquals(before,access.incidentCalls);assertEquals(4,dialogs.errors.size());
    }

    @Test void incidentExistingFileConsentSymlinkAndChangedProjectAreRejectedBeforeSerialization() throws Exception {
        open();Path target=directory.resolve("existing.json");Files.writeString(target,"keep");dialogs.target=target;dialogs.confirmed=false;
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
        Path link=directory.resolve("link.json");Files.createSymbolicLink(link,target);dialogs.target=link;dialogs.confirmed=true;
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
        dialogs.target=target;dialogs.onConfirm=()->access.project="new";
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
    }

    @Test void latestAllPathAdviceAndEngineAllowOriginalPentestPathsWithFuzzedHostAndUnavailableBody() throws Exception {
        access.policy=new GuardConfig(2,List.of(new ScopeEntry(true,"example.test","https",443,"")),List.of(),List.of(
                GuardConfig.defaults().rules().getFirst(),new Rule("body","Explicit body test",true,Mode.BLOCK,Condition.leaf(Field.BODY,Match.EXACT,"never-match"))),Mode.ALLOW,GuardConfig.defaults().limits());open();
        edt(()->{String help=get("scope.help",JTextArea.class).getText();assertTrue(help.contains("/c/;/main.do"));assertTrue(help.contains("/c/%2e/main.do"));assertTrue(help.contains("원문 그대로"));return null;});
        for(String path:List.of("/c/;/main.do","/c/%2e/main.do","/c/%252e/main.do","/c/%GG/main.do")) {
            RequestData r=new RequestData("POST","https://example.test"+path,"example.test",443,true,List.of(new RequestData.Header("Host","synthetic.invalid"),new RequestData.Header("Content-Type","application/json; charset=unsupported")),new byte[]{0,1,2});
            Decision decision=new PolicyEngine().evaluate(access.policy,r);assertEquals(Mode.ALLOW,decision.mode());assertTrue(decision.inspectionWarnings().stream().anyMatch(w->w.contains("UNSUPPORTED_CHARSET")));assertEquals("https://example.test"+path,r.url());
        }
    }

    void open() throws Exception { edt(()->{panel=new GuardPanel(access,dialogs,false);return null;}); }
    void click(String name){get(name,JButton.class).doClick(0);}
    <T>T get(String name,Class<T>type){Component c=find(panel,name);if(c==null&&dialogs.form!=null)c=find(dialogs.form.component(),name);return type.cast(java.util.Objects.requireNonNull(c,name));}
    void selectRule(String id){int index=java.util.stream.IntStream.range(0,access.policy.rules().size()).filter(i->access.policy.rules().get(i).id().equals(id)).findFirst().orElseThrow();JTable t=get("rules.table",JTable.class);int row=t.convertRowIndexToView(index);t.setRowSelectionInterval(row,row);}
    void awaitExport() throws Exception { long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);while(System.nanoTime()<until){if(edt(()->{var f=GuardPanel.class.getDeclaredField("exportWorker");f.setAccessible(true);return f.get(panel)==null;}))return;Thread.sleep(10);}fail("bounded export wait"); }
    static Component find(Component c,String name){if(c==null)return null;if(name.equals(c.getName()))return c;if(c instanceof Container p)for(Component child:p.getComponents()){Component f=find(child,name);if(f!=null)return f;}return null;}
    static <T>T edt(Callable<T> c)throws Exception{if(SwingUtilities.isEventDispatchThread())return c.call();FutureTask<T> f=new FutureTask<>(c);SwingUtilities.invokeAndWait(f);try{return f.get();}catch(java.util.concurrent.ExecutionException e){if(e.getCause() instanceof Error a)throw a;if(e.getCause() instanceof Exception a)throw a;throw e;}}
    static RequestData request(String path){return new RequestData("GET","https://example.test"+path,"example.test",443,true,List.of(),new byte[0]);}
    static Overlay overlay(String id,long duration){long now=System.currentTimeMillis();return new Overlay(id,"heavy","example.test","/large",now,now+duration,"HEAVY_ENDPOINT_AUTO_BLOCKED");}
    static Candidate candidate(String id,String url,long max){return new Candidate(id,"example.test","/large",url,max,70,3,System.currentTimeMillis(),1);}
    static GuardConfig fullPolicy(){Limits d=GuardConfig.defaults().limits();return new GuardConfig(2,List.of(),List.of(),GuardConfig.defaults().rules(),Mode.ALLOW,new Limits(d.globalRps(),d.perHostRps(),d.hostRps(),d.maxConcurrent(),d.maxQueued(),d.queueTimeoutMillis(),d.approvalTimeoutMillis(),d.requestTimeoutMillis(),123_456,789_123,new Circuit5xx(6000,7,8000,1),new Fanout(9000,10,FanoutAction.WARN),42,true,List.of(new ProbePath("https","example.test",443,"/health")),List.of(new PathByteLimit("https","example.test",443,"/small",123))),List.of(8080));}

    static final class Human implements GuardPanel.Dialogs {
        boolean confirmed=true;Path target;EditorForm<?> form;BiConsumer<EditorForm<?>,Runnable> edit=(f,s)->{};Runnable onConfirm=()->{};
        final List<String> confirmations=new ArrayList<>(),errors=new ArrayList<>();
        @Override public boolean confirm(Component p,String s){assertTrue(SwingUtilities.isEventDispatchThread());confirmations.add(s);onConfirm.run();return confirmed;}
        @Override public Path chooseExport(Component p,String extension){return target;}
        @Override public void error(Component p,String s){errors.add(s);}
        @Override public void edit(Component p,String title,String label,EditorForm<?> f,Runnable save){form=f;edit.accept(f,save);}
    }
    static final class Access implements GuardUiAccess {
        GuardConfig policy=GuardConfig.defaults();volatile String project="p";volatile long revision=7;boolean paused,off,failStatus,rawUnavailable,pendingMigration;
        int updates,updateAttempts,runtimeCalls,rawReads,incidentCalls;boolean exportOnEdt;String guard="PROTECTED",casProject,original="",persisted="";long casRevision,incidentFrom,incidentTo;
        List<Overlay> overlays=new ArrayList<>();List<Candidate> candidates=new ArrayList<>();Map<String,Object> watcher=Map.of();final EvidenceStore store=new EvidenceStore();
        @Override public GuardConfig config(){return policy;}
        void cas(String p,long r){casProject=p;casRevision=r;if(!project.equals(p)||revision!=r)throw new IllegalStateException("STALE");}
        @Override public void updateConfig(GuardConfig c,String p,long r){updateAttempts++;cas(p,r);policy=c;persisted=PolicyCodec.encode(c);updates++;revision++;pendingMigration=false;}
        @Override public Map<String,Object> status(){if(failStatus)throw new IllegalStateException();return Map.of("projectId",project,"revision",revision,"paused",paused,"passthrough",off,"closed",false,"guardState",guard,"watchers",watcher,"intents",Map.of("consumed",20,"rejected",2),"reasonCounters",Map.of("CIRCUIT_OPEN",3));}
        List<TrafficEntry> rows(){return store.snapshot();}
        @Override public List<TrafficEntry> traffic(){return rows();}
        @Override public List<Pending> approvals(){return List.of();}
        @Override public boolean decideApproval(String id,boolean allow){throw new AssertionError();}
        @Override public void bookmark(String id,boolean value){store.bookmark(id,value);}
        @Override public String exportJson(List<TrafficEntry> rows){exportOnEdt=SwingUtilities.isEventDispatchThread();return store.exportJson(rows);}
        @Override public String exportHar(List<TrafficEntry> rows){exportOnEdt=SwingUtilities.isEventDispatchThread();return store.exportHar(rows);}
        @Override public void clearEvidence(){store.clear();}
        @Override public void pause(boolean p){paused=p;off=false;revision++;}
        @Override public void passthrough(boolean on,String p,long r){cas(p,r);off=on;revision++;}
        @Override public void refreshProject(){}
        @Override public List<Overlay> overlays(){return List.copyOf(overlays);}
        @Override public boolean releaseOverlay(String id,String p,long r){cas(p,r);runtimeCalls++;return overlays.removeIf(o->o.id().equals(id));}
        @Override public int releaseAllOverlays(String p,long r){cas(p,r);runtimeCalls++;int n=overlays.size();overlays.clear();return n;}
        @Override public List<Candidate> heavyCandidates(){return List.copyOf(candidates);}
        @Override public boolean ignoreCandidate(String id,String p,long r){cas(p,r);runtimeCalls++;return candidates.removeIf(c->c.id().equals(id));}
        @Override public void resetIntentBudgets(String p,long r){cas(p,r);runtimeCalls++;}
        @Override public String exportIncident(long from,long to){exportOnEdt=SwingUtilities.isEventDispatchThread();incidentCalls++;incidentFrom=from;incidentTo=to;return "{\"events\":[{\"path\":\"/[REDACTED]\"}]}";}
        @Override public Map<String,Object> migrationView(){return Map.of("pending",pendingMigration,"original",original,"migrated",PolicyCodec.encode(policy));}
        @Override public String rawRequest(String id){rawReads++;return rawUnavailable?null:store.rawRequest(id);}
        @Override public String rawResponse(String id){rawReads++;return rawUnavailable?null:store.rawResponse(id);}
        @Override public String rawUrl(String id){rawReads++;return rawUnavailable?null:store.rawUrl(id);}
        @Override public Map<String,Object> rawCaptureInfo(String id){return rawUnavailable?Map.of("available",false):store.rawCaptureInfo(id);}
        void legacy(){GuardConfig d=GuardConfig.defaults();original=PolicyCodec.encodeLegacy(new GuardConfig(1,List.of(),List.of(),List.of(d.rules().getFirst(),new Rule("delete-string","Block delete string (conservative)",true,Mode.BLOCK,Condition.leaf(Field.ANY,Match.CONTAINS,"delete"))),Mode.ALLOW,new Limits(5,5,Map.of(),5,100,30000,30000,60000)));PolicyCodec.Decoded decoded=PolicyCodec.decode(original);policy=decoded.config();pendingMigration=true;}
        String addRaw(String intent,String run,String outcome){RequestData r=new RequestData("POST","https://example.test/x?token="+SECRET,"example.test",443,true,List.of(new RequestData.Header("Authorization","Bearer "+SECRET),new RequestData.Header("Cookie","session="+SECRET),new RequestData.Header("X-Broker-Grant",SECRET),new RequestData.Header("X-Cairn-Intent",intent),new RequestData.Header("X-Cairn-Run",run)),("body "+SECRET).getBytes(StandardCharsets.UTF_8));String id=store.begin("p","Synthetic",r,new Decision(Mode.ALLOW,"DEFAULT_ALLOW",List.of(),List.of("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_CHARSET","PATH_INTERPRETATION_INCOMPLETE")),7);store.outcome(id,"FORWARDED","NATIVE_RELEASED",200);store.context(id,outcome,"PROTECTED","");store.response(id,200,List.of(),("response "+SECRET).getBytes(StandardCharsets.UTF_8));return id;}
    }
}
