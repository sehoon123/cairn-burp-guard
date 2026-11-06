package dev.cairnguard.ui;

import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.*;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import dev.cairnguard.runtime.ResponseWatcher.Candidate;
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
            for(String name:List.of("overlays.release","overlays.releaseAll","candidates.block","candidates.threshold","candidates.ignore")) assertNull(find(panel,name),name);
            for(String name:List.of("incident.export","dashboard.resetIntent")) assertNotNull(find(panel,name),name);
            dialogs.edit=(form,save)-> {
                for(String name:List.of("settings.heavyMiB","settings.circuit.enabled","settings.fanout.enabled","settings.maxConcurrent","settings.requestTimeoutSeconds")) assertNull(find(form.component(),name),name);
                for(String name:List.of("settings.rates.off","settings.intent.maxRequests","settings.probes.table","settings.listenerPorts")) assertNotNull(find(form.component(),name),name);
                get("settings.globalRps",JSpinner.class).setValue(8);
                panel.refreshNow();
                assertEquals(8,get("settings.globalRps",JSpinner.class).getValue());
            };
            click("settings.edit"); return null;
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

    @Test void deferredListenerSelectionCannotBeNewlySavedBySettingsOrWholePolicyJson() throws Exception {
        open(); dialogs.confirmed=true;
        dialogs.edit=(form,save)->{get("settings.listenerPorts",JTextField.class).setText("8080");save.run();};
        edt(()->{click("settings.edit");return null;});
        assertEquals(0,access.updates);assertTrue(dialogs.errors.getLast().contains("추후"));
        GuardConfig d=access.policy;
        GuardConfig restricted=new GuardConfig(d.schemaVersion(),d.allowScope(),d.blockScope(),d.rules(),d.defaultMode(),d.limits(),List.of(8080));
        dialogs.edit=(form,save)->{get("advanced.policyJson",JTextArea.class).setText(PolicyCodec.encode(restricted));save.run();};
        edt(()->{click("settings.policyJson");return null;});
        assertEquals(0,access.updates);assertTrue(access.policy.guardListenerPorts().isEmpty());
        assertTrue(dialogs.errors.contains(UiText.error("LISTENER_SELECTION_DEFERRED")));
    }

    @Test void clearingExistingDeferredListenerSelectionRequiresConfirmationAndPreservesOtherPolicy() throws Exception {
        access.policy=fullPolicy();GuardConfig original=access.policy;open();dialogs.confirmed=false;
        dialogs.edit=(form,save)->{get("settings.listenerPorts",JTextField.class).setText("");save.run();};
        edt(()->{click("settings.edit");return null;});
        assertEquals(0,access.updates);assertEquals(original,access.policy);assertTrue(dialogs.confirmations.getLast().contains("모든 Proxy"));
        dialogs.confirmed=true;edt(()->{click("settings.edit");return null;});
        assertEquals(1,access.updates);assertTrue(access.policy.guardListenerPorts().isEmpty());
        assertEquals(original.limits(),access.policy.limits());assertEquals(original.rules(),access.policy.rules());
        assertEquals("p",access.casProject);assertEquals(7,access.casRevision);
    }

    @Test void probeEnableRequiresExplicitConfirmationAndUsesOriginalCas() throws Exception {
        open();dialogs.confirmed=false;
        dialogs.edit=(form,save)->{
            get("settings.probes.enabled",JCheckBox.class).setSelected(true);click("settings.probes.add");
            JTable t=get("settings.probes.table",JTable.class);t.setValueAt("example.test",0,1);t.setValueAt("/health",0,3);save.run();
        };
        edt(()->{click("settings.edit");return null;});assertFalse(access.policy.limits().healthProbePassthrough());assertTrue(dialogs.confirmations.getLast().contains("GET도 부작용"));
        dialogs.confirmed=true;dialogs.onConfirm=()->access.project="new-project";
        edt(()->{click("settings.edit");return null;});assertEquals(0,access.updates);assertFalse(access.policy.limits().healthProbePassthrough());
        assertTrue(dialogs.errors.contains(UiText.error("STALE_POLICY")));assertEquals(0,access.updateAttempts);
    }

    @Test void humanMethodFilterAndSearchUseTheDisplayedOriginalMethod() throws Exception {
        // REAL EvidenceStore capture: a valid nonstandard token method is retained as the original everywhere.
        RequestData custom=new RequestData("CUSTMETHOD","https://example.test/a","example.test",443,true,List.of(),new byte[0]);
        RequestData get=new RequestData("GET","https://example.test/b","example.test",443,true,List.of(),new byte[0]);
        Decision allow=new Decision(Mode.ALLOW,"DEFAULT_ALLOW",List.of());
        String customId=access.store.begin("p","Synthetic",custom,allow,7);access.store.begin("p","Synthetic",get,allow,7);
        open();
        edt(()->{
            TrafficEntry safe=access.rows().stream().filter(e->e.id().equals(customId)).findFirst().orElseThrow();
            assertEquals("CUSTMETHOD",safe.method(),"the row carries the original method");
            JTable t=get("traffic.table",JTable.class);
            java.util.Set<Object> shown=new java.util.HashSet<>();for(int i=0;i<t.getRowCount();i++)shown.add(t.getValueAt(i,2));
            assertEquals(java.util.Set.of("CUSTMETHOD","GET"),shown,"human table shows the retained originals");
            return null;
        });
        // each branch is observed independently, with a full reset before every assertion
        java.util.function.BiFunction<String,String,List<Object>> visible=(field,text)->{
            try{return edt(()->{
                for(String name:List.of("traffic.search","traffic.method"))get(name,JTextField.class).setText("");
                get(field,JTextField.class).setText(text);
                JTable t=get("traffic.table",JTable.class);List<Object> out=new ArrayList<>();for(int i=0;i<t.getRowCount();i++)out.add(t.getValueAt(i,2));return out;
            });}catch(Exception e){throw new AssertionError(e);}
        };
        org.junit.jupiter.api.Assertions.assertAll(
            ()->assertEquals(List.of("CUSTMETHOD"),visible.apply("traffic.method","CUSTMETHOD"),"dedicated method filter"),
            ()->assertEquals(List.of("CUSTMETHOD"),visible.apply("traffic.search","CUSTMETHOD"),"general search"),
            // controls: known method, and the safe masked text does not match a retained original
            ()->assertEquals(List.of("GET"),visible.apply("traffic.method","GET"),"known method filter"),
            ()->assertEquals(List.of("GET"),visible.apply("traffic.search","GET"),"known method search"),
            ()->assertEquals(List.of(),visible.apply("traffic.method","[REDACTED]"),"safe text is not the displayed method"),
            ()->assertEquals(List.of(),visible.apply("traffic.search","[REDACTED]"),"safe text is not the displayed method (search)"));
        // original copy unavailable: the explicit fallback label is displayed, with the row's own (original) method
        access.rawUnavailable=true;edt(()->{panel.refreshNow();return null;});
        org.junit.jupiter.api.Assertions.assertEquals(List.of("[원문 없음] CUSTMETHOD"),visible.apply("traffic.method","CUSTMETHOD").stream().distinct().toList(),"unavailable fallback method filter");
    }

    @Test void rawRequestResponseUrlAndTagsAreOriginalOnScreenAndInspectionWarningsAreHonest() throws Exception {
        String id=access.addRaw("intent1","run1","exempt");open();
        edt(()->{get("traffic.table",JTable.class).setRowSelectionInterval(0,0);return null;});
        GuardPanelTrafficViewTest.await(()->get("traffic.response",JTextArea.class).getText().contains(SECRET));
        edt(()->{
            JTable t=get("traffic.table",JTable.class);assertTrue(((String)t.getValueAt(0,3)).contains(SECRET));assertEquals("intent1",t.getValueAt(0,7));assertEquals("run1",t.getValueAt(0,8));
            t.setRowSelectionInterval(0,0);click("traffic.detail");
            for(String name:List.of("traffic.request","traffic.response")){String text=get(name,JTextArea.class).getText();assertTrue(text.contains(SECRET));assertTrue(text.contains("평문 원문"));assertFalse(get(name,JTextArea.class).isEditable());}
            String meta=get("traffic.metadata",JTextArea.class).getText();assertTrue(meta.contains("UNSUPPORTED_CHARSET"));assertTrue(meta.contains("PATH_INTERPRETATION_INCOMPLETE"));assertTrue(meta.contains("평가하지" )||meta.contains("검사 가능"));
            return null;
        });
        for(boolean har:List.of(false,true)){
            dialogs.target=directory.resolve(har?"human.har":"human.json");dialogs.confirmations.clear();
            edt(()->{get("traffic.exportFormat",JComboBox.class).setSelectedIndex(har?1:0);click("traffic.export");return null;});awaitExport();
            String text=Files.readString(dialogs.target);assertTrue(text.contains(SECRET),"explicit human export is plaintext");assertFalse(text.contains("[REDACTED]"));
            assertTrue(text.contains("HUMAN_ORIGINAL"));assertFalse(access.exportOnEdt);
            assertTrue(dialogs.confirmations.getFirst().contains("Authorization")&&dialogs.confirmations.getFirst().contains("평문"));
        }
        assertTrue(access.store.exportJson(access.store.snapshot()).contains(SECRET), "the evidence rows are original too");
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

    @Test void rawUnavailableClearProjectFailureAndCloseRemoveSensitiveScreenText() throws Exception {
        access.addRaw("i","r","forwarded");open();
        edt(()->{get("traffic.table",JTable.class).setRowSelectionInterval(0,0);return null;});
        GuardPanelTrafficViewTest.await(()->get("traffic.request",JTextArea.class).getText().contains(SECRET));
        edt(()->{
            click("traffic.detail");assertTrue(get("traffic.request",JTextArea.class).getText().contains(SECRET));
            access.rawUnavailable=true;panel.refreshNow();assertFalse(get("traffic.request",JTextArea.class).getText().contains(SECRET));assertTrue(get("traffic.request",JTextArea.class).getText().contains("원문 없음"));
            access.rawUnavailable=false;panel.refreshNow();access.failStatus=true;panel.refreshNow();assertFalse(get("traffic.request",JTextArea.class).getText().contains(SECRET));assertEquals(0,get("traffic.table",JTable.class).getRowCount());
            access.failStatus=false;panel.refreshNow();click("settings.clear");assertEquals(0,get("traffic.table",JTable.class).getRowCount());panel.close();assertEquals("",get("traffic.request",JTextArea.class).getText());return null;
        });
    }

    @Test void overviewUsesTypedDiagnosisAndReasonCountersAndIntentResetIsConfirmedCasNotPolicyWrite() throws Exception {
        access.watcher=Map.of("fanoutWarnings",1,"automaticPause",true,"overlays",1,"circuits",1);access.guard="OVERLAY_BLOCK";open();
        edt(()->{
            assertTrue(get("dashboard.diagnosis",JTextArea.class).getText().contains("local=true"));assertTrue(get("dashboard.warning",JTextArea.class).getText().contains("제거되었습니다"));assertTrue(get("dashboard.reasonCounters",JTextArea.class).getText().contains("CIRCUIT_OPEN"));
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

    @Test void incidentExportValidatesUtcWindowAndUsesTheConsentedHumanIncidentOffEdt() throws Exception {
        access.addRaw("i","r","forwarded");open();dialogs.target=directory.resolve("incident.json");
        edt(()->{get("incident.from",JTextField.class).setText("2026-01-01T00:00:00Z");get("incident.to",JTextField.class).setText("2026-01-01T01:00:00Z");click("incident.export");return null;});awaitExport();
        assertEquals(1767225600000L,access.incidentFrom);assertEquals(1767229200000L,access.incidentTo);assertFalse(access.exportOnEdt);
        assertEquals("{\"events\":[{\"path\":\"/original-incident-path\"}]}",Files.readString(dialogs.target));assertTrue(dialogs.confirmations.getFirst().contains("평문"));assertEquals(0,access.updates);
        int before=access.incidentCalls;
        for(String to:List.of("2026-01-01T00:00:00Z","2025-12-31T00:00:00Z","2026-01-01T01:00:00+00:00","2026-01-01T00:00:00.000000001Z")) {
            edt(()->{get("incident.to",JTextField.class).setText(to);click("incident.export");return null;});
        }
        assertEquals(before,access.incidentCalls);assertEquals(4,dialogs.errors.size());
        // a window longer than a day is valid: there is no 24-hour export refusal
        edt(()->{get("incident.to",JTextField.class).setText("2026-03-01T00:00:00Z");click("incident.export");return null;});awaitExport();
        assertEquals(1772323200000L,access.incidentTo);assertEquals(before+1,access.incidentCalls);
    }

    @Test void incidentExistingFileConsentSymlinkAndChangedProjectAreRejectedBeforeSerialization() throws Exception {
        open();Path target=directory.resolve("existing.json");Files.writeString(target,"keep");dialogs.target=target;dialogs.confirmed=false;
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
        Path link=directory.resolve("link.json");Files.createSymbolicLink(link,target);dialogs.target=link;dialogs.confirmed=true;
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
        dialogs.target=target;dialogs.onConfirm=()->access.project="new";
        edt(()->{click("incident.export");return null;});assertEquals(0,access.incidentCalls);assertEquals("keep",Files.readString(target));
    }

    @Test void trafficWarningsSeparateOptionalCaptureFromDemandedFieldInspectionInTableAndDetail() throws Exception {
        GuardConfig pathOnly=new GuardConfig(2,List.of(new ScopeEntry(true,"example.test","https",443,"")),List.of(),List.of(new Rule("path","Path only",true,Mode.BLOCK,Condition.leaf(Field.PATH,Match.EXACT,"/never"))),Mode.ALLOW,GuardConfig.defaults().limits());
        RequestData partial=new RequestData("POST","https://example.test/capture","example.test",443,true,List.of(),("body "+SECRET).getBytes(StandardCharsets.UTF_8),true,false);
        Decision capture=new PolicyEngine().evaluate(pathOnly,partial);assertEquals(Mode.ALLOW,capture.mode());assertEquals(List.of("BODY_INCOMPLETE"),capture.inspectionWarnings());
        GuardConfig json=new GuardConfig(2,pathOnly.allowScope(),List.of(),List.of(new Rule("json","JSON",true,Mode.BLOCK,Condition.leaf(Field.JSON,Match.CONTAINS,"never"))),Mode.ALLOW,GuardConfig.defaults().limits());
        RequestData malformed=new RequestData("POST","https://example.test/json","example.test",443,true,List.of(new RequestData.Header("Content-Type","application/json")),"{broken".getBytes(StandardCharsets.UTF_8));
        Decision demanded=new PolicyEngine().evaluate(json,malformed);assertEquals(Mode.ALLOW,demanded.mode());assertTrue(demanded.inspectionWarnings().contains("JSON_INSPECTION_UNAVAILABLE_MALFORMED_JSON"));
        for(var begin:List.of(java.util.Map.entry(partial,capture),java.util.Map.entry(malformed,demanded),java.util.Map.entry(request("/hostile"),new Decision(Mode.ALLOW,"DEFAULT_ALLOW",List.of(),List.of("<html>"+SECRET+"</html>"))))){
            String id=access.store.begin("p","Synthetic",begin.getKey(),begin.getValue(),7);access.store.outcome(id,"FORWARDED","NATIVE_RELEASED",200);
        }
        open();
        edt(()->{
            JTable t=get("traffic.table",JTable.class);assertEquals(3,t.getRowCount());
            for(int row=0;row<3;row++){
                String url=(String)t.getValueAt(row,3),cell=(String)t.getValueAt(row,10);
                boolean hostile=url.endsWith("/hostile");
                assertEquals(hostile,cell.contains("<html>"+SECRET+"</html>"),"an unknown code is shown plainly, only for the row that carries it");assertFalse(cell.contains("모호"));assertTrue(cell.length()<=600,cell);
                if(url.endsWith("/capture")){assertTrue(cell.contains("본문 수집 불완전"),cell);assertTrue(cell.contains("요구했다는 뜻은 아님"),cell);assertFalse(cell.contains("검사 불가"),cell);}
                else if(url.endsWith("/json")){assertTrue(cell.contains("JSON 조건 검사 불가"),cell);assertTrue(cell.contains("JSON 형식 오류"),cell);}
                else assertTrue(cell.contains("알 수 없는 경고 코드: <html>"+SECRET+"</html>"),cell);
                t.setRowSelectionInterval(row,row);click("traffic.detail");
                String meta=get("traffic.metadata",JTextArea.class).getText();
                for(String label:cell.split(" · "))assertTrue(meta.contains(label),"detail agrees with the table: "+label);assertEquals(hostile,meta.contains("<html>"+SECRET+"</html>"));
                if(url.endsWith("/json"))assertTrue(meta.contains("JSON_INSPECTION_UNAVAILABLE_MALFORMED_JSON"),"machine ID retained for recognized warnings");
            }
            return null;
        });
    }

    @Test void latestAllPathAdviceAndEngineAllowOriginalPentestPathsWithFuzzedHostAndUnavailableBody() throws Exception {
        access.policy=new GuardConfig(2,List.of(new ScopeEntry(true,"example.test","https",443,"")),List.of(),List.of(
                GuardConfig.defaults().rules().getFirst(),new Rule("body","Explicit body test",true,Mode.BLOCK,Condition.leaf(Field.BODY,Match.EXACT,"never-match"))),Mode.ALLOW,GuardConfig.defaults().limits());open();
        edt(()->{String help=get("scope.help",JTextArea.class).getText();assertTrue(help.contains("/c/;/main.do"));assertTrue(help.contains("/c/%2e/main.do"));assertTrue(help.contains("원문 그대로"));assertTrue(help.contains("Drop all out-of-scope requests"));assertTrue(help.contains("Burp Target Scope와 별개"));assertTrue(help.contains("Burp Target Scope 밖"));assertTrue(help.contains("로컬 451"));assertTrue(help.contains("결론을 낼 수 없"));assertFalse(help.contains("Cairn 판정이 아닙니다"));return null;});
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
    static Candidate candidate(String id,String url,long max){return new Candidate(id,"example.test","/large",url,max,70,3,System.currentTimeMillis(),1);}
    static GuardConfig fullPolicy(){Limits d=GuardConfig.defaults().limits();return new GuardConfig(2,List.of(),List.of(),GuardConfig.defaults().rules(),Mode.ALLOW,new Limits(d.globalRps(),d.perHostRps(),d.hostRps(),d.maxConcurrent(),d.maxQueued(),d.queueTimeoutMillis(),d.approvalTimeoutMillis(),d.requestTimeoutMillis(),123_456,789_123,new Circuit5xx(6000,7,8000,1),new Fanout(9000,10,FanoutAction.WARN),42,true,List.of(new ProbePath("https","example.test",443,"/health")),List.of(new PathByteLimit("https","example.test",443,"/small",123)),List.of(new ProbePath("https","example.test",443,"/circuit-ok")),false,List.of(new ProbePath("https","example.test",443,"/fanout-ok"))),List.of(8080));}

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
        Map<String,Object> watcher=Map.of();final EvidenceStore store=new EvidenceStore();
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
        @Override public HumanExport humanExport(List<String> ids,boolean har){
            EvidenceStore.HumanEvidence evidence=store.humanEvidence(ids);
            return ()->{exportOnEdt=SwingUtilities.isEventDispatchThread();return har?evidence.har(Map.of("projectId",project)):evidence.json(Map.of("projectId",project));};
        }
        @Override public HumanExport humanIncident(long from,long to){
            incidentCalls++;incidentFrom=from;incidentTo=to;
            return ()->{exportOnEdt=SwingUtilities.isEventDispatchThread();return "{\"events\":[{\"path\":\"/original-incident-path\"}]}".getBytes(StandardCharsets.UTF_8);};
        }
        @Override public boolean humanExportCurrent(HumanExport e){return true;}
        @Override public void resetIntentBudgets(String p,long r){cas(p,r);runtimeCalls++;}
        @Override public String exportIncident(long from,long to){throw new AssertionError("the human UI must not use the safe masked incident export");}
        @Override public Map<String,Object> migrationView(){return Map.of("pending",pendingMigration,"original",original,"migrated",PolicyCodec.encode(policy));}
        @Override public String rawRequest(String id){rawReads++;return rawUnavailable?null:store.rawRequest(id);}
        @Override public String rawResponse(String id){rawReads++;return rawUnavailable?null:store.rawResponse(id);}
        @Override public String rawUrl(String id){rawReads++;return rawUnavailable?null:store.rawUrl(id);}
        @Override public Map<String,Object> rawCaptureInfo(String id){return rawUnavailable?Map.of("available",false):store.rawCaptureInfo(id);}
        void legacy(){GuardConfig d=GuardConfig.defaults();original=PolicyCodec.encodeLegacy(new GuardConfig(1,List.of(),List.of(),List.of(d.rules().getFirst(),new Rule("delete-string","Block delete string (conservative)",true,Mode.BLOCK,Condition.leaf(Field.ANY,Match.CONTAINS,"delete"))),Mode.ALLOW,new Limits(5,5,Map.of(),5,100,30000,30000,60000)));PolicyCodec.Decoded decoded=PolicyCodec.decode(original);policy=decoded.config();pendingMigration=true;}
        String addRaw(String intent,String run,String outcome){RequestData r=new RequestData("POST","https://example.test/x?token="+SECRET,"example.test",443,true,List.of(new RequestData.Header("Authorization","Bearer "+SECRET),new RequestData.Header("Cookie","session="+SECRET),new RequestData.Header("X-Broker-Grant",SECRET),new RequestData.Header("X-Cairn-Intent",intent),new RequestData.Header("X-Cairn-Run",run)),("body "+SECRET).getBytes(StandardCharsets.UTF_8));String id=store.begin("p","Synthetic",r,new Decision(Mode.ALLOW,"DEFAULT_ALLOW",List.of(),List.of("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_CHARSET","PATH_INTERPRETATION_INCOMPLETE")),7);store.outcome(id,"FORWARDED","NATIVE_RELEASED",200);store.context(id,outcome,"PROTECTED","");store.response(id,200,List.of(),("response "+SECRET).getBytes(StandardCharsets.UTF_8));return id;}
    }
}
