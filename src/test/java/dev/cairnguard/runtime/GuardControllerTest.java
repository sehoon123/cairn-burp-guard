package dev.cairnguard.runtime;

import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import dev.cairnguard.runtime.GuardController.Admission;
import dev.cairnguard.runtime.GuardController.Prepared;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Actual controller, synthetic persistence/completions only. No Burp or sockets in this class. */
@Timeout(20)
class GuardControllerTest {
    private static final String SECRET = "fabricated-controller-secret-8701";
    private static final ProjectAccess.Ref A = new ProjectAccess.Ref("project-a", "Synthetic project A");
    private static final ProjectAccess.Ref B = new ProjectAccess.Ref("project-b", "Synthetic project B");
    private final MemoryProjects projects = new MemoryProjects();
    private final List<GuardController> controllers = new ArrayList<>();
    private final List<RateGate.Permit> permits = Collections.synchronizedList(new ArrayList<>());
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private GuardController controller;

    @AfterEach void cleanup() throws Exception {
        controllers.forEach(GuardController::close); // Wake pending approval/rate waits before joining.
        workers.shutdownNow();
        try { assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS), "synthetic workers terminated"); }
        finally {
            // No dispatch occurs in this suite; these are explicit confirmed-unsent/simulated completions.
            permits.forEach(RateGate.Permit::close);
        }
    }

    @ParameterizedTest @NullAndEmptySource @ValueSource(strings = "   ")
    void absentProjectPolicyUsesEmptyAllowlistWithoutSaving(String stored) {
        projects.document(A, stored);
        open();
        assertEquals(GuardConfig.defaults(), controller.config());
        assertEquals(1, revision());
        assertEquals(false, controller.status().get("paused"));
        blocked(controller.prepare(request("GET", "/safe", "")), "SCOPE_NOT_ALLOWED");
        assertEquals(0, projects.saves.get());
        assertEquals(0, gate("active"));
        assertTrue(controller.approvals().isEmpty());
    }

    @Test void validProjectPolicyLoadsWithoutWritingAndStatusDoesNotExposeNativeName() {
        GuardConfig config = policy(Mode.MONITOR, limits(3, 10, 5_000, 5_000, 10_000));
        projects.ref = new ProjectAccess.Ref(A.id(), SECRET);
        projects.document(A, Json.write(config));
        open();
        assertEquals(config, controller.config());
        assertEquals("project-a", controller.status().get("projectId"));
        assertEquals("Current Burp project", controller.status().get("projectName"));
        assertFalse(controller.status().toString().contains(SECRET));
        assertEquals(1, projects.loads.get());
        assertEquals(0, projects.saves.get());
        controller.refreshProject();
        assertEquals(1, projects.loads.get(), "normal same-project refresh does not replace policy/drafts");
        assertEquals(1, revision());
    }

    static Stream<String> invalidDocuments() {
        String valid = Json.write(policy(Mode.ALLOW, ordinaryLimits()));
        ObjectNode nullPort = Json.MAPPER.valueToTree(policy(Mode.ALLOW, ordinaryLimits()));
        ((ObjectNode) nullPort.withArray("allowScope").get(0)).putNull("port");
        ObjectNode missingPort = nullPort.deepCopy();
        ((ObjectNode) missingPort.withArray("allowScope").get(0)).remove("port");
        ObjectNode fractionalPort = nullPort.deepCopy();
        ((ObjectNode) fractionalPort.withArray("allowScope").get(0)).put("port", 443.9);
        ObjectNode nullEnabled = nullPort.deepCopy();
        ((ObjectNode) nullEnabled.withArray("allowScope").get(0)).put("port", 443);
        ((ObjectNode) nullEnabled.withArray("allowScope").get(0)).putNull("enabled");
        ObjectNode fractionalRate = Json.MAPPER.valueToTree(policy(Mode.ALLOW, ordinaryLimits()));
        ((ObjectNode) fractionalRate.get("limits")).put("globalRps", 5.9);
        ObjectNode unknown = Json.MAPPER.valueToTree(policy(Mode.ALLOW, ordinaryLimits()));
        unknown.put("unknown", SECRET);
        GuardConfig invalidRule = new GuardConfig(1, policy(Mode.ALLOW, ordinaryLimits()).allowScope(), List.of(),
                List.of(new Rule("invalid", "Disabled invalid expression", false, Mode.ALLOW,
                        Condition.leaf(Field.PATH, Match.REGEX, "(?=unsupported)"))), Mode.ALLOW, ordinaryLimits());
        return Stream.of("{", "null", valid + " true", "{\"schemaVersion\":1,\"schemaVersion\":1}",
                Json.write(unknown), valid.replace("\"schemaVersion\" : 2", "\"schemaVersion\" : 3"),
                Json.write(Json.MAPPER.valueToTree(invalidRule)), " ".repeat(2_097_153), Json.write(nullPort), Json.write(missingPort),
                Json.write(fractionalPort), Json.write(nullEnabled), Json.write(fractionalRate));
    }

    @ParameterizedTest(name = "invalid persisted document [{index}]") @MethodSource("invalidDocuments")
    void invalidProjectPolicyIsDefaultDenyPausedAndNeverPartiallyApplied(String stored) {
        projects.document(A, stored);
        open();
        assertEquals(GuardConfig.defaults(), controller.config());
        assertEquals(true, controller.status().get("paused"));
        assertEquals("PROJECT_POLICY_INVALID_DEFAULT_DENY_PAUSED", controller.status().get("note"));
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        assertEquals(0, projects.saves.get());
        assertFalse(controller.status().toString().contains(SECRET));
    }

    @Test void failedLoadCanBeRetriedButCannotBeResumedUntilPolicyReloadSucceeds() {
        projects.document(A, Json.write(policy(Mode.ALLOW, ordinaryLimits())));
        projects.failLoad = true;
        open();
        assertEquals(GuardConfig.defaults(), controller.config());
        assertEquals(true, controller.status().get("paused"));
        assertThrows(IllegalStateException.class, () -> controller.pause(false));
        assertEquals(true, controller.status().get("paused"));
        projects.failLoad = false;
        controller.refreshProject();
        assertEquals(policy(Mode.ALLOW, ordinaryLimits()), controller.config());
        assertEquals(2, projects.loads.get());
        assertEquals(true, controller.status().get("paused"), "reload alone is not a human resume");
        controller.pause(false);
        Admission admission = authorize(controller.prepare(request("GET", "/safe", "")));
        assertTrue(admission.allowed());
    }

    @Test void invalidLoadCanInsteadBeRepairedByExplicitValidatedHumanPolicySave() {
        projects.document(A, "{");
        open();
        apply(policy(Mode.ALLOW, ordinaryLimits()));
        assertEquals(true, controller.status().get("paused"));
        controller.pause(false);
        assertTrue(authorize(controller.prepare(request("GET", "/safe", ""))).allowed());
        assertEquals(1, projects.saves.get());
    }

    @Test void unavailableProjectStartsPausedWithNoRawExceptionAndRecoversOnlyAfterReload() {
        projects.document(A, Json.write(policy(Mode.ALLOW, ordinaryLimits())));
        projects.failCurrent = true;
        open();
        assertEquals("PROJECT_UNAVAILABLE", controller.status().get("note"));
        assertEquals(true, controller.status().get("paused"));
        assertFalse(controller.status().toString().contains(SECRET));
        projects.failCurrent = false;
        assertThrows(IllegalStateException.class, () -> controller.pause(false));
        controller.refreshProject();
        controller.pause(false);
        assertTrue(authorize(controller.prepare(request("GET", "/safe", ""))).allowed());
    }

    @Test void successfulSaveIsProjectLocalAtomicAndInvalidatesOldPreparedRequest() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared before = controller.prepare(request("GET", "/safe", ""));
        long baseline = revision();
        GuardConfig replacement = policy(Mode.MONITOR, limits(2, 7, 4_000, 3_000, 20_000));
        apply(replacement);
        assertEquals(replacement, controller.config());
        assertEquals(baseline + 1, revision());
        assertEquals(replacement, Json.read(projects.documents.get(A.id()), GuardConfig.class));
        assertNull(projects.documents.get(B.id()));
        assertEquals("POLICY_APPLIED", controller.status().get("note"));
        blocked(before, "POLICY_CHANGED");
        assertEquals(2, gate("maxConcurrent"));
    }

    @Test void invalidSaveIsAtomicAndNeverCallsProjectPersistence() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        GuardConfig original = controller.config();
        String stored = projects.documents.get(A.id());
        long baseline = revision();
        GuardConfig invalid = policy(Mode.ALLOW, new Limits(0, 5, Map.of(), 1, 2, 1_000, 1_000, 1_000));
        assertThrows(IllegalArgumentException.class, () -> apply(invalid));
        assertEquals(original, controller.config());
        assertEquals(stored, projects.documents.get(A.id()));
        assertEquals(baseline, revision());
        assertEquals(0, projects.saves.get());
    }

    @Test void staleRevisionDraftCannotOverwriteNewerPolicy() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        long baseline = revision();
        GuardConfig replacement = policy(Mode.BLOCK, ordinaryLimits());
        apply(replacement);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> controller.updateConfig(policy(Mode.ALLOW, ordinaryLimits()), A.id(), baseline));
        assertEquals("STALE_POLICY_DRAFT", failure.getMessage());
        assertEquals(replacement, controller.config());
        assertEquals(1, projects.saves.get());
    }

    @Test void staleProjectDraftIsRejectedEvenBeforeUiRefresh() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        long baseline = revision();
        projects.ref = B;
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> controller.updateConfig(policy(Mode.MONITOR, ordinaryLimits()), A.id(), baseline));
        assertEquals("STALE_POLICY_DRAFT", failure.getMessage());
        assertEquals(0, projects.saves.get());
        assertNull(projects.documents.get(B.id()));
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        assertEquals("PROJECT_UNVERIFIED", controller.status().get("guardState"));
    }

    @Test void unavailableProjectDuringDraftCheckIsCategoricalAndDoesNotSave() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        projects.failCurrent = true;
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> controller.updateConfig(policy(Mode.BLOCK, ordinaryLimits()), A.id(), revision()));
        assertEquals("STALE_POLICY_DRAFT", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(0, projects.saves.get());
    }

    @Test void concurrentDraftsWithOneBaselineHaveExactlyOneSuccessfulSave() throws Exception {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        long baseline = revision();
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (Mode mode : List.of(Mode.BLOCK, Mode.MONITOR)) results.add(workers.submit(() -> {
            assertTrue(start.await(5, TimeUnit.SECONDS));
            try { controller.updateConfig(policy(mode, ordinaryLimits()), A.id(), baseline); return true; }
            catch (IllegalStateException e) { assertEquals("STALE_POLICY_DRAFT", e.getMessage()); return false; }
        }));
        start.countDown();
        assertEquals(1, (get(results.get(0)) ? 1 : 0) + (get(results.get(1)) ? 1 : 0));
        assertEquals(1, projects.saves.get());
        assertEquals(baseline + 1, revision());
        assertEquals(controller.config(), Json.read(projects.documents.get(A.id()), GuardConfig.class));
    }

    @Test void uncertainPartialSaveLatchesPauseUntilSameProjectPolicyIsReloaded() {
        GuardConfig old = policy(Mode.ALLOW, ordinaryLimits());
        GuardConfig storedNew = policy(Mode.BLOCK, ordinaryLimits());
        open(old);
        projects.saveThenFail = true;
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> apply(storedNew));
        assertEquals("POLICY_SAVE_UNCERTAIN", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(old, controller.config(), "uncertain save does not publish a guessed config");
        assertEquals(storedNew, Json.read(projects.documents.get(A.id()), GuardConfig.class));
        assertEquals(true, controller.status().get("paused"));
        assertThrows(IllegalStateException.class, () -> controller.pause(false), "old permissive policy must not resume");
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        projects.saveThenFail = false;
        long baseline = revision();
        controller.refreshProject();
        assertEquals(storedNew, controller.config());
        assertEquals(baseline + 1, revision());
        assertEquals(true, controller.status().get("paused"));
        controller.pause(false);
        blocked(controller.prepare(request("GET", "/safe", "")), "DEFAULT_BLOCK");
    }

    @Test void saveFailureBeforeWriteCancelsApprovalAndNeverUnpausesCachedPolicy() throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        Prepared pending = controller.prepare(request("GET", "/safe", ""));
        Future<Admission> result = workers.submit(() -> authorize(pending));
        await(() -> controller.approvals().size() == 1);
        projects.failSave = true;
        assertThrows(IllegalStateException.class, () -> apply(policy(Mode.ALLOW, ordinaryLimits())));
        denied(get(result), "POLICY_CHANGED");
        assertTrue(controller.approvals().isEmpty());
        assertEquals(0, gate("active"));
        assertEquals(true, controller.status().get("paused"));
        assertThrows(IllegalStateException.class, () -> controller.pause(false));
        assertFalse(controller.status().toString().contains(SECRET));
    }

    @Test void uncertainSaveWakesQueuedRequestButDoesNotCompleteAlreadyReleasedRequest() throws Exception {
        open(policy(Mode.ALLOW, limits(1, 10, 5_000, 5_000, 10_000)));
        Prepared first = controller.prepare(request("GET", "/first", ""));
        Admission running = authorize(first);
        assertTrue(controller.commit(first));
        Prepared second = controller.prepare(request("GET", "/second", ""));
        Future<Admission> waiting = workers.submit(() -> authorize(second));
        await(() -> gate("queued") == 1);
        projects.saveThenFail = true;
        assertThrows(IllegalStateException.class, () -> apply(policy(Mode.BLOCK, ordinaryLimits())));
        denied(get(waiting), "PAUSED");
        assertEquals(1, gate("active"));
        assertEquals(1, evidence("forwarded"));
        assertFalse(controller.current(first));
        controller.refreshProject();
        assertEquals(Mode.BLOCK, controller.config().defaultMode());
        assertEquals(1, gate("active"));
        controller.response(first.evidenceId(), 200, List.of(), new byte[0]);
        running.permit().close();
        assertEquals(0, gate("active"));
    }

    @Test void projectSwitchDuringSaveDoesNotPublishOrUseOldProjectPolicy() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        projects.document(B, Json.write(policy(Mode.BLOCK, ordinaryLimits())));
        projects.afterSave.set(() -> projects.ref = B);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> apply(policy(Mode.MONITOR, ordinaryLimits())));
        assertEquals("PROJECT_CHANGED", failure.getMessage());
        assertEquals("PROJECT_CHANGED_DURING_SAVE", controller.status().get("note"));
        assertEquals(true, controller.status().get("paused"));
        controller.refreshProject();
        assertEquals(B.id(), controller.status().get("projectId"));
        assertEquals(Mode.BLOCK, controller.config().defaultMode());
        controller.pause(false);
        blocked(controller.prepare(request("GET", "/safe", "")), "DEFAULT_BLOCK");
    }

    @Test void projectBecomingUnavailableAfterSaveIsFailClosedUntilReload() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        projects.afterSave.set(() -> projects.failCurrent = true);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> apply(policy(Mode.BLOCK, ordinaryLimits())));
        assertEquals("PROJECT_CHANGED", failure.getMessage());
        assertFalse(failure.getMessage().contains(SECRET));
        projects.failCurrent = false;
        assertEquals(true, controller.status().get("paused"));
        assertThrows(IllegalStateException.class, () -> controller.pause(false));
        controller.refreshProject();
        controller.pause(false);
        blocked(controller.prepare(request("GET", "/safe", "")), "DEFAULT_BLOCK");
    }

    @Test void switchingProjectsLoadsSeparatePoliciesAndRejectsPriorProjectDraft() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        long baselineA = revision();
        Prepared prior = controller.prepare(request("GET", "/safe", ""));
        projects.document(B, Json.write(policy(Mode.BLOCK, ordinaryLimits())));
        projects.ref = B;
        controller.refreshProject();
        assertEquals(B.id(), controller.status().get("projectId"));
        assertEquals(Mode.BLOCK, controller.config().defaultMode());
        blocked(prior, "PROJECT_CHANGED");
        assertThrows(IllegalStateException.class,
                () -> controller.updateConfig(policy(Mode.ALLOW, ordinaryLimits()), A.id(), baselineA));
        assertEquals(0, projects.saves.get());
        projects.ref = A;
        controller.refreshProject();
        assertEquals(Mode.ALLOW, controller.config().defaultMode());
        assertTrue(revision() > baselineA);
        assertFalse(controller.current(prior), "switching away and back does not revive old revision");
    }

    @Test void invalidNewProjectNeverInheritsPriorPermissivePolicy() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        projects.document(B, "{");
        projects.ref = B;
        controller.refreshProject();
        assertEquals(B.id(), controller.status().get("projectId"));
        assertEquals(GuardConfig.defaults(), controller.config());
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        assertThrows(IllegalStateException.class, () -> controller.pause(false));
    }

    @Test void projectSwitchDuringLoadDiscardsAmbiguousPolicyAndSubsequentRefreshLoadsLiveProject() {
        projects.document(A, Json.write(policy(Mode.ALLOW, ordinaryLimits())));
        projects.document(B, Json.write(policy(Mode.BLOCK, ordinaryLimits())));
        projects.afterLoad.set(() -> projects.ref = B);
        open();
        assertEquals(GuardConfig.defaults(), controller.config());
        assertEquals(true, controller.status().get("paused"));
        controller.refreshProject();
        assertEquals(B.id(), controller.status().get("projectId"));
        assertEquals(Mode.BLOCK, controller.config().defaultMode());
        controller.pause(false);
        blocked(controller.prepare(request("GET", "/safe", "")), "DEFAULT_BLOCK");
    }

    @Test void normalPipelineRecordsPendingQueuedReleasedAndResponseWithoutInventingDelivery() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        assertEquals("PENDING", row(p).disposition());
        assertEquals("", row(p).response());
        Admission admission = authorize(p);
        assertTrue(admission.allowed());
        assertEquals("QUEUED", row(p).disposition());
        assertNull(row(p).statusCode());
        assertEquals(1, gate("active"));
        assertTrue(controller.commit(p));
        assertEquals("FORWARDED", row(p).disposition());
        assertEquals("NATIVE_RELEASED", row(p).reason());
        assertNull(row(p).statusCode(), "release is not a fabricated server success");
        controller.response(p.evidenceId(), 403, List.of(new Header("Content-Type", "application/json")), bytes("{\"ok\":false}"));
        assertEquals(403, row(p).statusCode());
        assertEquals("FORWARDED", row(p).disposition(), "target error is not a local block");
        assertEquals(1, gate("active"), "evidence capture cannot claim native completion ownership");
        admission.permit().close(); // Simulated real completion owner, not a timer or evidence method.
        assertEquals(0, gate("active"));
        assertEquals(1, evidence("forwarded"));
        assertEquals(1, evidence("upstreamResponses"));
        assertEquals(0, evidence("localResponses"));
        assertTrue(controller.exportJson(controller.traffic()).contains("NATIVE_RELEASE_NOT_PROVEN_DELIVERY"));
    }

    @Test void askHasReferenceOnlyPendingEvidenceAndHoldsNoPermitUntilOneShotHumanApproval() throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        Prepared p = controller.prepare(request("POST", "/safe", "{\"token\":\"" + SECRET + "\"}"));
        Future<Admission> result = workers.submit(() -> authorize(p));
        await(() -> controller.approvals().size() == 1);
        ApprovalQueue.Pending pending = controller.approvals().getFirst();
        assertEquals(p.evidenceId(), pending.evidenceId());
        assertEquals(A.id(), pending.projectId());
        assertEquals("AWAITING_APPROVAL", row(p).disposition());
        assertEquals(0, gate("active"));
        assertEquals(0, gate("queued"));
        assertFalse(p.toString().contains(SECRET));
        assertFalse(pending.toString().contains(SECRET));
        assertEquals(List.of("id", "evidenceId", "projectId", "createdAt", "expiresAt"),
                Stream.of(ApprovalQueue.Pending.class.getRecordComponents()).map(c -> c.getName()).toList());
        assertTrue(controller.decideApproval(pending.id(), true));
        Admission admission = get(result);
        assertTrue(admission.allowed());
        assertFalse(controller.decideApproval(pending.id(), true));
        assertTrue(controller.approvals().isEmpty());
        assertEquals("QUEUED", row(p).disposition());
        assertEquals(1, gate("active"));
        assertTrue(controller.commit(p));
        admission.permit().close();
    }

    @Test void deniedAskCannotBeReapprovedAndNeverAcquiresPermit() throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Future<Admission> result = workers.submit(() -> authorize(p));
        await(() -> controller.approvals().size() == 1);
        String id = controller.approvals().getFirst().id();
        assertTrue(controller.decideApproval(id, false));
        denied(get(result), "DENIED");
        assertFalse(controller.decideApproval(id, true));
        assertEquals("BLOCKED", row(p).disposition());
        assertEquals(0, gate("admitted"));
        assertEquals(0, evidence("forwarded"));
    }

    @Test void expiredAskFailsClosedAndLateClickCannotSend() throws Exception {
        open(policy(Mode.ASK, limits(1, 5, 5_000, 1_000, 10_000)));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Future<Admission> result = workers.submit(() -> authorize(p));
        await(() -> !controller.approvals().isEmpty());
        String id = controller.approvals().getFirst().id();
        denied(get(result), "APPROVAL_TIMEOUT");
        assertFalse(controller.decideApproval(id, true));
        assertTrue(controller.approvals().isEmpty());
        assertEquals(0, gate("admitted"));
        assertEquals(451, row(p).statusCode());
    }

    @ParameterizedTest @EnumSource(Change.class)
    void projectRevisionPauseOrCloseInvalidatesPendingApproval(Change change) throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Future<Admission> result = workers.submit(() -> authorize(p));
        await(() -> !controller.approvals().isEmpty());
        String id = controller.approvals().getFirst().id();
        change(change);
        denied(get(result), change == Change.CLOSE ? "SHUTDOWN" : "POLICY_CHANGED");
        assertFalse(controller.decideApproval(id, true));
        assertTrue(controller.approvals().isEmpty());
        assertEquals(0, gate("active"));
        assertEquals(0, evidence("forwarded"));
    }

    @ParameterizedTest @EnumSource(Change.class)
    void projectRevisionPauseOrCloseInvalidatesQueuedRequestWithoutReleasingActiveSend(Change change) throws Exception {
        open(policy(Mode.ALLOW, limits(1, 10, 5_000, 5_000, 10_000)));
        Prepared first = controller.prepare(request("GET", "/first", ""));
        Admission running = authorize(first);
        assertTrue(running.allowed());
        assertTrue(controller.commit(first));
        Prepared waiting = controller.prepare(request("GET", "/second", ""));
        Future<Admission> result = workers.submit(() -> authorize(waiting));
        await(() -> gate("queued") == 1);
        assertEquals("QUEUED", row(waiting).disposition());
        change(change);
        denied(get(result), queuedChangeReason(change));
        assertEquals(0, gate("queued"));
        assertEquals(1, gate("active"), "a state change does not complete the first send");
        assertEquals("BLOCKED", row(waiting).disposition());
        assertEquals(1, evidence("forwarded"));
        controller.response(first.evidenceId(), 200, List.of(), new byte[0]);
        running.permit().close();
        assertEquals(0, gate("active"));
    }

    @ParameterizedTest @EnumSource(Change.class)
    void approvalConsumedBeforeQueueDoesNotSurviveSubsequentChange(Change change) throws Exception {
        open(policy(Mode.ASK, limits(1, 10, 5_000, 5_000, 10_000)));
        Prepared first = controller.prepare(request("GET", "/first", ""));
        Admission running = approve(first);
        assertTrue(controller.commit(first));
        Prepared waiting = controller.prepare(request("GET", "/second", ""));
        Future<Admission> result = workers.submit(() -> authorize(waiting));
        await(() -> !controller.approvals().isEmpty());
        String id = controller.approvals().getFirst().id();
        assertTrue(controller.decideApproval(id, true));
        await(() -> gate("queued") == 1);
        assertTrue(controller.approvals().isEmpty());
        assertFalse(controller.decideApproval(id, true));
        change(change);
        denied(get(result), queuedChangeReason(change));
        assertEquals(1, gate("active"));
        running.permit().close();
        assertEquals(1, evidence("forwarded"));
    }

    @ParameterizedTest @EnumSource(Change.class)
    void finalCommitRejectsStateChangesAfterAuthorizationAndCallerReleasesConfirmedUnsentPermit(Change change) {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Admission admission = authorize(p);
        assertTrue(admission.allowed());
        change(change);
        assertFalse(controller.commit(p));
        assertFalse(controller.current(p));
        assertEquals("BLOCKED", row(p).disposition());
        assertEquals(switch (change) {
            case POLICY, PASSTHROUGH -> "POLICY_CHANGED";
            case PROJECT, REFRESH_PROJECT -> "PROJECT_CHANGED";
            case PAUSE -> "PAUSED"; // Shared fixed native vocabulary is preserved in evidence.
            case CLOSE -> "SHUTDOWN";
        }, row(p).reason());
        assertEquals(0, evidence("forwarded"));
        assertEquals(1, gate("active"), "commit has no completion ownership");
        admission.permit().close(); // No dispatch began: the caller can conclusively release.
        admission.permit().close();
        assertEquals(0, gate("active"));
    }

    @Test void pauseResumeDoesNotRevivePreparedRequestOrPreviouslyCancelledApproval() throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        Prepared old = controller.prepare(request("GET", "/safe", ""));
        Future<Admission> waiting = workers.submit(() -> authorize(old));
        await(() -> !controller.approvals().isEmpty());
        String id = controller.approvals().getFirst().id();
        controller.pause(true);
        denied(get(waiting), "POLICY_CHANGED");
        controller.pause(false);
        blocked(old, "POLICY_CHANGED");
        assertFalse(controller.decideApproval(id, true));
        assertTrue(approve(controller.prepare(request("GET", "/safe", ""))).allowed());
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void interruptedApprovalOrRateWaitIsDeniedAndInterruptFlagPreserved(boolean ask) throws Exception {
        open(policy(ask ? Mode.ASK : Mode.ALLOW, limits(1, 10, 5_000, 5_000, 10_000)));
        if (!ask) assertTrue(authorize(controller.prepare(request("GET", "/held", ""))).allowed());
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        AtomicReference<Thread> thread = new AtomicReference<>();
        Future<Boolean> result = workers.submit(() -> {
            thread.set(Thread.currentThread());
            Admission admission = authorize(p);
            denied(admission, "CANCELLED");
            return Thread.currentThread().isInterrupted();
        });
        await(() -> ask ? !controller.approvals().isEmpty() : gate("queued") == 1);
        thread.get().interrupt();
        assertTrue(get(result));
        assertTrue(controller.approvals().isEmpty());
        assertEquals(0, gate("queued"));
        assertEquals(ask ? 0 : 1, gate("active"));
        assertEquals("CANCELLED", row(p).reason());
    }

    @Test void queueCapacityAndTimeoutAreLocalDenialsNotExtraSends() throws Exception {
        open(policy(Mode.ALLOW, limits(1, 1, 1_000, 5_000, 10_000)));
        Prepared first = controller.prepare(request("GET", "/first", ""));
        Admission running = authorize(first);
        assertTrue(controller.commit(first));
        Prepared queued = controller.prepare(request("GET", "/queued", ""));
        Future<Admission> result = workers.submit(() -> authorize(queued));
        await(() -> gate("queued") == 1);
        Prepared overflow = controller.prepare(request("GET", "/overflow", ""));
        blocked(overflow, "QUEUE_FULL");
        denied(get(result), "QUEUE_TIMEOUT");
        assertEquals(1, gate("active"));
        assertEquals(1, gate("admitted"));
        assertEquals(2, evidence("blocked"));
        assertEquals(1, evidence("forwarded"));
        running.permit().close();
    }

    @Test void inFlightTimeoutQuarantinesWithoutImplicitReleaseAndLateCompletionClearsIt() throws Exception {
        open(policy(Mode.ALLOW, limits(1, 10, 5_000, 5_000, 1_000)));
        Prepared first = controller.prepare(request("GET", "/first", ""));
        Admission running = authorize(first);
        assertTrue(controller.commit(first));
        Prepared waiting = controller.prepare(request("GET", "/waiting", ""));
        Future<Admission> result = workers.submit(() -> authorize(waiting));
        denied(get(result), "IN_FLIGHT_TIMEOUT");
        assertEquals(1, gate("active"));
        assertEquals(1, gate("stalled"));
        controller.pause(true);
        apply(policy(Mode.ALLOW, limits(1, 10, 5_000, 5_000, 60_000)));
        controller.pause(false);
        blocked(controller.prepare(request("GET", "/new", "")), "IN_FLIGHT_TIMEOUT");
        assertEquals(1, gate("active"));
        controller.response(first.evidenceId(), 200, List.of(), new byte[0]);
        assertEquals(1, gate("active"), "even capture of a response does not close a caller-owned permit");
        running.permit().close(); // Synthetic late real completion.
        assertEquals(0, gate("stalled"));
        assertTrue(authorize(controller.prepare(request("GET", "/fresh", ""))).allowed());
    }

    @Test void closeIsIdempotentDeniesFreshWorkAndNeverReleasesExistingPermit() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Admission admission = authorize(p);
        assertTrue(controller.commit(p));
        controller.close();
        controller.close();
        assertEquals(true, controller.status().get("closed"));
        assertEquals(1, gate("active"));
        blocked(controller.prepare(request("GET", "/new", "")), "SHUTDOWN");
        int loads = projects.loads.get();
        controller.refreshProject();
        assertEquals(loads, projects.loads.get());
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> apply(controller.config()));
        assertEquals("SHUTDOWN", failure.getMessage());
        controller.response(p.evidenceId(), 200, List.of(), new byte[0]);
        admission.permit().close();
        assertEquals(0, gate("active"));
    }

    @ParameterizedTest @ValueSource(strings = {"scope", "method"})
    void hardBlocksAreNeverPresentedAsHumanApprovable(String kind) {
        GuardConfig config = policy(Mode.ASK, ordinaryLimits());
        open(config);
        RequestData input = switch (kind) {
            case "scope" -> new RequestData("GET", "https://outside.test/safe", "outside.test", 443, true, List.of(), new byte[0]);
            case "method" -> request("DELETE", "/safe", "");
            default -> throw new AssertionError(kind);
        };
        Prepared p = controller.prepare(input);
        assertEquals(Mode.BLOCK, p.decision().mode());
        assertFalse(authorize(p).allowed());
        assertTrue(controller.approvals().isEmpty());
        assertEquals(0, gate("admitted"));
        assertFalse(controller.decideApproval(p.evidenceId(), true));
    }

    @Test void local451AndUpstream451HaveDistinctEvidenceCountersAndHarProvenance() throws Exception {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared local = controller.prepare(request("DELETE", "/safe", ""));
        assertFalse(authorize(local).allowed());
        assertEquals("", row(local).response(), "block decision alone does not invent a captured response");
        controller.localResponse(local.evidenceId(), bytes("{\"source\":\"cairn-proxy-guard\",\"outcome\":\"blocked\",\"retryable\":false}"));
        Prepared remote = controller.prepare(request("GET", "/safe", ""));
        Admission admission = authorize(remote);
        assertTrue(controller.commit(remote));
        controller.response(remote.evidenceId(), 451, List.of(new Header("Content-Type", "application/json")), bytes("{\"origin\":\"fixture\"}"));
        admission.permit().close();
        assertEquals("BLOCKED", row(local).disposition());
        assertEquals("FORWARDED", row(remote).disposition());
        assertEquals(451, row(local).statusCode());
        assertEquals(451, row(remote).statusCode());
        assertTrue(row(local).response().contains("X-Cairn-Guard: blocked"));
        assertEquals(1, evidence("localResponses"));
        assertEquals(1, evidence("upstreamResponses"));
        var entries = Json.MAPPER.readTree(controller.exportHar(controller.traffic())).path("log").path("entries");
        for (var entry : entries) {
            var provenance = entry.path("_cairnGuard");
            String expected = provenance.path("evidenceId").asText().equals(local.evidenceId()) ? "LOCAL_BLOCK" : "RESPONSE_CALLBACK";
            assertEquals(expected, provenance.path("responseSource").asText());
            assertFalse(provenance.path("completeWireCapture").asBoolean(true));
        }
    }

    @Test void adapterRejectionOmitsRawCaptureAndUnknownCategoryIsNotEchoedToEvidence() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        Prepared p = controller.prepareRejected(SECRET);
        assertFalse(authorize(p).allowed());
        assertEquals("[REDACTED]", row(p).method(), "unknown methods are conservatively suppressed by evidence");
        assertEquals("https://redacted.invalid/", row(p).url());
        assertTrue(row(p).request().contains("OMITTED"));
        assertFalse(controller.exportJson(controller.traffic()).contains(SECRET));
        assertEquals(0, gate("admitted"));
    }

    @Test void inspectionApprovalEvidenceAndExportsNeverMutateAuthenticationInputs() throws Exception {
        open(policy(Mode.ASK, ordinaryLimits()));
        List<Header> headers = List.of(new Header("Authorization", "Bearer " + SECRET),
                new Header("Proxy-Authorization", "Basic ZmFrZTpmYWtl"), new Header("Cookie", "sid=" + SECRET),
                new Header("X-API-Key", SECRET), new Header("Content-Type", "application/json"),
                new Header("X-Duplicate", "one"), new Header("X-Duplicate", "two"));
        byte[] body = bytes("{\"token\":\"" + SECRET + "\",\"value\":\"safe\"}");
        byte[] originalBody = body.clone();
        RequestData request = new RequestData("POST", "https://example.test/safe?token=" + SECRET,
                "example.test", 443, true, headers, body);
        Prepared p = controller.prepare(request);
        Admission admission = approve(p);
        assertTrue(controller.commit(p));
        List<Header> responseHeaders = List.of(new Header("Set-Cookie", "sid=" + SECRET + "; HttpOnly"),
                new Header("Content-Type", "application/json"));
        byte[] response = bytes("{\"token\":\"" + SECRET + "\"}");
        byte[] originalResponse = response.clone();
        controller.response(p.evidenceId(), 200, responseHeaders, response);
        admission.permit().close();
        assertEquals(headers, request.headers());
        assertArrayEquals(originalBody, request.body());
        assertArrayEquals(originalBody, body);
        assertArrayEquals(originalResponse, response);
        assertEquals("sid=" + SECRET + "; HttpOnly", responseHeaders.getFirst().value());
        for (String export : List.of(controller.exportJson(controller.traffic()), controller.exportHar(controller.traffic()))) {
            assertFalse(export.contains(SECRET));
            assertFalse(export.contains("ZmFrZTpmYWtl"));
            assertTrue(export.contains("[REDACTED]"));
        }
    }

    @Test void bookmarkAndClearAreEvidenceOnlyNotPolicyOrPermitOperations() {
        open(policy(Mode.MONITOR, ordinaryLimits()));
        Prepared p = controller.prepare(request("GET", "/safe", ""));
        Admission admission = authorize(p);
        assertEquals(Mode.MONITOR, p.decision().mode());
        assertTrue(controller.commit(p));
        long revision = revision();
        TrafficEntry old = row(p);
        controller.bookmark(p.evidenceId(), true);
        assertTrue(row(p).bookmarked());
        assertFalse(old.bookmarked());
        controller.clearEvidence();
        assertTrue(controller.traffic().isEmpty());
        assertEquals(revision, revision());
        assertEquals(1, gate("active"));
        assertEquals(1, evidence("forwarded"));
        assertEquals(0, evidence("retainedEntries"));
        controller.response(p.evidenceId(), 200, List.of(), new byte[0]);
        admission.permit().close();
        assertEquals(1, evidence("orphanResponses"));
    }

    @Test void passthroughIsExplicitRuntimeOnlyCountOnlyAndDoesNotChangeSavedPolicy() {
        open();
        GuardConfig before = controller.config();
        long baseline = revision();
        assertEquals(false, controller.status().get("passthrough"));
        assertNull(controller.passthroughToken());
        controller.passthrough(true, A.id(), baseline);
        assertEquals(true, controller.status().get("passthrough"));
        assertEquals(false, controller.status().get("paused"));
        assertEquals(baseline + 1, revision());
        var token = controller.passthroughToken();
        assertNotNull(token);
        assertTrue(controller.commitPassthrough(token));
        assertEquals(1L, controller.status().get("passthroughCount"));
        assertTrue(controller.traffic().isEmpty());
        assertEquals(0, gate("active"));
        assertEquals(before, controller.config());
        assertEquals(0, projects.saves.get());
        controller.passthrough(true, A.id(), revision());
        assertEquals(baseline + 1, revision(), "same-state operation does not mutate a runtime generation");
        controller.passthrough(false, A.id(), revision());
        assertFalse(controller.commitPassthrough(token));
        assertNull(controller.passthroughToken());
        blocked(controller.prepare(request("GET", "/safe", "")), "SCOPE_NOT_ALLOWED");
        GuardController fresh = new GuardController(projects); controllers.add(fresh);
        assertEquals(false, fresh.status().get("passthrough"));
        assertEquals(0L, fresh.status().get("passthroughCount"));
        assertEquals(0, projects.saves.get());
    }

    @Test void staleModeIntentCannotCrossRevisionProjectOrUnavailableState() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        long baseline = revision();
        apply(controller.config());
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), baseline));
        assertEquals(false, controller.status().get("passthrough"));
        projects.ref = B;
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        projects.ref = A; projects.failCurrent = true;
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        assertNull(controller.passthroughToken());
        assertEquals(1, projects.saves.get());
    }

    @Test void passthroughTokensCannotSurviveModeCyclesOrSaveAndDoNotDrainProtectedPipeline() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        controller.passthrough(true, A.id(), revision());
        var old = controller.passthroughToken();
        controller.passthrough(false, A.id(), revision());
        controller.passthrough(true, A.id(), revision());
        assertFalse(controller.commitPassthrough(old));
        var beforeSave = controller.passthroughToken();
        apply(policy(Mode.BLOCK, ordinaryLimits()));
        assertEquals(true, controller.status().get("passthrough"), "a policy save must not silently turn protection on");
        assertFalse(controller.commitPassthrough(beforeSave));
        assertTrue(controller.commitPassthrough(controller.passthroughToken()));
        blocked(controller.prepare(request("GET", "/safe", "")), "POLICY_CHANGED");
        controller.passthrough(false, A.id(), revision());
        blocked(controller.prepare(request("GET", "/safe", "")), "DEFAULT_BLOCK");
    }

    @Test void blockNewRequestsAndResumeAreNotPassthroughAndCannotReviveAnOldToken() {
        open(policy(Mode.ALLOW, ordinaryLimits()));
        controller.pause(true);
        controller.passthrough(true, A.id(), revision());
        assertEquals(false, controller.status().get("paused"));
        var token = controller.passthroughToken();
        controller.pause(true);
        assertEquals(false, controller.status().get("passthrough"));
        assertFalse(controller.commitPassthrough(token));
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        controller.pause(false);
        assertNull(controller.passthroughToken());
        assertTrue(authorize(controller.prepare(request("GET", "/safe", ""))).allowed());
    }

    @Test void projectChangeResetsPassthroughAndCounterAndCannotReviveOldTokens() {
        open();
        controller.passthrough(true, A.id(), revision());
        var token = controller.passthroughToken();
        assertTrue(controller.commitPassthrough(token));
        projects.ref = B;
        assertNull(controller.passthroughToken(), "even before the UI refresh, do not bypass a different project");
        assertFalse(controller.commitPassthrough(token));
        controller.refreshProject();
        assertEquals(false, controller.status().get("passthrough"));
        assertEquals(0L, controller.status().get("passthroughCount"));
        blocked(controller.prepare(request("GET", "/safe", "")), "PAUSED");
        controller.pause(false); // A detected unverifiable project ends OFF and requires explicit resume after reload.
        blocked(controller.prepare(request("GET", "/safe", "")), "SCOPE_NOT_ALLOWED");
        projects.ref = A; controller.refreshProject();
        assertNull(controller.passthroughToken());
        assertFalse(controller.commitPassthrough(token));
    }

    @Test void projectUnavailabilityResetsPassthroughAndRequiresVerifiedReload() {
        open();
        controller.passthrough(true, A.id(), revision());
        var token = controller.passthroughToken();
        projects.failCurrent = true;
        assertNull(controller.passthroughToken());
        assertFalse(controller.commitPassthrough(token));
        controller.refreshProject();
        assertEquals(false, controller.status().get("passthrough"));
        assertEquals(true, controller.status().get("paused"));
        projects.failCurrent = false;
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        controller.refreshProject();
        assertEquals(false, controller.status().get("passthrough"));
        assertEquals(true, controller.status().get("paused"), "reload alone must not turn anything on");
        assertFalse(controller.commitPassthrough(token));
        controller.passthrough(true, A.id(), revision());
        assertNotNull(controller.passthroughToken());
    }

    @Test void uncertainPolicySaveWhileOffDisablesPassthroughRatherThanKeepingAnUnsafeState() {
        open();
        controller.passthrough(true, A.id(), revision());
        var token = controller.passthroughToken();
        projects.failSave = true;
        assertThrows(IllegalStateException.class, () -> apply(policy(Mode.ALLOW, ordinaryLimits())));
        assertEquals(false, controller.status().get("passthrough"));
        assertEquals(true, controller.status().get("paused"));
        assertFalse(controller.commitPassthrough(token));
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        assertNull(controller.passthroughToken());
    }

    @Test void invalidStartupAndShutdownNeverOfferPassthroughTokens() {
        projects.document(A, "{"); open();
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        assertNull(controller.passthroughToken());
        apply(GuardConfig.defaults());
        controller.passthrough(true, A.id(), revision());
        var token = controller.passthroughToken();
        controller.close();
        assertNull(controller.passthroughToken());
        assertFalse(controller.commitPassthrough(token));
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, A.id(), revision()));
        assertEquals(false, controller.status().get("passthrough"));
    }

    @Test void automaticOffTerminationInvalidatesHumanModeBaselinesAndExplainsTheReset() {
        open();
        controller.passthrough(true, A.id(), revision());
        long baseline = revision();
        projects.failCurrent = true; controller.refreshProject();
        assertTrue(revision() > baseline);
        assertEquals(true, controller.status().get("passthroughEnded"));
        assertEquals(false, controller.status().get("passthroughAvailable"));
        projects.failCurrent = false;
        assertThrows(IllegalStateException.class, () -> controller.passthrough(false, A.id(), baseline));
        controller.refreshProject();
        assertEquals(true, controller.status().get("passthroughAvailable"));
        assertEquals(true, controller.status().get("paused"));
        assertEquals(true, controller.status().get("passthroughEnded"));
        controller.pause(false);
        assertEquals(false, controller.status().get("passthroughEnded"));
    }

    private enum Change { POLICY, PROJECT, REFRESH_PROJECT, PAUSE, CLOSE, PASSTHROUGH }

    private static String queuedChangeReason(Change change) {
        return switch (change) {
            case CLOSE -> "SHUTDOWN";
            case PROJECT, REFRESH_PROJECT -> "PROJECT_CHANGED";
            case PAUSE -> "PAUSED";
            case POLICY, PASSTHROUGH -> "POLICY_CHANGED";
        };
    }

    private void change(Change change) {
        switch (change) {
            case POLICY -> apply(controller.config());
            case PROJECT -> projects.ref = B;
            case REFRESH_PROJECT -> { projects.ref = B; controller.refreshProject(); }
            case PAUSE -> controller.pause(true);
            case CLOSE -> controller.close();
            case PASSTHROUGH -> controller.passthrough(true, A.id(), revision());
        }
    }

    private void open(GuardConfig config) { projects.document(A, Json.write(config)); open(); }
    private void open() { controller = new GuardController(projects); controllers.add(controller); }
    private void apply(GuardConfig config) {
        controller.updateConfig(config, (String) controller.status().get("projectId"), revision());
    }
    private long revision() { return ((Number) controller.status().get("revision")).longValue(); }
    private long gate(String key) { return metric("gate", key); }
    private long evidence(String key) { return metric("evidence", key); }
    private long metric(String section, String key) {
        return ((Number) ((Map<?, ?>) controller.status().get(section)).get(key)).longValue();
    }
    private Admission authorize(Prepared p) {
        Admission admission = controller.authorize(p);
        if (admission.permit() != null) permits.add(admission.permit());
        return admission;
    }
    private Admission approve(Prepared p) throws Exception {
        Future<Admission> result = workers.submit(() -> authorize(p));
        await(() -> controller.approvals().stream().anyMatch(a -> a.evidenceId().equals(p.evidenceId())));
        String id = controller.approvals().stream().filter(a -> a.evidenceId().equals(p.evidenceId())).findFirst().orElseThrow().id();
        assertTrue(controller.decideApproval(id, true));
        Admission admission = get(result);
        assertTrue(admission.allowed());
        return admission;
    }
    private void blocked(Prepared p, String reason) {
        denied(authorize(p), reason);
        assertEquals("BLOCKED", row(p).disposition());
        assertEquals(451, row(p).statusCode());
    }
    private static void denied(Admission admission, String reason) {
        assertFalse(admission.allowed());
        assertEquals(reason, admission.reason());
        assertNull(admission.permit());
    }
    private TrafficEntry row(Prepared p) {
        return controller.traffic().stream().filter(e -> e.id().equals(p.evidenceId())).findFirst().orElseThrow();
    }
    private static RequestData request(String method, String path, String body) {
        return new RequestData(method, "https://example.test" + path, "example.test", 443, true,
                List.of(new Header("Content-Type", "application/json")), bytes(body));
    }
    private static GuardConfig policy(Mode mode, Limits limits) {
        return new GuardConfig(2, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), List.of(),
                GuardConfig.defaults().rules(), mode, limits);
    }
    private static Limits ordinaryLimits() { return limits(3, 20, 5_000, 5_000, 10_000); }
    private static Limits limits(int concurrent, int queued, long queueTimeout, long approvalTimeout, long requestTimeout) {
        return new Limits(1_000, 1_000, Map.of(), concurrent, queued, queueTimeout, approvalTimeout, requestTimeout);
    }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static <T> T get(Future<T> future) throws Exception { return future.get(6, TimeUnit.SECONDS); }
    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline >= 0) fail("finite wait expired for synthetic controller state");
            Thread.sleep(5);
        }
    }

    /** Policies are keyed to a fabricated project; hooks model native persistence ambiguity, not disk I/O. */
    private static final class MemoryProjects implements ProjectAccess {
        final Map<String, String> documents = new ConcurrentHashMap<>();
        final AtomicInteger saves = new AtomicInteger();
        final AtomicInteger loads = new AtomicInteger();
        final AtomicReference<Runnable> afterSave = new AtomicReference<>();
        final AtomicReference<Runnable> afterLoad = new AtomicReference<>();
        volatile Ref ref = A;
        volatile boolean failCurrent;
        volatile boolean failLoad;
        volatile boolean failSave;
        volatile boolean saveThenFail;
        void document(Ref project, String value) {
            if (value == null) documents.remove(project.id()); else documents.put(project.id(), value);
        }
        @Override public Ref current() {
            if (failCurrent) throw new IllegalStateException(SECRET);
            return ref;
        }
        @Override public String load() {
            loads.incrementAndGet();
            if (failLoad) throw new IllegalStateException(SECRET);
            String document = documents.get(ref.id());
            run(afterLoad);
            return document;
        }
        @Override public void save(String json) {
            saves.incrementAndGet();
            if (failSave) throw new IllegalStateException(SECRET);
            documents.put(ref.id(), json);
            run(afterSave);
            if (saveThenFail) throw new IllegalStateException(SECRET);
        }
        private static void run(AtomicReference<Runnable> hook) {
            Runnable action = hook.getAndSet(null);
            if (action != null) action.run();
        }
    }
}
