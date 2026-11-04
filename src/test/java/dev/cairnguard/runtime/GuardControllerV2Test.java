package dev.cairnguard.runtime;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.PolicyCodec;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import dev.cairnguard.runtime.GuardController.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real controller/watcher/budget/evidence/queue dependencies. No native Burp or outbound network. */
@Timeout(20)
class GuardControllerV2Test {
    private static final String SECRET = "synthetic-issued-grant-8462";
    private final Projects projects = new Projects();
    private final AtomicLong nano = new AtomicLong();
    private final List<RateGate.Permit> permits = new ArrayList<>();
    private GuardController controller;
    private ResponseWatcher watcher;
    @AfterEach void close() {
        if (controller != null) controller.close();
        permits.forEach(RateGate.Permit::close); // Synthetic completions/conclusively unsent only.
    }

    @Test void exemptBeatsBlockButNeverScopePauseHeavyOrBudget() {
        Limits limits = limits(10, null, null, 1, false);
        open(policy(limits, List.of(rule("block", Mode.BLOCK, "/broker"), rule("exempt", Mode.EXEMPT, "/broker"))));
        Prepared first = prepare("GET", "/broker", "one");
        assertEquals(Mode.EXEMPT, first.decision().mode());
        handoff(first);
        assertEquals("exempt", row(first).outcome());
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 11);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/broker", "other")).reason());
        assertEquals(1, metric("intents", "consumed"));
        controller.releaseAllOverlays("a", revision());
        assertEquals("INTENT_BUDGET_EXCEEDED", controller.authorize(prepare("GET", "/broker", "one")).reason());
        controller.pause(true);
        assertEquals("PAUSED", controller.authorize(prepare("GET", "/broker", "other")).reason());
        controller.pause(false);
        RequestData outside = new RequestData("GET", "https://owned.test/broker", "outside.test", 443, true, List.of(), new byte[0]);
        assertEquals("SCOPE_NOT_ALLOWED", controller.authorize(controller.prepare(outside)).reason());
        assertEquals(0, projects.saves.get());
    }

    @Test void twentyFirstExactFinalCommitIsDeniedOtherIntentAndRunUnaffected() {
        open(policy(limits(0, null, null, 20, false), List.of()));
        for (int i = 0; i < 20; i++) {
            Prepared p = prepare("GET", "/safe", "i048");
            handoff(p);
            controller.response(p.evidenceId(), 200, List.of(), new byte[0], 0);
            permits.getLast().close();
        }
        Prepared over = prepare("GET", "/safe", "i048");
        assertEquals("INTENT_BUDGET_EXCEEDED", controller.authorize(over).reason());
        assertEquals("INTENT_BUDGET", controller.denial(over, "INTENT_BUDGET_EXCEEDED").guardState());
        assertEquals(20, metric("intents", "consumed"));
        handoff(prepare("GET", "/safe", "i049"));
        RequestData otherRun = request("GET", "/safe", List.of(new Header("X-Cairn-Intent", "i048"), new Header("X-Cairn-Run", "other")), new byte[0], true, true);
        handoff(controller.prepare(otherRun));
        for (int i = 0; i < 3; i++) handoff(prepare("GET", "/untagged", null));
        assertEquals(22, metric("intents", "consumed"));
        assertEquals(1L, ((Map<?, ?>) controller.status().get("reasonCounters")).get("INTENT_BUDGET_EXCEEDED"));
    }

    @Test void simultaneousFinalHandoffsHaveExactlyTwentyWinnersAndNoDuplicateSpend() throws Exception {
        open(policy(limits(0, null, null, 20, false), List.of()));
        List<Prepared> ready = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            Prepared p = prepare("GET", "/safe", "racing");
            authorize(p);
            ready.add(p);
        }
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            var results = ready.stream().map(p -> workers.submit(() -> {
                assertTrue(start.await(5, TimeUnit.SECONDS));
                CommitResult result = controller.commitDetailed(p);
                if (result.allowed()) winners.incrementAndGet();
                else assertEquals("INTENT_BUDGET_EXCEEDED", result.reason());
                return result;
            })).toList();
            start.countDown();
            for (var result : results) result.get(5, TimeUnit.SECONDS);
        }
        assertEquals(20, winners.get());
        assertEquals(20, metric("intents", "consumed"));
        assertEquals(20, metric("evidence", "forwarded"));
        assertEquals(20, metric("evidence", "blocked"));
        assertFalse(controller.commitDetailed(ready.getFirst()).allowed());
        assertEquals(20, metric("intents", "consumed"));
    }

    @ParameterizedTest @ValueSource(strings = {"duplicate-intent", "duplicate-run", "bad", "incomplete-absent", "incomplete-valid"})
    void invalidOrUnprovableAttributionIsRejectedOnlyWithBudgetEnabled(String kind) {
        Limits enabled = limits(0, null, null, 20, false);
        open(policy(enabled, List.of()));
        List<Header> headers = switch (kind) {
            case "duplicate-intent" -> List.of(new Header("X-Cairn-Intent", "one"), new Header("x-cairn-intent", "one"));
            case "duplicate-run" -> List.of(new Header("X-Cairn-Intent", "one"), new Header("X-Cairn-Run", "r"), new Header("X-Cairn-Run", "r"));
            case "bad" -> List.of(new Header("X-Cairn-Intent", " bad "));
            case "incomplete-valid" -> List.of(new Header("X-Cairn-Intent", "one"));
            default -> List.of();
        };
        RequestData request = request("GET", "/safe", headers, new byte[0], !kind.startsWith("incomplete"), true);
        assertEquals("INVALID_INTENT_TAG", controller.authorize(controller.prepare(request)).reason());
        assertEquals(0, metric("intents", "consumed"));
        assertEquals(0, metric("gate", "admitted"));
        save(policy(limits(0, null, null, 0, false), List.of()));
        handoff(controller.prepare(request));
    }

    @Test void finalFanoutRejectionAndResponseBetweenAuthorizeAndCommitConsumeNoBudget() {
        Limits limits = limits(10, null, new Fanout(60_000, 2, FanoutAction.BLOCK), 20, false);
        open(policy(limits, List.of()));
        Prepared first = prepare("GET", "/one", "one");
        handoff(first);
        Prepared second = prepare("GET", "/two", "one");
        authorize(second); // advisory check has not yet counted distinct paths
        CommitResult result = controller.commitDetailed(second);
        assertFalse(result.allowed());
        assertEquals("FANOUT_SUSPECTED", result.reason());
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(1, metric("watchers", "activeTickets"));
        assertFalse(controller.denial(second, result.reason()).overlayId().isEmpty());
        controller.releaseAllOverlays("a", revision());
        Prepared same = prepare("GET", "/one", "one");
        authorize(same);
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 11);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.commitDetailed(same).reason());
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(0, projects.saves.get());
    }

    @Test void completedWarnFanoutChurnDoesNotExhaustWatcherPathCapacity() {
        GuardConfig config = policy(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN), 20, false), List.of());
        projects.document = PolicyCodec.encode(config);
        openStored(config.limits(), 4096, 2, 4096);
        for (String path : List.of("/a", "/b", "/c", "/d")) {
            Prepared p = prepare("GET", path, "one");
            handoff(p);
            controller.response(p.evidenceId(), 200, List.of(), new byte[0], 0);
        }
        assertEquals(4, metric("intents", "consumed"));
        assertEquals(2, metric("watchers", "fanoutHistoryOmitted"));
    }

    @Test void warnOmissionDebtFailsEnforcingClosedAcrossSaveAndOffWithoutIntentSpendUntilEpochReset() {
        List<Rule> rules = List.of(rule("exempt", Mode.EXEMPT, "/exempt"));
        GuardConfig warn = policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN), 20, true), rules);
        projects.document = PolicyCodec.encode(warn);
        openStored(warn.limits(), 4096, 2, 4096);
        for (String path : List.of("/a", "/b", "/c")) {
            Prepared p = prepare("GET", path, "one");
            handoff(p);
            controller.response(p.evidenceId(), 200, List.of(), new byte[0], 0);
        }
        assertEquals(1, metric("watchers", "fanoutHistoryOmitted"));
        save(policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK), 20, true), rules));
        controller.passthrough(true, "a", revision());
        controller.passthrough(false, "a", revision());
        for (String path : List.of("/a", "/new", "/exempt", "/health")) {
            Admission admission = controller.authorize(prepare("GET", path, "one"));
            assertFalse(admission.allowed(), path);
            assertEquals("RESPONSE_WATCHER_CAPACITY", admission.reason(), path);
        }
        assertEquals(3, metric("intents", "consumed"));
        assertEquals(1, metric("watchers", "fanoutHistoryOmitted"));
        projects.id = "b";
        controller.refreshProject();
        assertEquals(0, metric("watchers", "fanoutHistoryOmitted"));
        handoff(prepare("GET", "/a", "one"));
    }

    @Test void finalCommitRejectsEnforcingIdentityWithoutHistorySlotBeforeIntentSpend() {
        GuardConfig warn = policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN), 20, false), List.of());
        projects.document = PolicyCodec.encode(warn);
        openStored(warn.limits(), 4096, 2, 4096);
        Prepared indexed = prepare("GET", "/a", "one");
        handoff(indexed);
        controller.response(indexed.evidenceId(), 200, List.of(), new byte[0], 0);
        save(policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK), 20, false), List.of()));
        Prepared first = prepare("GET", "/b", "one");
        Prepared second = prepare("GET", "/c", "one");
        authorize(first);
        authorize(second);
        assertTrue(controller.commitDetailed(first).allowed());
        CommitResult result = controller.commitDetailed(second);
        assertFalse(result.allowed());
        assertEquals("RESPONSE_WATCHER_CAPACITY", result.reason());
        assertEquals(2, metric("intents", "consumed"));
        assertEquals(0, metric("watchers", "fanoutHistoryOmitted"));
    }

    @Test void policyGenerationAndLocalQueueRejectionsNeverConsumeBudgetOrRecycleNativePermit() {
        Limits limits = new Limits(1000, 1000, Map.of(), 1, 0, 1000, 1000, 1000,
                0, 1000, null, null, 20, false, List.of(), List.of());
        projects.document = PolicyCodec.encode(policy(limits, List.of()));
        watcher = new ResponseWatcher(limits, nano::get, () -> 1_000_000L);
        controller = new GuardController(projects, watcher, new IntentBudget(), new RateGate(limits, nano::get, 4096),
                new ListenerRegistry(), nano::get, 4096);
        Prepared first = prepare("GET", "/one", "one");
        handoff(first);
        assertEquals("QUEUE_FULL", controller.authorize(prepare("GET", "/two", "one")).reason());
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(1, metric("gate", "active"));
        permits.getFirst().close();
        advance(1); // deterministic rate debt expiry; no scheduler-dependent wall-clock sleep.
        Prepared stale = prepare("GET", "/two", "one");
        authorize(stale);
        save(controller.config());
        assertEquals("POLICY_CHANGED", controller.commitDetailed(stale).reason());
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(1, metric("gate", "active"));
        advance(1000);
        Prepared timedOut = prepare("GET", "/two", "one");
        assertEquals("IN_FLIGHT_TIMEOUT", controller.authorize(timedOut).reason());
        assertEquals("IN_FLIGHT_STALLED", controller.denial(timedOut, "IN_FLIGHT_TIMEOUT").guardState());
        assertEquals("IN_FLIGHT_STALLED", controller.status().get("guardState"));
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(1, metric("gate", "active"));
    }

    @Test void halfOpenIsFinalAtomicGetHeadOnlyHasCadenceAndDoesNotRecycleNativePermits() {
        Limits limits = limits(0, new Circuit5xx(60_000, 1, 1000, 1), null, 20, false);
        open(policy(limits, List.of()));
        Prepared first = prepare("GET", "/safe", "one");
        handoff(first);
        controller.response(first.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals("CIRCUIT_OPEN", controller.authorize(prepare("GET", "/safe", "one")).reason());
        advance(1000);
        assertEquals("CIRCUIT_OPEN", controller.authorize(prepare("POST", "/safe", "one")).reason());
        Prepared a = prepare("GET", "/safe", "one");
        Prepared b = prepare("HEAD", "/safe", "one");
        authorize(a); authorize(b);
        assertTrue(controller.commitDetailed(a).allowed());
        assertEquals("half_open", row(a).outcome());
        assertEquals("CIRCUIT_OPEN", controller.commitDetailed(b).reason());
        assertEquals(2, metric("intents", "consumed"));
        advance(60_000);
        controller.status(); // logical deadline reopens only, does not free any native permits
        assertEquals(0, metric("watchers", "activeTickets"));
        assertEquals(3, metric("gate", "active"));
        controller.response(a.evidenceId(), 200, List.of(), new byte[0], 0);
        assertEquals(1, metric("watchers", "circuits"), "late success cannot heal a timed-out probe");
    }

    @Test void healthGetExactNoQueryBodyPassesPauseCircuitButNeverHealsOrBypassesRulesAndBudget() {
        Limits limits = limits(0, new Circuit5xx(60_000, 1, 1000, 1), null, 2, true);
        open(policy(limits, List.of(rule("deny", Mode.BLOCK, "/blocked"))));
        Prepared first = prepare("GET", "/safe", "one");
        handoff(first);
        controller.response(first.evidenceId(), 503, List.of(), new byte[0], 0);
        controller.pause(true);
        Prepared health = prepare("GET", "/health", "one");
        handoff(health);
        assertEquals("probe_allowed", row(health).outcome());
        controller.response(health.evidenceId(), 200, List.of(), new byte[0], 0);
        assertEquals(1, metric("watchers", "circuits"));
        assertEquals("INTENT_BUDGET_EXCEEDED", controller.authorize(prepare("GET", "/health", "one")).reason());
        assertEquals("PAUSED", controller.authorize(prepare("HEAD", "/health", "other")).reason());
        assertEquals("PAUSED", controller.authorize(prepare("GET", "/health?", "other")).reason());
        assertEquals("PAUSED", controller.authorize(controller.prepare(request("GET", "/health", List.of(), new byte[]{1}, true, true))).reason());
        save(policy(limits, List.of(rule("health-block", Mode.BLOCK, "/health"))));
        assertEquals("RULE_BLOCK", controller.authorize(prepare("GET", "/health", "other")).reason());
    }

    @Test void healthProbeNeverBypassesHardScopeHeavyFanoutOrInvalidPolicy() {
        Limits limits = limits(10, null, null, 0, true);
        open(policy(limits, List.of()));
        Prepared health = prepare("GET", "/health", null);
        handoff(health);
        controller.response(health.evidenceId(), 200, List.of(), new byte[0], 11);
        controller.pause(true);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/health", null)).reason());
        GuardConfig noScope = new GuardConfig(2, List.of(), List.of(), List.of(), Mode.ALLOW, limits);
        save(noScope);
        assertEquals("SCOPE_NOT_ALLOWED", controller.authorize(prepare("GET", "/health", null)).reason());
        projects.failSave = true;
        assertThrows(IllegalStateException.class, () -> save(policy(limits, List.of())));
        assertEquals("PAUSED", controller.authorize(prepare("GET", "/health", null)).reason());
        assertEquals("POLICY_SAVE_UNCERTAIN", controller.status().get("guardState"));
    }

    @Test void offAndKnownUnselectedAreNoCaptureCountOnlyAndPauseIsPreservedAcrossOff() {
        GuardConfig base = policy(limits(0, null, null, 1, false), List.of());
        open(new GuardConfig(2, base.allowScope(), List.of(), List.of(), Mode.ALLOW, base.limits(), List.of(8080)));
        controller.pause(true);
        controller.recordListener(1, "127.0.0.1:8081");
        NativeMode unselected = controller.nativeMode(1);
        assertEquals(BypassKind.UNSELECTED_LISTENER, unselected.token().kind());
        assertTrue(controller.commitPassthrough(unselected.token()));
        controller.recordListener(2, "127.0.0.1:8080");
        assertNull(controller.nativeMode(2).token());
        assertEquals("LISTENER_UNVERIFIED", controller.nativeMode(3).rejection());
        assertTrue(controller.traffic().isEmpty());
        assertEquals(1L, controller.status().get("unguardedListenerCount"));
        controller.passthrough(true, "a", revision());
        assertEquals(false, controller.status().get("paused"));
        assertEquals(true, controller.status().get("operatorPaused"));
        assertEquals(BypassKind.OFF, controller.nativeMode(99).token().kind());
        assertTrue(controller.commitPassthrough(controller.nativeMode(99).token()));
        assertTrue(controller.traffic().isEmpty());
        assertEquals(0, metric("intents", "consumed"));
        controller.passthrough(false, "a", revision());
        assertEquals(true, controller.status().get("paused"));
        assertEquals("PAUSED_BY_OPERATOR", controller.status().get("guardState"));
        assertFalse(controller.commitPassthrough(unselected.token()));
        assertEquals(0, projects.saves.get());
    }

    @Test void listenerMappingsAndBypassTokensCannotCrossRevisionProjectOffCycleOrUncertainty() {
        GuardConfig base = policy(limits(0, null, null, 0, false), List.of());
        open(new GuardConfig(2, base.allowScope(), List.of(), List.of(), Mode.ALLOW, base.limits(), List.of(8080)));
        controller.recordListener(1, "localhost:8081");
        var old = controller.nativeMode(1).token();
        assertNotNull(old);
        controller.recordListener(2, "localhost:8081");
        save(controller.config());
        assertFalse(controller.commitPassthrough(old));
        assertEquals("LISTENER_UNVERIFIED", controller.nativeMode(2).rejection());
        assertFalse(controller.commitPassthrough(new PassthroughToken("a", revision(), BypassKind.UNSELECTED_LISTENER, 8081)));
        controller.recordListener(3, "localhost:8081");
        var beforeFailure = controller.nativeMode(3).token();
        projects.unavailable = true;
        assertFalse(controller.commitPassthrough(beforeFailure));
        projects.unavailable = false;
        assertEquals("PAUSED", controller.nativeMode(4).rejection());
        controller.refreshProject();
        assertFalse(controller.commitPassthrough(beforeFailure));
        assertEquals(true, controller.status().get("paused"));
    }

    @Test void strictV1MigrationIsMemoryOnlyPreservesExactLegacyRuleUntilExplicitHumanSave() {
        GuardConfig legacy = new GuardConfig(1, policy(limits(0, null, null, 0, false), List.of()).allowScope(), List.of(),
                List.of(new Rule("delete-string", "Block delete string (conservative)", true, Mode.BLOCK,
                        Condition.leaf(Field.ANY, Match.CONTAINS, "delete"))), Mode.ALLOW,
                new Limits(1000, 1000, Map.of(), 10, 10, 1000, 1000, 1000));
        String original = PolicyCodec.encodeLegacy(legacy);
        projects.document = original;
        openStored(legacy.limits(), 4096, 2048, 4096);
        assertEquals(2, controller.config().schemaVersion());
        assertEquals(0, controller.config().limits().perPathMaxResponseBytes());
        assertNull(controller.config().limits().circuit5xx());
        assertEquals(true, controller.migrationView().get("pending"));
        assertEquals(original, controller.migrationView().get("original"));
        controller.refreshProject(); controller.status(); controller.releaseAllOverlays("a", revision());
        assertEquals(original, projects.document);
        assertEquals(0, projects.saves.get());
        assertEquals("RULE_BLOCK", controller.authorize(prepare("GET", "/ui/deleteInfoBoardComnt.do", null)).reason());
        save(PolicyCodec.removeLegacyDeleteString(controller.config()));
        assertEquals(1, projects.saves.get());
        assertEquals(false, controller.migrationView().get("pending"));
        assertEquals(2, PolicyCodec.decode(projects.document).config().schemaVersion());
        handoff(prepare("GET", "/ui/deleteInfoBoardComnt.do", null));
    }

    @Test void invalidPolicyIsTypedNoCaptureAndHumanSaveDoesNotSilentlyResume() {
        projects.document = "{\"schemaVersion\":2}";
        openStored(limits(0, null, null, 0, false), 4096, 2048, 4096);
        assertEquals("PAUSED", controller.nativeMode(1).rejection());
        Prepared rejected = controller.prepareRejected("PAUSED");
        assertEquals("POLICY_INVALID", controller.denial(rejected, "PAUSED").guardState());
        assertThrows(IllegalStateException.class, () -> controller.passthrough(true, "a", revision()));
        assertEquals(0, projects.saves.get());
        save(policy(limits(0, null, null, 0, false), List.of()));
        assertEquals(true, controller.status().get("paused"));
        controller.pause(false);
        handoff(prepare("GET", "/safe", null));
    }

    @Test void sameProjectSaveOffAndDetectorDisableRetainOverlaysAndIntentDebt() {
        open(policy(limits(10, null, null, 1, false), List.of()));
        Prepared first = prepare("GET", "/large", "one");
        handoff(first);
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 11);
        String id = controller.overlays().getFirst().id();
        String original = projects.document;
        controller.passthrough(true, "a", revision());
        controller.passthrough(false, "a", revision());
        assertEquals(original, projects.document);
        save(policy(limits(0, null, null, 0, false), List.of()));
        assertEquals(id, controller.overlays().getFirst().id());
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/large", "one")).reason());
        save(policy(limits(0, null, null, 1, false), List.of()));
        controller.releaseAllOverlays("a", revision());
        assertEquals("INTENT_BUDGET_EXCEEDED", controller.authorize(prepare("GET", "/large", "one")).reason());
        controller.resetIntentBudgets("a", revision());
        handoff(prepare("GET", "/large", "one"));
    }

    @Test void rawHistoryIsHumanLocalResponseDiscoveryRemasksAllWatcherViewsAndStaleExports() throws Exception {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared first = prepare("GET", "/download/" + SECRET, null);
        handoff(first);
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 1);
        Prepared second = prepare("GET", "/download/" + SECRET, null);
        handoff(second);
        List<TrafficEntry> stale = List.of(row(second));
        List<Header> headers = List.of(new Header("Content-Type", "application/json"), new Header("X-Broker-Grant", SECRET));
        byte[] body = bytes("{\"grant\":\"" + SECRET + "\"}");
        controller.response(second.evidenceId(), 200, headers, body, 20, true, true);
        assertTrue(controller.rawResponse(second.evidenceId()).contains(SECRET));
        assertTrue(controller.rawUrl(second.evidenceId()).contains(SECRET));
        // Evidence uses same-entry fingerprints; watcher display refresh also covers older route
        // observations. A selected stale snapshot of THIS entry cannot undo response discovery.
        assertFalse(controller.exportJson(List.of(row(second))).contains(SECRET));
        assertFalse(controller.exportJson(stale).contains(SECRET));
        assertFalse(controller.exportHar(stale).contains(SECRET));
        assertFalse(controller.overlays().toString().contains(SECRET));
        assertFalse(controller.heavyCandidates().toString().contains(SECRET));
        assertEquals("", controller.heavyCandidates().getFirst().policyUrl());
        var incident = Json.MAPPER.readTree(controller.exportIncident(999_999, 1_000_001));
        assertTrue(incident.has("events"));
        assertFalse(incident.toString().contains(SECRET));
        assertEquals(20, row(second).responseBytes());
    }

    @Test void actualBytesSurviveCaptureOmissionRawLabelsAreHonestAndExportsOmitPrefix() {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared p = prepare("GET", "/large", null);
        handoff(p);
        controller.response(p.evidenceId(), 200, List.of(new Header("Content-Type", "application/json")), bytes("{\"grant\":\"partial"),
                6L * 1_048_576, true, false);
        assertEquals(6L * 1_048_576, row(p).responseBytes());
        assertTrue(row(p).responseCapture().bodyOmitted());
        assertFalse(controller.exportJson(controller.traffic()).contains("partial"));
        assertTrue(controller.rawResponse(p.evidenceId()).contains("partial"));
        assertEquals(false, controller.rawCaptureInfo(p.evidenceId()).get("responseBodyComplete"));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/large", null)).reason());
    }

    @Test void projectEpochDisposesRawTicketsBudgetsAndListenersLateOldResponseCannotAffectNewWatcher() {
        open(policy(limits(10, new Circuit5xx(60_000, 1, 1000, 1), null, 1, false), List.of()));
        Prepared old = prepare("GET", "/old", "one");
        handoff(old);
        assertNotNull(controller.rawRequest(old.evidenceId()));
        projects.id = "b";
        controller.refreshProject();
        assertNull(controller.rawRequest(old.evidenceId()));
        assertEquals(0, metric("intents", "consumed"));
        assertEquals(0, metric("watchers", "activeTickets"));
        assertEquals(1, metric("gate", "active"));
        Prepared fresh = prepare("GET", "/fresh", "one");
        handoff(fresh);
        controller.response(old.evidenceId(), 503, List.of(new Header("X-Broker-Grant", "owned.test")), new byte[0], 1000);
        assertEquals(0, metric("watchers", "circuits"));
        assertTrue(controller.overlays().isEmpty());
        assertNull(controller.rawResponse(old.evidenceId()));
        controller.response(fresh.evidenceId(), 200, List.of(), new byte[0], 1);
        assertEquals("owned.test", controller.heavyCandidates().getFirst().host());
    }

    @Test void runtimeDisplayReadDetectsProjectUncertaintyBeforeUiRefreshAndDisposesEpoch() {
        open(policy(limits(10, null, null, 1, false), List.of()));
        Prepared p = prepare("GET", "/large", "one");
        handoff(p);
        controller.response(p.evidenceId(), 200, List.of(), new byte[0], 11);
        assertFalse(controller.overlays().isEmpty());
        projects.id = "b";
        assertTrue(controller.overlays().isEmpty());
        assertTrue(controller.heavyCandidates().isEmpty());
        assertNull(controller.rawRequest(p.evidenceId()));
        assertEquals(0, metric("intents", "consumed"));
        assertEquals(1, metric("gate", "active"));
        assertEquals("PROJECT_UNVERIFIED", controller.status().get("guardState"));
    }

    @Test void clearEvidenceRemovesIncidentsAndRawButNeverProtectionBudgetOrNativePermit() {
        open(policy(limits(10, null, null, 1, false), List.of()));
        Prepared p = prepare("GET", "/large", "one");
        handoff(p);
        controller.response(p.evidenceId(), 200, List.of(), new byte[0], 11);
        controller.clearEvidence();
        assertTrue(controller.traffic().isEmpty());
        assertNull(controller.rawRequest(p.evidenceId()));
        assertTrue(controller.heavyCandidates().isEmpty());
        assertFalse(controller.overlays().isEmpty());
        assertEquals(1, metric("intents", "consumed"));
        assertEquals(1, metric("gate", "active"));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/large", "other")).reason());
    }

    @ParameterizedTest @ValueSource(strings = {"/c/;/main.do", "/c/%2e/main.do", "/c/%252e/main.do", "/c/%zz/main.do", "/c/../main.do", "/c/%252f/main.do", "/ui/deleteInfoBoardComnt.do"})
    void actualDestinationAllPathsAndFuzzedHostAreForwardedUnchanged(String path) {
        open(policy(limits(0, null, null, 0, false), GuardConfig.defaults().rules()));
        List<Header> headers = List.of(new Header("Host", "synthetic.invalid"), new Header("Authorization", "Bearer " + SECRET));
        RequestData request = request("GET", path, headers, new byte[0], true, true);
        Prepared p = controller.prepare(request);
        handoff(p);
        assertEquals(headers, request.headers());
        assertEquals("https://owned.test" + path, request.url());
        assertTrue(controller.rawRequest(p.evidenceId()).contains("Host: synthetic.invalid"));
        if (path.contains("%zz")) {
            assertTrue(row(p).inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
            assertTrue(controller.exportJson(controller.traffic()).contains("PATH_INTERPRETATION_INCOMPLETE"));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"charset", "binary", "multipart", "json", "encoding", "body-incomplete", "headers-incomplete"})
    void optionalInspectionFailuresAreWarningsNotScopeOrContentDenials(String kind) {
        var bodyRule = new Rule("explicit-body", "Explicit body condition", true, Mode.BLOCK, Condition.leaf(Field.BODY, Match.CONTAINS, "dangerous"));
        var jsonRule = new Rule("explicit-json", "Explicit JSON condition", true, Mode.BLOCK, Condition.leaf(Field.JSON, Match.CONTAINS, "dangerous"));
        open(policy(limits(0, null, null, 0, false), List.of(bodyRule, jsonRule)));
        List<Header> headers = switch (kind) {
            case "charset" -> List.of(new Header("Content-Type", "text/plain; charset=unsupported"));
            case "binary" -> List.of(new Header("Content-Type", "application/octet-stream"));
            case "multipart" -> List.of(new Header("Content-Type", "multipart/form-data; boundary=x"));
            case "encoding" -> List.of(new Header("Content-Type", "application/json"), new Header("Content-Encoding", "gzip"));
            default -> List.of(new Header("Content-Type", "application/json"));
        };
        RequestData request = request("POST", "/safe", headers, bytes(kind.equals("json") ? "{" : "safe"),
                !kind.equals("headers-incomplete"), !kind.equals("body-incomplete"));
        Prepared p = controller.prepare(request);
        handoff(p);
        assertFalse(row(p).inspectionWarnings().isEmpty());
        assertArrayEquals(bytes(kind.equals("json") ? "{" : "safe"), request.body());
        assertFalse(controller.rawCaptureInfo(p.evidenceId()).isEmpty());
    }

    @Test void explicitInspectableRulesStillBlockAndDeleteMethodIsRetainedWithoutBroadDeleteString() {
        open(policy(limits(0, null, null, 0, false), List.of(new Rule("body", "Explicit body", true, Mode.BLOCK,
                Condition.leaf(Field.BODY, Match.EXACT, "dangerous")), GuardConfig.defaults().rules().getFirst())));
        assertEquals("RULE_BLOCK", controller.authorize(controller.prepare(request("POST", "/safe",
                List.of(new Header("Content-Type", "text/plain")), bytes("dangerous"), true, true))).reason());
        assertEquals("RULE_BLOCK", controller.authorize(prepare("DELETE", "/safe", null)).reason());
        handoff(prepare("GET", "/ui/deleteInfoBoardComnt.do", null));
    }

    @Test void ticketWatcherAndIntentCapacitiesFailClosedWithoutLiveEvictionAndNoBudgetSpend() {
        GuardConfig config = policy(limits(0, null, null, 20, false), List.of());
        projects.document = PolicyCodec.encode(config);
        openStored(config.limits(), 1, 2048, 1);
        Prepared first = prepare("GET", "/one", "one");
        handoff(first);
        Prepared second = prepare("GET", "/two", "one");
        authorize(second);
        assertEquals("RESPONSE_WATCHER_CAPACITY", controller.commitDetailed(second).reason());
        assertEquals(1, metric("intents", "consumed"));
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 0);
        assertEquals("INTENT_BUDGET_CAPACITY", controller.authorize(prepare("GET", "/two", "other")).reason());
        handoff(prepare("GET", "/two", "one"));
        advance(60_000);
        assertEquals(0, ((Number) controller.status().get("watcherTickets")).intValue());
        assertEquals(3, metric("gate", "active"));
        assertEquals(2, metric("intents", "consumed"));
    }

    @Test void explicitRuntimeActionsAreProjectRevisionCasAndNeverSavePolicy() {
        open(policy(limits(10, null, null, 1, false), List.of()));
        Prepared p = prepare("GET", "/large", "one");
        handoff(p);
        controller.response(p.evidenceId(), 503, List.of(), new byte[0], 11);
        String overlay = controller.overlays().getFirst().id();
        String candidate = controller.heavyCandidates().getFirst().id();
        long stale = revision();
        controller.pause(true);
        assertThrows(IllegalStateException.class, () -> controller.releaseOverlay(overlay, "a", stale));
        assertThrows(IllegalStateException.class, () -> controller.ignoreCandidate(candidate, "a", stale));
        assertThrows(IllegalStateException.class, () -> controller.resetIntentBudgets("a", stale));
        assertFalse(controller.overlays().isEmpty());
        assertTrue(controller.ignoreCandidate(candidate, "a", revision()));
        assertTrue(controller.heavyCandidates().isEmpty());
        assertTrue(controller.releaseOverlay(overlay, "a", revision()));
        controller.resetIntentBudgets("a", revision());
        assertEquals(0, metric("intents", "consumed"));
        assertEquals(0, projects.saves.get());
    }

    @Test void preparedNeverRetainsRawAttributionOrMessagesAndForgedPreparedCannotCommit() {
        open(policy(limits(0, null, null, 20, false), List.of()));
        RequestData request = request("POST", "/safe", List.of(new Header("Authorization", "Bearer " + SECRET),
                new Header("X-Cairn-Intent", SECRET), new Header("X-Cairn-Run", SECRET)), bytes("{\"grant\":\"" + SECRET + "\"}"), true, true);
        Prepared p = controller.prepare(request);
        assertFalse(p.toString().contains(SECRET));
        assertFalse(p.attribution().toString().contains(SECRET));
        assertNotEquals(SECRET, p.attribution().intentId());
        assertEquals(64, p.attribution().intentId().length());
        assertFalse(controller.commitDetailed(p).allowed(), "authorization cannot be skipped");
        Prepared forged = new Prepared("fake", "a", revision(), "owned.test", new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()));
        assertFalse(controller.commit(forged));
        Prepared legacyBlock = new Prepared(p.evidenceId(), "a", revision(), "blocked.invalid", Decision.blocked("RULE_BLOCK"));
        assertEquals("RULE_BLOCK", controller.authorize(legacyBlock).reason(), "old BLOCK-only projections still deny categorically");
        controller.reject(legacyBlock, "SHUTDOWN");
        assertEquals("FINAL_CHECK_REJECTED", row(p).reason(), "foreign projections cannot mutate an owned evidence ID");
        assertEquals(0, metric("intents", "consumed"));
    }

    private Prepared prepare(String method, String path, String intent) {
        return controller.prepare(request(method, path, intent == null ? List.of() : List.of(new Header("X-Cairn-Intent", intent)), new byte[0], true, true));
    }
    private void authorize(Prepared p) {
        Admission admission = controller.authorize(p);
        assertTrue(admission.allowed(), admission.reason());
        assertNotNull(admission.permit());
        permits.add(admission.permit());
    }
    private void handoff(Prepared p) {
        authorize(p);
        CommitResult result = controller.commitDetailed(p);
        assertTrue(result.allowed(), result.reason());
    }
    private void open(GuardConfig config) {
        projects.document = PolicyCodec.encode(config);
        openStored(config.limits(), 4096, 2048, 4096);
    }
    private void openStored(Limits limits, int ticketCapacity, int pathCapacity, int intentCapacity) {
        watcher = new ResponseWatcher(limits, nano::get, () -> 1_000_000 + TimeUnit.NANOSECONDS.toMillis(nano.get()),
                1024, pathCapacity, 1024, 4096, 8192);
        controller = new GuardController(projects, watcher, new IntentBudget(intentCapacity), new RateGate(limits),
                new ListenerRegistry(nano::get, 4096, TimeUnit.SECONDS.toNanos(30)), nano::get, ticketCapacity);
    }
    private void save(GuardConfig config) { controller.updateConfig(config, projects.id, revision()); }
    private long revision() { return ((Number) controller.status().get("revision")).longValue(); }
    private long metric(String section, String key) { return ((Number) ((Map<?, ?>) controller.status().get(section)).get(key)).longValue(); }
    private TrafficEntry row(Prepared p) { return controller.traffic().stream().filter(row -> row.id().equals(p.evidenceId())).findFirst().orElseThrow(); }
    private void advance(long millis) { nano.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static RequestData request(String method, String path, List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        return new RequestData(method, "https://owned.test" + path, "owned.test", 443, true, headers, body, headersComplete, bodyComplete);
    }
    private static GuardConfig policy(Limits limits, List<Rule> rules) {
        return new GuardConfig(2, List.of(new ScopeEntry(true, "owned.test", "https", 443, "")), List.of(), rules, Mode.ALLOW, limits);
    }
    private static Rule rule(String id, Mode mode, String path) { return new Rule(id, id, true, mode, Condition.leaf(Field.PATH, Match.EXACT, path)); }
    private static Limits limits(long bytes, Circuit5xx circuit, Fanout fanout, int budget, boolean probes) {
        return new Limits(1000, 1000, Map.of(), 100, 100, 1000, 1000, 60_000,
                bytes, 60_000, circuit, fanout, budget, probes, probes ? List.of(new ProbePath("https", "owned.test", 443, "/health")) : List.of(), List.of());
    }
    private static final class Projects implements ProjectAccess {
        String id = "a";
        String document;
        boolean unavailable;
        boolean failSave;
        final AtomicInteger saves = new AtomicInteger();
        @Override public Ref current() { if (unavailable) throw new IllegalStateException(SECRET); return new Ref(id, "Synthetic project"); }
        @Override public String load() { return document; }
        @Override public void save(String value) { if (failSave) throw new IllegalStateException(SECRET); saves.incrementAndGet(); document = value; }
    }
}
