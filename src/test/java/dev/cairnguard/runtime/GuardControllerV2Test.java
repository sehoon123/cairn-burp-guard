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

    @Test void enforcingOmissionDebtIsReportedAsCapacityOnlyWhileConfiguredAndProtectionIsOn() {
        GuardConfig warn = policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN), 20, false), List.of());
        projects.document = PolicyCodec.encode(warn);
        openStored(warn.limits(), 4096, 2, 4096);
        for (String path : List.of("/a", "/b", "/c")) {
            Prepared p = prepare("GET", path, "one");
            handoff(p);
            controller.response(p.evidenceId(), 200, List.of(), new byte[0], 0);
        }
        assertEquals("PROTECTED", controller.status().get("guardState"));
        assertEquals(60_000, metric("watchers", "fanoutHistoryRemainingMillis"));
        for (FanoutAction action : List.of(FanoutAction.BLOCK, FanoutAction.PAUSE)) {
            save(policy(limits(0, null, new Fanout(60_000, 10, action), 20, false), List.of()));
            assertEquals("CAPACITY", controller.status().get("guardState"), action.name());
            assertEquals(true, watchers().get("fanoutHistoryEnforcing"));
            assertEquals("RESPONSE_WATCHER_CAPACITY", controller.authorize(prepare("GET", "/a", "one")).reason());
        }
        save(warn);
        assertEquals("PROTECTED", controller.status().get("guardState"), "WARN retains debt without a gate");
        assertEquals(60_000, metric("watchers", "fanoutHistoryRemainingMillis"));
        save(policy(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK), 20, false), List.of()));
        assertEquals("CAPACITY", controller.status().get("guardState"), "re-enabled before the deadline");
        controller.passthrough(true, "a", revision());
        assertEquals("PROTECTED", controller.status().get("guardState"), "OFF has no active watcher gate");
        assertEquals(true, watchers().get("fanoutHistoryEnforcing"), "watcher-local configuration diagnostic");
        controller.passthrough(false, "a", revision());
        assertEquals("CAPACITY", controller.status().get("guardState"));
        advance(59_999);
        assertEquals("CAPACITY", controller.status().get("guardState"));
        advance(1);
        assertEquals("PROTECTED", controller.status().get("guardState"));
        assertEquals(0, metric("watchers", "fanoutHistoryRemainingMillis"));
        assertEquals(3, metric("intents", "consumed"), "rejections spent no budget");
    }

    @Test void globalOmissionCapacityStatusOutranksPerHostCircuitOnlyWhileEnforcing() {
        Circuit5xx circuit = new Circuit5xx(60_000, 1, 60_000, 1);
        GuardConfig warn = policy(limits(0, circuit, new Fanout(60_000, 10, FanoutAction.WARN), 20, false), List.of());
        projects.document = PolicyCodec.encode(warn);
        openStored(warn.limits(), 4096, 2, 4096);
        for (String path : List.of("/a", "/b", "/c")) {
            Prepared p = prepare("GET", path, "one");
            handoff(p);
            controller.response(p.evidenceId(), path.equals("/c") ? 503 : 200, List.of(), new byte[0], 0);
        }
        assertEquals(1, metric("watchers", "circuits"));
        assertEquals("CIRCUIT_OPEN", controller.status().get("guardState"));
        save(policy(limits(0, circuit, new Fanout(60_000, 10, FanoutAction.BLOCK), 20, false), List.of()));
        assertEquals("CAPACITY", controller.status().get("guardState"));
        assertEquals("CIRCUIT_OPEN", controller.authorize(prepare("GET", "/a", "one")).reason(), "per-request gate order unchanged");
    }

    private static Limits withCircuit(Limits l, Circuit5xx circuit, List<ProbePath> exceptions) {
        return new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), circuit,
                l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(), exceptions);
    }

    @Test void exactCircuitExceptionPassesAnOpenCircuitButScopeRulesAskAndPauseStillApply() {
        List<ProbePath> exceptions = List.of(new ProbePath("https", "owned.test", 443, "/expected-error"),
                new ProbePath("https", "owned.test", 443, "/blocked-error"));
        Limits on = withCircuit(limits(0, null, null, 0, false), new Circuit5xx(60_000, 1, 60_000, 1), exceptions);
        open(policy(on, List.of(rule("block", Mode.BLOCK, "/blocked-error"), rule("ask", Mode.ASK, "/ask-error"))));
        Prepared failing = prepare("GET", "/x", null);
        handoff(failing);
        controller.response(failing.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals("CIRCUIT_OPEN", controller.status().get("guardState"));
        assertEquals("CIRCUIT_OPEN", controller.authorize(prepare("GET", "/y", null)).reason());
        handoff(prepare("POST", "/expected-error", null));
        assertEquals("RULE_BLOCK", controller.authorize(prepare("GET", "/blocked-error", null)).reason(), "ordinary rules still win");
        controller.pause(true);
        assertEquals("PAUSED", controller.authorize(prepare("GET", "/expected-error", null)).reason());
        assertEquals(1, metric("watchers", "circuits"), "exception traffic never heals the circuit");
    }

    @Test void explicitCircuitOffSaveImmediatelyEndsCircuitGatingButKeepsActiveNativePermits() {
        Limits on = withCircuit(limits(0, null, null, 0, false), new Circuit5xx(60_000, 1, 60_000, 1), List.of());
        open(policy(on, List.of()));
        Prepared failing = prepare("GET", "/x", null);
        handoff(failing);
        Prepared outstanding = prepare("GET", "/slow", null);
        handoff(outstanding); // physical permit held
        controller.response(failing.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals("CIRCUIT_OPEN", controller.status().get("guardState"));
        long active = metric("gate", "active");
        assertEquals(2, active, "both synthetic native permits are still held by the adapter");
        save(policy(withCircuit(on, null, List.of()), List.of()));
        assertEquals("PROTECTED", controller.status().get("guardState"));
        assertEquals(0, metric("watchers", "circuits"));
        assertEquals(active, metric("gate", "active"), "OFF is not a native permit reset");
        handoff(prepare("GET", "/x", null));
        save(policy(on, List.of())); // OFF -> ON: fresh generation, the old flight cannot trip it
        controller.response(outstanding.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals(0, metric("watchers", "circuits"));
        assertEquals("PROTECTED", controller.status().get("guardState"));
        assertTrue(GuardConfig.defaults().limits().circuit5xx() == null, "fresh profiles have no circuit");
    }

    private static Limits detectors(Limits l, boolean heavy, Fanout fanout, List<ProbePath> fanoutExceptions) {
        return new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), l.circuit5xx(),
                fanout, l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(),
                l.circuit5xxExceptions(), heavy, fanoutExceptions);
    }

    @Test void selectiveDetectorSavesEndOnlyTheirOwnGatingAndNeverResumeAnOperatorPauseOrReleasePermits() {
        Limits base = limits(10, null, new Fanout(60_000, 2, FanoutAction.PAUSE), 0, false);
        open(policy(base, List.of()));
        Prepared large = prepare("GET", "/large", null);
        handoff(large);
        controller.response(large.evidenceId(), 200, List.of(), new byte[0], 11); // heavy overlay
        assertThrows(AssertionError.class, () -> handoff(prepare("GET", "/second", null))); // fan-out PAUSE
        long active = metric("gate", "active");
        assertEquals("OVERLAY_BLOCK", controller.status().get("guardState"));
        save(policy(detectors(base, true, new Fanout(60_000, 2, FanoutAction.WARN), List.of()), List.of()));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/large", null)).reason(), "heavy is independent");
        handoff(prepare("GET", "/third", null));
        controller.pause(true);
        save(policy(detectors(base, false, null, List.of(new ProbePath("https", "owned.test", 443, "/batch"))), List.of()));
        assertEquals("PAUSED", controller.authorize(prepare("GET", "/large", null)).reason(), "operator pause is never resumed by detector saves");
        controller.pause(false);
        handoff(prepare("GET", "/large", null));
        assertEquals(0, metric("watchers", "overlays"));
        assertTrue(metric("gate", "active") >= active, "no native permit is released by detector changes");
    }

    @Test void overlayExceptionReviewPersistsOnlyTheSelectedKindRelativeToTheCurrentPolicy() {
        for (String kind : List.of("HEAVY", "CIRCUIT", "FANOUT")) {
            Limits base = switch (kind) {
                case "HEAVY" -> limits(10, null, null, 0, false);
                case "CIRCUIT" -> withCircuit(limits(0, null, null, 0, false), new Circuit5xx(60_000, 1, 60_000, 1), List.of());
                default -> limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK), 0, false);
            };
            open(policy(base, List.of(rule("keep", Mode.BLOCK, "/never"))));
            String path = switch (kind) { case "HEAVY" -> "/large"; case "CIRCUIT" -> "/x"; default -> "/two"; };
            if (kind.equals("FANOUT")) {
                Prepared one = prepare("GET", "/one", null); handoff(one); controller.response(one.evidenceId(), 200, List.of(), new byte[0], 0);
                Prepared two = prepare("GET", "/two", null); authorize(two);
                assertFalse(controller.commitDetailed(two).allowed());
            } else {
                Prepared p = prepare("GET", path, null); handoff(p);
                controller.response(p.evidenceId(), kind.equals("CIRCUIT") ? 503 : 200, List.of(), new byte[0], 11);
            }
            var overlay = controller.humanOverlays().getFirst();
            assertEquals(kind.equals("HEAVY") ? path : "", overlay.path(), "host-scoped rows never invent a path");
            var exception = overlay.exception();
            assertEquals(kind, exception.kind()); assertEquals(path, exception.path()); assertNull(exception.unavailable());
            assertEquals("OverlaySource[opaque]", exception.source().toString());
            GuardConfig before = controller.config();
            GuardConfig draft = dev.cairnguard.ui.GuardUiAccess.withDetectorException(before, kind, "https", "owned.test", 443, path);
            // forged: an unrelated extra change is refused, nothing written
            GuardConfig unrelated = new GuardConfig(2, draft.allowScope(), draft.blockScope(), List.of(), draft.defaultMode(), draft.limits(), draft.guardListenerPorts());
            int saves = projects.saves.get();
            assertThrows(IllegalStateException.class, () -> controller.updateConfig(unrelated, "a", revision(), exception.source()));
            // type substitution: another kind's change with this token
            String other = kind.equals("HEAVY") ? "CIRCUIT" : "HEAVY";
            GuardConfig substituted = dev.cairnguard.ui.GuardUiAccess.withDetectorException(before, other, "https", "owned.test", 443, path);
            assertThrows(IllegalStateException.class, () -> controller.updateConfig(substituted, "a", revision(), exception.source()));
            assertEquals(saves, projects.saves.get());
            assertTrue(controller.overlayExceptionCurrent(exception.source()));
            controller.updateConfig(draft, "a", revision(), exception.source());
            assertEquals(saves + 1, projects.saves.get());
            Limits after = controller.config().limits();
            switch (kind) {
                case "HEAVY" -> assertEquals(List.of(new PathByteLimit("https", "owned.test", 443, "/large", 0)), after.heavyPathLimits());
                case "CIRCUIT" -> assertEquals(List.of(new ProbePath("https", "owned.test", 443, "/x")), after.circuit5xxExceptions());
                default -> assertEquals(List.of(new ProbePath("https", "owned.test", 443, "/two")), after.fanoutExceptions());
            }
            assertEquals(before.rules(), controller.config().rules());
            assertEquals(before.limits().circuit5xx(), after.circuit5xx(), "a disabled/enabled detector is never toggled");
            assertEquals(before.limits().fanout(), after.fanout());
            assertEquals(before.limits().heavyResponseEnabled(), after.heavyResponseEnabled());
            assertEquals(1, metric("watchers", "overlays"), "saving an exception is not a release");
            var done = controller.humanOverlays().getFirst().exception();
            assertEquals("ALREADY_EXCEPTED", done.unavailable(), kind + ": the retained overlay is conditional, the route is already excepted");
            assertNull(done.source(), "no authority to re-save the same exception");
            controller.close(); controller = null;
        }
    }

    @Test void withDetectorExceptionReplacesInPlaceNeverReordersAndNeverDuplicates() {
        GuardConfig base = policy(limits(10, null, null, 0, false), List.of());
        Limits l = base.limits();
        PathByteLimit first = new PathByteLimit("https", "owned.test", 443, "/large", 7), second = new PathByteLimit("https", "owned.test", 443, "/other", 9);
        GuardConfig two = new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), null, null, 0,
                        false, List.of(), List.of(first, second), List.of(), true, List.of()));
        GuardConfig once = dev.cairnguard.ui.GuardUiAccess.withDetectorException(two, "HEAVY", "https", "OWNED.test.", 443, "/large");
        assertEquals(List.of(new PathByteLimit("https", "OWNED.test.", 443, "/large", 0), second), once.limits().heavyPathLimits(),
                "an existing positive entry is replaced at the same position");
        GuardConfig again = dev.cairnguard.ui.GuardUiAccess.withDetectorException(once, "HEAVY", "https", "owned.test", 443, "/large");
        assertEquals(once, again, "an already excepted route is not reordered, re-added or rewritten");
        GuardConfig zeroFirst = new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), null, null, 0,
                        false, List.of(), List.of(new PathByteLimit("https", "owned.test", 443, "/large", 0), second), List.of(), true, List.of()));
        assertEquals(zeroFirst, dev.cairnguard.ui.GuardUiAccess.withDetectorException(zeroFirst, "HEAVY", "https", "owned.test", 443, "/large"),
                "an existing exception that is not last stays exactly where it is");
    }

    @Test void alreadyExceptedHeavyRouteGivesNoAuthorityAndNoMutationEvenWithSeveralEntries() {
        GuardConfig base = policy(limits(10, null, null, 0, false), List.of());
        Limits l = base.limits();
        open(new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), null, null, 0,
                        false, List.of(), List.of(new PathByteLimit("https", "owned.test", 443, "/large", 7)), List.of(), true, List.of()),
                base.guardListenerPorts()));
        Prepared p = prepare("GET", "/large", null); handoff(p);
        controller.response(p.evidenceId(), 200, List.of(), new byte[0], 11);
        var exception = controller.humanOverlays().getFirst().exception();
        assertNull(exception.unavailable());
        GuardConfig draft = dev.cairnguard.ui.GuardUiAccess.withDetectorException(controller.config(), "HEAVY", "https", "owned.test", 443, "/large");
        controller.updateConfig(draft, "a", revision(), exception.source());
        long revision = revision(); int saves = projects.saves.get();
        var after = controller.humanOverlays().getFirst().exception();
        assertEquals("ALREADY_EXCEPTED", after.unavailable());
        assertNull(after.source());
        assertEquals(revision, revision(), "reviewing never bumps the revision");
        assertEquals(saves, projects.saves.get());
        assertEquals(1, metric("watchers", "overlays"));
    }

    @Test void clearInvalidatesJsonHarAndIncidentSnapshotsButUnrelatedRowsAndLaterUpdatesDoNot() throws Exception {
        open(policy(limits(10, null, null, 0, false), List.of()));
        // never answered, so it is in no event/top row of the incident either (an incident USES every row's original)
        Prepared unrelated = prepare("GET", "/unrelated", null); handoff(unrelated);
        Prepared used = prepare("GET", "/large", null); handoff(used);
        controller.response(used.evidenceId(), 200, List.of(new Header("X-Original", "kept")), bytes("first"), 11);
        var json = controller.humanExport(List.of(used.evidenceId()), false);
        var har = controller.humanExport(List.of(used.evidenceId()), true);
        var incident = controller.humanIncident(999_999, 1_000_001);
        byte[] before = json.serialize();
        assertTrue(new String(incident.serialize(), StandardCharsets.UTF_8).contains("/large"));
        for (var export : List.of(json, har, incident)) assertTrue(controller.humanExportCurrent(export));
        // an ordinary later response update neither cancels the export nor injects newer data into the frozen snapshot
        controller.response(used.evidenceId(), 200, List.of(new Header("X-Original", "newer")), bytes("later"), 11);
        for (var export : List.of(json, har, incident)) assertTrue(controller.humanExportCurrent(export), "later update");
        assertArrayEquals(before, json.serialize(), "the frozen snapshot is unchanged");
        // many unrelated captures: nothing is evicted (no quota), every original and export stays valid
        for (int i = 0; i < 2100; i++) controller.prepareRejected("CAPTURE_FAILED");
        assertEquals(Boolean.TRUE, controller.rawCaptureInfo(unrelated.evidenceId()).get("available"), "no quota eviction");
        assertEquals(Boolean.TRUE, controller.rawCaptureInfo(used.evidenceId()).get("available"));
        for (var export : List.of(json, har, incident)) assertTrue(controller.humanExportCurrent(export), "unrelated captures");
        // an explicit clear releases the used original and must fail the final predicate
        controller.clearEvidence();
        assertEquals(Boolean.FALSE, controller.rawCaptureInfo(used.evidenceId()).get("available"));
        for (var export : List.of(json, har, incident)) assertFalse(controller.humanExportCurrent(export), "clear");
        // a fresh snapshot taken after the clear is independent of it and is valid
        controller.prepareRejected("CAPTURE_FAILED");
        var late = controller.humanExport(List.of(controller.traffic().getFirst().id()), false);
        assertTrue(controller.humanExportCurrent(late));
    }

    @Test void staleReleasedClearedOrForeignOverlayAuthorityWritesNothing() {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared p = prepare("GET", "/large", null); handoff(p);
        controller.response(p.evidenceId(), 200, List.of(), new byte[0], 11);
        var exception = controller.humanOverlays().getFirst().exception();
        GuardConfig draft = dev.cairnguard.ui.GuardUiAccess.withDetectorException(controller.config(), "HEAVY", "https", "owned.test", 443, "/large");
        int saves = projects.saves.get();
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(draft, "a", revision(), (dev.cairnguard.ui.GuardUiAccess.OverlaySource) null));
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(draft, "a", revision(), new dev.cairnguard.ui.GuardUiAccess.OverlaySource() {}));
        controller.releaseAllOverlays("a", revision());
        assertFalse(controller.overlayExceptionCurrent(exception.source()), "released overlay");
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(draft, "a", revision(), exception.source()));
        Prepared again = prepare("GET", "/large", null); handoff(again);
        controller.response(again.evidenceId(), 200, List.of(), new byte[0], 11);
        var fresh = controller.humanOverlays().getFirst().exception();
        controller.clearEvidence();
        assertFalse(controller.overlayExceptionCurrent(fresh.source()), "raw clear");
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(draft, "a", revision(), fresh.source()));
        assertEquals(saves, projects.saves.get());
        assertEquals("ORIGINAL_UNAVAILABLE", controller.humanOverlays().getFirst().unavailable());
    }

    @Test void overlayExceptionIsUnavailableForAmbiguousRoutesFullTablesAndTheCapacityFence() {
        List<ProbePath> sixteen = new java.util.ArrayList<>();
        for (int i = 0; i < 16; i++) sixteen.add(new ProbePath("https", "owned.test", 443, "/e/" + i));
        open(policy(withCircuit(limits(0, null, null, 0, false), new Circuit5xx(60_000, 1, 60_000, 1), sixteen), List.of()));
        Prepared p = prepare("GET", "/x", null); handoff(p);
        controller.response(p.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals("EXCEPTION_TABLE_FULL", controller.humanOverlays().getFirst().exception().unavailable());
        assertNull(controller.humanOverlays().getFirst().exception().source());
        controller.close();
        open(policy(withCircuit(limits(0, null, null, 0, false), new Circuit5xx(60_000, 1, 60_000, 1), List.of()), List.of()));
        Prepared encoded = controller.prepare(new RequestData("GET", "https://owned.test/c/%2c", "owned.test", 443, true, List.of(), new byte[0], true, true, "/c/%2c"));
        handoff(encoded);
        controller.response(encoded.evidenceId(), 503, List.of(), new byte[0], 0);
        assertEquals("ENCODED_OR_AMBIGUOUS_ROUTE", controller.humanOverlays().getFirst().exception().unavailable());
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

    @Test void responseDiscoveryNeverRemasksWatcherViewsAndStaleSelectionsExportTheCurrentOriginalRow() throws Exception {
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
        assertTrue(controller.exportJson(List.of(row(second))).contains(SECRET));
        assertTrue(controller.exportJson(stale).contains("X-Broker-Grant"), "a stale seal exports the current retained row");
        assertTrue(controller.exportHar(stale).contains("X-Broker-Grant"));
        assertTrue(controller.overlays().toString().contains(SECRET));
        assertTrue(controller.heavyCandidates().toString().contains(SECRET));
        assertEquals("https://owned.test/download/" + SECRET, controller.heavyCandidates().getFirst().policyUrl());
        var incident = Json.MAPPER.readTree(controller.exportIncident(999_999, 1_000_001));
        assertTrue(incident.has("events"));
        assertTrue(incident.toString().contains(SECRET));
        assertEquals(20, row(second).responseBytes());
    }

    // ---- 0.2.0: human originals via opaque source references; safe projections stay masked ----
    @Test void humanCandidateOverlayAndExportsUseOriginalsAndSafeViewsAreOriginalToo() throws Exception {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared first = prepare("GET", "/download/" + SECRET + "?q=1", null);
        handoff(first);
        controller.response(first.evidenceId(), 200, List.of(new Header("X-Broker-Grant", SECRET), new Header("Set-Cookie", "a=1"),
                new Header("Set-Cookie", "b=2")), new byte[]{0, (byte) 0xff, 'x'}, 20, true, true);
        // machine projections are original too; counters/status stay payload-free
        assertTrue(controller.heavyCandidates().toString().contains(SECRET));
        assertTrue(controller.overlays().toString().contains(SECRET));
        assertTrue(controller.exportIncident(999_999, 1_000_001).contains(SECRET));
        assertFalse(controller.status().toString().contains(SECRET));
        // human projections use the retained original actual-service route
        var candidate = controller.humanCandidates().getFirst();
        assertEquals("owned.test", candidate.host());
        assertEquals("/download/" + SECRET, candidate.path(), "no query in the route identity");
        assertEquals("https://owned.test/download/" + SECRET, candidate.ruleUrl());
        assertEquals("/download/" + SECRET, candidate.limitPath());
        assertNull(candidate.ruleUnavailable());
        assertNotNull(candidate.source());
        assertEquals("CandidateSource[opaque]", candidate.source().toString());
        var overlay = controller.humanOverlays().getFirst();
        assertEquals("owned.test", overlay.host());
        assertEquals("/download/" + SECRET, overlay.path());
        dev.cairnguard.ui.GuardUiAccess.HumanExport json = controller.humanExport(List.of(first.evidenceId()), false);
        String text = new String(json.serialize(), StandardCharsets.UTF_8);
        assertTrue(text.contains("\"cairn-human-inspection\""));
        assertTrue(text.contains("HUMAN_ORIGINAL"));
        assertTrue(text.contains(SECRET), "explicit human export is plaintext");
        var tree = Json.MAPPER.readTree(text);
        var response = tree.at("/entries/0/original/response");
        assertArrayEquals(new byte[]{0, (byte) 0xff, 'x'}, java.util.Base64.getDecoder().decode(response.at("/body/base64").asText()));
        assertEquals("BINARY_OR_UNSUPPORTED", response.at("/body/encoding").asText());
        assertEquals("a=1", response.at("/headers/1/value").asText());
        assertEquals("b=2", response.at("/headers/2/value").asText(), "duplicate header order is preserved");
        assertFalse(text.contains("[REDACTED]"));
        String har = new String(controller.humanExport(List.of(first.evidenceId()), true).serialize(), StandardCharsets.UTF_8);
        var harTree = Json.MAPPER.readTree(har);
        assertEquals("1.2", harTree.at("/log/version").asText());
        assertEquals("HUMAN_ORIGINAL", harTree.at("/log/_cairnGuard/exportMode").asText());
        assertEquals("base64", harTree.at("/log/entries/0/response/content/encoding").asText());
        assertTrue(harTree.at("/log/entries/0/request/url").asText().contains(SECRET));
        String incident = new String(controller.humanIncident(999_999, 1_000_001).serialize(), StandardCharsets.UTF_8);
        assertTrue(incident.contains("\"cairn-human-incident\""));
        assertTrue(incident.contains("/download/" + SECRET));
        assertFalse(incident.contains("_source"), "opaque references never reach files");
        assertTrue(controller.humanExportCurrent(json));
        controller.clearEvidence();
        assertFalse(controller.humanExportCurrent(json), "a clear invalidates the consented snapshot before publication");
        assertEquals("ORIGINAL_UNAVAILABLE", controller.humanCandidates().stream().findFirst().map(c -> c.ruleUnavailable()).orElse("ORIGINAL_UNAVAILABLE"));
        assertTrue(controller.humanOverlays().stream().allMatch(o -> o.host().isEmpty() && "ORIGINAL_UNAVAILABLE".equals(o.unavailable())),
                "protections stay, their originals are gone; no masked substitute");
        assertEquals(1, controller.overlays().size());
    }

    @Test void humanRoutesSeparateServicesIgnoreHostFuzzAndExplainEncodedRouteLimits() {
        open(policy(limits(10, null, null, 0, false), List.of()));
        for (String path : List.of("/same", "/c/%2c")) {
            Prepared p = controller.prepare(new RequestData("GET", "https://evil.invalid" + path, "owned.test", 443, true,
                    List.of(new Header("Host", "evil.invalid")), new byte[0], true, true, path));
            handoff(p);
            controller.response(p.evidenceId(), 200, List.of(), new byte[0], 1);
        }
        var byPath = controller.humanCandidates().stream().collect(java.util.stream.Collectors.toMap(c -> c.path(), c -> c));
        assertEquals("owned.test", byPath.get("/same").host(), "actual service, never the fuzzed Host header");
        assertEquals("/same", byPath.get("/same").limitPath());
        var encoded = byPath.get("/c/%2c");
        assertEquals("https://owned.test/c/%2c", encoded.ruleUrl(), "ordinary BLOCK draft keeps the raw spelling");
        assertNull(encoded.limitPath());
        assertEquals("ENCODED_OR_AMBIGUOUS_ROUTE", encoded.limitUnavailable());
    }

    @Test void candidateSaveRevalidatesTheCurrentSourceAfterConfirmationsAndWritesNothingWhenStale() {
        GuardConfig base = policy(limits(10, null, null, 0, false), List.of());
        open(base);
        Prepared first = prepare("GET", "/large", null);
        handoff(first);
        controller.response(first.evidenceId(), 200, List.of(), new byte[0], 5);
        var candidate = controller.humanCandidates().getFirst();
        GuardConfig withLimit = withPathLimit(base, new PathByteLimit("https", "owned.test", 443, "/large", 7));
        int saves = projects.saves.get();
        // wrong route for a byte-limit save
        GuardConfig wrong = withPathLimit(base, new PathByteLimit("https", "owned.test", 443, "/other", 7));
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(wrong, "a", revision(), candidate.source(), true));
        assertEquals(saves, projects.saves.get());
        // a newer observation replaces the candidate's latest source
        Prepared second = prepare("GET", "/large", null);
        handoff(second);
        controller.response(second.evidenceId(), 200, List.of(), new byte[0], 5);
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(withLimit, "a", revision(), candidate.source(), true));
        assertEquals(saves, projects.saves.get());
        var current = controller.humanCandidates().getFirst();
        controller.updateConfig(withLimit, "a", revision(), current.source(), true);
        assertEquals(saves + 1, projects.saves.get());
        assertEquals(7, controller.config().limits().heavyPathLimits().getFirst().maxBytes());
        // clear/epoch invalidates
        var again = controller.humanCandidates().getFirst();
        controller.clearEvidence();
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(withLimit, "a", revision(), again.source(), false));
        assertEquals(saves + 1, projects.saves.get());
        assertThrows(IllegalStateException.class, () -> controller.updateConfig(withLimit, "a", revision(), null, false));
    }
    private static GuardConfig withPathLimit(GuardConfig base, PathByteLimit limit) {
        Limits l = base.limits();
        return new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(),
                        l.circuit5xx(), l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(),
                        List.of(limit), l.circuit5xxExceptions()), base.guardListenerPorts());
    }

    @Test void actualBytesSurvivePartialCopyAndLabelsAreHonestWhileTheSuppliedPrefixIsExportedAsIncomplete() {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared p = prepare("GET", "/large", null);
        handoff(p);
        controller.response(p.evidenceId(), 200, List.of(new Header("Content-Type", "application/json")), bytes("{\"grant\":\"partial"),
                6L * 1_048_576, true, false);
        assertEquals(6L * 1_048_576, row(p).responseBytes());
        assertFalse(row(p).responseCapture().bodyOmitted());
        assertTrue(row(p).responseCapture().truncated(), "supplied copy is incomplete");
        assertTrue(controller.exportJson(controller.traffic()).contains("partial"));
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

    @Test void originalsSurviveResponseDiscoveryAcrossControllerSurfacesAndStatusProjectName() throws Exception {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared first = prepare("GET", "/download/" + SECRET, null);
        handoff(first);
        controller.response(first.evidenceId(), 200, List.of(new Header("Content-Type", "application/json"), new Header("X-Broker-Grant", SECRET)),
                bytes("{\"grant\":\"" + SECRET + "\"}"), 20, true, true);
        assertTrue(controller.exportJson(controller.traffic()).contains("/download/" + SECRET));
        assertTrue(controller.exportJson(controller.traffic()).contains("X-Broker-Grant"));
        assertTrue(controller.exportHar(controller.traffic()).contains("/download/" + SECRET));
        assertTrue(row(first).response().contains(SECRET));
        assertEquals("/download/" + SECRET, controller.heavyCandidates().getFirst().path());
        assertEquals("https://owned.test/download/" + SECRET, controller.heavyCandidates().getFirst().policyUrl());
        assertEquals("/download/" + SECRET, controller.overlays().getFirst().path());
        assertTrue(controller.exportIncident(999_999, 1_000_001).contains("/download/" + SECRET));
        assertEquals("Synthetic project", controller.status().get("projectName"));
    }

    @Test void originalsProjectChangeAndCloseReleaseOriginalBearingHistory() {
        open(policy(limits(0, null, null, 0, false), List.of()));
        Prepared old = prepare("GET", "/old/" + SECRET, null);
        handoff(old);
        controller.response(old.evidenceId(), 200, List.of(), new byte[0], 0);
        List<TrafficEntry> stale = controller.traffic();
        assertEquals(1, stale.size());
        projects.id = "b";
        assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class, () -> controller.exportJson(stale)).getMessage(),
                "an export that discovers the change releases old rows first and rejects their seals");
        assertThrows(IllegalArgumentException.class, () -> controller.exportHar(stale));
        assertFalse(controller.exportJson(List.of()).contains(SECRET), "an empty selection is an original-free document");
        assertFalse(controller.exportIncident(999_999, 1_000_001).contains(SECRET), "watcher history was reset with the epoch");
        assertTrue(controller.traffic().isEmpty(), "a read that discovers a project change must not return old originals");
        controller.refreshProject();
        assertTrue(controller.traffic().isEmpty());
        controller.response(old.evidenceId(), 200, List.of(), bytes(SECRET), 6, true, true);
        assertTrue(controller.traffic().isEmpty(), "late old-project response cannot recreate a row");
        Prepared fresh = prepare("GET", "/fresh", null);
        assertEquals(1, controller.traffic().size());
        controller.close();
        assertTrue(controller.traffic().isEmpty(), "unload releases retained originals");
        controller.response(fresh.evidenceId(), 200, List.of(), bytes(SECRET), 6, true, true);
        assertTrue(controller.traffic().isEmpty());
    }

    @Test void originalsExplicitClearRemovesWatcherDisplayOriginalsButKeepsProtection() throws Exception {
        open(policy(limits(10, null, null, 0, false), List.of()));
        Prepared heavy = prepare("GET", "/clear/" + SECRET, null);
        handoff(heavy);
        Prepared pending = prepare("GET", "/pending/" + SECRET, null);
        controller.response(heavy.evidenceId(), 200, List.of(), new byte[0], 20);
        controller.clearEvidence();
        assertEquals(1, controller.overlays().size());
        assertFalse(controller.overlays().toString().contains(SECRET), "explicit clear releases protection display originals");
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", controller.authorize(prepare("GET", "/clear/" + SECRET, null)).reason());
        handoff(pending);
        controller.response(pending.evidenceId(), 200, List.of(), new byte[0], 20);
        assertFalse(controller.overlays().toString().contains("/pending/" + SECRET), "pre-clear endpoint cannot resurrect originals");
        assertFalse(controller.exportIncident(999_999, 1_000_001).contains(SECRET));
        Prepared after = prepare("GET", "/after/" + SECRET, null);
        handoff(after);
        controller.response(after.evidenceId(), 200, List.of(), new byte[0], 1);
        assertTrue(controller.heavyCandidates().stream().anyMatch(c -> c.path().equals("/after/" + SECRET)));
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
                1024, pathCapacity, 1024);
        controller = new GuardController(projects, watcher, new IntentBudget(intentCapacity), new RateGate(limits),
                new ListenerRegistry(nano::get, 4096, TimeUnit.SECONDS.toNanos(30)), nano::get, ticketCapacity);
    }
    private void save(GuardConfig config) { controller.updateConfig(config, projects.id, revision()); }
    private long revision() { return ((Number) controller.status().get("revision")).longValue(); }
    private Map<?, ?> watchers() { return (Map<?, ?>) controller.status().get("watchers"); }
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
