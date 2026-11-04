package dev.cairnguard.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Circuit5xx;
import dev.cairnguard.model.GuardConfig.Fanout;
import dev.cairnguard.model.GuardConfig.FanoutAction;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.PathByteLimit;
import dev.cairnguard.model.GuardState;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.runtime.ResponseWatcher.Endpoint;
import dev.cairnguard.runtime.ResponseWatcher.Ticket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic scalar callbacks only; no target traffic/native Burp or policy writes/threads in watcher. */
@Timeout(20)
class ResponseWatcherTest {
    @Test void heavyUsesObservedBytesNotContentLengthAndExpiresOnMonotonicClock() throws Exception {
        Clock clock = new Clock();
        Limits limits = limits(10, null, null);
        ResponseWatcher watcher = watcher(limits, clock);
        RequestData request = new RequestData("GET", "https://example.test/report?token=synthetic", "example.test", 443,
                true, List.of(new RequestData.Header("Content-Length", "999999999")), new byte[0]);
        Endpoint endpoint = watcher.endpoint(request, "https://example.test/report?token=%5BREDACTED%5D", List.of("/report"));
        watcher.observe(watcher.commit(endpoint, false, "not-retained"), 200, 10);
        assertTrue(watcher.check(endpoint, false).allowed(), "strictly above, not at the limit");
        watcher.observe(watcher.commit(endpoint, false, ""), 200, 11);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(endpoint, false).reason());
        assertEquals(GuardState.OVERLAY_BLOCK, watcher.check(endpoint, false).guardState());
        assertFalse(watcher.check(endpoint, true).allowed(), "health cannot bypass heavy protection");
        assertTrue(watcher.check(endpoint(watcher, "/other"), false).allowed());
        clock.wall += 86_400_000;
        assertFalse(watcher.check(endpoint, false).allowed(), "wall-clock jumps cannot expire protections");
        clock.advance(999);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(1);
        assertTrue(watcher.check(endpoint, false).allowed());
        assertTrue(watcher.overlays().isEmpty());
    }

    @Test void allRoutingViewsAreHashedAndAliasesCannotEvadeHeavyProtection() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        Endpoint encoded = endpoint(watcher, "GET", "example.test", 443, true, "/a%252Fb?x=1",
                "https://example.test/a%252Fb?x=1", List.of("/a%252Fb", "/a%2Fb", "/a/b"));
        assertEquals(3, encoded.pathKeys().size());
        assertTrue(encoded.pathKeys().stream().allMatch(k -> k.matches("[0-9a-f]{64}")));
        watcher.observe(watcher.commit(encoded, false, ""), 200, 2);
        assertFalse(watcher.check(endpoint(watcher, "/a/b?other=query"), false).allowed());
        assertTrue(watcher.check(endpoint(watcher, "GET", "example.test", 8443, true, "/a/b",
                "https://example.test:8443/a/b", List.of("/a/b")), false).allowed());
        assertTrue(watcher.check(endpoint(watcher, "GET", "example.test", 80, false, "/a/b",
                "http://example.test/a/b", List.of("/a/b")), false).allowed());
    }

    @Test void keysUseActualServiceAndNeverRetainRawSecretsInViewsOrIncidents() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        RequestData request = new RequestData("GET", "https://spoofed.invalid/token/synthetic-secret?grant=secret-query",
                "example.test", 443, true, List.of(new RequestData.Header("Authorization", "Bearer synthetic-secret")), new byte[0]);
        Endpoint endpoint = watcher.endpoint(request, "https://example.test/token/%5BREDACTED%5D?grant=%5BREDACTED%5D",
                List.of("/token/synthetic-secret"));
        assertEquals("", endpoint.policyUrl());
        assertFalse(endpoint.hostKey().contains("example"));
        assertFalse(endpoint.pathKeys().toString().contains("synthetic-secret"));
        watcher.observe(watcher.commit(endpoint, false, "synthetic-secret"), 503, 200);
        assertEquals("", watcher.candidates().getFirst().policyUrl());
        String exported = watcher.incidentJson(clock.wall, clock.wall + 1);
        assertFalse(exported.contains("synthetic-secret"));
        assertFalse(exported.contains("secret-query"));
        assertFalse(exported.contains("spoofed.invalid"));
        assertFalse(watcher.overlays().toString().contains("synthetic-secret"));
        assertFalse(watcher.snapshot().toString().contains("synthetic-secret"));
        Endpoint actual = endpoint(watcher, "/token/synthetic-secret");
        assertEquals(endpoint.hostKey(), actual.hostKey());
        assertEquals(endpoint.pathKeys(), actual.pathKeys());
    }

    @Test void safeNoQueryPolicyUrlAndRedactedFallbackAreNeverRawFallbacks() {
        ResponseWatcher watcher = watcher(limits(0, null, null), new Clock());
        Endpoint safe = endpoint(watcher, "/report?q=one");
        assertEquals("https://example.test/report", safe.policyUrl());
        Endpoint bad = endpoint(watcher, "GET", "example.test", 443, true, "/secret",
                "not a URL", List.of("/secret"));
        assertEquals("[REDACTED]", bad.host());
        assertEquals("[REDACTED]", bad.path());
        assertEquals("", bad.policyUrl());
        Endpoint another = endpoint(watcher(limits(0, null, null), new Clock()), "/report");
        assertNotEquals(safe.hostKey(), another.hostKey(), "per-instance keyed hashes");
        assertThrows(UnsupportedOperationException.class, () -> safe.pathKeys().add("raw"));
    }

    @Test void repeatedOutstandingHeavyResponsesExtendTtlWithoutDuplicateEpisodeEvents() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        Endpoint endpoint = endpoint(watcher, "/big");
        Ticket first = watcher.commit(endpoint, false, "");
        Ticket second = watcher.commit(endpoint, false, "");
        watcher.observe(first, 200, 2);
        String id = watcher.overlays().getFirst().id();
        clock.advance(500);
        watcher.observe(second, 200, 3);
        assertEquals(id, watcher.overlays().getFirst().id());
        assertEquals(1, number(watcher, "events"));
        clock.advance(500);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(500);
        assertTrue(watcher.check(endpoint, false).allowed());
    }

    @Test void authoredPathThresholdOverridesDefaultAndZeroDisablesOnlyThatPath() throws Exception {
        Clock clock = new Clock();
        Limits base = limits(10, null, null);
        Limits configured = withPaths(base, List.of(new PathByteLimit("https", "example.test", 443, "/large", 20),
                new PathByteLimit("https", "example.test", 443, "/off", 0)));
        ResponseWatcher watcher = watcher(configured, clock);
        Endpoint large = endpoint(watcher, "/large");
        watcher.observe(watcher.commit(large, false, ""), 200, 15);
        assertTrue(watcher.check(large, false).allowed());
        watcher.observe(watcher.commit(large, false, ""), 200, 21);
        assertFalse(watcher.check(large, false).allowed());
        Endpoint off = endpoint(watcher, "/off");
        watcher.observe(watcher.commit(off, false, ""), 200, 99_999);
        assertTrue(watcher.check(off, false).allowed());
    }

    @Test void disablingDetectorsDoesNotEraseActiveProtectionOrModifyHumanPolicy() throws Exception {
        Clock clock = new Clock();
        Limits original = limits(1, new Circuit5xx(1_000, 1, 1_000, 1), new Fanout(1_000, 3, FanoutAction.WARN));
        String policyBefore = Json.write(original);
        ResponseWatcher watcher = watcher(original, clock);
        Endpoint endpoint = endpoint(watcher, "/heavy");
        watcher.observe(watcher.commit(endpoint, false, ""), 200, 2);
        String overlayId = watcher.overlays().getFirst().id();
        watcher.update(limits(0, null, null));
        assertEquals(overlayId, watcher.check(endpoint, true).overlayId());
        assertEquals(policyBefore, Json.write(original), "watcher has no policy persistence path");
        assertTrue(watcher.release(overlayId));
        assertTrue(watcher.check(endpoint, false).allowed());
        assertFalse(watcher.release(overlayId));
    }

    @Test void runtimeActionsNeverAutosaveTheHumanPolicyFile(@TempDir Path directory) throws Exception {
        Clock clock = new Clock();
        Limits limits = limits(1, new Circuit5xx(1_000, 1, 1_000, 1), null);
        GuardConfig config = new GuardConfig(2, List.of(), List.of(), List.of(), GuardConfig.Mode.BLOCK, limits);
        Path policy = directory.resolve("synthetic-policy.json");
        Files.writeString(policy, Json.write(config));
        byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(policy));
        ResponseWatcher watcher = watcher(limits, clock);
        Endpoint endpoint = endpoint(watcher, "/big");
        watcher.observe(watcher.commit(endpoint, false, ""), 503, 2);
        assertEquals(2, watcher.overlays().size());
        watcher.ignoreCandidate(watcher.candidates().getFirst().id());
        watcher.update(limits(0, null, null));
        watcher.releaseAll();
        clock.advance(1_000);
        watcher.reset();
        assertArrayEquals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(policy)));
        assertEquals(Json.write(config), Files.readString(policy));
    }

    @Test void circuitCountsOnly5xxAndWindowIncludesItsLowerBoundary() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 2, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/test");
        respond(watcher, endpoint, 500);
        respond(watcher, endpoint, 499);
        clock.advance(1_000);
        respond(watcher, endpoint, 599);
        assertEquals("CIRCUIT_OPEN", watcher.check(endpoint, false).reason());
        assertEquals(GuardState.CIRCUIT_OPEN, watcher.check(endpoint, false).guardState());
        ResponseWatcher other = watcher(limits(0, new Circuit5xx(1_000, 2, 1_000, 1), null), clock);
        Endpoint otherEndpoint = endpoint(other, "/test");
        respond(other, otherEndpoint, 500);
        clock.advance(1_001);
        respond(other, otherEndpoint, 503);
        assertTrue(other.check(otherEndpoint, false).allowed(), "old 5xx left the window");
    }

    @Test void halfOpenIsGetHeadOnlyAndAdvisoryCheckDoesNotClaimIt() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint get = endpoint(watcher, "/test");
        respond(watcher, get, 500);
        clock.advance(1_000);
        assertTrue(watcher.check(get, false).allowed());
        assertTrue(watcher.check(get, false).allowed());
        Endpoint post = endpoint(watcher, "POST", "example.test", 443, true, "/test",
                "https://example.test/test", List.of("/test"));
        assertFalse(watcher.check(post, false).allowed());
        Endpoint head = endpoint(watcher, "HEAD", "example.test", 443, true, "/test",
                "https://example.test/test", List.of("/test"));
        Ticket ticket = watcher.commit(head, false, "");
        assertTrue(ticket.halfOpen());
        assertFalse(watcher.check(get, false).allowed());
        watcher.observe(ticket, 499, 0);
        assertTrue(watcher.overlays().isEmpty());
        assertTrue(watcher.check(post, false).allowed());
    }

    @Test void simultaneousFinalCommitsClaimExactlyOneHalfOpen() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/test");
        respond(watcher, endpoint, 500);
        clock.advance(1_000);
        CountDownLatch ready = new CountDownLatch(32);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger admitted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 32; i++) futures.add(workers.submit(() -> {
                ready.countDown();
                assertTrue(go.await(5, TimeUnit.SECONDS));
                try { watcher.commit(endpoint, false, ""); admitted.incrementAndGet(); }
                catch (ResponseWatcher.Rejected denied) { assertEquals("CIRCUIT_OPEN", denied.reason()); rejected.incrementAndGet(); }
                return null;
            }));
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            for (Future<?> future : futures) future.get(5, TimeUnit.SECONDS);
        }
        assertEquals(1, admitted.get());
        assertEquals(31, rejected.get());
        assertEquals(1, number(watcher, "halfOpen"));
    }

    @Test void failedCancelledAndMissingProbesCannotBypassThirtySecondCadence() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/test");
        respond(watcher, endpoint, 500);
        clock.advance(1_000);
        Ticket failed = watcher.commit(endpoint, false, "");
        watcher.observe(failed, 500, 0);
        clock.advance(1_000);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(29_000);
        Ticket cancelled = watcher.commit(endpoint, false, "");
        watcher.cancel(cancelled);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(30_000);
        Ticket missing = watcher.commit(endpoint, false, "");
        watcher.abandon(missing);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(30_000);
        Ticket invalid = watcher.commit(endpoint, false, "");
        watcher.observe(invalid, 0, 0);
        assertFalse(watcher.check(endpoint, false).allowed());
    }

    @Test void deadlineIsLogicalOnlyAndLateProbeCannotCloseReplacementEpisode() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/test");
        respond(watcher, endpoint, 500);
        clock.advance(1_000);
        Ticket old = watcher.commit(endpoint, false, "");
        watcher.update(withTimeout(limits(0, null, null), 60_000));
        clock.advance(1_000); // Deadline captured at commit, not extended by a policy save.
        assertEquals(0, number(watcher, "activeTickets"));
        assertEquals(1, number(watcher, "timedOut"));
        clock.advance(29_000);
        Ticket replacement = watcher.commit(endpoint, false, "");
        watcher.observe(old, 200, 0);
        assertEquals(1, number(watcher, "halfOpen"));
        assertFalse(watcher.check(endpoint, false).allowed());
        watcher.observe(replacement, 204, 0);
        assertTrue(watcher.check(endpoint, false).allowed());
        // No native permit API/object is present in watcher: caller still owns actual native release.
    }

    @Test void healthBypassesOnlyCircuitAndCannotCloseIt() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(10, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/health");
        respond(watcher, endpoint, 503);
        assertTrue(watcher.check(endpoint, true).allowed());
        Ticket health = watcher.commit(endpoint, true, "");
        assertFalse(health.halfOpen());
        watcher.observe(health, 200, 0);
        assertFalse(watcher.check(endpoint, false).allowed());
        watcher.observe(watcher.commit(endpoint, true, ""), 200, 11);
        assertFalse(watcher.check(endpoint, true).allowed(), "heavy applies even to health");
    }

    @Test void releaseUsesNonReusableEpisodeIdsAndOldProbeCannotClearNewCircuit() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), clock);
        Endpoint endpoint = endpoint(watcher, "/test");
        respond(watcher, endpoint, 500);
        String firstId = watcher.overlays().getFirst().id();
        clock.advance(1_000);
        Ticket oldProbe = watcher.commit(endpoint, false, "");
        assertTrue(watcher.release(firstId));
        respond(watcher, endpoint, 500);
        String secondId = watcher.overlays().getFirst().id();
        assertNotEquals(firstId, secondId);
        assertFalse(watcher.release(firstId));
        watcher.observe(oldProbe, 200, 0);
        assertEquals(secondId, watcher.overlays().getFirst().id());
        assertFalse(watcher.check(endpoint, false).allowed());
    }

    @Test void fanoutBlockCountsRequestsWithoutAnyResponsesAndDeduplicatesEpisode() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 3, FanoutAction.BLOCK)), clock);
        watcher.commit(endpoint(watcher, "/one"), false, "");
        watcher.commit(endpoint(watcher, "/two"), false, "");
        ResponseWatcher.Rejected rejected = assertThrows(ResponseWatcher.Rejected.class,
                () -> watcher.commit(endpoint(watcher, "/three"), false, ""));
        assertEquals("FANOUT_SUSPECTED", rejected.reason());
        assertEquals(2, number(watcher, "admitted"));
        for (int i = 0; i < 10; i++) assertFalse(watcher.check(endpoint(watcher, "/three"), false).allowed());
        JsonNode incident = json(watcher.incidentJson(clock.wall, clock.wall + 1));
        assertEquals(1, incident.get("events").size());
        assertEquals(3, incident.at("/events/0/distinctPaths").asInt());
        assertTrue(watcher.check(endpoint(watcher, "GET", "other.test", 443, true, "/ok",
                "https://other.test/ok", List.of("/ok")), false).allowed());
        assertEquals(1, watcher.releaseAll());
        assertTrue(watcher.check(endpoint(watcher, "/three"), false).allowed());
    }

    @Test void fanoutFinalRejectionPrecedesIntentConsumptionIncludingHealthAndExemptCallers() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 3, FanoutAction.BLOCK)), clock);
        IntentBudget budget = new IntentBudget();
        RequestAttribution attribution = new RequestAttribution("one", "run", true);
        for (String path : List.of("/ordinary", "/exempt")) {
            assertNull(budget.check(attribution, 20));
            watcher.commit(endpoint(watcher, path), false, "");
            assertNull(budget.commit(attribution, 20));
        }
        assertNull(budget.check(attribution, 20));
        assertThrows(ResponseWatcher.Rejected.class,
                () -> watcher.commit(endpoint(watcher, "/health"), true, ""));
        assertEquals(2, ((Number) budget.snapshot().get("consumed")).intValue());
    }

    @Test void conclusivelyUnsentAdmissionsDoNotCountForFanoutEvenWhenCancelledOutOfOrder() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 3, FanoutAction.BLOCK)), clock);
        Endpoint one = endpoint(watcher, "/one");
        Ticket first = watcher.commit(one, false, "");
        Ticket laterSamePath = watcher.commit(one, false, "");
        watcher.cancel(first);
        watcher.cancel(laterSamePath);
        watcher.commit(endpoint(watcher, "/two"), false, "");
        watcher.commit(endpoint(watcher, "/three"), false, "");
        assertTrue(watcher.overlays().isEmpty());
        assertThrows(ResponseWatcher.Rejected.class,
                () -> watcher.commit(endpoint(watcher, "/four"), false, ""));
        assertEquals("FANOUT_SUSPECTED", watcher.overlays().getFirst().reason());
    }

    @Test void cancelledDuplicateDoesNotEraseAnotherAcceptedAdmissionOnSamePath() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 2, FanoutAction.BLOCK)), clock);
        Endpoint one = endpoint(watcher, "/one");
        Ticket first = watcher.commit(one, false, "");
        Ticket duplicate = watcher.commit(one, false, "");
        watcher.observe(first, 200, 0);
        watcher.cancel(duplicate);
        assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
    }

    @Test void fanoutPauseIsGlobalAutomaticOverlayNotOperatorFlagAndSurvivesDisable() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 2, FanoutAction.PAUSE)), clock);
        watcher.commit(endpoint(watcher, "/one"), false, "");
        assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
        Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok",
                "https://other.test/ok", List.of("/ok"));
        assertFalse(watcher.check(other, true).allowed());
        assertEquals(true, watcher.snapshot().get("automaticPause"));
        watcher.update(limits(0, null, null));
        assertFalse(watcher.check(other, false).allowed());
        clock.advance(1_000);
        assertTrue(watcher.check(other, false).allowed());
        assertEquals(false, watcher.snapshot().get("automaticPause"));
    }

    @Test void fanoutWarnAllowsRequestsAndOneEventUntilEpisodeExpiry() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)), clock);
        for (int i = 0; i < 5; i++) respond(watcher, endpoint(watcher, "/path-" + i), 200);
        assertTrue(watcher.overlays().isEmpty());
        assertEquals(1, number(watcher, "fanoutWarnings"));
        assertEquals(1, json(watcher.incidentJson(clock.wall, clock.wall + 1)).get("events").size());
        clock.advance(1_000);
        respond(watcher, endpoint(watcher, "/path-new"), 200);
        assertEquals(2, json(watcher.incidentJson(clock.wall - 1_000, clock.wall + 1)).get("events").size());
    }

    @Test void completedWarnFanoutPathsDoNotExhaustPathCapacity() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 2, 4, 8, 8);
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        Ticket third = watcher.commit(endpoint(watcher, "/c"), false, "");
        watcher.observe(third, 200, 0);
        for (int i = 0; i < 20; i++) respond(watcher, endpoint(watcher, "/churn-" + i), 200);
        assertTrue(watcher.overlays().isEmpty());
    }

    @Test void liveWarnEpisodeDoesNotSuppressLaterBlockOrPauseDetection() throws Exception {
        for (FanoutAction action : List.of(FanoutAction.BLOCK, FanoutAction.PAUSE)) {
            Clock clock = new Clock();
            ResponseWatcher watcher = watcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)), clock);
            respond(watcher, endpoint(watcher, "/a"), 200);
            respond(watcher, endpoint(watcher, "/b"), 200);
            assertEquals(1, number(watcher, "fanoutWarnings"));
            watcher.update(limits(0, null, new Fanout(60_000, 2, action)));
            ResponseWatcher.Rejected rejected = assertThrows(ResponseWatcher.Rejected.class,
                    () -> watcher.commit(endpoint(watcher, "/c"), false, ""), action.name());
            assertEquals("FANOUT_SUSPECTED", rejected.reason());
            assertEquals(1, watcher.overlays().size());
            Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok", "https://other.test/ok", List.of("/ok"));
            assertEquals(action == FanoutAction.BLOCK, watcher.check(other, false).allowed(), "BLOCK is service-local, PAUSE global");
            assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
            assertEquals(true, json(watcher.incidentJson(clock.wall, clock.wall + 1)).get("fanoutHistoryComplete").asBoolean());
        }
    }

    @Test void warnChurnBeyondCapacityKeepsIndexedHistoryBoundedAndReportsStickyOmissions() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 2, 4, 8, 8);
        long start = clock.wall;
        for (int i = 0; i < 22; i++) respond(watcher, endpoint(watcher, "/p" + i), 200);
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(2, number(watcher, "fanoutHistoryCapacity"));
        assertEquals(20, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(true, watcher.snapshot().get("fanoutHistoryIncomplete"));
        assertEquals(start + 60_000, number(watcher, "fanoutHistoryIncompleteUntil"));
        assertEquals(0, number(watcher, "paths"), "completed WARN paths are not pinned");
        // Indexed identity and a routing alias of it receive marks without omission.
        respond(watcher, endpoint(watcher, "/p0"), 200);
        respond(watcher, endpoint(watcher, "GET", "example.test", 443, true, "/%70%30", "https://example.test/%70%30",
                List.of("/%70%30", "/p0")), 200);
        assertEquals(20, number(watcher, "fanoutHistoryOmitted"));
        JsonNode incident = json(watcher.incidentJson(start, clock.wall + 1));
        assertFalse(incident.get("fanoutHistoryComplete").asBoolean());
        assertFalse(incident.get("complete").asBoolean());
        assertTrue(incident.get("truncated").asBoolean());
        assertEquals(20, incident.at("/retention/fanoutHistoryOmitted").asLong());
        assertTrue(incident.at("/retention/eventsComplete").asBoolean(), "distinct from ring truncation");
        clock.advance(60_000);
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
        assertEquals(0, number(watcher, "fanoutHistoryIncompleteUntil"));
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        respond(watcher, endpoint(watcher, "/later"), 200);
        JsonNode later = json(watcher.incidentJson(clock.wall, clock.wall + 1));
        assertFalse(later.get("fanoutHistoryComplete").asBoolean(), "historical omission stays disclosed after debt expiry");
        assertFalse(later.get("complete").asBoolean());
        assertTrue(later.get("truncated").asBoolean());
        assertFalse(watcher.snapshot().toString().contains("/p1"));
    }

    @Test void indexedHistoryBudgetIsSharedAcrossActualServices() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 2, 4, 8, 8);
        respond(watcher, endpoint(watcher, "/same"), 200);
        respond(watcher, endpoint(watcher, "GET", "example.test", 8443, true, "/same", "https://example.test:8443/same",
                List.of("/same")), 200);
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
        respond(watcher, endpoint(watcher, "GET", "example.test", 80, false, "/same", "http://example.test/same",
                List.of("/same")), 200);
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"), "another actual service is another identity");
        respond(watcher, endpoint(watcher, "/same"), 200);
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
    }

    @Test void warnStillPinsGenuineInFlightPathsAndTimeoutOrAbandonNeverFreesThem() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 2, 4, 8, 8);
        Ticket first = watcher.commit(endpoint(watcher, "/a"), false, "");
        Ticket second = watcher.commit(endpoint(watcher, "/b"), false, "");
        assertEquals(GuardState.CAPACITY, watcher.check(endpoint(watcher, "/c"), false).guardState());
        watcher.abandon(first);
        clock.advance(1_000);
        assertEquals(1, number(watcher, "timedOut"));
        assertEquals(GuardState.CAPACITY, watcher.check(endpoint(watcher, "/c"), false).guardState());
        watcher.observe(first, 200, 0);
        respond(watcher, endpoint(watcher, "/c"), 200);
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        watcher.cancel(second);
        assertEquals(0, number(watcher, "paths"));
    }

    @Test void omissionDebtFailsEveryEnforcingTransitionClosedUntilOriginalWindowEnds() throws Exception {
        for (String route : List.of("BLOCK", "PAUSE", "NULL_BLOCK", "NULL_PAUSE")) {
            Clock clock = new Clock();
            ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                    clock::nano, clock::wall, 4, 2, 4, 8, 8);
            for (String path : List.of("/a", "/b", "/c")) respond(watcher, endpoint(watcher, path), 200);
            assertEquals(1, number(watcher, "fanoutHistoryOmitted"), route);
            if (route.startsWith("NULL")) {
                watcher.update(limits(0, null, null));
                assertTrue(watcher.check(endpoint(watcher, "/a"), false).allowed(), "no enforcing detector, no gate");
            }
            Limits enforcing = limits(0, null, new Fanout(60_000, 10, FanoutAction.valueOf(route.replace("NULL_", ""))));
            watcher.update(enforcing);
            Endpoint existing = endpoint(watcher, "/a");
            Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok", "https://other.test/ok", List.of("/ok"));
            for (Endpoint endpoint : List.of(existing, endpoint(watcher, "/new"), other)) {
                for (boolean health : List.of(false, true)) {
                    ResponseWatcher.Gate gate = watcher.check(endpoint, health);
                    assertEquals("RESPONSE_WATCHER_CAPACITY", gate.reason(), route);
                    assertEquals(GuardState.CAPACITY, gate.guardState());
                }
            }
            ResponseWatcher.Rejected rejected = assertThrows(ResponseWatcher.Rejected.class,
                    () -> watcher.commit(existing, false, ""));
            assertEquals("RESPONSE_WATCHER_CAPACITY", rejected.reason());
            assertEquals(GuardState.CAPACITY, rejected.guardState());
            assertEquals(1, number(watcher, "fanoutHistoryOmitted"), "advisory/rejected admissions record nothing");
            watcher.update(enforcing);
            watcher.clearEvidence();
            assertEquals(0, watcher.releaseAll());
            clock.advance(59_999);
            assertFalse(watcher.check(existing, false).allowed(), "save/clear/release cannot shorten debt");
            clock.advance(1);
            assertTrue(watcher.check(existing, false).allowed(), route);
            assertTrue(watcher.check(other, false).allowed());
            assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
            watcher.observe(watcher.commit(existing, false, ""), 200, 0);
        }
    }

    @Test void enforcingRejectsNewIdentityWithoutHistorySlotButKeepsIndexedIdentities() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 4, 4, 8, 8);
        for (String path : List.of("/a", "/b", "/c", "/d")) respond(watcher, endpoint(watcher, path), 200);
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
        watcher.update(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK)));
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(endpoint(watcher, "/e"), false).reason());
        Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok", "https://other.test/ok", List.of("/ok"));
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(other, true).reason());
        assertTrue(watcher.check(endpoint(watcher, "/a"), false).allowed());
        respond(watcher, endpoint(watcher, "/a"), 200);
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
    }

    @Test void historyCapacityRejectionDoesNotClaimHalfOpenProbe() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1),
                new Fanout(60_000, 10, FanoutAction.WARN)), clock::nano, clock::wall, 4, 2, 4, 8, 8);
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        respond(watcher, endpoint(watcher, "/c"), 503);
        assertEquals(1, number(watcher, "circuits"));
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        watcher.update(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), new Fanout(60_000, 10, FanoutAction.BLOCK)));
        Endpoint probe = endpoint(watcher, "/a");
        assertEquals("CIRCUIT_OPEN", watcher.check(probe, false).reason(), "existing circuit precedence");
        clock.advance(1_000);
        assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(probe, false, ""));
        assertEquals(0, number(watcher, "halfOpen"));
        clock.advance(59_000);
        Ticket ticket = watcher.commit(probe, false, "");
        assertTrue(ticket.halfOpen(), "cadence was not spent by the capacity rejection");
        watcher.observe(ticket, 200, 0);
        assertEquals(0, number(watcher, "circuits"));
    }

    @Test void omissionDeadlineUsesLargestOriginalWindowAcrossMonotonicWrap() throws Exception {
        Clock clock = new Clock();
        clock.nanos = Long.MAX_VALUE - 5_000_000_000L;
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(10_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 1, 4, 8, 8);
        long start = clock.wall;
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        watcher.update(limits(0, null, new Fanout(1_000, 10, FanoutAction.WARN)));
        clock.advance(1);
        respond(watcher, endpoint(watcher, "/c"), 200);
        assertEquals(2, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(start + 10_000, number(watcher, "fanoutHistoryIncompleteUntil"), "a shorter window cannot shorten debt");
        watcher.update(limits(0, null, new Fanout(1_000, 10, FanoutAction.PAUSE)));
        clock.advance(9_998); // crosses the nano wrap
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(endpoint(watcher, "/a"), false).reason());
        clock.advance(1);
        assertTrue(watcher.check(endpoint(watcher, "/a"), false).allowed(), "exact original deadline");
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
    }

    @Test void pendingDuplicatesOutOfOrderCallbacksAndDetachedHistoryStayBounded() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(1_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 3, 4, 8, 8);
        Endpoint a = endpoint(watcher, "/a");
        Ticket first = watcher.commit(a, false, "");
        Ticket duplicate = watcher.commit(a, false, "");
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"));
        watcher.releaseAll(); // detaches pending history; late callbacks must not reinsert it
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        Ticket b = watcher.commit(endpoint(watcher, "/b"), false, "");
        Ticket c = watcher.commit(endpoint(watcher, "/c"), false, "");
        watcher.observe(duplicate, 200, 0);
        watcher.cancel(first);
        watcher.observe(duplicate, 200, 0);
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
        clock.advance(1_000); // logical timeout of b/c; history window also ends
        watcher.abandon(b);
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        watcher.observe(b, 200, 0);
        watcher.cancel(c);
        watcher.observe(c, 200, 0);
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(0, number(watcher, "activeTickets") + number(watcher, "lateTickets"));
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
        respond(watcher, endpoint(watcher, "/d"), 200);
        respond(watcher, endpoint(watcher, "/e"), 200);
        respond(watcher, endpoint(watcher, "/f"), 200);
        respond(watcher, endpoint(watcher, "/g"), 200);
        assertEquals(3, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
    }

    @Test void resetClearsOmissionDebtButClearEvidenceAndReleaseDoNot() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 1, 4, 8, 8);
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        watcher.clearEvidence();
        watcher.releaseAll();
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(true, watcher.snapshot().get("fanoutHistoryIncomplete"));
        watcher.reset();
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
        watcher.update(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK)));
        assertTrue(watcher.check(endpoint(watcher, "/a"), false).allowed());
        assertTrue(json(watcher.incidentJson(clock.wall, clock.wall + 1)).get("fanoutHistoryComplete").asBoolean());
    }

    @Test void warnReclamationKeepsEarlierEnforcingRetentionHeavyAndActiveBlock() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(1, null, new Fanout(60_000, 10, FanoutAction.BLOCK)),
                clock::nano, clock::wall, 4, 3, 4, 8, 8);
        respond(watcher, endpoint(watcher, "/a"), 200);
        watcherHeavy(watcher, endpoint(watcher, "/heavy"));
        watcher.update(limits(1, null, new Fanout(60_000, 10, FanoutAction.WARN)));
        respond(watcher, endpoint(watcher, "/b"), 200);
        assertEquals(2, number(watcher, "paths"), "enforcing-era /a and heavy remain pinned, WARN /b is not");
        assertFalse(watcher.check(endpoint(watcher, "/heavy"), true).allowed());
        ResponseWatcher blocked = watcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)), clock);
        respond(blocked, endpoint(blocked, "/one"), 200);
        assertThrows(ResponseWatcher.Rejected.class, () -> blocked.commit(endpoint(blocked, "/two"), false, ""));
        blocked.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)));
        assertEquals("FANOUT_SUSPECTED", blocked.check(endpoint(blocked, "/three"), false).reason());
        blocked.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)));
        assertEquals("FANOUT_SUSPECTED", blocked.check(endpoint(blocked, "/three"), false).reason(),
                "entering enforcing mode ends only WARN latches");
        assertEquals(1, blocked.overlays().size());
    }

    @Test void candidateStatsAndIncidentTopListsUseIndependentRetainedWindow() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        Endpoint one = endpoint(watcher, "/one");
        Endpoint two = endpoint(watcher, "/two");
        long start = clock.wall;
        watcher.observe(watcher.commit(one, false, ""), 500, 100);
        clock.advance(10);
        watcher.observe(watcher.commit(one, false, ""), 200, 10);
        clock.advance(10);
        watcher.observe(watcher.commit(two, false, ""), 503, 50);
        var candidate = watcher.candidates().getFirst();
        assertEquals("/one", candidate.path());
        assertEquals(100, candidate.maxBytes());
        assertEquals(127, candidate.p95Bytes());
        assertEquals(2, candidate.count());
        assertEquals(1, candidate.count5xx());
        assertEquals(start + 10, candidate.lastSeen());
        JsonNode incident = json(watcher.incidentJson(start + 10, start + 20));
        assertTrue(incident.get("complete").asBoolean());
        assertEquals(0, incident.get("events").size(), "observations do not require detector events");
        assertEquals(0, incident.get("top5xx").size());
        assertEquals(1, incident.get("topBytes").size());
        assertEquals(10, incident.at("/topBytes/0/maxBytes").asLong());
        assertEquals(1, incident.at("/topBytes/0/count").asLong());
        assertTrue(incident.get("approximate").asBoolean());
    }

    @Test void observationAndEventCapacityReportIncompleteWithoutInventingLifetimeTotals() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(1, null, null), clock::nano, clock::wall, 4, 8, 8, 2, 2);
        long start = clock.wall;
        for (int i = 0; i < 3; i++) {
            Endpoint endpoint = endpoint(watcher, "/" + i);
            watcher.observe(watcher.commit(endpoint, false, ""), 500, 10 + i);
            clock.advance(1);
        }
        assertEquals(2, number(watcher, "events"));
        assertEquals(2, number(watcher, "observations"));
        assertEquals(true, watcher.snapshot().get("candidatesIncomplete"));
        JsonNode all = json(watcher.incidentJson(start, clock.wall));
        assertFalse(all.get("complete").asBoolean());
        assertTrue(all.at("/retention/eventsDropped").asBoolean());
        assertTrue(all.at("/retention/observationsDropped").asBoolean());
        assertEquals(2, all.get("topBytes").size());
        assertEquals(1, all.at("/topBytes/0/count").asLong());
        JsonNode tail = json(watcher.incidentJson(start + 1, clock.wall));
        assertTrue(tail.get("complete").asBoolean(), "a dropped older sample does not taint a fully retained later window");
    }

    @Test void candidateIgnoreIsRuntimeOnlyAndDoesNotHideIncidentEvidenceOrDisableOverlay() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        Endpoint endpoint = endpoint(watcher, "/big");
        watcher.observe(watcher.commit(endpoint, false, ""), 500, 2);
        String id = watcher.candidates().getFirst().id();
        assertTrue(watcher.ignoreCandidate(id));
        assertTrue(watcher.candidates().isEmpty());
        assertFalse(watcher.check(endpoint, false).allowed());
        assertEquals(1, json(watcher.incidentJson(clock.wall, clock.wall + 1)).get("topBytes").size());
        assertFalse(watcher.ignoreCandidate("not-a-candidate"));
    }

    @Test void activeHostPathAndOverlayCapacityNeverEvictsExistingProtection() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher hosts = new ResponseWatcher(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null),
                clock::nano, clock::wall, 1, 4, 4, 8, 8);
        Endpoint first = endpoint(hosts, "/one");
        respond(hosts, first, 500);
        clock.advance(1_000); // Half-open is still active protection and cannot be evicted.
        Endpoint other = endpoint(hosts, "GET", "other.test", 443, true, "/two", "https://other.test/two", List.of("/two"));
        assertEquals(GuardState.CAPACITY, hosts.check(other, false).guardState());
        assertEquals(1, number(hosts, "circuits"));
        ResponseWatcher paths = new ResponseWatcher(limits(0, null, null), clock::nano, clock::wall, 4, 1, 4, 8, 8);
        Ticket pinned = paths.commit(endpoint(paths, "/one"), false, "");
        assertEquals(GuardState.CAPACITY, paths.check(endpoint(paths, "/two"), false).guardState());
        paths.cancel(pinned);
        assertTrue(paths.check(endpoint(paths, "/two"), false).allowed());
        ResponseWatcher overlays = new ResponseWatcher(limits(1, null, null), clock::nano, clock::wall, 4, 8, 2, 8, 8);
        Endpoint heavy = endpoint(overlays, "/one");
        watcherHeavy(overlays, heavy);
        String old = overlays.overlays().getFirst().id();
        watcherHeavy(overlays, endpoint(overlays, "/two"));
        assertEquals(2, overlays.overlays().size(), "one reserved capacity fence, no growth or active eviction");
        assertTrue(overlays.overlays().stream().anyMatch(o -> o.id().equals(old)));
        assertEquals(GuardState.CAPACITY, overlays.check(endpoint(overlays, "/three"), true).guardState());
        assertEquals(2, overlays.releaseAll());
        assertTrue(overlays.check(heavy, false).allowed());
    }

    @Test void candidateLruIsBoundedButIncidentUsesAllIndependentRetainedObservations() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, null), clock::nano, clock::wall, 4, 2, 4, 8, 8);
        for (int i = 0; i < 3; i++) {
            Endpoint endpoint = endpoint(watcher, "/" + i);
            watcher.observe(watcher.commit(endpoint, false, ""), 500, i + 1);
        }
        assertEquals(2, watcher.candidates().size());
        assertEquals(true, watcher.snapshot().get("candidatesIncomplete"));
        assertEquals(1, number(watcher, "candidateEvictions"));
        JsonNode incident = json(watcher.incidentJson(clock.wall, clock.wall + 1));
        assertEquals(3, incident.get("topBytes").size(), "candidate eviction must not drop an independent observation");
        assertTrue(incident.get("complete").asBoolean());
        for (var candidate : watcher.candidates()) assertTrue(watcher.ignoreCandidate(candidate.id()));
        assertTrue(watcher.candidates().isEmpty());
        respond(watcher, endpoint(watcher, "/new"), 200);
        assertTrue(watcher.candidates().isEmpty(), "bounded ignored runtime entries remain pinned");
    }

    @Test void concurrentDuplicateObserveCancelAbandonCannotDoubleCountOrUnderflow() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        Ticket ticket = watcher.commit(endpoint(watcher, "/one"), false, "");
        CountDownLatch go = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 32; i++) futures.add(executor.submit(() -> {
                assertTrue(go.await(5, TimeUnit.SECONDS));
                watcher.observe(ticket, 500, 10);
                watcher.cancel(ticket);
                watcher.abandon(ticket);
                return null;
            }));
            go.countDown();
            for (Future<?> future : futures) future.get(5, TimeUnit.SECONDS);
        }
        assertEquals(0, number(watcher, "activeTickets"));
        assertEquals(1, watcher.candidates().getFirst().count());
        assertTrue(watcher.check(endpoint(watcher, "/two"), false).allowed());
    }

    @Test void scalarHistogramHandlesLongMaxAndNegativeLengthsWithoutOverflow() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        Endpoint endpoint = endpoint(watcher, "/size");
        watcher.observe(watcher.commit(endpoint, false, ""), 200, Long.MAX_VALUE);
        watcher.observe(watcher.commit(endpoint, false, ""), 200, -1);
        var candidate = watcher.candidates().getFirst();
        assertEquals(Long.MAX_VALUE, candidate.maxBytes());
        assertEquals(Long.MAX_VALUE, candidate.p95Bytes());
        assertEquals(2, candidate.count());
    }

    @Test void resetMakesTicketsEndpointsReleasesAndHashesStaleAcrossEpochs() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        Endpoint old = endpoint(watcher, "/same");
        Ticket late = watcher.commit(old, false, "");
        watcher.observe(watcher.commit(old, false, ""), 500, 2);
        String id = watcher.overlays().getFirst().id();
        long oldEpoch = late.epoch();
        watcher.reset();
        Endpoint current = endpoint(watcher, "/same");
        assertNotEquals(old.hostKey(), current.hostKey());
        assertNotEquals(old.pathKeys(), current.pathKeys());
        assertFalse(watcher.check(old, false).allowed());
        watcher.observe(late, 500, Long.MAX_VALUE);
        watcher.cancel(late);
        watcher.abandon(late);
        assertFalse(watcher.release(id));
        assertTrue(watcher.overlays().isEmpty());
        assertTrue(watcher.candidates().isEmpty());
        Ticket fresh = watcher.commit(current, false, "");
        assertNotEquals(oldEpoch, fresh.epoch());
        watcher.cancel(fresh);
    }

    @Test void staleTicketsFromAnotherWatcherCannotMutateStateEvenWithSameEpoch() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher first = watcher(limits(1, null, null), clock);
        ResponseWatcher second = watcher(limits(1, null, null), clock);
        Ticket ticket = first.commit(endpoint(first, "/secret"), false, "");
        second.observe(ticket, 500, Long.MAX_VALUE);
        second.abandon(ticket);
        second.cancel(ticket);
        assertTrue(second.overlays().isEmpty());
        assertTrue(second.candidates().isEmpty());
        assertEquals(0, number(second, "activeTickets"));
    }

    @Test void retentionExpiresAfter24HoursAndInvalidWindowsAreRejected() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        respond(watcher, endpoint(watcher, "/old"), 503);
        clock.advance(86_400_001);
        assertTrue(watcher.candidates().isEmpty());
        assertEquals(0, number(watcher, "observations"));
        assertThrows(IllegalArgumentException.class, () -> watcher.incidentJson(1, 1));
        assertThrows(IllegalArgumentException.class, () -> watcher.incidentJson(0, 86_400_001));
        assertThrows(IllegalArgumentException.class, () -> watcher.incidentJson(Long.MIN_VALUE, Long.MAX_VALUE));
    }

    @Test void negativeNanoOriginAndNanoWrapDoNotBreakExpiration() throws Exception {
        Clock clock = new Clock();
        clock.nanos = Long.MAX_VALUE - 500_000_000;
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        Endpoint endpoint = endpoint(watcher, "/big");
        watcherHeavy(watcher, endpoint);
        clock.advance(999);
        assertFalse(watcher.check(endpoint, false).allowed());
        clock.advance(1);
        assertTrue(watcher.check(endpoint, false).allowed());
    }

    private static void watcherHeavy(ResponseWatcher watcher, Endpoint endpoint) throws Exception {
        watcher.observe(watcher.commit(endpoint, false, ""), 200, 2);
    }
    private static void respond(ResponseWatcher watcher, Endpoint endpoint, int status) throws Exception {
        watcher.observe(watcher.commit(endpoint, false, ""), status, 0);
    }
    private static ResponseWatcher watcher(Limits limits, Clock clock) {
        return new ResponseWatcher(limits, clock::nano, clock::wall);
    }
    private static Endpoint endpoint(ResponseWatcher watcher, String path) {
        String rawPath = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        return endpoint(watcher, "GET", "example.test", 443, true, path, "https://example.test" + path, List.of(rawPath));
    }
    private static Endpoint endpoint(ResponseWatcher watcher, String method, String host, int port, boolean secure,
                                     String path, String redactedUrl, List<String> views) {
        return watcher.endpoint(new RequestData(method, (secure ? "https" : "http") + "://" + host
                + ((secure && port == 443 || !secure && port == 80) ? "" : ":" + port) + path,
                host, port, secure, List.of(), new byte[0]), redactedUrl, views);
    }
    private static Limits limits(long bytes, Circuit5xx circuit, Fanout fanout) {
        return new Limits(100, 100, Map.of(), 100, 100, 1_000, 1_000, 1_000,
                bytes, 1_000, circuit, fanout, 0, false, List.of(), List.of());
    }
    private static Limits withTimeout(Limits base, long timeout) {
        return new Limits(base.globalRps(), base.perHostRps(), base.hostRps(), base.maxConcurrent(), base.maxQueued(),
                base.queueTimeoutMillis(), base.approvalTimeoutMillis(), timeout, base.perPathMaxResponseBytes(),
                base.autoBlockMillis(), base.circuit5xx(), base.fanout(), base.perIntentMaxRequests(),
                base.healthProbePassthrough(), base.healthProbePaths(), base.heavyPathLimits());
    }
    private static Limits withPaths(Limits base, List<PathByteLimit> paths) {
        return new Limits(base.globalRps(), base.perHostRps(), base.hostRps(), base.maxConcurrent(), base.maxQueued(),
                base.queueTimeoutMillis(), base.approvalTimeoutMillis(), base.requestTimeoutMillis(), base.perPathMaxResponseBytes(),
                base.autoBlockMillis(), base.circuit5xx(), base.fanout(), base.perIntentMaxRequests(),
                base.healthProbePassthrough(), base.healthProbePaths(), paths);
    }
    private static long number(ResponseWatcher watcher, String key) { return ((Number) watcher.snapshot().get(key)).longValue(); }
    private static JsonNode json(String value) throws Exception { return Json.MAPPER.readTree(value); }
    private static final class Clock {
        volatile long nanos = -9_000_000_000L;
        volatile long wall = 10_000L;
        long nano() { return nanos; }
        long wall() { return wall; }
        void advance(long millis) { nanos += TimeUnit.MILLISECONDS.toNanos(millis); wall += millis; }
    }
}
