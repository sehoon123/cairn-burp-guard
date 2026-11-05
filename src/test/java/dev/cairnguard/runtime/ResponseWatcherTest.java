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
import dev.cairnguard.policy.PolicyEngine;
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
        Endpoint endpoint = watcher.endpoint(request, List.of("/report"));
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

    @Test void keysUseActualServiceAndDisplayKeepsTheOriginalActualHostAndPathNotTheFuzzedAuthority() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        RequestData request = new RequestData("GET", "https://spoofed.invalid/token/synthetic-secret?grant=secret-query",
                "example.test", 443, true, List.of(new RequestData.Header("Authorization", "Bearer synthetic-secret")), new byte[0]);
        Endpoint endpoint = watcher.endpoint(request, List.of("/token/synthetic-secret"));
        assertEquals("https://example.test/token/synthetic-secret", endpoint.policyUrl());
        assertEquals("example.test", endpoint.host());
        assertEquals("/token/synthetic-secret", endpoint.path());
        assertFalse(endpoint.hostKey().contains("example"), "enforcement identities stay keyed hashes");
        assertFalse(endpoint.pathKeys().toString().contains("synthetic-secret"));
        watcher.observe(watcher.commit(endpoint, false, "synthetic-secret"), 503, 200);
        assertEquals("https://example.test/token/synthetic-secret", watcher.candidates().getFirst().policyUrl());
        String exported = watcher.incidentJson(clock.wall, clock.wall + 1);
        assertTrue(exported.contains("/token/synthetic-secret"));
        assertFalse(exported.contains("secret-query"), "the query is not part of the route identity");
        assertFalse(exported.contains("spoofed.invalid"));
        assertTrue(watcher.overlays().toString().contains("/token/synthetic-secret"));
        Endpoint actual = endpoint(watcher, "/token/synthetic-secret");
        assertEquals(endpoint.hostKey(), actual.hostKey());
        assertEquals(endpoint.pathKeys(), actual.pathKeys());
    }

    @Test void safeNoQueryPolicyUrlIsOnlyAnActualServiceDraftHint() {
        ResponseWatcher watcher = watcher(limits(0, null, null), new Clock());
        Endpoint safe = endpoint(watcher, "/report?q=one");
        assertEquals("https://example.test/report", safe.policyUrl());
        Endpoint bad = endpoint(watcher, "GET", "example.test", 443, true, "/a b",
                "unused", List.of("/a b"));
        assertEquals("example.test", bad.host());
        assertEquals("/a b", bad.path(), "an unfaithful ordinary path is displayed as-is");
        assertEquals("", bad.policyUrl(), "...but never drafted");
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

    // ---- 0.2.0: optional circuit, exact 5xx exceptions, explicit OFF/ON generations ----
    private static final GuardConfig.ProbePath EXPECTED = new GuardConfig.ProbePath("https", "example.test", 443, "/expected-error");
    private static Limits exceptions(Limits l, List<GuardConfig.ProbePath> routes) {
        return new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), l.circuit5xx(),
                l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(), routes);
    }
    private static Endpoint post(ResponseWatcher watcher, String path) {
        String raw = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        return endpoint(watcher, "POST", "example.test", 443, true, path, "https://example.test" + path, List.of(raw));
    }

    @Test void excludedRoute5xxNeverOpensTheCircuitButOrdinaryRoutesStillDo() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(exceptions(limits(0, new Circuit5xx(60_000, 2, 60_000, 1), null), List.of(EXPECTED)), clock);
        for (int i = 0; i < 5; i++) {
            respond(watcher, endpoint(watcher, "/expected-error"), 503);
            respond(watcher, endpoint(watcher, "/expected-error?variant=" + i), 500);
            respond(watcher, post(watcher, "/expected-error"), 502);
        }
        assertEquals(0, number(watcher, "circuits"), "exception 5xx adds no failure sample");
        respond(watcher, endpoint(watcher, "/x"), 503);
        assertEquals(0, number(watcher, "circuits"));
        respond(watcher, endpoint(watcher, "/x"), 503);
        assertEquals(1, number(watcher, "circuits"), "ordinary routes still trip");
        assertEquals("CIRCUIT_OPEN", watcher.check(endpoint(watcher, "/x"), false).reason());
    }

    @Test void openCircuitAdmitsOnlyTheExactExceptionForEveryMethodWithoutHealingReopeningOrProbeState() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(exceptions(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), List.of(EXPECTED)), clock);
        respond(watcher, endpoint(watcher, "/x"), 503);
        long expires = watcher.overlays().getFirst().expiresAt();
        assertEquals("CIRCUIT_OPEN", watcher.check(endpoint(watcher, "/x"), false).reason());
        assertEquals("CIRCUIT_OPEN", watcher.check(post(watcher, "/x"), false).reason());
        for (Endpoint exact : List.of(endpoint(watcher, "/expected-error"), post(watcher, "/expected-error"),
                endpoint(watcher, "/expected-error?q=%zz"))) {
            assertTrue(watcher.check(exact, false).allowed());
            Ticket ticket = watcher.commit(exact, false, "");
            assertFalse(ticket.halfOpen(), "an exception is never the half-open lease");
            assertEquals(0, number(watcher, "halfOpen"));
            watcher.observe(ticket, 200, 0);
            assertEquals(1, number(watcher, "circuits"), "exception success cannot heal");
            respond(watcher, exact, 503);
            assertEquals(expires, watcher.overlays().getFirst().expiresAt(), "exception 5xx cannot reopen/extend");
        }
        clock.advance(1_000);
        respond(watcher, endpoint(watcher, "/expected-error"), 503); // right at half-open eligibility
        Ticket probe = watcher.commit(endpoint(watcher, "/x"), false, "");
        assertTrue(probe.halfOpen(), "exceptions consumed no probe cadence");
        watcher.observe(probe, 200, 0);
        assertEquals(0, number(watcher, "circuits"));
    }

    @Test void wrongServiceAmbiguousOrIncompleteRoutesNeverGainTheException() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(exceptions(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null),
                List.of(EXPECTED, new GuardConfig.ProbePath("https", "other.test", 443, "/x"))), clock);
        respond(watcher, endpoint(watcher, "/x"), 503);
        // Other actual services get their own open circuit; the exception names only https://example.test:443.
        respond(watcher, endpoint(watcher, "GET", "example.test", 80, false, "/x", "http://example.test/x", List.of("/x")), 503);
        respond(watcher, endpoint(watcher, "GET", "example.test", 8443, true, "/x", "https://example.test:8443/x", List.of("/x")), 503);
        List<Endpoint> denied = new ArrayList<>(List.of(
                endpoint(watcher, "GET", "example.test", 80, false, "/expected-error", "http://example.test/expected-error", List.of("/expected-error")),
                endpoint(watcher, "GET", "example.test", 8443, true, "/expected-error", "https://example.test:8443/expected-error", List.of("/expected-error")),
                endpoint(watcher, "/Expected-Error"), endpoint(watcher, "/expected-error/"), endpoint(watcher, "/expected-errorx")));
        for (String alias : List.of("/expected-error;m", "/expected-error%2f", "/%65xpected-error", "/./expected-error",
                "//expected-error", "/x/../expected-error", "/expected-error%zz")) {
            denied.add(endpoint(watcher, "GET", "example.test", 443, true, alias, "https://example.test" + alias,
                    PolicyEngine.routingPaths(new RequestData("GET", "https://example.test" + alias, "example.test", 443, true, List.of(), new byte[0]))));
        }
        for (Endpoint endpoint : denied) assertEquals("CIRCUIT_OPEN", watcher.check(endpoint, false).reason(), endpoint.path());
        // A fuzzed Host header neither removes the actual-service exception nor grants another service's.
        RequestData fuzzed = new RequestData("GET", "https://example.test/expected-error", "example.test", 443, true,
                List.of(new RequestData.Header("Host", "other.test")), new byte[0]);
        assertTrue(watcher.check(watcher.endpoint(fuzzed, List.of("/expected-error")), false).allowed());
        RequestData spoof = new RequestData("GET", "https://example.test/x", "example.test", 443, true,
                List.of(new RequestData.Header("Host", "other.test")), new byte[0]);
        assertEquals("CIRCUIT_OPEN", watcher.check(watcher.endpoint(spoof, List.of("/x")), false).reason());
        assertFalse(watcher.check(new Endpoint("x", List.of("y"), "example.test", "/expected-error", ""), false).allowed(),
                "a public display projection can never carry the privilege");
    }

    @Test void liveExceptionChangesAffectOnlyNewFinalCommitsAndNeverRewriteOldClassification() throws Exception {
        Clock clock = new Clock();
        Limits on = limits(0, new Circuit5xx(60_000, 2, 60_000, 1), null);
        ResponseWatcher watcher = watcher(on, clock);
        Ticket ordinary = watcher.commit(endpoint(watcher, "/expected-error"), false, ""); // classified before the exception exists
        watcher.update(exceptions(on, List.of(EXPECTED)));
        Ticket excluded = watcher.commit(endpoint(watcher, "/expected-error"), false, "");
        watcher.update(on); // removed again
        watcher.observe(excluded, 503, 0);
        assertEquals(0, number(watcher, "circuits"));
        watcher.observe(ordinary, 503, 0);
        assertEquals(0, number(watcher, "circuits"), "one ordinary sample so far");
        respond(watcher, endpoint(watcher, "/expected-error"), 503);
        assertEquals(1, number(watcher, "circuits"), "the excluded sample was never counted; removal restores normal admission");
        Endpoint exact = endpoint(watcher, "/expected-error");
        assertEquals("CIRCUIT_OPEN", watcher.check(exact, false).reason());
        watcher.update(exceptions(on, List.of(EXPECTED)));
        assertTrue(watcher.check(exact, false).allowed(), "adding an exception immediately admits NEW exact requests");
        assertEquals(1, number(watcher, "circuits"), "but never heals or erases the circuit");
        assertEquals("CIRCUIT_OPEN", watcher.check(endpoint(watcher, "/other"), false).reason());
        watcher.update(exceptions(new Limits(100, 100, Map.of(), 100, 100, 1_000, 1_000, 1_000, 0, 1_000,
                new Circuit5xx(30_000, 9, 30_000, 1), null, 0, false, List.of(), List.of()), List.of(EXPECTED)));
        assertEquals(1, number(watcher, "circuits"), "same-ON tuning does not reset circuit history");
    }

    @Test void explicitCircuitOffReleasesLogicalCircuitsImmediatelyButKeepsPhysicalOwnershipAndOtherProtections() throws Exception {
        Clock clock = new Clock();
        Limits on = limits(1, new Circuit5xx(1_000, 1, 1_000, 1), null);
        ResponseWatcher watcher = watcher(on, clock);
        Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/o", "https://other.test/o", List.of("/o"));
        respond(watcher, endpoint(watcher, "/x"), 503);
        Ticket active = watcher.commit(endpoint(watcher, "GET", "third.test", 443, true, "/a", "https://third.test/a", List.of("/a")), false, "");
        Ticket late = watcher.commit(endpoint(watcher, "GET", "third.test", 443, true, "/b", "https://third.test/b", List.of("/b")), false, "");
        clock.advance(1_000);
        watcher.abandon(late);
        watcherHeavy(watcher, other); // heavy overlay on another service (autoBlock 1 s from now)
        Ticket probe = watcher.commit(endpoint(watcher, "/x"), false, "");
        assertTrue(probe.halfOpen());
        assertEquals(1, number(watcher, "circuits")); assertEquals(1, number(watcher, "halfOpen"));
        Limits off = new Limits(on.globalRps(), on.perHostRps(), on.hostRps(), on.maxConcurrent(), on.maxQueued(), on.queueTimeoutMillis(),
                on.approvalTimeoutMillis(), on.requestTimeoutMillis(), on.perPathMaxResponseBytes(), on.autoBlockMillis(), null, on.fanout(),
                on.perIntentMaxRequests(), false, List.of(), List.of());
        watcher.update(off);
        assertEquals(0, number(watcher, "circuits")); assertEquals(0, number(watcher, "halfOpen"));
        assertTrue(watcher.overlays().stream().noneMatch(o -> o.reason().equals("CIRCUIT_OPEN")));
        assertTrue(watcher.check(endpoint(watcher, "/x"), false).allowed(), "OFF stops circuit gating at once");
        assertTrue(watcher.check(post(watcher, "/x"), false).allowed());
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(other, false).reason(), "unrelated protections stay");
        assertEquals(3, number(watcher, "activeTickets") + number(watcher, "lateTickets"), "physical ownership is not released");
        assertTrue(number(watcher, "lateTickets") >= 1);
        Ticket whileOff = watcher.commit(endpoint(watcher, "/x"), false, "");
        watcher.update(on); // OFF -> ON starts a fresh generation
        assertEquals(0, number(watcher, "circuits"));
        watcher.observe(whileOff, 503, 0);
        watcher.observe(active, 503, 0);
        watcher.observe(late, 503, 0);
        assertEquals(0, number(watcher, "circuits"), "pre-OFF and while-OFF callbacks cannot trip the new generation");
        respond(watcher, endpoint(watcher, "/x"), 503);
        assertEquals(1, number(watcher, "circuits"), "new generation works normally");
        long expires = watcher.overlays().stream().filter(o -> o.reason().equals("CIRCUIT_OPEN")).findFirst().orElseThrow().expiresAt();
        clock.advance(500);
        watcher.observe(probe, 503, 0);
        watcher.observe(probe, 200, 0);
        assertEquals(1, number(watcher, "circuits"), "old half-open callbacks can neither heal nor reopen the new circuit");
        assertEquals(expires, watcher.overlays().stream().filter(o -> o.reason().equals("CIRCUIT_OPEN")).findFirst().orElseThrow().expiresAt());
        assertEquals(0, number(watcher, "activeTickets") + number(watcher, "lateTickets"));
    }

    @Test void circuitTriggeredCapacityFenceIsASeparateConditionThatCircuitOffDoesNotClear() throws Exception {
        Clock clock = new Clock();
        Limits on = limits(0, new Circuit5xx(1_000, 1, 60_000, 1), null);
        ResponseWatcher watcher = new ResponseWatcher(on, clock::nano, clock::wall, 4, 8, 1);
        respond(watcher, endpoint(watcher, "/x"), 503); // no overlay slot: the shared capacity fence is installed instead
        assertEquals(0, number(watcher, "circuits"));
        assertEquals(true, watcher.snapshot().get("capacityBlocked"));
        watcher.update(limits(0, null, null));
        assertEquals(true, watcher.snapshot().get("capacityBlocked"), "its contributors are not attributable; it stays until expiry/release");
        ResponseWatcher.Gate gate = watcher.check(endpoint(watcher, "/x"), false);
        assertEquals("RESPONSE_WATCHER_CAPACITY", gate.reason());
        assertEquals(GuardState.CAPACITY, gate.guardState(), "not CIRCUIT_OPEN");
        assertEquals(List.of("RESPONSE_WATCHER_CAPACITY"), watcher.overlays().stream().map(ResponseWatcher.Overlay::reason).toList());
        clock.advance(60_000);
        assertTrue(watcher.check(endpoint(watcher, "/x"), false).allowed());
    }

    @Test void exceptionBypassesOnlyTheCircuitNotHeavyFanoutOrOmissionGates() throws Exception {
        Clock clock = new Clock();
        Limits on = exceptions(limits(1, new Circuit5xx(1_000, 1, 60_000, 1), null), List.of(EXPECTED));
        ResponseWatcher watcher = watcher(on, clock);
        respond(watcher, endpoint(watcher, "/x"), 503);
        Endpoint exact = endpoint(watcher, "/expected-error");
        watcherHeavy(watcher, exact);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(exact, false).reason());
        Limits fanned = exceptions(limits(0, new Circuit5xx(1_000, 1, 60_000, 1), new Fanout(60_000, 2, FanoutAction.BLOCK)), List.of(EXPECTED));
        ResponseWatcher fanout = watcher(fanned, clock);
        respond(fanout, endpoint(fanout, "/expected-error"), 200);
        assertThrows(ResponseWatcher.Rejected.class, () -> fanout.commit(endpoint(fanout, "/y"), false, ""));
        assertEquals("FANOUT_SUSPECTED", fanout.check(endpoint(fanout, "/expected-error"), false).reason());
    }

    // ---- 0.2.0 selective automatic-block controls ----
    private static Limits controls(Limits l, boolean heavy, List<GuardConfig.ProbePath> fanoutExceptions) {
        return new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), l.circuit5xx(),
                l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(),
                l.circuit5xxExceptions(), heavy, fanoutExceptions);
    }
    private static Limits with(Limits l, Circuit5xx circuit, Fanout fanout) {
        return new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), circuit,
                fanout, l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(),
                l.circuit5xxExceptions(), l.heavyResponseEnabled(), l.fanoutExceptions());
    }
    private static final GuardConfig.ProbePath BATCH = new GuardConfig.ProbePath("https", "example.test", 443, "/batch");

    @Test void heavyMasterOffStopsDefaultAndRouteLimitsImmediatelyWithoutTouchingOtherState() throws Exception {
        Clock clock = new Clock();
        Limits on = withPaths(limits(1, null, null), List.of(new PathByteLimit("https", "example.test", 443, "/route", 20)));
        ResponseWatcher watcher = watcher(on, clock);
        Endpoint x = endpoint(watcher, "/x");
        watcher.observe(watcher.commit(x, false, ""), 200, 2);
        Ticket held = watcher.commit(endpoint(watcher, "/held"), false, "");
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(x, false).reason());
        Limits off = controls(on, false, List.of());
        watcher.update(off);
        assertTrue(watcher.check(x, false).allowed(), "master OFF ends heavy gating at once");
        assertTrue(watcher.overlays().isEmpty());
        assertEquals(1, number(watcher, "activeTickets"), "physical ownership untouched");
        watcher.observe(watcher.commit(x, false, ""), 200, 999);
        watcher.observe(watcher.commit(endpoint(watcher, "/route"), false, ""), 200, 999);
        assertTrue(watcher.overlays().isEmpty(), "neither the default nor a positive route limit applies while OFF");
        assertEquals(1, off.perPathMaxResponseBytes()); assertEquals(20, off.heavyPathLimits().getFirst().maxBytes());
        assertFalse(watcher.candidates().isEmpty(), "scalar diagnostics are still recorded");
        watcher.observe(held, 200, 0);
    }

    @Test void heavyOffOnFencesPreOffWhileOffAndLateCallbacksButNewEligibleFlightsActuate() throws Exception {
        Clock clock = new Clock();
        Limits on = limits(1, null, null);
        ResponseWatcher watcher = watcher(on, clock);
        Ticket before = watcher.commit(endpoint(watcher, "/a"), false, "");
        Ticket late = watcher.commit(endpoint(watcher, "/b"), false, "");
        watcher.update(controls(on, false, List.of()));
        Ticket whileOff = watcher.commit(endpoint(watcher, "/c"), false, "");
        clock.advance(1_000);
        watcher.abandon(late);
        watcher.update(on);
        watcher.observe(before, 200, 99);
        watcher.observe(late, 200, 99);
        watcher.observe(whileOff, 200, 99);
        assertTrue(watcher.overlays().isEmpty(), "old generations cannot actuate the re-enabled detector");
        watcher.observe(watcher.commit(endpoint(watcher, "/d"), false, ""), 200, 99);
        assertEquals(List.of("HEAVY_ENDPOINT_AUTO_BLOCKED"), watcher.overlays().stream().map(ResponseWatcher.Overlay::reason).toList());
        // a flight committed while its effective bound was zero is not made eligible by a later edit
        ResponseWatcher zero = watcher(limits(0, null, null), clock);
        Ticket unbounded = zero.commit(endpoint(zero, "/z"), false, "");
        zero.update(limits(1, null, null));
        zero.observe(unbounded, 200, 99);
        assertTrue(zero.overlays().isEmpty());
    }

    @Test void explicitZeroRouteLimitBypassesOnlyHeavyGatingImmediatelyButAPositiveAliasStillWins() throws Exception {
        Clock clock = new Clock();
        Limits on = limits(1, null, null);
        ResponseWatcher watcher = watcher(on, clock);
        Endpoint big = endpoint(watcher, "GET", "example.test", 443, true, "/big", "https://example.test/big", List.of("/big"));
        watcher.observe(watcher.commit(big, false, ""), 200, 99);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(big, false).reason());
        watcher.update(withPaths(on, List.of(new PathByteLimit("https", "example.test", 443, "/big", 0))));
        assertTrue(watcher.check(big, false).allowed(), "a size-0 exception bypasses the retained heavy overlay at once");
        assertEquals(1, watcher.overlays().size(), "the overlay is retained (it may still protect another view)");
        Endpoint aliased = endpoint(watcher, "GET", "example.test", 443, true, "/big", "https://example.test/big", List.of("/big", "/alias"));
        watcher.update(withPaths(on, List.of(new PathByteLimit("https", "example.test", 443, "/big", 0),
                new PathByteLimit("https", "example.test", 443, "/alias", 5))));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(aliased, false).reason(), "positive beats zero among aliases");
        watcher.update(limits(0, null, null));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(big, false).reason(), "a default 0 is not an exception: retained overlays keep their expiry");
    }

    @Test void fanoutExceptionAdmissionsCreateNoCountSeenRetentionOrOmissionDebt() throws Exception {
        Clock clock = new Clock();
        Limits on = controls(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)), true, List.of(BATCH));
        ResponseWatcher watcher = new ResponseWatcher(on, clock::nano, clock::wall, 4, 1, 4);
        for (int i = 0; i < 5; i++) {
            respond(watcher, endpoint(watcher, "/batch?page=" + i), 200);
            respond(watcher, post(watcher, "/batch"), 200);
        }
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(0, number(watcher, "fanoutWarnings"));
        assertEquals(0, number(watcher, "paths"), "no fan-out path retention");
        respond(watcher, endpoint(watcher, "/a"), 200);
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"), "ordinary routes still count");
        watcher.check(endpoint(watcher, "/batch"), false);
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"), "advisory checks have no side effect");
    }

    @Test void fanoutExceptionBypassesServiceBlockAndPauseButNeverEnforcingOmissionDebt() throws Exception {
        for (FanoutAction action : List.of(FanoutAction.BLOCK, FanoutAction.PAUSE)) {
            Clock clock = new Clock();
            Limits on = controls(limits(0, null, new Fanout(60_000, 2, action)), true, List.of(BATCH));
            ResponseWatcher watcher = watcher(on, clock);
            respond(watcher, endpoint(watcher, "/one"), 200);
            assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
            assertEquals("FANOUT_SUSPECTED", watcher.check(endpoint(watcher, "/three"), false).reason());
            respond(watcher, endpoint(watcher, "/batch"), 200);
            respond(watcher, post(watcher, "/batch?x=%zz"), 200);
            assertEquals("FANOUT_SUSPECTED", watcher.check(endpoint(watcher, "/three"), false).reason(), action.name());
            ResponseWatcher debt = new ResponseWatcher(controls(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)), true, List.of(BATCH)),
                    clock::nano, clock::wall, 4, 1, 4);
            respond(debt, endpoint(debt, "/a"), 200);
            respond(debt, endpoint(debt, "/b"), 200); // omitted: WARN debt, not enforcing
            assertTrue(debt.check(endpoint(debt, "/batch"), false).allowed());
            assertTrue(debt.check(endpoint(debt, "/c"), false).allowed(), "retained debt does not enforce under WARN");
            debt.update(controls(limits(0, null, new Fanout(60_000, 10, action)), true, List.of(BATCH)));
            assertEquals("RESPONSE_WATCHER_CAPACITY", debt.check(endpoint(debt, "/batch"), false).reason(), "an exception cannot bypass enforcing debt");
            clock.advance(60_000);
            assertTrue(debt.check(endpoint(debt, "/batch"), false).allowed(), "original deadline");
        }
    }

    @Test void warnFullSeenWithoutOmissionThenBlockAdmitsAnExcludedRouteWithoutSeenCountRetentionOrDebtWhileOrdinaryRoutesGetCapacity() throws Exception {
        Clock clock = new Clock();
        Limits warn = controls(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)), true, List.of(BATCH));
        ResponseWatcher watcher = new ResponseWatcher(warn, clock::nano, clock::wall, 4, 2, 4); // path capacity 2
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"), "WARN filled the slots exactly, nothing was omitted");
        watcher.update(controls(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK)), true, List.of(BATCH)));
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(endpoint(watcher, "/c"), false).reason(), "an ordinary new route has no Seen slot");
        assertTrue(watcher.check(endpoint(watcher, "/a"), false).allowed(), "an indexed identity keeps its slot");
        assertTrue(watcher.check(endpoint(watcher, "/batch"), false).allowed(), "an excluded route needs no new Seen slot");
        Ticket excluded = watcher.commit(endpoint(watcher, "/batch?page=1"), false, "");
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"), "no Seen/mark was allocated");
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"), "no omission debt was created");
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
        assertEquals(1, number(watcher, "paths"), "only the real in-flight physical path reservation, no fan-out retention");
        watcher.observe(excluded, 200, 0);
        assertEquals(0, number(watcher, "paths"));
        assertEquals(2, number(watcher, "fanoutHistoryIndexed"));
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(endpoint(watcher, "/c"), false).reason());
    }

    @Test void fanoutExceptionNeverGrantsAnAliasAmbiguousOtherServiceOrHostHeaderPrivilegeWhileAnEpisodeIsOpen() throws Exception {
        Clock clock = new Clock();
        Limits block = controls(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)), true, List.of(BATCH, new GuardConfig.ProbePath("https", "other.test", 443, "/batch")));
        ResponseWatcher watcher = watcher(block, clock);
        // an episode on example.test:443 and on the three other actual services used below
        for (String[] service : new String[][]{{"example.test", "443", "true"}, {"example.test", "80", "false"}, {"example.test", "8443", "true"}}) {
            int port = Integer.parseInt(service[1]); boolean secure = Boolean.parseBoolean(service[2]);
            String scheme = secure ? "https" : "http";
            respond(watcher, endpoint(watcher, "GET", service[0], port, secure, "/one", scheme + "://" + service[0] + ":" + port + "/one", List.of("/one")), 200);
            int p = port;
            assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "GET", service[0], p, secure, "/two", scheme + "://" + service[0] + ":" + p + "/two", List.of("/two")), false, ""));
        }
        List<Endpoint> denied = new ArrayList<>(List.of(
                endpoint(watcher, "GET", "example.test", 80, false, "/batch", "http://example.test/batch", List.of("/batch")),
                endpoint(watcher, "GET", "example.test", 8443, true, "/batch", "https://example.test:8443/batch", List.of("/batch")),
                endpoint(watcher, "/Batch"), endpoint(watcher, "/batch/"), endpoint(watcher, "/batchx")));
        for (String alias : List.of("/batch;m", "/batch%2f", "/%62atch", "/./batch", "//batch", "/x/../batch", "/batch%zz", "/c/%2c")) {
            denied.add(endpoint(watcher, "GET", "example.test", 443, true, alias, "https://example.test" + alias,
                    PolicyEngine.routingPaths(new RequestData("GET", "https://example.test" + alias, "example.test", 443, true, List.of(), new byte[0]))));
        }
        for (Endpoint endpoint : denied) assertEquals("FANOUT_SUSPECTED", watcher.check(endpoint, false).reason(), endpoint.path());
        // Host header fuzz: the ACTUAL service decides, in both directions
        RequestData fuzzed = new RequestData("GET", "https://example.test/batch", "example.test", 443, true,
                List.of(new RequestData.Header("Host", "attacker.invalid")), new byte[0]);
        assertTrue(watcher.check(watcher.endpoint(fuzzed, List.of("/batch")), false).allowed(), "the actual-service exception still applies");
        RequestData spoof = new RequestData("GET", "https://example.test:8443/batch", "example.test", 8443, true,
                List.of(new RequestData.Header("Host", "example.test")), new byte[0]);
        assertEquals("FANOUT_SUSPECTED", watcher.check(watcher.endpoint(spoof, List.of("/batch")), false).reason(),
                "a matching Host header on another actual service grants nothing");
        assertFalse(watcher.check(new Endpoint("x", List.of("y"), "example.test", "/batch", ""), false).allowed(), "a public display projection never carries the privilege");
    }

    @Test void oldOrdinaryMarksKeepTheirOriginalWindowWhenAnExceptionIsAddedOrRemoved() throws Exception {
        Clock clock = new Clock();
        Limits warn = limits(0, null, new Fanout(10_000, 10, FanoutAction.WARN));
        ResponseWatcher watcher = watcher(warn, clock);
        Ticket ordinary = watcher.commit(endpoint(watcher, "/batch"), false, "");
        watcher.update(controls(warn, true, List.of(BATCH)));
        clock.advance(5_000);
        watcher.observe(ordinary, 200, 0);
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"), "the earlier ordinary mark is confirmed, not rewritten");
        respond(watcher, endpoint(watcher, "/batch"), 200);
        watcher.update(warn);
        clock.advance(4_999);
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"));
        clock.advance(1);
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"), "expires at the ORIGINAL window; excluded admission left no mark");
    }

    @Test void fanoutOffOrWarnDetachesEnforcementAtOnceKeepsHistoryAndBlockPauseSwitchKeepsTheEpisode() throws Exception {
        for (String route : List.of("OFF", "WARN")) {
            Clock clock = new Clock();
            Limits block = limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK));
            ResponseWatcher watcher = watcher(block, clock);
            respond(watcher, endpoint(watcher, "/one"), 200);
            assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
            long indexed = number(watcher, "fanoutHistoryIndexed");
            watcher.update(route.equals("OFF") ? with(block, null, null) : with(block, null, new Fanout(60_000, 2, FanoutAction.WARN)));
            assertTrue(watcher.check(endpoint(watcher, "/three"), false).allowed(), route);
            assertTrue(watcher.overlays().isEmpty(), route);
            assertEquals(indexed, number(watcher, "fanoutHistoryIndexed"), "Seen history is preserved, not cleared");
            watcher.update(block);
            assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/four"), false, ""),
                    "re-enabling may retrigger from live retained history at a NEW admission");
        }
        Clock clock = new Clock();
        Limits pause = limits(0, null, new Fanout(60_000, 2, FanoutAction.PAUSE));
        ResponseWatcher watcher = watcher(pause, clock);
        respond(watcher, endpoint(watcher, "/one"), 200);
        assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
        ResponseWatcher.Overlay before = watcher.overlays().getFirst();
        Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok", "https://other.test/ok", List.of("/ok"));
        assertFalse(watcher.check(other, false).allowed());
        watcher.update(with(pause, null, new Fanout(60_000, 2, FanoutAction.BLOCK)));
        assertTrue(watcher.check(other, false).allowed(), "PAUSE -> BLOCK is service-local now");
        assertEquals(false, watcher.snapshot().get("automaticPause"));
        assertEquals(before.id(), watcher.overlays().getFirst().id()); assertEquals(before.expiresAt(), watcher.overlays().getFirst().expiresAt());
        watcher.update(pause);
        assertFalse(watcher.check(other, false).allowed(), "BLOCK -> PAUSE is global again, same id/TTL");
        assertEquals(before.expiresAt(), watcher.overlays().getFirst().expiresAt());
        watcher.update(with(pause, null, new Fanout(60_000, 2, FanoutAction.WARN)));
        assertEquals(false, watcher.snapshot().get("automaticPause"), "WARN never keeps an automatic pause");
        assertTrue(watcher.check(other, false).allowed());
    }

    @Test void sharedCapacityFenceIsRetainedWhileAnyBlockingActuatorIsOnAndClearedOnlyWhenAllAreNonEnforcing() throws Exception {
        Circuit5xx circuit = new Circuit5xx(1_000, 1, 60_000, 1);
        for (String producer : List.of("HEAVY", "CIRCUIT", "FANOUT")) {
            Clock clock = new Clock();
            Limits all = limits(1, circuit, new Fanout(60_000, 2, FanoutAction.BLOCK));
            ResponseWatcher watcher = new ResponseWatcher(all, clock::nano, clock::wall, 4, 8, 1); // no overlay slot
            Ticket held = watcher.commit(endpoint(watcher, "GET", "held.test", 443, true, "/h", "https://held.test/h", List.of("/h")), false, "");
            switch (producer) {
                case "HEAVY" -> watcher.observe(watcher.commit(endpoint(watcher, "/x"), false, ""), 200, 99);
                case "CIRCUIT" -> respond(watcher, endpoint(watcher, "/x"), 503);
                default -> {
                    respond(watcher, endpoint(watcher, "/x"), 200);
                    assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/y"), false, ""));
                }
            }
            assertEquals(true, watcher.snapshot().get("capacityBlocked"), producer);
            Limits heavyOff = controls(all, false, List.of());
            watcher.update(heavyOff);
            assertEquals(true, watcher.snapshot().get("capacityBlocked"), producer + ": circuit/fanout still enforce");
            watcher.update(with(heavyOff, null, new Fanout(60_000, 2, FanoutAction.BLOCK)));
            assertEquals(true, watcher.snapshot().get("capacityBlocked"), producer + ": fanout BLOCK still enforces");
            Limits legacyZero = with(limits(0, null, null), null, null); // heavy master ON with bytes 0 is NOT OFF
            ResponseWatcher legacy = new ResponseWatcher(all, clock::nano, clock::wall, 4, 8, 1);
            respond(legacy, endpoint(legacy, "/x"), 503);
            legacy.update(legacyZero);
            assertEquals(true, legacy.snapshot().get("capacityBlocked"), "legacy bytes 0 keeps the fence");
            watcher.update(with(heavyOff, null, new Fanout(60_000, 2, FanoutAction.WARN)));
            assertEquals(false, watcher.snapshot().get("capacityBlocked"), producer + ": all automatic actuators are non-enforcing");
            assertTrue(watcher.check(endpoint(watcher, "/z"), false).allowed());
            assertEquals(1, number(watcher, "activeTickets"), "real ownership untouched");
            watcher.observe(held, 503, 999);
            assertEquals(false, watcher.snapshot().get("capacityBlocked"), "no late producer can recreate it");
            watcher.update(all);
            assertEquals(false, watcher.snapshot().get("capacityBlocked"), "re-enable is not a resurrection");
        }
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
        // Same-ON save (0.2.0: an explicit circuit OFF would logically reset the circuit instead).
        watcher.update(withTimeout(limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null), 60_000));
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

    @Test void fanoutPauseIsGlobalAutomaticOverlayNotOperatorFlagAndExplicitDisableEndsIt() throws Exception {
        // 0.2.0 revision: an explicit fan-out OFF now ends the automatic PAUSE at once (history preserved).
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(1_000, 2, FanoutAction.PAUSE)), clock);
        watcher.commit(endpoint(watcher, "/one"), false, "");
        assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/two"), false, ""));
        Endpoint other = endpoint(watcher, "GET", "other.test", 443, true, "/ok",
                "https://other.test/ok", List.of("/ok"));
        assertFalse(watcher.check(other, true).allowed());
        assertEquals(true, watcher.snapshot().get("automaticPause"));
        watcher.update(limits(0, null, null));
        assertTrue(watcher.check(other, false).allowed());
        assertEquals(false, watcher.snapshot().get("automaticPause"));
        assertEquals(1, number(watcher, "fanoutHistoryIndexed"), "pending history is preserved");
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
                clock::nano, clock::wall, 4, 2, 4);
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
                clock::nano, clock::wall, 4, 2, 4);
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
                clock::nano, clock::wall, 4, 2, 4);
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
                clock::nano, clock::wall, 4, 2, 4);
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
                    clock::nano, clock::wall, 4, 2, 4);
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

    @Test void enforcingOmissionDiagnosticFollowsConfiguredActionAndMonotonicDeadline() throws Exception {
        Clock clock = new Clock();
        clock.nanos = Long.MAX_VALUE - 30_000_000_000L; // the 60 s debt deadline crosses the nano wrap
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 2, 4);
        assertEquals(false, watcher.snapshot().get("fanoutHistoryEnforcing"));
        assertEquals(0, number(watcher, "fanoutHistoryRemainingMillis"));
        for (String path : List.of("/a", "/b", "/c")) respond(watcher, endpoint(watcher, path), 200);
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(false, watcher.snapshot().get("fanoutHistoryEnforcing"), "WARN retains debt without enforcing it");
        assertEquals(60_000, number(watcher, "fanoutHistoryRemainingMillis"));
        Endpoint existing = endpoint(watcher, "/a");
        for (FanoutAction action : List.of(FanoutAction.BLOCK, FanoutAction.PAUSE)) {
            watcher.update(limits(0, null, new Fanout(60_000, 10, action)));
            assertEquals(true, watcher.snapshot().get("fanoutHistoryEnforcing"), action.name());
            assertEquals(false, watcher.snapshot().get("capacityBlocked"), "existing key keeps its meaning");
            assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(existing, false).reason());
        }
        watcher.update(limits(0, null, null));
        assertEquals(false, watcher.snapshot().get("fanoutHistoryEnforcing"), "disabled detector");
        assertEquals(60_000, number(watcher, "fanoutHistoryRemainingMillis"), "retained, not reset");
        assertTrue(watcher.check(existing, false).allowed());
        watcher.update(limits(0, null, new Fanout(1_000, 10, FanoutAction.WARN)));
        clock.wall -= 50_000; // wall regression is diagnostic only
        clock.nanos += 59_999_500_000L;
        assertEquals(1, number(watcher, "fanoutHistoryRemainingMillis"), "shorter window/wall regression cannot shorten; rounds up");
        watcher.update(limits(0, null, new Fanout(1_000, 10, FanoutAction.BLOCK)));
        assertEquals(true, watcher.snapshot().get("fanoutHistoryEnforcing"), "re-enabling before the deadline restores enforcement");
        assertFalse(watcher.check(existing, false).allowed());
        clock.nanos += 500_000L;
        assertEquals(false, watcher.snapshot().get("fanoutHistoryEnforcing"), "exact original deadline");
        assertEquals(0, number(watcher, "fanoutHistoryRemainingMillis"));
        assertTrue(watcher.check(existing, false).allowed());
    }

    @Test void idleWarnHostHistoryIsReclaimedOnlyByCommitAndBecomesConservativeDebt() throws Exception {
        Clock clock = new Clock();
        clock.nanos = Long.MAX_VALUE - 30_000_000_000L; // the original 60 s deadline crosses the nano wrap
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 2, 8, 4);
        long start = clock.wall;
        respond(watcher, service(watcher, 443), 200);
        respond(watcher, service(watcher, 8443), 200);
        Endpoint third = service(watcher, 9443);
        clock.advance(5_000);
        assertTrue(watcher.check(third, false).allowed(), "idle diagnostic history must not exhaust host capacity");
        assertEquals(2, number(watcher, "hosts"), "check() never reclaims");
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"), "check() never creates debt");
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
        Ticket ticket = watcher.commit(third, false, "");
        assertEquals(2, number(watcher, "hosts"));
        assertEquals(1, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(true, watcher.snapshot().get("fanoutHistoryIncomplete"));
        assertEquals(start + 60_000, number(watcher, "fanoutHistoryIncompleteUntil"));
        assertEquals(55_000, number(watcher, "fanoutHistoryRemainingMillis"));
        assertEquals(false, watcher.snapshot().get("fanoutHistoryEnforcing"), "WARN keeps debt without enforcing it");
        watcher.observe(ticket, 200, 0);
        watcher.update(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK)));
        assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(service(watcher, 443), false).reason());
        assertEquals(true, watcher.snapshot().get("fanoutHistoryEnforcing"));
        clock.advance(54_999);
        assertFalse(watcher.check(service(watcher, 443), false).allowed());
        clock.advance(1);
        assertTrue(watcher.check(service(watcher, 443), false).allowed(), "exact original deadline");
    }

    @Test void hostReclaimAccountsEveryDiscardedHistoryWithItsOwnDeadlineAndKeepsLongerExistingDebt() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 1, 8, 4);
        long start = clock.wall;
        respond(watcher, endpoint(watcher, "/a"), 200);
        clock.advance(10_000);
        respond(watcher, endpoint(watcher, "/b"), 200);
        clock.advance(10_000);
        respond(watcher, endpoint(watcher, "/c"), 200);
        clock.advance(5_000);
        watcher.update(limits(0, null, new Fanout(2_000, 10, FanoutAction.WARN))); // later, shorter window
        respond(watcher, service(watcher, 8443), 200); // discards three confirmed histories
        assertEquals(3, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(start + 80_000, number(watcher, "fanoutHistoryIncompleteUntil"), "largest ORIGINAL window");
        respond(watcher, service(watcher, 9443), 200); // shorter discarded history cannot shorten debt
        assertEquals(4, number(watcher, "fanoutHistoryOmitted"));
        assertEquals(start + 80_000, number(watcher, "fanoutHistoryIncompleteUntil"));
        assertEquals(55_000, number(watcher, "fanoutHistoryRemainingMillis"));
    }

    @Test void hostReclaimRefusesAnyHostWithProtectedOrUnresolvedState() throws Exception {
        Circuit5xx circuit = new Circuit5xx(1_000, 1, 1_000, 1);
        Circuit5xx slowCircuit = new Circuit5xx(1_000, 3, 1_000, 1);
        // (0.2.0: an enforcing episode can no longer coexist with WARN/disabled fan-out, so ENFORCING_MODE covers it.)
        for (String route : List.of("IN_FLIGHT", "LATE", "CIRCUIT", "PROBE_CADENCE", "FAILURE_SAMPLE", "ENFORCING_MODE")) {
            Clock clock = new Clock();
            Limits warn = limits(0, route.equals("FAILURE_SAMPLE") ? slowCircuit : circuit, new Fanout(60_000, route.equals("BLOCK_EPISODE") ? 2 : 10, FanoutAction.WARN));
            ResponseWatcher watcher = new ResponseWatcher(warn, clock::nano, clock::wall, 1, 8, 4);
            Endpoint first = service(watcher, 443);
            switch (route) {
                case "IN_FLIGHT" -> watcher.commit(first, false, "");
                case "LATE" -> {
                    Ticket ticket = watcher.commit(first, false, "");
                    clock.advance(1_000);
                    watcher.abandon(ticket);
                }
                case "CIRCUIT" -> respond(watcher, first, 503);
                case "PROBE_CADENCE" -> {
                    respond(watcher, first, 503);
                    clock.advance(1_000);
                    Ticket probe = watcher.commit(first, false, "");
                    assertTrue(probe.halfOpen());
                    watcher.observe(probe, 200, 0);
                    assertEquals(0, number(watcher, "circuits"));
                }
                case "FAILURE_SAMPLE" -> respond(watcher, first, 503);
                case "BLOCK_EPISODE" -> {
                    watcher.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)));
                    respond(watcher, endpoint(watcher, "/a"), 200);
                    assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(endpoint(watcher, "/b"), false, ""));
                    watcher.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)));
                }
                default -> {
                    respond(watcher, first, 200);
                    watcher.update(limits(0, null, new Fanout(60_000, 10, FanoutAction.BLOCK)));
                }
            }
            long hosts = number(watcher, "hosts");
            Endpoint other = service(watcher, 9443);
            assertEquals("RESPONSE_WATCHER_CAPACITY", watcher.check(other, false).reason(), route);
            assertThrows(ResponseWatcher.Rejected.class, () -> watcher.commit(other, false, ""), route);
            assertEquals(hosts, number(watcher, "hosts"), route);
            assertEquals(0, number(watcher, "fanoutHistoryOmitted"), route + ": nothing was discarded");
        }
    }

    @Test void reclaimedLiveWarnLatchRetiresCurrentCountButKeepsOriginalEventWithoutInventedDebt() throws Exception {
        Clock clock = new Clock();
        // Seen window (5 s) is shorter than the WARN episode lifetime (autoBlock 60 s).
        Limits warn = new Limits(100, 100, Map.of(), 100, 100, 1_000, 1_000, 1_000, 0, 60_000, null,
                new Fanout(5_000, 2, FanoutAction.WARN), 0, false, List.of(), List.of());
        ResponseWatcher watcher = new ResponseWatcher(warn, clock::nano, clock::wall, 1, 8, 4);
        long start = clock.wall;
        respond(watcher, endpoint(watcher, "/a"), 200);
        respond(watcher, endpoint(watcher, "/b"), 200);
        assertEquals(1, number(watcher, "fanoutWarnings"));
        clock.advance(6_000); // Seen histories expired, the diagnostic episode is still live
        assertEquals(0, number(watcher, "fanoutHistoryIndexed"));
        assertEquals(1, number(watcher, "hosts"));
        respond(watcher, service(watcher, 8443), 200);
        assertEquals(1, number(watcher, "hosts"), "host bound kept by retiring the purely diagnostic latch");
        assertEquals(0, number(watcher, "fanoutWarnings"), "live count describes retained hosts only");
        assertEquals(0, number(watcher, "fanoutHistoryOmitted"), "no path debt is invented when no Seen history is discarded");
        assertEquals(false, watcher.snapshot().get("fanoutHistoryIncomplete"));
        JsonNode events = json(watcher.incidentJson(start, clock.wall + 1)).get("events");
        assertEquals(1, events.size());
        assertEquals("FANOUT_SUSPECTED", events.get(0).get("kind").asText(), "the original event ring is not cleared");
    }

    @Test void enforcingRejectsNewIdentityWithoutHistorySlotButKeepsIndexedIdentities() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, new Fanout(60_000, 10, FanoutAction.WARN)),
                clock::nano, clock::wall, 4, 4, 4);
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
                new Fanout(60_000, 10, FanoutAction.WARN)), clock::nano, clock::wall, 4, 2, 4);
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
                clock::nano, clock::wall, 4, 1, 4);
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
                clock::nano, clock::wall, 4, 3, 4);
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
                clock::nano, clock::wall, 4, 1, 4);
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
                clock::nano, clock::wall, 4, 3, 4);
        respond(watcher, endpoint(watcher, "/a"), 200);
        watcherHeavy(watcher, endpoint(watcher, "/heavy"));
        watcher.update(limits(1, null, new Fanout(60_000, 10, FanoutAction.WARN)));
        respond(watcher, endpoint(watcher, "/b"), 200);
        assertEquals(2, number(watcher, "paths"), "enforcing-era /a and heavy remain pinned, WARN /b is not");
        assertFalse(watcher.check(endpoint(watcher, "/heavy"), true).allowed());
        ResponseWatcher blocked = watcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)), clock);
        respond(blocked, endpoint(blocked, "/one"), 200);
        assertThrows(ResponseWatcher.Rejected.class, () -> blocked.commit(endpoint(blocked, "/two"), false, ""));
        // 0.2.0 revision: BLOCK -> WARN ends the enforcing episode at once; history is kept, so a NEW
        // admission after re-entering BLOCK can legitimately retrigger from the retained Seen entries.
        blocked.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)));
        assertTrue(blocked.check(endpoint(blocked, "/three"), false).allowed());
        assertTrue(blocked.overlays().isEmpty());
        blocked.update(limits(0, null, new Fanout(60_000, 2, FanoutAction.BLOCK)));
        assertThrows(ResponseWatcher.Rejected.class, () -> blocked.commit(endpoint(blocked, "/three"), false, ""));
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

    @Test void diagnosticHistoryIsNotCapacityLimitedAndNeverReportsFictionalLoss() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(1, null, null), clock::nano, clock::wall, 4, 8, 8);
        long start = clock.wall;
        for (int i = 0; i < 3; i++) {
            Endpoint endpoint = endpoint(watcher, "/" + i);
            watcher.observe(watcher.commit(endpoint, false, ""), 500, 10 + i);
            clock.advance(1);
        }
        assertEquals(3, number(watcher, "events"));
        assertEquals(3, number(watcher, "observations"));
        assertEquals(false, watcher.snapshot().get("candidatesIncomplete"));
        JsonNode all = json(watcher.incidentJson(start, clock.wall));
        assertTrue(all.get("complete").asBoolean());
        assertFalse(all.at("/retention/eventsDropped").asBoolean());
        assertEquals(3, all.get("topBytes").size());
    }

    @Test @Timeout(120) void productionHistoryKeepsMoreThan4096EventsAndIsNotDayPrunedOrWindowCapped() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(1, null, null), clock);
        long start = clock.wall;
        Endpoint endpoint = endpoint(watcher, "/heavy");
        for (int i = 0; i < 4_097; i++) {
            watcherHeavy(watcher, endpoint); // a NEW heavy episode (event) each time, after the previous TTL ended
            clock.advance(1_000);
        }
        assertEquals(4_097, number(watcher, "events"));
        clock.advance(25L * 3_600_000);
        assertEquals(4_097, number(watcher, "events"), "no day pruning of diagnostic history");
        assertEquals(4_097, number(watcher, "observations"));
        JsonNode incident = json(assertDoesNotThrow(() -> watcher.incidentJson(start, clock.wall + 1), "incident window is not capped at 24h"));
        assertEquals(4_097, incident.get("events").size());
        assertTrue(incident.get("complete").asBoolean());
        assertEquals("UNTIL_CLEAR_PROJECT_OR_UNLOAD", incident.at("/retention/mode").asText());
        assertEquals(1, watcher.candidates().size());
    }

    @Test @Timeout(120) void productionHistoryKeepsMoreThan8192ObservationsAndTheirCandidateCount() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        long start = clock.wall;
        Endpoint endpoint = endpoint(watcher, "/same");
        for (int i = 0; i < 8_193; i++) { respond(watcher, endpoint, 200); if (i % 64 == 0) clock.advance(1); }
        assertEquals(8_193, number(watcher, "observations"));
        assertEquals(false, watcher.snapshot().get("candidatesIncomplete"));
        assertEquals(8_193, watcher.candidates().getFirst().count());
        JsonNode incident = json(watcher.incidentJson(start, clock.wall + 1));
        assertTrue(incident.get("complete").asBoolean());
        assertEquals(8_193, incident.at("/topBytes/0/count").asLong());
    }

    @Test void candidateDisplayKeepsTheActualServiceHostAndFullUntouchedPathNotTheFuzzedAuthority() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        String path = "/token/SYNTH-PATH-SECRET/" + "p".repeat(3_000);
        RequestData request = new RequestData("GET", "https://spoofed.invalid" + path + "?q=SYNTH-QUERY", "example.test", 443, true,
                List.of(new RequestData.Header("Host", "spoofed.invalid")), new byte[0]);
        respond(watcher, watcher.endpoint(request, List.of(path)), 200);
        ResponseWatcher.Candidate candidate = watcher.candidates().getFirst();
        assertEquals("example.test", candidate.host());
        assertEquals(path, candidate.path());
        assertEquals("https://example.test" + path, candidate.policyUrl());
    }

    @Test void clearEvidenceReleasesTheOriginalHostFromRetainedWarnEpisodesButKeepsTheOperationalEpisode() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, new Fanout(60_000, 2, FanoutAction.WARN)), clock);
        Ticket early = watcher.commit(endpoint(watcher, "/early"), false, ""); // pre-clear flight stays physically owned
        for (int i = 0; i < 3; i++) respond(watcher, endpoint(watcher, "/p" + i), 200);
        assertEquals(1, number(watcher, "fanoutWarnings"));
        assertEquals(List.of("example.test"), warnEpisodeDisplayHosts(watcher), "WARN is not an installed overlay but holds the display host");
        long hosts = number(watcher, "hosts"), indexed = number(watcher, "fanoutHistoryIndexed");
        watcher.clearEvidence();
        assertEquals(List.of(""), warnEpisodeDisplayHosts(watcher), "explicit clear releases the store-owned original display reference");
        assertEquals(1, number(watcher, "fanoutWarnings"), "the logical episode itself is operational state");
        assertEquals(hosts, number(watcher, "hosts"));
        assertEquals(indexed, number(watcher, "fanoutHistoryIndexed"), "Seen history is untouched");
        assertEquals(1, number(watcher, "activeTickets"));
        respond(watcher, endpoint(watcher, "/p-after-clear"), 200);
        assertEquals(0, number(watcher, "events"), "the surviving episode is not re-announced");
        watcher.observe(early, 200, 0);
        assertEquals(0, number(watcher, "activeTickets"));
        assertEquals(List.of(""), warnEpisodeDisplayHosts(watcher), "a pre-clear flight cannot repopulate the display reference");
    }

    @SuppressWarnings("unchecked")
    private static List<String> warnEpisodeDisplayHosts(ResponseWatcher watcher) throws Exception {
        var hostsField = ResponseWatcher.class.getDeclaredField("hosts");
        hostsField.setAccessible(true);
        List<String> out = new ArrayList<>();
        synchronized (watcher) {
            for (Object host : ((Map<String, Object>) hostsField.get(watcher)).values()) {
                var episodeField = host.getClass().getDeclaredField("episode");
                episodeField.setAccessible(true);
                Object episode = episodeField.get(host);
                if (episode == null) continue;
                var display = episode.getClass().getDeclaredField("displayHost");
                display.setAccessible(true);
                out.add((String) display.get(episode));
            }
        }
        return out;
    }

    @Test void clearEvidenceReleasesTheDisplayOfADetachedHalfOpenCircuitStillHeldByItsInFlightProbe() throws Exception {
        for (String detach : List.of("release", "releaseAll", "circuitOff")) {
            Clock clock = new Clock();
            Limits on = limits(0, new Circuit5xx(1_000, 1, 1_000, 1), null);
            ResponseWatcher watcher = watcher(on, clock);
            respond(watcher, endpoint(watcher, "/x"), 503);
            clock.advance(1_000);
            Ticket probe = watcher.commit(endpoint(watcher, "/x"), false, ""); // logical watcher ticket, not a native permit
            assertTrue(probe.halfOpen(), detach);
            switch (detach) {
                case "release" -> assertTrue(watcher.release(watcher.overlays().getFirst().id()));
                case "releaseAll" -> assertEquals(1, watcher.releaseAll());
                default -> watcher.update(new Limits(on.globalRps(), on.perHostRps(), on.hostRps(), on.maxConcurrent(), on.maxQueued(),
                        on.queueTimeoutMillis(), on.approvalTimeoutMillis(), on.requestTimeoutMillis(), on.perPathMaxResponseBytes(),
                        on.autoBlockMillis(), null, on.fanout(), on.perIntentMaxRequests(), false, List.of(), List.of()));
            }
            assertEquals(0, number(watcher, "circuits"), detach + ": detached from protections/Host.circuit");
            Object flight = probeFlights(watcher).getFirst();
            Object circuit = field(watcher, flight, "probeCircuit");
            Object host = field(watcher, flight, "host");
            assertEquals("example.test", field(watcher, circuit, "displayHost"), detach + ": the in-flight probe still reaches the original");
            List<Object> operational = new ArrayList<>();
            for (String name : List.of("started", "timeout", "circuitGeneration", "circuitExcluded")) operational.add(field(watcher, flight, name));
            for (String name : List.of("id", "serviceKey", "expiresAt", "until", "openMillis", "source")) operational.add(field(watcher, circuit, name));
            for (String name : List.of("hasProbeAttempt", "lastProbeAttempt")) operational.add(field(watcher, host, name));
            String hostKey = ((Endpoint) field(watcher, flight, "endpoint")).hostKey();
            long hosts = number(watcher, "hosts");
            watcher.clearEvidence();
            Object kept = probeFlights(watcher).getFirst();
            assertSame(circuit, field(watcher, kept, "probeCircuit"), detach + ": the operational reference is kept, not replaced");
            assertSame(host, field(watcher, kept, "host"));
            assertSame(probe, field(watcher, circuit, "probe"), detach + ": probe identity is unchanged");
            assertEquals("", field(watcher, circuit, "displayHost"), detach + ": explicit clear releases the store-owned display original");
            assertEquals("", field(watcher, circuit, "displayPath"));
            List<Object> after = new ArrayList<>();
            for (String name : List.of("started", "timeout", "circuitGeneration", "circuitExcluded")) after.add(field(watcher, kept, name));
            for (String name : List.of("id", "serviceKey", "expiresAt", "until", "openMillis", "source")) after.add(field(watcher, circuit, name));
            for (String name : List.of("hasProbeAttempt", "lastProbeAttempt")) after.add(field(watcher, host, name));
            assertEquals(operational, after, detach + ": deadlines, keys and probe cadence are untouched");
            assertEquals(hostKey, ((Endpoint) field(watcher, kept, "endpoint")).hostKey());
            assertEquals(hosts, number(watcher, "hosts"));
            assertEquals(1, number(watcher, "activeTickets"), detach + ": the logical flight is retained");
            if (detach.equals("circuitOff")) watcher.update(on);
            respond(watcher, endpoint(watcher, "/x"), 503);
            assertEquals(1, number(watcher, "circuits"), detach + ": a new circuit opens normally");
            ResponseWatcher.Overlay fresh = watcher.overlays().getFirst();
            assertEquals("example.test", fresh.host(), detach + ": a new episode has its own display");
            watcher.observe(probe, 200, 0);
            assertEquals(1, number(watcher, "circuits"), detach + ": the old probe cannot heal the new circuit (ABA)");
            assertEquals(fresh.expiresAt(), watcher.overlays().getFirst().expiresAt());
            assertEquals(0, number(watcher, "activeTickets"));
            assertTrue(probeFlights(watcher).isEmpty());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Object> probeFlights(ResponseWatcher watcher) throws Exception {
        var flightsField = ResponseWatcher.class.getDeclaredField("flights");
        flightsField.setAccessible(true);
        List<Object> out = new ArrayList<>();
        synchronized (watcher) {
            for (Object flight : ((Map<Object, Object>) flightsField.get(watcher)).values())
                if (field(watcher, flight, "probeCircuit") != null) out.add(flight);
        }
        return out;
    }
    private static Object field(ResponseWatcher watcher, Object owner, String name) throws Exception {
        var field = owner.getClass().getDeclaredField(name);
        field.setAccessible(true);
        synchronized (watcher) { return field.get(owner); }
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
                clock::nano, clock::wall, 1, 4, 4);
        Endpoint first = endpoint(hosts, "/one");
        respond(hosts, first, 500);
        clock.advance(1_000); // Half-open is still active protection and cannot be evicted.
        Endpoint other = endpoint(hosts, "GET", "other.test", 443, true, "/two", "https://other.test/two", List.of("/two"));
        assertEquals(GuardState.CAPACITY, hosts.check(other, false).guardState());
        assertEquals(1, number(hosts, "circuits"));
        ResponseWatcher paths = new ResponseWatcher(limits(0, null, null), clock::nano, clock::wall, 4, 1, 4);
        Ticket pinned = paths.commit(endpoint(paths, "/one"), false, "");
        assertEquals(GuardState.CAPACITY, paths.check(endpoint(paths, "/two"), false).guardState());
        paths.cancel(pinned);
        assertTrue(paths.check(endpoint(paths, "/two"), false).allowed());
        ResponseWatcher overlays = new ResponseWatcher(limits(1, null, null), clock::nano, clock::wall, 4, 8, 2);
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

    @Test void candidateRetentionIsNotTiedToEnforcementPathCapacity() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = new ResponseWatcher(limits(0, null, null), clock::nano, clock::wall, 4, 2, 4);
        for (int i = 0; i < 3; i++) {
            Endpoint endpoint = endpoint(watcher, "/" + i);
            watcher.observe(watcher.commit(endpoint, false, ""), 500, i + 1);
        }
        assertEquals(3, watcher.candidates().size());
        assertEquals(false, watcher.snapshot().get("candidatesIncomplete"));
        assertEquals(0, number(watcher, "candidateEvictions"));
        JsonNode incident = json(watcher.incidentJson(clock.wall, clock.wall + 1));
        assertEquals(3, incident.get("topBytes").size());
        assertTrue(incident.get("complete").asBoolean());
        for (var candidate : watcher.candidates()) assertTrue(watcher.ignoreCandidate(candidate.id()));
        assertTrue(watcher.candidates().isEmpty());
        respond(watcher, endpoint(watcher, "/new"), 200);
        assertEquals(1, watcher.candidates().size(), "ignored runtime entries do not pin the table");
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

    @Test void retentionHasNoDayExpiryAndOnlyUnorderedWindowsAreRejected() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        long start = clock.wall;
        respond(watcher, endpoint(watcher, "/old"), 503);
        clock.advance(86_400_001);
        assertEquals(1, watcher.candidates().size());
        assertEquals(1, number(watcher, "observations"));
        JsonNode wide = json(watcher.incidentJson(start, clock.wall + 1));
        assertTrue(wide.get("complete").asBoolean(), "a window longer than a day is a valid retained window");
        assertEquals(1, wide.get("topBytes").size());
        assertThrows(IllegalArgumentException.class, () -> watcher.incidentJson(1, 1));
        assertThrows(IllegalArgumentException.class, () -> watcher.incidentJson(5, 4));
        assertDoesNotThrow(() -> watcher.incidentJson(Long.MIN_VALUE, Long.MAX_VALUE), "no overflowing duration arithmetic");
        assertFalse(json(watcher.incidentJson(Long.MIN_VALUE, Long.MAX_VALUE)).get("complete").asBoolean(), "coverage before start is unknown");
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
                host, port, secure, List.of(), new byte[0]), views);
    }
    private static Endpoint service(ResponseWatcher watcher, int port) {
        return endpoint(watcher, "GET", "example.test", port, true, "/same", "https://example.test:" + port + "/same", List.of("/same"));
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
