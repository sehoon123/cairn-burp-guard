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
        watcher.observe(endpoint, 503, 200);
        assertEquals("https://example.test/token/synthetic-secret", watcher.candidates().getFirst().policyUrl());
        String exported = watcher.incidentJson(clock.wall, clock.wall + 1);
        assertTrue(exported.contains("/token/synthetic-secret"));
        assertFalse(exported.contains("secret-query"), "the query is not part of the route identity");
        assertFalse(exported.contains("spoofed.invalid"));
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

    @Test void candidateStatsAndIncidentTopListsUseIndependentRetainedWindow() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        Endpoint one = endpoint(watcher, "/one");
        Endpoint two = endpoint(watcher, "/two");
        long start = clock.wall;
        watcher.observe(one, 500, 100);
        clock.advance(10);
        watcher.observe(one, 200, 10);
        clock.advance(10);
        watcher.observe(two, 503, 50);
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
        ResponseWatcher watcher = new ResponseWatcher(limits(1, null, null), clock::nano, clock::wall);
        long start = clock.wall;
        for (int i = 0; i < 3; i++) {
            Endpoint endpoint = endpoint(watcher, "/" + i);
            watcher.observe(endpoint, 500, 10 + i);
            clock.advance(1);
        }
        assertEquals(3, number(watcher, "observations"));
        assertEquals(3, number(watcher, "observations"));
        assertEquals(false, watcher.snapshot().get("observationsTruncated"));
        JsonNode all = json(watcher.incidentJson(start, clock.wall));
        assertTrue(all.get("complete").asBoolean());
        assertFalse(all.at("/retention/eventsDropped").asBoolean());
        assertEquals(3, all.get("topBytes").size());
    }

    @Test @Timeout(120) void productionHistoryKeepsMoreThan8192ObservationsAndTheirCandidateCount() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        long start = clock.wall;
        Endpoint endpoint = endpoint(watcher, "/same");
        for (int i = 0; i < 8_193; i++) { respond(watcher, endpoint, 200); if (i % 64 == 0) clock.advance(1); }
        assertEquals(8_193, number(watcher, "observations"));
        assertEquals(false, watcher.snapshot().get("observationsTruncated"));
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

    @Test void scalarHistogramHandlesLongMaxAndNegativeLengthsWithoutOverflow() throws Exception {
        Clock clock = new Clock();
        ResponseWatcher watcher = watcher(limits(0, null, null), clock);
        Endpoint endpoint = endpoint(watcher, "/size");
        watcher.observe(endpoint, 200, Long.MAX_VALUE);
        watcher.observe(endpoint, 200, -1);
        var candidate = watcher.candidates().getFirst();
        assertEquals(Long.MAX_VALUE, candidate.maxBytes());
        assertEquals(Long.MAX_VALUE, candidate.p95Bytes());
        assertEquals(2, candidate.count());
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

    private static void respond(ResponseWatcher watcher, Endpoint endpoint, int status) throws Exception {
        watcher.observe(endpoint, status, 0);
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
