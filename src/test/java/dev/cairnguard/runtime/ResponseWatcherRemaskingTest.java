package dev.cairnguard.runtime;

import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ResponseWatcherRemaskingTest {
    private static final String SECRET = "synthetic-issued-credential-3948";
    private final AtomicLong clock = new AtomicLong();
    private final EvidenceStore evidence = new EvidenceStore();
    private final ResponseWatcher watcher = new ResponseWatcher(limits(), clock::get, () -> 1_000L);

    @Test void responseOnlyGrantRemasksAllHistoryFlightsAndOldEndpointWithoutWeakeningEnforcement() throws Exception {
        RequestData request = request("/download/" + SECRET);
        String id = evidence.begin("p", "Synthetic project", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        var endpoint = watcher.endpoint(request, evidence.entry(id).url(), PolicyEngine.routingPaths(request));
        var keys = endpoint.pathKeys();
        watcher.observe(watcher.commit(endpoint, false, id), 200, 2);
        var late = watcher.commit(endpoint, false, id);
        evidence.response(id, 200, List.of(new RequestData.Header("X-Broker-Grant", SECRET)), new byte[0]);
        assertFalse(evidence.entry(id).url().contains(SECRET));
        watcher.refreshDisplay(evidence.displaySanitizer(id));
        watcher.observe(late, 503, 20);
        assertEquals(2, watcher.candidates().getFirst().count());
        assertEquals("", watcher.candidates().getFirst().policyUrl());
        assertFalse(watcher.candidates().toString().contains(SECRET));
        var overlay = watcher.overlays().getFirst();
        assertFalse(overlay.toString().contains(SECRET));
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(endpoint, false).reason());
        assertEquals(keys, endpoint.pathKeys(), "private keyed enforcement aliases were never changed");
        assertFalse(watcher.incidentJson(999, 1_001).contains(SECRET));
        assertTrue(watcher.release(overlay.id()));
        // An older Prepared/Endpoint created before response discovery cannot reintroduce the URL.
        watcher.observe(watcher.commit(endpoint, false, id), 200, 1);
        assertEquals(3, watcher.candidates().getFirst().count());
        assertFalse(watcher.candidates().toString().contains(SECRET));
        assertEquals("", watcher.candidates().getFirst().policyUrl());
    }
    @Test void newlyDiscoveredSecretMatchingSchemaKeysNeverCorruptsIncidentStructure() throws Exception {
        RequestData request = request("/events/path");
        String id = evidence.begin("p", "Synthetic", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        var endpoint = watcher.endpoint(request, evidence.entry(id).url(), PolicyEngine.routingPaths(request));
        watcher.observe(watcher.commit(endpoint, false, id), 503, 20);
        evidence.response(id, 200, List.of(new RequestData.Header("Content-Type", "application/json")),
                "{\"grant\":\"events\",\"token\":\"path\"}".getBytes(StandardCharsets.UTF_8));
        watcher.refreshDisplay(evidence.displaySanitizer(id));
        var document = Json.MAPPER.readTree(watcher.incidentJson(999, 1_001));
        assertTrue(document.has("events"));
        assertTrue(document.path("events").get(0).has("path"));
        assertEquals(20, document.path("events").get(0).path("bytes").asLong());
        assertEquals(1, document.path("topBytes").get(0).path("count").asLong());
        assertFalse(document.path("events").get(0).path("path").asText().contains("events"));
        assertEquals("", watcher.candidates().getFirst().policyUrl());
    }
    @Test void disposedFingerprintsAreOpaqueAndClearEvidenceDoesNotReleaseProtection() throws Exception {
        RequestData request = request("/download/" + SECRET);
        String id = evidence.begin("p", "Synthetic", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        var endpoint = watcher.endpoint(request, evidence.entry(id).url(), PolicyEngine.routingPaths(request));
        watcher.observe(watcher.commit(endpoint, false, id), 200, 20);
        String overlayId = watcher.overlays().getFirst().id();
        evidence.clear();
        watcher.refreshDisplay(evidence.displaySanitizer(id));
        assertFalse(watcher.overlays().toString().contains(SECRET));
        watcher.clearEvidence();
        assertTrue(watcher.candidates().isEmpty());
        assertEquals(0, Json.MAPPER.readTree(watcher.incidentJson(999, 1_001)).path("events").size());
        assertEquals(overlayId, watcher.check(endpoint, false).overlayId());
        assertFalse(watcher.check(endpoint, false).allowed());
    }
    @Test void hostileSanitizerCannotInjectUnboundedOrControlDisplayOrChangeKeys() throws Exception {
        RequestData request = request("/safe");
        var endpoint = watcher.endpoint(request, request.url(), PolicyEngine.routingPaths(request));
        watcher.observe(watcher.commit(endpoint, false, ""), 200, 20);
        watcher.refreshDisplay(value -> "bad\r\n" + "x".repeat(20_000));
        assertFalse(watcher.candidates().toString().contains("bad"));
        assertEquals("", watcher.candidates().getFirst().policyUrl());
        assertFalse(watcher.check(endpoint, false).allowed());
    }
    @Test void allPathPentestTargetsUseUnchangedRoutingViewsNotGenericUriSanitization() throws Exception {
        for (String path : List.of("/c/;/main.do", "/c/%2e/main.do", "/c/%252e/main.do", "/c/%zz/main.do", "/c/#/main.do", "/c/../main.do")) {
            RequestData request = request(path);
            var endpoint = watcher.endpoint(request, "https://redacted.invalid/", PolicyEngine.routingPaths(request));
            assertTrue(watcher.check(endpoint, false).allowed(), path);
            watcher.cancel(watcher.commit(endpoint, false, ""));
        }
    }
    @Test void actualIpv6ServiceKeepsCanonicalSingleBracketPolicyUrlAndAliasIdentity() throws Exception {
        RequestData compressed = new RequestData("GET", "https://[::1]/safe", "[::1]", 443, true, List.of(), new byte[0]);
        RequestData expanded = new RequestData("GET", "https://[0:0:0:0:0:0:0:1]/safe", "0:0:0:0:0:0:0:1", 443, true, List.of(), new byte[0]);
        var one = watcher.endpoint(compressed, compressed.url(), PolicyEngine.routingPaths(compressed));
        var two = watcher.endpoint(expanded, expanded.url(), PolicyEngine.routingPaths(expanded));
        assertEquals(one.hostKey(), two.hostKey());
        assertEquals(one.pathKeys(), two.pathKeys());
        assertFalse(one.policyUrl().contains("[["));
        assertNotNull(java.net.URI.create(one.policyUrl()).getHost());
        watcher.observe(watcher.commit(one, false, ""), 200, 20);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED", watcher.check(two, false).reason());
    }
    private static RequestData request(String path) {
        return new RequestData("GET", "https://owned.test" + path, "owned.test", 443, true, List.of(), new byte[0]);
    }
    private static Limits limits() {
        return new Limits(1000, 1000, Map.of(), 10, 10, 1000, 1000, 1000, 10, 60_000, null, null, 0, false, List.of(), List.of());
    }
}
