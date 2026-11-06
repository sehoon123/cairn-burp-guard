package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.Json;
import dev.cairnguard.runtime.GuardController;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Actual controller/evidence/watcher with Montoya mocks. Not installed Burp or wire delivery proof. */
@Timeout(20)
class ProxyV2Test {
    private static Limits limits(long heavy, Circuit5xx circuit, Fanout fanout, int budget, List<ProbePath> probes) {
        return new Limits(1_000, 1_000, Map.of(), 5, 128, 500, 5_000, 60_000,
                heavy, 60_000, circuit, fanout, budget, !probes.isEmpty(), probes, List.of());
    }
    private static GuardConfig policy(Limits limits, List<Rule> rules, List<Integer> ports) {
        var base = config(Mode.ALLOW, 5, 60_000);
        return new GuardConfig(2, base.allowScope(), List.of(), rules, Mode.ALLOW, limits, ports);
    }
    private static Rule rule(String id, Mode mode, Field field, Match match, String value) {
        return new Rule(id, id, true, mode, Condition.leaf(field, match, value));
    }
    private static HttpRequestToBeSent tagged(int id, String intent) {
        var request = request(id);
        when(request.headers()).thenReturn(List.of(header("Host", "synthetic.invalid"), header("X-Cairn-Intent", intent), header("X-Cairn-Run", "fixture")));
        return request;
    }
    private static long metric(GuardController c, String section, String key) { return ((Number) ((Map<?, ?>) c.status().get(section)).get(key)).longValue(); }
    private static long revision(GuardController c) { return ((Number) c.status().get("revision")).longValue(); }
    private static com.fasterxml.jackson.databind.JsonNode denial(Actions a, String reason, String state) throws Exception {
        var value = Json.MAPPER.readTree(a.local.substring(a.local.indexOf("\r\n\r\n") + 4));
        assertEquals(reason, value.path("reason").asText()); assertEquals(state, value.path("guardState").asText());
        assertTrue(value.path("local").asBoolean()); assertTrue(value.path("policyRevision").asLong() > 0);
        return value;
    }
    @ParameterizedTest @ValueSource(strings = {"/c/;/main.do", "/c/%2e/main.do", "/c/%252e/main.do", "/c/%25252e/main.do",
            "/c/./main.do", "/c/a/../main.do", "/c/;x/main.do", "/c/%3b/main.do", "/c/%253b/main.do",
            "/c%2fmain.do", "/c%252fmain.do", "/c\\main.do", "//c///main.do", "/c/%ZZ/main.do", "/c/%/main.do?x=%ZZ"})
    void allPathsPreservesRawPathNativeObjectsAndFuzzedHost(String path) {
        var controller = controller(); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var request = request(1); when(request.path()).thenReturn(path);
            when(request.url()).thenReturn("https://spoof.invalid/not-the-actual-path");
            when(request.headers()).thenReturn(List.of(header("Host", "spoof.invalid"), header(":authority", "fuzz.invalid")));
            var result = handler.handleHttpRequestToBeSent(request);
            assertSame(request, result.request()); assertSame(request.annotations(), result.annotations()); assertNull(actions.local);
            assertEquals("https://example.test:443" + path, controller.rawUrl(controller.traffic().getFirst().id()));
            verify(request, never()).url(); verifyNoInteractions(request.annotations());
            handler.handleHttpResponseReceived(response(1, "{}"));
        }
    }
    @Test void oversizedOptionalQueryCannotBecomeAutomaticDenyOrFalseCompleteQueryMatch() {
        var rules = List.of(rule("query", Mode.BLOCK, Field.QUERY, Match.CONTAINS, "operator-denied-marker"));
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 0, List.of()), rules, List.of())));
        try (var handler = new ProxyGuardHandler(controller, new Actions())) {
            String target = "/safe?q=" + "x".repeat(2 * 16_384);
            var request = request(1); when(request.path()).thenReturn(target);
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            var row = controller.traffic().getFirst();
            assertTrue(row.inspectionWarnings().stream().anyMatch(w -> w.startsWith("QUERY_INSPECTION_UNAVAILABLE_")));
            assertEquals(false, controller.rawCaptureInfo(row.id()).get("requestTruncated"));
            assertTrue(controller.rawUrl(row.id()).endsWith(target), "the complete optional query is retained"); handler.handleHttpResponseReceived(response(1, "{}"));
        }
    }
    @Test void spoofedHostCannotAuthorizeDifferentActualService() throws Exception {
        var controller = controller(); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var request = request(1); when(request.httpService().host()).thenReturn("outside.test");
            when(request.url()).thenReturn("https://example.test/safe"); when(request.headers()).thenReturn(List.of(header("Host", "example.test")));
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request).action());
            denial(actions, "SCOPE_NOT_ALLOWED", "PROTECTED"); assertEquals(0, handler.inFlightCount());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"charset", "binary", "multipart", "encoding", "malformed-json", "header-overflow", "body-overflow", "body-failure"})
    void optionalInspectionLimitationsWarnButForwardSameNativeObjects(String kind) {
        // Demand content explicitly so malformed/unsupported fields really are attempted, not
        // falsely claimed to have been parsed by a default method-only policy.
        var rules = List.of(rule("body", Mode.BLOCK, Field.BODY, Match.CONTAINS, "operator-denied-marker"),
                rule("json", Mode.BLOCK, Field.JSON, Match.CONTAINS, "operator-denied-marker"));
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 0, List.of()), rules, List.of())));
        var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var request = request(1); var original = new byte[] {0, (byte) 0xff, 7}; doReturn(bytes(original)).when(request).body();
            switch (kind) {
                case "charset" -> when(request.headers()).thenReturn(List.of(header("Content-Type", "text/plain; charset=unsupported-fixture")));
                case "binary" -> when(request.headers()).thenReturn(List.of(header("Content-Type", "application/octet-stream")));
                case "multipart" -> when(request.headers()).thenReturn(List.of(header("Content-Type", "multipart/form-data; boundary=fixture")));
                case "encoding" -> when(request.headers()).thenReturn(List.of(header("Content-Encoding", "gzip")));
                case "malformed-json" -> { when(request.headers()).thenReturn(List.of(header("Content-Type", "application/json"))); doReturn(bytes("{".getBytes(StandardCharsets.UTF_8))).when(request).body(); }
                case "header-overflow" -> when(request.headers()).thenReturn(java.util.Collections.nCopies(257, header("X-Fixture", "synthetic")));
                case "body-overflow" -> { var huge = mock(ByteArray.class); when(huge.length()).thenReturn(Integer.MAX_VALUE); when(request.body()).thenReturn(huge); }
                case "body-failure" -> when(request.body()).thenThrow(new IllegalStateException("SYNTHETIC-PRIVATE"));
                default -> fail(kind);
            }
            assertSame(request, handler.handleHttpRequestToBeSent(request).request()); assertNull(actions.local);
            assertFalse(controller.traffic().getFirst().inspectionWarnings().isEmpty());
            assertTrue(mockingDetails(request).getInvocations().stream().noneMatch(i -> i.getMethod().getName().startsWith("with")));
            handler.handleHttpResponseReceived(response(1, "{}"));
        }
    }
    @Test void explicitHeaderAndBodyRulesStillBlockInspectableContentAndExemptWinsBlock() throws Exception {
        var rules = List.of(rule("header", Mode.BLOCK, Field.HEADER, Match.CONTAINS, "operator-header-marker"),
                rule("body", Mode.BLOCK, Field.BODY, Match.CONTAINS, "operator-body-marker"),
                rule("block-route", Mode.BLOCK, Field.PATH, Match.EXACT, "/broker"),
                rule("exempt", Mode.EXEMPT, Field.PATH, Match.EXACT, "/broker"));
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 0, List.of()), rules, List.of()))); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var header = request(1); when(header.headers()).thenReturn(List.of(header("X-Fixture", "operator-header-marker")));
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(header).action()); denial(actions, "RULE_BLOCK", "PROTECTED");
            var body = request(2); when(body.headers()).thenReturn(List.of(header("Content-Type", "text/plain"))); doReturn(bytes("operator-body-marker".getBytes(StandardCharsets.UTF_8))).when(body).body();
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(body).action());
            var exempt = request(3); when(exempt.path()).thenReturn("/broker"); assertSame(exempt, handler.handleHttpRequestToBeSent(exempt).request());
            assertEquals("exempt", controller.traffic().getFirst().outcome()); handler.handleHttpResponseReceived(response(3, "{}"));
        }
    }
    @Test void nativeAuthCookieGrantAreOriginalsInHumanGettersEvidenceAndExports() {
        var controller = controller(); var actions = new Actions();
        String auth = "synthetic-native-auth-9164", cookie = "synthetic-native-cookie-9164", grant = "synthetic-native-grant-9164";
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var request = request(1); when(request.headers()).thenReturn(List.of(header("Host", "example.test"),
                    header("Authorization", "Bearer " + auth), header("Cookie", "fixture=" + cookie), header("X-Broker-Grant", grant)));
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            var response = response(1, "{\"token\":\"" + grant + "\"}"); assertSame(response, handler.handleHttpResponseReceived(response).response());
            var row = controller.traffic().getFirst(); String raw = controller.rawRequest(row.id());
            for (String secret : List.of(auth, cookie, grant)) {
                assertTrue(raw.contains(secret)); assertTrue(row.request().contains(secret));
                assertTrue(controller.exportJson(controller.traffic()).contains(secret)); assertTrue(controller.exportHar(controller.traffic()).contains(secret));
            }
            assertTrue(controller.rawResponse(row.id()).contains(grant)); assertTrue(row.response().contains(grant));
            controller.clearEvidence(); assertNull(controller.rawRequest(row.id())); assertNull(controller.rawResponse(row.id()));
        }
    }
    @Test void sixMiBObservationWithUnavailableCopyDoesNotDenyTheNextRequestOrSavePolicy() throws Exception {
        var project = new MemoryProject(policy(limits(5L * 1_048_576, null, null, 0, List.of()), List.of(), List.of()));
        String before = project.json; var controller = new GuardController(project); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            handler.handleHttpRequestToBeSent(request(1)); var response = response(1, "{}"); var huge = mock(ByteArray.class);
            when(huge.length()).thenReturn(6 * 1_048_576); when(response.body()).thenReturn(huge);
            when(response.headers()).thenReturn(List.of(header("Content-Length", "1")));
            assertSame(response, handler.handleHttpResponseReceived(response).response()); // mocked getBytes() supplies nothing
            var row = controller.traffic().getFirst(); assertEquals(6L * 1_048_576, row.responseBytes());
            assertEquals(false, controller.rawCaptureInfo(row.id()).get("responseBodyComplete"));
            assertTrue(controller.rawResponse(row.id()).contains("Body incomplete or omitted"));
            assertFalse(controller.rawResponse(row.id()).contains("00000000"));
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(2)).action());
            assertEquals(before, project.json);
            var incident = Json.MAPPER.readTree(controller.exportIncident(System.currentTimeMillis() - 60_000, System.currentTimeMillis() + 1));
            assertTrue(incident.has("events")); assertTrue(incident.has("topBytes"));
        }
    }
    @Test void fiveNative5xxNeverOpenACircuitOrRequireHalfOpen() throws Exception {
        var controller = new GuardController(new MemoryProject(policy(limits(0, new Circuit5xx(60_000, 5, 1_000, 1), null, 0, List.of()), List.of(), List.of()))); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            for (int id = 1; id <= 5; id++) {
                assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(id)).action());
                var response = response(id, "{}"); when(response.statusCode()).thenReturn((short) 503); handler.handleHttpResponseReceived(response);
            }
            for(int id=6;id<=9;id++) assertEquals(RequestAction.CONTINUE,handler.handleHttpRequestToBeSent(request(id)).action());
        }
    }
    @Test void exact21stIntentDenialAndOtherIntentAllowed() throws Exception {
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 20, List.of()), List.of(), List.of()))); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            for (int id = 1; id <= 20; id++) { assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(tagged(id, "i048")).action()); handler.handleHttpResponseReceived(response(id, "{}")); }
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(tagged(21, "i048")).action()); denial(actions, "INTENT_BUDGET_EXCEEDED", "INTENT_BUDGET");
            assertEquals(20, metric(controller, "intents", "consumed"));
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(tagged(22, "other")).action()); handler.handleHttpResponseReceived(response(22, "{}"));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"throw", "null", "pause"})
    void localPreHandoffFailuresNeverSpendBudgetAndFinalReasonIsNotGeneric(String kind) throws Exception {
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, kind.equals("fanout") ? new Fanout(60_000, 2, FanoutAction.BLOCK) : null, 20, List.of()), List.of(), List.of())));
        var actions = new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations a) {
                if (request.messageId() == 2) switch (kind) {
                    case "throw" -> throw new IllegalStateException("SYNTHETIC");
                    case "null" -> { return null; }
                    case "pause" -> controller.pause(true);
                    default -> { }
                }
                return super.continueRequest(request, a);
            }
        };
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            var first = tagged(1, "one"); when(first.path()).thenReturn("/first"); handler.handleHttpRequestToBeSent(first); handler.handleHttpResponseReceived(response(1, "{}"));
            var second = tagged(2, "one"); when(second.path()).thenReturn("/second"); assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(second).action());
            String reason = kind.equals("fanout") ? "FANOUT_SUSPECTED" : kind.equals("pause") ? "PAUSED" : "CONTINUATION_FAILED";
            denial(actions, reason, kind.equals("fanout") ? "OVERLAY_BLOCK" : kind.equals("pause") ? "PAUSED_BY_OPERATOR" : "PROTECTED");
            assertEquals(1, metric(controller, "intents", "consumed")); assertEquals(0, handler.inFlightCount());
            assertFalse(controller.status().containsKey("watcherTickets"));
        }
    }
    @Test void knownUnselectedAndUnknownRestrictedListenerNeverCaptureContentOrResponseScalars() throws Exception {
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 20, List.of()), List.of(), List.of(8080)))); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions)) {
            controller.pause(true); controller.recordListener(1, "127.0.0.1:8081"); var request = request(1);
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            verify(request, never()).headers(); verify(request, never()).body(); verify(request, never()).method(); verify(request, never()).httpService();
            var response = response(1, "{}"); assertSame(response, handler.handleHttpResponseReceived(response).response());
            verify(response, never()).statusCode(); verify(response, never()).body(); verify(response, never()).headers();
            assertTrue(controller.traffic().isEmpty()); assertEquals(1L, controller.status().get("unguardedListenerCount")); assertEquals(0, metric(controller, "intents", "consumed"));
            var unknown = request(2); assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(unknown).action()); denial(actions, "LISTENER_UNVERIFIED", "LISTENER_UNVERIFIED");
            verify(unknown, never()).body(); verify(unknown, never()).headers(); verify(unknown, never()).path();
            controller.pause(false); controller.recordListener(3, "127.0.0.1:8080");
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(3)).action()); handler.handleHttpResponseReceived(response(3, "{}"));
        }
    }
    @Test void responseScalarIsObservedWithoutAnOverlayWhileRequestInspectionSlotsAreBusy() throws Exception {
        var controller = new GuardController(new MemoryProject(policy(limits(5L * 1_048_576, null, null, 0, List.of()), List.of(), List.of())));
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var worker = Executors.newSingleThreadExecutor();
        try (var handler = new ProxyGuardHandler(controller, new Actions(), 2, 1)) {
            handler.handleHttpRequestToBeSent(request(1)); var second = request(2); when(second.path()).thenReturn("/another");
            when(second.body().getBytes()).thenAnswer(i -> { entered.countDown(); assertTrue(release.await(5, TimeUnit.SECONDS)); return new byte[0]; });
            var pending = worker.submit(() -> handler.handleHttpRequestToBeSent(second)); assertTrue(entered.await(5, TimeUnit.SECONDS));
            var response = response(1, "{}"); var huge = mock(ByteArray.class); when(huge.length()).thenReturn(6 * 1_048_576); when(response.body()).thenReturn(huge);
            handler.handleHttpResponseReceived(response); verify(response).headers(); // response copies need no inspection slot
            assertEquals(6L * 1_048_576,controller.traffic().stream().filter(row->row.statusCode()!=null).findFirst().orElseThrow().responseBytes());
            release.countDown(); assertEquals(RequestAction.CONTINUE, pending.get(5, TimeUnit.SECONDS).action()); handler.handleHttpResponseReceived(response(2, "{}"));
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS)); }
    }
    @Test void exactHealthProbeNeedsVerifiedEmptyBodyEvenWhenInspectionSlotUnavailable() throws Exception {
        var probes = List.of(new ProbePath("https", "example.test", 443, "/health"));
        var controller = new GuardController(new MemoryProject(policy(limits(0, null, null, 0, probes), List.of(), List.of())));
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var worker = Executors.newSingleThreadExecutor(); var actions = new Actions();
        try (var handler = new ProxyGuardHandler(controller, actions, 2, 1)) {
            var old = request(1); when(old.body().getBytes()).thenAnswer(i -> { entered.countDown(); assertTrue(release.await(5, TimeUnit.SECONDS)); return new byte[0]; });
            var pending = worker.submit(() -> handler.handleHttpRequestToBeSent(old)); assertTrue(entered.await(5, TimeUnit.SECONDS)); controller.pause(true);
            for (int id = 2; id <= 4; id++) {
                var nonprobe = request(id); when(nonprobe.path()).thenReturn("/health" + (id == 2 ? "?query=1" : ""));
                if (id == 3) when(nonprobe.body()).thenThrow(new IllegalStateException("SYNTHETIC"));
                if (id == 4) doReturn(bytes(new byte[] {1})).when(nonprobe).body();
                assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(nonprobe).action()); denial(actions, "PAUSED", "PAUSED_BY_OPERATOR");
            }
            var health = request(5); when(health.path()).thenReturn("/health");
            assertSame(health, handler.handleHttpRequestToBeSent(health).request());
            assertEquals("probe_allowed", controller.traffic().getFirst().outcome());
            assertEquals(true, controller.rawCaptureInfo(controller.traffic().getFirst().id()).get("bodyComplete"), "verified EMPTY copy");
            handler.handleHttpResponseReceived(response(5, "{}"));
            release.countDown(); assertEquals(RequestAction.SPOOF_RESPONSE, pending.get(5, TimeUnit.SECONDS).action());
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS)); }
    }
    @Test void reentrantEarlyResponseCannotBeAttachedToAFutureSend() {
        var controller=controller(); var ref=new AtomicReference<ProxyGuardHandler>();
        var actions=new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request,Annotations a) {
                ref.get().handleHttpResponseReceived(response(request.messageId(),"early"));
                return super.continueRequest(request,a);
            }
        };
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            ref.set(handler); assertEquals(RequestAction.CONTINUE,handler.handleHttpRequestToBeSent(request(1)).action());
            assertEquals(0,handler.inFlightCount()); handler.handleHttpResponseReceived(response(1,"late-ambiguous"));
            assertNull(controller.rawResponse(controller.traffic().getFirst().id()));
        }
    }
}
