package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.runtime.GuardController;
import dev.cairnguard.runtime.ProjectAccess;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Synthetic native-boundary regressions; no real Burp, targets, credentials or network calls. */
@Timeout(15)
class ProxyPassthroughTest {
    @ParameterizedTest @ValueSource(strings = {"EMPTY_SCOPE", "BLOCK_SCOPE", "BLOCK", "ASK", "BINARY", "ENCODING", "WEBSOCKET", "HUGE", "AUTHORITY"})
    void explicitOffReallySkipsEveryPolicyAndCaptureLayerAndKeepsOriginalObjects(String scenario) throws Exception {
        GuardConfig config = config(scenario.equals("ASK") ? Mode.ASK : Mode.BLOCK, 1, 60_000);
        if (scenario.equals("EMPTY_SCOPE")) config = GuardConfig.defaults();
        if (scenario.equals("BLOCK_SCOPE")) config = new GuardConfig(1, config.allowScope(),
                List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), config.rules(), config.defaultMode(), config.limits());
        GuardController controller = new GuardController(new MemoryProject(config));
        Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1);
            switch (scenario) {
                case "BINARY" -> when(request.headers()).thenReturn(List.of(header("Content-Type", "application/octet-stream")));
                case "ENCODING" -> when(request.headers()).thenReturn(List.of(header("Content-Encoding", "gzip")));
                case "WEBSOCKET" -> when(request.headers()).thenReturn(List.of(header("Upgrade", "websocket")));
                case "HUGE" -> { ByteArray huge = mock(ByteArray.class); when(huge.length()).thenReturn(Integer.MAX_VALUE); when(request.body()).thenReturn(huge); }
                case "AUTHORITY" -> when(request.url()).thenReturn("https://different.example.test/unsafe");
                default -> when(request.method()).thenReturn("DELETE");
            }
            off(controller, true);
            RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);
            assertEquals(RequestAction.CONTINUE, result.action());
            assertSame(request, result.request()); assertSame(request.annotations(), result.annotations());
            verify(request, never()).body(); verify(request, never()).headers(); verify(request, never()).url();
            verify(request, never()).method(); verify(request, never()).path(); verify(request, never()).httpService();
            verifyNoInteractions(request.annotations());
            assertTrue(controller.traffic().isEmpty()); assertTrue(controller.approvals().isEmpty());
            assertEquals(0, gate(controller).get("active")); assertEquals(0, handler.inFlightCount());
            assertEquals(1L, controller.status().get("passthroughCount")); assertNull(actions.local);
            off(controller, false); // The outstanding OFF response must remain untracked after restoring protection.
            var response = response(1, "{\"token\":\"SYNTHETIC-OFF-SECRET\"}");
            var continued = handler.handleHttpResponseReceived(response);
            assertSame(response, continued.response()); assertSame(response.annotations(), continued.annotations());
            verify(response, never()).body(); verify(response, never()).headers(); verify(response, never()).statusCode();
            verifyNoInteractions(response.annotations()); assertTrue(controller.traffic().isEmpty());
        }
    }

    @Test void offDoesNotWaitOnEdtOrExhaustedCallbackAndInspectionSlotsAndDoesNotReleaseOldCapture() throws Exception {
        GuardController controller = controller(); Actions actions = new Actions();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        var worker = Executors.newSingleThreadExecutor();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 1, 1)) {
            HttpRequestToBeSent old = request(1);
            when(old.body().getBytes()).thenAnswer(i -> {
                entered.countDown();
                if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("SYNTHETIC-SECRET");
                return new byte[0];
            });
            var waiting = worker.submit(() -> handler.handleHttpRequestToBeSent(old));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            off(controller, true);
            HttpRequestToBeSent bypassed = request(2);
            AtomicReference<RequestToBeSentAction> result = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> result.set(handler.handleHttpRequestToBeSent(bypassed)));
            assertEquals(RequestAction.CONTINUE, result.get().action()); assertSame(bypassed, result.get().request());
            verify(bypassed, never()).body();
            release.countDown();
            assertEquals(RequestAction.SPOOF_RESPONSE, waiting.get(5, TimeUnit.SECONDS).action());
            assertEquals(1L, controller.status().get("passthroughCount"));
            assertTrue(controller.traffic().stream().noneMatch(e -> e.disposition().equals("FORWARDED")));
            assertEquals(0, gate(controller).get("active"));
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS)); }
    }

    @Test void enablingOffCancelsApprovalRatherThanForwardingItAndOnlyNewRequestsBypass() throws Exception {
        GuardController controller = new GuardController(new MemoryProject(config(Mode.ASK, 1, 60_000)));
        var worker = Executors.newSingleThreadExecutor(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            var old = worker.submit(() -> handler.handleHttpRequestToBeSent(request(1)));
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (controller.approvals().isEmpty() && System.nanoTime() < until) Thread.sleep(5);
            assertEquals(1, controller.approvals().size());
            String id = controller.approvals().getFirst().id();
            off(controller, true);
            assertEquals(RequestAction.SPOOF_RESPONSE, old.get(5, TimeUnit.SECONDS).action());
            assertFalse(controller.decideApproval(id, true));
            assertEquals("BLOCKED", controller.traffic().getFirst().disposition());
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(2)).action());
            assertEquals(1, controller.traffic().size()); assertEquals(1L, controller.status().get("passthroughCount"));
            assertEquals(0, gate(controller).get("active"));
        } finally { worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS)); }
    }

    @Test void offKeepsPreviousProtectedPermitUntilItsRealResponseAndNeverTracksNewOffResponses() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(1)).action());
            off(controller, true);
            assertEquals(1, handler.inFlightCount()); assertEquals(1, gate(controller).get("active"));
            for (int id = 2; id < 150; id++) assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(id)).action());
            assertEquals(1, handler.inFlightCount()); assertEquals(1, gate(controller).get("active"));
            var untracked = response(2, "{}"); handler.handleHttpResponseReceived(untracked);
            verify(untracked, never()).body(); assertEquals(1, gate(controller).get("active"));
            handler.handleHttpResponseReceived(response(1, "{\"token\":\"SYNTHETIC-OLD-SECRET\"}"));
            assertEquals(0, handler.inFlightCount()); assertEquals(0, gate(controller).get("active"));
            assertEquals(1, controller.traffic().size());
            assertTrue(controller.exportJson(controller.traffic()).contains("SYNTHETIC-OLD-SECRET"));
            off(controller, false);
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(200)).action());
            assertEquals(1, handler.inFlightCount());
            handler.handleHttpResponseReceived(response(200, "{}"));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"RESTORE", "CYCLE", "PAUSE", "SAVE", "PROJECT", "SHUTDOWN", "NULL", "THROW"})
    void bypassActionFactoryCannotSmuggleAnOldOffGenerationPastTheFinalCommit(String change) {
        MemoryProject project = new MemoryProject(GuardConfig.defaults());
        GuardController controller = new GuardController(project);
        Actions actions = new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) {
                switch (change) {
                    case "RESTORE" -> off(controller, false);
                    case "CYCLE" -> { off(controller, false); off(controller, true); }
                    case "PAUSE" -> controller.pause(true);
                    case "SAVE" -> controller.updateConfig(controller.config(), project.ref.id(), revision(controller));
                    case "PROJECT" -> project.ref = new ProjectAccess.Ref("other-project", "Other synthetic project");
                    case "SHUTDOWN" -> controller.close();
                    case "NULL" -> { return null; }
                    case "THROW" -> throw new IllegalStateException("SYNTHETIC-SECRET");
                    default -> fail(change);
                }
                return super.continueRequest(request, annotations);
            }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            off(controller, true);
            var request = request(1);
            assertNotEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request).action());
            verify(request, never()).body(); assertEquals(0L, controller.status().get("passthroughCount"));
            assertEquals(0, handler.inFlightCount()); assertEquals(0, gate(controller).get("active"));
            assertFalse(actions.local.contains("SYNTHETIC"));
        }
    }

    @Test void duplicateOfOldProtectedIdIsStillDroppedWithoutSpoofingItsCompletionWhileOff() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.CONTINUE, handler.handleHttpRequestToBeSent(request(1)).action());
            off(controller, true);
            assertEquals(RequestAction.DROP, handler.handleHttpRequestToBeSent(request(1)).action());
            assertEquals(1, gate(controller).get("active")); assertEquals(1, handler.inFlightCount());
            assertEquals(0L, controller.status().get("passthroughCount"));
            handler.handleHttpResponseReceived(response(1, "{}"));
            assertEquals(0, gate(controller).get("active"));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"PROJECT_SWITCH", "PROJECT_THROWS"})
    void offWithAnUnverifiableProjectRejectsWithoutFallingBackToNativeCapture(String cause) {
        MemoryProject backing = new MemoryProject(GuardConfig.defaults());
        var unavailable = new java.util.concurrent.atomic.AtomicBoolean();
        ProjectAccess project = new ProjectAccess() {
            @Override public Ref current() { if (unavailable.get()) throw new IllegalStateException("SYNTHETIC-SECRET"); return backing.current(); }
            @Override public String load() { return backing.load(); }
            @Override public void save(String json) { backing.save(json); }
        };
        GuardController controller = new GuardController(project); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            off(controller, true);
            var original = backing.ref; var oldToken = controller.passthroughToken(); long baseline = revision(controller);
            if (cause.equals("PROJECT_SWITCH")) backing.ref = new ProjectAccess.Ref("new-project", "Synthetic");
            else unavailable.set(true);
            var request = request(1);
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request).action());
            verify(request, never()).body(); verify(request, never()).headers(); verify(request, never()).url();
            verify(request, never()).httpService(); verify(request, never()).method();
            assertTrue(actions.local.contains("\"reason\":\"PROJECT_CHANGED\""));
            assertFalse(controller.exportJson(controller.traffic()).contains("example.test"));
            assertEquals(0L, controller.status().get("passthroughCount"));
            assertEquals(0, gate(controller).get("active"));
            assertEquals(false, controller.status().get("passthrough"));
            assertEquals(true, controller.status().get("passthroughEnded")); assertTrue(revision(controller) > baseline);
            backing.ref = original; unavailable.set(false); // No UI tick: returning to A must not revive OFF.
            assertFalse(controller.commitPassthrough(oldToken));
            var next = request(2);
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(next).action());
            verify(next, never()).body(); verify(next, never()).headers(); verify(next, never()).url();
        }
    }

    private static long revision(GuardController controller) { return ((Number) controller.status().get("revision")).longValue(); }
    private static void off(GuardController controller, boolean value) {
        controller.passthrough(value, (String) controller.status().get("projectId"), revision(controller));
    }
}
