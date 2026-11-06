package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.fasterxml.jackson.databind.JsonNode;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.runtime.GuardController;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

/** Synthetic in-process adapter tests. No real Burp, target traffic, auth API or sockets involved. */
@SuppressWarnings("try") // Explicit shutdown precedes late-response and waiter checks.
class ProxyGuardHandlerTest {
    @Test void allowedNativeRequestAndResponseAndAnnotationsAreTheSameObjects() throws Exception {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1);
            RequestToBeSentAction sent = handler.handleHttpRequestToBeSent(request);
            assertEquals(RequestAction.CONTINUE, sent.action()); assertSame(request, sent.request()); assertSame(request.annotations(), sent.annotations());
            assertEquals(1, handler.inFlightCount());
            assertEquals("FORWARDED", controller.traffic().getFirst().disposition());
            assertNull(actions.local);
            HttpResponseReceived response = response(1, "{\"ok\":true,\"token\":\"SYNTHETIC-RESPONSE-SECRET\"}");
            ResponseReceivedAction continued = handler.handleHttpResponseReceived(response);
            assertSame(response, continued.response()); assertSame(response.annotations(), continued.annotations());
            assertEquals(0, handler.inFlightCount());
            String exported = controller.exportJson(controller.traffic());
            assertTrue(exported.contains("Bearer SYNTHETIC-SECRET")); assertTrue(exported.contains("SYNTHETIC-RESPONSE-SECRET"), "evidence keeps originals");
            assertTrue(mockingDetails(request).getInvocations().stream().noneMatch(i -> i.getMethod().getName().startsWith("with")));
            assertTrue(mockingDetails(response).getInvocations().stream().noneMatch(i -> i.getMethod().getName().startsWith("with")));
            verifyNoInteractions(request.annotations(), response.annotations());
        }
    }
    @ParameterizedTest @EnumSource(value = ToolType.class, names = "PROXY", mode = EnumSource.Mode.EXCLUDE)
    void everyOtherToolBypassesInspectionAndIsUntouched(ToolType tool) {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1); when(request.toolSource()).thenReturn(source(tool));
            HttpResponseReceived response = response(1, "{}"); when(response.toolSource()).thenReturn(source(tool));
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            assertSame(response, handler.handleHttpResponseReceived(response).response());
            verify(request, never()).body(); verify(request, never()).url(); verify(request, never()).headers();
            verify(response, never()).body(); verify(response, never()).headers();
            assertTrue(controller.traffic().isEmpty());
        }
    }
    @Test void defaultDenySpoofsLocal451WithFixedJsonAndNoRawUrlOrSecret() throws Exception {
        GuardController controller = new GuardController(new MemoryProject(GuardConfig.defaults())); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1);
            when(request.url()).thenReturn("https://example.test/safe?token=SYNTHETIC-URL-SECRET");
            RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);
            assertEquals(RequestAction.SPOOF_RESPONSE, result.action()); assertSame(request.annotations(), result.annotations());
            JsonNode local = local(actions, "SCOPE_NOT_ALLOWED");
            assertEquals(controller.traffic().getFirst().id(), local.path("evidenceId").asText());
            assertFalse(actions.local.contains("example.test")); assertFalse(actions.local.contains("SYNTHETIC"));
            assertEquals("BLOCKED", controller.traffic().getFirst().disposition()); assertEquals(451, controller.traffic().getFirst().statusCode());
             assertEquals(0, handler.inFlightCount());
            handler.handleHttpResponseReceived(response(1, "{}"));

        }
    }
    @Test void optionalBodyCopyErrorOmitsBodyWithWarningButPreservesNativeContinuation() throws Exception {
        GuardController controller = spy(controller()); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1);
            doReturn(bytes(new byte[] {1})).when(request).body();
            when(request.body().getBytes()).thenThrow(new IllegalArgumentException("SYNTHETIC-EXCEPTION-SECRET"));
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            verify(controller, never()).prepareRejected(anyString()); verify(controller).prepare(any(RequestData.class), anyBoolean());
            assertTrue(controller.traffic().getFirst().inspectionWarnings().contains("BODY_INCOMPLETE"));
            assertNull(actions.local); assertFalse(controller.exportJson(controller.traffic()).contains("SYNTHETIC-EXCEPTION-SECRET"));
            handler.handleHttpResponseReceived(response(1, "{}"));
        }
    }
    @Test void unreadableHugeNativeBodyDoesNotDenyAndIsUnavailableNotInvented() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1); ByteArray body = mock(ByteArray.class);
            when(body.length()).thenReturn(Integer.MAX_VALUE); when(request.body()).thenReturn(body);
            assertSame(request, handler.handleHttpRequestToBeSent(request).request());
            assertEquals(1, handler.inFlightCount()); // mocked getBytes() supplies nothing
            assertTrue(controller.traffic().getFirst().inspectionWarnings().contains("BODY_INCOMPLETE"));
            handler.handleHttpResponseReceived(response(1, "{}"));
        }
    }
    @Test void unknownToolSourceIsNeverImplicitlyAllowed() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1); when(request.toolSource()).thenThrow(new IllegalStateException("SYNTHETIC-SECRET"));
            assertEquals(RequestAction.DROP, handler.handleHttpRequestToBeSent(request).action());
            verify(request, never()).body(); assertTrue(controller.traffic().getFirst().request().contains("OMITTED"));
        }
    }
    @Test void cannotWaitOrInspectOnEdt() throws Exception {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            HttpRequestToBeSent request = request(1); AtomicReference<RequestToBeSentAction> result = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> result.set(handler.handleHttpRequestToBeSent(request)));
            assertEquals(RequestAction.SPOOF_RESPONSE, result.get().action()); local(actions, "CALLBACK_ON_EDT");
            verify(request, never()).body(); assertTrue(controller.approvals().isEmpty());
        }
    }
    @Test void boundedCallbackSlotsRejectWithoutCapturingAnotherBodyWhileApprovalWaits() throws Exception {
        GuardController controller = new GuardController(new MemoryProject(config(Mode.ASK, 5, 60_000))); Actions actions = new Actions();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 1, 1)) {
            HttpRequestToBeSent first = request(1); Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(first));
            await(() -> controller.approvals().size() == 1);
             verify(first.body()).getBytes();
            HttpRequestToBeSent second = request(2);
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(second).action());
            local(actions, "CALLBACK_CAPACITY"); verify(second, never()).body();
            assertTrue(controller.decideApproval(controller.approvals().getFirst().id(), true));
            assertEquals(RequestAction.CONTINUE, pending.get(3, TimeUnit.SECONDS).action());
            handler.handleHttpResponseReceived(response(1, "{}"));
        } finally { worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void inspectionSlotEndsBeforeApprovalWaitAndCarriesNoExtraBodyCopies() throws Exception {
        GuardController controller = new GuardController(new MemoryProject(config(Mode.ASK, 5, 60_000))); Actions actions = new Actions();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 2, 1)) {
            HttpRequestToBeSent first = request(1), second = request(2);
            Future<RequestToBeSentAction> a = workers.submit(() -> handler.handleHttpRequestToBeSent(first));
            await(() -> controller.approvals().size() == 1);
            Future<RequestToBeSentAction> b = workers.submit(() -> handler.handleHttpRequestToBeSent(second));
            await(() -> controller.approvals().size() == 2);
            verify(first.body()).getBytes(); verify(second.body()).getBytes();

            controller.pause(true);
            assertEquals(RequestAction.SPOOF_RESPONSE, a.get(3, TimeUnit.SECONDS).action());
            assertEquals(RequestAction.SPOOF_RESPONSE, b.get(3, TimeUnit.SECONDS).action());
            assertEquals(0, handler.inFlightCount());
        } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void boundedInspectionParallelismUsesTryAcquireWithoutSkippingTheOriginalCopy() throws Exception {
        GuardController controller = controller(); Actions actions = new Actions(); ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 2, 1)) {
            HttpRequestToBeSent first = request(1);
            when(first.body().getBytes()).thenAnswer(i -> { entered.countDown(); if (!release.await(3, TimeUnit.SECONDS)) throw new IllegalStateException(); return new byte[0]; });
            Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(first));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            HttpRequestToBeSent second = request(2);
            assertSame(second, handler.handleHttpRequestToBeSent(second).request());
            verify(second).headers(); verify(second.body()).getBytes();
            assertTrue(controller.traffic().getFirst().inspectionWarnings().isEmpty(), "no rule demanded content; nothing is falsely incomplete");
            release.countDown(); assertEquals(RequestAction.CONTINUE, pending.get(3, TimeUnit.SECONDS).action());
            handler.handleHttpResponseReceived(response(1, "{}")); handler.handleHttpResponseReceived(response(2, "{}"));
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void continuationFactoryFailureNeverCommitsOrAssociatesResponseEvidence() throws Exception {
        GuardController controller = controller();
        Actions actions = new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) { throw new IllegalStateException("SYNTHETIC-FACTORY-SECRET"); }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            local(actions, "CONTINUATION_FAILED"); assertFalse(actions.local.contains("SYNTHETIC"));
             assertEquals(0, handler.inFlightCount());
            assertEquals("BLOCKED", controller.traffic().getFirst().disposition());
        }
    }
    @Test void nullContinuationFactoryNeverCommits() {
        GuardController controller = spy(controller());
        Actions actions = new Actions() { @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) { return null; } };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            verify(controller, never()).commitDetailed(any());
        }
    }
    @Test void nativeActionIsConstructedBeforeFinalCommitAndPolicyChangeDuringFactoryBlocks() throws Exception {
        GuardController controller = controller();
        Actions actions = new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) {
                assertNotEquals("FORWARDED", controller.traffic().getFirst().disposition()); controller.pause(true);
                return super.continueRequest(request, annotations);
            }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            local(actions, "PAUSED"); assertEquals(0, handler.inFlightCount());
        }
    }
    @Test void projectChangeInsideFactoryBlocksWithoutAssociatingOldEvidence() throws Exception {
        MemoryProject project = new MemoryProject(config(Mode.ALLOW, 5, 60_000)); GuardController controller = new GuardController(project);
        Actions actions = new Actions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) {
                project.ref = new dev.cairnguard.runtime.ProjectAccess.Ref("other-project", "Other fixture");
                return super.continueRequest(request, annotations);
            }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            local(actions, "PROJECT_CHANGED");
        }
    }
    @Test void duplicateOutstandingIdAllowsBothButNeverPairsEitherResponse() {
        var controller=controller(); var actions=new Actions();
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            var first=request(1); var second=request(1);
            assertSame(first,handler.handleHttpRequestToBeSent(first).request());
            assertSame(second,handler.handleHttpRequestToBeSent(second).request());
            assertEquals(0,handler.inFlightCount()); assertEquals(2,controller.traffic().size());
            var requests=List.copyOf(controller.traffic());
            handler.handleHttpResponseReceived(response(1,"ambiguous-full-synthetic-[REDACTED]"));
            for(var row:requests) assertNull(controller.rawResponse(row.id()));
            var unpaired=controller.traffic().getFirst();
            assertEquals("unpaired_response",unpaired.outcome()); assertFalse(unpaired.requestCapture().present());
            assertTrue(controller.rawResponse(unpaired.id()).contains("ambiguous-full-synthetic-[REDACTED]"));
        }
    }
    @Test void duplicateIdDuringApprovalDoesNotBypassOrDenyExplicitAsk() throws Exception {
        var controller=new GuardController(new MemoryProject(config(Mode.ASK,5,60_000)));
        try(var handler=new ProxyGuardHandler(controller,new Actions());var workers=Executors.newVirtualThreadPerTaskExecutor()) {
            var one=workers.submit(()->handler.handleHttpRequestToBeSent(request(1)));
            await(()->controller.approvals().size()==1);
            var two=workers.submit(()->handler.handleHttpRequestToBeSent(request(1)));
            await(()->controller.approvals().size()==2);
            for(var pending:controller.approvals()) controller.decideApproval(pending.id(),true);
            assertEquals(RequestAction.CONTINUE,one.get(3,TimeUnit.SECONDS).action());
            assertEquals(RequestAction.CONTINUE,two.get(3,TimeUnit.SECONDS).action());
            assertEquals(0,handler.inFlightCount());
        }
    }
    @Test void deniedDuplicateCannotTurnItsLocalResponseIntoAnOlderUpstreamPair() {
        var controller=controller(); var actions=new Actions();
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            handler.handleHttpRequestToBeSent(request(1)); var old=controller.traffic().getFirst().id();
            var duplicate=request(1); when(duplicate.httpService().host()).thenReturn("outside.test");
            assertEquals(RequestAction.SPOOF_RESPONSE,handler.handleHttpRequestToBeSent(duplicate).action());
            handler.handleHttpResponseReceived(response(1,"local-or-upstream-unknown"));
            assertNull(controller.rawResponse(old));
        }
    }
    @Test void unreadableIdDoesNotDenyButCannotInventResponseProvenance() {
        var controller=controller(); var actions=new Actions();
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            var request=request(1); when(request.messageId()).thenThrow(new IllegalStateException("SYNTHETIC"));
            assertSame(request,handler.handleHttpRequestToBeSent(request).request());
            handler.handleHttpResponseReceived(response(1,"unknown"));
            assertNull(controller.rawResponse(controller.traffic().getFirst().id()));
            assertEquals(0,handler.inFlightCount()); assertNull(actions.local);
        }
    }
    @Test void missingCallbackPastOldTimeoutAndHundredFlightCliffAllowsLaterPathsAndHosts() throws Exception {
        var base=config(Mode.ALLOW,1,1);
        var scopes=new java.util.ArrayList<>(base.allowScope()); scopes.add(new GuardConfig.ScopeEntry(true,"other.test","https",443,""));
        var policy=new GuardConfig(2,scopes,List.of(),List.of(),Mode.ALLOW,base.limits());
        var controller=new GuardController(new MemoryProject(policy)); var actions=new Actions();
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            var first=request(1); assertSame(first,handler.handleHttpRequestToBeSent(first).request());
            var old=controller.traffic().getFirst().id(); Thread.sleep(5);
            for(int id=2;id<=127;id++) {
                var next=request(id); when(next.path()).thenReturn(id%3==0?"/safe":"/later/"+id);
                if(id%2==0) when(next.httpService().host()).thenReturn("other.test");
                assertSame(next,handler.handleHttpRequestToBeSent(next).request(),"request "+id);
            }
            assertEquals(127,handler.inFlightCount()); assertEquals(127,controller.traffic().size());
            assertNull(controller.rawResponse(old)); assertNull(actions.local);
            var late=response(1,"late-full-original"); assertSame(late,handler.handleHttpResponseReceived(late).response());
            assertTrue(controller.rawResponse(old).contains("late-full-original"));
            handler.close(); handler.handleHttpResponseReceived(response(2,"after-close")); assertTrue(controller.traffic().isEmpty());
        }
    }
    @Test void responseMismatchAndDuplicatesNeverPairOtherProtectedRequests() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            handler.handleHttpRequestToBeSent(request(1)); handler.handleHttpRequestToBeSent(request(2));
            handler.handleHttpResponseReceived(response(99, "{}"));
            HttpResponseReceived repeater = response(1, "{}"); when(repeater.toolSource()).thenReturn(source(ToolType.REPEATER));
            handler.handleHttpResponseReceived(repeater);
            handler.handleHttpResponseReceived(response(1, "{}")); handler.handleHttpResponseReceived(response(1, "{}"));
             assertEquals(1, handler.inFlightCount());
            handler.handleHttpResponseReceived(response(2, "{}"));
        }
    }
    @Test void matchingNormal500AndRepeatedFailuresNeverDenyTheNextOriginal() {
        var controller=controller(); var actions=new Actions();
        try(var handler=new ProxyGuardHandler(controller,actions)) {
            for(int id=1;id<=125;id++) {
                var request=request(id); assertSame(request,handler.handleHttpRequestToBeSent(request).request());
                var response=response(id,"synthetic-full-500"); when(response.statusCode()).thenReturn((short)500);
                assertSame(response,handler.handleHttpResponseReceived(response).response());
                assertEquals(500,controller.traffic().getFirst().statusCode());
            }
            var next=request(126); assertSame(next,handler.handleHttpRequestToBeSent(next).request());
            assertNull(actions.local); assertEquals("PROTECTED",controller.status().get("guardState"));
        }
    }
    @Test void spoofFactoryFailureDropsAndBothDenialFactoriesFailCategorically() {
        GuardController controller = new GuardController(new MemoryProject(GuardConfig.defaults()));
        Actions actions = new Actions() { @Override public RequestToBeSentAction spoof(String wire, Annotations annotations) { throw new IllegalStateException("SYNTHETIC-SECRET"); } };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.DROP, handler.handleHttpRequestToBeSent(request(1)).action()); assertEquals(1, actions.drops);
        }
        GuardController second = new GuardController(new MemoryProject(GuardConfig.defaults()));
        Actions broken = new Actions() {
            @Override public RequestToBeSentAction spoof(String wire, Annotations annotations) { throw new IllegalStateException("SYNTHETIC-SECRET"); }
            @Override public RequestToBeSentAction drop() { throw new IllegalStateException("SYNTHETIC-SECRET"); }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(second, broken)) {
            IllegalStateException error = assertThrows(IllegalStateException.class, () -> handler.handleHttpRequestToBeSent(request(2)));
            assertEquals("NATIVE_DENIAL_UNAVAILABLE", error.getMessage()); assertNull(error.getCause());
        }
    }
    @Test void originalsAreCompleteWhileInspectionSlotIsHeldAndOnlyDemandedInspectionIsUnavailable() throws Exception {
        GuardConfig base = config(Mode.ALLOW, 5, 60_000);
        GuardConfig policy = new GuardConfig(2, base.allowScope(), List.of(), List.of(new GuardConfig.Rule("ex", "body exemption", true,
                Mode.EXEMPT, GuardConfig.Condition.leaf(GuardConfig.Field.BODY, GuardConfig.Match.CONTAINS, "SYNTH-SLOT-BODY"))), Mode.ALLOW, base.limits());
        GuardController controller = new GuardController(new MemoryProject(policy)); Actions actions = new Actions();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 2, 1)) {
            HttpRequestToBeSent first = request(1);
            when(first.body().getBytes()).thenAnswer(i -> { entered.countDown(); if (!release.await(3, TimeUnit.SECONDS)) throw new IllegalStateException(); return new byte[0]; });
            Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(first));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            HttpRequestToBeSent second = request(2);
            when(second.headers()).thenReturn(List.of(header("Authorization", "Bearer SYNTH-SLOT-AUTH"), header("Content-Type", "text/plain")));
            doReturn(bytes("SYNTH-SLOT-BODY".getBytes(java.nio.charset.StandardCharsets.UTF_8))).when(second).body();
            assertSame(second, handler.handleHttpRequestToBeSent(second).request(), "saturation is not an automatic 451");
            TrafficEntry row = controller.traffic().getFirst();
            assertEquals("forwarded", row.outcome(), "missing demanded inspection never grants EXEMPT");
            assertEquals(List.of("BODY_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY"), row.inspectionWarnings());
            String raw = controller.rawRequest(row.id());
            assertTrue(raw.contains("Bearer SYNTH-SLOT-AUTH") && raw.contains("SYNTH-SLOT-BODY"));
            assertEquals(true, controller.rawCaptureInfo(row.id()).get("headersComplete"));
            assertEquals(true, controller.rawCaptureInfo(row.id()).get("bodyComplete"));
            release.countDown(); assertEquals(RequestAction.CONTINUE, pending.get(3, TimeUnit.SECONDS).action());
            handler.handleHttpResponseReceived(response(1, "{}")); handler.handleHttpResponseReceived(response(2, "{}"));
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void originalsResponseIsCapturedWhileRequestInspectionSlotIsHeld() throws Exception {
        GuardController controller = controller(); Actions actions = new Actions(); ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 2, 1)) {
            handler.handleHttpRequestToBeSent(request(1));
            HttpRequestToBeSent second = request(2);
            when(second.body().getBytes()).thenAnswer(i -> { entered.countDown(); if (!release.await(3, TimeUnit.SECONDS)) throw new IllegalStateException(); return new byte[0]; });
            Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(second));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            handler.handleHttpResponseReceived(response(1, "{\"token\":\"SYNTH-RESPONSE-ORIGINAL\"}"));

            TrafficEntry row = controller.traffic().stream().filter(e -> e.statusCode() != null && e.statusCode() == 200).findFirst().orElseThrow();
            assertFalse(row.responseCapture().bodyOmitted());
            assertTrue(controller.rawResponse(row.id()).contains("SYNTH-RESPONSE-ORIGINAL"));
            assertTrue(controller.exportJson(controller.traffic()).contains("SYNTH-RESPONSE-ORIGINAL"));
            release.countDown(); assertEquals(RequestAction.CONTINUE, pending.get(3, TimeUnit.SECONDS).action());
            handler.handleHttpResponseReceived(response(2, "{}"));
        } finally { release.countDown(); worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void oversizedResponseUsesExplicitOmissionNotZeroSentinelAndContinuesOriginal() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            handler.handleHttpRequestToBeSent(request(1)); HttpResponseReceived response = response(1, "{}");
            ByteArray body = mock(ByteArray.class); when(body.length()).thenReturn(Integer.MAX_VALUE); when(response.body()).thenReturn(body);
            assertSame(response, handler.handleHttpResponseReceived(response).response()); // mocked getBytes() supplies nothing
            TrafficEntry row = controller.traffic().getFirst(); assertTrue(row.responseCapture().bodyOmitted()); assertTrue(row.truncated());
             assertEquals(0, handler.inFlightCount());
        }
    }
    @Test void responseCaptureFailureIsCategoricalOmissionAndManyHeadersAreRetainedWhole() {
        GuardController controller = controller(); Actions actions = new Actions();
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            handler.handleHttpRequestToBeSent(request(1)); HttpResponseReceived response = response(1, "{}");
            when(response.body().getBytes()).thenThrow(new IllegalArgumentException("SYNTHETIC-RESPONSE-SECRET"));
            assertSame(response, handler.handleHttpResponseReceived(response).response());
            assertTrue(controller.traffic().getFirst().responseCapture().bodyOmitted());
            handler.handleHttpRequestToBeSent(request(2)); HttpResponseReceived second = response(2, "{}");
            when(second.headers()).thenReturn(java.util.Collections.nCopies(257, header("X-Secret", "SYNTHETIC-HEADER-SECRET")));
            assertSame(second, handler.handleHttpResponseReceived(second).response()); verify(second).body();
            assertEquals(true, controller.rawCaptureInfo(controller.traffic().getFirst().id()).get("responseHeadersComplete"));
            assertEquals(257, controller.traffic().getFirst().responseCapture().headers().size());
            assertFalse(controller.traffic().getFirst().responseCapture().bodyOmitted());
            String exported = controller.exportJson(controller.traffic());
            assertFalse(exported.contains("SYNTHETIC-RESPONSE-SECRET"), "native exception text is never captured");
            assertTrue(exported.contains("SYNTHETIC-HEADER-SECRET"));
        }
    }
    @Test void responseContinuationFailureKeepsObservedEvidenceWithoutExceptionContent() {
        GuardController controller = controller();
        Actions actions = new Actions() {
            @Override public ResponseReceivedAction continueResponse(HttpResponseReceived response, Annotations annotations) { throw new IllegalStateException("SYNTHETIC-SECRET"); }
        };
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            handler.handleHttpRequestToBeSent(request(1));
            IllegalStateException error = assertThrows(IllegalStateException.class, () -> handler.handleHttpResponseReceived(response(1, "{}")));
            assertEquals("NATIVE_RESPONSE_CONTINUATION_UNAVAILABLE", error.getMessage()); assertNull(error.getCause());
             assertEquals(0, handler.inFlightCount());
            assertTrue(controller.rawResponse(controller.traffic().getFirst().id()).contains("{}"));
        }
    }
    @Test void closeWakesApprovalWaitAndRejectsNewRequestsWithoutBodyRead() throws Exception {
        GuardController controller = new GuardController(new MemoryProject(config(Mode.ASK, 5, 60_000))); Actions actions = new Actions();
        ExecutorService worker = Executors.newSingleThreadExecutor(); ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions);
        try {
            Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(request(1)));
            await(() -> controller.approvals().size() == 1); handler.close();
            assertEquals(RequestAction.SPOOF_RESPONSE, pending.get(3, TimeUnit.SECONDS).action()); assertTrue(controller.approvals().isEmpty());
            HttpRequestToBeSent second = request(2);
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(second).action());
            verify(second, never()).body(); local(actions, "SHUTDOWN");
        } finally { handler.close(); worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void closeWakesPacingWaitAndDisposesOnlyEvidenceMetadata() throws Exception {
        var base=config(Mode.ALLOW,1,60_000); var l=base.limits();
        var paced=new GuardConfig(base.schemaVersion(),base.allowScope(),base.blockScope(),base.rules(),base.defaultMode(),
                new GuardConfig.Limits(1,0,Map.of(),l.maxConcurrent(),l.maxQueued(),l.queueTimeoutMillis(),l.approvalTimeoutMillis(),l.requestTimeoutMillis()));
        GuardController controller = new GuardController(new MemoryProject(paced)); Actions actions = new Actions();
        ExecutorService worker = Executors.newSingleThreadExecutor(); ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions, 2, 1);
        try {
            handler.handleHttpRequestToBeSent(request(1)); HttpRequestToBeSent second = request(2);
            Future<RequestToBeSentAction> pending = worker.submit(() -> handler.handleHttpRequestToBeSent(second));
            await(() -> ((Number) gate(controller).get("queued")).intValue() == 1);
            verify(second.body()).getBytes(); handler.close();
            assertEquals(RequestAction.SPOOF_RESPONSE, pending.get(3, TimeUnit.SECONDS).action());
             assertEquals(0, handler.inFlightCount());
            handler.handleHttpResponseReceived(response(1, "{}"));
        } finally { handler.close(); worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)); }
    }
    @Test void unknownControllerCategoriesAndEvidenceIdNeverEchoArbitraryContent() throws Exception {
        GuardController controller = spy(controller()); Actions actions = new Actions();
        doReturn(new GuardController.Admission(false, "SYNTHETIC-REASON-SECRET")).when(controller).authorize(any());
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            local(actions, "ADAPTER_ERROR"); assertFalse(actions.local.contains("SYNTHETIC"));
        }
    }
    @Test void malformedEvidenceIdIsNeverEchoedIntoLocalJson() throws Exception {
        GuardController controller = spy(controller()); Actions actions = new Actions();
        doReturn(new GuardController.Prepared("SYNTHETIC-EVIDENCE-SECRET", "fixture-project", 1, "blocked.invalid",
                dev.cairnguard.model.Decision.blocked("RULE_BLOCK"))).when(controller).prepare(any(), anyBoolean());
        try (ProxyGuardHandler handler = new ProxyGuardHandler(controller, actions)) {
            assertEquals(RequestAction.SPOOF_RESPONSE, handler.handleHttpRequestToBeSent(request(1)).action());
            assertEquals("unavailable", local(actions, "RULE_BLOCK").path("evidenceId").asText()); assertFalse(actions.local.contains("SYNTHETIC"));
        }
    }
    @Test void clearCannotEraseUsedIdFencingOrResurrectAnOldResponse() {
        var controller=controller();
        try(var handler=new ProxyGuardHandler(controller,new Actions())) {
            handler.handleHttpRequestToBeSent(request(1)); var old=controller.traffic().getFirst().id();
            controller.clearEvidence(); handler.handleHttpResponseReceived(response(1,"cleared-old"));
            assertTrue(controller.traffic().isEmpty()); assertNull(controller.rawResponse(old));
            handler.handleHttpRequestToBeSent(request(1)); var reused=controller.traffic().getFirst().id();
            handler.handleHttpResponseReceived(response(1,"duplicate-old-or-new-unknown"));
            assertNull(controller.rawResponse(reused));
        }
    }

    private static JsonNode local(Actions actions, String reason) throws Exception {
        String wire = actions.local; assertNotNull(wire); assertTrue(wire.startsWith("HTTP/1.1 451 "));
        JsonNode json = Json.MAPPER.readTree(wire.substring(wire.indexOf("\r\n\r\n") + 4));
        assertTrue(json.size() == 8 || json.size() == 9); assertEquals("cairn-proxy-guard", json.path("source").asText());
        assertTrue(json.path("local").asBoolean()); assertTrue(json.path("policyRevision").canConvertToLong());
        assertDoesNotThrow(() -> dev.cairnguard.model.GuardState.valueOf(json.path("guardState").asText()));
        java.util.List<String> keys = new java.util.ArrayList<>(); json.fieldNames().forEachRemaining(keys::add);
        assertEquals(List.of("source", "outcome", "reason", "evidenceId", "retryable", "guardState", "local", "policyRevision"), keys.subList(0, 8));
        assertEquals("blocked", json.path("outcome").asText()); assertEquals(reason, json.path("reason").asText());
        assertFalse(json.path("retryable").asBoolean(true)); assertFalse(json.path("evidenceId").asText().isBlank());
        return json;
    }
    private static void await(BooleanSupplier predicate) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!predicate.getAsBoolean() && System.nanoTime() < until) Thread.sleep(5);
        assertTrue(predicate.getAsBoolean(), "Synthetic callback failed to reach expected state");
    }
}
