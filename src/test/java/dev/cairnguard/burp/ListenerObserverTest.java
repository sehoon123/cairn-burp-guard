package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.proxy.MessageToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.runtime.GuardController;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Native testing falsified cross-namespace correlation. These regressions prevent false proof. */
class ListenerObserverTest {
    private record Received(HttpRequest request, Annotations annotations) implements ProxyRequestReceivedAction {
        @Override public MessageReceivedAction action() { return MessageReceivedAction.CONTINUE; }
    }
    private record Sending(HttpRequest request, Annotations annotations) implements ProxyRequestToBeSentAction {
        @Override public MessageToBeSentAction action() { return MessageToBeSentAction.CONTINUE; }
    }
    private final ListenerObserver.Actions actions = new ListenerObserver.Actions() {
        @Override public ProxyRequestReceivedAction received(InterceptedRequest r, Annotations a) { return new Received(r, a); }
        @Override public ProxyRequestToBeSentAction sending(InterceptedRequest r, Annotations a) { return new Sending(r, a); }
    };
    @Test void unsupportedBridgeReadsOnlyAnnotationsAndContinuesOriginalObjects() {
        var observer = new ListenerObserver(actions);
        var request = mock(InterceptedRequest.class); var annotations = mock(Annotations.class);
        when(request.messageId()).thenReturn(7); when(request.listenerInterface()).thenReturn("127.0.0.1:8081"); when(request.annotations()).thenReturn(annotations);
        var received = observer.handleRequestReceived(request); var sending = observer.handleRequestToBeSent(request);
        assertSame(request, received.request()); assertSame(request, sending.request()); assertSame(annotations, received.annotations()); assertSame(annotations, sending.annotations());
        assertTrue(mockingDetails(request).getInvocations().stream().allMatch(i -> Set.of("annotations").contains(i.getMethod().getName())));
        verifyNoInteractions(annotations);
    }
    @Test void observerFailureCannotInventUnselectedMappingAndNeverFallsBackToDestination() {
        var base = config(Mode.ALLOW, 5, 60_000);
        GuardController controller = new GuardController(new MemoryProject(new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(), base.limits(), List.of(8080))));
        var observer = new ListenerObserver(actions); var request = mock(InterceptedRequest.class);
        when(request.messageId()).thenReturn(7); when(request.listenerInterface()).thenThrow(new LinkageError("SYNTHETIC"));
        assertSame(request, observer.handleRequestReceived(request).request());
        assertEquals("LISTENER_UNVERIFIED", controller.nativeMode(7).rejection()); verify(request, never()).httpService(); controller.close();
    }
    @ParameterizedTest @CsvSource({"8080,7", "8081,7", "8080,8", "8081,8"})
    void proxyNamespaceIdsAndOriginalAnnotationIdentityCannotAuthorizeHttpListener(int inboundPort, int httpId) throws Exception {
        var base = config(Mode.ALLOW, 5, 60_000);
        var policy = new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(), base.limits(), List.of(8080));
        try (var controller = new GuardController(new MemoryProject(policy))) {
            var sharedAnnotations = mock(Annotations.class);
            var proxy = mock(InterceptedRequest.class);
            when(proxy.messageId()).thenReturn(7);
            when(proxy.listenerInterface()).thenReturn("127.0.0.1:" + inboundPort);
            when(proxy.annotations()).thenReturn(sharedAnnotations);
            var observer = new ListenerObserver(actions);
            assertSame(proxy, observer.handleRequestReceived(proxy).request());
            assertSame(proxy, observer.handleRequestToBeSent(proxy).request());
            var http = request(httpId);
            when(http.annotations()).thenReturn(sharedAnnotations);
            var nativeActions = new Actions();
            try (var handler = new ProxyGuardHandler(controller, nativeActions)) {
                assertEquals(burp.api.montoya.http.handler.RequestAction.SPOOF_RESPONSE,
                        handler.handleHttpRequestToBeSent(http).action());
                var denial = dev.cairnguard.model.Json.MAPPER.readTree(nativeActions.local.substring(nativeActions.local.indexOf("\r\n\r\n") + 4));
                assertEquals("LISTENER_UNVERIFIED", denial.path("reason").asText());
                verify(http, never()).httpService(); verify(http, never()).headers();
                verify(http, never()).body(); verify(http, never()).path(); verify(http, never()).url();
                verify(proxy, never()).messageId(); verify(proxy, never()).listenerInterface();
                verifyNoInteractions(sharedAnnotations);
            }
        }
    }
    @Test void actionFactoryFailureIsCategoricalWithNoExceptionPayload() {
        var broken = new ListenerObserver.Actions() {
            @Override public ProxyRequestReceivedAction received(InterceptedRequest r, Annotations a) { throw new IllegalStateException("SYNTHETIC"); }
            @Override public ProxyRequestToBeSentAction sending(InterceptedRequest r, Annotations a) { return null; }
        };
        var observer = new ListenerObserver(broken); var request = mock(InterceptedRequest.class);
        var first = assertThrows(IllegalStateException.class, () -> observer.handleRequestReceived(request));
        var second = assertThrows(IllegalStateException.class, () -> observer.handleRequestToBeSent(request));
        for (var error : List.of(first, second)) { assertEquals("NATIVE_LISTENER_CONTINUATION_UNAVAILABLE", error.getMessage()); assertNull(error.getCause()); }
    }
}
