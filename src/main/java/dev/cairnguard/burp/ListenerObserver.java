package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import java.util.Objects;

/** Original-object Proxy continuation only. Listener attribution is NOT supported here: native
 * Proxy and HTTP callbacks use distinct message-ID namespaces and have no documented shared key.
 * Equal numbers or annotations are not proof. Do not populate the controller's trusted registry.
 * With no supported producer, restricted-listener HTTP admission stays LISTENER_UNVERIFIED before
 * content capture. No content, listener/destination guessing, marker, annotation edit or I/O.
 */
final class ListenerObserver implements ProxyRequestHandler {
    interface Actions {
        ProxyRequestReceivedAction received(InterceptedRequest request, Annotations annotations);
        ProxyRequestToBeSentAction sending(InterceptedRequest request, Annotations annotations);
    }
    private final Actions actions;

    ListenerObserver() {
        this(new Actions() {
            @Override public ProxyRequestReceivedAction received(InterceptedRequest request, Annotations annotations) {
                return ProxyRequestReceivedAction.continueWith(request, annotations);
            }
            @Override public ProxyRequestToBeSentAction sending(InterceptedRequest request, Annotations annotations) {
                return ProxyRequestToBeSentAction.continueWith(request, annotations);
            }
        });
    }
    ListenerObserver(Actions actions) {
        this.actions = Objects.requireNonNull(actions);
    }
    @Override public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try { return Objects.requireNonNull(actions.received(request, request.annotations())); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_LISTENER_CONTINUATION_UNAVAILABLE"); }
    }
    @Override public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        // No cross-callback correlation, even if an ID or the original annotations happen to match.
        try { return Objects.requireNonNull(actions.sending(request, request.annotations())); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_LISTENER_CONTINUATION_UNAVAILABLE"); }
    }
}
