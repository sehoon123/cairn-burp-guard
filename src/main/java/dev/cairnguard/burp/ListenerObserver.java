package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import dev.cairnguard.runtime.GuardController;
import java.util.Objects;

/** Data-free inbound listener correlation. No content, destination fallback, intercept or edits. */
final class ListenerObserver implements ProxyRequestHandler {
    interface Actions {
        ProxyRequestReceivedAction received(InterceptedRequest request, Annotations annotations);
        ProxyRequestToBeSentAction sending(InterceptedRequest request, Annotations annotations);
    }
    private final GuardController controller;
    private final Actions actions;

    ListenerObserver(GuardController controller) {
        this(controller, new Actions() {
            @Override public ProxyRequestReceivedAction received(InterceptedRequest request, Annotations annotations) {
                return ProxyRequestReceivedAction.continueWith(request, annotations);
            }
            @Override public ProxyRequestToBeSentAction sending(InterceptedRequest request, Annotations annotations) {
                return ProxyRequestToBeSentAction.continueWith(request, annotations);
            }
        });
    }
    ListenerObserver(GuardController controller, Actions actions) {
        this.controller = Objects.requireNonNull(controller);
        this.actions = Objects.requireNonNull(actions);
    }
    @Override public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try { controller.recordListener(request.messageId(), request.listenerInterface()); }
        catch (RuntimeException | LinkageError ignored) {
            // Missing observation is UNKNOWN, never evidence for bypass. HttpHandler rejects an
            // unverified restricted listener before capture. No raw native exception is retained.
        }
        try { return Objects.requireNonNull(actions.received(request, request.annotations())); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_LISTENER_CONTINUATION_UNAVAILABLE"); }
    }
    @Override public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        // Do NOT record twice: identical duplicate observations must fail closed in the registry.
        try { return Objects.requireNonNull(actions.sending(request, request.annotations())); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_LISTENER_CONTINUATION_UNAVAILABLE"); }
    }
}
