package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import dev.cairnguard.model.DenialReasons;
import dev.cairnguard.model.GuardState;
import dev.cairnguard.runtime.GuardController;
import dev.cairnguard.runtime.GuardController.Admission;
import dev.cairnguard.runtime.GuardController.Prepared;
import dev.cairnguard.runtime.GuardController.PassthroughToken;
import dev.cairnguard.runtime.RateGate;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Semaphore;
import javax.swing.SwingUtilities;

/** Proxy-only native boundary. Native traffic is never sent by this extension or edited on allow. */
public final class ProxyGuardHandler implements HttpHandler, AutoCloseable {
    static final int MAX_CALLBACKS = 128;
    static final int MAX_INSPECTIONS = 8;
    static final int MAX_IN_FLIGHT = 100;
    private record Flight(String evidenceId, RateGate.Permit permit) {}
    private final GuardController controller;
    private final NativeActions actions;
    private final Semaphore callbacks;
    private final Semaphore inspections;
    private final Object releaseLock = new Object();
    private final Map<Integer, Flight> inFlight = new HashMap<>();
    private final Set<Integer> preparing = new HashSet<>(); // At most MAX_CALLBACKS; no native/raw data.
    private volatile boolean closed;

    public ProxyGuardHandler(GuardController controller) { this(controller, NativeActions.montoya()); }
    public ProxyGuardHandler(GuardController controller, NativeActions actions) {
        this(controller, actions, MAX_CALLBACKS, MAX_INSPECTIONS);
    }
    ProxyGuardHandler(GuardController controller, NativeActions actions, int callbackSlots, int inspectionSlots) {
        this.controller = Objects.requireNonNull(controller);
        this.actions = Objects.requireNonNull(actions);
        if (callbackSlots < 1 || callbackSlots > MAX_CALLBACKS || inspectionSlots < 1 || inspectionSlots > MAX_INSPECTIONS)
            throw new IllegalArgumentException("INVALID_ADAPTER_CAPACITY");
        callbacks = new Semaphore(callbackSlots);
        inspections = new Semaphore(inspectionSlots);
    }

    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        Annotations annotations = null;
        Prepared prepared = null;
        Admission admission = null;
        Flight flight = null;
        Integer messageId = null;
        boolean slot = false;
        boolean released = false;
        boolean ownsId = false;
        boolean collision = false;
        boolean passthroughAttempt = false;
        try {
            ToolType tool = Objects.requireNonNull(request.toolSource().toolType());
            annotations = request.annotations();
            if (tool != ToolType.PROXY) return Objects.requireNonNull(actions.continueRequest(request, annotations));
            messageId = request.messageId();
            synchronized (releaseLock) { collision = inFlight.containsKey(messageId) || preparing.contains(messageId); }
            if (collision) return block(rejected("MESSAGE_ID_COLLISION"), "MESSAGE_ID_COLLISION", annotations, true);
            if (closed) return block(rejected("SHUTDOWN"), "SHUTDOWN", annotations, false);
            GuardController.NativeMode mode = controller.nativeMode(messageId);
            if (mode.rejection() != null)
                return block(rejected(mode.rejection()), mode.rejection(), annotations, false);
            PassthroughToken token = mode.token();
            if (token != null) {
                passthroughAttempt = true;
                // Deliberately before capture, EDT checks, slots, approvals and rate admission.
                // No raw/native data, correlation entry or permit is retained for OFF traffic.
                RequestToBeSentAction continuation = Objects.requireNonNull(actions.continueRequest(request, annotations));
                synchronized (releaseLock) {
                    if (closed) return block(rejected("SHUTDOWN"), "SHUTDOWN", annotations, false);
                    collision = inFlight.containsKey(messageId) || preparing.contains(messageId);
                    if (collision) return block(rejected("MESSAGE_ID_COLLISION"), "MESSAGE_ID_COLLISION", annotations, true);
                    if (!controller.commitPassthrough(token))
                        return block(rejected("FINAL_CHECK_REJECTED"), "FINAL_CHECK_REJECTED", annotations, false);
                    return continuation;
                }
            }
            if (SwingUtilities.isEventDispatchThread())
                return block(rejected("CALLBACK_ON_EDT"), "CALLBACK_ON_EDT", annotations, false);
            slot = callbacks.tryAcquire();
            if (!slot) return block(rejected("CALLBACK_CAPACITY"), "CALLBACK_CAPACITY", annotations, false);
            synchronized (releaseLock) {
                collision = inFlight.containsKey(messageId) || !preparing.add(messageId);
                ownsId = !collision;
            }
            if (collision) return block(rejected("MESSAGE_ID_COLLISION"), "MESSAGE_ID_COLLISION", annotations, true);
            // This helper's frame (including RequestData and all body copies) ends BEFORE authorize waits.
            prepared = prepare(request);
            admission = Objects.requireNonNull(controller.authorize(prepared));
            if (!admission.allowed()) return block(prepared, admission.reason(), annotations, false);
            if (admission.permit() == null) throw new IllegalStateException("ADAPTER_ERROR");
            // Factories can fail or reenter UI. Build the original-object continuation BEFORE final commit.
            RequestToBeSentAction continuation = Objects.requireNonNull(actions.continueRequest(request, annotations));
            flight = new Flight(prepared.evidenceId(), admission.permit());
            synchronized (releaseLock) {
                if (closed) return block(prepared, "SHUTDOWN", annotations, false);
                if (inFlight.containsKey(messageId)) {
                    collision = true;
                    // A local spoof with an ambiguous ID could look like the older native completion.
                    // Drop this conclusively unsent duplicate instead; never replace the older permit.
                    return block(prepared, "MESSAGE_ID_COLLISION", annotations, true);
                }
                if (inFlight.size() >= MAX_IN_FLIGHT) return block(prepared, "CORRELATION_CAPACITY", annotations, false);
                inFlight.put(messageId, flight);
                GuardController.CommitResult committed = Objects.requireNonNull(controller.commitDetailed(prepared));
                if (!committed.allowed()) return block(prepared, committed.reason(), annotations, false);
                released = true;
                return continuation;
            }
        } catch (RuntimeException | LinkageError e) {
            // No exception message/cause, raw URL/header/body or operator pattern crosses this boundary.
            String reason = prepared == null && !passthroughAttempt ? "CAPTURE_FAILED" : "CONTINUATION_FAILED";
            if (prepared == null) prepared = rejected(reason);
            return block(prepared, reason, annotations, collision || messageId == null);
        } finally {
            synchronized (releaseLock) {
                if (ownsId) preparing.remove(messageId);
                if (!released && messageId != null && flight != null) inFlight.remove(messageId, flight);
            }
            if (!released && admission != null && admission.permit() != null) {
                // No native continuation has been returned: dispatch is conclusively not begun.
                admission.permit().close();
            }
            if (slot) callbacks.release();
        }
    }

    private Prepared prepare(HttpRequestToBeSent request) {
        // The slot bounds optional policy parsing only; the complete original copy is always taken.
        boolean inspection = inspections.tryAcquire();
        try {
            return controller.prepare(NativeCapture.request(request), inspection);
        } catch (NativeCapture.Rejected e) {
            return controller.prepareRejected(e.category());
        } catch (RuntimeException | LinkageError e) {
            return controller.prepareRejected("CAPTURE_FAILED");
        } finally { if (inspection) inspections.release(); }
    }

    private Prepared rejected(String category) {
        try { return controller.prepareRejected(category); }
        catch (RuntimeException | LinkageError e) { return null; }
    }

    private RequestToBeSentAction block(Prepared prepared, String reason, Annotations annotations, boolean dropOnly) {
        String category = category(reason);
        if (prepared != null) {
            try { controller.reject(prepared, category); }
            catch (RuntimeException | LinkageError ignored) { /* Denial must not depend on evidence availability. */ }
        }
        if (!dropOnly) {
            String id = prepared == null ? "unavailable" : evidenceId(prepared.evidenceId());
            GuardController.Denial denial = null;
            try { denial = controller.denial(prepared, category); }
            catch (RuntimeException | LinkageError ignored) { /* Fixed categorical fallback only. */ }
            String state = guardState(denial == null ? null : denial.guardState());
            long revision = denial == null ? 0 : Math.max(0, denial.policyRevision());
            String overlay = denial == null ? "unavailable" : evidenceId(denial.overlayId());
            // Preserve the original FIVE keys/order, append only typed fixed-alphabet metadata.
            // No request values, notes, paths, tags or exception strings can enter this document.
            String json = "{\"source\":\"cairn-proxy-guard\",\"outcome\":\"blocked\",\"reason\":\"" + category
                    + "\",\"evidenceId\":\"" + id + "\",\"retryable\":false,\"guardState\":\"" + state
                    + "\",\"local\":true,\"policyRevision\":" + revision
                    + (overlay.equals("unavailable") ? "" : ",\"overlayId\":\"" + overlay + "\"") + "}";
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            if (prepared != null) {
                try { controller.localResponse(prepared.evidenceId(), body); }
                catch (RuntimeException | LinkageError ignored) { /* Only fixed local bytes, never raw traffic. */ }
            }
            String wire = "HTTP/1.1 451 Unavailable For Legal Reasons\r\nContent-Type: application/json; charset=utf-8\r\n"
                    + "Cache-Control: no-store\r\nX-Cairn-Guard: blocked\r\nContent-Length: " + body.length + "\r\n\r\n" + json;
            try { return Objects.requireNonNull(actions.spoof(wire, annotations)); }
            catch (RuntimeException | LinkageError ignored) { /* Never fall back to a native continuation. */ }
        }
        try { return Objects.requireNonNull(actions.drop()); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_DENIAL_UNAVAILABLE"); }
    }

    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        // Permit lifetime follows an actual matching Proxy response, independent of capture/factory success.
        try {
            if (response.toolSource().toolType() == ToolType.PROXY) {
                Flight flight;
                synchronized (releaseLock) { flight = inFlight.remove(response.messageId()); }
                if (flight != null) {
                    flight.permit().close();
                    captureResponse(flight.evidenceId(), response);
                }
            }
        } catch (RuntimeException | LinkageError ignored) { /* Categorical omission; no native mutation or raw logging. */ }
        try { return Objects.requireNonNull(actions.continueResponse(response, response.annotations())); }
        catch (RuntimeException | LinkageError e) { throw new IllegalStateException("NATIVE_RESPONSE_CONTINUATION_UNAVAILABLE"); }
    }

    private void captureResponse(String evidenceId, HttpResponseReceived response) {
        // Scalars come from the native body length, never Content-Length. Response copies need no policy
        // inspection slot. Untracked OFF/unselected responses never get here.
        NativeCapture.Observation observed = NativeCapture.observe(response);
        NativeCapture.Response copy = NativeCapture.response(response, observed);
        controller.response(evidenceId, copy.status(), copy.headers(), copy.body(), copy.actualBytes(),
                copy.headersComplete(), copy.bodyComplete());
    }

    private static String category(String value) { return DenialReasons.category(value); }
    private static String guardState(String value) {
        try { return GuardState.valueOf(value).name(); }
        catch (RuntimeException ignored) { return GuardState.PROTECTED.name(); }
    }
    private static String evidenceId(String id) {
        if (id == null || id.length() != 36) return "unavailable";
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return "unavailable"; }
            else if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) return "unavailable";
        }
        return id;
    }
    int inFlightCount() { synchronized (releaseLock) { return inFlight.size(); } }

    /** Shutdown wakes all waits. It NEVER guesses completion or recycles outstanding native permits. */
    @Override public void close() {
        synchronized (releaseLock) {
            closed = true;
            controller.close();
        }
    }
}
