package dev.cairnguard.runtime;

import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.DenialReasons;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardState;
import dev.cairnguard.model.PolicyCodec;
import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.ui.GuardUiAccess;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Human UI policy + callback pipeline. No outbound HTTP, authentication actions or automatic saves. */
public final class GuardController implements GuardUiAccess, AutoCloseable {
    private record State(ProjectAccess.Ref project, GuardConfig config, long revision) {}
    private record Tracked(ResponseWatcher.Ticket ticket, long epoch, long started, long timeout) {}
    private static final int MAX_TICKETS = 4_096;
    private static final Set<String> RUNTIME_REASONS = Set.of("HEAVY_ENDPOINT_AUTO_BLOCKED", "CIRCUIT_OPEN",
            "FANOUT_SUSPECTED", "RESPONSE_WATCHER_CAPACITY", "INVALID_INTENT_TAG", "INTENT_BUDGET_EXCEEDED",
            "INTENT_BUDGET_CAPACITY", "LISTENER_UNVERIFIED");

    /**
     * Only opaque references, masked policy/display metadata and keyed attribution survive a wait.
     * No RequestData/body/native object is retained. The old constructor/accessors remain available;
     * caller-constructed projections have no admission provenance and cannot commit a send.
     */
    public static final class Prepared {
        private final String evidenceId;
        private final String projectId;
        private final long revision;
        private final String rateHost;
        private final Decision decision;
        private final ResponseWatcher.Endpoint endpoint;
        private final RequestAttribution attribution;
        private final boolean healthProbe;
        private final Object owner;
        // Controller mutation lock only. Authorization and handoff are one-shot, not replayable.
        private boolean authorizing;
        private boolean authorized;
        private boolean terminal;
        private String rejectedReason;
        private Denial denied;
        public Prepared(String evidenceId, String projectId, long revision, String rateHost, Decision decision) {
            this(evidenceId, projectId, revision, rateHost, decision, null, null, false, null);
        }
        private Prepared(String evidenceId, String projectId, long revision, String rateHost, Decision decision,
                         ResponseWatcher.Endpoint endpoint, RequestAttribution attribution, boolean healthProbe, Object owner) {
            this.evidenceId = evidenceId;
            this.projectId = projectId;
            this.revision = revision;
            this.rateHost = rateHost;
            this.decision = decision;
            this.endpoint = endpoint;
            this.attribution = attribution;
            this.healthProbe = healthProbe;
            this.owner = owner;
        }
        public String evidenceId() { return evidenceId; }
        public String projectId() { return projectId; }
        public long revision() { return revision; }
        public String rateHost() { return rateHost; }
        public Decision decision() { return decision; }
        public ResponseWatcher.Endpoint endpoint() { return endpoint; }
        public RequestAttribution attribution() { return attribution; }
        public boolean healthProbe() { return healthProbe; }
        @Override public String toString() {
            return "Prepared[evidenceId=" + evidenceId + ", revision=" + revision + ", decision=" + decision + "]";
        }
    }
    public record Admission(boolean allowed, String reason, RateGate.Permit permit) {}
    public record CommitResult(boolean allowed, String reason) {}
    public record Denial(String guardState, long policyRevision, String overlayId) {}
    public enum BypassKind { OFF, UNSELECTED_LISTENER }
    /** No native/raw data. Only instance-issued tokens can pass final generation/project checks. */
    public static final class PassthroughToken {
        private final String projectId;
        private final long revision;
        private final BypassKind kind;
        private final int listenerPort;
        private final Object owner;
        public PassthroughToken(String projectId, long revision) { this(projectId, revision, BypassKind.OFF, 0, null); }
        public PassthroughToken(String projectId, long revision, BypassKind kind, int listenerPort) {
            this(projectId, revision, kind, listenerPort, null);
        }
        private PassthroughToken(String projectId, long revision, BypassKind kind, int listenerPort, Object owner) {
            this.projectId = projectId; this.revision = revision; this.kind = kind;
            this.listenerPort = listenerPort; this.owner = owner;
        }
        public String projectId() { return projectId; }
        public long revision() { return revision; }
        public BypassKind kind() { return kind; }
        public int listenerPort() { return listenerPort; }
    }
    /** Exactly one of: protected (both null), count-only bypass token, or data-free rejection. */
    public record NativeMode(PassthroughToken token, String rejection) {}
    private static final NativeMode PROTECTED = new NativeMode(null, null);
    private final Object mutation = new Object();
    private final Object identity = new Object();
    private final ProjectAccess projects;
    private final PolicyEngine engine = new PolicyEngine();
    private final EvidenceStore evidence = new EvidenceStore();
    private final RateGate gate;
    private final ApprovalQueue approvals = new ApprovalQueue();
    private final ResponseWatcher watcher;
    private final IntentBudget intents;
    private final ListenerRegistry listeners;
    private final LongSupplier nanoTime;
    private final int ticketCapacity;
    private final Map<String, Tracked> tickets = new LinkedHashMap<>();
    // Diagnostic correlation may evict; unlike tickets it owns no enforcement/permit. Prevents old
    // project/cleared responses from applying display sanitizers to a new project epoch.
    private final Map<String, Long> captures = new LinkedHashMap<>();
    private final byte[] attributionKey = new byte[32];
    private final AtomicReference<State> state = new AtomicReference<>(new State(
            new ProjectAccess.Ref("unavailable", "Current Burp project"), GuardConfig.defaults(), 0));
    private volatile boolean operatorPaused;
    private volatile boolean resumeRequired;
    private volatile boolean passthrough;
    private boolean passthroughEnded;
    private long passthroughCount;
    private long unguardedListenerCount;
    private long runtimeEpoch;
    private boolean migrationPending;
    private String migrationOriginal = "";
    private volatile boolean reloadRequired;
    private volatile boolean closed;
    private volatile GuardState lifecycle = GuardState.PROTECTED;
    // Predicates run under ApprovalQueue/RateGate locks: latch ONLY, never take mutation or call
    // those queues here. The next serialized entry reconciles/reset the uncertain project epoch.
    private volatile boolean projectUnverified;
    private volatile String note = "INITIALIZING";

    public GuardController(ProjectAccess projects) {
        this(projects, new ResponseWatcher(GuardConfig.defaults().limits()), new IntentBudget(),
                new RateGate(GuardConfig.defaults().limits()), new ListenerRegistry(), System::nanoTime, MAX_TICKETS);
    }
    /** Package-local bounded, real-dependency fake-clock/capacity seam. */
    GuardController(ProjectAccess projects, ResponseWatcher watcher, IntentBudget intents, RateGate gate,
                    ListenerRegistry listeners, LongSupplier nanoTime, int ticketCapacity) {
        if (ticketCapacity < 1 || ticketCapacity > MAX_TICKETS) throw new IllegalArgumentException("INVALID_TICKET_CAPACITY");
        this.projects = Objects.requireNonNull(projects);
        this.watcher = Objects.requireNonNull(watcher);
        this.intents = Objects.requireNonNull(intents);
        this.gate = Objects.requireNonNull(gate);
        this.listeners = Objects.requireNonNull(listeners);
        this.nanoTime = Objects.requireNonNull(nanoTime);
        this.ticketCapacity = ticketCapacity;
        new SecureRandom().nextBytes(attributionKey);
        refreshProject();
    }

    /** This entire raw inspection frame ends before authorize() can wait. */
    public Prepared prepare(RequestData request) {
        Objects.requireNonNull(request);
        synchronized (mutation) {
            reconcileProjectFailure();
            State s = state.get();
            boolean health = lifecycle == GuardState.PROTECTED && healthProbe(s.config(), request);
            String failure = failure(s.project().id(), s.revision(), health);
            if (projectUnverified) { reconcileProjectFailure(); s = state.get(); }
            // NativeMode rejects these before native capture. Also defend direct/old adapter callers
            // against recording new contents through OFF, shutdown or an unverified project.
            if (passthrough || closed || reloadRequired || projectUnverified)
                return rejectedLocked(s, failure == null ? "POLICY_CHANGED" : failure);
            Decision decision = failure == null ? engine.evaluate(s.config(), request) : Decision.blocked(failure);
            String id = evidence.begin(s.project().id(), s.project().name(), request, decision, s.revision());
            rememberCapture(id);
            TrafficEntry safe = evidence.entry(id);
            Decision masked = new Decision(decision.mode(), category(decision.reason()), safe == null ? List.of() : safe.hits(),
                    safe == null ? List.of() : safe.inspectionWarnings());
            ResponseWatcher.Endpoint endpoint = null;
            String host = "blocked.invalid";
            if (decision.mode() != Mode.BLOCK) {
                try {
                    host = PolicyEngine.canonicalHost(request.host());
                    endpoint = watcher.endpoint(request, safe == null ? "https://redacted.invalid/" : safe.url(),
                            PolicyEngine.routingPaths(request));
                } catch (RuntimeException ignored) {
                    masked = Decision.blocked("RESPONSE_WATCHER_CAPACITY");
                    host = "blocked.invalid";
                }
            }
            RequestAttribution attribution = request.headersComplete() ? RequestAttribution.parse(request.headers())
                    : new RequestAttribution("?", "?", false);
            return new Prepared(id, s.project().id(), s.revision(), host, masked, endpoint,
                    hashAttribution(attribution), health, identity);
        }
    }

    /** No raw/native data is captured on adapter or listener failures. */
    public Prepared prepareRejected(String reason) {
        synchronized (mutation) {
            reconcileProjectFailure();
            return rejectedLocked(state.get(), category(reason));
        }
    }
    private Prepared rejectedLocked(State s, String reason) {
        RequestData omitted = new RequestData("UNKNOWN", "https://redacted.invalid/", "redacted.invalid", 443, true,
                List.of(new RequestData.Header("X-Cairn-Guard-Capture", "OMITTED")), new byte[0]);
        Decision decision = Decision.blocked(category(reason));
        String id = evidence.begin(s.project().id(), "Current Burp project", omitted, decision, s.revision());
        rememberCapture(id);
        Prepared p = new Prepared(id, s.project().id(), s.revision(), "blocked.invalid", decision,
                null, new RequestAttribution("-", "-", true), false, identity);
        p.denied = denialFor(reason, "");
        return p;
    }

    public Admission authorize(Prepared p) {
        synchronized (mutation) {
            reconcileProjectFailure();
            // Legacy caller-created BLOCK projections remain usable for categorical denial only.
            // They can neither acquire a permit nor mutate another entry by supplying its ID.
            if (!owned(p)) return new Admission(false, p != null && p.decision() != null && p.decision().mode() == Mode.BLOCK
                    ? category(p.decision().reason()) : "FINAL_CHECK_REJECTED", null);
            if (p.authorizing || p.authorized || p.terminal)
                return rejectLocked(p, p.rejectedReason != null ? p.rejectedReason : "FINAL_CHECK_REJECTED", null, "");
            p.authorizing = true;
            String failed = precheck(p);
            if (failed != null) return rejectLocked(p, failed, p.denied, "");
        }
        try {
            if (p.decision().mode() == Mode.ASK) {
                evidence.outcome(p.evidenceId(), "AWAITING_APPROVAL", "ASK", null);
                ApprovalQueue.Result result = approvals.await(p.evidenceId(), p.projectId(),
                        state.get().config().limits().approvalTimeoutMillis(), () -> current(p));
                if (!result.allowed()) return reject(p, result.reason());
            }
            synchronized (mutation) {
                String failed = precheck(p);
                if (failed != null) return rejectLocked(p, failed, p.denied, "");
                evidence.outcome(p.evidenceId(), "QUEUED", "QUEUED", null);
            }
            RateGate.Permit permit = gate.acquire(p.rateHost(), () -> current(p));
            synchronized (mutation) {
                String failed = precheck(p);
                if (failed != null) { permit.close(); return rejectLocked(p, failed, p.denied, ""); }
                p.authorized = true;
                return new Admission(true, "APPROVED", permit);
            }
        } catch (RateGate.Rejected e) {
            // A predicate cancellation must report the actual current lifecycle/project reason,
            // not hide PAUSED/SHUTDOWN/project uncertainty behind RateGate's generic POLICY_CHANGED.
            String failed = failure(p.projectId(), p.revision(), p.healthProbe());
            return reject(p, "POLICY_CHANGED".equals(e.reason()) && failed != null ? failed : e.reason());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return reject(p, "CANCELLED");
        }
    }

    /** Data-free observer seam, called only with the ACTUAL inbound listener, never service.port(). */
    public void recordListener(int messageId, String listenerInterface) {
        synchronized (mutation) {
            reconcileProjectFailure();
            State s = state.get();
            if (closed || reloadRequired || passthrough || s.config().guardListenerPorts().isEmpty()) return;
            if (!liveProject(s.project().id())) { reconcileProjectFailure(); return; }
            listeners.record(messageId, listenerInterface, s.revision());
        }
    }
    public NativeMode nativeMode() { return nativeModeFor(null); }
    public NativeMode nativeMode(int messageId) { return nativeModeFor(messageId); }
    private NativeMode nativeModeFor(Integer messageId) {
        synchronized (mutation) {
            reconcileProjectFailure();
            if (closed) return new NativeMode(null, "SHUTDOWN");
            if (reloadRequired) return new NativeMode(null, "PAUSED");
            State s = state.get();
            if (!liveProject(s.project().id())) {
                reconcileProjectFailure();
                return new NativeMode(null, "PROJECT_CHANGED");
            }
            // OFF is first: no correlation/capture even when listener restrictions are configured.
            if (passthrough) return new NativeMode(token(s, BypassKind.OFF, 0), null);
            if (s.config().guardListenerPorts().isEmpty()) return PROTECTED;
            OptionalInt port = messageId == null ? OptionalInt.empty() : listeners.consume(messageId, s.revision());
            if (port.isEmpty()) return new NativeMode(null, "LISTENER_UNVERIFIED");
            if (s.config().guardListenerPorts().contains(port.getAsInt())) return PROTECTED;
            return new NativeMode(token(s, BypassKind.UNSELECTED_LISTENER, port.getAsInt()), null);
        }
    }
    private PassthroughToken token(State s, BypassKind kind, int port) {
        return new PassthroughToken(s.project().id(), s.revision(), kind, port, identity);
    }
    public PassthroughToken passthroughToken() { return nativeMode().token(); }
    /** Atomic with human mode/project/config changes; no contents, permit or watcher ticket. */
    public boolean commitPassthrough(PassthroughToken token) {
        synchronized (mutation) {
            reconcileProjectFailure();
            State s = state.get();
            if (token == null || token.owner != identity || closed || reloadRequired
                    || !s.project().id().equals(token.projectId()) || s.revision() != token.revision()) return false;
            if (!liveProject(s.project().id())) { reconcileProjectFailure(); return false; }
            if (token.kind() == BypassKind.OFF && passthrough) {
                passthroughCount = increment(passthroughCount);
                return true;
            }
            if (token.kind() == BypassKind.UNSELECTED_LISTENER && !passthrough
                    && !s.config().guardListenerPorts().isEmpty() && token.listenerPort() >= 1
                    && token.listenerPort() <= 65_535 && !s.config().guardListenerPorts().contains(token.listenerPort())) {
                unguardedListenerCount = increment(unguardedListenerCount);
                return true;
            }
            return false;
        }
    }

    /** Atomic final recheck/claim/consume. No native side effects have begun. */
    public CommitResult commitDetailed(Prepared p) {
        synchronized (mutation) {
            reconcileProjectFailure();
            if (!owned(p)) return new CommitResult(false, "FINAL_CHECK_REJECTED");
            if (!p.authorized || p.terminal) return commitRejected(p, "FINAL_CHECK_REJECTED", null, "");
            String failed = precheck(p);
            if (failed != null) return commitRejected(p, failed, p.denied, "");
            reapTickets();
            if (tickets.size() >= ticketCapacity)
                return commitRejected(p, "RESPONSE_WATCHER_CAPACITY", null, "");
            ResponseWatcher.Ticket ticket;
            try { ticket = watcher.commit(p.endpoint(), p.healthProbe(), p.evidenceId()); }
            catch (ResponseWatcher.Rejected e) {
                return commitRejected(p, e.reason(), new Denial(e.guardState().name(), state.get().revision(), e.overlayId()), e.overlayId());
            }
            // Watcher goes FIRST: a final fanout/half-open rejection consumes no intent budget.
            // Both operations and all resets/config changes are under this same mutation lock.
            String budgetReason;
            try { budgetReason = intents.commit(p.attribution(), state.get().config().limits().perIntentMaxRequests()); }
            catch (RuntimeException e) { watcher.cancel(ticket); return commitRejected(p, "ADAPTER_ERROR", null, ""); }
            if (budgetReason != null) {
                watcher.cancel(ticket); // conclusively unsent; does NOT refund half-open cadence/native permits.
                return commitRejected(p, budgetReason, null, "");
            }
            tickets.put(p.evidenceId(), new Tracked(ticket, runtimeEpoch, nanoTime.getAsLong(),
                    TimeUnit.MILLISECONDS.toNanos(state.get().config().limits().requestTimeoutMillis())));
            p.terminal = true;
            String outcome = p.healthProbe() ? "probe_allowed" : ticket.halfOpen() ? "half_open"
                    : p.decision().mode() == Mode.EXEMPT ? "exempt" : "forwarded";
            // Evidence failure cannot turn an already consumed, valid final handoff into a local
            // rejection (or refund a possibly used quota). It has no native-completion ownership.
            try {
                evidence.context(p.evidenceId(), outcome, ticket.halfOpen() ? "CIRCUIT_OPEN" : "PROTECTED", "");
                evidence.outcome(p.evidenceId(), "FORWARDED", "NATIVE_RELEASED", null);
            } catch (RuntimeException ignored) { /* Do not log raw/native errors or alter admission. */ }
            return new CommitResult(true, "NATIVE_RELEASED");
        }
    }
    public boolean commit(Prepared p) { return commitDetailed(p).allowed(); }
    private CommitResult commitRejected(Prepared p, String reason, Denial denied, String overlay) {
        Admission rejected = rejectLocked(p, reason, denied, overlay);
        return new CommitResult(false, rejected.reason());
    }
    public Admission reject(Prepared p, String reason) {
        synchronized (mutation) {
            reconcileProjectFailure();
            return rejectLocked(p, reason, null, "");
        }
    }
    private Admission rejectLocked(Prepared p, String reason, Denial denied, String overlay) {
        reconcileProjectFailure();
        reason = category(reason);
        if (owned(p)) {
            // Preserve the precise watcher overlay from final commit when the adapter records the
            // same local denial a second time. Never infer lifecycle from the explanatory note.
            if (denied != null) p.denied = denied;
            else if (p.denied == null || !reason.equals(p.rejectedReason)) p.denied = denialFor(reason, overlay);
            p.rejectedReason = reason;
            p.terminal = true;
            evidence.context(p.evidenceId(), "blocked", p.denied.guardState(), p.denied.overlayId());
            evidence.outcome(p.evidenceId(), "BLOCKED", reason, 451);
        }
        return new Admission(false, reason, null);
    }
    public Denial denial(Prepared p, String reason) {
        synchronized (mutation) {
            if (owned(p) && p.denied != null && (p.rejectedReason == null || p.rejectedReason.equals(category(reason)))) return p.denied;
            return denialFor(category(reason), "");
        }
    }
    private Denial denialFor(String reason, String overlay) {
        GuardState cause = switch (category(reason)) {
            case "SHUTDOWN" -> GuardState.SHUTDOWN;
            case "PAUSED" -> lifecycle != GuardState.PROTECTED ? lifecycle
                    : resumeRequired ? GuardState.PROJECT_UNVERIFIED : GuardState.PAUSED_BY_OPERATOR;
            case "INVALID_CONFIG" -> GuardState.POLICY_INVALID;
            case "PROJECT_CHANGED", "POLICY_CHANGED" -> GuardState.PROJECT_UNVERIFIED;
            case "CIRCUIT_OPEN" -> GuardState.CIRCUIT_OPEN;
            case "HEAVY_ENDPOINT_AUTO_BLOCKED", "FANOUT_SUSPECTED" -> GuardState.OVERLAY_BLOCK;
            case "INVALID_INTENT_TAG", "INTENT_BUDGET_EXCEEDED", "INTENT_BUDGET_CAPACITY" -> GuardState.INTENT_BUDGET;
            case "LISTENER_UNVERIFIED" -> GuardState.LISTENER_UNVERIFIED;
            case "IN_FLIGHT_TIMEOUT" -> GuardState.IN_FLIGHT_STALLED;
            case "RESPONSE_WATCHER_CAPACITY", "HOST_CAPACITY", "QUEUE_FULL", "APPROVAL_CAPACITY", "CALLBACK_CAPACITY",
                    "INSPECTION_CAPACITY", "CORRELATION_CAPACITY" -> GuardState.CAPACITY;
            default -> GuardState.PROTECTED;
        };
        return new Denial(cause.name(), Math.max(0, state.get().revision()), uuid(overlay) ? overlay : "");
    }
    /** Advisory; never claims a half-open attempt or consumes a quota. mutation lock required. */
    private String precheck(Prepared p) {
        if (!owned(p)) return "FINAL_CHECK_REJECTED";
        String failed = failure(p.projectId(), p.revision(), p.healthProbe());
        if (failed != null) return failed;
        if (p.decision().mode() == Mode.BLOCK) return p.decision().reason();
        ResponseWatcher.Gate check = watcher.check(p.endpoint(), p.healthProbe());
        if (!check.allowed()) {
            p.denied = new Denial(check.guardState().name(), state.get().revision(), check.overlayId());
            return check.reason();
        }
        return intents.check(p.attribution(), state.get().config().limits().perIntentMaxRequests());
    }
    public boolean current(Prepared p) {
        // Do NOT acquire mutation: queues call this while holding their own locks.
        return owned(p) && failure(p.projectId(), p.revision(), p.healthProbe()) == null;
    }
    private boolean owned(Prepared p) { return p != null && p.owner == identity; }

    public void response(String id, int status, List<RequestData.Header> headers, byte[] body) {
        response(id, status, headers, body, body == null || body.length > RequestData.MAX_INSPECT_BYTES ? -1 : body.length, true, true);
    }
    public void response(String id, int status, List<RequestData.Header> headers, byte[] body, long actualResponseBytes) {
        response(id, status, headers, body, actualResponseBytes, true, true);
    }
    /** Actual native byte scalar is independent of optional bounded inspection/display copies. */
    public void response(String id, int status, List<RequestData.Header> headers, byte[] body,
                         long actualResponseBytes, boolean headersComplete, boolean bodyComplete) {
        synchronized (mutation) {
            if (!closed && !liveProject(state.get().project().id())) reconcileProjectFailure();
            reconcileProjectFailure();
            reapTickets();
            evidence.responseBytes(id, actualResponseBytes);
            evidence.response(id, status, headers, body, headersComplete, bodyComplete);
            // Learn response-only grants FIRST, then re-mask all existing watcher display state and
            // its pending flights. Never call a raw UI getter or replace text in serialized JSON.
            Tracked tracked = tickets.remove(id);
            boolean currentEpoch = tracked != null && tracked.epoch == runtimeEpoch
                    || Objects.equals(captures.get(id), runtimeEpoch);
            if (currentEpoch) watcher.refreshDisplay(evidence.displaySanitizer(id));
            if (tracked != null && tracked.epoch == runtimeEpoch) watcher.observe(tracked.ticket, status, actualResponseBytes);
        }
    }
    public void localResponse(String id, byte[] body) {
        synchronized (mutation) {
            evidence.response(id, 451, List.of(new RequestData.Header("Content-Type", "application/json"),
                    new RequestData.Header("X-Cairn-Guard", "blocked")), body);
            if (Objects.equals(captures.get(id), runtimeEpoch)) watcher.refreshDisplay(evidence.displaySanitizer(id));
        }
    }
    private void rememberCapture(String id) {
        if (captures.size() >= EvidenceStore.MAX_ENTRIES) captures.remove(captures.keySet().iterator().next());
        captures.put(id, runtimeEpoch);
    }
    private void reapTickets() {
        long now = nanoTime.getAsLong();
        Iterator<Tracked> iterator = tickets.values().iterator();
        while (iterator.hasNext()) {
            Tracked tracked = iterator.next();
            if (tracked.epoch != runtimeEpoch || now - tracked.started >= tracked.timeout) {
                iterator.remove();
                watcher.abandon(tracked.ticket); // logical failure ONLY; no native permit reference.
            }
        }
    }
    private String failure(String projectId, long revision, boolean health) {
        if (closed) return "SHUTDOWN";
        State now = state.get();
        if (!now.project().id().equals(projectId)) return "PROJECT_CHANGED";
        if (reloadRequired) return lifecycle == GuardState.PROJECT_UNVERIFIED && now.revision() != revision
                ? "PROJECT_CHANGED" : "PAUSED";
        if (projectUnverified) return "PROJECT_CHANGED";
        if (!liveProject(projectId)) return "PROJECT_CHANGED";
        if (passthrough) return "POLICY_CHANGED";
        if (resumeRequired || operatorPaused && !health) return "PAUSED";
        if (now.revision() != revision) return "POLICY_CHANGED";
        return null;
    }

    @Override public GuardConfig config() { return state.get().config(); }
    @Override public void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision) {
        GuardConfig v2 = PolicyCodec.toV2(config);
        String document = PolicyCodec.encode(v2);
        synchronized (mutation) {
            reconcileProjectFailure();
            State old = state.get();
            checkCas(expectedProjectId, expectedRevision, "STALE_POLICY_DRAFT", false);
            try { projects.save(document); }
            catch (RuntimeException e) {
                failClosed(GuardState.POLICY_SAVE_UNCERTAIN, "POLICY_SAVE_UNCERTAIN_RELOAD_BEFORE_CONTINUING");
                throw new IllegalStateException("POLICY_SAVE_UNCERTAIN");
            }
            if (!liveProject(old.project().id())) {
                failClosed(GuardState.PROJECT_UNVERIFIED, "PROJECT_CHANGED_DURING_SAVE");
                throw new IllegalStateException("PROJECT_CHANGED");
            }
            state.set(new State(old.project(), v2, old.revision() + 1));
            lifecycle = GuardState.PROTECTED;
            reloadRequired = false;
            migrationPending = false;
            migrationOriginal = "";
            approvals.cancelAll("POLICY_CHANGED");
            gate.update(v2.limits());
            watcher.update(v2.limits()); // No reset/debt erasure on same-project saves or toggles.
            listeners.reset();
            note = "POLICY_APPLIED";
        }
    }
    @Override public void refreshProject() {
        synchronized (mutation) {
            if (closed) return;
            reconcileProjectFailure();
            ProjectAccess.Ref ref;
            try {
                ref = projects.current();
                if (ref == null || ref.id() == null || ref.id().isBlank() || ref.id().length() > 512) throw new IllegalStateException();
            } catch (RuntimeException e) {
                failClosed(GuardState.PROJECT_UNVERIFIED, "PROJECT_UNAVAILABLE");
                return;
            }
            State old = state.get();
            if (old.revision() > 0 && old.project().id().equals(ref.id()) && !reloadRequired) return;
            GuardConfig config = GuardConfig.defaults();
            PolicyCodec.Decoded decoded = null;
            boolean invalid = false;
            boolean unverified = false;
            try {
                decoded = PolicyCodec.decode(projects.load());
                config = decoded.config();
            } catch (RuntimeException e) { config = GuardConfig.defaults(); invalid = true; }
            if (!invalid) {
                try {
                    if (!ref.id().equals(projects.current().id())) throw new IllegalStateException();
                } catch (RuntimeException e) { config = GuardConfig.defaults(); invalid = true; unverified = true; }
            }
            boolean projectChanged = !old.project().id().equals(ref.id());
            if (projectChanged || invalid || projectUnverified) resetEpoch();
            passthroughEnded |= passthrough;
            if (projectChanged) { passthroughCount = 0; unguardedListenerCount = 0; }
            state.set(new State(ref, config, old.revision() + 1));
            approvals.cancelAll("PROJECT_CHANGED");
            gate.update(config.limits());
            watcher.update(config.limits());
            listeners.reset();
            migrationPending = !invalid && decoded != null && decoded.migrationPending();
            migrationOriginal = migrationPending ? Objects.requireNonNullElse(decoded.originalDocument(), "") : "";
            if (invalid) resumeRequired = true;
            reloadRequired = invalid;
            lifecycle = invalid ? unverified ? GuardState.PROJECT_UNVERIFIED : GuardState.POLICY_INVALID : GuardState.PROTECTED;
            projectUnverified = false;
            note = invalid ? "PROJECT_POLICY_INVALID_DEFAULT_DENY_PAUSED" : "PROJECT_POLICY_LOADED";
            passthrough = false;
        }
    }
    /** mutation lock only. Never touches native permits. */
    private void resetEpoch() {
        runtimeEpoch++;
        tickets.clear();
        captures.clear();
        watcher.reset();
        intents.reset();
        listeners.reset();
        evidence.clearRawUi();
        new SecureRandom().nextBytes(attributionKey);
    }
    private void reconcileProjectFailure() {
        if (projectUnverified) failClosed(GuardState.PROJECT_UNVERIFIED, "PROJECT_UNVERIFIED_PASSTHROUGH_ENDED");
    }
    private void failClosed(GuardState cause, String explanation) {
        State s = state.get();
        if (!reloadRequired || lifecycle != cause || passthrough) {
            state.set(new State(s.project(), s.config(), s.revision() + 1));
            resetEpoch();
        }
        passthroughEnded |= passthrough;
        lifecycle = cause;
        reloadRequired = true;
        resumeRequired = true;
        projectUnverified = false;
        passthrough = false;
        note = explanation;
        approvals.cancelAll("PROJECT_CHANGED");
        gate.update(s.config().limits());
    }
    /** Safe to call under queue locks; latch uncertainty without acquiring any other lock. */
    private boolean liveProject(String projectId) {
        try {
            ProjectAccess.Ref ref = projects.current();
            if (ref != null && projectId.equals(ref.id())) return true;
        } catch (RuntimeException ignored) { /* Categorical only. */ }
        projectUnverified = true;
        return false;
    }
    private void checkCas(String projectId, long revision, String reason, boolean requireValid) {
        State s = state.get();
        if (closed) throw new IllegalStateException("SHUTDOWN");
        if (!s.project().id().equals(projectId) || s.revision() != revision || !liveProject(s.project().id())) {
            reconcileProjectFailure();
            throw new IllegalStateException(reason);
        }
        if (requireValid && reloadRequired) throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
    }

    @Override public Map<String, Object> status() {
        synchronized (mutation) {
            if (!closed && !reloadRequired && !liveProject(state.get().project().id())) reconcileProjectFailure();
            reconcileProjectFailure();
            reapTickets();
            State s = state.get();
            Map<String, Object> result = new LinkedHashMap<>();
            Map<String, Object> watching = watcher.snapshot();
            Map<String, Object> gating = gate.snapshot();
            Map<String, Object> evidenceStats = evidence.stats();
            GuardState guard = lifecycle;
            if (guard == GuardState.PROTECTED && !passthrough) {
                if (operatorPaused) guard = GuardState.PAUSED_BY_OPERATOR;
                else if (resumeRequired) guard = GuardState.PROJECT_UNVERIFIED;
                else if (((Number) gating.get("stalled")).longValue() > 0) guard = GuardState.IN_FLIGHT_STALLED;
                else if (Boolean.TRUE.equals(watching.get("capacityBlocked"))) guard = GuardState.CAPACITY;
                else if (Boolean.TRUE.equals(watching.get("automaticPause"))) guard = GuardState.OVERLAY_BLOCK;
                else if (((Number) watching.get("circuits")).longValue() > 0) guard = GuardState.CIRCUIT_OPEN;
                else if (((Number) watching.get("overlays")).longValue() > 0) guard = GuardState.OVERLAY_BLOCK;
            }
            result.put("projectId", s.project().id());
            result.put("projectName", "Current Burp project");
            result.put("revision", s.revision());
            result.put("policyRevision", s.revision());
            result.put("guardState", guard.name());
            result.put("pauseCause", lifecycle != GuardState.PROTECTED ? lifecycle.name()
                    : resumeRequired ? GuardState.PROJECT_UNVERIFIED.name() : operatorPaused ? GuardState.PAUSED_BY_OPERATOR.name() : "");
            result.put("paused", !passthrough && (operatorPaused || resumeRequired || reloadRequired));
            result.put("operatorPaused", operatorPaused);
            result.put("closed", closed);
            result.put("passthrough", passthrough);
            result.put("passthroughCount", passthroughCount);
            result.put("unguardedListenerCount", unguardedListenerCount);
            result.put("passthroughEnded", passthroughEnded);
            result.put("passthroughAvailable", !closed && !reloadRequired);
            result.put("migrationPending", migrationPending);
            result.put("guardListenerPorts", s.config().guardListenerPorts());
            result.put("note", note);
            result.put("evidence", evidenceStats);
            result.put("reasonCounters", evidenceStats.get("reasonCounters"));
            result.put("gate", gating);
            result.put("watchers", watching);
            result.put("intents", intents.snapshot());
            result.put("listeners", listeners.snapshot());
            result.put("watcherTickets", tickets.size());
            result.put("approvalCount", approvals.snapshot().size());
            return Map.copyOf(result);
        }
    }
    @Override public List<TrafficEntry> traffic() { return evidence.snapshot(); }
    @Override public List<ApprovalQueue.Pending> approvals() { return approvals.snapshot(); }
    @Override public boolean decideApproval(String id, boolean allow) { return approvals.decide(id, allow); }
    @Override public void bookmark(String id, boolean value) { evidence.bookmark(id, value); }
    @Override public String exportJson(List<TrafficEntry> rows) { synchronized (mutation) { return evidence.exportJson(rows); } }
    @Override public String exportHar(List<TrafficEntry> rows) { synchronized (mutation) { return evidence.exportHar(rows); } }
    @Override public void clearEvidence() {
        synchronized (mutation) { evidence.clear(); captures.clear(); watcher.clearEvidence(); }
    }
    @Override public List<ResponseWatcher.Overlay> overlays() {
        synchronized (mutation) { verifyReadProject(); return watcher.overlays(); }
    }
    @Override public List<ResponseWatcher.Candidate> heavyCandidates() {
        synchronized (mutation) { verifyReadProject(); return watcher.candidates(); }
    }
    private void verifyReadProject() {
        reconcileProjectFailure();
        if (!closed && !reloadRequired && !liveProject(state.get().project().id())) reconcileProjectFailure();
    }
    @Override public boolean releaseOverlay(String id, String projectId, long revision) {
        synchronized (mutation) { checkCas(projectId, revision, "STALE_PROTECTION_STATE", true); return watcher.release(id); }
    }
    @Override public int releaseAllOverlays(String projectId, long revision) {
        synchronized (mutation) { checkCas(projectId, revision, "STALE_PROTECTION_STATE", true); return watcher.releaseAll(); }
    }
    @Override public boolean ignoreCandidate(String id, String projectId, long revision) {
        synchronized (mutation) { checkCas(projectId, revision, "STALE_PROTECTION_STATE", true); return watcher.ignoreCandidate(id); }
    }
    @Override public void resetIntentBudgets(String projectId, long revision) {
        synchronized (mutation) { checkCas(projectId, revision, "STALE_PROTECTION_STATE", true); intents.reset(); }
    }
    @Override public String exportIncident(long fromMillis, long toMillis) {
        synchronized (mutation) {
            verifyReadProject();
            // Response discovery and watcher display refresh share this lock with every display/
            // export projection; an export cannot race between learning and re-masking a secret.
            return watcher.incidentJson(fromMillis, toMillis);
        }
    }
    @Override public Map<String, Object> migrationView() {
        synchronized (mutation) {
            return Map.of("pending", migrationPending, "original", migrationOriginal,
                    "migrated", migrationPending ? PolicyCodec.encode(state.get().config()) : "");
        }
    }
    private boolean rawProjectCurrent() {
        reconcileProjectFailure();
        if (closed || reloadRequired) return false;
        if (!liveProject(state.get().project().id())) { reconcileProjectFailure(); return false; }
        return true;
    }
    @Override public String rawRequest(String id) { synchronized (mutation) { return rawProjectCurrent() ? evidence.rawRequest(id) : null; } }
    @Override public String rawResponse(String id) { synchronized (mutation) { return rawProjectCurrent() ? evidence.rawResponse(id) : null; } }
    @Override public String rawUrl(String id) { synchronized (mutation) { return rawProjectCurrent() ? evidence.rawUrl(id) : null; } }
    @Override public Map<String, Object> rawCaptureInfo(String id) {
        synchronized (mutation) { return rawProjectCurrent() ? evidence.rawCaptureInfo(id) : Map.of("available", false); }
    }

    @Override public void pause(boolean value) {
        synchronized (mutation) {
            reconcileProjectFailure();
            if (closed) return;
            if (!value && reloadRequired) throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
            if (!liveProject(state.get().project().id())) {
                reconcileProjectFailure();
                throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
            }
            passthroughEnded = false;
            passthrough = false;
            operatorPaused = value;
            if (!value) resumeRequired = false;
            bumpGeneration();
            note = value ? "PAUSED_NEW_PROXY_REQUESTS_BLOCKED" : "RESUMED";
        }
    }
    @Override public void passthrough(boolean enabled, String expectedProjectId, long expectedRevision) {
        synchronized (mutation) {
            reconcileProjectFailure();
            checkCas(expectedProjectId, expectedRevision, "STALE_PROTECTION_STATE", false);
            if (enabled && reloadRequired) throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
            if (passthrough == enabled) return;
            passthrough = enabled;
            passthroughEnded = false;
            // Deliberately retain operatorPaused/resumeRequired across OFF/ON. OFF is NOT resume.
            bumpGeneration();
            note = enabled ? "PASSTHROUGH_PROTECTION_OFF_NO_CAPTURE" : "PROTECTION_RESTORED";
        }
    }
    private void bumpGeneration() {
        State s = state.get();
        state.set(new State(s.project(), s.config(), s.revision() + 1));
        approvals.cancelAll("POLICY_CHANGED");
        gate.update(s.config().limits()); // Wake waits, NEVER recycle outstanding native permits.
        listeners.reset();
    }
    @Override public void close() {
        synchronized (mutation) {
            if (closed) return;
            closed = true;
            lifecycle = GuardState.SHUTDOWN;
            passthrough = false;
            note = "SHUTDOWN";
            listeners.reset();
            evidence.clearRawUi();
            approvals.close();
            gate.close();
        }
    }

    private static boolean healthProbe(GuardConfig config, RequestData request) {
        if (!config.limits().healthProbePassthrough() || !"GET".equals(request.method()) || !request.bodyComplete()
                || request.bodyLength() != 0 || request.url() == null || request.url().indexOf('?') >= 0) return false;
        try {
            List<String> paths = PolicyEngine.routingPaths(request);
            String host = PolicyEngine.canonicalHost(request.host());
            String scheme = request.secure() ? "https" : "http";
            return config.limits().healthProbePaths().stream().anyMatch(probe -> probe.scheme().equals(scheme)
                    && PolicyEngine.canonicalHost(probe.host()).equals(host) && probe.port() == request.port()
                    && paths.stream().allMatch(probe.path()::equals));
        } catch (RuntimeException ignored) { return false; }
    }
    private RequestAttribution hashAttribution(RequestAttribution raw) {
        if (!raw.valid()) return new RequestAttribution("?", "?", false);
        return new RequestAttribution(raw.intentId().equals("-") ? "-" : hashLabel("intent", raw.intentId()),
                raw.runId().equals("-") ? "-" : hashLabel("run", raw.runId()), true);
    }
    private String hashLabel(String domain, String label) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(attributionKey, "HmacSHA256"));
            for (String component : new String[]{domain, label}) {
                byte[] bytes = component.getBytes(StandardCharsets.US_ASCII);
                mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                mac.update(bytes);
            }
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (GeneralSecurityException ignored) { throw new IllegalStateException("INTENT_HASH_UNAVAILABLE"); }
    }
    private static String category(String value) {
        return value != null && (DenialReasons.ALL.contains(value) || RUNTIME_REASONS.contains(value)
                || Set.of("DEFAULT_ALLOW", "DEFAULT_MONITOR", "DEFAULT_ASK", "RULE_ALLOW", "RULE_MONITOR", "RULE_ASK", "RULE_EXEMPT").contains(value))
                ? value : "ADAPTER_ERROR";
    }
    private static boolean uuid(String value) {
        if (value == null || value.length() != 36) return false;
        try { return java.util.UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException ignored) { return false; }
    }
    private static long increment(long value) { return value == Long.MAX_VALUE ? value : value + 1; }
}
