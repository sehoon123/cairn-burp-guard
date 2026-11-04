package dev.cairnguard.runtime;

import com.fasterxml.jackson.databind.DeserializationFeature;
import dev.cairnguard.evidence.EvidenceStore;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.ui.GuardUiAccess;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** Human UI policy + callback pipeline. Never performs outbound HTTP or authentication actions. */
public final class GuardController implements GuardUiAccess, AutoCloseable {
    private record State(ProjectAccess.Ref project, GuardConfig config, long revision) {}
    /** Only masked evidence reference and categorical policy results survive into a wait. */
    public record Prepared(String evidenceId, String projectId, long revision, String rateHost, Decision decision) {}
    public record Admission(boolean allowed, String reason, RateGate.Permit permit) {}
    /** No native/raw data; final bypass commit must still match this exact runtime generation. */
    public record PassthroughToken(String projectId, long revision) {}
    /** Exactly one of: protected (both null), valid OFF token, or data-free rejection. */
    public record NativeMode(PassthroughToken token, String rejection) {}
    private static final NativeMode PROTECTED = new NativeMode(null, null);
    private final Object mutation = new Object();
    private final ProjectAccess projects;
    private final PolicyEngine engine = new PolicyEngine();
    private final EvidenceStore evidence = new EvidenceStore();
    private final RateGate gate = new RateGate(GuardConfig.defaults().limits());
    private final ApprovalQueue approvals = new ApprovalQueue();
    private final AtomicReference<State> state = new AtomicReference<>(new State(
            new ProjectAccess.Ref("unavailable", "Current Burp project"), GuardConfig.defaults(), 0));
    private volatile boolean paused;
    private volatile boolean passthrough;
    private boolean passthroughEnded;
    // Guarded by mutation; never saved to the project and never includes request metadata.
    private long passthroughCount;
    // Written under mutation, also read by the native fast path. Resume cannot restore an uncertain policy.
    private volatile boolean reloadRequired;
    private volatile boolean closed;
    private volatile String note = "INITIALIZING";

    public GuardController(ProjectAccess projects) {
        this.projects = Objects.requireNonNull(projects);
        refreshProject();
    }
    public Prepared prepare(RequestData request) {
        State s = state.get();
        String failure = failure(s.project().id(), s.revision());
        Decision decision = failure == null ? engine.evaluate(s.config(), request) : Decision.blocked(failure);
        String host = decision.mode() == Mode.BLOCK ? "blocked.invalid" : PolicyEngine.canonicalHost(request.host());
        String id = evidence.begin(s.project().id(), s.project().name(), request, decision, s.revision());
        return new Prepared(id, s.project().id(), s.revision(), host, decision);
    }
    /** No raw native data is captured on adapter capacity/inspection failure. */
    public Prepared prepareRejected(String category) {
        State s = state.get();
        RequestData omitted = new RequestData("UNKNOWN", "https://redacted.invalid/", "redacted.invalid", 443, true,
                List.of(new RequestData.Header("X-Cairn-Guard-Capture", "OMITTED")), new byte[0]);
        Decision d = Decision.blocked(category);
        String id = evidence.begin(s.project().id(), s.project().name(), omitted, d, s.revision());
        return new Prepared(id, s.project().id(), s.revision(), "blocked.invalid", d);
    }
    public Admission authorize(Prepared p) {
        if (p.decision().mode() == Mode.BLOCK) return reject(p, p.decision().reason());
        String failed = failure(p.projectId(), p.revision());
        if (failed != null) return reject(p, failed);
        try {
            if (p.decision().mode() == Mode.ASK) {
                evidence.outcome(p.evidenceId(), "AWAITING_APPROVAL", "ASK", null);
                ApprovalQueue.Result result = approvals.await(p.evidenceId(), p.projectId(),
                        state.get().config().limits().approvalTimeoutMillis(), () -> current(p));
                if (!result.allowed()) return reject(p, result.reason());
            }
            failed = failure(p.projectId(), p.revision());
            if (failed != null) return reject(p, failed);
            evidence.outcome(p.evidenceId(), "QUEUED", "QUEUED", null);
            RateGate.Permit permit = gate.acquire(p.rateHost(), () -> current(p));
            failed = failure(p.projectId(), p.revision());
            if (failed != null) { permit.close(); return reject(p, failed); }
            return new Admission(true, "APPROVED", permit);
        } catch (RateGate.Rejected e) {
            return reject(p, e.reason());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return reject(p, "CANCELLED");
        }
    }
    /** OFF applies only at the native boundary, never by approving a protected Prepared request. */
    public NativeMode nativeMode() {
        // Read the mode BEFORE its validity flags: automatic OFF exit publishes those
        // flags/state before clearing this volatile bit, so an ON fast path sees them.
        boolean off = passthrough;
        if (closed) return new NativeMode(null, "SHUTDOWN");
        if (reloadRequired) return new NativeMode(null, "PAUSED");
        if (!off) return PROTECTED; // Normal ON callbacks do not serialize on UI save/load.
        synchronized (mutation) {
            if (closed) return new NativeMode(null, "SHUTDOWN");
            if (reloadRequired) return new NativeMode(null, "PAUSED");
            if (!passthrough) return PROTECTED;
            State s = state.get();
            if (!passthroughCurrent(s.project().id(), s.revision()))
                return new NativeMode(null, "PROJECT_CHANGED"); // NEVER fall back to native capture.
            return new NativeMode(new PassthroughToken(s.project().id(), s.revision()), null);
        }
    }
    public PassthroughToken passthroughToken() { return nativeMode().token(); }
    /** Atomic with human mode/project changes; called AFTER building the original-object action. */
    public boolean commitPassthrough(PassthroughToken token) {
        synchronized (mutation) {
            if (token == null || !passthroughCurrent(token.projectId(), token.revision())) return false;
            if (passthroughCount < Long.MAX_VALUE) passthroughCount++;
            return true;
        }
    }
    private boolean passthroughCurrent(String projectId, long revision) {
        State s = state.get();
        if (!passthrough || closed || paused || reloadRequired
                || !s.project().id().equals(projectId) || s.revision() != revision) return false;
        if (liveProject(projectId)) return true;
        // Called only under mutation. A detected A->B->A (or temporary lookup failure)
        // must not revive a previous human OFF choice before the UI's next refresh.
        failClosed(); note = "PROJECT_UNVERIFIED_PASSTHROUGH_ENDED";
        approvals.cancelAll("PROJECT_CHANGED"); gate.update(s.config().limits());
        return false;
    }
    /** Atomic with UI policy/project/pause updates. Native side effects have not yet begun. */
    public boolean commit(Prepared p) {
        synchronized (mutation) {
            String reason = failure(p.projectId(), p.revision());
            if (reason != null) { reject(p, reason); return false; }
            evidence.outcome(p.evidenceId(), "FORWARDED", "NATIVE_RELEASED", null);
            return true;
        }
    }
    public Admission reject(Prepared p, String reason) {
        evidence.outcome(p.evidenceId(), "BLOCKED", reason, 451);
        return new Admission(false, reason, null);
    }
    public boolean current(Prepared p) { return failure(p.projectId(), p.revision()) == null; }
    public void response(String id, int status, List<RequestData.Header> headers, byte[] body) {
        evidence.response(id, status, headers, body);
    }
    public void localResponse(String id, byte[] body) {
        evidence.response(id, 451, List.of(new RequestData.Header("Content-Type", "application/json"),
                new RequestData.Header("X-Cairn-Guard", "blocked")), body);
    }
    private String failure(String projectId, long revision) {
        if (closed) return "SHUTDOWN";
        if (paused) return "PAUSED";
        State now = state.get();
        if (!now.project().id().equals(projectId)) return "PROJECT_CHANGED";
        if (now.revision() != revision) return "POLICY_CHANGED";
        try {
            if (!projectId.equals(projects.current().id())) return "PROJECT_CHANGED";
        } catch (RuntimeException e) { return "PROJECT_CHANGED"; }
        if (passthrough) return "POLICY_CHANGED"; // Never drain protected callbacks through OFF.
        return null;
    }
    @Override public GuardConfig config() { return state.get().config(); }
    @Override public void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision) {
        engine.validate(config);
        String document = Json.write(config);
        synchronized (mutation) {
            State old = state.get();
            if (closed) throw new IllegalStateException("SHUTDOWN");
            if (!old.project().id().equals(expectedProjectId) || old.revision() != expectedRevision
                    || !liveProject(old.project().id())) throw new IllegalStateException("STALE_POLICY_DRAFT");
            try { projects.save(document); }
            catch (RuntimeException e) {
                note = "POLICY_SAVE_UNCERTAIN_RELOAD_BEFORE_CONTINUING";
                failClosed();
                approvals.cancelAll("POLICY_CHANGED");
                gate.update(old.config().limits());
                throw new IllegalStateException("POLICY_SAVE_UNCERTAIN");
            }
            if (!liveProject(old.project().id())) {
                failClosed();
                note = "PROJECT_CHANGED_DURING_SAVE";
                approvals.cancelAll("PROJECT_CHANGED");
                gate.update(old.config().limits());
                throw new IllegalStateException("PROJECT_CHANGED");
            }
            state.set(new State(old.project(), config, old.revision() + 1));
            reloadRequired = false;
            approvals.cancelAll("POLICY_CHANGED");
            gate.update(config.limits());
            note = "POLICY_APPLIED";
        }
    }
    @Override public void refreshProject() {
        synchronized (mutation) {
            if (closed) return;
            ProjectAccess.Ref ref;
            try {
                ref = projects.current();
                if (ref.id() == null || ref.id().isBlank() || ref.id().length() > 512) throw new IllegalStateException();
            } catch (RuntimeException e) {
                failClosed();
                note = "PROJECT_UNAVAILABLE";
                approvals.cancelAll("PROJECT_CHANGED");
                return;
            }
            State old = state.get();
            if (old.revision() > 0 && old.project().id().equals(ref.id()) && !reloadRequired) return;
            GuardConfig config = GuardConfig.defaults();
            boolean invalid = false;
            try {
                config = storedConfig(projects.load());
                engine.validate(config);
                if (!ref.id().equals(projects.current().id())) throw new IllegalStateException();
            } catch (RuntimeException e) {
                config = GuardConfig.defaults(); invalid = true;
            }
            passthroughEnded |= passthrough;
            if (!old.project().id().equals(ref.id())) passthroughCount = 0;
            state.set(new State(ref, config, old.revision() + 1));
            approvals.cancelAll("PROJECT_CHANGED");
            gate.update(config.limits());
            paused = invalid || paused;
            reloadRequired = invalid;
            note = invalid ? "PROJECT_POLICY_INVALID_DEFAULT_DENY_PAUSED" : "PROJECT_POLICY_LOADED";
            passthrough = false; // Publish the verified/rejecting replacement state before ON.
        }
    }
    /** Guarded by mutation. Operational changes invalidate old human drafts/tokens as well. */
    private void failClosed() {
        State s = state.get();
        if (passthrough || !paused || !reloadRequired)
            state.set(new State(s.project(), s.config(), s.revision() + 1));
        passthroughEnded |= passthrough;
        reloadRequired = true; paused = true;
        passthrough = false; // Volatile publication: an ON fast path must see rejection first.
    }
    private boolean liveProject(String projectId) {
        try { return projectId.equals(projects.current().id()); }
        catch (RuntimeException e) { return false; }
    }
    private static GuardConfig storedConfig(String document) {
        if (document == null) return GuardConfig.defaults();
        if (document.length() > 2_097_152) throw new IllegalArgumentException("INVALID_PROJECT_POLICY");
        if (document.isBlank()) return GuardConfig.defaults();
        try {
            // Preserve shared duplicate/unknown/trailing/depth checks without mutating its mapper.
            // A null/missing port must not become any-port; fractional limits must not be truncated.
            return Json.MAPPER.readerFor(GuardConfig.class)
                    .with(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                    .without(DeserializationFeature.ACCEPT_FLOAT_AS_INT).readValue(document);
        } catch (IOException e) { throw new IllegalArgumentException("INVALID_PROJECT_POLICY"); }
    }
    @Override public Map<String,Object> status() {
        synchronized (mutation) {
            State s = state.get();
            Map<String,Object> result = new LinkedHashMap<>();
            result.put("projectId", s.project().id());
            // Do not put an uncontrolled native project name in operational status/error strings.
            result.put("projectName", "Current Burp project");
            result.put("revision", s.revision()); result.put("paused", paused); result.put("closed", closed);
            result.put("passthrough", passthrough); result.put("passthroughCount", passthroughCount);
            result.put("passthroughEnded", passthroughEnded); result.put("passthroughAvailable", !closed && !reloadRequired);
            result.put("note", note); result.put("evidence", evidence.stats()); result.put("gate", gate.snapshot());
            result.put("approvalCount", approvals.snapshot().size());
            return Map.copyOf(result);
        }
    }
    @Override public List<TrafficEntry> traffic() { return evidence.snapshot(); }
    @Override public List<ApprovalQueue.Pending> approvals() { return approvals.snapshot(); }
    @Override public boolean decideApproval(String id, boolean allow) { return approvals.decide(id, allow); }
    @Override public void bookmark(String id, boolean value) { evidence.bookmark(id, value); }
    @Override public String exportJson(List<TrafficEntry> rows) { return evidence.exportJson(rows); }
    @Override public String exportHar(List<TrafficEntry> rows) { return evidence.exportHar(rows); }
    @Override public void clearEvidence() { evidence.clear(); }
    @Override public void pause(boolean value) {
        synchronized (mutation) {
            if (closed) return;
            if (!value && reloadRequired) throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
            passthroughEnded = false;
            passthrough = false; // Block/Resume is a deliberate return to protected handling.
            paused = value;
            State s = state.get();
            state.set(new State(s.project(), s.config(), s.revision() + 1));
            approvals.cancelAll("POLICY_CHANGED");
            gate.update(s.config().limits());
            note = value ? "PAUSED_NEW_PROXY_REQUESTS_BLOCKED" : "RESUMED";
        }
    }
    @Override public void passthrough(boolean enabled, String expectedProjectId, long expectedRevision) {
        synchronized (mutation) {
            State s = state.get();
            if (closed || !s.project().id().equals(expectedProjectId) || s.revision() != expectedRevision
                    || !liveProject(s.project().id())) throw new IllegalStateException("STALE_PROTECTION_STATE");
            if (enabled && reloadRequired) throw new IllegalStateException("PROJECT_POLICY_RELOAD_REQUIRED");
            if (passthrough == enabled) return;
            passthrough = enabled;
            passthroughEnded = false;
            paused = !enabled && reloadRequired;
            state.set(new State(s.project(), s.config(), s.revision() + 1));
            approvals.cancelAll("POLICY_CHANGED");
            gate.update(s.config().limits()); // Wake/cancel waits, NEVER recycle existing native permits.
            note = enabled ? "PASSTHROUGH_PROTECTION_OFF_NO_CAPTURE" : "PROTECTION_RESTORED";
        }
    }
    @Override public void close() {
        synchronized (mutation) {
            closed = true; paused = true; passthrough = false; note = "SHUTDOWN";
            approvals.close(); gate.close();
        }
    }
}
