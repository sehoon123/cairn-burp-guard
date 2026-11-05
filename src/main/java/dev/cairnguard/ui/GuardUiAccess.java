package dev.cairnguard.ui;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.runtime.ApprovalQueue;
import dev.cairnguard.runtime.ResponseWatcher;
import java.util.List;
import java.util.Map;

/** In-process human UI only. Never exposed as an agent API or network endpoint. */
public interface GuardUiAccess {
    GuardConfig config();
    void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision);
    Map<String,Object> status();
    List<TrafficEntry> traffic();
    List<ApprovalQueue.Pending> approvals();
    boolean decideApproval(String approvalId, boolean allow);
    void bookmark(String evidenceId, boolean value);
    String exportJson(List<TrafficEntry> entries);
    String exportHar(List<TrafficEntry> entries);
    void clearEvidence();
    void pause(boolean paused);
    /** Explicit human protection-OFF/ON transition, atomic against project and revision changes. */
    void passthrough(boolean enabled, String expectedProjectId, long expectedRevision);
    void refreshProject();
    default List<ResponseWatcher.Overlay> overlays() { return List.of(); }
    default boolean releaseOverlay(String id, String projectId, long revision) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default int releaseAllOverlays(String projectId, long revision) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default List<ResponseWatcher.Candidate> heavyCandidates() { return List.of(); }
    default boolean ignoreCandidate(String id, String projectId, long revision) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default void resetIntentBudgets(String projectId, long revision) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default String exportIncident(long fromMillis, long toMillis) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default Map<String,Object> migrationView() { return Map.of("pending", false, "original", "", "migrated", ""); }
    /** Text/byte views of the retained ORIGINAL copies (plaintext); not for logs. */
    default String rawRequest(String evidenceId) { return null; }
    default String rawResponse(String evidenceId) { return null; }
    default String rawUrl(String evidenceId) { return null; }
    default Map<String,Object> rawCaptureInfo(String evidenceId) { return Map.of("available", false); }

    /**
     * HUMAN projection of a large-response candidate: original actual-service host/path when its
     * latest retained source still exists, else categorical unavailability (never a guessed substitute).
     * ruleUrl seeds an UNSAVED ordinary URL BLOCK draft; limitPath is set only for a strict exact route.
     */
    record HumanCandidate(ResponseWatcher.Candidate candidate, String scheme, String host, int port, String path,
                          String ruleUrl, String ruleUnavailable, String limitPath, String limitUnavailable,
                          CandidateSource source) {}
    /** HUMAN overlay projection; host-only protections never invent a path, capacity has no service. */
    record HumanOverlay(ResponseWatcher.Overlay overlay, String host, String path, String unavailable, OverlayException exception) {
        public HumanOverlay(ResponseWatcher.Overlay overlay, String host, String path, String unavailable) {
            this(overlay, host, path, unavailable, null);
        }
    }
    /**
     * Separate review of an exact detector exception seeded ONLY by the overlay's own retained original
     * triggering request (kind HEAVY / CIRCUIT / FANOUT). A null source means unavailable (see reason).
     */
    record OverlayException(String kind, String scheme, String host, int port, String path, String unavailable,
                            OverlaySource source) {}
    /** Opaque overlay-exception authority issued by the implementation; only it can validate its own tokens. */
    interface OverlaySource {}
    /** Authoritative currentness check (call after every confirmation). */
    default boolean overlayExceptionCurrent(OverlaySource source) { return false; }
    /** Saves ONLY the selected detector's route exception; the implementation revalidates at the CAS. */
    default void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision, OverlaySource source) {
        throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION");
    }
    /** True when the CURRENT policy already holds this detector's exact exception for the canonical route. */
    static boolean detectorExceptionPresent(GuardConfig base, String kind, String scheme, String host, int port, String path) {
        java.util.function.Predicate<String> same = h -> {
            try { return dev.cairnguard.policy.PolicyEngine.canonicalHost(h).equals(dev.cairnguard.policy.PolicyEngine.canonicalHost(host)); }
            catch (RuntimeException e) { return false; }
        };
        GuardConfig.Limits l = base.limits();
        return switch (kind) {
            case "HEAVY" -> l.heavyPathLimits().stream().anyMatch(p -> p.maxBytes() == 0 && p.scheme().equals(scheme) && p.port() == port && p.path().equals(path) && same.test(p.host()));
            case "CIRCUIT" -> l.circuit5xxExceptions().stream().anyMatch(p -> p.scheme().equals(scheme) && p.port() == port && p.path().equals(path) && same.test(p.host()));
            case "FANOUT" -> l.fanoutExceptions().stream().anyMatch(p -> p.scheme().equals(scheme) && p.port() == port && p.path().equals(path) && same.test(p.host()));
            default -> false;
        };
    }
    /**
     * The one config change an overlay exception may make, relative to the CURRENT policy: HEAVY upserts a
     * canonical size-0 PathByteLimit, CIRCUIT/FANOUT add one exact route (canonical duplicates are kept once).
     * Every other field is preserved. Full tables are refused (IllegalStateException "EXCEPTION_TABLE_FULL").
     */
    static GuardConfig withDetectorException(GuardConfig base, String kind, String scheme, String host, int port, String path) {
        GuardConfig.Limits l = base.limits();
        List<GuardConfig.PathByteLimit> heavy = new java.util.ArrayList<>(l.heavyPathLimits());
        List<GuardConfig.ProbePath> circuit = new java.util.ArrayList<>(l.circuit5xxExceptions());
        List<GuardConfig.ProbePath> fanout = new java.util.ArrayList<>(l.fanoutExceptions());
        java.util.function.Predicate<String> same = h -> {
            try { return dev.cairnguard.policy.PolicyEngine.canonicalHost(h).equals(dev.cairnguard.policy.PolicyEngine.canonicalHost(host)); }
            catch (RuntimeException e) { return false; }
        };
        switch (kind) {
            case "HEAVY" -> {
                // In place: an existing entry for this canonical route keeps its position (never a reorder-only save).
                int at = -1;
                for (int i = 0; i < heavy.size(); i++) {
                    GuardConfig.PathByteLimit p = heavy.get(i);
                    if (p.scheme().equals(scheme) && p.port() == port && p.path().equals(path) && same.test(p.host())) { at = i; break; }
                }
                if (at >= 0) { if (heavy.get(at).maxBytes() != 0) heavy.set(at, new GuardConfig.PathByteLimit(scheme, host, port, path, 0)); }
                else {
                    if (heavy.size() >= 256) throw new IllegalStateException("EXCEPTION_TABLE_FULL");
                    heavy.add(new GuardConfig.PathByteLimit(scheme, host, port, path, 0));
                }
            }
            case "CIRCUIT", "FANOUT" -> {
                List<GuardConfig.ProbePath> list = kind.equals("CIRCUIT") ? circuit : fanout;
                if (list.stream().noneMatch(p -> p.scheme().equals(scheme) && p.port() == port && p.path().equals(path) && same.test(p.host()))) {
                    if (list.size() >= 16) throw new IllegalStateException("EXCEPTION_TABLE_FULL");
                    list.add(new GuardConfig.ProbePath(scheme, host, port, path));
                }
            }
            default -> throw new IllegalArgumentException("UNKNOWN_DETECTOR");
        }
        return new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new GuardConfig.Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(),
                        l.queueTimeoutMillis(), l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(),
                        l.autoBlockMillis(), l.circuit5xx(), l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(),
                        l.healthProbePaths(), heavy, circuit, l.heavyResponseEnabled(), fanout), base.guardListenerPorts());
    }
    default List<HumanCandidate> humanCandidates() { return List.of(); }
    default List<HumanOverlay> humanOverlays() { return List.of(); }
    /** Candidate-derived save: the controller revalidates the candidate source after every confirmation. */
    default void updateConfig(GuardConfig config, String expectedProjectId, long expectedRevision,
                              CandidateSource source, boolean byteLimit) {
        throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION");
    }
    /** Explicitly consented HUMAN original exports (plaintext). Snapshot under lock; caller writes the file. */
    default HumanExport humanExport(List<String> evidenceIds, boolean har) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default HumanExport humanIncident(long fromMillis, long toMillis) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    /** Final pre-publication checkpoint: still the same project/revision/epoch and raw generation. */
    default boolean humanExportCurrent(HumanExport export) { return false; }
    /** Opaque candidate-draft authority issued by the implementation; only it can validate its own tokens. */
    interface CandidateSource {}
    /** Immutable consented snapshot; serialize() has no size cap and must run off the EDT, outside locks. */
    interface HumanExport { byte[] serialize(); }
}
