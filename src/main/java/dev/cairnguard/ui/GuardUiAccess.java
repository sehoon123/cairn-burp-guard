package dev.cairnguard.ui;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.runtime.ApprovalQueue;
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
    default void resetIntentBudgets(String projectId, long revision) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default String exportIncident(long fromMillis, long toMillis) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default Map<String,Object> migrationView() { return Map.of("pending", false, "original", "", "migrated", ""); }
    /** Text/byte views of the retained ORIGINAL copies (plaintext); not for logs. */
    default String rawRequest(String evidenceId) { return null; }
    default String rawResponse(String evidenceId) { return null; }
    default String rawUrl(String evidenceId) { return null; }
    default Map<String,Object> rawCaptureInfo(String evidenceId) { return Map.of("available", false); }

    /** Explicitly consented HUMAN original exports (plaintext). Snapshot under lock; caller writes the file. */
    default HumanExport humanExport(List<String> evidenceIds, boolean har) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    default HumanExport humanIncident(long fromMillis, long toMillis) { throw new UnsupportedOperationException("UNSUPPORTED_UI_ACTION"); }
    /** Final pre-publication checkpoint: still the same project/revision/epoch and raw generation. */
    default boolean humanExportCurrent(HumanExport export) { return false; }
    /** Immutable consented snapshot; serialize() has no size cap and must run off the EDT, outside locks. */
    interface HumanExport { byte[] serialize(); }
}
