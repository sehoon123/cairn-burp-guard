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
}
