package dev.cairnguard.model;

import java.util.List;
import dev.cairnguard.model.GuardConfig.Mode;

public record Decision(Mode mode, String reason, List<RuleHit> hits, List<String> inspectionWarnings) {
    public record RuleHit(String id, String name, Mode mode) {}
    public Decision {
        hits = List.copyOf(hits);
        inspectionWarnings = List.copyOf(inspectionWarnings);
    }
    public Decision(Mode mode, String reason, List<RuleHit> hits) {
        this(mode, reason, hits, List.of());
    }
    public static Decision blocked(String reason) { return new Decision(Mode.BLOCK, reason, List.of()); }
}
