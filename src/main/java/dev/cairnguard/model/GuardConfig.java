package dev.cairnguard.model;

import java.util.List;
import java.util.Map;

/** Operator-authored project policy. No credentials or authentication state. */
public record GuardConfig(int schemaVersion, List<ScopeEntry> allowScope, List<ScopeEntry> blockScope,
                          List<Rule> rules, Mode defaultMode, Limits limits, List<Integer> guardListenerPorts) {
    public GuardConfig {
        allowScope = List.copyOf(allowScope);
        blockScope = List.copyOf(blockScope);
        rules = List.copyOf(rules);
        guardListenerPorts = List.copyOf(guardListenerPorts);
    }
    /** Compatibility constructor; the supplied schema is deliberately NOT silently upgraded. */
    public GuardConfig(int schemaVersion, List<ScopeEntry> allowScope, List<ScopeEntry> blockScope,
                       List<Rule> rules, Mode defaultMode, Limits limits) {
        this(schemaVersion, allowScope, blockScope, rules, defaultMode, limits, List.of());
    }
    public enum Mode { EXEMPT, ALLOW, BLOCK, MONITOR, ASK }
    public enum FanoutAction { BLOCK, PAUSE, WARN }
    public enum Field { METHOD, URL, PATH, QUERY, HEADER, BODY, JSON, FORM, ANY }
    public enum Match { CONTAINS, EXACT, REGEX }
    public enum Logic { LEAF, AND, OR }
    public record ScopeEntry(boolean enabled, String host, String scheme, int port, String pathRegex) {}
    public record Rule(String id, String name, boolean enabled, Mode mode, Condition condition) {}
    public record Condition(Logic logic, Field field, String name, Match match, String value,
                            boolean caseSensitive, List<Condition> children) {
        public Condition { children = children == null ? List.of() : List.copyOf(children); }
        public static Condition leaf(Field field, Match match, String value) {
            return new Condition(Logic.LEAF, field, "", match, value, false, List.of());
        }
        public static Condition and(Condition... children) {
            return new Condition(Logic.AND, null, "", null, "", false, List.of(children));
        }
        public static Condition or(Condition... children) {
            return new Condition(Logic.OR, null, "", null, "", false, List.of(children));
        }
    }
    public record Circuit5xx(long windowMillis, int threshold, long openMillis, int halfOpenProbe) {}
    public record Fanout(long windowMillis, int distinctPaths, FanoutAction action) {}
    public record ProbePath(String scheme, String host, int port, String path) {}
    public record PathByteLimit(String scheme, String host, int port, String path, long maxBytes) {}
    public record Limits(int globalRps, int perHostRps, Map<String,Integer> hostRps, int maxConcurrent,
                         int maxQueued, long queueTimeoutMillis, long approvalTimeoutMillis,
                         long requestTimeoutMillis, long perPathMaxResponseBytes, long autoBlockMillis,
                         Circuit5xx circuit5xx, Fanout fanout, int perIntentMaxRequests,
                         boolean healthProbePassthrough, List<ProbePath> healthProbePaths,
                         List<PathByteLimit> heavyPathLimits, List<ProbePath> circuit5xxExceptions,
                         boolean heavyResponseEnabled, List<ProbePath> fanoutExceptions) {
        public Limits {
            hostRps = Map.copyOf(hostRps);
            healthProbePaths = List.copyOf(healthProbePaths);
            heavyPathLimits = List.copyOf(heavyPathLimits);
            circuit5xxExceptions = List.copyOf(circuit5xxExceptions);
            fanoutExceptions = List.copyOf(fanoutExceptions);
        }
        /**
         * Compatibility shape (17 fields): large-response master ON and no fan-out exceptions. Production
         * copiers MUST use the full 19-field constructor so authored detector settings are never dropped.
         */
        public Limits(int globalRps, int perHostRps, Map<String,Integer> hostRps, int maxConcurrent,
                      int maxQueued, long queueTimeoutMillis, long approvalTimeoutMillis,
                      long requestTimeoutMillis, long perPathMaxResponseBytes, long autoBlockMillis,
                      Circuit5xx circuit5xx, Fanout fanout, int perIntentMaxRequests,
                      boolean healthProbePassthrough, List<ProbePath> healthProbePaths,
                      List<PathByteLimit> heavyPathLimits, List<ProbePath> circuit5xxExceptions) {
            this(globalRps, perHostRps, hostRps, maxConcurrent, maxQueued, queueTimeoutMillis,
                    approvalTimeoutMillis, requestTimeoutMillis, perPathMaxResponseBytes, autoBlockMillis,
                    circuit5xx, fanout, perIntentMaxRequests, healthProbePassthrough, healthProbePaths,
                    heavyPathLimits, circuit5xxExceptions, true, List.of());
        }
        /**
         * Compatibility shape without the 5xx circuit exception list (empty). Production copiers that
         * change limits MUST use the full constructor so authored exceptions are never dropped.
         */
        public Limits(int globalRps, int perHostRps, Map<String,Integer> hostRps, int maxConcurrent,
                      int maxQueued, long queueTimeoutMillis, long approvalTimeoutMillis,
                      long requestTimeoutMillis, long perPathMaxResponseBytes, long autoBlockMillis,
                      Circuit5xx circuit5xx, Fanout fanout, int perIntentMaxRequests,
                      boolean healthProbePassthrough, List<ProbePath> healthProbePaths,
                      List<PathByteLimit> heavyPathLimits) {
            this(globalRps, perHostRps, hostRps, maxConcurrent, maxQueued, queueTimeoutMillis,
                    approvalTimeoutMillis, requestTimeoutMillis, perPathMaxResponseBytes, autoBlockMillis,
                    circuit5xx, fanout, perIntentMaxRequests, healthProbePassthrough, healthProbePaths,
                    heavyPathLimits, List.of(), true, List.of());
        }
        /** Legacy fixtures and migrated v1 policies keep all new protections explicitly off. */
        public Limits(int globalRps, int perHostRps, Map<String, Integer> hostRps, int maxConcurrent,
                      int maxQueued, long queueTimeoutMillis, long approvalTimeoutMillis,
                      long requestTimeoutMillis) {
            this(globalRps, perHostRps, hostRps, maxConcurrent, maxQueued, queueTimeoutMillis,
                    approvalTimeoutMillis, requestTimeoutMillis, 0, 600_000, null, null, 0,
                    false, List.of(), List.of(), List.of(), true, List.of());
        }
    }
    public static GuardConfig defaults() {
        return new GuardConfig(2, List.of(), List.of(), List.of(
                new Rule("delete-method", "Block DELETE method", true, Mode.BLOCK,
                        Condition.leaf(Field.METHOD, Match.EXACT, "DELETE"))), Mode.ALLOW,
                new Limits(5, 5, Map.of(), 5, 100, 30_000, 30_000, 60_000,
                        5L * 1_048_576, 600_000, null, // 5xx circuit is OPTIONAL and OFF by default
                        new Fanout(60_000, 100, FanoutAction.WARN), 0, false, List.of(), List.of(), List.of(), true, List.of()));
    }
}
