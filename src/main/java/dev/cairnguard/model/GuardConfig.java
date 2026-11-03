package dev.cairnguard.model;

import java.util.List;
import java.util.Map;

/** Operator-authored project policy. No credentials or authentication state. */
public record GuardConfig(int schemaVersion, List<ScopeEntry> allowScope, List<ScopeEntry> blockScope,
                          List<Rule> rules, Mode defaultMode, Limits limits) {
    public GuardConfig {
        allowScope = List.copyOf(allowScope);
        blockScope = List.copyOf(blockScope);
        rules = List.copyOf(rules);
    }
    public enum Mode { ALLOW, BLOCK, MONITOR, ASK }
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
    }
    public record Limits(int globalRps, int perHostRps, Map<String,Integer> hostRps, int maxConcurrent,
                         int maxQueued, long queueTimeoutMillis, long approvalTimeoutMillis,
                         long requestTimeoutMillis) {
        public Limits { hostRps = Map.copyOf(hostRps); }
    }
    public static GuardConfig defaults() {
        return new GuardConfig(1, List.of(), List.of(), List.of(
                new Rule("delete-method", "Block DELETE method", true, Mode.BLOCK,
                        Condition.leaf(Field.METHOD, Match.EXACT, "DELETE")),
                new Rule("delete-string", "Block delete string (conservative)", true, Mode.BLOCK,
                        Condition.leaf(Field.ANY, Match.CONTAINS, "delete"))), Mode.ALLOW,
                new Limits(5, 5, Map.of(), 5, 100, 30_000, 30_000, 60_000));
    }
}
