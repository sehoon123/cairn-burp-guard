package dev.cairnguard.policy;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.Decision.RuleHit;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.RequestData;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import static dev.cairnguard.policy.PolicySupport.*;

/**
 * Bounded, network-free policy evaluation of immutable inspection copies. No native request is
 * produced or changed. All errors exposed to callers are categorical and omit traffic and patterns.
 * Instances are thread-safe; only the most recently compiled configuration is cached, never traffic.
 */
public final class PolicyEngine {
    private static final int MAX_SCOPES = 256;
    private static final int MAX_RULES = 256;
    private static final int MAX_CONDITIONS = 2_048;
    private static final int MAX_CONDITION_DEPTH = 16;
    private volatile CompiledPolicy cached;

    /** Canonical rate-limit key, using precisely the same authority normalization as scope. */
    public static String canonicalHost(String value) {
        try { return host(value); }
        catch (RuntimeException e) { throw new IllegalArgumentException("INVALID_HOST"); }
    }

    /** Validates even disabled entries, so enabling them cannot activate an unvalidated expression. */
    public void validate(GuardConfig config) {
        compiled(config);
    }

    /** Mandatory authority/scope/inspection gates cannot be overridden by any mode or rule order. */
    public Decision evaluate(GuardConfig config, RequestData request) {
        CompiledPolicy policy;
        try { policy = compiled(config); }
        catch (RuntimeException e) { return Decision.blocked("INVALID_CONFIG"); }
        try {
            Budget budget = new Budget();
            RequestInspection.Target target = RequestInspection.target(request, budget);
            for (CompiledScope scope : policy.block) {
                if (scope.authorityMatches(target) && scope.anyPath(target.paths(), budget))
                    return Decision.blocked("SCOPE_BLOCKED");
            }
            boolean allowed = false;
            for (CompiledScope scope : policy.allow) {
                if (scope.authorityMatches(target) && scope.allPaths(target.paths(), budget)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) return Decision.blocked("SCOPE_NOT_ALLOWED");
            RequestInspection inspection = RequestInspection.inspect(target, request, budget);
            List<RuleHit> hits = new ArrayList<>();
            Mode action = null;
            for (CompiledRule rule : policy.rules) {
                if (rule.enabled && rule.condition.matches(inspection, budget)) {
                    hits.add(new RuleHit(rule.id, rule.name, rule.mode));
                    if (rule.mode != Mode.MONITOR && (action == null || rank(rule.mode) > rank(action)))
                        action = rule.mode;
                }
            }
            if (action == null) return new Decision(policy.defaultMode, "DEFAULT_" + policy.defaultMode.name(), hits);
            return new Decision(action, "RULE_" + action.name(), hits);
        } catch (Failure e) {
            return Decision.blocked(e.getMessage());
        } catch (RuntimeException e) {
            // Never propagate parser/library exception text (which may include credentials) to a callback.
            return Decision.blocked("INSPECTION_ERROR");
        }
    }

    private static int rank(Mode mode) {
        return switch (mode) {
            case BLOCK -> 3;
            case ASK -> 2;
            case ALLOW -> 1;
            case MONITOR -> 0;
        };
    }

    private CompiledPolicy compiled(GuardConfig config) {
        CompiledPolicy current = cached;
        if (current != null && current.source == config) return current;
        synchronized (this) {
            current = cached;
            if (current != null && current.source == config) return current;
            CompiledPolicy next = compile(config);
            cached = next;
            return next;
        }
    }

    private static CompiledPolicy compile(GuardConfig config) {
        require(config != null && config.schemaVersion() == 1 && config.defaultMode() != null, "INVALID_CONFIG");
        require(config.allowScope() != null && config.blockScope() != null && config.rules() != null
                && config.allowScope().size() <= MAX_SCOPES && config.blockScope().size() <= MAX_SCOPES
                && config.rules().size() <= MAX_RULES, "CONFIG_LIMIT");
        validateLimits(config.limits());
        CompileBudget budget = new CompileBudget();
        List<CompiledScope> allow = scopes(config.allowScope(), budget);
        List<CompiledScope> block = scopes(config.blockScope(), budget);
        List<CompiledRule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        int[] nodes = new int[1];
        for (Rule rule : config.rules()) {
            require(rule != null && validId(rule.id()) && ids.add(rule.id()), "INVALID_RULE_ID");
            require(rule.name() != null && rule.name().length() <= 256 && !rule.name().isBlank()
                    && cleanUnicode(rule.name(), false) && rule.mode() != null, "INVALID_RULE");
            rules.add(new CompiledRule(rule.id(), rule.name(), rule.enabled(), rule.mode(),
                    condition(rule.condition(), 0, nodes, budget)));
        }
        return new CompiledPolicy(config, allow, block, List.copyOf(rules), config.defaultMode());
    }

    private static boolean validId(String id) {
        if (id == null || id.isEmpty() || id.length() > 128) return false;
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.')) return false;
        }
        return true;
    }

    private static List<CompiledScope> scopes(List<ScopeEntry> entries, CompileBudget budget) {
        List<CompiledScope> result = new ArrayList<>();
        for (ScopeEntry entry : entries) {
            require(entry != null && entry.host() != null && entry.scheme() != null && entry.scheme().length() <= 5
                    && entry.pathRegex() != null && entry.port() >= 0 && entry.port() <= 65_535, "INVALID_SCOPE");
            boolean wildcard = entry.host().startsWith("*.");
            String host;
            try { host = host(wildcard ? entry.host().substring(2) : entry.host()); }
            catch (Failure e) { throw invalid("INVALID_SCOPE"); }
            require(!wildcard || !host.startsWith("[") && !numericHost(host), "INVALID_SCOPE");
            String scheme = entry.scheme().toLowerCase(Locale.ROOT);
            require(scheme.equals("http") || scheme.equals("https") || scheme.equals("any"), "INVALID_SCOPE");
            Pattern path = entry.pathRegex().isEmpty() ? null : regex(entry.pathRegex(), true, budget);
            result.add(new CompiledScope(entry.enabled(), host, wildcard, scheme, entry.port(), path));
        }
        return List.copyOf(result);
    }

    private static boolean numericHost(String host) {
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (!(c >= '0' && c <= '9' || c == '.')) return false;
        }
        return true;
    }

    private static CompiledCondition condition(Condition condition, int depth, int[] nodes, CompileBudget budget) {
        require(condition != null && condition.logic() != null && depth <= MAX_CONDITION_DEPTH
                && ++nodes[0] <= MAX_CONDITIONS, "INVALID_CONDITION");
        List<Condition> children = condition.children();
        require(children != null, "INVALID_CONDITION");
        if (condition.logic() != Logic.LEAF) {
            require(!children.isEmpty() && children.size() <= 64 && condition.field() == null
                    && condition.match() == null && empty(condition.name()) && empty(condition.value()), "INVALID_CONDITION");
            List<CompiledCondition> compiled = new ArrayList<>();
            for (Condition child : children) compiled.add(condition(child, depth + 1, nodes, budget));
            return new CompiledCondition(condition.logic(), null, "", null, false, 1, false, List.of(),
                    List.copyOf(compiled));
        }
        require(children.isEmpty() && condition.field() != null && condition.match() != null
                && condition.value() != null && condition.value().length() <= 4_096
                && cleanUnicode(condition.value(), true), "INVALID_CONDITION");
        String name = condition.name() == null ? "" : condition.name();
        require(name.length() <= 512 && cleanUnicode(name, false), "INVALID_SELECTOR");
        Field field = condition.field();
        require(name.isEmpty() || field == Field.HEADER || field == Field.QUERY || field == Field.JSON
                || field == Field.FORM, "INVALID_SELECTOR");
        if (field == Field.HEADER && !name.isEmpty()) require(token(name), "INVALID_SELECTOR");
        List<String> pointer = field == Field.JSON && !name.isEmpty() ? pointer(name) : List.of();
        Pattern pattern = condition.match() == Match.REGEX ? regex(condition.value(), condition.caseSensitive(), budget)
                : literal(condition.value(), condition.caseSensitive(), budget);
        return new CompiledCondition(Logic.LEAF, field, name, pattern, condition.match() == Match.EXACT,
                condition.match() == Match.REGEX ? pattern.programSize() : 1,
                condition.caseSensitive(), pointer, List.of());
    }

    private static boolean empty(String value) { return value == null || value.isEmpty(); }

    private static List<String> pointer(String value) {
        require(value.charAt(0) == '/', "INVALID_JSON_POINTER");
        List<String> result = new ArrayList<>();
        for (String encoded : parts(value.substring(1), '/')) {
            StringBuilder segment = new StringBuilder();
            for (int i = 0; i < encoded.length(); i++) {
                char c = encoded.charAt(i);
                if (c == '~') {
                    require(i + 1 < encoded.length(), "INVALID_JSON_POINTER");
                    char next = encoded.charAt(++i);
                    require(next == '0' || next == '1', "INVALID_JSON_POINTER");
                    segment.append(next == '0' ? '~' : '/');
                } else segment.append(c);
            }
            result.add(segment.toString());
        }
        require(result.size() <= MAX_JSON_DEPTH, "INVALID_JSON_POINTER");
        return List.copyOf(result);
    }

    private static final class CompileBudget {
        private long chars;
        private long instructions;
        void text(String value) {
            chars += value.length();
            require(chars <= 65_536, "CONFIG_PATTERN_LIMIT");
        }
        Pattern program(Pattern pattern) {
            instructions += pattern.programSize();
            require(instructions <= 131_072, "CONFIG_PATTERN_LIMIT");
            return pattern;
        }
    }

    private static Pattern regex(String expression, boolean caseSensitive, CompileBudget budget) {
        require(expression.length() <= MAX_PATTERN && cleanUnicode(expression, true), "INVALID_PATTERN");
        budget.text(expression);
        try {
            Pattern pattern = Pattern.compile(expression, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
            require(pattern.programSize() <= MAX_PROGRAM, "PATTERN_LIMIT");
            return budget.program(pattern);
        } catch (PatternSyntaxException | IllegalArgumentException e) {
            // No original expression or library exception/cause escapes this boundary.
            throw invalid("INVALID_PATTERN");
        }
    }

    private static Pattern literal(String expression, boolean caseSensitive, CompileBudget budget) {
        budget.text(expression);
        return budget.program(Pattern.compile(Pattern.quote(expression), caseSensitive ? 0 : Pattern.CASE_INSENSITIVE));
    }

    private static void validateLimits(Limits limits) {
        require(limits != null, "INVALID_LIMITS");
        rate(limits.globalRps());
        rate(limits.perHostRps());
        require(limits.maxConcurrent() >= 1 && limits.maxConcurrent() <= 100
                && limits.maxQueued() >= 0 && limits.maxQueued() <= 10_000, "INVALID_LIMITS");
        timeout(limits.queueTimeoutMillis());
        timeout(limits.approvalTimeoutMillis());
        timeout(limits.requestTimeoutMillis());
        require(limits.hostRps() != null && limits.hostRps().size() <= MAX_SCOPES, "INVALID_LIMITS");
        Set<String> hosts = new HashSet<>();
        for (Map.Entry<String, Integer> entry : limits.hostRps().entrySet()) {
            require(entry.getValue() != null, "INVALID_LIMITS");
            rate(entry.getValue());
            try { require(hosts.add(host(entry.getKey())), "INVALID_LIMITS"); }
            catch (Failure e) { throw invalid("INVALID_LIMITS"); }
        }
    }

    private static void rate(int rate) { require(rate >= 1 && rate <= 1_000, "INVALID_LIMITS"); }
    private static void timeout(long timeout) { require(timeout >= 1 && timeout <= 600_000, "INVALID_LIMITS"); }
    private static void require(boolean valid, String category) { if (!valid) throw invalid(category); }
    private static IllegalArgumentException invalid(String category) { return new IllegalArgumentException(category); }

    private record CompiledPolicy(GuardConfig source, List<CompiledScope> allow, List<CompiledScope> block,
                                  List<CompiledRule> rules, Mode defaultMode) {}
    private record CompiledRule(String id, String name, boolean enabled, Mode mode, CompiledCondition condition) {}

    private record CompiledScope(boolean enabled, String host, boolean wildcard, String scheme,
                                 int port, Pattern path) {
        boolean authorityMatches(RequestInspection.Target target) {
            if (!enabled || !scheme.equals("any") && !scheme.equals(target.scheme())
                    || port != 0 && port != target.authority().port()) return false;
            String actual = target.authority().host();
            return wildcard ? actual.length() > host.length() + 1 && actual.endsWith("." + host) : actual.equals(host);
        }

        boolean pathMatches(String value, Budget budget) {
            if (path == null) return true;
            budget.work(value.length(), path.programSize());
            return path.matcher(value).matches();
        }

        boolean anyPath(List<String> paths, Budget budget) {
            for (String value : paths) if (pathMatches(value, budget)) return true;
            return false;
        }

        boolean allPaths(List<String> paths, Budget budget) {
            for (String value : paths) if (!pathMatches(value, budget)) return false;
            return true;
        }
    }

    private record CompiledCondition(Logic logic, Field field, String name, Pattern pattern, boolean exact,
                                     int weight, boolean caseSensitive, List<String> pointer,
                                     List<CompiledCondition> children) {
        boolean matches(RequestInspection input, Budget budget) {
            if (logic == Logic.AND) {
                for (CompiledCondition child : children) if (!child.matches(input, budget)) return false;
                return true;
            }
            if (logic == Logic.OR) {
                for (CompiledCondition child : children) if (child.matches(input, budget)) return true;
                return false;
            }
            return switch (field) {
                case METHOD -> values(input.method, budget);
                case URL -> values(input.url, budget);
                case PATH -> values(input.path, budget);
                case QUERY -> named(input.query, false, budget);
                case HEADER -> named(input.headers, true, budget);
                case BODY -> values(input.body, budget);
                case JSON -> (name.isEmpty() ? input.json : input.json.select(pointer)).matches(value -> test(value, budget));
                case FORM -> named(input.form, false, budget);
                case ANY -> values(input.any, budget);
            };
        }

        private boolean named(List<RequestInspection.Named> values, boolean header, Budget budget) {
            for (RequestInspection.Named item : values) {
                if (name.isEmpty()) {
                    if (values(item.names(), budget) || values(item.values(), budget)) return true;
                } else {
                    boolean selected = false;
                    for (String candidate : item.names()) {
                        budget.work(candidate.length(), 1);
                        if ((header || !caseSensitive) ? candidate.equalsIgnoreCase(name) : candidate.equals(name)) {
                            selected = true;
                            break;
                        }
                    }
                    if (selected && values(item.values(), budget)) return true;
                }
            }
            return false;
        }

        private boolean values(List<String> values, Budget budget) {
            for (String value : values) if (test(value, budget)) return true;
            return false;
        }

        private boolean test(String value, Budget budget) {
            budget.work(value.length(), weight);
            return exact ? pattern.matcher(value).matches() : pattern.matcher(value).find();
        }
    }
}
