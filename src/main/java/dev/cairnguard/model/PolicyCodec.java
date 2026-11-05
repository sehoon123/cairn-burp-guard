package dev.cairnguard.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.policy.PolicyEngine;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Strict, version-dispatched policy storage boundary. Migration is in memory only: callers must
 * present the original/migrated diff and obtain an explicit human save before replacing storage.
 * No file, project store, logger or network is accessed here. Parser source/cause text never escapes.
 */
public final class PolicyCodec {
    private static final int MAX_DOCUMENT = 2_097_152;
    private static final Set<String> ROOT_V1 = Set.of("schemaVersion", "allowScope", "blockScope", "rules", "defaultMode", "limits");
    private static final Set<String> ROOT_V2 = Set.of("schemaVersion", "allowScope", "blockScope", "rules", "defaultMode", "limits", "guardListenerPorts");
    private static final Set<String> LIMITS_V1 = Set.of("globalRps", "perHostRps", "hostRps", "maxConcurrent", "maxQueued", "queueTimeoutMillis", "approvalTimeoutMillis", "requestTimeoutMillis");
    private static final String EXCEPTIONS = "circuit5xxExceptions";
    private static final String HEAVY = "heavyResponseEnabled";
    private static final String FANOUT_EXCEPTIONS = "fanoutExceptions";
    private static final Set<String> OPTIONAL_V2 = Set.of(EXCEPTIONS, HEAVY, FANOUT_EXCEPTIONS);
    // Schema 2 as first released had no circuit5xxExceptions; absence is accepted ONLY for that one field.
    private static final Set<String> LIMITS_V2_BASE = Set.of("globalRps", "perHostRps", "hostRps", "maxConcurrent", "maxQueued", "queueTimeoutMillis", "approvalTimeoutMillis", "requestTimeoutMillis", "perPathMaxResponseBytes", "autoBlockMillis", "circuit5xx", "fanout", "perIntentMaxRequests", "healthProbePassthrough", "healthProbePaths", "heavyPathLimits");
    private static final Set<String> LIMITS_V2 = withExceptions();

    private PolicyCodec() {}
    private static Set<String> withExceptions() {
        java.util.HashSet<String> all = new java.util.HashSet<>(LIMITS_V2_BASE);
        all.addAll(OPTIONAL_V2);
        return Set.copyOf(all);
    }
    /** The exact limits field set of THIS document: the first schema-2 shape plus the optional fields present. */
    private static Set<String> limitsShape(JsonNode limits) {
        java.util.HashSet<String> fields = new java.util.HashSet<>(LIMITS_V2_BASE);
        for (String optional : OPTIONAL_V2) if (limits.has(optional)) fields.add(optional);
        return Set.copyOf(fields);
    }

    public record Decoded(GuardConfig config, boolean migrationPending, String originalDocument) {}

    public static Decoded decode(String document) {
        if (document != null && document.length() > MAX_DOCUMENT) throw invalid();
        if (document == null || document.isBlank()) return new Decoded(GuardConfig.defaults(), false, document);
        try {
            JsonNode root = Json.MAPPER.readTree(document);
            check(root != null && root.isObject());
            JsonNode version = root.get("schemaVersion");
            integer(version, false);
            int schema = version.intValue();
            check(schema == 1 || schema == 2);
            shape(root, schema == 1 ? ROOT_V1 : ROOT_V2);
            policyShape(root, schema);
            if (schema == 2) {
                // Narrow compatibility for the three optional fields ONLY: absent lists are empty and an absent
                // heavy master is ON. Null/wrong types were already rejected by policyShape.
                JsonNode limits = root.get("limits");
                if (!limits.has(EXCEPTIONS) || !limits.has(HEAVY) || !limits.has(FANOUT_EXCEPTIONS)) {
                    root = root.deepCopy();
                    ObjectNode copy = (ObjectNode) root.get("limits");
                    if (!copy.has(EXCEPTIONS)) copy.putArray(EXCEPTIONS);
                    if (!copy.has(HEAVY)) copy.put(HEAVY, true);
                    if (!copy.has(FANOUT_EXCEPTIONS)) copy.putArray(FANOUT_EXCEPTIONS);
                }
            }
            GuardConfig config;
            if (schema == 1) {
                // Frozen DTO has ONLY the original fields. Never deserialize raw v1 as today's record.
                LegacyPolicy legacy = Json.MAPPER.treeToValue(root, LegacyPolicy.class);
                config = new GuardConfig(2, legacy.allowScope(), legacy.blockScope(), legacy.rules(),
                        legacy.defaultMode(), legacy.limits().runtime(), List.of());
            } else config = Json.MAPPER.treeToValue(root, GuardConfig.class);
            new PolicyEngine().validate(config);
            return new Decoded(config, schema == 1, document);
        } catch (Exception e) {
            throw invalid();
        }
    }

    /** All explicit saves produce the full schema-2 document, including nullable detector fields. */
    public static String encode(GuardConfig config) {
        GuardConfig v2 = toV2(config);
        try {
            JsonNode tree = Json.MAPPER.valueToTree(v2);
            // An EMPTY exception list is omitted so no-exception policies keep the first schema-2 shape
            // (rollback to an older reader works); a non-empty list requires this or a newer reader.
            ObjectNode limits = (ObjectNode) tree.get("limits");
            if (v2.limits().circuit5xxExceptions().isEmpty()) limits.remove(EXCEPTIONS);
            // Same rule for the detector controls: the default (master ON / no fan-out exceptions) keeps the old shape.
            if (v2.limits().heavyResponseEnabled()) limits.remove(HEAVY);
            if (v2.limits().fanoutExceptions().isEmpty()) limits.remove(FANOUT_EXCEPTIONS);
            String document = Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(tree);
            check(document.length() <= MAX_DOCUMENT); // never save a document this reader cannot reopen
            return document;
        } catch (Exception e) { throw invalid(); }
    }

    public static GuardConfig toV2(GuardConfig config) {
        new PolicyEngine().validate(config);
        if (config.schemaVersion() == 2) return config;
        return new GuardConfig(2, config.allowScope(), config.blockScope(), config.rules(),
                config.defaultMode(), config.limits(), config.guardListenerPorts());
    }

    /** Optional migration action ONLY: do not remove a customized/disabled/look-alike rule. */
    public static GuardConfig removeLegacyDeleteString(GuardConfig config) {
        GuardConfig v2 = toV2(config);
        Rule original = new Rule("delete-string", "Block delete string (conservative)", true, Mode.BLOCK,
                Condition.leaf(Field.ANY, Match.CONTAINS, "delete"));
        return new GuardConfig(2, v2.allowScope(), v2.blockScope(),
                v2.rules().stream().filter(rule -> !original.equals(rule)).toList(),
                v2.defaultMode(), v2.limits(), v2.guardListenerPorts());
    }

    /**
     * Compatibility serialization for old Java test fixtures only. It deliberately emits the frozen
     * v1 shape (no new Limits/listener fields). Production saves must use encode(), never this API.
     */
    public static String encodeLegacy(GuardConfig config) {
        check(config != null && config.schemaVersion() == 1);
        new PolicyEngine().validate(config);
        // The frozen v1 shape cannot carry these; never drop them silently.
        check(config.limits().circuit5xxExceptions().isEmpty() && config.limits().heavyResponseEnabled()
                && config.limits().fanoutExceptions().isEmpty());
        Limits l = config.limits();
        LegacyPolicy legacy = new LegacyPolicy(1, config.allowScope(), config.blockScope(), config.rules(),
                config.defaultMode(), new LegacyLimits(l.globalRps(), l.perHostRps(), l.hostRps(),
                l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(), l.approvalTimeoutMillis(), l.requestTimeoutMillis()));
        try { return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(legacy); }
        catch (Exception e) { throw invalid(); }
    }

    private record LegacyPolicy(int schemaVersion, List<ScopeEntry> allowScope, List<ScopeEntry> blockScope,
                                List<Rule> rules, Mode defaultMode, LegacyLimits limits) {}
    private record LegacyLimits(int globalRps, int perHostRps, Map<String, Integer> hostRps,
                                int maxConcurrent, int maxQueued, long queueTimeoutMillis,
                                long approvalTimeoutMillis, long requestTimeoutMillis) {
        Limits runtime() {
            return new Limits(globalRps, perHostRps, hostRps, maxConcurrent, maxQueued,
                    queueTimeoutMillis, approvalTimeoutMillis, requestTimeoutMillis);
        }
    }

    private static void policyShape(JsonNode root, int schema) {
        for (String scopes : List.of("allowScope", "blockScope")) {
            array(root.get(scopes));
            for (JsonNode entry : root.get(scopes)) {
                shape(entry, Set.of("enabled", "host", "scheme", "port", "pathRegex"));
                bool(entry.get("enabled"));
                strings(entry, "host", "scheme", "pathRegex");
                integer(entry.get("port"), false);
            }
        }
        array(root.get("rules"));
        for (JsonNode rule : root.get("rules")) {
            shape(rule, Set.of("id", "name", "enabled", "mode", "condition"));
            strings(rule, "id", "name", "mode");
            bool(rule.get("enabled"));
            if (schema == 1) check(!rule.get("mode").textValue().equals("EXEMPT"));
            conditionShape(rule.get("condition"));
        }
        strings(root, "defaultMode");
        check(!root.get("defaultMode").textValue().equals("EXEMPT"));
        JsonNode limits = root.get("limits");
        shape(limits, schema == 1 ? LIMITS_V1 : limitsShape(limits));
        for (String name : List.of("globalRps", "perHostRps", "maxConcurrent", "maxQueued")) integer(limits.get(name), false);
        for (String name : List.of("queueTimeoutMillis", "approvalTimeoutMillis", "requestTimeoutMillis")) integer(limits.get(name), true);
        JsonNode hostRps = limits.get("hostRps");
        check(hostRps.isObject());
        hostRps.elements().forEachRemaining(value -> integer(value, false));
        if (schema == 1) return;
        array(root.get("guardListenerPorts"));
        for (JsonNode port : root.get("guardListenerPorts")) integer(port, false);
        integer(limits.get("perPathMaxResponseBytes"), true);
        integer(limits.get("autoBlockMillis"), true);
        integer(limits.get("perIntentMaxRequests"), false);
        bool(limits.get("healthProbePassthrough"));
        if (limits.has(HEAVY)) bool(limits.get(HEAVY));
        JsonNode circuit = limits.get("circuit5xx");
        if (!circuit.isNull()) {
            shape(circuit, Set.of("windowMillis", "threshold", "openMillis", "halfOpenProbe"));
            integer(circuit.get("windowMillis"), true);
            integer(circuit.get("openMillis"), true);
            integer(circuit.get("threshold"), false);
            integer(circuit.get("halfOpenProbe"), false);
        }
        JsonNode fanout = limits.get("fanout");
        if (!fanout.isNull()) {
            shape(fanout, Set.of("windowMillis", "distinctPaths", "action"));
            integer(fanout.get("windowMillis"), true);
            integer(fanout.get("distinctPaths"), false);
            strings(fanout, "action");
        }
        List<String> routeLists = new java.util.ArrayList<>(List.of("healthProbePaths", "heavyPathLimits"));
        if (limits.has(EXCEPTIONS)) routeLists.add(EXCEPTIONS);
        if (limits.has(FANOUT_EXCEPTIONS)) routeLists.add(FANOUT_EXCEPTIONS);
        for (String list : routeLists) {
            array(limits.get(list));
            for (JsonNode route : limits.get(list)) {
                boolean bytes = list.equals("heavyPathLimits");
                shape(route, bytes ? Set.of("scheme", "host", "port", "path", "maxBytes") : Set.of("scheme", "host", "port", "path"));
                strings(route, "scheme", "host", "path");
                integer(route.get("port"), false);
                if (bytes) integer(route.get("maxBytes"), true);
            }
        }
    }

    private static void conditionShape(JsonNode node) {
        shape(node, Set.of("logic", "field", "name", "match", "value", "caseSensitive", "children"));
        strings(node, "logic");
        for (String field : List.of("field", "name", "match", "value")) {
            JsonNode value = node.get(field);
            check(value.isNull() || value.isTextual());
        }
        bool(node.get("caseSensitive"));
        array(node.get("children"));
        for (JsonNode child : node.get("children")) conditionShape(child);
    }

    private static void shape(JsonNode node, Set<String> fields) {
        check(node != null && node.isObject() && node.size() == fields.size());
        node.fieldNames().forEachRemaining(name -> check(fields.contains(name)));
        for (String name : fields) check(node.has(name)); // explicit null is distinct from missing
    }
    private static void strings(JsonNode node, String... names) {
        for (String name : names) check(node.get(name) != null && node.get(name).isTextual());
    }
    private static void integer(JsonNode node, boolean wide) {
        check(node != null && node.isIntegralNumber() && (wide ? node.canConvertToLong() : node.canConvertToInt()));
    }
    private static void bool(JsonNode node) { check(node != null && node.isBoolean()); }
    private static void array(JsonNode node) { check(node != null && node.isArray()); }
    private static void check(boolean valid) { if (!valid) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_PROJECT_POLICY"); }
}
