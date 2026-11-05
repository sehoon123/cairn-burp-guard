package dev.cairnguard.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.policy.PolicyEngine;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class PolicyCodecTest {
    private static final Rule LEGACY_STRING = new Rule("delete-string", "Block delete string (conservative)", true,
            Mode.BLOCK, Condition.leaf(Field.ANY, Match.CONTAINS, "delete"));

    private static GuardConfig legacy() {
        return new GuardConfig(1, List.of(new ScopeEntry(true, "example.test", "https", 443, "")), List.of(),
                List.of(GuardConfig.defaults().rules().getFirst(), LEGACY_STRING), Mode.ALLOW,
                new Limits(7, 3, Map.of("example.test", 2), 4, 10, 1234, 2345, 3456));
    }
    /** A historically saved schema-2 policy: circuit explicitly ON, no circuit5xxExceptions field. */
    private static GuardConfig savedOn() { return withCircuit(GuardConfig.defaults(), new Circuit5xx(60_000, 5, 600_000, 1), List.of()); }
    private static GuardConfig withCircuit(GuardConfig base, Circuit5xx circuit, List<ProbePath> exceptions) {
        Limits l = base.limits();
        return new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), circuit,
                        l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(), exceptions),
                base.guardListenerPorts());
    }
    private static ObjectNode document() {
        ObjectNode node = Json.MAPPER.valueToTree(savedOn());
        // the exact first schema-2 shape: none of the three optional fields
        ((ObjectNode) node.get("limits")).remove(List.of("circuit5xxExceptions", "heavyResponseEnabled", "fanoutExceptions"));
        return node;
    }
    private static PolicyCodec.Decoded decode(JsonNode node) { return PolicyCodec.decode(Json.write(node)); }
    private static void invalid(String document) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> PolicyCodec.decode(document));
        assertEquals("INVALID_PROJECT_POLICY", error.getMessage());
        assertNull(error.getCause(), "Parser source/cause must never escape");
    }
    private static void invalid(JsonNode document) { invalid(Json.write(document)); }
    private static ObjectNode parent(ObjectNode root, String pointer) {
        return (ObjectNode) root.at(pointer.substring(0, pointer.lastIndexOf('/')));
    }
    private static void replace(ObjectNode root, String pointer, Object value) {
        parent(root, pointer).set(pointer.substring(pointer.lastIndexOf('/') + 1), Json.MAPPER.valueToTree(value));
    }

    @Test void blankStartsNewProfileButLegacyMigrationIsOffDefaultAndReadOnly() {
        for (String blank : new String[]{null, "", " \n\t"}) {
            PolicyCodec.Decoded decoded = PolicyCodec.decode(blank);
            assertEquals(GuardConfig.defaults(), decoded.config());
            assertFalse(decoded.migrationPending());
            assertEquals(blank, decoded.originalDocument());
        }
        GuardConfig original = legacy();
        assertEquals(1, original.schemaVersion(), "Compatibility ctor must not silently normalize schema");
        String source = Json.write(original);
        assertFalse(source.contains("guardListenerPorts"));
        assertFalse(source.contains("perPathMaxResponseBytes"));
        PolicyCodec.Decoded migrated = PolicyCodec.decode(source);
        GuardConfig cfg = migrated.config();
        assertEquals(source, migrated.originalDocument());
        assertTrue(migrated.migrationPending());
        assertEquals(2, cfg.schemaVersion());
        assertEquals(original.allowScope(), cfg.allowScope());
        assertEquals(original.blockScope(), cfg.blockScope());
        assertEquals(original.rules(), cfg.rules());
        assertEquals(original.defaultMode(), cfg.defaultMode());
        assertEquals(original.limits(), cfg.limits()); // old 8-arg ctor's new features are all off
        assertEquals(0, cfg.limits().perPathMaxResponseBytes());
        assertEquals(600_000, cfg.limits().autoBlockMillis());
        assertNull(cfg.limits().circuit5xx());
        assertNull(cfg.limits().fanout());
        assertEquals(0, cfg.limits().perIntentMaxRequests());
        assertFalse(cfg.limits().healthProbePassthrough());
        assertTrue(cfg.limits().healthProbePaths().isEmpty());
        assertTrue(cfg.limits().heavyPathLimits().isEmpty());
        assertTrue(cfg.guardListenerPorts().isEmpty());
        assertTrue(cfg.rules().stream().noneMatch(rule -> rule.mode() == Mode.EXEMPT));
        assertEquals(source, Json.write(original), "Decode does not alter original Java policy or stored source");
        assertEquals(cfg, Json.read(source, GuardConfig.class));
    }

    @Test void explicitV2RoundtripRetainsLegacyDeleteUntilSeparateReviewedRemoval() {
        GuardConfig cfg = PolicyCodec.decode(Json.write(legacy())).config();
        String saved = PolicyCodec.encode(cfg);
        PolicyCodec.Decoded reread = PolicyCodec.decode(saved);
        assertFalse(reread.migrationPending());
        assertEquals(cfg, reread.config());
        assertTrue(saved.contains("\"circuit5xx\" : null"));
        assertTrue(saved.contains("\"fanout\" : null"));
        assertTrue(saved.contains("\"guardListenerPorts\" : [ ]"));
        RequestData get = new RequestData("GET", "https://example.test/ui/bp/common/board/deleteInfoBoardComnt.do",
                "example.test", 443, true, List.of(), new byte[0]);
        assertEquals("RULE_BLOCK", new PolicyEngine().evaluate(reread.config(), get).reason());
        GuardConfig removed = PolicyCodec.removeLegacyDeleteString(cfg);
        assertEquals(1, removed.rules().size());
        assertEquals("delete-method", removed.rules().getFirst().id());
        assertEquals(Mode.ALLOW, new PolicyEngine().evaluate(removed, get).mode());
        assertEquals(2, cfg.rules().size(), "Removal returns a new draft, never mutates loaded policy");
        assertEquals(removed, PolicyCodec.decode(PolicyCodec.encode(removed)).config());
    }

    @Test void legacyCompositeConditionsSelectorsCaseFlagsAndRuleOrderSurviveMigration() {
        Condition selected = new Condition(Logic.LEAF, Field.JSON, "/a~1b/0", Match.REGEX, "^delete$", true, List.of());
        Condition group = new Condition(Logic.AND, null, null, null, null, false,
                List.of(Condition.leaf(Field.METHOD, Match.EXACT, "POST"),
                        Condition.or(selected, new Condition(Logic.LEAF, Field.HEADER, "X-Action", Match.EXACT, "delete", false, List.of()))));
        GuardConfig old = new GuardConfig(1, legacy().allowScope(), legacy().blockScope(),
                List.of(new Rule("custom", "Original composite", false, Mode.ASK, group), LEGACY_STRING),
                Mode.MONITOR, legacy().limits());
        PolicyCodec.Decoded decoded = PolicyCodec.decode(Json.write(old));
        assertEquals(old.rules(), decoded.config().rules());
        assertEquals(old.defaultMode(), decoded.config().defaultMode());
        assertEquals(decoded.config(), PolicyCodec.decode(PolicyCodec.encode(decoded.config())).config());
    }

    @Test void removalDoesNotDeleteCustomizedDisabledOrLookalikeRules() {
        for (Rule customized : List.of(
                new Rule("other", LEGACY_STRING.name(), true, Mode.BLOCK, LEGACY_STRING.condition()),
                new Rule(LEGACY_STRING.id(), "Customized name", true, Mode.BLOCK, LEGACY_STRING.condition()),
                new Rule(LEGACY_STRING.id(), LEGACY_STRING.name(), false, Mode.BLOCK, LEGACY_STRING.condition()),
                new Rule(LEGACY_STRING.id(), LEGACY_STRING.name(), true, Mode.ASK, LEGACY_STRING.condition()),
                new Rule(LEGACY_STRING.id(), LEGACY_STRING.name(), true, Mode.BLOCK, Condition.leaf(Field.BODY, Match.CONTAINS, "delete")))) {
            GuardConfig cfg = new GuardConfig(2, List.of(), List.of(), List.of(customized), Mode.ALLOW, legacy().limits());
            assertEquals(cfg, PolicyCodec.removeLegacyDeleteString(cfg));
        }
    }

    @Test void newDefaultsHaveOnlyDeleteMethodAndConfiguredV2AvailabilityDefaults() {
        GuardConfig cfg = GuardConfig.defaults();
        assertEquals(2, cfg.schemaVersion());
        assertEquals(List.of("delete-method"), cfg.rules().stream().map(Rule::id).toList());
        assertEquals(5L * 1_048_576, cfg.limits().perPathMaxResponseBytes());
        assertNull(cfg.limits().circuit5xx(), "the 5xx circuit is optional and OFF for fresh profiles");
        assertTrue(cfg.limits().circuit5xxExceptions().isEmpty());
        assertEquals(new Fanout(60_000, 100, FanoutAction.WARN), cfg.limits().fanout());
        assertEquals(cfg, PolicyCodec.decode(PolicyCodec.encode(cfg)).config());
        assertSame(cfg, PolicyCodec.toV2(cfg));
        assertEquals(1, legacy().schemaVersion());
        assertEquals(2, PolicyCodec.toV2(legacy()).schemaVersion());
    }

    @Test void rawV1CannotSmuggleAnyV2FieldOrExemptEvenWhenDisabled() throws Exception {
        ObjectNode raw = (ObjectNode) Json.MAPPER.readTree(Json.write(legacy()));
        ObjectNode withListeners = raw.deepCopy();
        withListeners.putArray("guardListenerPorts");
        invalid(withListeners);
        List<String> newFields = List.of("perPathMaxResponseBytes", "autoBlockMillis", "circuit5xx", "fanout",
                "perIntentMaxRequests", "healthProbePassthrough", "healthProbePaths", "heavyPathLimits");
        for (String name : newFields) {
            ObjectNode altered = raw.deepCopy();
            ((ObjectNode) altered.get("limits")).set(name, document().at("/limits/" + name));
            invalid(altered);
        }
        ((ObjectNode) raw.at("/rules/0")).put("mode", "EXEMPT").put("enabled", false);
        invalid(raw);
        raw = (ObjectNode) Json.MAPPER.readTree(Json.write(legacy()));
        raw.put("defaultMode", "EXEMPT");
        invalid(raw);
    }

    @Test void everyV2FieldIsRequiredIncludingNullableDetectorObjectsAndNestedFields() {
        ObjectNode complete = document();
        for (String pointer : List.of("", "/limits", "/limits/circuit5xx", "/limits/fanout", "/rules/0", "/rules/0/condition")) {
            ObjectNode object = (ObjectNode) complete.at(pointer);
            List<String> names = new ArrayList<>();
            object.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                ObjectNode copy = complete.deepCopy();
                ((ObjectNode) copy.at(pointer)).remove(name);
                invalid(copy);
            }
        }
        ObjectNode off = document();
        ((ObjectNode) off.get("limits")).putNull("circuit5xx").putNull("fanout");
        assertDoesNotThrow(() -> decode(off));
    }

    private static final ProbePath EXPECTED = new ProbePath("https", "example.test", 443, "/expected-error");

    @Test void emptyExceptionListIsOmittedOnEncodeSoOldReadersAndOldShapeStillWork() {
        for (GuardConfig empty : List.of(GuardConfig.defaults(), savedOn())) {
            String saved = PolicyCodec.encode(empty);
            assertFalse(saved.contains("circuit5xxExceptions"));
            assertEquals(Json.write(empty), saved);
            assertEquals(empty, PolicyCodec.decode(saved).config());
        }
        JsonNode oldShape = document();
        assertFalse(oldShape.get("limits").has("circuit5xxExceptions"));
        PolicyCodec.Decoded old = PolicyCodec.decode(Json.write(oldShape));
        assertEquals(savedOn(), old.config(), "an explicitly saved ON circuit stays ON and gains an empty list in memory only");
        assertFalse(old.migrationPending());
    }

    @Test void nonEmptyExceptionListRoundTripsAndIsPreservedByEveryProductionCopyPath() {
        GuardConfig cfg = withCircuit(GuardConfig.defaults(), null, List.of(EXPECTED, new ProbePath("http", "other.test", 8080, "/a/b")));
        String saved = PolicyCodec.encode(cfg);
        assertTrue(saved.contains("\"circuit5xxExceptions\""));
        assertEquals(cfg, PolicyCodec.decode(saved).config());
        assertEquals(cfg, Json.read(Json.write(cfg), GuardConfig.class));
        assertSame(cfg, PolicyCodec.toV2(cfg));
        assertEquals(cfg.limits().circuit5xxExceptions(), PolicyCodec.removeLegacyDeleteString(cfg).limits().circuit5xxExceptions());
        assertThrows(IllegalArgumentException.class, () -> PolicyCodec.encodeLegacy(withLegacySchema(cfg)),
                "the frozen v1 shape cannot carry the field; it is validated and rejected, never silently dropped");
        assertEquals(cfg.limits().circuit5xxExceptions(), new Limits(1, 1, Map.of(), 1, 0, 1, 1, 1, 0, 1000, null, null, 0, false, List.of(), List.of(), cfg.limits().circuit5xxExceptions()).circuit5xxExceptions());
        assertTrue(new Limits(1, 1, Map.of(), 1, 0, 1, 1, 1).circuit5xxExceptions().isEmpty());
    }
    private static GuardConfig withLegacySchema(GuardConfig c) {
        return new GuardConfig(1, c.allowScope(), c.blockScope(), c.rules(), c.defaultMode(), c.limits());
    }

    private static GuardConfig controls(GuardConfig base, boolean heavy, List<ProbePath> fanout) {
        Limits l = base.limits();
        return new GuardConfig(2, base.allowScope(), base.blockScope(), base.rules(), base.defaultMode(),
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(), l.queueTimeoutMillis(),
                        l.approvalTimeoutMillis(), l.requestTimeoutMillis(), l.perPathMaxResponseBytes(), l.autoBlockMillis(), l.circuit5xx(),
                        l.fanout(), l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), l.heavyPathLimits(),
                        l.circuit5xxExceptions(), heavy, fanout), base.guardListenerPorts());
    }

    @Test void detectorControlsDefaultToOldShapeAndRoundTripEveryOptionalCombination() {
        GuardConfig defaults = GuardConfig.defaults();
        assertTrue(defaults.limits().heavyResponseEnabled(), "large-response protection stays ON for fresh profiles");
        assertTrue(defaults.limits().fanoutExceptions().isEmpty());
        assertEquals(new Fanout(60_000, 100, FanoutAction.WARN), defaults.limits().fanout());
        String saved = PolicyCodec.encode(defaults);
        assertFalse(saved.contains("heavyResponseEnabled")); assertFalse(saved.contains("fanoutExceptions"));
        PolicyCodec.Decoded old = PolicyCodec.decode(Json.write(document()));
        assertTrue(old.config().limits().heavyResponseEnabled(), "absent master means ON");
        assertTrue(old.config().limits().fanoutExceptions().isEmpty());
        assertFalse(old.migrationPending());
        for (boolean heavy : List.of(true, false)) for (List<ProbePath> fanout : List.of(List.<ProbePath>of(), List.of(EXPECTED)))
            for (List<ProbePath> circuit : List.of(List.<ProbePath>of(), List.of(new ProbePath("http", "other.test", 8080, "/c")))) {
                GuardConfig cfg = controls(withCircuit(GuardConfig.defaults(), null, circuit), heavy, fanout);
                String text = PolicyCodec.encode(cfg);
                assertEquals(!heavy, text.contains("\"heavyResponseEnabled\""));
                assertEquals(!fanout.isEmpty(), text.contains("\"fanoutExceptions\""));
                assertEquals(!circuit.isEmpty(), text.contains("\"circuit5xxExceptions\""));
                assertEquals(cfg, PolicyCodec.decode(text).config());
                assertEquals(cfg.limits(), PolicyCodec.removeLegacyDeleteString(cfg).limits());
            }
        // compatibility constructors keep the master ON and no fan-out exceptions
        Limits l = defaults.limits();
        assertTrue(new Limits(1, 1, Map.of(), 1, 0, 1, 1, 1).heavyResponseEnabled());
        assertTrue(new Limits(1, 1, Map.of(), 1, 0, 1, 1, 1, 0, 1000, null, null, 0, false, List.of(), List.of()).fanoutExceptions().isEmpty());
        assertTrue(new Limits(1, 1, Map.of(), 1, 0, 1, 1, 1, 0, 1000, null, null, 0, false, List.of(), List.of(), List.of(EXPECTED)).heavyResponseEnabled());
        GuardConfig off = controls(defaults, false, List.of(EXPECTED));
        assertThrows(IllegalArgumentException.class, () -> PolicyCodec.encodeLegacy(withLegacySchema(off)),
                "the frozen v1 shape cannot carry heavy=false or fan-out exceptions; never dropped silently");
        assertThrows(IllegalArgumentException.class, () -> PolicyCodec.encodeLegacy(withLegacySchema(controls(defaults, true, List.of(EXPECTED)))));
        assertThrows(IllegalArgumentException.class, () -> PolicyCodec.encodeLegacy(withLegacySchema(controls(defaults, false, List.of()))));
    }

    @Test void detectorControlFieldsAreStrictlyTypedBoundedAndNeverAcceptedByV1() throws Exception {
        ObjectNode valid = document();
        ((ObjectNode) valid.get("limits")).put("heavyResponseEnabled", false).putArray("fanoutExceptions").add(Json.MAPPER.valueToTree(EXPECTED));
        assertDoesNotThrow(() -> decode(valid));
        for (Object bad : new Object[]{null, "false", 0, List.of(), Map.of()}) {
            ObjectNode altered = valid.deepCopy(); replace(altered, "/limits/heavyResponseEnabled", bad); invalid(altered);
        }
        for (Object bad : new Object[]{null, "[]", Map.of(), 1, true}) {
            ObjectNode altered = valid.deepCopy(); replace(altered, "/limits/fanoutExceptions", bad); invalid(altered);
        }
        for (String field : List.of("scheme", "host", "port", "path")) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/fanoutExceptions/0")).remove(field); invalid(altered);
        }
        ObjectNode unknown = valid.deepCopy(); ((ObjectNode) unknown.at("/limits/fanoutExceptions/0")).put("unknown", true); invalid(unknown);
        for (String path : List.of("/a?x=1", "/a#f", "/a/../b", "/a;b", "/a%2fb", "relative")) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/fanoutExceptions/0")).put("path", path); invalid(altered);
        }
        ObjectNode alias = valid.deepCopy();
        ((ArrayNode) alias.at("/limits/fanoutExceptions")).add(Json.MAPPER.valueToTree(new ProbePath("https", "EXAMPLE.test.", 443, "/expected-error")));
        invalid(alias);
        ObjectNode sixteen = document(); ArrayNode rows = ((ObjectNode) sixteen.get("limits")).putArray("fanoutExceptions");
        for (int i = 0; i < 16; i++) rows.add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/f/" + i)));
        assertDoesNotThrow(() -> decode(sixteen));
        rows.add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/f/16"))); invalid(sixteen);
        for (String field : List.of("heavyResponseEnabled", "fanoutExceptions")) {
            ObjectNode raw = (ObjectNode) Json.MAPPER.readTree(Json.write(legacy()));
            if (field.equals("heavyResponseEnabled")) ((ObjectNode) raw.get("limits")).put(field, true);
            else ((ObjectNode) raw.get("limits")).putArray(field);
            invalid(raw);
        }
        String text = PolicyCodec.encode(controls(GuardConfig.defaults(), false, List.of()));
        invalid(text.replace("\"heavyResponseEnabled\" :", "\"heavyResponseEnabled\" : true, \"heavyResponseEnabled\" :"));
    }

    @Test void exceptionFieldIsStrictlyTypedBoundedAndNeverAcceptedByV1() throws Exception {
        ObjectNode valid = document();
        ((ObjectNode) valid.get("limits")).putArray("circuit5xxExceptions").add(Json.MAPPER.valueToTree(EXPECTED));
        assertDoesNotThrow(() -> decode(valid));
        for (Object bad : new Object[]{null, "[]", Map.of(), 1, true}) {
            ObjectNode altered = valid.deepCopy(); replace(altered, "/limits/circuit5xxExceptions", bad); invalid(altered);
        }
        for (String field : List.of("scheme", "host", "port", "path")) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/circuit5xxExceptions/0")).remove(field); invalid(altered);
        }
        ObjectNode unknown = valid.deepCopy(); ((ObjectNode) unknown.at("/limits/circuit5xxExceptions/0")).put("unknown", true); invalid(unknown);
        ObjectNode coerced = valid.deepCopy(); ((ObjectNode) coerced.at("/limits/circuit5xxExceptions/0")).put("port", "443"); invalid(coerced);
        ObjectNode nullRow = valid.deepCopy(); ((ArrayNode) nullRow.at("/limits/circuit5xxExceptions")).addNull(); invalid(nullRow);
        for (String path : List.of("", "relative", "//other.test/a", "/a?x=1", "/a#f", "/a/../b", "/a/./b", "/a;b", "/a%2fb", "/a%zz", "/a\\b", "/a b")) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/circuit5xxExceptions/0")).put("path", path); invalid(altered);
        }
        for (String host : List.of("*.example.test", "user@example.test", "example.test:443", "")) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/circuit5xxExceptions/0")).put("host", host); invalid(altered);
        }
        ObjectNode alias = valid.deepCopy();
        ((ArrayNode) alias.at("/limits/circuit5xxExceptions")).add(Json.MAPPER.valueToTree(new ProbePath("https", "EXAMPLE.test.", 443, "/expected-error")));
        invalid(alias);
        ObjectNode sixteen = document(); ArrayNode rows = ((ObjectNode) sixteen.get("limits")).putArray("circuit5xxExceptions");
        for (int i = 0; i < 16; i++) rows.add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/e/" + i)));
        assertDoesNotThrow(() -> decode(sixteen));
        rows.add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/e/16"))); invalid(sixteen);
        // The raw v1 shape cannot smuggle the field, not even as an empty list.
        ObjectNode raw = (ObjectNode) Json.MAPPER.readTree(Json.write(legacy()));
        ((ObjectNode) raw.get("limits")).putArray("circuit5xxExceptions");
        invalid(raw);
        String text = PolicyCodec.encode(withCircuit(GuardConfig.defaults(), null, List.of(EXPECTED)));
        invalid(text.replace("\"circuit5xxExceptions\" :", "\"circuit5xxExceptions\" : [ ], \"circuit5xxExceptions\" :"));
    }

    @Test void strictDuplicateUnknownTrailingAndBoundedDocumentChecksApplyToBothVersions() {
        for (String valid : List.of(Json.write(legacy()), PolicyCodec.encode(GuardConfig.defaults()))) {
            invalid(valid + " {}");
            invalid(valid.replace("\"schemaVersion\" :", "\"schemaVersion\":1, \"schemaVersion\" :"));
            invalid(valid.replace("\"globalRps\" :", "\"globalRps\":5, \"globalRps\" :"));
            invalid(valid.replace("\"limits\" : {", "\"unknown\":true, \"limits\" : {"));
            invalid(valid.replace("\"globalRps\" :", "\"unknown\":true, \"globalRps\" :"));
        }
        invalid("null"); invalid("[]"); invalid("{}"); invalid(" ".repeat(2_097_153));
        invalid("[".repeat(50) + "0" + "]".repeat(50));
        invalid("{\"schemaVersion\":2,\"secret\":\"" + "s".repeat(1_048_577) + "\"}");
    }

    @Test void unknownNestedScopeRuleConditionAndDetectorFieldsCannotBeSilentlyIgnored() {
        ObjectNode root = document();
        ((ArrayNode) root.get("allowScope")).add(Json.MAPPER.valueToTree(new ScopeEntry(false, "example.test", "https", 443, "")));
        for (String pointer : List.of("/allowScope/0", "/rules/0", "/rules/0/condition", "/limits/circuit5xx", "/limits/fanout")) {
            ObjectNode altered = root.deepCopy();
            ((ObjectNode) altered.at(pointer)).put("unknown", true);
            invalid(altered);
        }
        ObjectNode limits = (ObjectNode) root.get("limits");
        limits.putArray("healthProbePaths").add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/health")));
        limits.putArray("heavyPathLimits").add(Json.MAPPER.valueToTree(new PathByteLimit("https", "example.test", 443, "/heavy", 0)));
        for (String pointer : List.of("/limits/healthProbePaths/0", "/limits/heavyPathLimits/0")) {
            ObjectNode altered = root.deepCopy();
            ((ObjectNode) altered.at(pointer)).put("unknown", true);
            invalid(altered);
        }
    }

    @Test void encoderNeverProducesAnOversizedDocumentItsDecoderCannotReopen() {
        GuardConfig defaults = GuardConfig.defaults();
        Limits l = defaults.limits();
        List<PathByteLimit> paths = new ArrayList<>();
        for (int i = 0; i < 256; i++) paths.add(new PathByteLimit("https", "example.test", 443, "/" + "x".repeat(10_000) + i, 0));
        GuardConfig large = new GuardConfig(2, List.of(), List.of(), List.of(), Mode.ALLOW,
                new Limits(l.globalRps(), l.perHostRps(), l.hostRps(), l.maxConcurrent(), l.maxQueued(),
                        l.queueTimeoutMillis(), l.approvalTimeoutMillis(), l.requestTimeoutMillis(),
                        l.perPathMaxResponseBytes(), l.autoBlockMillis(), l.circuit5xx(), l.fanout(),
                        l.perIntentMaxRequests(), l.healthProbePassthrough(), l.healthProbePaths(), paths));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> PolicyCodec.encode(large));
        assertEquals("INVALID_PROJECT_POLICY", error.getMessage());
        assertNull(error.getCause());
    }

    static Stream<Arguments> scalarCoercions() {
        return Stream.of(
                Arguments.of("/schemaVersion", "2"), Arguments.of("/schemaVersion", 2.0),
                Arguments.of("/schemaVersion", 0), Arguments.of("/schemaVersion", 3),
                Arguments.of("/schemaVersion", 4_294_967_298L), Arguments.of("/schemaVersion", true),
                Arguments.of("/defaultMode", 0), Arguments.of("/defaultMode", "EXEMPT"),
                Arguments.of("/defaultMode", "allow"), Arguments.of("/limits/globalRps", "5"),
                Arguments.of("/limits/globalRps", 5.1), Arguments.of("/limits/globalRps", true),
                Arguments.of("/limits/healthProbePassthrough", "false"), Arguments.of("/limits/healthProbePassthrough", 0),
                Arguments.of("/limits/perPathMaxResponseBytes", "0"), Arguments.of("/limits/perPathMaxResponseBytes", 1.0),
                Arguments.of("/limits/hostRps", List.of()), Arguments.of("/limits/healthProbePaths", Map.of()),
                Arguments.of("/guardListenerPorts", Map.of()), Arguments.of("/rules/0/enabled", "true"),
                Arguments.of("/rules/0/mode", 1), Arguments.of("/rules/0/id", 123),
                Arguments.of("/rules/0/condition/field", 0), Arguments.of("/rules/0/condition/value", 42),
                Arguments.of("/rules/0/condition/caseSensitive", "false"), Arguments.of("/rules/0/condition/children", Map.of()),
                Arguments.of("/limits/circuit5xx/halfOpenProbe", "1"), Arguments.of("/limits/fanout/action", 0));
    }
    @ParameterizedTest @MethodSource("scalarCoercions")
    void noScalarContainerEnumOrVersionCoercion(String path, Object value) {
        ObjectNode altered = document(); replace(altered, path, value); invalid(altered);
    }

    @ParameterizedTest @ValueSource(strings = {"/schemaVersion", "/limits", "/allowScope", "/rules", "/guardListenerPorts",
            "/defaultMode", "/limits/globalRps", "/limits/hostRps", "/limits/perPathMaxResponseBytes", "/limits/healthProbePassthrough",
            "/limits/healthProbePaths", "/rules/0/enabled", "/rules/0/condition/caseSensitive", "/rules/0/condition/children"})
    void nullCannotBecomeAFalseZeroOrEmptyDefault(String path) {
        ObjectNode altered = document(); replace(altered, path, null); invalid(altered);
    }

    static Stream<Arguments> invalidBounds() {
        return Stream.of(
                Arguments.of("perPathMaxResponseBytes", -1L), Arguments.of("perPathMaxResponseBytes", 2_147_483_649L),
                Arguments.of("autoBlockMillis", 999L), Arguments.of("autoBlockMillis", 86_400_001L),
                Arguments.of("perIntentMaxRequests", -1), Arguments.of("perIntentMaxRequests", 1_000_001),
                Arguments.of("circuit5xx/windowMillis", 999), Arguments.of("circuit5xx/windowMillis", 3_600_001),
                Arguments.of("circuit5xx/openMillis", 999), Arguments.of("circuit5xx/openMillis", 86_400_001),
                Arguments.of("circuit5xx/threshold", 0), Arguments.of("circuit5xx/threshold", 1001),
                Arguments.of("circuit5xx/halfOpenProbe", 0), Arguments.of("circuit5xx/halfOpenProbe", 2),
                Arguments.of("fanout/windowMillis", 999), Arguments.of("fanout/windowMillis", 3_600_001),
                Arguments.of("fanout/distinctPaths", 1), Arguments.of("fanout/distinctPaths", 1001),
                Arguments.of("fanout/action", "ALLOW"));
    }
    @ParameterizedTest @MethodSource("invalidBounds")
    void allNewNumericLimitsAreBounded(String name, Object value) {
        ObjectNode altered = document(); replace(altered, "/limits/" + name, value); invalid(altered);
    }

    static Stream<Arguments> validBounds() {
        return Stream.of(
                Arguments.of("perPathMaxResponseBytes", 0L), Arguments.of("perPathMaxResponseBytes", 2_147_483_648L),
                Arguments.of("autoBlockMillis", 1000L), Arguments.of("autoBlockMillis", 86_400_000L),
                Arguments.of("perIntentMaxRequests", 0), Arguments.of("perIntentMaxRequests", 1_000_000),
                Arguments.of("circuit5xx/windowMillis", 1000), Arguments.of("circuit5xx/windowMillis", 3_600_000),
                Arguments.of("circuit5xx/openMillis", 1000), Arguments.of("circuit5xx/openMillis", 86_400_000),
                Arguments.of("circuit5xx/threshold", 1), Arguments.of("circuit5xx/threshold", 1000),
                Arguments.of("fanout/windowMillis", 1000), Arguments.of("fanout/windowMillis", 3_600_000),
                Arguments.of("fanout/distinctPaths", 2), Arguments.of("fanout/distinctPaths", 1000),
                Arguments.of("fanout/action", "BLOCK"), Arguments.of("fanout/action", "PAUSE"), Arguments.of("fanout/action", "WARN"));
    }
    @ParameterizedTest @MethodSource("validBounds")
    void documentedInclusiveBoundsAreAccepted(String name, Object value) {
        ObjectNode altered = document(); replace(altered, "/limits/" + name, value); assertDoesNotThrow(() -> decode(altered));
    }

    @Test void exactAuthoredRouteLimitsListenerBoundsAndCanonicalDuplicatesAreValidated() {
        ObjectNode valid = document();
        ArrayNode probes = ((ObjectNode) valid.get("limits")).putArray("healthProbePaths");
        for (int i = 0; i < 16; i++) probes.add(Json.MAPPER.valueToTree(new ProbePath("https", "example.test", 443, "/health/" + i)));
        ArrayNode paths = ((ObjectNode) valid.get("limits")).putArray("heavyPathLimits");
        for (int i = 0; i < 256; i++) paths.add(Json.MAPPER.valueToTree(new PathByteLimit("https", "example.test", 443, "/path/" + i, i == 0 ? 2_147_483_648L : 0)));
        ArrayNode listeners = valid.putArray("guardListenerPorts");
        listeners.add(1).add(65535);
        for (int i = 2; i <= 15; i++) listeners.add(i);
        GuardConfig cfg = assertDoesNotThrow(() -> decode(valid).config());
        assertEquals(cfg, decode(Json.MAPPER.valueToTree(cfg)).config());
        ObjectNode tooMany = valid.deepCopy(); ((ArrayNode) tooMany.at("/limits/healthProbePaths")).add(probes.get(0)); invalid(tooMany);
        tooMany = valid.deepCopy(); ((ArrayNode) tooMany.at("/limits/heavyPathLimits")).add(paths.get(0)); invalid(tooMany);
        tooMany = valid.deepCopy(); ((ArrayNode) tooMany.get("guardListenerPorts")).add(16); invalid(tooMany);
        for (List<?> invalid : List.of(List.of(0), List.of(65536), List.of(8080, 8080), List.of("8080"), List.of(8080.5))) {
            ObjectNode altered = document(); altered.set("guardListenerPorts", Json.MAPPER.valueToTree(invalid)); invalid(altered);
        }
        for (String routeList : List.of("healthProbePaths", "heavyPathLimits")) {
            ObjectNode altered = valid.deepCopy();
            ((ObjectNode) altered.at("/limits/" + routeList + "/1")).put("host", "EXAMPLE.test.").put("path", routeList.equals("healthProbePaths") ? "/health/0" : "/path/0");
            invalid(altered);
            for (String field : List.of("scheme", "host", "port", "path")) {
                altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/" + routeList + "/0")).remove(field); invalid(altered);
            }
            for (String path : List.of("", "relative", "//other.test/a", "/a?x=1", "/a#fragment", "/a/../b", "/a/./b", "/a;b", "/a%2fb", "/a%252fb", "/a%zz", "/a\\b", "/a b")) {
                altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/" + routeList + "/0")).put("path", path); invalid(altered);
            }
            for (String host : List.of("*.example.test", "user@example.test", "example.test:443", "127.1")) {
                altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/" + routeList + "/0")).put("host", host); invalid(altered);
            }
            altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/" + routeList + "/0")).put("scheme", "any"); invalid(altered);
            altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/" + routeList + "/0")).put("port", 0); invalid(altered);
        }
        for (long bytes : new long[]{-1, 2_147_483_649L}) {
            ObjectNode altered = valid.deepCopy(); ((ObjectNode) altered.at("/limits/heavyPathLimits/0")).put("maxBytes", bytes); invalid(altered);
        }
    }
}
