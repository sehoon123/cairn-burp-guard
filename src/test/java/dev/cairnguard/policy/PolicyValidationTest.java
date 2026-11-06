package dev.cairnguard.policy;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.policy.PolicyEngineTest.*;
import static org.junit.jupiter.api.Assertions.*;

class PolicyValidationTest {
    private final PolicyEngine engine = new PolicyEngine();

    private void invalid(GuardConfig config) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> engine.validate(config));
        assertNull(error.getCause());
        assertTrue(error.getMessage().chars().allMatch(c -> c >= 'A' && c <= 'Z' || c == '_'));
    }

    @Test void defaultsAndSupportedNestedConditionsValidate() {
        assertDoesNotThrow(() -> engine.validate(GuardConfig.defaults()));
        assertDoesNotThrow(() -> engine.validate(config(List.of(rule("linear", Mode.BLOCK,
                leaf(Field.BODY, Match.REGEX, "(a+)+$"))))));
        invalid(null);
        GuardConfig valid = config(List.of());
        assertDoesNotThrow(() -> engine.validate(new GuardConfig(2, valid.allowScope(), valid.blockScope(), valid.rules(), valid.defaultMode(), valid.limits())));
        invalid(new GuardConfig(3, valid.allowScope(), valid.blockScope(), valid.rules(), valid.defaultMode(), valid.limits()));
        invalid(new GuardConfig(1, valid.allowScope(), valid.blockScope(), valid.rules(), null, valid.limits()));
        invalid(new GuardConfig(1, valid.allowScope(), valid.blockScope(), valid.rules(), Mode.ALLOW, null));
    }

    @ParameterizedTest @ValueSource(strings = {"(?=delete)", "(?!delete)", "(?<=delete)", "(?<!delete)", "(a)\\1", "[", "a{1001}", "a{1000}b{1000}c{1000}d{1000}e{1000}"})
    void unsupportedOrExcessiveRe2ExpressionsAreRejected(String pattern) {
        invalid(config(List.of(rule("regex", Mode.BLOCK, leaf(Field.BODY, Match.REGEX, pattern)))));
        invalid(config(List.of(scope("example.test", "any", 0, pattern)), List.of(), List.of(), Mode.ALLOW));
    }

    @ParameterizedTest @ValueSource(strings = {"*", "*example.test", "foo.*.test", "a..test", "example.test/path", "example.test:443", " example.test", "*.127.0.0.1", "*.::1", "127.1", "0177.0.0.1", "0x7f.1", "[not-ipv6]", "127.0.0.1::"})
    void malformedScopeHostsAreRejectedEvenIfDisabled(String host) {
        invalid(config(List.of(new ScopeEntry(false, host, "any", 0, "")), List.of(), List.of(), Mode.ALLOW));
    }

    @Test void scopeSchemePortAndEntryBounds() {
        for (ScopeEntry scope : List.of(scope("example.test", "ftp", 0, ""), scope("example.test", "any", -1, ""),
                scope("example.test", "any", 65_536, ""), scope("example.test", "any", 0, "["))) {
            invalid(config(List.of(scope), List.of(), List.of(), Mode.ALLOW));
        }
        invalid(config(Collections.nCopies(257, scope("example.test", "any", 0, "")), List.of(), List.of(), Mode.ALLOW));
    }

    @Test void idsNamesAndDisabledConditionsAreValidated() {
        Rule rule = rule("same", Mode.BLOCK, leaf(Field.METHOD, Match.EXACT, "DELETE"));
        invalid(config(List.of(rule, rule)));
        invalid(config(List.of(new Rule("bad id", "Name", true, Mode.ALLOW, rule.condition()))));
        invalid(config(List.of(new Rule("id", " ", true, Mode.ALLOW, rule.condition()))));
        invalid(config(List.of(new Rule("id", "Name\nunsafe", true, Mode.ALLOW, rule.condition()))));
        invalid(config(List.of(new Rule("id", "Name", true, null, rule.condition()))));
        invalid(config(List.of(new Rule("id", "Name", false, Mode.BLOCK, leaf(Field.BODY, Match.REGEX, "(?=delete)")))));
        List<Rule> many = new ArrayList<>();
        for (int i = 0; i < 257; i++) many.add(rule("r" + i, Mode.ALLOW, rule.condition()));
        invalid(config(many));
    }

    @Test void conditionShapeAndDepthBoundsAreStrict() {
        Condition leaf = leaf(Field.METHOD, Match.EXACT, "GET");
        for (Condition bad : List.of(
                new Condition(null, Field.METHOD, "", Match.EXACT, "GET", false, List.of()),
                new Condition(Logic.LEAF, null, "", Match.EXACT, "GET", false, List.of()),
                new Condition(Logic.LEAF, Field.METHOD, "", null, "GET", false, List.of()),
                new Condition(Logic.LEAF, Field.METHOD, "", Match.EXACT, null, false, List.of()),
                new Condition(Logic.LEAF, Field.METHOD, "", Match.EXACT, "GET", false, List.of(leaf)),
                new Condition(Logic.AND, null, "", null, "", false, List.of()),
                new Condition(Logic.OR, Field.ANY, "", Match.CONTAINS, "", false, List.of(leaf)),
                new Condition(Logic.OR, null, "", null, "", false, Collections.nCopies(65, leaf)))) {
            invalid(config(List.of(rule("shape", Mode.BLOCK, bad))));
        }
        invalid(config(List.of(new Rule("id", "Name", true, Mode.BLOCK, null))));
        Condition deep = leaf;
        for (int i = 0; i < 18; i++) deep = new Condition(Logic.AND, null, null, null, null, false, List.of(deep));
        invalid(config(List.of(rule("depth", Mode.BLOCK, deep))));
        Condition group = new Condition(Logic.OR, null, null, null, null, false, Collections.nCopies(64, leaf));
        Condition wide = new Condition(Logic.AND, null, null, null, null, false, Collections.nCopies(64, group));
        invalid(config(List.of(rule("nodes", Mode.BLOCK, wide))));
    }

    @Test void invalidSelectorsAndPointerEscapesAreRejected() {
        for (String pointer : List.of("action", "/a~2b", "/a~", "/a".repeat(33))) {
            invalid(config(List.of(rule("pointer", Mode.BLOCK, leaf(Field.JSON, pointer, Match.CONTAINS, "delete", false)))));
        }
        invalid(config(List.of(rule("name", Mode.BLOCK, leaf(Field.METHOD, "selector", Match.EXACT, "GET", false)))));
        invalid(config(List.of(rule("header", Mode.BLOCK, leaf(Field.HEADER, "bad name", Match.EXACT, "GET", false)))));
        invalid(config(List.of(rule("query", Mode.BLOCK, leaf(Field.QUERY, "q".repeat(513), Match.EXACT, "GET", false)))));
    }

    @Test void perExpressionAndAggregateCompileMemoryAreBounded() {
        invalid(config(List.of(rule("long", Mode.BLOCK, leaf(Field.BODY, Match.REGEX, "x".repeat(2_049))))));
        invalid(config(List.of(rule("long", Mode.BLOCK, leaf(Field.BODY, Match.EXACT, "x".repeat(4_097))))));
        List<Rule> rules = new ArrayList<>();
        for (int i = 0; i < 17; i++) rules.add(rule("memory-" + i, Mode.BLOCK, leaf(Field.BODY, Match.EXACT, "x".repeat(4_096))));
        invalid(config(rules));
    }

    static Stream<Limits> badLimits() {
        return Stream.of(
                new Limits(-1, 5, Map.of(), 5, 100, 30_000, 30_000, 60_000),
                new Limits(1_001, 5, Map.of(), 5, 100, 30_000, 30_000, 60_000),
                new Limits(5, -1, Map.of(), 5, 100, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 0, 100, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 101, 100, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 5, -1, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 5, 10_001, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 5, 100, 0, 30_000, 60_000),
                new Limits(5, 5, Map.of(), 5, 100, 30_000, 600_001, 60_000),
                new Limits(5, 5, Map.of(), 5, 100, 30_000, 30_000, Long.MAX_VALUE),
                new Limits(5, 5, Map.of("*.example.test", 3), 5, 100, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of("example.test", -1), 5, 100, 30_000, 30_000, 60_000),
                new Limits(5, 5, Map.of("EXAMPLE.test", 3, "example.test.", 4), 5, 100, 30_000, 30_000, 60_000));
    }

    @ParameterizedTest @MethodSource("badLimits")
    void limitsHaveHardBounds(Limits limits) {
        GuardConfig cfg = config(List.of());
        invalid(new GuardConfig(1, cfg.allowScope(), cfg.blockScope(), cfg.rules(), cfg.defaultMode(), limits));
    }
}
