package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.ui.editor.ScopeDraft.Input;
import dev.cairnguard.ui.editor.ScopeDraft.Member;
import dev.cairnguard.ui.editor.ScopeDraft.PathMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class ScopeDraftTest {
    @Test void portsAcceptOnlyAsciiEdgeFormattingAndReturnImmutableNumericChoices() {
        List<Integer> ports = ScopeDraft.parsePorts(" 080\t, 443 ,65535");
        assertEquals(List.of(80, 443, 65535), ports);
        assertThrows(UnsupportedOperationException.class, () -> ports.add(8080));
    }

    @ParameterizedTest @ValueSource(strings = {"", " ", ",", "80,", ",80", "80,,443", "0", "65536", "999999999", "-1", "+80", "80-443", "80.0", "80;443", "80 443", "80\n,443", "80\r", "８０", "٨٠", "\u00a080", "80\u2003", "80,080", "443,443"})
    void invalidPortTokenRejectsTheWholeListWithoutEchoOrImplicitAll(String text) {
        FormValidationException error = assertThrows(FormValidationException.class, () -> ScopeDraft.parsePorts(text));
        assertNull(error.getCause());
        assertThrows(FormValidationException.class, () -> new ScopeDraft(List.of(), List.of()).product(input(text, "/api")));
    }

    @Test void pathsPreserveLiteralCommaCasePercentUnicodeAndExactlyOneFinalLineEnding() {
        for (String ending : List.of("", "\n", "\r\n")) {
            assertEquals(List.of("/API,one", "/%61pi", "/한글+😀"), ScopeDraft.parsePaths("/API,one\r\n/%61pi\n/한글+😀" + ending));
        }
        assertEquals(List.of("/api", "/API"), ScopeDraft.parsePaths("/api\n/API"));
    }

    @ParameterizedTest @ValueSource(strings = {"", "\n", "\r\n", "/a\n\n/b", "/a\n\n", "/a\r", "/a\rb", " /a", "/a ", "/a\t", "/a\u0001", "/a\n/a", "relative", "/a/../b", "/a/./b", "/a?x", "/a#x", "/a;b", "/a\\b", "/bad%ZZ"})
    void invalidPathLineNeverTrimsNormalizesDeduplicatesOrMeansAll(String text) {
        assertThrows(FormValidationException.class, () -> ScopeDraft.parsePaths(text));
        assertThrows(FormValidationException.class, () -> new ScopeDraft(List.of(), List.of()).product(input("80", text)));
    }

    @Test void productUsesFourIndependentExactTuplesWithIndependentScheme() {
        ScopeDraft draft = new ScopeDraft(List.of(), List.of());
        List<ScopeEntry> section = draft.section(draft.product(input("80,443", "/api\n/manager")));
        assertEquals(List.of(entry(80, "/api"), entry(80, "/manager"), entry(443, "/api"), entry(443, "/manager")), section);
        GuardConfig policy = policy(section);
        for (int port : List.of(80, 443)) for (String path : List.of("/api", "/manager")) assertEquals(Mode.ALLOW, evaluate(policy, port, path));
        for (String path : List.of("/admin", "/apix", "/api/", "/api/child")) assertEquals(Mode.BLOCK, evaluate(policy, 80, path));
        assertEquals(Mode.BLOCK, evaluate(policy, 8080, "/api"));
        Input any = new Input(true, "example.test", "any", false, "80,443", PathMode.EXACT, "/api", "");
        GuardConfig either = policy(draft.section(draft.product(any)));
        for (int port : List.of(80, 443)) for (boolean secure : List.of(false, true))
            assertEquals(Mode.ALLOW, new PolicyEngine().evaluate(either, new RequestData("GET", "https://display.invalid/", "example.test", port, secure, List.of(), new byte[0], true, true, "/api")).mode());
    }

    @Test void allAndPrefixAndOpaqueRegexAreExplicitNotEmptyInputFallbacks() {
        ScopeDraft draft = new ScopeDraft(List.of(), List.of());
        for (Input input : List.of(new Input(true, "example.test", "https", true, "", PathMode.ALL, "", ""),
                new Input(true, "example.test", "https", true, "", PathMode.REGEX, "", "(?i)/line\n\r\t"))) {
            List<ScopeEntry> rows = draft.section(draft.product(input));
            assertEquals(1, rows.size()); assertEquals(0, rows.getFirst().port());
            assertEquals(input.pathMode() == PathMode.ALL ? "" : input.regexText(), rows.getFirst().pathRegex());
        }
        Input prefix = new Input(true, "example.test", "https", false, "80,443", PathMode.PREFIX, "/api\n/manager/", "");
        GuardConfig policy = policy(draft.section(draft.product(prefix)));
        assertEquals(Mode.ALLOW, evaluate(policy, 80, "/api/child"));
        assertEquals(Mode.ALLOW, evaluate(policy, 443, "/manager/child"));
        assertEquals(Mode.BLOCK, evaluate(policy, 80, "/apix"));
        assertEquals(Mode.BLOCK, evaluate(policy, 443, "/manager"));
        assertThrows(FormValidationException.class, () -> draft.product(new Input(true, "example.test", "httpſ", false, "80", PathMode.ALL, "", "")));
        assertThrows(FormValidationException.class, () -> draft.product(new Input(true, "example.test", "https", true, "", PathMode.REGEX, "", "")));
    }

    @Test void compactProofRequiresExactRectangleOrderAndRawQualifiersWithoutDuplicateLoss() {
        List<ScopeEntry> rectangle = List.of(entry(80, "/api"), entry(80, "/manager"), entry(443, "/api"), entry(443, "/manager"));
        ScopeDraft complete = new ScopeDraft(rectangle, List.of(3, 0, 2, 1));
        Input fields = complete.compactInput().orElseThrow();
        assertEquals("80,443", fields.portText()); assertEquals("/api\n/manager", fields.pathText());
        assertEquals(rectangle, complete.section(complete.product(fields)));
        List<List<ScopeEntry>> irregular = List.of(List.of(entry(80, "/api"), entry(443, "/manager")),
                List.of(entry(80, "/api"), entry(80, "/api")),
                List.of(rectangle.get(0), rectangle.get(2), rectangle.get(1), rectangle.get(3)),
                List.of(entry(0, "/api"), entry(80, "/api")),
                List.of(entry(80, "/api"), new ScopeEntry(false, "example.test", "https", 443, exact("/api"))),
                List.of(entry(80, "/api"), new ScopeEntry(true, "example.test", "HTTPS", 443, exact("/api"))),
                List.of(new ScopeEntry(true, "example.test", "https", 80, "/api.*"), new ScopeEntry(true, "example.test", "https", 443, "/api.*")));
        for (List<ScopeEntry> rows : irregular) {
            ScopeDraft draft = new ScopeDraft(rows, IntStream.range(0, rows.size()).boxed().toList());
            assertTrue(draft.compactInput().isEmpty(), rows.toString());
            assertEquals(rows, draft.section(draft.members()));
            assertThrows(FormValidationException.class, () -> draft.product(input("80,443", "/api\n/manager")));
        }
    }

    @Test void occurrenceReplacementPreservesInterleavingAndOnlyAppendsExplicitNewCells() {
        ScopeEntry unrelated = new ScopeEntry(false, "*.Other.test.", "AnY", 0, "(?i)/line\n\r\t");
        List<ScopeEntry> original = List.of(entry(80, "/api"), unrelated, entry(80, "/manager"), entry(443, "/api"), entry(443, "/manager"), unrelated);
        ScopeDraft draft = new ScopeDraft(original, List.of(0, 2, 3, 4));
        Input initial = draft.compactInput().orElseThrow();
        assertEquals(original, draft.section(draft.product(initial)));
        Input changed = new Input(false, "Changed.test.", "HTTPS", false, "80,443", PathMode.EXACT, "/api\n/new", "");
        List<Member> proposed = draft.product(changed);
        assertEquals(List.of(0, -1, 3, -1), proposed.stream().map(Member::sourceIndex).toList());
        List<ScopeEntry> revised = draft.section(proposed);
        assertEquals(List.of(proposed.get(0).entry(), unrelated, proposed.get(2).entry(), unrelated, proposed.get(1).entry(), proposed.get(3).entry()), revised);
        assertEquals(original, draft.section(draft.members()));
        assertThrows(UnsupportedOperationException.class, () -> revised.add(entry(80, "/bad")));
    }

    @Test void memberEditsRetainOccurrenceIdentityAndCannotBecomeAProduct() {
        List<ScopeEntry> old = List.of(entry(80, "/api"), entry(443, "/manager"));
        ScopeDraft draft = new ScopeDraft(old, List.of(0, 1));
        Member changed = draft.member(1, input("443", "/manager2"));
        assertEquals(1, changed.sourceIndex());
        assertEquals(List.of(old.getFirst(), entry(443, "/manager2")), draft.section(List.of(draft.members().getFirst(), changed)));
        assertThrows(FormValidationException.class, () -> draft.member(1, input("80,443", "/api")));
        assertThrows(FormValidationException.class, () -> draft.member(1, input("443", "/api\n/manager")));
        assertThrows(FormValidationException.class, () -> draft.section(List.of(changed, changed)));
        assertThrows(FormValidationException.class, () -> draft.section(List.of(new Member(2, old.getFirst()))));
        assertThrows(FormValidationException.class, () -> draft.section(List.of(new Member(-2, old.getFirst()))));
        assertThrows(FormValidationException.class, () -> new ScopeDraft(old, List.of(0, 0)));
        assertThrows(FormValidationException.class, () -> new ScopeDraft(old, List.of(2)));
    }

    @Test void singleLegacyValuesAndDuplicateOccurrencesStayLossless() {
        for (String host : List.of("*.Example.test.", "bücher.example", "[2001:db8::1]")) for (String expression : List.of("", ".*", "(?i)/line\n\r\t", "\\A\\Q/a\\E.*\\Q/b\\E\\z")) {
            ScopeEntry old = new ScopeEntry(false, host, "AnY", 0, expression);
            ScopeDraft draft = new ScopeDraft(List.of(old), List.of(0));
            assertEquals(List.of(old), draft.section(draft.product(draft.compactInput().orElseThrow())));
            ScopeDraft duplicates = new ScopeDraft(List.of(old, old), List.of(0, 1));
            assertEquals(List.of(old, old), duplicates.section(duplicates.members()));
        }
        ArrayList<ScopeEntry> original = new ArrayList<>(List.of(entry(80, "/api")));
        ArrayList<Integer> selected = new ArrayList<>(List.of(0));
        ScopeDraft copied = new ScopeDraft(original, selected);
        original.clear(); selected.clear();
        assertEquals(List.of(entry(80, "/api")), copied.section(copied.members()));
    }

    @Test void sectionCapacityAndPerPatternAndAggregateBudgetsRemainEnforced() {
        String ports = String.join(",", IntStream.rangeClosed(1, 16).mapToObj(Integer::toString).toList());
        String paths = String.join("\n", IntStream.range(0, 16).mapToObj(i -> "/p" + i).toList());
        ScopeDraft empty = new ScopeDraft(List.of(), List.of());
        assertEquals(256, empty.section(empty.product(input(ports, paths))).size());
        ScopeDraft retained = new ScopeDraft(List.of(entry(443, "/retained")), List.of());
        assertThrows(FormValidationException.class, () -> retained.product(input(ports, paths)));
        String many = String.join(",", IntStream.rangeClosed(1, 256).mapToObj(Integer::toString).toList());
        assertThrows(FormValidationException.class, () -> empty.product(input(many, paths)));
        assertThrows(FormValidationException.class, () -> empty.product(input("80", "/" + "a".repeat(2047))));
        assertThrows(FormValidationException.class, () -> empty.product(new Input(true, "example.test", "https", false, "80", PathMode.REGEX, "", "(?:abcde){1000}")));
        String expensive = String.join("\n", IntStream.range(0, 64).mapToObj(i -> "/" + i + "a".repeat(590)).toList());
        List<ScopeEntry> duplicatedPatterns = empty.section(empty.product(input("80,443", expensive)));
        assertThrows(IllegalArgumentException.class, () -> new PolicyEngine().validate(policy(duplicatedPatterns)));
    }

    @Test void separateEncodedAndDecodedPredicatesNeverBecomeOneAllowAlternation() {
        List<ScopeEntry> old = List.of(entry(443, "/%61pi"), entry(443, "/api"));
        ScopeDraft draft = new ScopeDraft(old, List.of(0, 1));
        List<ScopeEntry> result = draft.section(draft.product(draft.compactInput().orElseThrow()));
        assertEquals(old, result);
        assertEquals(Mode.BLOCK, evaluate(policy(result), 443, "/%61pi"));
        assertEquals(Mode.ALLOW, evaluate(policy(result), 443, "/api"));
    }

    private static Input input(String ports, String paths) { return new Input(true, "example.test", "https", false, ports, PathMode.EXACT, paths, ""); }
    private static String exact(String path) { return "\\A\\Q" + path + "\\E\\z"; }
    private static ScopeEntry entry(int port, String path) { return new ScopeEntry(true, "example.test", "https", port, exact(path)); }
    private static GuardConfig policy(List<ScopeEntry> scope) { return new GuardConfig(2, scope, List.of(), List.of(), Mode.ALLOW, GuardConfig.defaults().limits()); }
    private static Mode evaluate(GuardConfig policy, int port, String path) {
        return new PolicyEngine().evaluate(policy, new RequestData("GET", "https://display.invalid/", "example.test", port, true, List.of(), new byte[0], true, true, path)).mode();
    }
}
