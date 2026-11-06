package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.evidence.TrafficEntry.Message;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static dev.cairnguard.ui.TrafficSearch.Location.*;
import static dev.cairnguard.ui.TrafficSearch.MatchMode.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.swing.SwingUtilities;
import static org.junit.jupiter.api.Assertions.*;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;

class TrafficSearchTest {
    static Message message(String body, String encoding) { return new Message(List.of(new Header("Duplicate", "one"), new Header("Duplicate", "TWO.[x]")), body, "", false, false, true, encoding); }
    @Test void fullLiteralHeadersUnicodeTextHexAndUnavailable() {
        Message text = message("한글 AbC.[Literal] [REDACTED]", "UTF8_TEXT");
        for (String term : List.of("한글", "abc.[literal]", "duplicate: two.[X]", "[redacted]", "e: T")) assertTrue(contains(text, term, () -> false), term);
        assertFalse(contains(text, "AbC.*", () -> false));
        assertFalse(contains(text, "one\nDuplicate", () -> false));
        assertTrue(contains(message("01abcdef", "HEX"), "1AbC", () -> false));
        assertFalse(contains(message("736563726574", "HEX"), "secret", () -> false));
        assertFalse(contains(message("body", "UNAVAILABLE"), "body", () -> false));
        assertTrue(contains(message("", "UNAVAILABLE"), "TWO.[x]", () -> false));
        assertTrue(contains(message("a".repeat(2_200_000) + "FULL-END", "UTF8_TEXT"), "full-end", () -> false));
    }
    @Test void cancellationCountsInnerComparisonWorkAndHeaders() {
        AtomicInteger checks = new AtomicInteger();
        assertThrows(CancellationException.class, () -> contains(message("a".repeat(1_000_000), "UTF8_TEXT"), "a".repeat(500_000) + "b", () -> checks.incrementAndGet() == 4));
        assertEquals(4, checks.get());
        Message header = new Message(List.of(new Header("X", "a".repeat(1_000_000))), "", "", false, false, true, "EMPTY");
        checks.set(0);
        assertThrows(CancellationException.class, () -> contains(header, "a".repeat(500_000) + "b", () -> checks.incrementAndGet() == 4));
    }
    @Test void pumpReplacesOnlyAfterActualExitAndKeepsOnlyLatestInputAndResult() throws Exception {
        TrafficSearch.Pump pump = new TrafficSearch.Pump("cairn-pump-test");
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1), exited = new CountDownLatch(1), delivered = new CountDownLatch(1);
        AtomicInteger runs = new AtomicInteger(); AtomicReference<Object> value = new AtomicReference<>();
        try {
            pump.submit(cancelled -> { started.countDown(); try { while (release.getCount() != 0) try { release.await(); } catch (InterruptedException ignored) {} return "stale"; } finally { exited.countDown(); } }, r -> fail("stale publication"));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            for (int i = 0; i < 100; i++) { final int n = i; pump.submit(c -> { assertEquals(0, exited.getCount()); runs.incrementAndGet(); return n; }, r -> { assertTrue(SwingUtilities.isEventDispatchThread()); value.set(r.value()); delivered.countDown(); }); }
            assertEquals(0, runs.get()); release.countDown(); assertTrue(delivered.await(5, TimeUnit.SECONDS));
            assertEquals(1, runs.get()); assertEquals(99, value.get());
        } finally { release.countDown(); pump.close(); assertTrue(pump.awaitExit(5000)); assertFalse(pump.retainsPending()); }
    }
    @Test void pumpFailureIsFixedAndCloseDropsPublication() throws Exception {
        TrafficSearch.Pump pump = new TrafficSearch.Pump("cairn-failure-test"); CountDownLatch got = new CountDownLatch(1);
        pump.submit(c -> { throw new IllegalStateException("synthetic-plaintext-must-not-escape"); }, r -> { assertTrue(r.failed()); assertNull(r.value()); got.countDown(); });
        assertTrue(got.await(5, TimeUnit.SECONDS)); pump.close(); assertTrue(pump.awaitExit(5000));
        pump.submit(c -> { fail("closed processing"); return null; }, r -> fail("closed publication")); assertFalse(pump.retainsPending());
    }
    @Test void identityCacheReusesUnchangedMessagesAndInvalidatesEqualReplacement() throws Exception {
        TrafficSearch.Session session = edt(TrafficSearch.Session::new);
        Message one = message("hit", "UTF8_TEXT"), equal = message("hit", "UTF8_TEXT"); assertEquals(one, equal); assertNotSame(one, equal);
        TrafficSearch.Subject first = subject(one, Message.EMPTY, List.of("metadata")), replacement = subject(equal, Message.EMPTY, List.of("metadata"));
        CountDownLatch done = new CountDownLatch(1);
        edt(() -> { session.update(query("hit", ALL, LITERAL), List.of(first), done::countDown); return null; }); assertTrue(done.await(5, TimeUnit.SECONDS));
        edt(() -> {
            assertTrue(session.hit(first)); assertFalse(session.hit(replacement));
            session.update(query("hit", ALL, LITERAL), List.of(first), () -> fail("unchanged body rescanned")); assertFalse(session.pending());
            session.update(query("hit", ALL, LITERAL), List.of(replacement), () -> {}); assertFalse(session.hit(first)); assertTrue(session.pending());
            session.clear(); assertFalse(session.hit(replacement)); assertFalse(session.pending()); session.close(); return null;
        }); assertTrue(session.awaitExit(5000));
    }

    static TrafficSearch.CompiledQuery query(String text, TrafficSearch.Location location, TrafficSearch.MatchMode mode) {
        return assertInstanceOf(TrafficSearch.CompiledQuery.class, TrafficSearch.compile(new TrafficSearch.Query(text, location, mode)));
    }
    static boolean contains(Message message, String text, java.util.function.BooleanSupplier cancelled) {
        return TrafficSearch.contains(message, query(text, ALL, LITERAL), cancelled);
    }
    static TrafficSearch.Subject subject(Message request, Message response, List<String> metadata) {
        return new TrafficSearch.Subject(new TrafficEntry("e", "p", "Synthetic", "2026-01-01T00:00:00Z", "POST", "https://example.test/plain",
                "ALLOW", "FORWARDED", "DEFAULT_ALLOW", 200, List.of(), 7, false, request, response, false, ""), true, metadata);
    }
    static void update(TrafficSearch.Session session, TrafficSearch.CompiledQuery query, List<TrafficSearch.Subject> subjects) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        boolean pending = edt(() -> { session.update(query, subjects, done::countDown); return session.pending(); });
        if (pending) assertTrue(done.await(5, TimeUnit.SECONDS));
        edt(() -> { assertFalse(session.pending()); assertFalse(session.failed()); return null; });
    }
    @Test void sixLocationsAndBothModesKeepRequestResponseAndMetadataSeparate() throws Exception {
        var subject = subject(new Message(List.of(new Header("X-Request", "request-header")), "request-body", "text/plain", false, false, true, "UTF8_TEXT"),
                new Message(List.of(new Header("X-Response", "response-header")), "response-body", "text/plain", false, false, true, "UTF8_TEXT"), List.of("metadata-only"));
        String[] terms = {"metadata-only", "request-header", "request-body", "response-header", "response-body"};
        var session = edt(TrafficSearch.Session::new);
        try {
            for (var mode : TrafficSearch.MatchMode.values()) for (var location : TrafficSearch.Location.values()) for (int i = 0; i < terms.length; i++) {
                update(session, query(terms[i], location, mode), List.of(subject));
                boolean expected = location == ALL || location.ordinal() == i + 1;
                assertEquals(expected, edt(() -> session.hit(subject)), location + " " + mode + " " + terms[i]);
            }
            for (var location : TrafficSearch.Location.values()) for (var mode : TrafficSearch.MatchMode.values()) {
                edt(() -> { session.update(query("", location, mode), List.of(subject), () -> fail("empty query ran"));
                    assertTrue(session.hit(subject)); assertFalse(session.pending()); return null; });
            }
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }
    @Test void re2FindFlagsUnicodeHeadersAndFullTailsDoNotJoinFields() {
        Message text = new Message(List.of(new Header("Duplicate", "one"), new Header("Duplicate", "TWO.[x]")), "start\n한글 ÅΣ AbC.[Literal] [REDACTED]\nend", "text/plain", false, false, true, "UTF8_TEXT");
        for (String pattern : List.of("한글", "åσ", "AbC\\.\\[Literal\\]", "(?s)start.*end", "(?m)^end$", "absent|duplicate: two", "(?-i:AbC)")) {
            assertTrue(TrafficSearch.contains(text, query(pattern, ALL, RE2), () -> false), pattern);
        }
        assertFalse(TrafficSearch.contains(text, query("(?-i:abc)", ALL, RE2), () -> false));
        for (String pattern : List.of("(?s)one.*Duplicate", "(?s)TWO.*start")) assertFalse(TrafficSearch.contains(text, query(pattern, ALL, RE2), () -> false), pattern);
        assertTrue(TrafficSearch.contains(message("a".repeat(2_200_000) + "FULL-END", "UTF8_TEXT"), query("FULL-END$", REQUEST_BODY, RE2), () -> false));
        Message giantHeader = new Message(List.of(new Header("X", "a".repeat(2_200_000) + "HEADER-END")), "", "", false, false, true, "EMPTY");
        assertTrue(TrafficSearch.contains(giantHeader, query("HEADER-END$", RESPONSE_HEADERS, RE2), () -> false));
    }
    @Test void bodyEligibilityHexOddPositionsPartialAndResponseOnlyStayHonest() throws Exception {
        for (String encoding : List.of("EMPTY", "UNAVAILABLE")) {
            assertFalse(TrafficSearch.contains(message("placeholder", encoding), query("^", REQUEST_BODY, RE2), () -> false));
        }
        assertFalse(TrafficSearch.contains(message("", "UTF8_TEXT"), query("^", REQUEST_BODY, RE2), () -> false));
        assertFalse(TrafficSearch.contains(Message.EMPTY, query("^", REQUEST_BODY, RE2), () -> false));
        assertTrue(TrafficSearch.contains(message("", "UNAVAILABLE"), query("Duplicate", REQUEST_HEADERS, RE2), () -> false));
        assertTrue(TrafficSearch.contains(message("01abcdef", "HEX"), query("1aBc", RESPONSE_BODY, RE2), () -> false));
        assertFalse(TrafficSearch.contains(message("736563726574", "HEX"), query("secret", RESPONSE_BODY, RE2), () -> false));
        Message partial = new Message(List.of(), "known-partial", "text/plain", true, true, true, "UTF8_TEXT");
        assertTrue(TrafficSearch.contains(partial, query("partial$", REQUEST_BODY, RE2), () -> false));
        var responseOnly = subject(Message.EMPTY, message("response-only", "UTF8_TEXT"), List.of(""));
        var session = edt(TrafficSearch.Session::new);
        try {
            update(session, query("^", REQUEST_BODY, RE2), List.of(responseOnly)); assertFalse(edt(() -> session.hit(responseOnly)));
            update(session, query("^", RESPONSE_BODY, RE2), List.of(responseOnly)); assertTrue(edt(() -> session.hit(responseOnly)));
            update(session, query("^$", METADATA, RE2), List.of(responseOnly)); assertTrue(edt(() -> session.hit(responseOnly)), "an existing empty metadata value is eligible");
            var unavailable = new TrafficSearch.Subject(responseOnly.entry(), false, List.of("original unavailable"));
            update(session, query("response-only", RESPONSE_BODY, RE2), List.of(unavailable)); assertFalse(edt(() -> session.hit(unavailable)));
            update(session, query("(?s)one.*two", METADATA, RE2), List.of(new TrafficSearch.Subject(responseOnly.entry(), true, List.of("one", "two"))));
            assertFalse(edt(() -> session.hit(new TrafficSearch.Subject(responseOnly.entry(), true, List.of("one", "two")))));
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }
    @Test void compilerUsesFixedInvalidCategoriesAndPreservesExactWholeQuery() {
        for (String pattern : List.of("[", "(", "(?=unsupported)", "(a)\\1")) {
            assertSame(TrafficSearch.Invalid.BAD_RE2, TrafficSearch.compile(new TrafficSearch.Query(pattern, ALL, RE2)), pattern);
        }
        assertSame(TrafficSearch.Invalid.TOO_LONG, TrafficSearch.compile(new TrafficSearch.Query("a".repeat(4097), ALL, RE2)));
        assertSame(TrafficSearch.Invalid.TOO_COMPLEX, TrafficSearch.compile(new TrafficSearch.Query("(abc){1000}", ALL, RE2)));
        String text = " .* 한글 "; var key = new TrafficSearch.Query(text, REQUEST_BODY, LITERAL);
        var compiled = assertInstanceOf(TrafficSearch.CompiledQuery.class, TrafficSearch.compile(key)); assertEquals(key, compiled.key()); assertEquals(text, compiled.key().text());
        assertTrue(TrafficSearch.contains(message("before .* 한글 after", "UTF8_TEXT"), compiled, () -> false));
        assertFalse(TrafficSearch.contains(message(".*한글", "UTF8_TEXT"), compiled, () -> false));
        assertInstanceOf(TrafficSearch.CompiledQuery.class, TrafficSearch.compile(new TrafficSearch.Query("a".repeat(500_001), ALL, LITERAL)), "pure literal matching retains large synthetic needle support");
    }
    @Test void equalCompiledKeysReuseWhileSameTextModeAndLocationChangesInvalidate() throws Exception {
        var subject = subject(new Message(List.of(new Header("X", "a.*b")), "axxb", "text/plain", false, false, true, "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var session = edt(TrafficSearch.Session::new);
        try {
            update(session, query("a.*b", REQUEST_BODY, LITERAL), List.of(subject)); assertFalse(edt(() -> session.hit(subject)));
            edt(() -> { session.update(query("a.*b", REQUEST_BODY, LITERAL), List.of(subject), () -> fail("equal key rescanned")); assertFalse(session.pending()); return null; });
            update(session, query("a.*b", REQUEST_BODY, RE2), List.of(subject)); assertTrue(edt(() -> session.hit(subject)));
            update(session, query("a.*b", RESPONSE_BODY, RE2), List.of(subject)); assertFalse(edt(() -> session.hit(subject)));
            update(session, query("a.*b", REQUEST_HEADERS, LITERAL), List.of(subject)); assertTrue(edt(() -> session.hit(subject)));
            update(session, query("A.*B", REQUEST_HEADERS, LITERAL), List.of(subject)); assertTrue(edt(() -> session.hit(subject)));
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }
    @Test void advancedMetadataCacheUsesEntryIdentityAndExactAvailabilitySnapshot() throws Exception {
        List<String> mutable = new ArrayList<>(List.of("hit"));
        var original = subject(Message.EMPTY, Message.EMPTY, mutable); mutable.set(0, "not retained"); assertEquals(List.of("hit"), original.metadata());
        var session = edt(TrafficSearch.Session::new);
        try {
            update(session, query("hit", METADATA, RE2), List.of(original)); assertTrue(edt(() -> session.hit(original)));
            var equivalent = new TrafficSearch.Subject(original.entry(), true, new ArrayList<>(List.of("hit")));
            edt(() -> { session.update(query("hit", METADATA, RE2), List.of(equivalent), () -> fail("equivalent snapshot rescanned")); assertFalse(session.pending()); assertTrue(session.hit(equivalent)); return null; });
            var changed = new TrafficSearch.Subject(original.entry(), true, List.of("miss"));
            edt(() -> { assertFalse(session.hit(changed), "changed metadata cannot reuse an old hit"); return null; });
            update(session, query("hit", METADATA, RE2), List.of(changed)); assertFalse(edt(() -> session.hit(changed)));
            var unavailable = new TrafficSearch.Subject(original.entry(), false, List.of("miss"));
            edt(() -> { session.update(query("hit", METADATA, RE2), List.of(unavailable), () -> {}); assertTrue(session.pending(), "availability is part of snapshot identity"); return null; });
            update(session, query("hit", METADATA, RE2), List.of(original));
            var equalEntry = subject(Message.EMPTY, Message.EMPTY, List.of("hit")); assertEquals(original.entry(), equalEntry.entry()); assertNotSame(original.entry(), equalEntry.entry());
            edt(() -> { session.update(query("hit", METADATA, RE2), List.of(equalEntry), () -> {}); assertFalse(session.hit(original)); assertTrue(session.pending()); session.clear(); assertFalse(session.pending()); assertFalse(session.hit(equalEntry)); return null; });
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }
    @Test void pinnedRe2CancelsInsideGiantBodyHeaderAndMetadataPrefixScans() throws Exception {
        for (String pattern : List.of("not-present", "a+b", "^a+b$")) {
            var bodyQuery = query(pattern, REQUEST_BODY, RE2); AtomicInteger checks = new AtomicInteger();
            assertThrows(CancellationException.class, () -> TrafficSearch.contains(message("a".repeat(2_200_000), "UTF8_TEXT"), bodyQuery, () -> checks.incrementAndGet() == 4));
            assertEquals(4, checks.get(), pattern);
            checks.set(0);
            Message header = new Message(List.of(new Header("X", "a".repeat(2_200_000))), "", "", false, false, true, "EMPTY");
            String headerPattern = pattern.equals("^a+b$") ? "^X: a+b$" : pattern;
            assertThrows(CancellationException.class, () -> TrafficSearch.contains(header, query(headerPattern, REQUEST_HEADERS, RE2), () -> checks.incrementAndGet() == 4), headerPattern); assertEquals(4, checks.get());
            checks.set(0);
            var metadata = subject(Message.EMPTY, Message.EMPTY, List.of("a".repeat(2_200_000)));
            var method = TrafficSearch.CompiledQuery.class.getDeclaredMethod("metadata", TrafficSearch.Subject.class, TrafficSearch.Work.class); method.setAccessible(true);
            var compiled = query(pattern, METADATA, RE2);
            var error = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> method.invoke(compiled, metadata, new TrafficSearch.Work(() -> checks.incrementAndGet() == 4)));
            assertInstanceOf(CancellationException.class, error.getCause()); assertEquals(4, checks.get());
        }
    }
    @Test void fieldSubsequencesAreBoundedZeroCopyViewsWithCancellation() throws Exception {
        var type = Class.forName("dev.cairnguard.ui.TrafficSearch$Field");
        var constructor = type.getDeclaredConstructor(Header.class, TrafficSearch.Work.class); constructor.setAccessible(true);
        CharSequence line = (CharSequence) constructor.newInstance(new Header("X-Dup", "AbC"), new TrafficSearch.Work(() -> false));
        assertFalse(line instanceof String); assertEquals("X-Dup: AbC", line.toString());
        CharSequence body = line.subSequence(5, 10).subSequence(2, 5); assertEquals("AbC", body.toString());
        assertTrue(com.google.re2j.Pattern.compile("^AbC$").matcher(body).find());
        assertThrows(IndexOutOfBoundsException.class, () -> line.subSequence(-1, 2)); assertThrows(IndexOutOfBoundsException.class, () -> body.charAt(3));
        AtomicBoolean cancel = new AtomicBoolean();
        CharSequence cancellable = (CharSequence) constructor.newInstance(new Header("X", "a".repeat(8192)), new TrafficSearch.Work(cancel::get));
        CharSequence slice = cancellable.subSequence(3, 8195); cancel.set(true);
        assertThrows(CancellationException.class, () -> com.google.re2j.Pattern.compile("missing").matcher(slice).find());
    }

    @Test void subjectPendingDistinguishesSettledHitsAndMissesFromUnrelatedSelectedFieldWork() throws Exception {
        var session = edt(TrafficSearch.Session::new);
        var miss = subject(message("settled-miss", "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var hit = subject(message("hit", "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var unresolved = subject(message("new-hit", "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var retired = subject(message("retired-hit", "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var key = query("hit", REQUEST_BODY, RE2);
        try {
            update(session, key, List.of(miss, hit));
            edt(() -> {
                assertFalse(session.hit(miss)); assertTrue(session.hit(hit));
                session.update(key, List.of(miss, hit, unresolved), () -> {});
                assertTrue(session.pending()); assertFalse(session.pending(miss)); assertFalse(session.pending(hit));
                assertTrue(session.pending(unresolved)); assertFalse(session.pending(retired));
                assertFalse(session.pending(new TrafficSearch.Subject(unresolved.entry(), false, unresolved.metadata())));
                session.update(query("hit", RESPONSE_BODY, RE2), List.of(unresolved), () -> {});
                assertTrue(session.pending(unresolved), "only the newly selected response identity is unresolved");
                session.clear(); assertFalse(session.pending(unresolved)); assertFalse(session.pending()); return null;
            });
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }

    @Test void subjectPendingRequiresTheCurrentAdvancedMetadataSnapshotAndResetsWithTheQuery() throws Exception {
        var session = edt(TrafficSearch.Session::new);
        var original = subject(Message.EMPTY, Message.EMPTY, List.of("hit"));
        var changed = new TrafficSearch.Subject(original.entry(), true, List.of("miss"));
        var unavailable = new TrafficSearch.Subject(original.entry(), false, List.of("miss"));
        var replacement = subject(Message.EMPTY, Message.EMPTY, List.of("hit"));
        try {
            update(session, query("hit", METADATA, RE2), List.of(original));
            edt(() -> {
                assertFalse(session.pending(original)); assertFalse(session.pending(changed));
                session.update(query("hit", METADATA, RE2), List.of(changed), () -> {});
                assertTrue(session.pending(changed)); assertFalse(session.pending(original)); assertFalse(session.pending(unavailable));
                session.update(query("hit", METADATA, RE2), List.of(unavailable), () -> {});
                assertTrue(session.pending(unavailable), "retained metadata remains inspectable without raw originals");
                assertFalse(session.pending(changed));
                session.update(query("hit", METADATA, RE2), List.of(replacement), () -> {});
                assertTrue(session.pending(replacement)); assertFalse(session.pending(original)); assertFalse(session.pending(unavailable));
                session.update(query("hit", METADATA, LITERAL), List.of(replacement), () -> fail("literal metadata ran a worker"));
                assertTrue(session.hit(replacement)); assertFalse(session.pending(replacement));
                session.update(query("", ALL, RE2), List.of(replacement), () -> fail("empty query ran a worker"));
                assertFalse(session.pending(replacement));
                session.close(); assertFalse(session.pending(replacement)); return null;
            });
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }

    @Test void failedSubjectIsNotPendingAndTheSameFailedQueryDoesNotRetry() throws Exception {
        var session = edt(TrafficSearch.Session::new);
        var subject = subject(message("hit", "UTF8_TEXT"), Message.EMPTY, List.of("metadata"));
        var key = query("hit", REQUEST_BODY, RE2);
        com.google.re2j.Pattern broken = org.mockito.Mockito.mock(com.google.re2j.Pattern.class);
        org.mockito.Mockito.when(broken.matcher(org.mockito.ArgumentMatchers.any(CharSequence.class))).thenThrow(new IllegalStateException("synthetic-search-failure"));
        var pattern = TrafficSearch.CompiledQuery.class.getDeclaredField("pattern"); pattern.setAccessible(true); pattern.set(key, broken);
        CountDownLatch done = new CountDownLatch(1);
        try {
            edt(() -> { session.update(key, List.of(subject), done::countDown); assertTrue(session.pending(subject)); return null; });
            assertTrue(done.await(5, TimeUnit.SECONDS));
            edt(() -> {
                assertTrue(session.failed()); assertFalse(session.pending(subject)); assertFalse(session.pending()); assertFalse(session.hit(subject));
                session.update(key, List.of(subject), () -> fail("failed query retried")); assertFalse(session.pending(subject)); return null;
            });
            org.mockito.Mockito.verify(broken, org.mockito.Mockito.times(1)).matcher(org.mockito.ArgumentMatchers.any(CharSequence.class));
        } finally { edt(() -> { session.close(); return null; }); assertTrue(session.awaitExit(5000)); }
    }
}
