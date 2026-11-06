package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.ParameterizedTest;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RawTrafficStoreTest {
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());
    private static RequestData request(List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        return new RequestData("POST", "https://fixture.test/actual?echo=synthetic-auth-123456", "fixture.test", 443, true,
                headers, body, headersComplete, bodyComplete);
    }
    private static RequestData empty() { return request(List.of(), new byte[0], true, true); }
    private static long count(EvidenceStore store, String key) { return ((Number) store.stats().get(key)).longValue(); }

    @Test void humanLocalCopiesAndSerializedEvidenceAreBothOriginalAndPreserveTamperedHost() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request(List.of(new Header("Host", "synthetic.invalid"),
                new Header("Authorization", "Bearer synthetic-auth-123456"), new Header("Cookie", "sid=synthetic-cookie-345678"),
                new Header("X-Broker-Grant", "synthetic-grant-567890"), new Header("X-Cairn-Intent", "synthetic-auth-123456"),
                new Header("X-Cairn-Run", "synthetic-grant-567890"), new Header("Content-Type", "application/json")),
                "{\"echo\":\"synthetic-auth-123456\"}".getBytes(StandardCharsets.UTF_8), true, true), ALLOW, 1);
        store.response(id, 200, List.of(new Header("X-Broker-Grant", "synthetic-response-grant-789012"),
                new Header("Content-Type", "application/json")), "{\"echo\":\"synthetic-response-grant-789012\"}".getBytes(StandardCharsets.UTF_8));
        String ui = store.rawRequest(id) + store.rawResponse(id) + store.rawUrl(id) + store.rawCaptureInfo(id);
        for (String secret : List.of("synthetic-auth-123456", "synthetic-cookie-345678", "synthetic-grant-567890", "synthetic-response-grant-789012")) {
            assertTrue(ui.contains(secret));
            assertTrue(Json.write(store.snapshot()).contains(secret));
            assertTrue(store.exportJson(store.snapshot()).contains(secret));
            assertTrue(store.exportHar(store.snapshot()).contains(secret));
            assertFalse(Json.write(store.stats()).contains(secret), "counters stay payload-free");
        }
        assertTrue(store.rawRequest(id).contains("Host: synthetic.invalid\n"));
        assertTrue(store.rawRequest(id).contains("NOT wire proof"));
        assertEquals(true, store.rawCaptureInfo(id).get("available"));
        assertEquals(false, store.rawCaptureInfo(id).get("completeWireCapture"));
        assertEquals(false, store.rawCaptureInfo(id).get("requestTruncated"));
        assertEquals("synthetic-auth-123456", store.rawCaptureInfo(id).get("intentId"));
        assertThrows(UnsupportedOperationException.class, () -> store.rawCaptureInfo(id).clear());
        assertFalse(store.exportJson(store.snapshot()).contains("UNMASKED_INSPECTION"));
    }

    @Test void unsupportedCharsetAndBinaryHaveLosslessHexInsteadOfReplacementOrAutomaticOmission() {
        for (List<Header> headers : List.of(List.of(new Header("Content-Type", "application/json; charset=unknown-fixture")),
                List.of(new Header("Content-Type", "application/octet-stream")))) {
            EvidenceStore store = new EvidenceStore();
            byte[] original = new byte[] {0, 1, 10, 32, 65, (byte) 0xff};
            String id = store.begin("p", "p", request(headers, original, true, true), ALLOW, 1);
            assertEquals(0xff, original[5] & 255);
            assertTrue(store.rawRequest(id).contains("00 01 0a 20 41 ff"));
            assertEquals("HEX", store.rawCaptureInfo(id).get("requestBodyDisplay"));
            assertEquals(false, store.rawCaptureInfo(id).get("requestOmitted"));
            assertFalse(store.rawRequest(id).contains("\ufffd"));
            TrafficEntry.Message row = store.snapshot().getFirst().requestCapture();
            assertFalse(row.bodyOmitted());
            assertEquals("HEX", row.bodyEncoding());
            assertEquals("00010a2041ff", row.body(), "lossless hex of every supplied byte, never replacement text");
        }
    }

    @Test void malformedJsonEncodedMultipartAndUnknownCharsetStillHaveRawInspectionCopies() {
        for (String type : List.of("application/json", "application/json; charset=synthetic-unknown", "multipart/form-data; boundary=fixture")) {
            EvidenceStore store = new EvidenceStore();
            String body = "{\"password\":\"synthetic-raw-only-secret\"";
            String id = store.begin("p", "p", request(List.of(new Header("Content-Type", type), new Header("Content-Encoding", "gzip")),
                    body.getBytes(StandardCharsets.UTF_8), true, true), ALLOW, 1);
            String raw = store.rawRequest(id);
            assertNotNull(raw);
            assertTrue(raw.contains("synthetic-raw-only-secret") || raw.contains("[HEX:") && raw.contains("73 79 6e"));
            TrafficEntry.Message row = store.snapshot().getFirst().requestCapture();
            assertEquals(row.bodyEncoding().equals("HEX") ? java.util.HexFormat.of().formatHex(body.getBytes(StandardCharsets.UTF_8)) : body, row.body());
            assertFalse(row.bodyOmitted(), "malformed/encoded/unknown bodies are retained, not omitted");
        }
    }

    @Test void incompletePrefixesAreExportedAsSuppliedButLabeledIncompleteNeverAsComplete() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request(List.of(new Header("Host", "fuzz.invalid"),
                new Header("Content-Type", "application/json")), "{\"prefix\":true}".getBytes(StandardCharsets.UTF_8), false, false),
                new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of(), List.of("HEADER_INSPECTION_UNAVAILABLE_CAPTURE_INCOMPLETE")), 1);
        Map<String, Object> info = store.rawCaptureInfo(id);
        assertEquals(false, info.get("headersComplete"));
        assertEquals(false, info.get("bodyComplete"));
        assertEquals(true, info.get("requestTruncated"));
        // headers were omitted, so the declared charset is UNKNOWN: the prefix is shown as bytes, never as verified text
        assertTrue(store.rawRequest(id).contains("7b 22 70 72 65 66 69 78 22 3a 74 72 75 65"));
        assertTrue(store.rawRequest(id).contains("[Body incomplete or omitted]"));
        TrafficEntry e = store.snapshot().getFirst();
        assertFalse(e.requestCapture().bodyOmitted());
        assertTrue(e.requestCapture().truncated());
        assertEquals("HEX", e.requestCapture().bodyEncoding());
        assertTrue(e.inspectionWarnings().contains("HEADERS_INCOMPLETE"));
        assertTrue(e.inspectionWarnings().contains("BODY_INCOMPLETE"));
        store.responseBytes(id, 9_000_000);
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                "{\"responsePrefix\":true}".getBytes(StandardCharsets.UTF_8), true, false);
        assertTrue(store.rawResponse(id).contains("{\"responsePrefix\":true}"));
        assertEquals(true, store.rawCaptureInfo(id).get("responseTruncated"));
        assertTrue(store.snapshot().getFirst().responseCapture().truncated());
        assertFalse(store.snapshot().getFirst().responseCapture().bodyOmitted());
        assertEquals(9_000_000, store.snapshot().getFirst().responseBytes(), "a partial copy never replaces the native size");
        assertTrue(store.exportJson(store.snapshot()).contains("responsePrefix"));
        assertTrue(store.snapshot().getFirst().truncated());
    }

    @Test void absentAndUnavailableCopiesNeverBecomeInventedZeroByteTranscriptsWhileLargeCompleteBodiesAreKept() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", empty(), ALLOW, 1);
        assertNull(store.rawResponse(id));
        assertEquals(false, store.rawCaptureInfo(id).get("responseAvailable"));
        store.response(id, 200, List.of(), new byte[0], false, false);
        assertTrue(store.rawResponse(id).contains("OMITTED"));
        assertEquals(true, store.rawCaptureInfo(id).get("responseOmitted"));
        assertEquals(-1, store.snapshot().getFirst().responseBytes());
        assertEquals("UNAVAILABLE", store.snapshot().getFirst().responseCapture().bodyEncoding());
        // A complete supplied copy beyond the policy inspection size is retained whole (no capture cutoff).
        store.response(id, 200, List.of(), new byte[RequestData.MAX_INSPECT_BYTES + 1]);
        assertEquals(2 * (RequestData.MAX_INSPECT_BYTES + 1), store.snapshot().getFirst().responseCapture().body().length());
        assertEquals(RequestData.MAX_INSPECT_BYTES + 1, store.snapshot().getFirst().responseBytes());
    }

    @Test void clearAndProjectSwitchDisposeRowsAndRawWithoutLateResponseResurrection() {
        EvidenceStore store = new EvidenceStore();
        assertNull(store.rawRequest("unknown"));
        store.response("never-begun", 200, List.of(), "not-captured".getBytes(StandardCharsets.UTF_8));
        assertEquals(0, count(store, "rawRetainedEntries"));
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.clear();
        assertNull(store.rawUrl(first));
        store.response(first, 200, List.of(), "late-raw".getBytes(StandardCharsets.UTF_8));
        assertNull(store.rawResponse(first));
        assertNull(store.entry(first));
        String second = store.begin("p", "p", empty(), ALLOW, 1);
        assertNotNull(store.rawRequest(second));
        long generation = store.rawGeneration();
        String third = store.begin("other-project", "p", empty(), ALLOW, 1);
        assertNull(store.rawRequest(second));
        assertNull(store.entry(second), "another project's originals never share the store");
        assertTrue(store.rawGeneration() > generation);
        store.response(second, 200, List.of(), "late-old-project".getBytes(StandardCharsets.UTF_8));
        assertNull(store.rawResponse(second));
        assertNotNull(store.rawRequest(third));
        assertEquals(List.of(third), store.snapshot().stream().map(TrafficEntry::id).toList());
        store.clear();
        assertEquals(false, store.rawCaptureInfo(third).get("available"));
        assertEquals(0, count(store, "rawRetainedEntries"));
        assertEquals(0, count(store, "rawRetainedBytes"));
    }

    @Test void structuredRetentionAccountsMetadataAndHumanJsonRoundTripsRetainedBytesExactly() throws Exception {
        EvidenceStore store = new EvidenceStore();
        byte[] body = {0, 1, (byte) 0x80, 'a', '\n', (byte) 0xff};
        String id = store.begin("p", "Project", request(List.of(new Header("Content-Type", "text/plain; charset=unknown"),
                new Header("X-Dup", "1"), new Header("X-Dup", "2")), body, true, true), ALLOW, 1);
        byte[] json = store.humanEvidence(List.of(id)).json(Map.of("projectId", "p"));
        var tree = Json.MAPPER.readTree(json);
        assertEquals("cairn-human-inspection", tree.get("format").asText());
        assertEquals(1, tree.get("formatVersion").asInt());
        assertArrayEquals(body, java.util.Base64.getDecoder().decode(tree.at("/entries/0/original/request/body/base64").asText()));
        assertEquals(true, tree.at("/entries/0/original/request/body/retainedPrefixComplete").asBoolean());
        assertEquals("2", tree.at("/entries/0/original/request/headers/2/value").asText());
        assertTrue(tree.at("/entries/0/original/response").isNull());
        assertEquals("POST", tree.at("/entries/0/original/method").asText());
        assertEquals("synthetic-auth-123456", tree.at("/entries/0/original/url").asText().replaceAll(".*echo=", ""));
        assertTrue(new String(json, StandardCharsets.UTF_8).contains("PLAINTEXT_ORIGINALS"));
        store.clear();
        assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class,
                () -> store.humanEvidence(List.of(id))).getMessage(), "cleared originals cannot be snapshotted");
        // Every original hit is retained and accounted in the informational size estimate.
        List<Decision.RuleHit> hits = new java.util.ArrayList<>();
        for (int i = 0; i < 129; i++) hits.add(new Decision.RuleHit("id" + i, "n".repeat(1000), Mode.BLOCK));
        EvidenceStore many = new EvidenceStore();
        String all = many.begin("p", "p", empty(), new Decision(Mode.BLOCK, "RULE_BLOCK", hits), 1);
        assertEquals(129, ((List<?>) many.rawCaptureInfo(all).get("hits")).size());
        long withHits = count(many, "rawRetainedBytes");
        EvidenceStore plain = new EvidenceStore();
        plain.begin("p", "p", empty(), ALLOW, 1);
        assertTrue(withHits > count(plain, "rawRetainedBytes") + 30_000, "retained metadata is accounted in the estimate");
    }

    @Test void sourceReferencesAreReleasedWithTheirCaptureAndCannotBeResurrectedByLateCallbacks() {
        EvidenceStore store = new EvidenceStore();
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.bindRawSource(first, "ref-1");
        assertEquals(first, store.humanRoute("ref-1").evidenceId());
        assertEquals("fixture.test", store.humanRoute("ref-1").host());
        assertEquals("/actual?echo=synthetic-auth-123456", store.humanRoute("ref-1").rawTarget());
        assertEquals("/actual", store.humanRoute("ref-1").exactPath());
        store.clear();
        assertNull(store.humanRoute("ref-1"), "a clear releases the reference");
        store.bindRawSource(first, "ref-1");
        assertNull(store.humanRoute("ref-1"), "late bind cannot resurrect it");
        String fresh = store.begin("p", "p", empty(), ALLOW, 1);
        store.bindRawSource(fresh, "ref-2");
        long generation = store.rawGeneration();
        store.clear();
        assertNull(store.humanRoute("ref-2"));
        assertTrue(store.rawGeneration() > generation);
    }

    private static com.fasterxml.jackson.databind.JsonNode har(EvidenceStore store, String id) throws Exception {
        return Json.MAPPER.readTree(store.humanEvidence(List.of(id)).har(Map.of("projectId", "p")));
    }
    private static RequestData target(String target, List<Header> headers, byte[] body) {
        return new RequestData("POST", "https://fixture.test:443" + target, "fixture.test", 443, true, headers, body, true, true, target);
    }

    @Test void harPostDataTextRequiresValidUtf8AndAnAcceptedDeclaredCharsetOtherwiseOnlyTheBase64Extension() throws Exception {
        byte[] eAcute = {(byte) 0xC3, (byte) 0xA9};
        for (String type : List.of("text/plain; charset=windows-1252", "text/plain; charset=synthetic-unknown", "text/plain; charset=us-ascii")) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("p", "p", target("/a", List.of(new Header("Content-Type", type)), eAcute), ALLOW, 1);
            var post = har(store, id).at("/log/entries/0/request/postData");
            assertEquals("", post.get("text").asText(), type + ": no ordinary text interpretation");
            assertArrayEquals(eAcute, java.util.Base64.getDecoder().decode(post.get("_bodyBase64").asText()), type);
            assertEquals("base64", post.get("_encoding").asText());
        }
        for (String type : List.of("text/plain; charset=utf-8", "text/plain")) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("p", "p", target("/a", List.of(new Header("Content-Type", type)), eAcute), ALLOW, 1);
            var post = har(store, id).at("/log/entries/0/request/postData");
            assertEquals("\u00e9", post.get("text").asText(), type + ": positive control");
            assertTrue(post.path("_bodyBase64").isMissingNode());
        }
        EvidenceStore ascii = new EvidenceStore();
        String id = ascii.begin("p", "p", target("/a", List.of(new Header("Content-Type", "text/plain; charset=US-ASCII")), "plain".getBytes(StandardCharsets.US_ASCII)), ALLOW, 1);
        assertEquals("plain", har(ascii, id).at("/log/entries/0/request/postData/text").asText(), "valid ASCII under declared US-ASCII");
        assertTrue(ascii.rawRequest(id).contains("plain"));
        EvidenceStore display = new EvidenceStore();
        String shown = display.begin("p", "p", target("/a", List.of(new Header("Content-Type", "text/plain; charset=us-ascii")), eAcute), ALLOW, 1);
        assertEquals("HEX", display.rawCaptureInfo(shown).get("requestBodyDisplay"), "raw display uses the same shared decision");
    }

    @Test void harStandardUrlIsOnlyFilledWhenTheUnchangedTargetIsAFaithfulOrdinaryUrl() throws Exception {
        for (String bad : List.of("/a#b", "/a%zz", "/a b", "/a\u0001b", "/a\\b", "/\u00e9")) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("p", "p", target(bad, List.of(), new byte[0]), ALLOW, 1);
            var request = har(store, id).at("/log/entries/0/request");
            assertEquals("", request.get("url").asText(), bad);
            assertFalse(request.get("_urlUnavailable").asText().isEmpty(), bad);
            assertEquals(bad, request.get("_rawTarget").asText(), "the exact native target is preserved");
            assertEquals("fixture.test", request.at("/_service/host").asText());
            assertEquals(443, request.at("/_service/port").asInt());
        }
        for (String good : List.of("/a", "/a?x=1&y=%41", "/c/%2e/main.do", "/c/%2c", "/c/;/main.do", "/a%2fb", "//x", "/a/./b")) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("p", "p", target(good, List.of(), new byte[0]), ALLOW, 1);
            var request = har(store, id).at("/log/entries/0/request");
            assertEquals("https://fixture.test:443" + good, request.get("url").asText(), good + ": valid encoded/matrix targets stay exportable unchanged");
            assertTrue(request.path("_urlUnavailable").isMissingNode(), good);
            assertEquals(good, request.get("_rawTarget").asText());
        }
        EvidenceStore nonOrigin = new EvidenceStore();
        String id = nonOrigin.begin("p", "p", target("*", List.of(), new byte[0]), ALLOW, 1);
        assertEquals("", har(nonOrigin, id).at("/log/entries/0/request/url").asText());
    }

    private static void assertOneDecision(String label, List<Header> headers, byte[] body, boolean ordinaryText) throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", target("/a", headers, body), ALLOW, 1);
        String display = (String) store.rawCaptureInfo(id).get("requestBodyDisplay");
        var post = har(store, id).at("/log/entries/0/request/postData");
        var facts = Json.MAPPER.readTree(store.humanEvidence(List.of(id)).json(Map.of())).at("/entries/0/original/request/body");
        assertEquals(ordinaryText ? "UTF8_TEXT" : "HEX", display, label + ": raw display");
        assertEquals(ordinaryText, !post.get("text").asText().isEmpty(), label + ": HAR ordinary text");
        assertEquals(!ordinaryText, post.has("_bodyBase64"), label + ": HAR base64 extension");
        assertEquals(ordinaryText ? "UTF8_VALID" : "BINARY_OR_UNSUPPORTED", facts.get("encoding").asText(), label + ": JSON facts");
        assertEquals(ordinaryText, facts.has("utf8Text"), label);
        assertArrayEquals(body, java.util.Base64.getDecoder().decode(facts.get("base64").asText()), label + ": exact bytes");
        if (!ordinaryText) assertArrayEquals(body, java.util.Base64.getDecoder().decode(post.get("_bodyBase64").asText()), label);
        var order = har(store, id).at("/log/entries/0/request/headers");
        assertEquals(headers.size(), order.size(), label + ": every captured header is kept");
        for (int i = 0; i < headers.size(); i++) {
            assertEquals(headers.get(i).name(), order.get(i).get("name").asText());
            assertEquals(headers.get(i).value(), order.get(i).get("value").asText(), label + ": duplicate order is not collapsed or rewritten");
        }
    }

    @Test void oneConsistentCharsetDecisionCoversOverlongAndDuplicateContentTypeDeclarations() throws Exception {
        byte[] eAcute = {(byte) 0xC3, (byte) 0xA9};
        String padding = "a".repeat(1100);
        // complete retained values beyond the 1024 classification bound are UNKNOWN, never "no charset"
        assertOneDecision("long unsupported", List.of(new Header("Content-Type", "text/plain; padding=" + padding + "; charset=windows-1252")), eAcute, false);
        assertOneDecision("long even if it ends utf-8", List.of(new Header("Content-Type", "text/plain; padding=" + padding + "; charset=utf-8")), eAcute, false);
        // every captured declaration counts, in either order; nothing is guessed first/last
        Header utf8 = new Header("Content-Type", "text/plain; charset=utf-8"), unsupported = new Header("Content-Type", "text/plain; charset=windows-1252");
        assertOneDecision("[utf8, unsupported]", List.of(utf8, unsupported), eAcute, false);
        assertOneDecision("[unsupported, utf8]", List.of(unsupported, utf8), eAcute, false);
        assertOneDecision("[utf8, unknown mixed with other headers]", List.of(utf8, new Header("X-Between", "1"), new Header("content-type", "text/plain; charset=synthetic-unknown")), eAcute, false);
        // controls: supported declarations still produce ordinary text, unsupported/non-ASCII stay bytes
        assertOneDecision("utf8", List.of(utf8), eAcute, true);
        assertOneDecision("absent", List.of(new Header("X-Other", "1")), eAcute, true);
        assertOneDecision("duplicate supported", List.of(utf8, new Header("Content-Type", "text/plain; charset=UTF-8")), eAcute, true);
        assertOneDecision("ascii + utf8 duplicate, ascii bytes", List.of(new Header("Content-Type", "text/plain; charset=us-ascii"), utf8), "plain".getBytes(StandardCharsets.US_ASCII), true);
        assertOneDecision("ascii + utf8 duplicate, non-ascii bytes", List.of(new Header("Content-Type", "text/plain; charset=us-ascii"), utf8), eAcute, false);
        assertOneDecision("short unsupported", List.of(unsupported), eAcute, false);
        assertOneDecision("padding below the bound still decides by its charset", List.of(new Header("Content-Type", "text/plain; padding=" + "a".repeat(900) + "; charset=windows-1252")), eAcute, false);
        assertOneDecision("padding below the bound, utf-8", List.of(new Header("Content-Type", "text/plain; padding=" + "a".repeat(900) + "; charset=utf-8")), eAcute, true);
    }

    // ---- reviewfix3: incoming header loss, parameter boundaries, retained-header completeness ----
    private static RequestData incomplete(List<Header> headers, byte[] body) {
        return new RequestData("POST", "https://fixture.test:443/a", "fixture.test", 443, true, headers, body, false, true, "/a");
    }

    @Test void omittedIncomingHeadersAreUnknownCharsetNotVerifiedAbsenceAcrossEverySurface() throws Exception {
        byte[] eAcute = {(byte) 0xC3, (byte) 0xA9};
        for (List<Header> partial : List.of(List.<Header>of(), List.of(new Header("Content-Type", "text/plain; charset=utf-8")))) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("p", "p", incomplete(partial, eAcute), ALLOW, 1);
            String label = "incomplete headers " + partial;
            org.junit.jupiter.api.Assertions.assertAll(label,
                    () -> assertEquals("HEX", store.rawCaptureInfo(id).get("requestBodyDisplay"), "raw display"),
                    () -> assertTrue(har(store, id).at("/log/entries/0/request/postData/text").asText().isEmpty(), "no ordinary HAR text"),
                    () -> assertArrayEquals(eAcute, java.util.Base64.getDecoder().decode(har(store, id).at("/log/entries/0/request/postData/_bodyBase64").asText())),
                    () -> assertFalse(Json.MAPPER.readTree(store.humanEvidence(List.of(id)).json(Map.of())).at("/entries/0/original/request/body").has("utf8Text"), "no JSON utf8Text"),
                    () -> assertArrayEquals(eAcute, java.util.Base64.getDecoder().decode(Json.MAPPER.readTree(store.humanEvidence(List.of(id)).json(Map.of())).at("/entries/0/original/request/body/base64").asText())),
                    () -> assertEquals(false, store.rawCaptureInfo(id).get("headersComplete")));
            // the frozen decision survives later renders
            assertTrue(store.rawRequest(id).contains("c3 a9"), label);
            assertTrue(store.rawRequest(id).contains("c3 a9"), label);
        }
        // a COMPLETE empty header list is a verified absence of any declaration: ordinary text
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", target("/a", List.of(), eAcute), ALLOW, 1);
        assertEquals("UTF8_TEXT", store.rawCaptureInfo(id).get("requestBodyDisplay"));
        assertEquals("\u00e9", har(store, id).at("/log/entries/0/request/postData/text").asText());
    }

    static Stream<Arguments> charsetParameterCases() {
        return Stream.of(
                // review triggers and ambiguity: unsupported/duplicate/malformed real declarations => bytes
                Arguments.of("text/plain; charset=utf-8; charset=windows-1252", false),
                Arguments.of("text/plain; xcharset=utf-8; charset=windows-1252", false),
                Arguments.of("text/plain; name=\"charset=utf-8\"; charset=windows-1252", false),
                Arguments.of("text/plain; name=\"a;charset=utf-8\"; charset=windows-1252", false),
                Arguments.of("text/plain; charset=\"utf-8", false),
                Arguments.of("text/plain; charset=\"utf-8\"x", false),
                Arguments.of("text/plain; charset=utf-8\"", false),
                Arguments.of("text/plain; charset=utf-8; CHARSET=utf-8", false),
                Arguments.of("text/plain; charset = utf-8", false),
                Arguments.of("text/plain;\u0001charset=utf-8", false),
                Arguments.of("text/plain; charset=utf-8\u000b", false),
                Arguments.of("text/plain; charset=utf-8x", false),
                Arguments.of("text/plain; name=\"unterminated; charset=utf-8", false),
                // positive controls: one unambiguous supported charset, legitimate SP/HTAB OWS only
                Arguments.of("text/plain; charset=utf-8", true),
                Arguments.of("text/plain;\tcharset=utf-8", true),
                Arguments.of("text/plain ; charset=utf-8 \t", true),
                Arguments.of("text/plain; charset=\"utf-8\"", true),
                Arguments.of("text/plain; CHARSET=UTF-8", true),
                Arguments.of("text/plain; name=\"x;y\"; charset=utf-8", true),
                Arguments.of("text/plain; name=\"charset=windows-1252\"; charset=utf-8", true),
                Arguments.of("text/plain; xcharset=windows-1252", true),
                Arguments.of("text/plain", true));
    }
    @ParameterizedTest(name = "{0} -> text {1}") @MethodSource("charsetParameterCases")
    void oneContentTypeValueAcceptsOnlyAnUnambiguousRealCharsetParameter(String contentType, boolean text) throws Exception {
        assertOneDecision(contentType, List.of(new Header("Content-Type", contentType)), new byte[]{(byte) 0xC3, (byte) 0xA9}, text);
    }
    @Test void usAsciiParameterStillRequiresAsciiOnlyBytesAndQuotedFormIsExact() throws Exception {
        assertOneDecision("ascii", List.of(new Header("Content-Type", "text/plain; charset=\"US-ASCII\"")), "plain".getBytes(StandardCharsets.US_ASCII), true);
        assertOneDecision("ascii non-ascii", List.of(new Header("Content-Type", "text/plain; charset=us-ascii")), new byte[]{(byte) 0xC3, (byte) 0xA9}, false);
    }

    @Test void everySuppliedHeaderAndBodyByteIsRetainedWithTruthfulCompletenessForRequestAndResponse() throws Exception {
        String pad = "p".repeat(65_400);
        List<Header> supplied = List.of(new Header("Content-Type", "text/plain; charset=utf-8"), new Header("X-Keep", "1"), new Header("X-Pad", pad), new Header("X-After", "2"));
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", target("/a", supplied, "body".getBytes(StandardCharsets.UTF_8)), ALLOW, 1);
        store.response(id, 200, supplied, "resp".getBytes(StandardCharsets.UTF_8), true, true);
        var json = Json.MAPPER.readTree(store.humanEvidence(List.of(id)).json(Map.of()));
        var harDoc = har(store, id);
        org.junit.jupiter.api.Assertions.assertAll("no raw part budget",
                () -> assertTrue(json.at("/entries/0/original/request/headersComplete").asBoolean(false), "request JSON"),
                () -> assertTrue(json.at("/entries/0/original/response/headersComplete").asBoolean(false), "response JSON"),
                () -> assertTrue(harDoc.at("/log/entries/0/request/_headersComplete").asBoolean(false), "request HAR"),
                () -> assertTrue(harDoc.at("/log/entries/0/response/_headersComplete").asBoolean(false), "response HAR"),
                () -> assertEquals(true, store.rawCaptureInfo(id).get("headersComplete"), "request info"),
                () -> assertEquals(true, store.rawCaptureInfo(id).get("responseHeadersComplete"), "response info"));
        var retained = harDoc.at("/log/entries/0/request/headers");
        assertEquals(supplied.size(), retained.size());
        for (int i = 0; i < retained.size(); i++) {
            assertEquals(supplied.get(i).name(), retained.get(i).get("name").asText(), "headers are kept exactly in order");
            assertEquals(supplied.get(i).value(), retained.get(i).get("value").asText());
        }
        EvidenceStore body = new EvidenceStore();
        String big = body.begin("p", "p", target("/a", List.of(new Header("Content-Type", "text/plain"), new Header("X-Keep", "1")),
                "x".repeat(200_000).getBytes(StandardCharsets.UTF_8)), ALLOW, 1);
        var bodyJson = Json.MAPPER.readTree(body.humanEvidence(List.of(big)).json(Map.of()));
        assertTrue(bodyJson.at("/entries/0/original/request/headersComplete").asBoolean(false));
        assertFalse(bodyJson.at("/entries/0/original/request/body/truncated").asBoolean(true), "no local body cut");
        assertEquals(200_000, bodyJson.at("/entries/0/original/request/body/retainedBytes").asInt());
        assertEquals("UTF8_TEXT", body.rawCaptureInfo(big).get("requestBodyDisplay"));
    }

    // ---- reviewfix4: the recognized subset — token/token media type, EVERY parameter token=token|"whole quoted" ----
    static Stream<Arguments> recognizedSubsetCases() {
        return Stream.of(
                // both reviews' triggers: malformed syntax must never fall through as "charset absent"
                Arguments.of("text/plain; name=x\"; charset=windows-1252;\"", false),
                Arguments.of("text/plain; \"charset\"=windows-1252", false),
                Arguments.of("text/plain charset=windows-1252", false),
                Arguments.of("text/plain, charset=windows-1252", false),
                Arguments.of("text/plain\tcharset=windows-1252", false),
                Arguments.of("charset=windows-1252", false),
                // media segment boundaries
                Arguments.of("", false),
                Arguments.of("   ", false),
                Arguments.of("text", false),
                Arguments.of("text/", false),
                Arguments.of("/plain", false),
                Arguments.of("text/plain/x", false),
                Arguments.of("te\"xt/plain", false),
                Arguments.of("text/pl=ain", false),
                Arguments.of("text/pl@in", false),
                Arguments.of("t\u00e9xt/plain", false),
                Arguments.of("text / plain", false),
                // empty parameter segments are outside the conservative recognized subset
                Arguments.of("text/plain;", false),
                Arguments.of("text/plain;; charset=utf-8", false),
                Arguments.of("text/plain; ; charset=utf-8", false),
                Arguments.of("text/plain; charset=utf-8; \t", false),
                // parameter name/value boundaries (non-charset parameters too)
                Arguments.of("text/plain; name", false),
                Arguments.of("text/plain; name=", false),
                Arguments.of("text/plain; =x", false),
                Arguments.of("text/plain; na\"me=x", false),
                Arguments.of("text/plain; name=x\"y", false),
                Arguments.of("text/plain; name=\"x\"y", false),
                Arguments.of("text/plain; name=x\"y\"", false),
                Arguments.of("text/plain; na(me=x", false),
                Arguments.of("text/plain; name=a,b", false),
                Arguments.of("text/plain; name=a b", false),
                Arguments.of("text/plain; name=\"a\\\"b\"", false),
                Arguments.of("text/plain; name=x; charset=utf-8; other=\"unterminated", false),
                // RFC 2231/8187 charset* family: conservative unknown/bytes, never decoded or trusted
                Arguments.of("text/plain; charset*=us-ascii''windows-1252", false),
                Arguments.of("text/plain; CHARSET*0=x", false),
                Arguments.of("text/plain; charset*0*=x", false),
                Arguments.of("text/plain; charset*=\"utf-8\"", false),
                Arguments.of("text/plain; charset*=utf-8; charset=utf-8", false),
                // positive controls inside the recognized subset
                Arguments.of("text/plain; xcharset*=a", true),
                Arguments.of("text/plain; charse*=a", true),
                Arguments.of("application/json", true),
                Arguments.of("text/vnd.api+json; charset=utf-8", true),
                Arguments.of("text/plain ; charset=utf-8", true),
                Arguments.of("  text/plain;charset=\"UTF-8\"  ", true),
                Arguments.of("text/plain; name=\"a;b=charset=windows-1252\"; charset=utf-8", true),
                Arguments.of("text/plain; name=\"a;b\"", true),
                Arguments.of("text/plain; name=\"\"", true),
                Arguments.of("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk", true),
                Arguments.of("application/x-www-form-urlencoded; x=!#$%&'*+-.^_`|~", true));
    }
    @ParameterizedTest(name = "{0} -> text {1}") @MethodSource("recognizedSubsetCases")
    void charsetAbsenceIsAcceptedOnlyAfterTheMediaTypeAndEveryParameterAreUnambiguous(String contentType, boolean text) throws Exception {
        assertOneDecision(contentType, List.of(new Header("Content-Type", contentType)), new byte[]{(byte) 0xC3, (byte) 0xA9}, text);
    }
    @Test void recognizedSubsetKeepsDuplicateHeaderUsAsciiAndTrueAbsenceControls() throws Exception {
        byte[] eAcute = {(byte) 0xC3, (byte) 0xA9};
        assertOneDecision("duplicate supported headers", List.of(new Header("Content-Type", "text/plain; charset=utf-8"),
                new Header("Content-Type", "application/json")), eAcute, true);
        assertOneDecision("one malformed duplicate header", List.of(new Header("Content-Type", "text/plain; charset=utf-8"),
                new Header("Content-Type", "text/plain charset=windows-1252")), eAcute, false);
        assertOneDecision("us-ascii ascii", List.of(new Header("Content-Type", "text/plain; charset=us-ascii")), "ok".getBytes(StandardCharsets.US_ASCII), true);
        assertOneDecision("us-ascii non-ascii", List.of(new Header("Content-Type", "text/plain; charset=us-ascii")), eAcute, false);
        assertOneDecision("complete capture with no Content-Type is a true absence", List.of(new Header("X-Other", "1")), eAcute, true);
    }    @Test void unpairedProtectedResponseRetainsEveryByteButNoInventedRequestInAnyExport() throws Exception {
        var store=new EvidenceStore(); var source=store.begin("p","p",empty(),ALLOW,1);
        byte[] body=("synthetic-plaintext-[REDACTED]-"+"x".repeat(2*1024*1024)).getBytes(StandardCharsets.UTF_8);
        var original=body.clone(); var headers=List.of(new Header("Content-Type","text/plain"),new Header("Set-Cookie","synthetic-secret=unmasked"));
        store.unpairedResponse(source,500,headers,body,body.length,true,true); body[0]=0;
        var row=store.snapshot().getFirst(); var id=row.id();
        assertEquals("unpaired_response",row.outcome()); assertEquals("",row.method()); assertEquals("",row.url());
        assertFalse(row.requestCapture().present()); assertNull(store.rawRequest(id));
        assertEquals(false,store.rawCaptureInfo(id).get("requestAvailable"));
        assertEquals(true,store.rawCaptureInfo(id).get("responseAvailable"));
        assertNull(store.rawResponse(source)); assertEquals(1,count(store,"begun"));
        assertEquals(0,count(store,"forwarded")); assertEquals(0,count(store,"blocked"));
        assertEquals(0,count(store,"upstreamResponses")); assertEquals(1,count(store,"unpairedResponses"));
        var parser=new com.fasterxml.jackson.databind.ObjectMapper();
        var json=parser.readTree(store.humanEvidence(List.of(id)).json(Map.of()));
        assertTrue(json.at("/entries/0/original/request").isNull());
        assertEquals("RESPONSE_CORRELATION_UNAVAILABLE",json.at("/entries/0/original/requestUnavailable").asText());
        assertArrayEquals(original,java.util.Base64.getDecoder().decode(json.at("/entries/0/original/response/body/base64").asText()));
        var har=parser.readTree(store.humanEvidence(List.of(id)).har(Map.of()));
        assertEquals("",har.at("/log/entries/0/request/method").asText());
        assertEquals("RESPONSE_CORRELATION_UNAVAILABLE",har.at("/log/entries/0/request/_unavailable").asText());
        assertArrayEquals(original,java.util.Base64.getDecoder().decode(har.at("/log/entries/0/response/content/text").asText()));
        for(String output:List.of(store.exportJson(store.snapshot()),store.exportHar(store.snapshot()),store.rawResponse(id))) {
            assertTrue(output.contains("synthetic-secret=unmasked")); assertTrue(output.contains("synthetic-plaintext-[REDACTED]-"));
        }
        store.clear(); store.unpairedResponse(source,200,headers,original,original.length,true,true);
        assertTrue(store.snapshot().isEmpty());
        store.begin("other","other",empty(),ALLOW,1);
        store.unpairedResponse(source,200,headers,original,original.length,true,true);
        assertEquals(1,store.snapshot().size());
    }

}
