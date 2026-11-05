package dev.cairnguard.evidence;

import com.fasterxml.jackson.databind.JsonNode;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.DenialReasons;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceStoreTest {
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());
    private static RequestData request(String url, List<Header> headers, String body) {
        return new RequestData("POST", url, "fixture.test", 443, true, headers, body.getBytes(StandardCharsets.UTF_8));
    }
    private static RequestData empty() { return request("https://fixture.test/api?view=safe", List.of(), ""); }
    private static long count(EvidenceStore store, String key) { return ((Number) store.stats().get(key)).longValue(); }
    private static TrafficEntry only(EvidenceStore store) { return store.snapshot().getFirst(); }

    @Test void immutableSnapshotsSupportSearchAndBookmarksWithoutMutatingOldViews() {
        EvidenceStore store = new EvidenceStore();
        String first = store.begin("local", "Synthetic review", empty(), ALLOW, 7);
        List<TrafficEntry> before = store.snapshot();
        assertEquals("", before.getFirst().response());
        assertEquals("PENDING", before.getFirst().disposition());
        assertEquals(7, before.getFirst().revision());
        assertDoesNotThrow(() -> Instant.parse(before.getFirst().timestamp()));
        store.bookmark(first, true);
        String second = store.begin("local", "Other review", empty(), ALLOW, 8);
        assertEquals(List.of(second, first), store.snapshot().stream().map(TrafficEntry::id).toList());
        assertFalse(before.getFirst().bookmarked());
        assertTrue(store.snapshot().get(1).bookmarked());
        assertEquals(1, count(store, "bookmarked"));
        assertEquals(1, store.snapshot().stream().filter(e -> e.projectName().contains("Synthetic")).count());
        assertThrows(UnsupportedOperationException.class, () -> before.clear());
        assertThrows(UnsupportedOperationException.class, () -> only(store).hits().clear());
        assertThrows(UnsupportedOperationException.class, () -> only(store).requestCapture().headers().clear());
        assertThrows(UnsupportedOperationException.class, () -> store.stats().clear());
    }

    @Test void credentialsMetadataHeadersBodiesAndResponsesAreKeptAsOriginalsWhileReasonsStayCategorical() throws Exception {
        String secret = "fixture-credential-needle";
        EvidenceStore store = new EvidenceStore();
        String url = "https://user:" + secret + "@fixture.test/echo/" + secret + "?api_key=" + secret + "&echo=" + secret;
        String body = "{\"password\":\"" + secret + "\",\"echo\":\"prefix-" + secret + "-suffix\",\"ok\":\"safe\"}";
        RequestData request = request(url, List.of(new Header("Authorization", "Bearer " + secret), new Header("Cookie", "sid=" + secret),
                        new Header("X-Debug", "echo " + secret), new Header("Content-Type", "application/json")), body);
        Decision decision = new Decision(Mode.BLOCK, "exception: " + secret,
                List.of(new Decision.RuleHit("id-" + secret, "rule " + secret, Mode.BLOCK)));
        String id = store.begin("project-" + secret, "Review " + secret, request, decision, 2);
        store.outcome(id, "BLOCKED", "native error " + secret, 451);
        store.response(id, 451, List.of(new Header("Set-Cookie", "session=" + secret), new Header("X-Echo", secret),
                new Header("Content-Type", "application/json")), ("{\"echo\":\"" + secret + "\",\"ok\":true}").getBytes(StandardCharsets.UTF_8));
        TrafficEntry entry = only(store);
        assertEquals(url, entry.url());
        assertEquals("Review " + secret, entry.projectName());
        assertEquals("rule " + secret, entry.hits().getFirst().name());
        assertTrue(entry.request().contains("Authorization: Bearer " + secret));
        assertTrue(entry.response().contains("Set-Cookie: session=" + secret));
        assertEquals(body, entry.requestCapture().body(), "the original body text is not re-rendered");
        assertEquals("UTF8_TEXT", entry.requestCapture().bodyEncoding());
        for (String export : List.of(store.exportJson(store.snapshot()), store.exportHar(store.snapshot())))
            assertTrue(export.contains("session=" + secret) && export.contains("prefix-" + secret + "-suffix"));
        assertFalse(Json.write(store.stats()).contains(secret), "counters stay payload-free");
        assertEquals("OUTCOME_RECORDED", entry.reason());
        assertFalse(store.exportJson(store.snapshot()).contains("exception: "), "decision reason text is categorical, not copied");
        assertEquals("BLOCKED", entry.disposition());
        assertEquals(451, entry.statusCode());
        assertEquals(1, count(store, "blocked"));
        assertEquals(0, count(store, "forwarded"));
        assertEquals(1, count(store, "localResponses"));
        assertEquals(0, count(store, "upstreamResponses"));
        assertEquals("safe", Json.MAPPER.readTree(entry.requestCapture().body()).path("ok").asText());
    }

    static java.util.stream.Stream<String> nativeDenialReasons() {
        return DenialReasons.ALL.stream().sorted();
    }

    @ParameterizedTest @MethodSource("nativeDenialReasons")
    void everyNativeDenialKeepsItsFixedCategoryInSnapshotsAndBothExports(String reason) throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "Synthetic fixture", empty(), Decision.blocked(reason), 1);
        assertEquals(reason, only(store).reason());
        store.outcome(id, "BLOCKED", reason, 451);
        assertEquals(reason, only(store).reason());
        assertEquals(reason, Json.MAPPER.readTree(store.exportJson(store.snapshot())).at("/entries/0/reason").asText());
        assertEquals(reason, Json.MAPPER.readTree(store.exportHar(store.snapshot())).at("/log/entries/0/_cairnGuard/reason").asText());
    }

    @Test void unknownNativeDenialCannotBecomeRawAdapterOrEvidenceText() {
        assertEquals("ADAPTER_ERROR", DenialReasons.category("fixture-secret-not-a-category"));
        assertEquals("ADAPTER_ERROR", DenialReasons.category(null));
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "Synthetic fixture", empty(), Decision.blocked("fixture-secret-not-a-category"), 1);
        store.outcome(id, "BLOCKED", "fixture-secret-not-a-category", 451);
        assertEquals("OUTCOME_RECORDED", only(store).reason());
        assertFalse(store.exportJson(store.snapshot()).contains("fixture-secret-not-a-category"));
        assertFalse(store.exportHar(store.snapshot()).contains("fixture-secret-not-a-category"));
    }

    @Test void responseValuesNeverRemaskEarlierCopiesAndStaleSelectionsExportTheCurrentOriginalRow() {
        String secret = "response-only-fixture-needle";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin(secret, "review " + secret,
                request("https://fixture.test/" + secret, List.of(new Header("X-Echo", secret)), ""), ALLOW, 1);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Set-Cookie", "sid=" + secret), new Header("Content-Type", "application/json")),
                ("{\"echo\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        assertEquals("https://fixture.test/" + secret, only(store).url());
        assertTrue(only(store).request().contains("X-Echo: " + secret));
        assertTrue(store.exportJson(stale).contains("sid=" + secret), "a stale seal exports the current retained row");
        assertTrue(store.exportHar(stale).contains("sid=" + secret));
    }

    @Test void releasesAreNotDeliveryAndLocalBlockCannotBeOverwrittenByGenericCallback() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String forwarded = store.begin("p", "p", empty(), ALLOW, 1);
        store.outcome(forwarded, "FORWARDED", "NATIVE_RELEASED", null);
        store.outcome(forwarded, "FORWARDED", "NATIVE_RELEASED", null);
        store.outcome(forwarded, "BLOCKED", "LOCAL_BLOCK", 451);
        assertEquals("FORWARDED", only(store).disposition());
        assertEquals(0, count(store, "blocked"));
        assertNull(only(store).statusCode());
        assertEquals(1, count(store, "forwarded"));
        assertEquals(0, count(store, "responses"));
        String blocked = store.begin("p", "p", empty(), ALLOW, 1);
        store.response(blocked, 451, List.of(), new byte[0]);
        store.outcome(blocked, "BLOCKED", "LOCAL_BLOCK", 451);
        store.outcome(blocked, "FORWARDED", "NATIVE_RELEASED", null);
        assertEquals("BLOCKED", only(store).disposition());
        assertEquals("LOCAL_BLOCK", only(store).reason());
        assertEquals(1, count(store, "blocked"));
        assertEquals(1, count(store, "localResponses"));
        assertEquals(0, count(store, "upstreamResponses"));
        JsonNode har = Json.MAPPER.readTree(store.exportHar(store.snapshot()));
        assertEquals("LOCAL_BLOCK", har.at("/log/entries/0/_cairnGuard/responseSource").asText());
        assertFalse(har.at("/log/entries/1/_cairnGuard/responseObserved").asBoolean());
        assertEquals("NATIVE_RELEASE_NOT_PROVEN_DELIVERY", har.at("/log/_cairnGuard/forwardedMeans").asText());
    }

    @Test void noCountEvictionAndCountersSurviveClear() {
        EvidenceStore store = new EvidenceStore();
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.bookmark(first, true);
        store.outcome(first, "FORWARDED", "NATIVE_RELEASED", null);
        store.begin("p", "p", empty(), ALLOW, 1);
        store.begin("p", "p", empty(), ALLOW, 1);
        assertEquals(3, store.snapshot().size());
        assertEquals(0, count(store, "evictions"));
        assertEquals(first, store.snapshot().getLast().id());
        assertEquals(1, count(store, "bookmarked"));
        store.clear();
        store.response(first, 200, List.of(), new byte[0]);
        assertEquals(1, count(store, "orphanUpdates"));
        assertTrue(store.snapshot().isEmpty());
        assertEquals(0, count(store, "retainedBytes"));
        assertEquals(3, count(store, "begun"));
        assertEquals(1, count(store, "forwarded"));
        assertEquals(0, count(store, "evictions"));
        assertEquals(1, count(store, "clears"));
        assertEquals(3, count(store, "clearedEntries"));
    }

    @Test void pathInterpretationAndSuppliedWarningsSurviveEveryResealAndExportVerbatim() throws Exception {
        EvidenceStore store = new EvidenceStore();
        var request = new RequestData("GET", "https://owned.test/c/%zz/main.do", "owned.test", 443, true, List.of(), new byte[0]);
        String id = store.begin("p", "Synthetic", request,
                new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of(), List.of("PATH_INTERPRETATION_INCOMPLETE", "unsafe free form [REDACTED]")), 1);
        store.context(id, "forwarded", "PROTECTED", "");
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.responseBytes(id, 0);
        store.response(id, 200, List.of(), new byte[0]);
        store.bookmark(id, true);
        assertEquals(List.of("PATH_INTERPRETATION_INCOMPLETE", "unsafe free form [REDACTED]"), store.entry(id).inspectionWarnings());
        var document = Json.MAPPER.readTree(store.exportJson(store.snapshot()));
        assertEquals("PATH_INTERPRETATION_INCOMPLETE", document.path("entries").get(0).path("inspectionWarnings").get(0).asText());
        assertEquals("unsafe free form [REDACTED]", document.path("entries").get(0).path("inspectionWarnings").get(1).asText());
        assertTrue(store.exportHar(store.snapshot()).contains("PATH_INTERPRETATION_INCOMPLETE"));
    }

    @Test void clearedSnapshotsCannotExportAloneOrMixedWithLiveRows() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String oldId = store.begin("p", "Synthetic", new RequestData("GET", "https://owned.test/old", "owned.test", 443, true, List.of(), new byte[0]), ALLOW, 1);
        TrafficEntry old = store.entry(oldId);
        store.clear();
        String liveId = store.begin("p", "Synthetic", new RequestData("GET", "https://owned.test/benign", "owned.test", 443, true, List.of(), new byte[0]), ALLOW, 2);
        TrafficEntry live = store.entry(liveId);
        for (List<TrafficEntry> selection : List.of(List.of(old), List.of(old, live), List.of(live, old))) {
            assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class, () -> store.exportJson(selection)).getMessage());
            assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class, () -> store.exportHar(selection)).getMessage());
        }
        assertEquals(liveId, Json.MAPPER.readTree(store.exportJson(List.of(live))).path("entries").get(0).path("id").asText());
        assertTrue(store.exportHar(List.of(live)).contains("/benign"));
    }

    private static RequestData routed(String target) {
        return new RequestData("GET", "https://fixture.test:443" + target, "fixture.test", 443, true, List.of(), new byte[0], true, true, target);
    }

    @Test void legacyHarKeepsTheAuthoritativeRouteAndFillsTheStandardUrlOnlyWhenTheUnchangedTargetIsFaithful() throws Exception {
        for (String good : List.of("/a", "/a?x=1&y=%41", "/c/%2e/main.do", "/c/;/main.do", "/a%2fb")) {
            EvidenceStore store = new EvidenceStore();
            store.begin("p", "p", routed(good), ALLOW, 1);
            JsonNode request = Json.MAPPER.readTree(store.exportHar(store.snapshot())).at("/log/entries/0/request");
            assertEquals("https://fixture.test:443" + good, request.get("url").asText(), good);
            assertTrue(request.path("_urlUnavailable").isMissingNode(), good);
            assertEquals(good, request.get("_rawTarget").asText(), good);
            assertEquals("https", request.at("/_service/scheme").asText());
            assertEquals("fixture.test", request.at("/_service/host").asText());
            assertEquals(443, request.at("/_service/port").asInt());
            assertEquals(good.contains("?") ? 2 : 0, request.get("queryString").size(), good);
        }
        for (String bad : List.of("/raw#part", "/a%zz", "*", "/a b", "/\u00e9")) {
            EvidenceStore store = new EvidenceStore();
            store.begin("p", "p", routed(bad), ALLOW, 1);
            String url = store.snapshot().getFirst().url();
            JsonNode request = Json.MAPPER.readTree(store.exportHar(store.snapshot())).at("/log/entries/0/request");
            assertEquals("", request.get("url").asText(), bad + ": no unfaithful standard URL");
            assertFalse(request.get("_urlUnavailable").asText().isEmpty(), bad);
            assertEquals(bad, request.get("_rawTarget").asText(), bad + ": the exact untouched target is preserved");
            assertEquals("fixture.test", request.at("/_service/host").asText());
            assertEquals(url, request.get("_displayUrl").asText(), "the retained display text stays available, labelled as display only");
            assertEquals(0, request.get("queryString").size(), bad);
        }
    }

    @Test void legacyHarWithoutAnAuthoritativeRouteNeverGuessesOneFromTheDisplayUrl() throws Exception {
        EvidenceStore store = new EvidenceStore();
        store.begin("p", "p", new RequestData("GET", "https://fixture.test/raw#part", "", 443, true, List.of(), new byte[0]), ALLOW, 1);
        JsonNode request = Json.MAPPER.readTree(store.exportHar(store.snapshot())).at("/log/entries/0/request");
        assertEquals("NO_SERVICE_ROUTE", request.get("_urlUnavailable").asText());
        assertEquals("", request.get("url").asText());
        assertTrue(request.path("_rawTarget").isMissingNode());
        assertTrue(request.path("_service").isMissingNode());
        assertEquals("https://fixture.test/raw#part", request.get("_displayUrl").asText());
    }

    @Test void validHarHasRequiredFieldsNoClaimedWireSizesOrFakeMissingResponses() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "fixture", empty(), ALLOW, 1);
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.response(id, 204, List.of(new Header("X-Safe", "ok")), new byte[0]);
        JsonNode document = Json.MAPPER.readTree(store.exportHar(store.snapshot()));
        assertEquals("1.2", document.at("/log/version").asText());
        assertEquals("Cairn Proxy Guard", document.at("/log/creator/name").asText());
        JsonNode e = document.at("/log/entries/0");
        assertDoesNotThrow(() -> Instant.parse(e.path("startedDateTime").asText()));
        assertTrue(e.has("cache"));
        assertEquals(0, e.path("time").asInt());
        for (String part : List.of("request", "response")) {
            for (String key : List.of("httpVersion", "headers", "cookies", "headersSize", "bodySize")) assertTrue(e.path(part).has(key), part + ":" + key);
            assertEquals(-1, e.path(part).path("bodySize").asInt());
        }
        assertEquals(204, e.path("response").path("status").asInt());
        assertTrue(e.at("/response/content").has("mimeType"));
        assertEquals(0, e.at("/timings/send").asInt());
        assertEquals(0, e.at("/timings/wait").asInt());
        assertEquals(0, e.at("/timings/receive").asInt());
        assertTrue(e.at("/_cairnGuard/responseObserved").asBoolean());
        assertFalse(e.at("/_cairnGuard/completeWireCapture").asBoolean());
        assertEquals("ORIGINAL_EVIDENCE_NOT_WIRE_CAPTURE", e.at("/_cairnGuard/label").asText());
        assertFalse(store.exportJson(store.snapshot()).contains("provenanceSeal"));
    }

    @Test void exportRejectsForeignForgedAndClearedRecordsButRetainedSnapshotsExport() {
        EvidenceStore store = new EvidenceStore();
        store.begin("p", "p", empty(), ALLOW, 1);
        List<TrafficEntry> old = store.snapshot();
        TrafficEntry e = old.getFirst();
        // Forgery and foreign-store checks run while the row is still retained, so row disposal cannot mask a broken seal check.
        assertDoesNotThrow(() -> store.exportJson(old));
        assertDoesNotThrow(() -> store.exportHar(old));
        TrafficEntry forged = new TrafficEntry(e.id(), e.projectId(), "forged-name-must-not-export", e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal());
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(forged)));
        assertEquals("INVALID_EVIDENCE_SELECTION", failure.getMessage());
        assertThrows(IllegalArgumentException.class, () -> store.exportHar(List.of(forged)));
        TrafficEntry.Message hex = new TrafficEntry.Message(e.requestCapture().headers(), e.requestCapture().body(), e.requestCapture().mimeType(),
                e.requestCapture().bodyOmitted(), e.requestCapture().truncated(), e.requestCapture().present(), "UNAVAILABLE");
        TrafficEntry recoded = new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), hex, e.responseCapture(), e.truncated(), e.provenanceSeal());
        assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(recoded)), "the body encoding is sealed");
        EvidenceStore foreign = new EvidenceStore();
        foreign.begin("p", "p", empty(), ALLOW, 1);
        assertThrows(IllegalArgumentException.class, () -> foreign.exportJson(old));
        // A clear disposes the row; the historical seal alone no longer authorizes export.
        store.clear();
        assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class, () -> store.exportJson(old)).getMessage());
        assertEquals("INVALID_EVIDENCE_SELECTION", assertThrows(IllegalArgumentException.class, () -> store.exportHar(old)).getMessage());
    }

    @Test void concurrentCallbacksAndExportsHaveNoMutableAliasesOrRaces() throws Exception {
        EvidenceStore store = new EvidenceStore();
        try (var executor = Executors.newFixedThreadPool(6)) {
            List<Callable<Void>> jobs = new ArrayList<>();
            for (int n = 0; n < 120; n++) jobs.add(() -> {
                String id = store.begin("p", "p", empty(), ALLOW, 1);
                store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
                store.response(id, 200, List.of(), new byte[0]);
                store.bookmark(id, true);
                Json.MAPPER.readTree(store.exportJson(store.snapshot()));
                return null;
            });
            for (var result : executor.invokeAll(jobs)) result.get();
        }
        assertEquals(120, count(store, "begun"));
        assertEquals(120, count(store, "responses"));
        assertEquals(120, count(store, "forwarded"));
        assertEquals(120, count(store, "bookmarked"));
        assertEquals(120, store.snapshot().size());
    }

    @Test void schemaTwoMetadataSurvivesEveryMutationAndHarWithoutChangingDispositionVocabulary() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "fixture", request("https://fixture.test/route",
                List.of(new Header("X-Cairn-Intent", "i048"), new Header("X-Cairn-Run", "run:alpha")), ""),
                new Decision(Mode.EXEMPT, "RULE_EXEMPT", List.of(), List.of("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_CHARSET")), 9);
        assertEquals("pending", only(store).outcome());
        assertEquals(-1, only(store).responseBytes());
        String overlay = "a5bd8ee4-97b7-438d-b07b-e5366533046e";
        store.context(id, "exempt", "PROTECTED", overlay);
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.responseBytes(id, 6L * 1024 * 1024);
        store.response(id, 200, List.of(), new byte[0]);
        store.bookmark(id, true);
        TrafficEntry e = only(store);
        assertEquals("FORWARDED", e.disposition());
        assertEquals("exempt", e.outcome());
        assertEquals("PROTECTED", e.guardState());
        assertEquals(overlay, e.overlayId());
        assertEquals("i048", e.intentId());
        assertEquals("run:alpha", e.runId());
        assertEquals(6L * 1024 * 1024, e.responseBytes());
        assertEquals(List.of("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_CHARSET"), e.inspectionWarnings());
        assertTrue(e.bookmarked());
        JsonNode json = Json.MAPPER.readTree(store.exportJson(store.snapshot()));
        assertEquals(2, json.path("schemaVersion").asInt());
        JsonNode har = Json.MAPPER.readTree(store.exportHar(store.snapshot()));
        for (JsonNode metadata : List.of(json.at("/entries/0"), har.at("/log/entries/0/_cairnGuard"))) {
            assertEquals("exempt", metadata.path("outcome").asText());
            assertEquals("PROTECTED", metadata.path("guardState").asText());
            assertEquals(overlay, metadata.path("overlayId").asText());
            assertEquals(e.responseBytes(), metadata.path("responseBytes").asLong());
            assertEquals(e.inspectionWarnings().getFirst(), metadata.path("inspectionWarnings").get(0).asText());
        }
        assertThrows(UnsupportedOperationException.class, () -> e.inspectionWarnings().clear());
    }

    @Test void validAndMissingAttributionIsDisplayedAndDuplicatesAreNotCopied() {
        EvidenceStore store = new EvidenceStore();
        store.begin("p", "p", empty(), ALLOW, 1);
        assertEquals("-", only(store).intentId());
        assertEquals("-", only(store).runId());
        String id = store.begin("p", "p", request("https://fixture.test/", List.of(new Header("X-Cairn-Intent", "i048"),
                new Header("X-Cairn-Run", "run-1")), ""), ALLOW, 1);
        store.context(id, "probe_allowed", "PROTECTED", "");
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.response(id, 204, List.of(), new byte[0]);
        store.bookmark(id, true);
        assertEquals("i048", only(store).intentId());
        assertEquals("run-1", only(store).runId());
        assertEquals("probe_allowed", only(store).outcome());
        store.begin("p", "p", request("https://fixture.test/", List.of(new Header("X-Cairn-Intent", "a"),
                new Header("x-cairn-intent", "a")), ""), ALLOW, 1);
        assertEquals("?", only(store).intentId());
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"Authorization", "Cookie", "X-Broker-Grant"})
    void valuesReflectedIntoIntentRunPathAndStructuredCopiesExportAsOriginals(String header) {
        String secret = "synthetic-reflected-label-753951";
        String value = header.equals("Authorization") ? "Bearer " + secret : header.equals("Cookie") ? "sid=" + secret : secret;
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request("https://fixture.test/echo/" + secret,
                List.of(new Header(header, value), new Header("X-Cairn-Intent", secret), new Header("X-Cairn-Run", "run-" + secret),
                        new Header("Content-Type", "application/json")), "{\"echo\":\"" + secret + "\"}"), ALLOW, 1);
        store.context(id, "exempt", "PROTECTED", "");
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                ("{\"grant\":\"" + secret + "\",\"mirror\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        store.bookmark(id, true);
        assertEquals(secret, only(store).intentId());
        assertEquals("run-" + secret, only(store).runId());
        for (String export : List.of(store.exportJson(store.snapshot()), store.exportHar(store.snapshot())))
            assertTrue(export.contains(secret) && export.contains("run-" + secret));
        assertTrue(only(store).request().contains(header + ": " + value));
        assertFalse(Json.write(store.stats()).contains(secret), "counters stay payload-free");
        assertTrue(store.rawRequest(id).contains(secret));
        assertTrue(store.rawResponse(id).contains(secret));
        assertEquals(secret, store.rawCaptureInfo(id).get("intentId"));
    }

    @Test void responseValuesNeverRemaskTagsPathOrOverlayIncludingStaleSelections() {
        String secret = "9437cd9e-f397-4187-8e4d-f0d9d34ac726";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request("https://fixture.test/" + secret,
                List.of(new Header("X-Cairn-Intent", secret), new Header("X-Cairn-Run", secret)), ""), ALLOW, 1);
        store.context(id, "half_open", "CIRCUIT_OPEN", secret);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                ("{\"brokerGrant\":\"" + secret + "\",\"echo\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        assertTrue(store.exportJson(stale).contains("brokerGrant"));
        assertEquals(secret, only(store).overlayId());
        assertEquals(secret, only(store).intentId());
        assertEquals("half_open", only(store).outcome());
        assertTrue(only(store).url().contains(secret));
    }

    @Test void allNewMetadataParticipatesInProvenanceAndUnsealedRecordsAreRejected() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", empty(), ALLOW, 1);
        store.context(id, "forwarded", "PROTECTED", "7254314f-0495-438a-88ed-a972b701fba1");
        TrafficEntry e = only(store);
        List<TrafficEntry> forged = List.of(
                withMetadata(e, "forged-intent", e.runId(), e.outcome(), e.guardState(), e.overlayId(), e.responseBytes(), e.inspectionWarnings()),
                withMetadata(e, e.intentId(), "forged-run", e.outcome(), e.guardState(), e.overlayId(), e.responseBytes(), e.inspectionWarnings()),
                withMetadata(e, e.intentId(), e.runId(), "exempt", e.guardState(), e.overlayId(), e.responseBytes(), e.inspectionWarnings()),
                withMetadata(e, e.intentId(), e.runId(), e.outcome(), "SHUTDOWN", e.overlayId(), e.responseBytes(), e.inspectionWarnings()),
                withMetadata(e, e.intentId(), e.runId(), e.outcome(), e.guardState(), "", e.responseBytes(), e.inspectionWarnings()),
                withMetadata(e, e.intentId(), e.runId(), e.outcome(), e.guardState(), e.overlayId(), 987654, e.inspectionWarnings()),
                withMetadata(e, e.intentId(), e.runId(), e.outcome(), e.guardState(), e.overlayId(), e.responseBytes(), List.of("BODY_INCOMPLETE")));
        for (TrafficEntry invalid : forged) {
            assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(invalid)));
            assertThrows(IllegalArgumentException.class, () -> store.exportHar(List.of(invalid)));
        }
        TrafficEntry unsealed = new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), "");
        assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(unsealed)));
        assertDoesNotThrow(() -> store.exportJson(List.of(e)));
    }

    private static TrafficEntry withMetadata(TrafficEntry e, String intent, String run, String outcome, String guard,
                                             String overlay, long bytes, List<String> warnings) {
        return new TrafficEntry(e.id(), e.projectId(), e.projectName(), e.timestamp(), e.method(), e.url(), e.mode(), e.disposition(),
                e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(),
                e.provenanceSeal(), intent, run, outcome, guard, overlay, bytes, warnings);
    }

    @Test void arbitraryContextIsCategoricalWhileSuppliedWarningsAreKeptVerbatim() {
        String secret = "synthetic-untrusted-metadata-2468";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", empty(), new Decision(Mode.ALLOW, "ALLOW", List.of(), List.of(secret)), 1);
        store.context(id, secret, secret, secret);
        assertEquals("pending", only(store).outcome());
        assertEquals("", only(store).guardState());
        assertEquals("", only(store).overlayId());
        assertEquals(List.of(secret), only(store).inspectionWarnings());
        assertTrue(store.exportJson(store.snapshot()).contains(secret));
        store.outcome(id, "BLOCKED", "CIRCUIT_OPEN", 451);
        store.context(id, "exempt", "CIRCUIT_OPEN", "");
        assertEquals("blocked", only(store).outcome());
    }

    @Test void warningsAreNotCountCappedAndCannotHideCaptureIncompleteness() {
        EvidenceStore store = new EvidenceStore();
        RequestData partial = new RequestData("POST", "https://fixture.test/", "fixture.test", 443, true,
                List.of(), new byte[0], false, false);
        List<String> supplied = java.util.stream.IntStream.range(0, 40).mapToObj(i -> "warning-" + i).toList();
        store.begin("p", "p", partial, new Decision(Mode.ALLOW, "ALLOW", List.of(), supplied), 1);
        TrafficEntry entry = only(store);
        assertTrue(entry.truncated(), "an incomplete supplied copy is truthfully incomplete");
        assertEquals(42, entry.inspectionWarnings().size());
        assertEquals(List.of("HEADERS_INCOMPLETE", "BODY_INCOMPLETE"), entry.inspectionWarnings().subList(0, 2));
        assertEquals("UNAVAILABLE", entry.requestCapture().bodyEncoding());
    }

    @Test void v2RuntimeReasonsAndFixedCountersRemainCategoricalAndCumulative() {
        EvidenceStore store = new EvidenceStore();
        for (String reason : List.of("RULE_EXEMPT", "HEAVY_ENDPOINT_AUTO_BLOCKED", "CIRCUIT_OPEN", "FANOUT_SUSPECTED",
                "RESPONSE_WATCHER_CAPACITY", "INVALID_INTENT_TAG", "INTENT_BUDGET_EXCEEDED", "INTENT_BUDGET_CAPACITY", "LISTENER_UNVERIFIED")) {
            String id = store.begin("p", "p", empty(), Decision.blocked(reason), 1);
            store.outcome(id, "BLOCKED", reason, 451);
            store.outcome(id, "BLOCKED", reason, 451);
            store.bookmark(id, true);
            assertEquals(reason, only(store).reason());
            Map<?, ?> counters = (Map<?, ?>) store.stats().get("reasonCounters");
            assertEquals(1L, counters.get(reason));
            assertThrows(UnsupportedOperationException.class, counters::clear);
        }
        store.clear();
        assertEquals(1L, ((Map<?, ?>) store.stats().get("reasonCounters")).get("CIRCUIT_OPEN"));
    }

    @Test void statsHaveFixedCredentialFreeKeysAndUnknownMessagesAreNeverRetained() {
        EvidenceStore store = new EvidenceStore();
        Map<String, Object> before = store.stats();
        String id = store.begin("p", "p", empty(), new Decision(Mode.BLOCK, "Bearer error-secret-fixture", List.of()), 1);
        store.outcome(id, "error-secret-fixture", "secret fixture debug", 999);
        assertEquals(before.keySet(), store.stats().keySet());
        assertEquals("ERROR", only(store).disposition());
        assertNull(only(store).statusCode());
        assertEquals("OUTCOME_RECORDED", only(store).reason());
        assertFalse(store.exportJson(store.snapshot()).contains("error-secret-fixture"));
    }
}
