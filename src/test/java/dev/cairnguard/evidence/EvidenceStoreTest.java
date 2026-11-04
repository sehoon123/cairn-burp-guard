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

    @Test void masksCredentialsAcrossMetadataHeadersBodiesAndExportsIncludingResponses() throws Exception {
        String secret = "fixture-credential-needle";
        EvidenceStore store = new EvidenceStore();
        RequestData request = request("https://user:" + secret + "@fixture.test/echo/" + secret + "?api_key=" + secret + "&echo=" + secret,
                List.of(new Header("Authorization", "Bearer " + secret), new Header("Cookie", "sid=" + secret),
                        new Header("X-Debug", "echo " + secret), new Header("Content-Type", "application/json")),
                "{\"password\":\"" + secret + "\",\"echo\":\"prefix-" + secret + "-suffix\",\"ok\":\"safe\"}");
        Decision decision = new Decision(Mode.BLOCK, "exception: " + secret,
                List.of(new Decision.RuleHit("id-" + secret, "rule " + secret, Mode.BLOCK)));
        String id = store.begin("project-" + secret, "Review " + secret, request, decision, 2);
        store.outcome(id, "BLOCKED", "native error " + secret, 451);
        store.response(id, 451, List.of(new Header("Set-Cookie", "session=" + secret), new Header("X-Echo", secret),
                new Header("Content-Type", "application/json")), ("{\"echo\":\"" + secret + "\",\"ok\":true}").getBytes(StandardCharsets.UTF_8));
        TrafficEntry entry = only(store);
        String all = Json.write(entry) + store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
        assertFalse(all.contains(secret), all);
        assertFalse(entry.url().contains("user:"));
        assertTrue(entry.request().contains("[REDACTED]"));
        assertEquals("OUTCOME_RECORDED", entry.reason());
        assertEquals("BLOCKED", entry.disposition());
        assertEquals(451, entry.statusCode());
        assertEquals(1, count(store, "blocked"));
        assertEquals(0, count(store, "forwarded"));
        assertEquals(1, count(store, "localResponses"));
        assertEquals(0, count(store, "upstreamResponses"));
        assertDoesNotThrow(() -> URI.create(entry.url()));
        assertEquals("safe", Json.MAPPER.readTree(entry.requestCapture().body()).path("ok").asText());
    }

    @Test void newlyIssuedGrantValuesAreMaskedEvenWithoutARequestHeaderFingerprint() {
        for (String name : List.of("grant", "brokerGrant", "grant_value", "x-broker-grant")) {
            String issued = "synthetic-issued-grant-819753";
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("local", "Synthetic", request("https://fixture.test/issue", List.of(), ""), ALLOW, 1);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                    ("{\"" + name + "\":\"" + issued + "\",\"echo\":\"" + issued + "\"}").getBytes(StandardCharsets.UTF_8));
            String captures = Json.write(store.snapshot()) + store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
            assertFalse(captures.contains(issued)); assertTrue(captures.contains("[REDACTED]"));
        }
    }

    @Test void brokerGrantIsMaskedAndCannotLeakViaReflectionsOrEitherExport() {
        for (String headerName : List.of("X-Broker-Grant", "x-broker-grant", "X-BROKER-GRANT")) {
            String grant = "synthetic-broker-grant-value-753951";
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("local", "Synthetic", request("https://fixture.test/echo/" + grant,
                    List.of(new Header(headerName, grant), new Header("Authorization", "Bearer synthetic-auth-value"),
                            new Header("Cookie", "sid=synthetic-cookie-value"), new Header("Content-Type", "application/json")),
                    "{\"echo\":\"" + grant + "\"}"), ALLOW, 1);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                    ("{\"echo\":\"" + grant + "\"}").getBytes(StandardCharsets.UTF_8));
            String captures = Json.write(store.snapshot()) + store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
            assertFalse(captures.contains(grant));
            assertFalse(captures.contains("synthetic-auth-value")); assertFalse(captures.contains("synthetic-cookie-value"));
            assertTrue(captures.contains("[REDACTED]"));
        }
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

    @Test void responseCredentialDiscoveryRemasksEarlierCopiesWithoutRetainingPlaintextSecrets() {
        String secret = "response-only-fixture-needle";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin(secret, "review " + secret,
                request("https://fixture.test/" + secret, List.of(new Header("X-Echo", secret)), ""), ALLOW, 1);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Set-Cookie", "sid=" + secret), new Header("Content-Type", "application/json")),
                ("{\"echo\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        assertFalse(Json.write(only(store)).contains(secret));
        assertFalse(store.exportHar(store.snapshot()).contains(secret));
        assertFalse(store.exportJson(stale).contains(secret));
        assertFalse(store.exportHar(stale).contains(secret));
    }

    @Test void responseSecretsRemaskEscapedStructuredValuesNotJustSerializedSubstrings() throws Exception {
        String secret = "fixture\nmultiline-value";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "review", request("https://fixture.test/", List.of(new Header("Content-Type", "application/json")),
                "{\"echo\":\"fixture\\nmultiline-value\",\"safe\":\"visible\"}"), ALLOW, 1);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                "{\"password\":\"fixture\\nmultiline-value\"}".getBytes(StandardCharsets.UTF_8));
        JsonNode body = Json.MAPPER.readTree(only(store).requestCapture().body());
        assertEquals(Redactor.REDACTED, body.path("echo").asText());
        assertEquals("visible", body.path("safe").asText());
        assertFalse(store.exportJson(stale).contains("multiline-value"));
        assertFalse(store.exportHar(stale).contains("multiline-value"));
        assertFalse(only(store).request().contains(secret));
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

    @Test void countEvictionIsOldestFirstEvenForBookmarksAndCountersSurviveClear() {
        EvidenceStore store = new EvidenceStore(2, 1024 * 1024, 1024);
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.bookmark(first, true);
        store.outcome(first, "FORWARDED", "NATIVE_RELEASED", null);
        store.begin("p", "p", empty(), ALLOW, 1);
        store.begin("p", "p", empty(), ALLOW, 1);
        assertEquals(2, store.snapshot().size());
        assertEquals(1, count(store, "evictions"));
        assertFalse(store.snapshot().stream().anyMatch(e -> e.id().equals(first)));
        assertEquals(0, count(store, "bookmarked"));
        store.response(first, 200, List.of(), new byte[0]);
        assertEquals(1, count(store, "orphanUpdates"));
        store.clear();
        assertTrue(store.snapshot().isEmpty());
        assertEquals(0, count(store, "retainedBytes"));
        assertEquals(3, count(store, "begun"));
        assertEquals(1, count(store, "forwarded"));
        assertEquals(1, count(store, "evictions"));
        assertEquals(1, count(store, "clears"));
        assertEquals(2, count(store, "clearedEntries"));
    }

    @Test void totalBytesAndEachPartAreBoundedAfterMaskingNotBefore() {
        EvidenceStore store = new EvidenceStore(20, 20_000, 2048);
        String secret = "needle-after-the-capture-limit";
        String large = "x".repeat(12_000);
        RequestData request = request("https://fixture.test/?echo=" + secret,
                List.of(new Header("Content-Type", "application/json")),
                "{\"padding\":\"" + large + "\",\"password\":\"" + secret + "\"}");
        for (int i = 0; i < 20; i++) {
            String id = store.begin("p", "p", request, ALLOW, 1);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                    ("{\"echo\":\"" + secret + "\",\"pad\":\"" + large + "\"}").getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(count(store, "retainedBytes") <= 20_000);
        assertTrue(count(store, "evictions") > 0);
        assertEquals(20, count(store, "truncations"));
        assertFalse(store.snapshot().isEmpty());
        for (TrafficEntry entry : store.snapshot()) {
            assertTrue(entry.truncated());
            assertTrue(Redactor.bytes(entry.request()) <= 2048);
            assertTrue(Redactor.bytes(entry.response()) <= 2048);
            assertFalse(entry.url().contains(secret), entry.url());
        }
        assertFalse(store.exportJson(store.snapshot()).contains(secret));
    }

    @Test void defaultBoundsAreEnforcedAndNeverDisabledByResponseGrowth() {
        EvidenceStore store = new EvidenceStore();
        String payload = "{\"safe\":\"" + "z".repeat(80_000) + "\"}";
        for (int i = 0; i < 300; i++) {
            String id = store.begin("p", "p", empty(), ALLOW, i);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")), payload.getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(count(store, "retainedBytes") <= EvidenceStore.MAX_TOTAL_BYTES);
        assertTrue(count(store, "evictions") > 0);
        for (TrafficEntry e : store.snapshot()) assertTrue(Redactor.bytes(e.response()) <= EvidenceStore.MAX_PART_BYTES);
        EvidenceStore smallMessages = new EvidenceStore();
        for (int i = 0; i <= EvidenceStore.MAX_ENTRIES; i++) smallMessages.begin("p", "p", empty(), ALLOW, i);
        assertEquals(EvidenceStore.MAX_ENTRIES, smallMessages.snapshot().size());
        assertEquals(1, count(smallMessages, "evictions"));
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
        assertEquals("REDACTED_EVIDENCE_NOT_WIRE_CAPTURE", e.at("/_cairnGuard/label").asText());
        assertFalse(store.exportJson(store.snapshot()).contains("provenanceSeal"));
    }

    @Test void exportRejectsForeignForgedAndEvictedRecordsButRetainedSnapshotsExport() {
        EvidenceStore store = new EvidenceStore(1, 100_000, 1024);
        store.begin("p", "p", empty(), ALLOW, 1);
        List<TrafficEntry> old = store.snapshot();
        TrafficEntry e = old.getFirst();
        // Forgery and foreign-store checks run while the row is still retained, so row disposal cannot mask a broken seal check.
        assertDoesNotThrow(() -> store.exportJson(old));
        assertDoesNotThrow(() -> store.exportHar(old));
        TrafficEntry forged = new TrafficEntry(e.id(), e.projectId(), "raw-secret-must-not-export", e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal());
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(forged)));
        assertEquals("INVALID_EVIDENCE_SELECTION", failure.getMessage());
        assertThrows(IllegalArgumentException.class, () -> store.exportHar(List.of(forged)));
        EvidenceStore foreign = new EvidenceStore(1, 100_000, 1024);
        foreign.begin("p", "p", empty(), ALLOW, 1);
        assertThrows(IllegalArgumentException.class, () -> foreign.exportJson(old));
        // Eviction disposes the only masked row; the historical seal alone no longer authorizes export.
        store.begin("p", "p", empty(), ALLOW, 2);
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
    void secretReflectedIntoIntentRunPathAndStructuredCopiesNeverExports(String header) {
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
        String masked = Json.write(store.snapshot()) + store.exportJson(store.snapshot()) + store.exportHar(store.snapshot()) + Json.write(store.stats());
        assertFalse(masked.contains(secret));
        assertTrue(only(store).intentId().contains(Redactor.REDACTED));
        assertTrue(only(store).runId().contains(Redactor.REDACTED));
        assertTrue(store.rawRequest(id).contains(secret));
        assertTrue(store.rawResponse(id).contains(secret));
        assertEquals(secret, store.rawCaptureInfo(id).get("intentId"));
    }

    @Test void responseGrantIssuanceRemasksTagsPathAndOverlayIncludingStaleSelections() {
        String secret = "9437cd9e-f397-4187-8e4d-f0d9d34ac726";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request("https://fixture.test/" + secret,
                List.of(new Header("X-Cairn-Intent", secret), new Header("X-Cairn-Run", secret)), ""), ALLOW, 1);
        store.context(id, "half_open", "CIRCUIT_OPEN", secret);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                ("{\"brokerGrant\":\"" + secret + "\",\"echo\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        assertFalse(Json.write(store.snapshot()).contains(secret));
        assertFalse(store.exportJson(stale).contains(secret));
        assertFalse(store.exportHar(stale).contains(secret));
        assertEquals(Redactor.REDACTED, only(store).overlayId());
        assertEquals("half_open", only(store).outcome());
        assertTrue(store.rawUrl(id).contains(secret));
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

    @Test void arbitraryContextWarningsAndInvalidOverlayAreNeverFreeTextExportChannels() {
        String secret = "synthetic-untrusted-metadata-2468";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", empty(), new Decision(Mode.ALLOW, "ALLOW", List.of(), List.of(secret)), 1);
        store.context(id, secret, secret, secret);
        assertEquals("pending", only(store).outcome());
        assertEquals("", only(store).guardState());
        assertEquals("", only(store).overlayId());
        assertEquals(List.of("INSPECTION_UNAVAILABLE"), only(store).inspectionWarnings());
        assertFalse(store.exportJson(store.snapshot()).contains(secret));
        assertFalse(store.exportHar(store.snapshot()).contains(secret));
        store.outcome(id, "BLOCKED", "CIRCUIT_OPEN", 451);
        store.context(id, "exempt", "CIRCUIT_OPEN", "");
        assertEquals("blocked", only(store).outcome());
    }

    @Test void warningsAreCategoricalBoundedAndCannotHideCaptureIncompleteness() {
        EvidenceStore store = new EvidenceStore();
        RequestData partial = new RequestData("POST", "https://fixture.test/", "fixture.test", 443, true,
                List.of(), new byte[0], false, false);
        store.begin("p", "p", partial, new Decision(Mode.ALLOW, "ALLOW", List.of(),
                java.util.Collections.nCopies(1000, "untrusted-warning-secret")), 1);
        TrafficEntry entry = only(store);
        assertTrue(entry.truncated());
        assertTrue(entry.inspectionWarnings().size() <= 32);
        assertTrue(entry.inspectionWarnings().contains("HEADERS_INCOMPLETE"));
        assertTrue(entry.inspectionWarnings().contains("BODY_INCOMPLETE"));
        assertFalse(store.exportJson(store.snapshot()).contains("untrusted-warning-secret"));
        assertFalse(store.exportHar(store.snapshot()).contains("untrusted-warning-secret"));
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
