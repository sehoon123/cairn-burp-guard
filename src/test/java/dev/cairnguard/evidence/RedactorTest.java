package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RedactorTest {
    private static final String SECRET = "synthetic-credential-needle";
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());

    private static RequestData request(String contentType, String body) {
        return new RequestData("POST", "https://fixture.test/route", "fixture.test", 443, true,
                List.of(new Header("Content-Type", contentType)), body.getBytes(StandardCharsets.UTF_8));
    }
    private static TrafficEntry capture(RequestData request) {
        EvidenceStore store = new EvidenceStore();
        store.begin("fixture", "Synthetic review", request, ALLOW, 1);
        TrafficEntry result = store.snapshot().getFirst();
        assertFalse(Json.write(result).contains(SECRET), Json.write(result));
        assertFalse(store.exportJson(store.snapshot()).contains(SECRET));
        assertFalse(store.exportHar(store.snapshot()).contains(SECRET));
        return result;
    }

    @ParameterizedTest
    @ValueSource(strings = {"Authorization", "pRoXy-AuThOrIzAtIoN", "COOKIE", "Set-Cookie", "X-API-Key", "X-Auth-Token", "X-Key", "Authentication-Info"})
    void sensitiveHeadersAndTheirReflectionsAreMasked(String header) {
        RequestData request = new RequestData("GET", "https://fixture.test/" + SECRET + "?echo=" + SECRET,
                "fixture.test", 443, true, List.of(new Header(header, SECRET), new Header("X-Echo", "before " + SECRET + " after")), new byte[0]);
        TrafficEntry e = capture(request);
        assertEquals("[REDACTED]", e.requestCapture().headers().getFirst().value());
        assertTrue(e.requestCapture().headers().get(1).value().contains("[REDACTED]"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "PASSword", "api_key", "accessToken", "client-secret", "a[session_id]", "credentials", "%2570assword", "account.pin"})
    void nestedJsonSecretKeysCaseEncodingAndArrayValuesAreMasked(String key) throws Exception {
        String body = "{\"outer\":[{\"" + key + "\":{\"value\":\"" + SECRET + "\"},\"echo\":\"" + SECRET + "\",\"safe\":\"visible\"}]}";
        TrafficEntry e = capture(request("application/json", body));
        assertFalse(e.requestCapture().bodyOmitted());
        assertTrue(e.requestCapture().body().contains("[REDACTED]"));
        assertEquals("visible", Json.MAPPER.readTree(e.requestCapture().body()).at("/outer/0/safe").asText());
    }

    @Test void unicodeEscapedJsonKeysAndValuesAndStringifiedStructuresAreRedacted() {
        for (String body : List.of(
                "{\"p\\u0061ssword\":\"synthetic-credential-\\u006eeedle\",\"echo\":\"" + SECRET + "\"}",
                "{\"envelope\":\"{\\\"token\\\":\\\"" + SECRET + "\\\",\\\"echo\\\":\\\"" + SECRET + "\\\"}\"}",
                "{\"envelope\":\"password%3D" + SECRET + "%26echo%3D" + SECRET + "\"}",
                "{\"message\":\"log prefix {\\\"token\\\":\\\"" + SECRET + "\\\"} suffix\"}")) {
            TrafficEntry e = capture(request("application/json; charset=UTF-8", body));
            assertTrue(e.requestCapture().body().contains("[REDACTED]") || e.requestCapture().body().contains("%5BREDACTED%5D"), e.requestCapture().body());
        }
    }

    @Test void queryFormNestedPercentKeysAndValuesAndPlusSemanticsAreSafe() {
        String form = "%2570assword=" + SECRET + "&envelope=token%253D" + SECRET + "%2526safe%253Dok&safe=hello+world";
        RequestData request = new RequestData("POST", "https://fixture.test/a+b?%2574oken=" + SECRET + "&safe=hello+world&echo=" + SECRET,
                "fixture.test", 443, true, List.of(new Header("Content-Type", "application/x-www-form-urlencoded")), form.getBytes(StandardCharsets.UTF_8));
        TrafficEntry e = capture(request);
        assertFalse(e.requestCapture().bodyOmitted());
        assertTrue(e.url().contains("/a%2Bb?"), e.url());
        assertTrue(e.url().contains("safe=hello%20world"), e.url());
        assertTrue(e.requestCapture().body().contains("hello%20world"));
    }

    @Test void quotedCookieValuesAndMalformedQuotesDoNotLeakReflections() {
        for (String value : List.of("sid=\"fixture;quoted-cookie\"", "sid=\"fixture;quoted-cookie")) {
            EvidenceStore store = new EvidenceStore();
            String id = store.begin("local", "review", new RequestData("GET", "https://fixture.test/", "fixture.test", 443, true,
                    List.of(new Header("Cookie", value), new Header("X-Echo", "fixture;quoted-cookie")), new byte[0]), ALLOW, 1);
            assertEquals(Redactor.REDACTED, store.snapshot().getFirst().requestCapture().headers().getLast().value());
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                    "{\"echo\":\"fixture;quoted-cookie\"}".getBytes(StandardCharsets.UTF_8));
            assertFalse(store.exportJson(store.snapshot()).contains("fixture;quoted-cookie"));
        }
    }

    @Test void quotedOrMalformedBearerCredentialsCannotEscapeViaEchoFields() {
        for (String value : List.of("Bearer \"fixture-quoted-bearer\"", "Bearer \"fixture-quoted-bearer")) {
            EvidenceStore store = new EvidenceStore();
            store.begin("local", "review", new RequestData("GET", "https://fixture.test/", "fixture.test", 443, true,
                    List.of(new Header("Authorization", value), new Header("X-Echo", "fixture-quoted-bearer")), new byte[0]), ALLOW, 1);
            assertEquals(Redactor.REDACTED, store.snapshot().getFirst().requestCapture().headers().getLast().value());
            assertFalse(store.exportHar(store.snapshot()).contains("fixture-quoted-bearer"));
        }
    }

    @Test void declaredAsciiRejectsNonAsciiAndDuplicateCharsetsAreAmbiguous() {
        for (String type : List.of("application/json; charset=us-ascii", "application/json; charset=utf-8;charset=windows-1252")) {
            TrafficEntry e = capture(request(type, "{\"safe\":\"한글\",\"password\":\"" + SECRET + "\"}"));
            assertTrue(e.requestCapture().bodyOmitted());
        }
    }

    @Test void basicAuthorizationDecodedAndBase64ReflectionsAreMasked() {
        String password = "fixture-basic-password";
        String basic = Base64.getEncoder().encodeToString(("fixture-user:" + password).getBytes(StandardCharsets.UTF_8));
        String encodedPassword = Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "review", new RequestData("GET", "https://fixture.test/",
                "fixture.test", 443, true, List.of(new Header("Authorization", "Basic " + basic)), new byte[0]), ALLOW, 1);
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                ("{\"echo\":\"prefix" + password + "suffix\",\"encoded\":\"" + encodedPassword + "\",\"original\":\"" + basic + "\"}").getBytes(StandardCharsets.UTF_8));
        String output = store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
        assertFalse(output.contains(password), output);
        assertFalse(output.contains(encodedPassword), output);
        assertFalse(output.contains(basic), output);
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/html", "text/plain", "application/xml", "application/octet-stream", "multipart/form-data; boundary=fixture"})
    void unstructuredAndBinaryBodiesAreOmittedRatherThanGuessMasked(String type) {
        TrafficEntry e = capture(request(type, "unstructured hidden credentials " + SECRET));
        assertTrue(e.requestCapture().bodyOmitted());
        assertEquals(Redactor.OMITTED, e.requestCapture().body());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"password\":\"synthetic-credential-needle\"", "{\"password\":\"first\",\"password\":\"synthetic-credential-needle\"}",
            "{\"password\":\"synthetic-credential-needle\"} {}", "[1,]", "null trailing", ""})
    void malformedDuplicateAndTrailingJsonNeverLeak(String body) {
        TrafficEntry e = capture(request("application/json", body));
        if (body.isEmpty()) assertEquals("", e.requestCapture().body());
        else {
            assertTrue(e.requestCapture().bodyOmitted());
            assertEquals(Redactor.OMITTED, e.requestCapture().body());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"password=synthetic-credential-needle&bad=%GG", "password=%C0%AFsynthetic-credential-needle", "password=%2525252573ynthetic-credential-needle", "password=synthetic-credential-needle&&safe=x"})
    void malformedOrOverEncodedFormIsOmittedInFull(String body) {
        TrafficEntry e = capture(request("application/x-www-form-urlencoded", body));
        assertTrue(e.requestCapture().bodyOmitted());
        assertEquals(Redactor.OMITTED, e.requestCapture().body());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://fixture.test/?token=synthetic-credential-needle&bad=%GG", "https://fixture.test/%2525252574oken/synthetic-credential-needle", "not a URL synthetic-credential-needle", "https://fixture.test/?password=synthetic-credential-needle&bad=%C0%AF"})
    void malformedUrlsAreReplacedNotPartiallyCaptured(String url) {
        TrafficEntry e = capture(new RequestData("GET", url, "fixture.test", 443, true, List.of(), new byte[0]));
        assertEquals(Redactor.REDACTED_URL, e.url());
    }

    @Test void malformedUtf8UnsupportedCompressionAndCharsetsAreOmitted() {
        for (List<Header> headers : List.of(
                List.of(new Header("Content-Type", "application/json")),
                List.of(new Header("Content-Type", "application/json"), new Header("Content-Encoding", "gzip")),
                List.of(new Header("Content-Type", "application/json;charset=windows-1252")),
                List.of(new Header("Content-Type", "application/json"), new Header("Content-Type", "text/plain")))) {
            TrafficEntry e = capture(new RequestData("POST", "https://fixture.test/", "fixture.test", 443, true, headers, new byte[] {(byte) 0xc3, 0x28}));
            assertTrue(e.requestCapture().bodyOmitted());
        }
    }

    @Test void depthStructureAndOversizeLimitsOmitWholeBodyWithoutRawPrefixTruncation() {
        String deeplyNested = "[".repeat(49) + "\"" + SECRET + "\"" + "]".repeat(49);
        String many = "[" + "0,".repeat(8200) + "\"" + SECRET + "\"]";
        String tooLarge = "{\"padding\":\"" + "p".repeat(RequestData.MAX_INSPECT_BYTES) + "\",\"password\":\"" + SECRET + "\"}";
        for (String body : List.of(deeplyNested, many, tooLarge)) {
            TrafficEntry e = capture(request("application/json", body));
            assertTrue(e.requestCapture().bodyOmitted());
            assertEquals(Redactor.OMITTED, e.requestCapture().body());
        }
    }

    @Test void arbitraryMetadataAndInjectedHeaderNamesCannotLeakOrAddRawLines() {
        EvidenceStore store = new EvidenceStore();
        RequestData request = new RequestData("GET", "https://fixture.test/", "fixture.test", 443, true,
                List.of(new Header("Authorization", "Bearer " + SECRET), new Header("X-" + SECRET, SECRET),
                        new Header("bad\r\nInjected", SECRET), new Header("X-Debug", "line1\r\n" + SECRET)), new byte[0]);
        store.begin("password=" + SECRET, "https://user:" + SECRET + "@fixture.test/", request,
                new Decision(Mode.ALLOW, SECRET, List.of(new Decision.RuleHit(SECRET, "Bearer " + SECRET, Mode.ALLOW))), 1);
        String all = store.exportJson(store.snapshot());
        assertFalse(all.contains(SECRET));
        assertTrue(all.contains("X-Omitted-Header"));
        assertFalse(store.snapshot().getFirst().requestCapture().headers().getLast().value().contains("\n"));
    }

    @Test void headerAndFingerprintCapacityFailureSuppressesInsteadOfPartialMasking() {
        List<Header> headers = new ArrayList<>();
        for (int i = 0; i < 257; i++) headers.add(new Header("X-Header-" + i, SECRET));
        TrafficEntry e = capture(new RequestData("GET", "https://fixture.test/?echo=" + SECRET, "fixture.test", 443, true, headers, new byte[0]));
        assertTrue(e.requestCapture().headers().isEmpty());
        assertTrue(e.truncated());
        StringBuilder body = new StringBuilder("{");
        for (int i = 0; i < 150; i++) body.append(i == 0 ? "" : ",").append("\"token").append(i).append("\":\"").append(SECRET).append(i).append("\"");
        e = capture(request("application/json", body.append('}').toString()));
        assertFalse(e.requestCapture().body().contains(SECRET));
        assertEquals(Redactor.REDACTED_URL, e.url());
    }

    @Test void standaloneRedactorHasSameCrossFieldGuarantee() {
        RequestData request = new RequestData("GET", "https://fixture.test/?echo=" + SECRET, "fixture.test", 443, true,
                List.of(new Header("Authorization", "Bearer " + SECRET)), new byte[0]);
        String result = new Redactor().redactRequest(request);
        assertFalse(result.contains(SECRET));
        assertTrue(result.contains("[REDACTED]"));
    }

    @Test void truncationUsesUtf8CodePointBoundariesAndHappensAfterMasking() {
        String value = "한글😀".repeat(1000);
        String result = Redactor.limit(value, 255);
        assertTrue(Redactor.bytes(result) <= 255);
        assertTrue(result.endsWith(Redactor.TRUNCATED));
        assertFalse(result.contains("\uFFFD"));
        assertFalse(Character.isHighSurrogate(result.charAt(result.indexOf(Redactor.TRUNCATED) - 1)));
    }
}
