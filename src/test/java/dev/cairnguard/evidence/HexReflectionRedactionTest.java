package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Reproduces the owned native fixture's body_hex echo. No real credential or network traffic. */
class HexReflectionRedactionTest {
    private static final String SECRET = "synthetic-hex-reflection-password";
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());

    @ParameterizedTest @ValueSource(strings = {"lower", "upper", "mixed"})
    void fullBodyHexAndCredentialFragmentsAreMaskedButHumanRawUiRemainsSeparate(String casing) throws Exception {
        EvidenceStore store = new EvidenceStore();
        String body = Json.write(Map.of("password", SECRET, "safe", "visible"));
        String secretHex = hex(SECRET, casing);
        String bodyHex = hex(body, casing);
        String id = store.begin("synthetic", "Owned echo regression", new RequestData("POST", "https://owned.test/safe",
                "owned.test", 443, true, List.of(new Header("Content-Type", "application/json")),
                body.getBytes(StandardCharsets.UTF_8)), ALLOW, 1);
        store.response(id, 200, List.of(new Header("Content-Type", "application/json"),
                        new Header("X-Hex-Echo", "prefix" + secretHex + "suffix")),
                Json.write(Map.of("body_hex", bodyHex, "fragment", "prefix" + secretHex + "suffix",
                        "safe", "unchanged-CaFe1234")).getBytes(StandardCharsets.UTF_8));
        String json = store.exportJson(store.snapshot()), har = store.exportHar(store.snapshot());
        for (String output : List.of(json, har, Json.write(store.entry(id)))) {
            assertFalse(output.contains(SECRET), "Plain credential leaked");
            assertFalse(output.contains(secretHex), "HEX credential leaked");
            assertFalse(output.contains(bodyHex), "Full original body HEX leaked");
        }
        assertEquals("unchanged-CaFe1234", Json.MAPPER.readTree(store.entry(id).responseCapture().body()).path("safe").asText());
        assertTrue(store.rawRequest(id).contains(SECRET), "Human-only raw UI must not use masked evidence");
        assertTrue(store.rawResponse(id).contains(bodyHex), "Raw human echo view must remain unchanged");
    }

    @ParameterizedTest @ValueSource(strings = {"lower", "upper", "mixed"})
    void mirroredHexInMetadataPathAndHeadersCannotBypassValueMasking(String casing) {
        String encoded = hex(SECRET, casing);
        EvidenceStore store = new EvidenceStore();
        store.begin("synthetic", "Owned echo", new RequestData("GET", "https://owned.test/echo/" + encoded,
                "owned.test", 443, true, List.of(new Header("X-Broker-Grant", SECRET),
                        new Header("X-Echo", "prefix" + encoded + "suffix")), new byte[0]), ALLOW, 1);
        String output = store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
        assertFalse(output.contains(SECRET));
        assertFalse(output.contains(encoded), "Mixed-case HEX path/header echo leaked");
    }

    private static String hex(String value, String casing) {
        String lower = HexFormat.of().formatHex(value.getBytes(StandardCharsets.UTF_8));
        if (casing.equals("upper")) return lower.toUpperCase(Locale.ROOT);
        if (!casing.equals("mixed")) return lower;
        StringBuilder mixed = new StringBuilder(lower);
        for (int i = 1; i < mixed.length(); i += 4) mixed.setCharAt(i, Character.toUpperCase(mixed.charAt(i)));
        return mixed.toString();
    }
}
