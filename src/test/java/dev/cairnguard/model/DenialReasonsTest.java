package dev.cairnguard.model;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class DenialReasonsTest {
    @ParameterizedTest
    @ValueSource(strings = {"HEAVY_ENDPOINT_AUTO_BLOCKED", "CIRCUIT_OPEN", "FANOUT_SUSPECTED",
            "RESPONSE_WATCHER_CAPACITY", "INVALID_INTENT_TAG", "INTENT_BUDGET_EXCEEDED",
            "INTENT_BUDGET_CAPACITY", "LISTENER_UNVERIFIED"})
    void v2FinalGateReasonsReachNativeBoundaryWithoutBeingRewritten(String reason) {
        assertTrue(DenialReasons.ALL.contains(reason));
        assertEquals(reason, DenialReasons.category(reason));
    }

    @ParameterizedTest
    @ValueSource(strings = {"raw synthetic credential", "<html>unsafe</html>", "CIRCUIT_OPEN\nprivate"})
    void arbitraryDiagnosticTextCannotBecomeANativeDenialReason(String input) {
        assertEquals("ADAPTER_ERROR", DenialReasons.category(input));
    }
}
