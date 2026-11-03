package dev.cairnguard.ui;

import dev.cairnguard.model.DenialReasons;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UiTextTest {
    @Test void everyNativeDenialHasAFixedHumanExplanation() {
        for (String reason : DenialReasons.ALL) {
            assertNotEquals("처리 결과의 상세 정보를 확인하세요.", UiText.reason(reason), reason);
            assertFalse(UiText.reason(reason).contains(reason), reason);
            assertFalse(UiText.next(reason).isBlank(), reason);
        }
    }
    @Test void unknownInputNeverBecomesAnErrorOrHtmlMessage() {
        String unknown = "<html>synthetic-secret-untrusted</html>";
        for (String message : new String[]{UiText.error(unknown), UiText.reason(unknown), UiText.next(unknown), UiText.mode(unknown), UiText.outcome(unknown)})
            assertFalse(message.contains(unknown));
    }
    @Test void allowedNativeOutcomeDoesNotUseUnsupportedRequestTroubleshooting() {
        for (String reason : new String[]{"NATIVE_RELEASED", "NATIVE_FORWARDED", "DEFAULT_ALLOW", "POLICY_ALLOW", "POLICY_DECISION"}) {
            assertTrue(UiText.next(reason).contains("대상"), reason);
            assertFalse(UiText.next(reason).contains("지원하지 않는"), reason);
        }
    }
    @Test void realRuntimeWaitingVocabularyIsNotAnUnknownOutcome() {
        assertEquals("승인 대기", UiText.outcome("AWAITING_APPROVAL"));
        assertEquals("전송 대기", UiText.outcome("QUEUED"));
        assertTrue(UiText.reason("ASK").contains("승인"));
        assertTrue(UiText.reason("QUEUED").contains("전송"));
    }
}
