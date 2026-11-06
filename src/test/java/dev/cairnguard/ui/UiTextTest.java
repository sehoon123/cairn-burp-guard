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
    @Test void optionalCaptureFlagsAreNotDescribedAsAnUnevaluatedRuleCondition() {
        for (String capture : new String[]{"HEADERS_INCOMPLETE", "BODY_INCOMPLETE"}) {
            assertFalse(UiText.reason(capture).contains("평가하지"), capture);
            assertNotEquals(UiText.reason(capture), UiText.reason(capture.startsWith("HEADER") ? "HEADER_INSPECTION_UNAVAILABLE" : "BODY_INSPECTION_UNAVAILABLE"), capture);
        }
    }
    @Test void warningLabelsSeparateCaptureDemandedInspectionAndRoutingAndNeverEchoUnknownText() {
        String capture = UiText.warnings(java.util.List.of("HEADERS_INCOMPLETE", "BODY_INCOMPLETE"), true);
        assertTrue(capture.contains("수집 불완전") && capture.contains("요구했다는 뜻은 아님"), capture);
        assertFalse(capture.contains("검사 불가"), capture);
        for (String field : new String[]{"HEADER", "BODY", "JSON", "FORM", "ANY", "QUERY", "URL"}) {
            String id = field + "_INSPECTION_UNAVAILABLE_UNSUPPORTED_CHARSET";
            assertTrue(UiText.warnings(java.util.List.of(id), false).contains("조건 검사 불가: 지원하지 않는 문자셋"), id);
            assertTrue(UiText.warnings(java.util.List.of(id), true).contains("[" + id + "]"), id);
        }
        assertTrue(UiText.warnings(java.util.List.of("JSON_INSPECTION_UNAVAILABLE_MALFORMED_JSON"), false).contains("JSON 형식 오류"));
        String routing = UiText.warnings(java.util.List.of("PATH_INTERPRETATION_INCOMPLETE"), false);
        assertTrue(routing.contains("모든 경로") && routing.contains("EXEMPT"), routing);
        assertTrue(UiText.warnings(java.util.List.of("INSPECTION_UNAVAILABLE"), false).contains("검사 불가"));
        assertEquals("없음", UiText.warnings(java.util.List.of(), true));
        String secret = "<html>synthetic-secret-untrusted</html>";
        java.util.List<String> hostile = new java.util.ArrayList<>(java.util.Arrays.asList(secret, null, "BODY_INSPECTION_UNAVAILABLE_" + secret,
                secret + "_INSPECTION_UNAVAILABLE_INSPECTION_ERROR", "x".repeat(200)));
        for (boolean codes : new boolean[]{false, true}) {
            String text = UiText.warnings(hostile, codes);
            // Unknown/literal codes are shown plainly (the display is plain text) under a fixed unknown-code label, not hidden.
            assertTrue(text.contains("알 수 없는 경고 코드: " + secret) && text.contains("x".repeat(200)), text);
            assertTrue(text.contains("[REDACTED]") == false);
            for (String legacyAmbiguity : new String[]{"모호", "AMBIGUOUS"}) assertFalse(text.contains(legacyAmbiguity), text);
        }
        assertEquals("알 수 없는 경고 코드: [REDACTED]", UiText.warnings(java.util.List.of("[REDACTED]"), true), "a literal marker is just an unknown code");
        java.util.List<String> many = new java.util.ArrayList<>();
        for (String field : new String[]{"URL", "QUERY", "HEADER", "BODY", "JSON", "FORM", "ANY", "METHOD", "PATH"})
            for (String cause : new String[]{"INSPECTION_ERROR", "CAPTURE_INCOMPLETE", "REQUEST_TOO_LARGE"}) many.add(field + "_INSPECTION_UNAVAILABLE_" + cause);
        String all = UiText.warnings(many, true);
        assertFalse(all.contains("외 경고 생략"), "no label-count clipping");
        assertEquals(27, all.split(" · ").length);
    }
    @Test void distinctPrefixedUnknownWarningIdsKeepTheirCompleteOriginalAlongsideTheClassification() {
        java.util.List<String> ids = java.util.List.of("BODY_INSPECTION_UNAVAILABLE_SYNTH-A", "BODY_INSPECTION_UNAVAILABLE_SYNTH-B",
                "HEADER_INSPECTION_UNAVAILABLE_[REDACTED]", "QUERY_INSPECTION_UNAVAILABLE_<b>html-looking</b>");
        for (boolean codes : new boolean[]{false, true}) {
            String text = UiText.warnings(ids, codes);
            for (String id : ids) assertTrue(text.contains(id), codes + ": complete original " + id + " :: " + text);
            assertEquals(ids.size(), text.split(" · ").length, codes + ": distinct causes are not collapsed");
            assertTrue(text.contains("기타 분류"), "the classification stays");
        }
        assertEquals("본문 조건 검사 불가: 기타 분류 (규칙이 요구한 필드, 평가 완료로 보지 않음) [BODY_INSPECTION_UNAVAILABLE_SYNTH-A]",
                UiText.warnings(java.util.List.of("BODY_INSPECTION_UNAVAILABLE_SYNTH-A"), true));
        assertFalse(UiText.warnings(java.util.List.of("BODY_INSPECTION_UNAVAILABLE_CAPTURE_INCOMPLETE"), false).contains("["), "known compact labels stay compact");
    }
    @Test void retiredTimeoutHasHistoricalLabelsNotCurrentQuarantineOrOffRecoveryAdvice() {
        for(String text:java.util.List.of(UiText.reason("IN_FLIGHT_TIMEOUT"),UiText.next("IN_FLIGHT_TIMEOUT"))) {
            assertTrue(text.contains("이전 버전") && text.contains("제거"),text);
            assertFalse(text.contains("모두 통과")); assertFalse(text.contains("60초"));
        }
        assertTrue(UiText.outcome("unpaired_response").contains("요청 연결 불가"));
    }
}
