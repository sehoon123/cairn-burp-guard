package dev.cairnguard.ui;

/** Fixed human explanations. Never echo unknown native/exception/request text into UI messages. */
final class UiText {
    private UiText() {}

    static String mode(String value) {
        if (value == null) return "—";
        return switch (value) {
            case "BLOCK" -> "차단";
            case "ASK" -> "승인 요청";
            case "ALLOW" -> "허용";
            case "MONITOR" -> "기록만";
            default -> "—";
        };
    }

    static String outcome(String value) {
        if (value == null) return "확인 필요";
        return switch (value) {
            case "BLOCKED" -> "차단됨";
            case "FORWARDED" -> "전송 해제";
            case "PENDING" -> "검사 대기";
            case "AWAITING_APPROVAL" -> "승인 대기";
            case "QUEUED" -> "전송 대기";
            case "ERROR" -> "처리 오류";
            default -> "확인 필요";
        };
    }

    static String reason(String reason) {
        if (reason == null) return "처리 상태를 확인하세요.";
        return switch (reason) {
            case "SCOPE_NOT_ALLOWED" -> "허용 대상에 포함되지 않는 요청입니다.";
            case "SCOPE_BLOCKED" -> "차단 대상으로 등록된 주소입니다.";
            case "RULE_BLOCK" -> "차단 규칙에 해당합니다.";
            case "DEFAULT_BLOCK" -> "일치하는 규칙이 없어 기본 차단이 적용됐습니다.";
            case "RULE_MATCH" -> "등록한 규칙의 조건에 해당합니다.";
            case "ASK" -> "사람의 승인을 기다리고 있습니다.";
            case "QUEUED" -> "속도·동시성 제한에 따라 전송을 기다리고 있습니다.";
            case "DEFAULT_ALLOW", "POLICY_ALLOW", "POLICY_DECISION" -> "허용 범위와 정책에 따라 처리했습니다.";
            case "NATIVE_RELEASED", "NATIVE_FORWARDED" -> "Burp에 전송을 허용했습니다. 대상에 도착했다는 뜻은 아닙니다.";
            case "DENIED" -> "사용자가 이 요청을 거절했습니다.";
            case "PAUSED" -> "보호가 일시중지 상태여서 새 요청을 차단했습니다.";
            case "APPROVAL_TIMEOUT" -> "제한 시간 안에 승인하지 않아 차단했습니다.";
            case "QUEUE_TIMEOUT" -> "전송 대기 시간이 초과되어 차단했습니다.";
            case "QUEUE_FULL", "APPROVAL_CAPACITY", "HOST_CAPACITY", "CALLBACK_CAPACITY", "INSPECTION_CAPACITY", "CORRELATION_CAPACITY" -> "안전하게 처리할 수 있는 대기·검사 용량을 초과했습니다.";
            case "IN_FLIGHT_TIMEOUT" -> "기존 요청의 응답을 확인하지 못해 새 전송을 막았습니다.";
            case "POLICY_CHANGED", "PROJECT_CHANGED", "FINAL_CHECK_REJECTED" -> "대기 중 정책 또는 프로젝트가 바뀌어 이전 요청을 차단했습니다.";
            case "SHUTDOWN", "CANCELLED" -> "종료 또는 취소된 요청입니다.";
            case "WEBSOCKET_UNSUPPORTED" -> "WebSocket 프레임은 안전 검사를 지원하지 않습니다.";
            case "UNSUPPORTED_BODY", "UNSUPPORTED_CONTENT_ENCODING", "UNSUPPORTED_TRANSFER_ENCODING", "UNSUPPORTED_CHARSET", "UNSUPPORTED_HTTP_VERSION" -> "안전하게 검사할 수 없는 본문·인코딩·프로토콜입니다.";
            case "REQUEST_TOO_LARGE", "INSPECTION_LIMIT", "ENCODING_DEPTH_EXCEEDED", "CAPTURE_LIMIT" -> "요청 크기 또는 검사 한도를 초과했습니다.";
            case "AUTHORITY_MISMATCH", "INVALID_AUTHORITY", "INVALID_HOST", "HTTP2_INCONSISTENT", "AMBIGUOUS_PATH" -> "주소·경로·실제 연결 대상이 모호하거나 일치하지 않습니다.";
            case "MALFORMED_JSON", "AMBIGUOUS_JSON_KEYS", "MALFORMED_PERCENT_ENCODING", "INVALID_TEXT_ENCODING", "INVALID_CONTENT_LENGTH", "MALFORMED_CONTENT_TYPE", "INVALID_REQUEST", "INVALID_METHOD", "INVALID_URI", "INVALID_HEADERS", "UNSUPPORTED_SCHEME" -> "요청 형식이 올바르지 않거나 해석이 모호합니다.";
            case "INVALID_CONFIG" -> "현재 정책을 안전하게 해석할 수 없습니다.";
            case "INSPECTION_ERROR", "CAPTURE_FAILED", "ADAPTER_ERROR", "CONTINUATION_FAILED", "CALLBACK_ON_EDT", "MESSAGE_ID_COLLISION" -> "요청 처리의 안전성을 확인할 수 없어 차단했습니다.";
            default -> "처리 결과의 상세 정보를 확인하세요.";
        };
    }

    static String next(String reason) {
        if (reason == null) return "상세 정보와 현재 보호 상태를 확인하세요.";
        return switch (reason) {
            case "NATIVE_RELEASED", "NATIVE_FORWARDED" -> "마스킹된 응답과 대상 측 증거를 확인하세요. 전송 해제만으로 대상 도착이나 처리 성공을 단정하지 마세요.";
            case "DEFAULT_ALLOW", "POLICY_ALLOW", "POLICY_DECISION" -> "요청 기록의 처리 결과와 마스킹된 응답을 확인하세요. 정책상 허용과 실제 대상 도착은 다릅니다.";
            case "SCOPE_NOT_ALLOWED" -> "허가받은 대상인지 확인한 뒤 ‘대상’에서 호스트·연결 방식·포트·경로를 등록하세요. 빈 허용 목록은 모든 요청을 차단합니다.";
            case "SCOPE_BLOCKED" -> "‘대상 → 차단 대상’에서 해당 범위를 확인하세요. 차단 대상은 허용 대상보다 우선합니다.";
            case "RULE_BLOCK", "RULE_MATCH" -> "아래의 일치 규칙을 확인하고 ‘규칙’에서 의도한 조건인지 검토하세요. 필수 안전 차단은 승인으로 풀 수 없습니다.";
            case "DEFAULT_BLOCK" -> "‘설정 → 설정 변경 → 상세 설정’의 기본 동작을 확인하세요. 허용 범위 밖 요청은 계속 차단됩니다.";
            case "PAUSED" -> "‘개요’에서 일시중지 사유를 확인하고, 준비됐을 때 보호를 재개하세요.";
            case "ASK" -> "‘승인 대기’에서 이 요청의 주소·이유·마스킹된 내용을 확인한 뒤 한 번 승인하거나 거절하세요.";
            case "QUEUED" -> "진행 중 요청의 완료와 전송 예산을 기다립니다. 도착 여부는 응답과 별도 증거로 확인하세요.";
            case "APPROVAL_TIMEOUT", "DENIED" -> "필요한 요청이라면 다시 실행하고 ‘승인 대기’에서 새 요청을 검토하세요. 만료된 요청은 재승인할 수 없습니다.";
            case "QUEUE_TIMEOUT", "QUEUE_FULL", "APPROVAL_CAPACITY", "HOST_CAPACITY", "CALLBACK_CAPACITY", "INSPECTION_CAPACITY", "CORRELATION_CAPACITY" -> "요청 발생 속도를 줄이세요. ‘설정’에서 속도·동시성·대기 제한을 검토하되 안전 한도를 무작정 높이지 마세요.";
            case "IN_FLIGHT_TIMEOUT" -> "먼저 요청 발생을 멈추고 Burp의 진행 중 연결을 확인하세요. 설정 저장·재개로 미완료 요청의 자리를 강제로 비우지 않습니다.";
            case "POLICY_CHANGED", "PROJECT_CHANGED", "FINAL_CHECK_REJECTED" -> "현재 프로젝트와 설정을 확인한 뒤 필요한 요청만 새로 실행하세요. 이전 승인을 재사용하지 않습니다.";
            default -> "요청 형식과 상세 진단을 확인하세요. 지원하지 않는 요청·안전 검사 실패는 허용 규칙이나 승인으로 우회할 수 없습니다.";
        };
    }

    static String error(String category) {
        return switch (category) {
            case "STALE_POLICY", "UPDATE_REJECTED" -> "설정이 바뀌었거나 저장 완료를 확인하지 못했습니다. 창을 닫고 ‘새로고침’ 후 실제 저장된 내용을 확인한 뒤 현재 설정에서 다시 편집하세요.";
            case "PROJECT_UNAVAILABLE", "REFRESH_UNAVAILABLE" -> "현재 프로젝트의 상태를 확인할 수 없습니다. Burp 프로젝트를 확인하고 ‘새로고침’을 누르세요. 확인 전에는 설정 변경과 승인을 막습니다.";
            case "INVALID_POLICY", "INVALID_BOUNDED_JSON" -> "정책을 저장할 수 없습니다. 필수 항목·숫자 범위·중복 ID·RE2 정규식과 설정 형식을 확인하세요. 기존 정책은 이 작업으로 바뀌지 않았습니다.";
            case "POLICY_ROW_LIMIT" -> "대상과 규칙은 각각 최대 256개입니다. 사용하지 않는 항목을 삭제한 뒤 추가하세요.";
            case "SELECT_RULE_FIRST" -> "먼저 편집할 규칙을 표에서 선택하세요.";
            case "SELECT_SCOPE_FIRST" -> "먼저 편집할 대상을 표에서 선택하세요.";
            case "SELECT_TRAFFIC_FIRST" -> "먼저 요청 기록에서 하나 이상의 행을 선택하세요.";
            case "SELECT_PENDING_APPROVAL_FIRST" -> "먼저 검토할 요청을 승인 대기 표에서 선택하세요.";
            case "APPROVAL_STALE_OR_EXPIRED" -> "이 요청은 만료됐거나 현재 프로젝트의 유효한 승인 대기가 아닙니다. 새로고침 후 다시 확인하세요.";
            case "APPROVAL_EVIDENCE_MISSING" -> "이 요청의 마스킹된 증거가 남아 있지 않아 승인하지 않습니다. 거절하거나 만료를 기다린 뒤 필요하면 요청을 다시 실행하세요.";
            case "NO_DISPLAYED_EVIDENCE_TO_EXPORT" -> "내보낼 요청이 없습니다. 필터를 확인하거나 내보낼 행을 먼저 선택하세요.";
            case "EXPORT_IN_PROGRESS" -> "이미 내보내는 중입니다. 완료 후 다시 시도하세요.";
            case "EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE" -> "이 위치에는 안전하게 저장할 수 없습니다. 일반 파일 이름과 접근 가능한 폴더를 선택하세요. 심볼릭 링크는 덮어쓰지 않습니다.";
            case "EXPORT_FAILED" -> "내보내기를 완료하지 못했습니다. 파일 위치와 권한을 확인하고 다시 시도하세요. 원본 요청이나 오류 내용은 기록하지 않았습니다.";
            case "CLOSED" -> "확장이 종료되어 이 작업을 저장하지 않았습니다.";
            default -> "작업을 완료하지 못했습니다. 현재 보호 상태를 새로고침하고 다시 시도하세요. 원본 오류나 요청 정보는 표시하지 않습니다.";
        };
    }
}
