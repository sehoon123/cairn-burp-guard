package dev.cairnguard.ui;

/** Fixed human explanations. Never echo unknown native/exception/request text into UI messages. */
final class UiText {
    private UiText() {}

    static String mode(String value) {
        if (value == null) return "—";
        return switch (value) {
            case "EXEMPT" -> "EXEMPT 예외 (일반 차단 무시)";
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
            case "BLOCKED", "blocked" -> "차단됨";
            case "FORWARDED", "forwarded" -> "전송 해제";
            case "exempt" -> "EXEMPT 예외";
            case "probe_allowed" -> "상태 확인 통과";
            case "half_open" -> "회로 재확인";
            case "PENDING", "pending" -> "검사 대기";
            case "AWAITING_APPROVAL" -> "승인 대기";
            case "QUEUED" -> "전송 대기";
            case "UNPAIRED_RESPONSE", "unpaired_response" -> "응답만 기록 (요청 연결 불가)";
            case "ERROR" -> "처리 오류";
            default -> "확인 필요";
        };
    }

    static String guardState(String value) {
        if (value == null) return "상태 미확인";
        return switch (value) {
            case "PROTECTED" -> "보호 중";
            case "PAUSED_BY_OPERATOR" -> "운영자 일시중지";
            case "POLICY_INVALID" -> "정책 유효성 실패";
            case "POLICY_SAVE_UNCERTAIN" -> "정책 저장 불확실";
            case "PROJECT_UNVERIFIED" -> "프로젝트 미확인";
            case "SHUTDOWN" -> "종료";
            case "CIRCUIT_OPEN" -> "5xx 회로 열림";
            case "OVERLAY_BLOCK" -> "자동 안전 차단";
            case "INTENT_BUDGET" -> "태그 예산 소진";
            case "LISTENER_UNVERIFIED" -> "리스너 미확인";
            case "CAPACITY" -> "처리 용량 제한";
            case "IN_FLIGHT_STALLED" -> "응답 미확인 격리";
            default -> "상세 상태 확인";
        };
    }

    static String reason(String reason) {
        if (reason == null) return "처리 상태를 확인하세요.";
        return switch (reason) {
            case "SCOPE_NOT_ALLOWED" -> "허용 대상에 포함되지 않는 요청입니다.";
            case "SCOPE_BLOCKED" -> "차단 대상으로 등록된 주소입니다.";
            case "EXEMPT", "RULE_EXEMPT" -> "EXEMPT에 따라 일반 BLOCK·ASK를 무시했습니다. 범위·수동 일시중지·명시 속도·태그 예산은 유지됩니다.";
            case "HEAVY_ENDPOINT_AUTO_BLOCKED" -> "이전 버전의 대용량 자동 차단 기록입니다. 현재 기능은 제거되었습니다.";
            case "CIRCUIT_OPEN" -> "이전 버전의 5xx 회로 차단 기록입니다. 현재 기능은 제거되었습니다.";
            case "FANOUT_SUSPECTED" -> "이전 버전의 확산 자동 차단 기록입니다. 현재 기능은 제거되었습니다.";
            case "INTENT_CAPACITY", "INTENT_BUDGET_CAPACITY" -> "명시한 태그 예산 사용량을 안전하게 보관할 용량이 없습니다.";
            case "WATCHER_CAPACITY", "RESPONSE_WATCHER_CAPACITY" -> "이전 버전의 자동 감지 용량 진단입니다. 현재는 자동 감지 차단을 실행하지 않습니다.";
            case "INTENT_BUDGET_EXCEEDED" -> "같은 (Run, Intent)의 전송 예산을 소진했습니다.";
            case "INTENT_TAG_INVALID", "INVALID_INTENT_TAG" -> "예산 사용 중 태그가 중복·잘못된 형식이거나 헤더 검사 불완전입니다.";
            case "LISTENER_UNVERIFIED" -> "실제 인바운드 리스너를 확인하지 못해 내용 수집 없이 차단했습니다.";
            case "RESPONSE_CORRELATION_UNAVAILABLE" -> "응답과 요청을 안전하게 연결할 수 없습니다. 확인된 보호 출처의 응답만 별도로 보존하며 요청을 추측하지 않습니다.";
            case "PATH_INTERPRETATION_INCOMPLETE" -> "경로 해석이 불완전합니다. 모든 경로 범위는 원문 전송 가능하지만 제한 경로·경로 EXEMPT를 검증할 수 없습니다.";
            case "HEADERS_INCOMPLETE", "BODY_INCOMPLETE" -> "선택 헤더/본문 수집이 불완전합니다. 이 표시만으로 규칙이 해당 필드를 요구했다는 뜻은 아니며 형식 자체로 자동 차단하지 않습니다.";
            case "HEADER_INSPECTION_UNAVAILABLE", "BODY_INSPECTION_UNAVAILABLE" -> "규칙이 요구한 헤더/본문 조건을 검사할 수 없어 해당 조건을 평가하지 못했습니다 (형식 자체로 자동 차단하지 않음).";
            case "RULE_BLOCK" -> "차단 규칙에 해당합니다.";
            case "DEFAULT_BLOCK" -> "일치하는 규칙이 없어 기본 차단이 적용됐습니다.";
            case "RULE_MATCH" -> "등록한 규칙의 조건에 해당합니다.";
            case "ASK" -> "사람의 승인을 기다리고 있습니다.";
            case "QUEUED" -> "작성한 속도 제한에 따라 전송을 기다리고 있습니다.";
            case "DEFAULT_ALLOW", "POLICY_ALLOW", "POLICY_DECISION" -> "허용 범위와 정책에 따라 처리했습니다.";
            case "NATIVE_RELEASED", "NATIVE_FORWARDED" -> "Burp에 전송을 허용했습니다. 대상에 도착했다는 뜻은 아닙니다.";
            case "DENIED" -> "사용자가 이 요청을 거절했습니다.";
            case "PAUSED" -> "보호가 일시중지 상태여서 새 요청을 차단했습니다.";
            case "APPROVAL_TIMEOUT" -> "제한 시간 안에 승인하지 않아 차단했습니다.";
            case "QUEUE_TIMEOUT" -> "전송 대기 시간이 초과되어 차단했습니다.";
            case "QUEUE_FULL", "APPROVAL_CAPACITY", "HOST_CAPACITY", "CALLBACK_CAPACITY", "INSPECTION_CAPACITY", "CORRELATION_CAPACITY" -> "안전하게 처리할 수 있는 대기·검사 용량을 초과했습니다.";
            case "IN_FLIGHT_TIMEOUT" -> "이전 버전의 응답 미확인 격리 기록입니다. 현재는 제거되었으며 이전 응답·콜백을 기다려 새 요청을 차단하지 않습니다.";
            case "POLICY_CHANGED", "PROJECT_CHANGED", "FINAL_CHECK_REJECTED" -> "대기 중 정책 또는 프로젝트가 바뀌어 이전 요청을 차단했습니다.";
            case "SHUTDOWN", "CANCELLED" -> "종료 또는 취소된 요청입니다.";
            case "WEBSOCKET_UNSUPPORTED" -> "WebSocket 프레임은 안전 검사를 지원하지 않습니다.";
            case "UNSUPPORTED_BODY", "UNSUPPORTED_CONTENT_ENCODING", "UNSUPPORTED_TRANSFER_ENCODING", "UNSUPPORTED_CHARSET", "UNSUPPORTED_HTTP_VERSION" -> "선택 본문·인코딩·프로토콜 검사가 불가합니다. 형식만으로 자동 차단하지 않으며 검사 경고를 확인하세요.";
            case "REQUEST_TOO_LARGE", "INSPECTION_LIMIT", "ENCODING_DEPTH_EXCEEDED", "CAPTURE_LIMIT" -> "요청 크기 또는 검사 한도를 초과했습니다.";
            case "INVALID_AUTHORITY", "INVALID_HOST" -> "실제 연결 대상 메타데이터를 확인할 수 없습니다.";
            case "AUTHORITY_MISMATCH", "HTTP2_INCONSISTENT", "AMBIGUOUS_PATH" -> "이전 버전의 검사 진단입니다. 현재 범위는 실제 목적지를 사용하며 Host fuzz나 모든 경로의 세미콜론/인코딩 자체를 자동 차단하지 않습니다.";
            case "MALFORMED_JSON", "AMBIGUOUS_JSON_KEYS", "MALFORMED_PERCENT_ENCODING", "INVALID_TEXT_ENCODING", "INVALID_CONTENT_LENGTH", "MALFORMED_CONTENT_TYPE", "INVALID_REQUEST", "INVALID_METHOD", "INVALID_URI", "INVALID_HEADERS", "UNSUPPORTED_SCHEME" -> "요청 형식이 올바르지 않거나 해석이 모호합니다.";
            case "INVALID_CONFIG" -> "현재 정책을 안전하게 해석할 수 없습니다.";
            case "INSPECTION_ERROR", "CAPTURE_FAILED", "ADAPTER_ERROR", "CONTINUATION_FAILED", "CALLBACK_ON_EDT", "MESSAGE_ID_COLLISION" -> "요청 처리의 안전성을 확인할 수 없어 차단했습니다.";
            default -> "처리 결과의 상세 정보를 확인하세요.";
        };
    }

    /**
     * Human labels for inspection warning IDs. Capture flags (HEADERS_/BODY_INCOMPLETE) are
     * recorded regardless of rule demand; only FIELD_INSPECTION_UNAVAILABLE_* proves a rule asked for the
     * field. Unknown or literal IDs are shown plainly under a fixed "unknown code" label; none is hidden or counted away.
     */
    static String warnings(java.util.List<String> ids, boolean withCodes) {
        if (ids == null || ids.isEmpty()) return "없음";
        java.util.LinkedHashSet<String> labels = new java.util.LinkedHashSet<>();
        for (String id : ids) {
            String label = warning(id);
            if (label == UNKNOWN_WARNING) labels.add(id == null ? UNKNOWN_WARNING : UNKNOWN_WARNING + ": " + id);
            else labels.add(withCodes || label.contains(OTHER_CAUSE) ? label + " [" + id + "]" : label); // the classification alone cannot tell unknown causes apart
        }
        return String.join(" · ", labels);
    }

    private static final String UNKNOWN_WARNING = "알 수 없는 경고 코드";
    private static final String INSPECTION_UNAVAILABLE = "_INSPECTION_UNAVAILABLE_";
    private static final String OTHER_CAUSE = "기타 분류";

    private static String warning(String id) {
        if (id == null) return UNKNOWN_WARNING;
        switch (id) {
            case "HEADERS_INCOMPLETE": return "헤더 수집 불완전 (선택 수집, 규칙이 헤더를 요구했다는 뜻은 아님)";
            case "BODY_INCOMPLETE": return "본문 수집 불완전 (선택 수집, 규칙이 본문을 요구했다는 뜻은 아님)";
            case "PATH_INTERPRETATION_INCOMPLETE": return "경로 해석 불완전 (모든 경로 범위는 원문 전송 가능, 제한 경로·경로 EXEMPT는 증명 불가)";
            case "INSPECTION_UNAVAILABLE": return "규칙 조건 검사 불가 (세부 분류 미보존, 평가 완료로 보지 않음)";
            default: break;
        }
        int split = id.indexOf(INSPECTION_UNAVAILABLE);
        if (split <= 0) return UNKNOWN_WARNING;
        String field = switch (id.substring(0, split)) {
            case "URL" -> "URL"; case "QUERY" -> "쿼리"; case "HEADER" -> "헤더"; case "BODY" -> "본문";
            case "JSON" -> "JSON"; case "FORM" -> "폼"; case "ANY" -> "ANY"; case "METHOD" -> "메서드"; case "PATH" -> "경로";
            default -> null;
        };
        if (field == null) return UNKNOWN_WARNING;
        String cause = switch (id.substring(split + INSPECTION_UNAVAILABLE.length())) {
            case "CAPTURE_INCOMPLETE" -> "수집 불완전";
            case "REQUEST_TOO_LARGE", "INSPECTION_LIMIT", "ENCODING_DEPTH_EXCEEDED" -> "크기·검사 한도 초과";
            case "INSPECTION_CAPACITY" -> "검사 슬롯 부족 (원문은 전부 수집됨, 이 조건만 평가 불가)";
            case "UNSUPPORTED_CHARSET" -> "지원하지 않는 문자셋";
            case "UNSUPPORTED_BODY" -> "지원하지 않는 본문 형식";
            case "UNSUPPORTED_CONTENT_ENCODING", "UNSUPPORTED_TRANSFER_ENCODING" -> "지원하지 않는 전송·콘텐츠 인코딩";
            case "MALFORMED_JSON", "AMBIGUOUS_JSON_KEYS" -> "JSON 형식 오류·중복 키";
            case "INVALID_TEXT_ENCODING", "MALFORMED_PERCENT_ENCODING" -> "텍스트·퍼센트 인코딩 오류";
            case "INVALID_HEADERS", "MALFORMED_CONTENT_TYPE" -> "헤더·Content-Type 형식 오류";
            case "INSPECTION_ERROR" -> "검사 오류";
            default -> OTHER_CAUSE;
        };
        return field + " 조건 검사 불가: " + cause + " (규칙이 요구한 필드, 평가 완료로 보지 않음)";
    }

    static String next(String reason) {
        if (reason == null) return "상세 정보와 현재 보호 상태를 확인하세요.";
        return switch (reason) {
            case "NATIVE_RELEASED", "NATIVE_FORWARDED" -> "화면 원문은 민감정보를 포함합니다. 응답과 대상 측 증거를 확인하되 전송 해제만으로 대상 도착이나 처리 성공을 단정하지 마세요.";
            case "DEFAULT_ALLOW", "POLICY_ALLOW", "POLICY_DECISION", "EXEMPT", "RULE_EXEMPT" -> "요청 기록의 처리 결과·검사 경고·응답을 확인하세요. 정책상 허용과 실제 대상 도착은 다릅니다.";
            case "CIRCUIT_OPEN", "HEAVY_ENDPOINT_AUTO_BLOCKED", "FANOUT_SUSPECTED", "WATCHER_CAPACITY", "RESPONSE_WATCHER_CAPACITY" -> "이전 버전의 자동 차단 진단입니다. 현재 기능은 제거되었습니다. 대상 장애로 단정하지 마세요.";
            case "INTENT_BUDGET_EXCEEDED", "INTENT_TAG_INVALID", "INVALID_INTENT_TAG", "INTENT_CAPACITY", "INTENT_BUDGET_CAPACITY" -> "‘설정’의 태그 한도와 클라이언트 X-Cairn 태그를 검토하세요. 초기화는 ‘개요’에서 명시 확인해야 하며 태그는 인증이 아닙니다.";
            case "LISTENER_UNVERIFIED" -> "이전 포트 제한이 남아 있습니다. 포트별 보호는 추후 지원하므로 ‘설정’에서 기존 목록을 직접 비우고 모든 Proxy 보호 전환을 확인해 저장하세요. 자동 삭제나 리스너 추정은 하지 않습니다.";
            case "PATH_INTERPRETATION_INCOMPLETE" -> "명시적 모든 경로 범위에서 원래 target은 바꾸지 않습니다. 제한 경로·명시 차단은 계속 검사하며 불완전 경로로 EXEMPT를 부여하지 않습니다.";
            case "SCOPE_NOT_ALLOWED" -> "허가받은 대상인지 확인한 뒤 ‘대상’에서 호스트·연결 방식·포트·경로를 등록하세요. 빈 허용 목록은 모든 요청을 차단합니다.";
            case "SCOPE_BLOCKED" -> "‘대상 → 차단 대상’에서 해당 범위를 확인하세요. 차단 대상은 허용 대상보다 우선합니다.";
            case "RULE_BLOCK", "RULE_MATCH" -> "아래의 일치 규칙을 확인하고 ‘규칙’에서 의도한 조건인지 검토하세요. 필수 안전 차단은 승인으로 풀 수 없습니다.";
            case "DEFAULT_BLOCK" -> "‘설정 → 설정 변경 → 상세 설정’의 기본 동작을 확인하세요. 허용 범위 밖 요청은 계속 차단됩니다.";
            case "PAUSED" -> "‘개요’에서 일시중지 사유를 확인하고, 준비됐을 때 보호를 재개하세요.";
            case "ASK" -> "‘승인 대기’에서 이 요청의 원문 주소·이유·내용을 확인한 뒤 한 번 승인하거나 거절하세요.";
            case "QUEUED" -> "작성한 전송 간격을 기다립니다. 이전 응답·완료를 기다리지 않습니다. 도착 여부는 응답과 별도 증거로 확인하세요.";
            case "APPROVAL_TIMEOUT", "DENIED" -> "필요한 요청이라면 다시 실행하고 ‘승인 대기’에서 새 요청을 검토하세요. 만료된 요청은 재승인할 수 없습니다.";
            case "QUEUE_TIMEOUT", "QUEUE_FULL", "APPROVAL_CAPACITY", "HOST_CAPACITY", "CALLBACK_CAPACITY", "INSPECTION_CAPACITY", "CORRELATION_CAPACITY" -> "요청 발생 속도를 줄이세요. ‘설정’에서 작성한 속도·대기 제한을 검토하되 안전 한도를 무작정 높이지 마세요.";
            case "IN_FLIGHT_TIMEOUT" -> "이전 버전의 응답 미확인 격리 기록입니다. 현재는 제거되었으며 이전 응답·콜백을 기다려 새 요청을 차단하지 않습니다.";
            case "POLICY_CHANGED", "PROJECT_CHANGED", "FINAL_CHECK_REJECTED" -> "현재 프로젝트와 설정을 확인한 뒤 필요한 요청만 새로 실행하세요. 이전 승인을 재사용하지 않습니다.";
            default -> "실제 목적지·정책·검사 경고·보호 상태를 확인하세요. 선택 헤더/본문이 해석 불가여도 형식 자체로 자동 거절하지 않습니다. 범위·유효성·용량 등 필수 거절은 승인으로 우회할 수 없습니다.";
        };
    }

    static String error(String category) {
        return switch (category) {
            case "STALE_POLICY", "UPDATE_REJECTED" -> "설정이 바뀌었거나 저장 완료를 확인하지 못했습니다. 창을 닫고 ‘새로고침’ 후 실제 저장된 내용을 확인한 뒤 현재 설정에서 다시 편집하세요.";
            case "MODE_CHANGE_REJECTED" -> "보호 상태 전환을 완료하지 못했습니다. 프로젝트·설정 버전과 현재 보호 상태를 새로고침한 뒤 다시 확인하세요. 프로젝트를 확인할 수 없거나 정책 재확인이 필요하면 전체 통과로 전환하지 않습니다.";
            case "PROJECT_UNAVAILABLE", "REFRESH_UNAVAILABLE" -> "현재 프로젝트의 상태를 확인할 수 없습니다. Burp 프로젝트를 확인하고 ‘새로고침’을 누르세요. 확인 전에는 설정 변경과 승인을 막습니다.";
            case "INVALID_POLICY", "INVALID_BOUNDED_JSON" -> "정책을 저장할 수 없습니다. 필수 항목·숫자 범위·중복 ID·RE2 정규식과 설정 형식을 확인하세요. 기존 정책은 이 작업으로 바뀌지 않았습니다.";
            case "LISTENER_SELECTION_DEFERRED" -> "포트별 보호는 추후 지원합니다. 이번 버전은 빈 목록으로 모든 Proxy 리스너를 보호합니다. 새 포트 제한은 저장하지 않았습니다. 기존 제한은 직접 비운 뒤 전체 보호 전환을 확인하세요.";
            case "POLICY_ROW_LIMIT" -> "대상과 규칙은 각각 최대 256개입니다. 사용하지 않는 항목을 삭제한 뒤 추가하세요.";
            case "SELECT_OVERLAY_FIRST" -> "먼저 해제할 자동 차단을 표에서 선택하세요.";
            case "SELECT_CANDIDATE_FIRST" -> "먼저 대용량 후보를 표에서 선택하세요.";
            case "CANDIDATE_UNSAFE" -> "이 후보의 원문 출처가 없거나(만료·비움) 이 동작에 쓸 수 있는 경로가 아닙니다. 후보를 새로고침하거나 재관측한 뒤 다시 시도하거나 설정에서 직접 작성하세요.";
            case "OVERLAY_EXCEPTION_STALE" -> "선택한 자동 차단이 만료·해제·교체됐거나 원문 출처·프로젝트·설정이 바뀌어 예외를 저장하지 않았습니다. 새로고침 후 현재 항목에서 다시 검토하세요.";
            case "OVERLAY_EXCEPTION_UNAVAILABLE" -> "이 자동 차단에는 저장할 수 있는 정확한 원문 경로가 없습니다(원문 만료·인코딩/별칭 경로·원인 요청 없음·표 가득 참). 필요하면 설정에서 직접 작성하세요.";
            case "CANDIDATE_STALE" -> "후보가 만료·변경됐습니다. 새로고침 후 현재 후보에서 다시 작성하세요.";
            case "INVALID_INCIDENT_WINDOW" -> "UTC ISO-8601 (끝 Z)의 시작·끝을 입력하세요. [시작, 끝) 창은 끝이 시작보다 뒤여야 하고 1밀리초 단위여야 합니다.";
            case "SELECT_RULE_FIRST" -> "먼저 편집할 규칙을 표에서 선택하세요.";
            case "SELECT_SCOPE_FIRST" -> "먼저 편집할 대상을 표에서 선택하세요.";
            case "SELECT_TRAFFIC_FIRST" -> "먼저 요청 기록에서 하나 이상의 행을 선택하세요.";
            case "SELECT_PENDING_APPROVAL_FIRST" -> "먼저 검토할 요청을 승인 대기 표에서 선택하세요.";
            case "APPROVAL_STALE_OR_EXPIRED" -> "이 요청은 만료됐거나 현재 프로젝트의 유효한 승인 대기가 아닙니다. 새로고침 후 다시 확인하세요.";
            case "APPROVAL_EVIDENCE_MISSING" -> "이 요청의 증거가 남아 있지 않아 승인하지 않습니다. 거절하거나 만료를 기다린 뒤 필요하면 요청을 다시 실행하세요.";
            case "NO_DISPLAYED_EVIDENCE_TO_EXPORT" -> "내보낼 요청이 없습니다. 필터를 확인하거나 내보낼 행을 먼저 선택하세요.";
            case "EXPORT_IN_PROGRESS" -> "이미 내보내는 중입니다. 완료 후 다시 시도하세요.";
            case "EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE" -> "이 위치에는 안전하게 저장할 수 없습니다. 일반 파일 이름과 접근 가능한 폴더를 선택하세요. 심볼릭 링크는 덮어쓰지 않습니다.";
            case "EXPORT_FAILED" -> "내보내기를 완료하지 못했습니다. 파일 위치와 권한을 확인하고 다시 시도하세요. 원본 요청이나 오류 내용은 기록하지 않았습니다.";
            case "CLOSED" -> "확장이 종료되어 이 작업을 저장하지 않았습니다.";
            default -> "작업을 완료하지 못했습니다. 현재 보호 상태를 새로고침하고 다시 시도하세요. 원본 오류나 요청 정보는 표시하지 않습니다.";
        };
    }
}
