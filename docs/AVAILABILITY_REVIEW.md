# 가용성·귀속·정책 확장 명세 검토 초안 — 2026-11-04

> **이하 내용은 과거 설계 검토이며 현재 구현/수용 현황이 아닙니다. 4자 검토/합의는 미완료입니다.** 최신 실제 검사·HEX 수정·H 미지원 및 독립 감사 차단 상태는 [V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md)·[VERIFICATION.md](VERIFICATION.md)를 따릅니다.
> 현재 코드에 EXEMPT, ResponseWatcher, 자동 overlay, intent 예산, 사고 bundle, 호스트 RR, 리스너 선택, schema2를 추가했다는 뜻이 아닙니다. 기존 기본 `ANY CONTAINS delete` 규칙 제거도 아직 이 작업에 포함하지 않았습니다.

## 검토 상태

- 이전 모달/전체 통과 후보는 요청 모델의 독립 검토 3건을 받았습니다. OFF/프로젝트 불확실성에서 내용이 수집되는 결함 등을 수정했습니다. 이는 아래 확장 명세의 검토 3건을 대신하지 않습니다.
- 확장 명세는 오케스트레이터의 독립 초안과 `claude-advantage-assist` **1명**의 독립 1차 검토가 완료되었습니다. 그 검토자는 이후 기존 수정도 따로 확인했습니다.
- 나머지 요청 모델 2개 세션은 제공자 측 요청 중단으로 최초/순차 재시도 모두 시작하지 못했습니다. 모델을 임의 대체하거나 인증 설정을 변경하지 않았으며, 미실시 세션을 완료된 검토로 세지 않습니다.
- 완료한 검토자가 복제·재현한 소스/JAR은 `5c7839e3bb0cf4dcff44a4e338587ce2d1b67406629944006eb22f4d8d3a0a69` 당시 후보입니다: Java839/25 suites, 재빌드 hash 일치. 실제 Burp나 desktop 입력 검사를 독립 재실행한 것은 아닙니다.
- 그 이후의 **버그 수정 범위**는 지정 모델의 별도 독립 코드 검토를 받았습니다: 비교 값 공백/줄바꿈 경고, 선택 해제 시 상세 숨김, fast-path 상태 가시성, 발급 응답의 grant 마스킹. 남아 있던 레이아웃의 in-pass 재검증 결함도 수정하고 별도 좁은 후속 검토를 받았습니다. 이 검토들은 위 확장 명세의 미실시2건을 대신하지 않습니다. 로컬 자동 검사 결과는 [VERIFICATION.md](VERIFICATION.md), native 구분은 [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md)를 따릅니다.
- 전체 합의·확장 기능 구현 승인은 여전히 미완료입니다. 사용자의 명시 배포 요청에 따라 모달·조건 추가·전체 통과 수정 범위만 **제한된 개발 프리뷰**로 배포하며, 최신 JAR의 실제 Burp 검증이나 운영 안전성 인증을 주장하지 않습니다. 원본 세션 기록/로그/스크린샷/프로필은 게시하지 않습니다.

## 우선 결정할 사항

| 주제 | 검토 결과 / 아직 결정할 계약 |
|---|---|
| EXEMPT | 범위·검사·프로젝트/정책 유효성은 절대 우회하지 않음. 다른 BLOCK/ASK 규칙만 무력화하고 pause/자동 차단/rate는 유지하는 해석을 권장. intent 예산까지 제외할지는 검토자 간 차이가 있어 미결정. 기본 동작 EXEMPT와 광범위 예외는 금지/강한 확인이 필요. 표시상 위쪽 고정은 저장 순서 변경이 아님. |
| 기본 delete 오탐 | 제안한 PATH 정규식도 정상 GET의 delete 부분문자열과 `dropdown`을 차단함. `PATH REGEX .*`와의 AND는 아무 조건을 추가하지 않으며 규칙은 이미 허용 범위 안에서만 실행됨. 새 기본값은 DELETE 메서드 차단만 유지하는 방향을 권장. 기존 v1의 실제 저장 규칙은 자동 삭제하지 않고 **원본 기본 규칙 전체가 같은 경우만** 별도 변경안/명시적 동의를 제시. |
| schema1→2 | 마지막 단계가 아니라 **첫 설계 단계**. 버전별 엄격 DTO/검증이 필요하며 새 primitive 필드를 기존 record에 단순 추가하면 과거 문서가 로드 실패할 수 있음. v1의 새 감시값은 모두 off, 로드 시 쓰기 금지, diff 미리보기·취소·명시 저장·실패/rollback을 시험. storage key/구버전 동작도 결정해야 함. |
| 무거운 응답 | 응답을 받은 뒤 길이를 관찰하므로 **첫 큰 응답을 예방하거나 이미 전송한 요청을 취소할 수 없음**. ‘N MiB 초과만 차단’은 미래 응답 크기를 미리 알아내는 기능이 아니라 ‘관측 후 이후 같은 endpoint 요청 차단’으로 정의해야 함. native API가 노출하는 bytes와 wire/압축 해제 크기를 혼동하지 않음. |
| ResponseWatcher 입력 | 내용 캡처 슬롯 부족/본문 생략과 무관하게 status/실제 노출 길이를 별도로 관찰해야 함. 자체 로컬451, 미매칭/중복 응답을 5xx로 세지 않음. fan-out은 응답만 보면 무응답 burst를 놓치므로 요청 commit 시점의 관측도 필요. |
| 자동 overlay | 사람 정책/정책 파일을 절대 고치지 않음. 현재 정책/모드 revision과 분리한 generation 및 최종 전송 직전 재검사가 필요. 활동 중 overlay를 LRU로 지워 fail-open하지 않음. 생성·해제·만료·용량 고갈·늦은 응답을 명시. 해제는 영구 whitelist가 아님. |
| 회로/프로브 | 단조 시계, 실제 들어온 요청만 사용, 호스트별 단일 대기/전송 probe,30초 제한, 무응답/지역 거절/늦은 결과를 정의. timeout으로 실제 미완료 native permit을 재사용하지 않음. 401/404를 회로 성공으로 볼지, GET/HEAD 제한, health GET과 half-open의 관계가 미결정. 외부 네트워크 probe 생성 금지. |
| pause | 사람이 설정한 pause와 만료 가능한 자동 PAUSE overlay를 분리. health passthrough는 기본 false, GET도 부작용 가능, 정확한 허용 대상과 별도 한도가 필요. 유효하지 않은 정책/저장 불확실/종료/범위·검사 실패를 우회하면 안 됨. |
| 전체 통과 OFF | 새 OFF 요청은 watcher/귀속/경로 통계도 수집하지 않음. 예전 보호 요청의 실제 응답/permit 정리는 계속 필요. 그 응답이 만드는 overlay가 OFF를 몰래 해제해서는 안 됨. 보호 복원 후 독립 overlay/미완료 permit이 다시 제한할 수 있음을 설명. |
| intent/run | 클라이언트 표식은 신뢰 가능한 신원이나 강제 예산 경계가 아님. `(project epoch, run, intent)` 키, 중복/너무 긴 헤더, 없는 표식, 예산 수명/초기화, queued/ASK 예약 및 최종 handoff 계산을 결정. 없는 표식을 제외할지 하나의 익명 bucket으로 제한할지는 미결정. 활동 예산을 임의 evict/reset해서 재사용 허용하지 않음. |
| 키/마스킹/한도 | host/service와 method/path 기준, query 제외, 정규화 규칙, 표시용 가림 경로와 enforcement 키 분리가 필요. 모든 endpoint/window/event/예산/probe 상태를 제한. p95는 보존 창/표본을 명시. 가려진 경로에서 잘못된 BLOCK 정규식을 자동 생성하지 않음. |
| 리스너 선택 | Montoya2026.7의 현재 HTTP enforcement 요청에는 inbound listener가 없음. Proxy의 `InterceptedRequest.listenerInterface()`와의 **실제 콜백 순서/ID 연결** 검증이 선행되어야 함. 목적지 port로 대체하면 안 됨. 미확인 listener의 처리에는 검사 지속/내용 없는 차단 견해 차이가 있으며 native PoC 전 지원을 주장하지 않음. 선택하지 않은 listener는 내용 검사·수집·예산·watcher 전에 빠져야 함. |
| per-host RR | 호스트별 FIFO와 *eligible* head RR. A의 rate/concurrency 대기가 B를 막지 않아야 하며 기존 전역 한도·취소·deadline·격리를 보존. 한 호스트가 전체 queue를 차지하는 문제와 미완료 전송으로 인한 전역 격리를 단순 RR로 해결했다고 주장하지 않음. |
| 451/status | 기존 필드와 `retryable:false`를 유지하는 additive 변경을 기본으로 검토. 상태는 문자열 note 추정이 아니라 typed provenance로 결정. circuit/overlay 외 프로젝트 불확실·stalled·capacity·budget도 표현해야 함. 표식은 로컬 결과 구분용이지 위조 방지 증명이 아님. status용 네트워크/worker control API를 추가하지 않음. |
| 사고 export | 선택한 UTC `[from,to)`와 보존 범위/누락/잘림을 표시. 세션 전체 집계만으로 과거 임의 시간 창의 정확한 top 통계를 재구성할 수 없음. bounded scalar/event snapshot과 기존 사람용0600/no-overwrite/symlink 방어를 재사용. 원본 본문/헤더/자격증명/로그를 bundle에 넣지 않음. |

## 권장 단계 — 아직 확정 계획 아님

1. gate/상태 truth table, 새 profile 기본값, schema migration과 저장/rollback 계약 및 listener capability spike.
2. 새 기본 오탐 제거와 기존 정책의 명시 diff, EXEMPT +451 typed 필드/우선순위 시험.
3. bounded overlay 기반 → heavy → circuit → request-side fanout을 각각 독립 구현·검증. 자동 정책 저장 금지.
4. 자동 차단/무거운 후보 UI와 incident export, intent reservation/lifecycle.
5. per-host RR 및 확인된 listener adapter. 호스트/키/queue 포화와 늦은 응답을 함께 검증.
6. exact-artifact native: 소유한 큰 응답·5xx/half-open·EXEMPT+BLOCK·intent 초과·두 inbound listener가 같은 목적지로 가는 경우·마스킹 export. 이전 JAR의 native 결과는 이전 artifact 기록으로만 유지.

## 조건 추가 수정 관련 후속 검토 처리

- 단일 조건 추가/AND·OR/기존 조건 보존/저장·재열기는 독립 검토자가 headless 복사본에서 동의·재현했습니다.
- 공백을 자동 trim하거나 정상 multiline BODY/JSON/정규식까지 금지하면 기존 규칙 의미가 바뀝니다. 따라서 **원본 값 유지 + Enter/공백 경고 + 눈에 보이는 제어문자 표기**를 적용했으며 후속 독립 코드 검토에서도 이 대안에 동의했습니다. 이는 미구현 EXEMPT의 넓은 조건 허용 계약까지 합의했다는 뜻은 아닙니다.
- 선택 해제 후 상세 편집이 버려지는 현상, 상태 flag 가시성, 최초 발급 응답 grant 마스킹은 수정했습니다.
- 실제 툴킷의 창 축소 후 row 높이 문제는 별도 관찰만으로도2초 이상 남는 잘림을 재현했습니다. 부모 preferred-size를 실제 폭 변경 때만 **현재 validation pass가 끝난 뒤** 재검증하도록 수정했습니다. **추가 사용자 편집 없이** 회복하는 desktop 회귀와 스크롤 영역 없는 headless 회귀를 두고, 독립 후속 검토에서도 이전/수정 코드의 잘림 차이를 재현했습니다.
- 단일 자식 AND/OR를 자동 축약하지 않는 것은 AST/불필요 metadata 보존을 위한 보수적 동작입니다. ‘묶음 추가’의 선택 leaf 감싸기 의미와 정책 전체 node 한도 안내 개선은 추가 검토 대상으로 남습니다. full-policy 검증을 우회하지 않습니다.

## 0.2.0 후보 — 심사 지적과 시험 증거 (현재 구현 기준, native 검증 아님)

| 지적 | 처리 | 증거(소스 시험) |
|---|---|---|
| 선택 캡처 불완전이 “규칙이 필드를 요구했는데 검사 못 함”으로 보임 | 사람용 표시만 분리(`UiText.warnings`). 기계 ID·정책·evidence 불변 | `UiTextTest`, `GuardPanelV2Test#trafficWarnings…`, `AvailabilityPolicyTest#pathOnlyPolicyReports…` |
| 상태가 확산 BLOCK/PAUSE의 누락 부채 거절을 PROTECTED로 표시 | 가산 키 `fanoutHistoryEnforcing`/`RemainingMillis`, CAPACITY 상태 삽입(자동 PAUSE 뒤, 회로 앞), OFF에서는 활성 게이트로 표시 안 함 | `ResponseWatcherTest#enforcingOmissionDiagnostic…`, `GuardControllerV2Test#enforcingOmissionDebt…`/`globalOmissionCapacityStatus…`, `GuardPanelV2Test#enforcingOmissionDebt…` |
| 완료된 WARN 호스트 기록이 1024 호스트 용량을 점유 | 재현 후 `commit()`에서만 유휴 진단 호스트 1개 회수, 폐기 기록은 원래 단조 만료의 누락 부채로 전환. 활성/late/회로/failure/probe cadence/enforcing 호스트는 거절 유지 | `ResponseWatcherTest#idleWarnHostHistory…`, `hostReclaimAccounts…`, `hostReclaimRefuses…` |
| RateGate 호스트 용량/공정성 | **변경 없음(기대 동작 확인)**: rate debt는 만료 전 evict 불가, eligible head RR·호스트별 FIFO | `RateGateTest#hostCapacityPreservesRateDebt…`, `activeAndQueuedHostsCannotBeEvicted…`, `eligibleHeadsRoundRobin…`(3호스트) |
| watcher 거절이 intent 예산·half-open cadence를 소모 | **변경 없음**: 최종 거절은 예산 소비 전 | `GuardControllerV2Test#finalFanoutRejection…`, `finalCommitRejectsEnforcing…`, `ResponseWatcherTest#historyCapacityRejectionDoesNotClaimHalfOpenProbe` |
| 잘못된 intent 태그/예산 분류 | **변경 없음**: 예산 한도 활성일 때만 거절 | `IntentBudgetTest#missingIntentIsUnbudgetedAndInvalidTagsRejectedOnlyWhenEnabled` |

보류: 규칙 미리보기, H(포트별 보호), 투기적 공정성 재작성. Burp 자체 `Drop all out-of-scope requests` 설정은 확장이 읽거나 바꾸지 않습니다.

## 0.2.0 확장 — 선택형 자동 차단·예외 (소스 시험 근거, native 검증 아님)

| 요구 | 처리 | 증거(소스 시험) |
|---|---|---|
| 자동 차단 종류를 골라 쓰기 | 대용량 master(기본 켜짐), 5xx 회로(선택·기본 꺼짐), 확산(경고만/서비스 차단/전체 일시정지)을 각각 설정. 끄거나 경고만으로 바꾸면 그 종류의 열린 차단만 즉시 논리 해제, 기록·누락 부채·native 자리 유지 | `ResponseWatcherTest#heavyMasterOff…`, `heavyOffOn…`, `fanoutOffOrWarn…`, `explicitCircuitOff…`, `GuardControllerV2Test#selectiveDetectorSaves…` |
| 이미 자동 차단된 항목의 예외 | 자동 차단 탭 ‘예외 검토’: 원인 요청 원문 경로 → 그 종류만의 예외(대용량 0 / 회로·확산 정확 경로), 모든 확인 뒤·CAS에서 재검증, 다른 필드 불변 | `GuardControllerV2Test#overlayExceptionReview…`, `staleReleasedCleared…`, `overlayExceptionIsUnavailable…`, `GuardPanelV2Test#overlayException…` |
| 예외 범위 | 회로·확산: 실제 서비스 + 완전한 단일 경로 HMAC, 모든 메서드·query; 대용량 0: 기존 별칭 규칙(양수 우선). 확산 예외도 적용 중 누락 부채는 우회 불가 | `ResponseWatcherTest#fanoutException…`, `explicitZeroRouteLimit…`, `WatcherRoutingInteropTest` |
| 공유 용량 차단 | 모든 자동 차단이 비강제일 때만 해제(대용량 off·회로 off·확산 off/경고). 하나라도 켜져 있으면 유지 | `ResponseWatcherTest#sharedCapacityFence…` |
| upstream 실패 후 자리 회수 | **PLATFORM_BLOCKED**: 지원되는 완료/실패 콜백 없음. TTL/추정 해제 미구현(안전성 이유) | 부모 판정 `UPSTREAM-FAILURE-ADJUDICATION` (native, 기준선) |
