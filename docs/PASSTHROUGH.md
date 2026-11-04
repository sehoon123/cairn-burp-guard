# 임시 전체 통과와 확인 창 — 미배포 v2 소스

현재 작업 트리의 동작 설명입니다. 과거 공개 프리뷰 `738b41e` / JAR
`4232ae…`의 동작·검사와 구분하며 v2 설치/실제 native 수용/배포 완료를 뜻하지
않습니다. [검증 상태](VERIFICATION.md), [API](INTERFACES.md)를 함께 보세요.

## 사람에게 보이는 세 상태

| 상태 | 새 Proxy 요청 | 조작 |
|---|---|---|
| **보호 켜짐** | 보호 대상 listener에 실제 목적지/경로 범위·규칙·승인·자동 안전 제어·예산·속도/동시성 적용. 빈 허용 목록은 차단 | 기본 상태 / 상단 **보호 다시 켜기** |
| **전체 통과 · 보호 꺼짐** | 범위 밖·차단 대상·차단 규칙·지원하지 않는 검사 형식도 검사 없이 원본 continuation으로 전달 | 상단 **모두 통과 (보호 끔)…** → 경고 검토 → **모두 통과**를 명시적으로 클릭 |
| **새 요청 차단 중** | 보호 대상 listener의 새 요청을 `PAUSED` 로컬 차단. 명시한 health GET 예외는 별도. 전체 통과가 아님 | 개요 **새 요청 모두 차단** / **보호 재개** |

상태와 전체 통과/복원 버튼은 **모든 탭 위에** 계속 표시합니다. 보호 복원은 추가 위험 승인이 필요하지 않습니다. `전체 통과`는 Allow/Monitor 규칙이 아니라 사람이 명시적으로 보호 자체를 끄는 별도 runtime 상태입니다. 워커가 실행 중이면 허가 범위 밖 요청도 나갈 수 있습니다. **CAIRN 워커에는 이 버튼이나 제어 API를 제공하지 않습니다.** 인증/쿠키/세션 상태를 바꾸거나 요청을 대신 전송/재실행하는 기능도 아닙니다.

## 이미 대기하거나 전송한 요청

- **승인 대기 / 전송 대기 / 승인 뒤 전송 대기**: 모드 전환은 revision을 증가시키고 기존 대기를 취소합니다. 자동 승인하거나 전체 통과로 승격시키지 않습니다. 필요한 요청만 사람이 새로 실행합니다.
- **검사/continuation 생성 중**: 마지막 project/revision/mode 검사가 실패하면 차단합니다. 전체 통과 토큰도 continuation 생성 **후** 재검사하므로 보호 복원·재전환·저장·프로젝트 변경·종료 사이의 오래된 OFF 권한을 재사용하지 않습니다.
- **보호 상태에서 이미 전송한 요청**: 취소했다고 주장하지 않습니다. 기존 permit과 상관관계를 그대로 두며 실제 응답에서만 해제하고 기존 masked 증거 및 별도 bounded human raw 화면 사본을 갱신할 수 있습니다. OFF 전환·복원·설정 저장으로 격리된 permit을 강제 반환하지 않습니다.
- **전체 통과에서 새로 시작한 요청**: 요청/응답 내용·URL·호스트를 확장 증거로 수집하지 않으며 permit이나 correlation entry도 만들지 않습니다. 현재 controller에 바인딩된 프로젝트 구간의 포화형 누적 `passthroughCount`만 증가시키고, 보호 복원 후에도 상단에 표시합니다. 다른 ID의 프로젝트 정책으로 바인딩하면 초기화하며 A→B→A로 실제 바인딩했을 때 A의 예전 횟수를 복원하지 않습니다. 프로젝트 확인 실패로 OFF만 종료하고 다른 ID로 바인딩하지 않았다면 직전 횟수는 유지됩니다. 이는 대상 도착 횟수가 아니라 native continuation 해제 횟수입니다. **Burp 자체 history/다른 확장의 기록 정책은 변경하지 않습니다.**
- **보호 복원 후**: 새 요청부터 다시 검사합니다. 이전 전체 통과 요청은 계속 추적하지 않으므로 보호 복원 전에 요청 발생을 멈추고 기존 연결 완료를 별도로 확인하세요. 제한 통계는 보호한 요청의 permit만 포함하며 OFF 트래픽의 동시성/속도를 소급해서 증명하지 않습니다.

## 수명·실패·저장

새 요청 차단/자동 overlay/circuit/미응답 격리 상태에서 OFF로 전환하면 그 상태도
OFF의 새 요청을 막지 않습니다. 다만 **이전 운영자 수동 pause는 OFF/ON을 넘어
보존됩니다**. ‘보호 다시 켜기’ 후 그 pause로 돌아오며 명시적으로 **보호 재개**해야
해제됩니다. OFF는 Resume이 아닙니다. `status.paused=false`는 OFF 중 호환 표시이며
`status.operatorPaused`는 원래 선택을 유지합니다. 미해결 native permit·자동 차단·
probe cadence·Intent debt도 남습니다. 설정 저장/감지 OFF로 이를 지우지 않습니다.
이 점을 OFF 확인 창에서도 설명합니다.

`GuardUiAccess.passthrough(enabled, expectedProjectId, expectedRevision)`는 사람 UI의 원래 snapshot으로 compare-and-set합니다. 확인 창이 열린 동안 상태가 바뀌면 현재 버전을 몰래 대입하지 않고 거절합니다. 프로젝트가 확인되지 않거나 정책 재확인이 필요한 상태에서는 OFF를 새로 허용하지 않습니다.

OFF는 `GuardConfig`나 project storage/global preferences에 저장하지 않습니다. 확장 재로드/재시작·감지된 프로젝트 전환에서 OFF를 해제하고, 프로젝트/저장 불확실성에서는 OFF 해제와 함께 새 요청 차단을 유지합니다. 프로젝트를 확인할 수 없으면 atomic tri-state `nativeMode(messageId)`가 capture 전에 내용 미수집 거절을 반환합니다 (구 no-ID API도 호환용으로 남음). null 토큰을 일반 검사로 잘못 해석하지 않습니다. 실제 프로젝트 확인 실패를 감지하면 OFF를 즉시 종료하고 버전을 올려 차단/재확인 상태로 둡니다. UI refresh 전 A→B→A로 돌아와도 옛 OFF가 되살아나지 않으며, 재확인 전 콜백도 내용 미수집 거절합니다. 종료/충돌/stale 토큰 같은 실패에는 생략 placeholder와 고정 사유만 있는 거절 증거가 남을 수 있으나 실제 요청/응답 내용·URL·호스트는 수집하지 않습니다. 설정 저장에 성공해도 OFF를 자동으로 켜거나 끄지 않습니다. 저장 불확실성은 예외로 fail-closed 전환합니다.

OFF도 확장 종료·유효하지 않거나 확인 불가능한 정책/프로젝트·stale generation·native continuation factory 실패를 허용으로 처리하지 않습니다. 기존 보호 요청의 ID와 충돌하는 잘못된 native callback은 이전 permit을 훼손하지 않도록 drop합니다. 이는 scope/검사/속도 제한을 OFF에 몰래 남기는 기능이 아니라 lifecycle/SDK 오류 처리입니다. 프록시 밖의 직접 연결, 다른 도구·확장 소켓, 콜백에 없는 트래픽은 원래부터 보장하지 않습니다.

## OFF와 listener 선택·health 예외를 혼동하지 마세요

- `guardListenerPorts=[]`는 정상적인 모든 Proxy listener 보호입니다. 제한 목록은
  실제 inbound 포트이며 목적지 포트가 아니지만 **현재 native 한정은 미지원(H FAIL)**입니다.
  Proxy/HTTP 숫자 ID·원본 annotation 연결은 검증에 실패했습니다. Observer는 원래
  request/annotations를 그대로 continuation할 뿐 ID/listener/content를 읽거나 기록하지
  않습니다. Native producer가 없어 제한 목록은 선택·미선택 모두 내용 검사 전에
  `LISTENER_UNVERIFIED`입니다. 저장 확인과 지속 상태도 미지원·빈 목록 복구를 안내합니다.
- Core known-unselected token/registry는 합성 trusted proof 검사일 뿐 native 지원이 아닙니다.
  목적지·숫자·타이밍·내용 fingerprint로 대체하지 않습니다. Global OFF는 여전히 먼저
  처리하는 별도의 명시적 사람 결정입니다. [실제 발견 기록](V2_NATIVE_FINDINGS.md)
- Bypass token은 controller 발행 provenance와 project/revision/kind/listenerPort를
  최종 확인합니다. 원래 native request/annotations continuation factory가 성공한 뒤
  `commitPassthrough`하며 OFF/미선택 횟수를 구분합니다. 오래된 protected Prepared를
  bypass로 승격하지 않습니다. callback handoff 횟수이지 도착 횟수가 아닙니다.
- Health는 별도 기본 OFF 사람 설정입니다. 정확한 실제 scheme/host/port/path의
  **query/body 없는 GET**만 운영자 pause/circuit을 통과합니다. scope/일반 규칙·ASK/
  heavy/fanout/예산/rate/용량/수명 실패는 넘지 못하고 health 응답은 circuit을
  치유하지 않습니다. GET도 부작용이 있어 활성화/경로 변경 저장에 확인이 필요합니다.
- 보호 ON도 Host fuzz·지원하지 않는 본문/charset·선택적 capture 실패를 이유로
  무조건451하지 않습니다. 실제 목적지 hard scope와 명시 규칙·안전 제어는 유지하고
  unavailable inspection을 경고합니다. 모든 경로 허용은 `/c/;/main.do`,
  `/c/%2e/main.do` 등을 normalize/rewrite하지 않습니다. OFF만의 허용 기능이 아닙니다.

Raw UI는 masked 증거와 별도인 bounded/project-bound/memory-only 캐시입니다.
OFF 전 기록이 남을 수 있어 화면을 비운다는 뜻이 아닙니다. 새 OFF/미선택 요청·응답은
raw에도 수집하지 않습니다. project uncertainty/change·clear·eviction·종료는 raw를
폐기합니다. raw getter를 export/incident/log/정책 자동 수집에 쓰지 않습니다.

## 끝까지 읽을 수 있는 확인/오류 창

기존 zero-row wrapping `JTextArea`를 `JOptionPane`에 그대로 넣는 방식 대신 다음을 사용합니다.

- 일반 문자열·선택/복사 가능한 줄바꿈 본문 + 실제 세로 스크롤. 긴 한국어/URL/큰 폰트도 본문 끝으로 이동할 수 있습니다.
- 본문과 분리된 하단 action 영역. 가로 폭이 좁으면 버튼 행의 선호 높이도 함께 늘어나는 wrapping layout.
- 현재 모니터의 work area 안으로 제한한 크기·위치, 사용자가 조절 가능한 창. 편집 창도 같은 화면 제한을 사용합니다.
- 확인 창의 기본 Enter 동작은 **취소**, Escape/닫기/확장 panel 종료도 취소입니다. OFF/삭제/덮어쓰기는 확인 버튼을 명시적으로 눌러야 합니다. 오류 창은 닫기입니다.
- 확인·오류 창도 소유한 창 집합에 넣어 panel 종료 시 함께 정리합니다. 원본 예외/traffic을 표시하지 않습니다.
- 화면 갱신 실패로 OFF 여부를 확인할 수 없어도 개요의 **긴급: 새 요청 모두 차단**은 남습니다. 이 경로는 새 요청 차단만 요청하며 오래된 상태에서 재개/OFF를 허용하지 않습니다.
- 상태 표시는 Cairn Guard 확장 탭 내부입니다. 다른 Burp 도구 탭 전체를 덮는 경고 UI나 native project API의 비차단 실행을 보장하지 않습니다.

## 검증 구분

Headless layout, 실제 Swing modal lifecycle, Mockito native-boundary, owned socket,
설치 Burp는 서로 다른 층입니다. 최신437503…의 Java1231 / Swing27(scale1·2),
개별 실제 native 성공과 H 실패는 [최신 검증](VERIFICATION.md)·[발견 기록](V2_NATIVE_FINDINGS.md)을
따릅니다. **다음은 허가 전 과거 체크포인트 기록입니다:** revision3 clean Java1221 / native-harness
Python27 / local-template18 PASS이며 실제 upstream은 미실행입니다. 격리 Xvfb+소유 WM의
Swing은 scale1·scale2 각각27 PASS, scale2 반복27 PASS입니다. 테스트의 비동기 레이아웃·
클릭 좌표 대기만 보완했고 포커스/스크롤 단언은 유지했습니다. v2 Burp 시도는 첫 EULA에서
중단했으며 약관 동의·확장 로드·native
phase는 없습니다. 정확한 테스트/hash/재현·요청된 독립 감사·native 남은 범위는
[VERIFICATION.md](VERIFICATION.md), [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md)에
기록합니다. 과거 `738b41e`/`4232ae…` 프리뷰 및 `c071…` native 결과를 이 소스의
수용·배포·구현 감사 승인으로 대신하지 않습니다.
