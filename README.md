# Cairn Proxy Guard

CAIRN을 수정하지 않고 Burp를 **사람이 관리하는 중앙 HTTP/HTTPS 안전 통제 계층**으로 사용하는 독립 Burp Extension 개발 프로젝트입니다. PortSwigger/CAIRN의 공식 제품이나 기존 Independent MCP Bridge의 새 버전이 아닙니다.

> **현재: 실험용 v2 개발 프리릴리즈 — 새 JAR의 native 수용·최종 독립 감사 미완료.** 사용자가 현재 작업의 공개 체크포인트를 명시적으로 요청했습니다. 정식 배포/전체 안전 검증 완료가 아니며 **실서비스 보호에 의존하지 마세요**. 포트별 적용(H)은 추후 분리한 기능이지 현재 gate나 PASS가 아닙니다. [프리릴리즈의 남은 지적·설치/롤백 주의](docs/PRERELEASE_2026-11-04_V2_CHECKPOINT.md), [artifact별 실제 검증](docs/ALL_LISTENERS_ACCEPTANCE.md), [이전 발견](docs/V2_NATIVE_FINDINGS.md)을 구분하세요. 사용자 Burp/프로젝트/프록시/데스크톱을 자동 설정하거나 설치하지 않습니다.

**[v2 개발 체크포인트 다운로드](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-04-v2-all-listeners-checkpoint)** · [프리릴리즈 검증 기록](docs/PRERELEASE_2026-11-04_V2_CHECKPOINT.md) · [검증 현황](docs/VERIFICATION.md) · [실제 Burp 기록](docs/NATIVE_BURP_RESULTS.md) · [v2 API](docs/INTERFACES.md)

## v2 개발 체크포인트와 과거 artifact를 구분하세요

| 구분 | 상태 |
|---|---|
| 과거 공개 프리뷰 | `dev-2026-11-04-conditions-passthrough`, 소스 기준 `738b41e`; 모달·전체 통과·조건 추가 수정. **v2 배포가 아님** |
| 그 프리뷰 JAR SHA256 | `4232ae63d0a158d294fbe9ee3cf40cf58b9e8bdc85a300c8f829a5135b4bd159` |
| 그때의 검사 | Java845 / Swing20(scale1·2) / Python35. **그 JAR의 실제 Burp는 미실행**. 당시 제한된 수정 검토도 v2 감사가 아님 |
| 현재 v2 소스 | 모델·정책·runtime·증거·UI, HEX 마스킹 및 잘못된 listener-proof 제거. EXEMPT/URL alias·raw target/watcher interop·late scalar/미전송 permit 회귀 수정 포함. H 완료를 주장하지 않음 |
| 최신 자동 검사 | 격리 Java **1302 PASS**, Python helper offline unit **31 PASS**, local template **18 PASS**(upstream SKIP). 새 JAR의 native Burp/Swing 검증은 아님 |
| 이전 실제 Burp | Community2026.10.1 / `437503…`의 raw target/본문/실제 service·EXEMPT·intent·heavy/circuit·WARN fanout·원문/내보내기 개별 성공. 새 hash의 결과로 이전하지 않음 |
| 역사적956bcf… exact-JAR 검사 | 그 JAR의 Swing scale1·2 각27 PASS 및 Burp의 두 inbound HTTP/HTTPS, raw paths·health·fanout·OFF/old permit/ASK·queue·intent debt, raw UI·JSON56/HAR56/incident 개별 확인. HTTP2는5개 부분 검사와 percent-case 한계. **새 JAR에 결과를 이전하지 않음** |
| 현재 체크포인트 JAR SHA256 | `c61b7d1f869ec926c30f0e0fcc9cd188396f7fd694e9fc2cfac542a6d191f491` — clean/forced rebuild 동일, **native Burp/Swing 미실행** |
| 구 로컬 후보 | `82ec781` / `217730…` bundle은 H 실패와 HEX export 결함이 있는 과거 후보. 재현됐어도 공개하면 안 됨 |
| 남은 수용 조건 | 새 exact-JAR native 수용과 수정 소스의 최종 독립 감사3개 미완료. 지정 모델의 이전 소스 cold 보고서2개는 결함 지적이지 승인서가 아니며 privacy/export 세 번째는 blocked. Queue/fanout/불완전 capture 분류 등 지적의 전체 판정도 미완료. **프리릴리즈 공개는 수용/정식 승인과 별개**, H는 gate도 PASS도 아님 |

이번 공개 체크포인트의 빌드/남은 지적은 [프리릴리즈 기록](docs/PRERELEASE_2026-11-04_V2_CHECKPOINT.md)에, 이전 후보별 hash/검토 시도는 [VERIFICATION.md](docs/VERIFICATION.md)에 구분합니다. 과거 examples JAR(`c071…`)의13 native 시나리오 및 더 오래된12/54 결과를 v2에 이전하거나 합산하지 않습니다. 이전의 설계 제안/검토 문서는 역사적 자료이며 현재 구현 완료·승인 증거가 아닙니다.

## 역할과 제외 범위

```text
CAIRN Native Pi workers ──HTTP(S) proxy──> Burp Proxy + Cairn Proxy Guard ──> 허용된 실제 대상
           └─ 점검 계획·탐색·검증·한국어 Markdown 보고서 작성
사람 ──Burp extension 탭──> Scope / Rules / Limits / Approval / Evidence / 자동 차단
```

- 워커에 Burp MCP/Pi Extension/제어 API를 제공하지 않습니다. 확장 자체도 MCP/HTTP 서버를 열거나 대상에 요청을 대신 보내지 않습니다.
- 허용 시 **기존 native request/response 및 annotations를 그대로 continuation에 전달**합니다. 검사·화면·내보내기는 별도 사본이며, 이 경계가 최종 wire bytes를 입증하지는 않습니다.
- **로그인·쿠키/JWT 주입·세션 공유·만료 감지·갱신·계정/역할 관리가 없습니다.** 인증 충돌을 해결하거나 재로그인을 자동화하지 않습니다.
- 프록시를 우회하는 접속, 비Proxy 도구, 다른 확장 소켓과 콜백에 없는 트래픽은 통제하지 못합니다. 프록시 환경 변수만으로 강제 egress를 보장하지 않습니다.

## 현재 v2 소스의 동작

### 범위는 pentest 경로 정화기가 아닙니다

- 범위는 **실제 `httpService`의 host/scheme/port + 원래 `request.path()`**로 판단합니다. fuzzed Host/`:authority`나 Host에서 만든 URL authority로 허용된 실제 대상을 막거나 다른 대상을 허용하지 않습니다. 헤더·target을 고치지 않습니다.
- **모든 경로 허용은 정말 모든 경로 허용입니다.** `/c/;/main.do`, `/c/%2e/main.do`, 중첩 인코딩·dot/matrix/separator 변형을 불필요한 `AMBIGUOUS_PATH` 정화로 막지 않고 원래 spelling 그대로 전달합니다. 제한된 경로 scope/명시적 blockScope/사용자 BLOCK과 자동 안전 제어는 계속 적용합니다.
- raw/decoded/보수적 normalized alias는 **내부 판단용**입니다. 불완전한 해석은 all-path에서 `PATH_INTERPRETATION_INCOMPLETE` 경고가 될 수 있지만 제한 scope의 확인이나 경로 EXEMPT의 근거가 되지 않습니다. 전달 경로를 normalize/rewrite하지 않습니다.
- 헤더·본문·query는 활성 규칙이 필요로 할 때 best-effort로 검사합니다. 지원하지 않는 charset/binary/multipart/encoding, malformed JSON, 선택적 capture 한계는 **검사 불가 경고이지 자동451 사유가 아닙니다**. 검사 불가를 평가 성공으로 간주하지 않고, 불완전 조건으로 EXEMPT를 주지 않습니다. 실제 대상/필수 범위·정책·수명·용량 불확실성은 fail-closed입니다.

### 기본값과 독립 안전 제어

- 새 v2 정책: 빈 allowlist, **DELETE 메서드 차단만** 기본 규칙. broad `delete` 문자열 차단은 새 기본값에서 제거했습니다. **v1에서 읽은 기존 규칙은 자동 삭제하지 않습니다.**
- Global/host RPS **5/5**, in-flight **5**, queue **100**; queue/approval **30초**, 미응답 격리 기준 **60초**. 호스트별 FIFO와 eligible round-robin, no-burst admission pacing입니다. 서버 도착 시각 보장은 아닙니다.
- 일반 규칙 우선순위는 **EXEMPT > BLOCK > ASK > ALLOW**, Monitor는 기록만 합니다. EXEMPT도 실제 범위·정책/프로젝트 유효성·수동 pause·자동 overlay/circuit·태그 예산·속도/용량·종료를 우회하지 못합니다.
- 새 정책의 응답 감지: **5MiB 초과** 후 같은 경로를10분 임시 차단, **60초 내5xx 5회** 후 서비스 circuit10분, **60초100경로** fanout은 기본 WARN. **첫 큰 응답은 이미 전달된 뒤 감지**하며 잘라내거나 소급 차단하지 않습니다. circuit 만료도 자동 복구가 아니라 GET/HEAD half-open을 서비스당 최대30초1회 허용하는 시각입니다.
- Intent 예산은 기본 OFF. 켜면 변경하지 않은 `X-Cairn-Intent`/`X-Cairn-Run` 쌍을 최종 handoff에서 셉니다. limit20이면21번째를 막지만 **클라이언트 주장 태그일 뿐 인증/신뢰 quota가 아닙니다**. EXEMPT/health도 셉니다. 거절·큐/최종 검사·로컬 continuation 실패는 새 quota를 쓰지 않습니다.
- 미응답 permit은 자동 반환하지 않습니다. 해당 host를 격리하고 실제 사용 가능한 global slot만 다른 host가 쓸 수 있습니다. stalled permit만으로 전역 동시성이 꽉 차면 모두 막습니다. 설정/OFF/언로드는 native 완료 증거가 아닙니다.

### 화면과 저장

| 탭/조작 | 현재 소스 기능 |
|---|---|
| 개요·상단 | typed 보호 상태/이유/통계, 새 요청 차단, 사람 확인을 거친 전체 통과/OFF·복원 |
| 대상 | URL → 미저장 폼·실제 범위 미리보기 → 명시 저장; 정확한 대상부터 등록 |
| 규칙 | 메서드/실제 URL/경로/query/header/body/JSON/form, AND/OR·RE2, EXEMPT 위험 확인 |
| 요청 기록 | **사람 로컬 unmasked 원문 사본**·검사 경고·intent/run·결과·상태. JSON/HAR는 별도의 masked 증거만 내보냄 |
| 승인 대기 | 읽기 전용 검토 후 별도1회 승인/거절. 오래된 승인·프로젝트/버전 변경은 취소 |
| 설정 | RPS/동시성/초 단위 제한, 응답/circuit/fanout, 태그 한도, 정확한 GET health 경로. inbound listener 한정은 현재 미지원 경고 |
| 자동 차단 | 메모리 overlay TTL/원인; 확인 후 선택/전체 해제. 정책·pause·native permit은 바꾸지 않음 |
| 대용량 후보 | 보관 창 최대 bytes/근사 p95. 안전한 `policyUrl`만 미저장 BLOCK/한도 초안으로 검토. 무시는 표시만 숨김 |

- **Schema2는 엄격한 수동 저장**입니다. v1은 원본·변환 비교를 제공하고 메모리에서만 읽습니다. 새 감지는 OFF, 기존 규칙 보존. 사람이 원본을 먼저 내보내고 v2 저장을 확인해야 저장소를 교체합니다. 정확한 legacy delete-string 제거도 별도 선택입니다. 구버전 JAR은 schema2를 읽지 못하므로 되돌리려면 원본 정책이 필요합니다.
- Raw UI와 masked evidence는 **각각** 최대2000건/추정32MiB, 부분64KiB의 메모리 전용 저장소입니다. Raw는 잘림·생략·UTF8/HEX 사본을 표시하고 프로젝트 전환/불확실성·clear·eviction·종료에 폐기합니다. 완전 wire capture/메모리 영구 삭제 보장은 아닙니다. 화면 복사/스크린샷은 비밀을 노출할 수 있습니다.
- JSON/HAR/incident/log에는 raw getter를 사용하지 않습니다. sealed masked 증거·응답 후 재마스킹과 보관/근사/누락 정보를 사용합니다. 자동 저장/내보내기나 raw 값의 정책 수집은 없습니다. [EVIDENCE.md](docs/EVIDENCE.md)

### OFF·listener·health는 서로 다릅니다

**모두 통과 (보호 끔)…**는 사람이 확인하는 runtime-only 상태입니다. 새 Proxy callback은 범위/규칙/승인/안전 예산/속도/내용 수집을 건너뛰고 횟수만 셉니다. 기존 대기는 승인하지 않고 취소하며 기존 flight/overlay/intent debt를 보존합니다. **OFF 이전 수동 pause도 ON에서 그대로 돌아옵니다**. OFF는 resume이 아닙니다. 프로젝트 전환/불확실성·재시작에 유지하지 않습니다. 복원 전 트래픽을 멈추고 OFF 연결 완료를 별도로 확인하세요. [PASSTHROUGH.md](docs/PASSTHROUGH.md)

`guardListenerPorts=[]`는 정상적인 모든 Proxy listener 보호입니다. **포트별 한정 모드(H)는 추후 지원**합니다. 새 제한은 읽기 전용 폼/전체 정책 JSON에서 저장하지 못합니다. Proxy/HTTP 콜백 ID·원본 annotation으로 공통 identity를 추정하지 않습니다. **과거 저장된 nonempty 목록**은 자동 삭제하지 않고 보호 중 선택·미선택 모두 내용 검사 전에 `LISTENER_UNVERIFIED`로 거절합니다. 사람이 명시적으로 목록을 비우고 전체 보호 전환을 확인하면 복구됩니다. 무관한 편집은 기존 값을 보존하며 H 통과로 취급하지 않습니다.

Health 예외는 기본 OFF인 별도 사람 설정입니다. 정확한 scheme/host/port/path의 **query·body 없는 GET**만 운영자 pause/circuit을 통과합니다. 범위·일반 규칙·다른 overlay·속도·예산·수명 실패는 못 넘고 응답으로 circuit을 치유하지 않습니다. GET도 부작용이 있을 수 있어 활성화/경로 변경 저장에 확인이 필요합니다.

차단은 `X-Cairn-Guard: blocked` **로컬451 JSON**입니다. 원래 `source/outcome/reason/evidenceId/retryable:false` 뒤에 `guardState`, `local:true`, `policyRevision`, 필요 시 안전한 overlay UUID만 추가합니다. URL/비밀/tag는 넣지 않습니다. 대상 오류·취약점 증거로 오해하지 마세요. `FORWARDED`도 native continuation 해제이지 도착/처리 성공 증거가 아닙니다.

## 빌드 및 수동 검증 시작점

필요: Java **21**, Montoya API **2026.7** 호환 Burp. 의존성은 Gradle lock/strict verification으로 고정합니다. Montoya는 compile-only이며 포함 의존성의 고지는 [NOTICE](NOTICE)를 보세요. 다음은 **개발자가 별도로 재현할 명령**입니다. 실제 실행한 자동/native 검사 범위와 미검증 항목은 위 검증 문서를 따르세요. 설치·릴리스 명령이 아닙니다.

```sh
./gradlew clean test jar
python3 scripts/verify_templates.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

일반 산출 경로는 `build/libs/cairn-proxy-guard-0.1.0-SNAPSHOT.jar`입니다. 이름이 같아도 hash가 다른 후보는 같은 검증 산출물이 아닙니다. 현재 v2 체크포인트와 과거 프리뷰를 태그/해시로 구분하세요. 다운로드만으로 설치되지는 않습니다.

사람이 새 후보를 검증할 때만 실제 대상과 분리된 임시 Burp HOME/profile/project/display와 **소유 loopback fixture**를 사용하세요. EULA·라이선스 입력이 필요하면 멈추고 사용자에게 요청하며 동의/활성화 자료를 복사하거나 우회하지 않습니다. 정확한 JAR hash를 기록하고 [수동 native checklist](docs/MANUAL_BURP_SMOKE.md)를 따릅니다. 공개 허가는 미검증 개발 체크포인트의 보관·공유에 한정되며, native 수용·실서비스 안전 보증·사용자 설치 완료를 뜻하지 않습니다. 확장 언로드 후에는 보호가 없습니다.

## CAIRN 템플릿과 한계

[CAIRN_TEMPLATES.md](docs/CAIRN_TEMPLATES.md)의 외부 prompt_group과 `templates/native-pi-ko/`는 허가된 비파괴 계획·탐색·한국어 보고용이며, `templates/native-pi-ko-offline/`은 별도 네트워크0 fixture 모드입니다. **CAIRN이 보고서를 작성**하고, 사람의 masked export는 선택적 추가 증거입니다. 워커가 Burp를 제어하거나 로그인/세션을 복구하지 않습니다. Prompt-only 예산/완료 지시는 sandbox·강제 종료 후 보고서 보장이 아닙니다.

HTTPS TLS pass-through, opaque CONNECT, WebSocket frames, Repeater1건 외 비Proxy 도구 전수 검사, 다른 확장의 사후 변경, 직접 egress, HTTP2 전체 native matrix, Professional 디스크 프로젝트, CAIRN/Pi/model/report-file E2E는 별도 미검증 범위입니다. Inbound H2→H1 origin의5개 부분 검사와, Guard를 unload해도 소문자 `%2e`가 `%2E`로 바뀐 Burp baseline은 [현재 검증 기록](docs/ALL_LISTENERS_ACCEPTANCE.md)에 구분합니다. KISA 주제 응용은 공식 코드별 적합성·완전 점검·취약점 부재를 인증하지 않습니다.

## 문서

[정책](docs/POLICY.md) · [속도/승인](docs/RATE_APPROVAL.md) · [UI](docs/UI.md) · [Runtime/UI 계약](docs/RUNTIME_UI_CONTRACT.md) · [증거](docs/EVIDENCE.md) · [Burp adapter](docs/BURP_ADAPTER.md) · [Controller 검사](docs/CONTROLLER_TESTS.md) · [검증](docs/VERIFICATION.md) · [실제 Burp 기록](docs/NATIVE_BURP_RESULTS.md) · [v2 발견·차단 사유](docs/V2_NATIVE_FINDINGS.md) · [수동 smoke](docs/MANUAL_BURP_SMOKE.md)
