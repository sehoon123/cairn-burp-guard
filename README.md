# Cairn Proxy Guard

CAIRN을 수정하지 않고 Burp를 **사람이 관리하는 중앙 HTTP/HTTPS 안전 통제 계층**으로 사용하는 독립 Burp Extension 개발 프로젝트입니다. PortSwigger/CAIRN의 공식 제품이나 기존 Independent MCP Bridge의 새 버전이 아닙니다.

> **현재 소스: 자동 차단 제거 개발 변경 — 새 exact JAR의 native Burp 검증은 미실행.** 사용자가 공개를 명시적으로 요청한 개발 빌드입니다. **Authorization·Cookie·토큰도 원문으로 노출되며, 수집·보관 상한이 없어 메모리 증가·OOM·UI/프록시 지연이 가능합니다. 실서비스 보호에 의존하지 마세요.** 소스 변경·자동 검사 완료는 전체 A–G 수용이나 정식 배포 승인이 아닙니다. 포트별 적용(H)은 추후 기능이며 PASS가 아닙니다. 사용자 Burp/프로젝트/프록시/데스크톱을 자동 설정하거나 설치하지 않습니다.

**[무마스킹·무제한 수집 개발 빌드 다운로드](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-05-v2-unmasked-unbounded)** · [이번 릴리스의 검증·한계·출처](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-05-v2-unmasked-unbounded) · [이전 artifact별 검증](docs/VERIFICATION.md) · [전체 Proxy 과거 기록](docs/ALL_LISTENERS_ACCEPTANCE.md) · [v2 API](docs/INTERFACES.md)

## 현재 소스 변경: 자동 차단 제거 (아직 새 배포/native 검증 아님)

이전 응답5xx·크기·fan-out, 느린/스트리밍 응답, 미확인/늦은 콜백,
추정 timeout·회로·native-flight/correlation 용량으로 새 요청을 자동 차단하는
기능 자체를 제거했습니다. 우회 토글이나 더 긴 timeout으로 숨기지 않습니다.
실제 native 동시 실행 수를 제한하지 않으며 Burp 콜백 전달 문제를 고쳤다는 뜻도 아닙니다.

- 유지: 실제 목적지 scope, 명시 BLOCK/ALLOW/EXEMPT/ASK, 사람 승인·수동 pause,
  정책/프로젝트/종료/최종 전송 검사, 선택 검사·파서 및 즉시 callback 용량 보호.
- 수동 속도: 전체/기본 host/host override 각각0=끔,1–1000. 새 기본값0/0,
  저장된 양수는 보존. **모든 속도 제한 끄기 (초안)**는 override까지0으로 채우며
  정상 Save/CAS 전에는 적용하지 않습니다. 명시 intent 예산0=끔/수동 초기화는 별개입니다.
- 이전 자동 감지·동시성·응답 timeout 설정은 **INACTIVE legacy** 호환 데이터로만
  보존합니다. 저장/재로드로 재활성화되지 않으며 자동 차단/후보 authoring UI는 없습니다.
- 상관관계는 로그 전용입니다. 재사용 ID는 요청을 막지 않고 영구 ambiguous로 취급합니다.
  확인된 protected 출처의 모호한 응답은 요청을 추측하지 않는 **응답만 기록** 행으로
  원문 보존합니다. OFF/혼합/지운/이전 프로젝트/알 수 없는 출처는 수집·추측하지 않습니다.
  내용 없는 used-ID tombstone(OFF ID 포함)만 unload까지 메모리에 남고 집행 권한이 없습니다.
- 원문 전체 무마스킹·무제한 메모리 보관, 평문 확인·owner-only atomic 내보내기는 유지합니다.
  **평문 자격증명·무제한 메모리/OOM·무제한 native 동시성** 위험은 사용자가 관리해야 합니다.

[테스트 변경 지도](docs/AUTOBLOCK_REMOVAL_TEST_MAP.md)와 현재 소스 계약을 보세요.
과거 [무마스킹 프리릴리즈](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-05-v2-unmasked-unbounded) 및 native 보고서는 이전 artifact의 기록입니다.
이번 소스의 배포·native 수용·독립 검토 완료 증거가 아닙니다. 원문 자동 디스크 저장은 없습니다.

## 역할과 제외 범위

```text
CAIRN Native Pi workers ──HTTP(S) proxy──> Burp Proxy + Cairn Proxy Guard ──> 허용된 실제 대상
           └─ 점검 계획·탐색·검증·한국어 Markdown 보고서 작성
사람 ──Burp extension 탭──> Scope / Rules / Pacing / Approval / Evidence
```

- 워커에 Burp MCP/Pi Extension/제어 API를 제공하지 않습니다. 확장 자체도 MCP/HTTP 서버를 열거나 대상에 요청을 대신 보내지 않습니다.
- 허용 시 **기존 native request/response 및 annotations를 그대로 continuation에 전달**합니다. 검사·화면·내보내기는 별도 사본이며, 이 경계가 최종 wire bytes를 입증하지는 않습니다.
- **로그인·쿠키/JWT 주입·세션 공유·만료 감지·갱신·계정/역할 관리가 없습니다.** 인증 충돌을 해결하거나 재로그인을 자동화하지 않습니다.
- 프록시를 우회하는 접속, 비Proxy 도구, 다른 확장 소켓과 콜백에 없는 트래픽은 통제하지 못합니다. 프록시 환경 변수만으로 강제 egress를 보장하지 않습니다.

## 현재 v2 소스의 동작

### 범위는 pentest 경로 정화기가 아닙니다

- 범위는 **실제 `httpService`의 host/scheme/port + 원래 `request.path()`**로 판단합니다. fuzzed Host/`:authority`나 Host에서 만든 URL authority로 허용된 실제 대상을 막거나 다른 대상을 허용하지 않습니다. 헤더·target을 고치지 않습니다.
- **모든 경로 허용은 정말 모든 경로 허용입니다.** `/c/;/main.do`, `/c/%2e/main.do`, 중첩 인코딩·dot/matrix/separator 변형을 불필요한 `AMBIGUOUS_PATH` 정화로 막지 않고 원래 spelling 그대로 전달합니다. 제한된 경로 scope/명시적 blockScope/사용자 BLOCK과 수동 제어는 계속 적용합니다.
- raw/decoded/보수적 normalized alias는 **내부 판단용**입니다. 불완전한 해석은 all-path에서 `PATH_INTERPRETATION_INCOMPLETE` 경고가 될 수 있지만 제한 scope의 확인이나 경로 EXEMPT의 근거가 되지 않습니다. 전달 경로를 normalize/rewrite하지 않습니다.
- Cairn 허용 대상은 **Burp Target Scope와 별개**입니다. Burp의 `Out-of-scope request handling → Drop all out-of-scope requests`가 켜져 있으면 **Burp Target Scope 밖** 요청은 Cairn이 허용하거나 보호가 꺼져 있어도 Burp가 전송 전에 버릴 수 있고, 클라이언트에 `No response received from remote server` 같은 Burp 자체 오류가 보일 수 있습니다. Cairn은 Burp 설정을 읽거나 바꾸지 않으며 전역 확대를 권하지 않습니다. `X-Cairn-Guard: blocked` 로컬 451은 Cairn 거절의 긍정 표시이지 인증된 증명이나 모든 거절 방식의 목록이 아닙니다. 451이나 Cairn 증거 행이 없다는 사실만으로는 결론을 낼 수 없고(보호 꺼짐·보관 한도·drop-only/실패 경로), 행이 있어도 대상 도착을 뜻하지 않습니다.
- 이전 timeout 격리·회로·자동 overlay는 실행되지 않습니다. 미확인 응답은 미확인으로 남기되 다음 정책 허용 요청의 집행 권한을 갖지 않습니다.
- 헤더·본문·query는 활성 규칙이 필요로 할 때 best-effort로 검사합니다. 지원하지 않는 charset/binary/multipart/encoding, malformed JSON, 선택적 capture 한계는 **검사 불가 경고이지 자동451 사유가 아닙니다**. 검사 불가를 평가 성공으로 간주하지 않고, 불완전 조건으로 EXEMPT를 주지 않습니다. 실제 대상/필수 범위·정책·수명·용량 불확실성은 fail-closed입니다.

### 기본값과 독립 안전 제어

- 새 v2 정책: 빈 allowlist, **DELETE 메서드 차단만** 기본 규칙. broad `delete` 문자열 차단은 새 기본값에서 제거했습니다. **v1에서 읽은 기존 규칙은 자동 삭제하지 않습니다.**
- Global/host RPS **0/0 (끔)**, queue **100**; queue/approval **30초**. native in-flight/응답 시간 admission 제한은 없습니다. 호스트별 FIFO와 eligible round-robin, no-burst admission pacing입니다. 서버 도착 시각 보장은 아닙니다.
- 일반 규칙 우선순위는 **EXEMPT > BLOCK > ASK > ALLOW**, Monitor는 기록만 합니다. EXEMPT도 실제 범위·정책/프로젝트 유효성·수동 pause·태그 예산·속도/용량·종료를 우회하지 못합니다.
- 이전 대용량·5xx·fanout/예외 값은 호환용 비활성 데이터입니다. 설정 편집은 값을 보존하며 실행하지 않습니다.
- Intent 예산은 기본 OFF. 켜면 변경하지 않은 `X-Cairn-Intent`/`X-Cairn-Run` 쌍을 최종 handoff에서 셉니다. limit20이면21번째를 막지만 **클라이언트 주장 태그일 뿐 인증/신뢰 quota가 아닙니다**. EXEMPT/health도 셉니다. 거절·큐/최종 검사·로컬 continuation 실패는 새 quota를 쓰지 않습니다.
- 이전 콜백이 없어도 새 native 요청을 기다리게 하는 permit/timeout 격리가 없습니다. callback pacing은 대상 도착 간격이나 native 동시 실행 수 보장이 아닙니다.

### 화면과 저장

| 탭/조작 | 현재 소스 기능 |
|---|---|
| 개요·상단 | typed 보호 상태/이유/통계, 새 요청 차단, 사람 확인을 거친 전체 통과/OFF·복원 |
| 대상 | URL → 미저장 폼·실제 범위 미리보기 → 명시 저장; 정확한 대상부터 등록 |
| 규칙 | 메서드/실제 URL/경로/query/header/body/JSON/form, AND/OR·RE2, EXEMPT 위험 확인 |
| 요청 기록 | **마스킹 없는 평문 원문 전체**(상한 없음)·검사 경고·intent/run·결과·상태. JSON/HAR 내보내기는 매번 평문 비밀 경고 확인 후 원문 구조(헤더·본문 바이트)를 저장 |
| 승인 대기 | 읽기 전용 검토 후 별도1회 승인/거절. 오래된 승인·프로젝트/버전 변경은 취소 |
| 설정 | 0=끔 수동 RPS·모든 속도 끄기 초안·대기/승인 시간·태그 한도·정확한 GET health 경로. 이전 자동 설정은 비활성 보존 |

- **Schema2는 엄격한 수동 저장**입니다. v1은 원본·변환 비교를 제공하고 메모리에서만 읽습니다. 새 감지는 OFF, 기존 규칙 보존. 사람이 원본을 먼저 내보내고 v2 저장을 확인해야 저장소를 교체합니다. 정확한 legacy delete-string 제거도 별도 선택입니다. 구버전 JAR은 schema2를 읽지 못하므로 되돌리려면 원본 정책이 필요합니다.
- **마스킹과 수집 한도는 없습니다.** 모든 화면·증거 행·상태 밖 진단·JSON/HAR/사건 출력은 평문 원문(Authorization·Cookie·토큰 포함)이며, 헤더·본문·URL·메타데이터·행·관측·후보를 건수/바이트/기간 상한 없이 지우기·프로젝트 전환·언로드 전까지 메모리에 보관합니다. **메모리는 무한정 늘어 OOM·화면 지연이 생길 수 있으며 사용자가 직접 지우기로 관리**합니다(자동 디스크 저장·스풀 없음). 지원하지 않는 문자셋/바이너리는 바이트 전체의 HEX/base64이며 읽기 실패·응답 없음은 그대로 표시합니다. 완전 wire capture/메모리 영구 삭제(zeroization) 보장은 아닙니다. 화면 복사/스크린샷/이미 내보낸 파일은 비밀을 노출합니다. 요청 검사·파서·callback/승인·명시 속도/태그 예산 같은 **별도 집행 한도**는 유지됩니다.
- 사람이 누르는 JSON(`cairn-human-inspection` v1)/HAR(1.2, `HUMAN_ORIGINAL`)/사건(`cairn-human-incident` v1) 내보내기는 매번 Authorization·Cookie·토큰 평문 경고를 확인한 뒤 보관된 원문을 씁니다. 원문이 없으면 ‘원문 없음’입니다. 잠금 안에서 스냅샷만 만들고 직렬화·파일 쓰기는 잠금 밖, 이름 바꾸기 직전 최종 확인(그 사이 아주 짧은 경쟁은 막을 수 없음), 출력 크기 상한 없음. 기계용(schema 2 JSON/HAR/사건) 내보내기도 같은 원문을 담으며 자동 저장/내보내기는 없습니다. 상태·카운터 필드에는 요청 내용을 넣지 않습니다. [EVIDENCE.md](docs/EVIDENCE.md)

### OFF·listener·health는 서로 다릅니다

**모두 통과 (보호 끔)…**는 사람이 확인하는 runtime-only 상태입니다. 새 Proxy callback은 범위/규칙/승인/안전 예산/속도/내용 수집을 건너뛰고 횟수만 셉니다. 기존 대기는 승인하지 않고 취소하며 기존 protected 응답 association과 intent 사용량을 보존합니다 (native permit 소유가 아님). **OFF 이전 수동 pause도 ON에서 그대로 돌아옵니다**. OFF는 resume이 아닙니다. 프로젝트 전환/불확실성·재시작에 유지하지 않습니다. 복원 전 트래픽을 멈추고 OFF 연결 완료를 별도로 확인하세요. [PASSTHROUGH.md](docs/PASSTHROUGH.md)

`guardListenerPorts=[]`는 정상적인 모든 Proxy listener 보호입니다. **포트별 한정 모드(H)는 추후 지원**합니다. 새 제한은 읽기 전용 폼/전체 정책 JSON에서 저장하지 못합니다. Proxy/HTTP 콜백 ID·원본 annotation으로 공통 identity를 추정하지 않습니다. **과거 저장된 nonempty 목록**은 자동 삭제하지 않고 보호 중 선택·미선택 모두 내용 검사 전에 `LISTENER_UNVERIFIED`로 거절합니다. 사람이 명시적으로 목록을 비우고 전체 보호 전환을 확인하면 복구됩니다. 무관한 편집은 기존 값을 보존하며 H 통과로 취급하지 않습니다.

Health 예외는 기본 OFF인 별도 사람 설정입니다. 정확한 scheme/host/port/path의 **query·body 없는 GET**만 운영자 수동 pause를 통과합니다. 범위·일반 규칙·ASK·명시 속도·태그 예산·수명 실패는 못 넘습니다. 자동 circuit/overlay는 제거되었습니다. GET도 부작용이 있을 수 있어 활성화/경로 변경 저장에 확인이 필요합니다.

차단은 `X-Cairn-Guard: blocked` **로컬451 JSON**입니다. 원래 `source/outcome/reason/evidenceId/retryable:false` 뒤에 `guardState`, `local:true`, `policyRevision`, 필요 시 안전한 overlay UUID만 추가합니다. URL/비밀/tag는 넣지 않습니다. 대상 오류·취약점 증거로 오해하지 마세요. `FORWARDED`도 native continuation 해제이지 도착/처리 성공 증거가 아닙니다.

## 빌드 및 수동 검증 시작점

필요: Java **21**, Montoya API **2026.7** 호환 Burp. 의존성은 Gradle lock/strict verification으로 고정합니다. Montoya는 compile-only이며 포함 의존성의 고지는 [NOTICE](NOTICE)를 보세요. 다음은 **개발자가 별도로 재현할 명령**입니다. 실제 실행한 자동/native 검사 범위와 미검증 항목은 위 검증 문서를 따르세요. 설치·릴리스 명령이 아닙니다.

```sh
./gradlew clean test jar
python3 scripts/verify_templates.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

현재 후보 산출 경로는 `build/libs/cairn-proxy-guard-0.2.0.jar`입니다 (과거 프리뷰 JAR 이름은 `0.1.0-SNAPSHOT`이었음). 프로젝트 MIT `LICENSE`/`NOTICE`는 JAR의 `META-INF/cairn-proxy-guard/`에 있고, 루트 `META-INF/LICENSE`·`NOTICE`와 `META-INF/legal/`은 번들 라이브러리(Jackson/RE2J)의 원문 그대로이며 빌드가 이를 검사합니다. 이름이 같아도 hash가 다른 후보는 같은 검증 산출물이 아닙니다. 현재 v2 체크포인트와 과거 프리뷰를 태그/해시로 구분하세요. 다운로드만으로 설치되지는 않습니다.

사람이 새 후보를 검증할 때만 실제 대상과 분리된 임시 Burp HOME/profile/project/display와 **소유 loopback fixture**를 사용하세요. EULA·라이선스 입력이 필요하면 멈추고 사용자에게 요청하며 동의/활성화 자료를 복사하거나 우회하지 않습니다. 정확한 JAR hash를 기록하고 [자동 차단 제거 후보의 현재 native 절차](docs/MANUAL_BURP_SMOKE.md#current-removal-aware-procedure)를 따릅니다. 같은 문서의 과거 자동 제어/permit 단계와 helper는 현재 후보 절차나 성공 증거가 아닙니다. 현재 후보의 installed-Burp/native 전달·도착은 UNVERIFIED입니다. 공개 허가는 미검증 개발 체크포인트의 보관·공유에 한정되며, native 수용·실서비스 안전 보증·사용자 설치 완료를 뜻하지 않습니다. 확장 언로드 후에는 보호가 없습니다.

## CAIRN 템플릿과 한계

[CAIRN_TEMPLATES.md](docs/CAIRN_TEMPLATES.md)의 외부 prompt_group과 `templates/native-pi-ko/`는 허가된 비파괴 계획·탐색·한국어 보고용이며, `templates/native-pi-ko-offline/`은 별도 네트워크0 fixture 모드입니다. **CAIRN이 보고서를 작성**하고, 사람의 원문 export(평문 비밀 포함 가능)는 선택적 추가 증거입니다. 워커가 Burp를 제어하거나 로그인/세션을 복구하지 않습니다. Prompt-only 예산/완료 지시는 sandbox·강제 종료 후 보고서 보장이 아닙니다.

HTTPS TLS pass-through, opaque CONNECT, WebSocket frames, Repeater1건 외 비Proxy 도구 전수 검사, 다른 확장의 사후 변경, 직접 egress, HTTP2 전체 native matrix, Professional 디스크 프로젝트, CAIRN/Pi/model/report-file E2E는 별도 미검증 범위입니다. Inbound H2→H1 origin의5개 부분 검사와, Guard를 unload해도 소문자 `%2e`가 `%2E`로 바뀐 Burp baseline은 [현재 검증 기록](docs/ALL_LISTENERS_ACCEPTANCE.md)에 구분합니다. KISA 주제 응용은 공식 코드별 적합성·완전 점검·취약점 부재를 인증하지 않습니다.

## 문서

[정책](docs/POLICY.md) · [속도/승인](docs/RATE_APPROVAL.md) · [UI](docs/UI.md) · [Runtime/UI 계약](docs/RUNTIME_UI_CONTRACT.md) · [증거](docs/EVIDENCE.md) · [Burp adapter](docs/BURP_ADAPTER.md) · [Controller 검사](docs/CONTROLLER_TESTS.md) · [검증](docs/VERIFICATION.md) · [실제 Burp 기록](docs/NATIVE_BURP_RESULTS.md) · [v2 발견·차단 사유](docs/V2_NATIVE_FINDINGS.md) · [수동 smoke](docs/MANUAL_BURP_SMOKE.md)
