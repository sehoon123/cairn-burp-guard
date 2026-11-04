# 전체 Proxy 보호 기준 검증 기록 — 2026-11-04

## 사용자가 확정한 범위와 현재 판정

사용자는 **포트별 적용(H)을 추후로 분리**하고 나머지를 먼저 진행하도록 요청했습니다.
현재 범위는 **A–G + 기존 보호 OFF/일시중지/진행 요청/원문 분리 요구사항**이며,
`guardListenerPorts=[]`로 모든 Proxy 리스너를 보호합니다. H는 현재 완료 조건도 성공 기능도
아닙니다. 이전 artifact의 H 실패·HEX 수정은 [V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md)의
역사적 관찰입니다. 아래의 native 표는 **956bcf… exact JAR에서 직접 실행한 개별 검사**이며,
뒤이은 소스 수정/새 artifact에 그 성공을 이전하지 않습니다.

정의된 자동/native 시나리오를 아래처럼 확인했지만, **요청한 독립 구현 감사3개는 미완료**입니다.
이를 전체 수용·독립 검토·정식 배포 승인으로 합치지 않습니다. 아래 native 검증 당시에는
공개 push/tag/release/사용자 설치를 하지 않았습니다. 이후 사용자가 **현재 작업의
커밋·push·개발 프리릴리즈 공개만 명시적으로 요청**했습니다. 공개 대상·빌드·남은 지적은
[개발 체크포인트 기록](PRERELEASE_2026-11-04_V2_CHECKPOINT.md)에 구분하며, 이는
새 exact-JAR 수용/감사 완료나 사용자 설치 완료가 아닙니다.

## 감사 이후 소스 수정 — native 수용 미완료

두 개의 cold 감사는 정확한 `ica-se-claude/claude-advantage-assist`로
`7b974de` 소스를 독립적으로 읽고 실질 보고서를 작성했습니다. 승인 보고서가 아니라
High/Medium 결함을 지적한 보고서입니다. 세 번째 privacy/export 감사는
credential-rotator 실패로 실질 보고서가 없어 여전히 **BLOCKED**입니다. 기존 실패
시도와 뒤이은 두 실질 감사를 구분하며, 모델·인증·라우팅을 대체하지 않았습니다.

후속 로컬 수정:

- `0fa6b09`: EXEMPT의 PATH/URL 및 ANY routing 부분은 모든 routing view를 충족해야
  합니다. URL 규칙도 실제 service와 dot/matrix/encoded alias를 봅니다. Native target은
  별도 transient 필드로 그대로 보존하며 non-origin/control 경로는 불완전 경로로
  처리합니다. 제한 범위/건강 probe/경로 EXEMPT를 증명하지 못하되 명시적 전체 경로는
  검사할 수 있습니다. 이는 구현 작업이며 독립 감사/승인이 아닙니다.
- `e77dd60`: 논리 timeout 뒤에도 bounded masked ticket을 실제 응답까지 보관하여
  늦은 heavy/일반5xx scalar를 관찰합니다. 만료 half-open은 새 probe를 치유하지
  못합니다. 실제 native permit은 timeout으로 반환하지 않습니다. `authorize`가 permit을
  호출자에게 넘기기 전 예외가 나면 확실히 미전송인 그 permit만 닫습니다.
- `2afd923`: watcher도 빈/non-`/` 첫 view와 raw control/DEL/C1/lone surrogate를
  받아들이며 **최대9 view·각16384 code unit**을 hash 전에 검사합니다. Lone surrogate를
  `?`로 바꾸는 charset 충돌 없이 정확한 UTF-16 code unit을 HMAC에 넣습니다.
  `healthProbe`의 `allMatch(probe.path()::equals)`는 바꾸지 않았습니다.

새 isolated clean Java 검사: **1302 PASS**, failures/errors/skips0.
이 중 watcher routing interop18개, late scalar/permit 회귀7개입니다.
같은 frozen source에서 Python helper의 **offline unit31개**와 local template18개도
통과했습니다(실제 upstream은 SKIP). 현재 tracked build/source 입력113개와 byte 일치를
확인했고 production 강제 재빌드에서도 같은 JAR hash를 확인했습니다.
새 로컬 자동검사용 JAR SHA256:
`c61b7d1f869ec926c30f0e0fcc9cd188396f7fd694e9fc2cfac542a6d191f491`.
**이 새 JAR의 native Burp/Swing 재검증·전체 수용·업데이트된 소스의 최종 독립 검토는
아직 하지 않았습니다.** 아래956bcf…의 native/내보내기/desktop 성공으로 대신하지 않습니다.

나머지 queue/fanout/optional-capture 분류 등의 감사 지적도 아직 전체 adjudication/
검증이 끝난 것이 아닙니다. 일부 수정이나1302개 통과만으로 전체 결함 해결을 주장하지
않습니다. 사용자가 허가한 공개 작업은 **미검증 개발 체크포인트의 보관·공유**이며,
정식 수용/배포 승인은 계속 미완료입니다. 사용자 Burp에 자동 설치하지 않습니다.

## 미지원 옵션의 안전한 정리

- 새 프로필의 리스너 필드는 전체 보호로 고정·읽기 전용입니다. 폼 값을 프로그램으로
  바꿔도 새 포트 제한을 저장하지 못합니다. 전체 정책 JSON도 같은 저장 경계에서 거절합니다.
- 기존 nonempty 값은 로드/무관한 편집에서 자동 삭제하지 않습니다. 이 과거 설정은 여전히
  native 내용 캡처 전 `LISTENER_UNVERIFIED`로 거절합니다. 다른 제한 목록으로 교체하지 못합니다.
- 사람이 기존 목록을 직접 비우면 **모든 Proxy가 검사 대상이 된다는 별도 확인** 후 CAS 저장합니다.
  취소·stale 프로젝트/버전은 기존 정책을 보존합니다. 전체 보호는 전체 통과(OFF)가 아닙니다.
- 미래 H 모델/엄격 codec 호환성과 unknown 제한의 fail-closed 회귀는 보존합니다.
  숫자 ID·주석·시간·FIFO·내용·목적지 포트로 identity를 추정하지 않습니다.
- 실제 native 전체 정책 편집에서도 새 nonempty 목록의 저장을 거절했고, 읽어 온 정책은
  빈 목록/같은 revision을 유지했습니다. 이는 **미지원 설정 차단** 검사이지 H 성공이 아닙니다.

## 역사적956bcf… 산출물과 자동 검사

아래 native 검사에 사용했던 이전 로컬 후보 JAR SHA256:
`956bcf789cd3d4dc45e0db6a8197e52961a606be074f39f6610080dd6b12063d`.
기존437503… JAR의 native 성공을 이 hash로 이전하지 않았습니다. Main의 native 사본,
별도 frozen source의 clean build, forced rebuild가 모두 같은 bytes였습니다.

| 검사층 | 직접 결과 | 범위/한계 |
|---|---|---|
| Headless Java | **1235 PASS**, failures/errors/skips0 | 모델·정책·adapter·controller·증거·UI 회귀와 소유 socket 검사. Native Burp 자체가 아님 |
| Python native helper | **31 PASS** | 전체 리스너/health/fanout 외부 클라이언트 계약 포함. 실제 native 실행과 별도 |
| Local templates | **18 PASS**, fixture-only loader2개도 PASS | 실제 upstream은 **SKIP**. CAIRN/model/report E2E가 아님 |
| Clean isolated build + forced repeat | **동일956bcf… JAR** | lock/strict dependency verification 유지, 로컬 재현성이지 독립 감사가 아님 |
| Isolated real Swing, scale1/2 | **각27 PASS**, failures/errors/skips0 | 별도 인증된 Xvfb/소유 WM. Native LAF·모든 OS/접근성 인증이 아님 |
| Frozen/source 일치 | Java/Python/tests/build/lock 입력 일치 확인 | Desktop 검사 수정은 아래 설명처럼 test-only; production JAR 불변 |
| 요청한 최종 독립 구현 감사3개 | **미완료** | 기존10개 실제 dispatch는 credential-rotator 중단, 실질적 보고서/승인0; 모델·인증·라우팅 대체 없음 |

첫 desktop 실행은 여전히 새 리스너 제한을 만들 수 있다고 기대한 과거 검사에서 실패했습니다.
해당 검사를 실제 지원 계약인 **기존 목록의 명시적 해제/확인**으로 수정한 뒤 두 scale의
27개 전체 검사가 통과했습니다. 건너뛰기·실패 무시는 하지 않았고 JAR bytes는 바뀌지 않았습니다.

## 실제 Burp 환경과 개별 결과

이미 허가된 임시 상태의 정상 **Community2026.10.1**에서 Main이 사람용 UI로 exact JAR을
로드/재로드했습니다. 별도 HOME/XDG/preferences/display, 임시 메모리 프로젝트, 두 소유
numeric-loopback inbound와 두 소유 backend만 사용했습니다. 설정·정책·OFF·해제·초안·
내보내기는 사람용 UI 조작이고 외부 client/fixture는 Burp 제어 API를 호출하지 않습니다.
사용자 기존 Burp/설치 JAR/프로필/라이선스/데스크톱을 바꾸거나 활성화 자료를 복사하지 않았습니다.

| Native 검사 | 관찰한 결과 |
|---|---|
| 빈/정확/기본 범위 | 빈 allowlist 미도착451, 정확 `/safe`의 GET/HEAD/POST·benign delete query 허용, descendant/유사 path와 DELETE 거절. 기본 정책의 명시 blockScope도 미도착 |
| 전체 리스너 | **두 실제 inbound 모두 DELETE 차단·GET 허용**. HTTP와 inspected HTTPS에서 각각 재검증. 미선택 listener bypass나 H가 아님 |
| Raw paths / actual destination | HTTP/1.1의14개 matrix/dot/separator/encoded/backslash/double-slash/malformed-percent target 및6종 unsupported/optional-overflow payload가 같은 값으로 도착. `/c/;/main.do`, `/c/%2e/main.do` 포함. Fuzzed Host는 실제 허용 목적지를 막지 않고 다른 실제 목적지를 허용하지 않음 |
| Health | 운영자 pause 중 명시된 정확한 empty GET만 도착. Query/body/POST/다른 path는 로컬451·미도착. HEAD는 header/미도착만 확인하고 response body를 주장하지 않음 |
| Fanout WARN/BLOCK/PAUSE | Query 변형은 같은 path로 계산. BLOCK/PAUSE는 threshold 경로의 최종 전송을 막고 기존 path도 보호. BLOCK은 다른 서비스를 남겨 두고 PAUSE는 다른 소유 서비스도 차단. 사람 해제 뒤 도착 복원. WARN3개 경로는 모두 도착하고 사건 기록 |
| Pacing / concurrency | 두 host의18회에서 shared5RPS/host2RPS 관찰;6개 held client의 fixture peak5. 도착 시각 관찰이지 엄격한 wire pacing 보장이 아님 |
| Queue / quarantine | 하나만 실제 도착한 상태에서 나머지5개 `QUEUE_TIMEOUT`. 미응답은 `IN_FLIGHT_TIMEOUT` 격리하며 실제 응답 전 slot을 임의 반환하지 않음 |
| Intent / EXEMPT | 같은 합성 intent20회 도착·21번째 budget451, 다른 intent는 도착. 같은 `/broker`의 EXEMPT가 일반 BLOCK보다 우선하고 다른 DELETE 기본 차단 유지 |
| Heavy / circuit | 첫6MiB 그대로 수신·다음 같은 path heavy451·사람 해제 후 다시 도착. 실제503 다섯 번 후 circuit, held half-open 한 건만 허용·동시 시도 거절·성공 후 닫힘. 짧은 시험용 TTL이지 모든 실패 cadence 조합 검증은 아님 |
| 후보 초안/저장 | 안전한 후보의 명시적 BLOCK과 별도 정확 경로1MiB 한도를 UI로 저장하고 canonical 정책으로 확인. Unsafe URL의 초안 비활성화·ignore 후 정책/revision 불변 확인. **Ignore 당시 overlay는 이미 만료돼 active overlay 유지까지 native PASS로 세지 않음** |
| 비Proxy 경계 | 동일한 소유 DELETE를 Proxy에서 typed RULE_BLOCK451로 거절한 뒤 사람이 Repeater로 보내200/fixture1회 도착. Guard 새 evidence/flight는 생성하지 않음. 다른 모든 도구의 전수 검사는 아님 |

허용 비교는 request-target/method/body bytes/선택 헤더·응답 값과 소유 socket 관찰입니다.
**원래 native object/annotation continuation**은 별도 adapter 회귀로 검사하며, 전체 wire bytes나
다른 확장의 사후 처리까지 native equality로 주장하지 않습니다.

### OFF·pause·진행 요청의 실제 lifecycle

- 확인 취소 뒤 보호 유지, 명시 OFF의 지속 경고, scope/rule/inspection/rate 우회 확인.
  정상 OFF 요청들은 evidence/raw 통계를 바꾸지 않고 bypass 횟수만 증가했습니다.
- 기존 protected 응답을 fixture가 보류한 상태에서 OFF로 바꿔도 native active1 유지.
  OFF-origin의 다른 요청은 새 row/slot 없이 도착했고, ON의 새 protected 요청은 queued1로
  기다렸습니다. **실제 old 응답 후** queued 요청이 한 번만 도착하고 active0이 됐습니다.
  그 뒤 OFF-origin 응답을 완료해도 보호 기록/raw 응답 통계는 증가하지 않았습니다.
- 별도 재검증에서 **전송 큐에 있던 protected 요청을 OFF가 POLICY_CHANGED로 취소**했고
  해당 backend 도착0이었습니다. 다른 old flight의 active1은 실제 응답까지 유지됐습니다.
  대기 ASK도 OFF가 POLICY_CHANGED로 취소했으며 자동 승인/대상 도착은 없었습니다.
- Pause→OFF→ON에서 운영자 pause 유지. ON은 resume이 아니며 이후 새 요청도 pause로 거절됐습니다.
- Intent limit2를 소진한 동일 태그가 OFF에서 한 번 도착할 때 budget/evidence/raw 통계는
  그대로였고, ON 뒤에는 다시 budget451·미도착이었습니다. OFF가 기존 debt를 지우지 않았습니다.
- 사람의 보관 기록 비우기 후 retained/raw11→0, 정책 revision/빈 listener 목록/intent debt 유지.
  누적 통계까지 초기화하거나 Burp 자체 history/이미 내보낸 파일을 지웠다는 뜻은 아닙니다.

초기 old-flight 두 시도는 운영 단계 불일치/fixture control timeout으로 최종 증거에 넣지
않았습니다. 명시적인 **소유 fixture만 제어하는 파일 신호**와 매 단계 native 진단으로 다시
실행했습니다. ASK의 초기 잘못된 helper 인자와 Repeater의 초기 UI/fixture timeout도 성공으로
세지 않았습니다. 최종의 조건·미도착·실제 응답/permit·증거 비교를 별도로 확인했습니다.

### 사람 원문 / JSON·HAR·사건 내보내기

- 사람 원문 request/response 화면에서 합성 Authorization/Cookie/body/HEX 반사 값을 확인했습니다.
  원문을 export의 입력으로 쓰지 않았습니다.
- 사람이 생성한 **JSON56건/HAR56건**과 incident는 모두 실제 파일로 파싱했고 **0600**이었습니다.
  검사한 합성 비밀45개 평문/UTF-8 HEX 소·대문자/Base64/URL-encoded 변형이 없었습니다.
  이는 알려진 fixture 변형 검사이지 임의 인코딩 전체의 DLP 증명이 아닙니다.
- 잘못된 UTC 입력은 native UI가 파일 선택 전 거절했습니다. 유효한 `[시작, 끝)` 창의
  사람 생성 incident를 network-free helper로 검사했고 **4개 사건/세 종류**
  `HEAVY_ENDPOINT_AUTO_BLOCKED`, `CIRCUIT_OPEN`, `FANOUT_SUSPECTED`를 확인했습니다.
  Top5xx1/TopBytes15 및 보관·누락·근사·시간 창 필드도 검사했습니다.
  완전한 통신 기록/대상 도착/취약점 출처 증명은 아닙니다.

### HTTPS / HTTP2의 확인 범위와 baseline 차이

임시 Burp의 **공개 CA certificate만** UI로 내보내고, fixture용 자체 서명 인증서를 만들어
client의 명시적 CA 검증으로 inspected HTTPS의 exact/alllisteners/rawpaths를 다시 실행했습니다.
개인 키/activation 복사나 시스템 trust store 변경, `-k` 우회는 없었습니다.

외부 curl이 실제 inbound HTTP2를 협상한5개 검사에서는 semicolon path, 대문자 percent path,
합성 인증/본문, fuzzed `:authority`를 허용하고 DELETE를 로컬451로 거절했습니다. 소유 origin은
HTTP/1.1이므로 **inbound H2→Burp→H1 origin**의 부분 검사이지 backend H2/전체 H2 matrix가 아닙니다.

초기 H2 `/c/%2e/main.do`는 origin에서 `/c/%2E/main.do`로 관찰돼 literal equality 검사가
실패했습니다. **Guard를 완전히 unload한 비교에서도 동일**했습니다. 이를 Guard의 rewrite나
원형 보존 PASS로 덮지 않습니다. 이후 대문자 spelling 검사는 별개입니다. HTTP/1.1에서의
소문자 spelling 성공과 혼동하지 않으며 Burp transport의 canonicalization까지 보장하지 않습니다.

## 남은 범위 / 정리

- 요청한 정확한 `ica-se-claude/claude-advantage-assist`의 최종 독립 구현 감사3개 미완료.
  기존10개 실패 시도 뒤 이전 소스에 대한 두 실질 cold 보고서를 받았으나 결함이
  지적됐습니다. Privacy/export 세 번째는 여전히 blocked이고, 수정 소스의 최종 검토나
  새 exact-JAR native 수용도 완료하지 않았습니다. 실질 보고서 없이 승인하지 않습니다.
- Active overlay 상태의 unsafe-candidate ignore, native cross-project/ABA와 모든 포화·종료 race,
  Professional 디스크 프로젝트/재시작 migration, 전체 HTTP2, opaque CONNECT/TLS pass-through/
  WebSocket frame, CAIRN/Pi/model/report-file E2E는 이번 결과로 주장하지 않습니다.
  강제 egress·인증/세션 관리·플랫폼 안전 인증도 제공하지 않습니다.
- Native Burp는 정상 UI로 종료했고 두 inbound/두 소유 fixture 포트가 닫혔음을 확인했습니다.
  private 원본 로그·스크린샷·프로필·내보내기·인증서/키는 Git에 넣지 않습니다.
- **정의된 시나리오의 개별 성공과 전체 수용/독립 검토/릴리스 승인은 서로 다릅니다.**
  H는 계속 별도 미래 작업이며, 미완료 감사를 다른 모델/인증/라우팅으로 대신하지 않습니다.
