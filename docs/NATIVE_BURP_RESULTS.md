# 실제 Burp 검증 결과

## 2026-11-04 — 안내형 UI 빌드의 제한된 회귀 검증

검증 시각은 2026-11-04 KST / 2026-11-03 UTC입니다. **이전 UI의54개 시나리오를 새 UI 빌드에서 전부 재실행한 결과가 아닙니다.** 아래 두 산출물의 결과를 합산하지 않습니다.

| 항목 | 직접 확인한 값 |
|---|---|
| 제품 | 설치된 **Burp Community Edition v2026.10.1**의 정상 선택 화면 사용 |
| 확장 | Java21 / Montoya API2026.7, `cairn-proxy-guard-0.1.0-SNAPSHOT.jar` |
| 최종 JAR SHA256 | `a924d6c5aa08a10c3eceaf32f5e442cb5e423dc3499b3f4c2b5b9528e51eb2cc` |
| 격리 | 별도 임시 home/config/data/preferences, 인증된 중첩 X display, 임시 메모리 프로젝트 |
| 대상/클라이언트 | 소유한 numeric-loopback HTTP echo fixture와 Python 표준 라이브러리 클라이언트. **CAIRN/Pi 워커 아님** |
| 조작 | hash를 확인한 JAR 사본을 Extensions UI에서 새로 로드. 대상·규칙·설정·승인은 안내형 UI에서만 조작 |

중간 후보의 테스트를 최종 JAR 결과로 대체하지 않았습니다. 마지막 안내 문구 수정 후 clean build/test를 수행하고, 위 hash의 JAR을 다시 로드한 뒤 아래7개 phase를 모두 실행했습니다. 기존 사용자 프로젝트·설정·인증/활성화 자료를 가져오거나 바꾸지 않았고 CAIRN 소스·전역 프록시·CA 신뢰도 변경하지 않았습니다.

### 최종 JAR의 실제 HTTP 결과

**7개 phase / 12개 논리 시나리오 통과.** GET/HEAD를 함께 확인하는 한 시나리오가 있어 총13개 요청입니다.

| Phase | 논리 시나리오 | 직접 관찰한 결과 |
|---|---:|---|
| `empty` | 1 | 빈 허용 목록: `SCOPE_NOT_ALLOWED` 로컬451, fixture0건 |
| `exact` | 6 | URL 폼으로 정확한 `/safe` 등록. GET/HEAD 허용, 하위 `/safe/child`와 유사 `/safex` 제외, DELETE/디코딩 query 차단 유지, 허용 POST의 합성 값 보존 |
| `approve` | 1 | 폼에서 만든 AND(PATH `/ask`, METHOD GET) 승인 규칙. 미해결 때0건, 검토 창 확인 및 1회 승인 후1건 |
| `deny` | 1 | UI 거절: `DENIED`, fixture0건 |
| `expire` | 1 | 상세 설정에서 승인 제한을 **4초**로 입력/저장. `APPROVAL_TIMEOUT`, fixture0건 |
| `stale` | 1 | 승인 제한을30초로 복원 후 대기 중 설정 폼의 숫자를 바꿔 저장. `POLICY_CHANGED`, fixture0건 |
| `paused` | 1 | 개요의 새 요청 일시중지: `PAUSED`, fixture0건. 이후 UI에서 보호 재개 |

최종 보관 증거는 **13건 = fixture 응답200 4건 + 로컬451 9건**이었습니다. 차단은 단순 HTTP status가 아니라 guard 표식·정확한 reason·UUID evidence ID·`retryable:false`와 fixture 미도착을 함께 확인했습니다. `exact` phase는 외부 요청만 보내며 정책을 설정하는 Burp 제어 API는 없습니다.

허용된 합성 Authorization/Cookie/JSON body와 반환 body/선택 응답 헤더 값이 의도한 값과 일치했습니다. Burp의 transport/hop-by-hop 정규화까지 포함하는 전체 wire 동일성은 주장하지 않습니다. native 객체/annotations 보존은 별도 adapter unit tests의 범위입니다.

### 실제 화면/내보내기 확인

- 첫 화면의 빈 허용 목록 설명 → URL 폼 → 실제 범위 확인 → 저장을 사용했습니다. 전체 정책 JSON은 이 검증의 설정 경로에 필요하지 않았습니다.
- 조건 트리에서 기존 조건을 AND로 묶고 두 번째 조건을 추가하여 `/ask` 승인 규칙을 만들었습니다. 숫자 설정은 키보드 입력으로 변경하고 초 단위 제한도 저장했습니다.
- 승인 표의 주소/이유/남은 시간, 별도 마스킹 검토 창, 1회 승인/거절을 확인했습니다. 요청 상세도 메인 표와 경쟁하지 않는 별도 창에서 마스킹 요청/응답 탭을 확인했습니다.
- POST 검색·선택 항목 북마크 후 내보냈습니다. **전체 JSON13건 / 선택 HAR1건**, 두 파일 모두 `0600`이며 합성 bearer/cookie/password/response-cookie 원문4종은 없었습니다. 원본 내보내기·로그·스크린샷은 게시하지 않습니다.
- 독립 정적 리뷰가 찾은 숫자 필드 read-only와 실제 `AWAITING_APPROVAL`/`QUEUED` vocabulary 누락을 수정했습니다. 모든7개 숫자 필드 editable 회귀와 실제 controller/queue/UI 연결 회귀가 있습니다. 이 자동 검사가 native 큐 포화 UI 시험을 뜻하지는 않습니다.
- native에서 발견한 큰 폰트의 규칙 조건 영역 접힘과 안내 텍스트의 원치 않는 스크롤을 수정했습니다. 최종 JAR에서 전체 폼 스크롤과 상세 창을 확인했습니다. 허용된 요청의 다음 행동도 실패 진단 대신 응답/대상 증거 확인을 안내합니다.
- 모든 fixture 호출이 끝난 뒤 테스트 Burp를 정상 UI 종료하고, 이 작업이 만든 display/window manager와 임시 프로필·내보내기·로그·스크린샷만 정리했습니다.

### 이번 빌드에서 재검증하지 않은 범위

이번 native 실행은 **HTTP/1.1과 한 Linux 제품/디스플레이 환경**에 한정됩니다. HTTPS/HTTP2,6클라이언트 pacing/동시성/호스트 예외/큐 포화/격리, 전체 기존 custom matrix를 새 JAR에서 다시 실행하지 않았습니다. 아래 이전 hash의54개 결과는 이 빈칸을 채우지 않습니다. 관련 backend 자동 회귀는 통과했지만 별도의 native acceptance는 아닙니다.

`1100×760` 목표는 제품의 최소 창 크기 제약 때문에 이번 환경에서 native 확인하지 못했습니다. headless 큰 폰트/레이아웃 회귀를 완전한 HiDPI·다른 OS·접근성 검증으로 부르지 않습니다. Professional/디스크 프로젝트, native cross-project race, 재시작 복원, CAIRN/Pi/model 보고서 E2E, 강제 egress와 인증/세션 기능도 확인하거나 추가하지 않았습니다.

## 2026-11-03 — 이전 UI 빌드의 기록

> 다음54개 native 결과와 측정값은 **이전 SHA256 `56d0…d1a`에만 해당**합니다. 새 안내형 UI 빌드의 native 결과로 인용하지 마세요. 여기서 ‘최종’은 당시 빌드의 최종 산출물을 뜻합니다.

### 검증한 산출물과 환경

| 항목 | 직접 확인한 값 |
|---|---|
| 제품 | 설치된 Burp JAR의 정식 선택 화면에서 **Community Edition v2026.10.1** 선택, implementation build54773 |
| Burp JVM | 제품에 포함된 OpenJDK **26.0.2+10-55** |
| 확장 빌드 | Java21 / Montoya API2026.7, `cairn-proxy-guard-0.1.0-SNAPSHOT.jar` |
| 최종 JAR SHA256 | `56d0d1e3e02b6430352cd493bff97f8900eb4d5268140f44bac980d90c952d1a` |
| 격리 | 별도 임시 home/data/tmp, 인증된 중첩 X display, 임시 메모리 프로젝트 |
| 대상 | 자체 echo fixture만 사용: HTTP numeric loopback 두 호스트와 HTTPS `localhost` |
| 클라이언트 | Python 표준 라이브러리 HTTP 클라이언트. **CAIRN/Pi 워커 실행이 아님** |
| 조작 경로 | 배포 JAR을 Burp Extensions UI에서 로드. 정책·승인은 제품 UI에서만 조작 |

기존 사용자 프로젝트/프로필·인증정보·Professional 활성화 상태를 가져오지 않았습니다. 제품의 Community 모드 선택을 사용했으며 라이선스/활성화를 우회하지 않았습니다. CAIRN 소스, 설치된 Burp 바이너리, 시스템 프록시·전역 CA 신뢰 설정은 변경하지 않았습니다.

다음은 **최종 SHA256의 JAR을 다시 로드한 뒤** 실행한 결과입니다. 이전 JAR의 관찰과 합산하지 않습니다. 테스트 방법과 UI 설정별 전제는 [MANUAL_BURP_SMOKE.md](MANUAL_BURP_SMOKE.md), 정책은 [guard.loopback-smoke.json](../templates/examples/guard.loopback-smoke.json), 외부 fixture/client는 [native_burp_smoke.py](../scripts/native_burp_smoke.py)에 있습니다. 이 스크립트에는 Burp 제어 API가 없습니다.

### 실제 Proxy 결과

**14개 phase / 54개 논리 시나리오 통과.** 하나의 논리 시나리오가 여러 요청을 포함할 수 있으므로 요청 수나 JUnit 수와 혼동하지 않습니다.

| Phase | 논리 시나리오 | 직접 관찰한 결과 |
|---|---:|---|
| HTTP empty | 1 | 빈 allowlist: `SCOPE_NOT_ALLOWED` 로컬451, fixture0건 |
| HTTP default | 15 | GET/HEAD/POST 허용; DELETE, 혼합 대소문자, percent/double-percent, query/header/form/JSON Unicode, unsupported encoding/body, scope 차단; 공유 RPS·동시성 |
| HTTP custom | 8 | AND/OR, RE2 header, JSON pointer, form selector, case-sensitive/AND 음성 대조군; broad Allow/Monitor가 Block·hard gate를 덮지 못함 |
| disabled | 1 | UI에서 custom BLOCK 규칙 toggle/apply 후 해당 fixture 요청만 허용 |
| approve | 1 | 미해결 상태0건, UI 1회 승인 후1건; broad Allow보다 Ask 우선 |
| deny | 1 | `DENIED`, fixture0건 |
| expire | 1 | 승인4000ms 후 `APPROVAL_TIMEOUT`, fixture0건 |
| stale | 1 | 승인 대기 중 UI 정책 변경/apply → `POLICY_CHANGED`, fixture0건 |
| host | 1 | Global5 + 정확한 두 호스트 override2RPS, 6클라이언트/18건 |
| queue | 1 | 동시성1/큐80ms: 서버1건, 나머지5건 `QUEUE_TIMEOUT` |
| quarantine | 1 | 응답1.5초 보류/격리기준500ms: `IN_FLIGHT_TIMEOUT`; 실제 응답 후에만 후속 요청 허용 |
| paused | 1 | UI pause: `PAUSED`, fixture0건 |
| HTTPS basic | 13 | CONNECT 후 인증서 검증된 TLS 내부 HTTP/1.1에서 허용·변형/인코딩 차단·hard scope 결과 확인 |
| HTTPS custom | 8 | TLS에서 복합/selector/대소문자 조건과 hard-gate 우선순위 재확인 |

최종 수집 증거 **102건 = 실제 fixture 수신/응답200 57건 + 로컬451 차단45건**입니다. 보류 중 항목은 없었습니다. 차단 시 응답의 `source`, `outcome`, 정확한 reason, UUID evidence ID, `retryable:false`와 **해당 요청의 fixture 수신0건**을 함께 검사했습니다. 단순히451이라는 이유만으로 성공 처리하지 않았습니다.

#### 측정값

- Global5RPS: 6개 클라이언트가 두 호스트로18건 전송. 첫/마지막 fixture 도착 사이 **3.400초**, 최소 도착 간격 **0.199초**.
- 최대 동시성5: 응답을1.5초 보류한6건의 fixture 최대 활성 수 **5**. 실제 응답 전 permit을 재활용하지 않음.
- 호스트 override2RPS: 전체18건 도착 구간 **6.700초**, 각9건의 호스트별 구간 **6.700초 / 5.801초**. 전역 최소 도착 간격 **0.200초**. 상한은 처리량 보장이 아니며 FIFO/스케줄링으로 더 느려질 수 있습니다.
- 이 값은 이번 **로컬 fixture 도착 시각**입니다. 구현의 기준은 native callback admission이며, 임의 네트워크에서의 엄격한 도착 간격을 보장하지 않습니다.

#### 원본 값 보존과 마스킹

- 허용된 POST가 synthetic Authorization/Cookie와 JSON body bytes를 fixture에 그대로 전달했습니다. 반환 body와 선택한 응답 헤더/Set-Cookie 값도 클라이언트에서 일치했습니다.
- 이는 **확인이 가능한 값/본문의 비교**입니다. Burp 자체의 hop-by-hop/transport 정규화까지 포함한 전체 wire 동일성을 주장하지 않습니다. 확장의 native 객체/annotations 동일성은 별도의 adapter unit tests로 검사합니다.
- 실제 Traffic UI에서 `/echo`/POST 검색, 선택 항목 북마크, bookmarked-only 필터를 적용했습니다. 필터 JSON 및 선택 HAR는 각각 **표시된1건만** 내보냈습니다.
- 전체 JSON/HAR는 각각102건이며, synthetic bearer/cookie/password/response-cookie 원문4종은 네 내보내기 어디에도 없었습니다. 파일 권한은 모두 **0600**입니다. 원본 로그·스크린샷·내보내기는 게시하지 않습니다.
- `PAUSED` / `IN_FLIGHT_TIMEOUT`이 JSON/HAR에서도 정확히 유지되고 `OUTCOME_RECORDED`로 바뀌지 않음을 재검증했습니다.

#### TLS 신뢰 처리

임시 fixture 인증서를 만들고, Burp UI에서 임시 인스턴스의 **공개 CA 인증서만 DER로** 내보내 클라이언트별 `SSLContext`에 전달했습니다. hostname/chain 검증을 끄거나 시스템 trust store를 변경하지 않았습니다. `localhost`의 모든 해석 주소가 loopback인지 먼저 검사하고 그 주소에만 서버를 열었습니다.

설치된 제품이 numeric-IP 대상에 만든 인증서는 엄격한 IP-SAN 검증에서 거절됐습니다. 이 실패를 무시하지 않고, DNS identity가 명확한 `localhost`로 fixture/scope를 명시적으로 바꿔 검증을 통과시켰습니다. Numeric-IP HTTPS 호환을 확인했다는 뜻은 아닙니다.

### 실험 중 수정/정리한 사항

1. Native look-and-feel의 큰 컨트롤 때문에 Traffic 표가 접힘: 필터3행 구성, split 양쪽 최소 높이, 처음 표시될 때 divider 비율 적용. Headless regression2건과 실제 재로드 UI로 확인했습니다.
2. 일부 runtime/adapter 차단 사유가 증거에서 generic fallback으로 변함: adapter와 evidence가 **유한한 공통 `DenialReasons` vocabulary**를 사용하도록 수정했습니다. 53개 허용 사유 전부를 snapshot/JSON/HAR에서 검사하고, 임의 원문은 계속 제외합니다.
3. 첫 cold-cache GitHub CI에서 일부 BOM/parent 메타데이터 checksum 누락: refresh 후 검토한 checksum을 추가했습니다. 검증을 비활성화하거나 실패 테스트를 건너뛰지 않았습니다.
4. Composite JSON의 필수 primitive 필드 누락과 GUI 반복 중 남은 disabled draft 같은 **실험 전제 오류**는 그대로 성공 처리하지 않았습니다. canonical fixture 정책을 UI에서 복원하고, 최종 JAR을 재로드한 후 위54개 phase 시나리오를 전부 다시 실행했습니다.
5. 도구가 제공한 임시 CAIRN checkout이 만료돼 재검증이 중단된 경우, 같은 공개 upstream commit의 새 독립 checkout으로 재실행했습니다. 이는 확장 네이티브 성공이나 CAIRN E2E 실행으로 계산하지 않습니다.

### 아직 확인하지 않은 것

- 실제 CAIRN dispatcher/Pi/model의 능동 요청·보고서 파일 생성 E2E. 외부 템플릿의 실제 loader/parser/contracts/`DispatchConfig.load` 검증과는 별개입니다.
- HTTP/2 실트래픽, opaque CONNECT/TLS pass-through, WebSocket frame, 비Proxy 도구, 다른 확장의 사후 변경, 직접 소켓/강제 egress 방지.
- Professional 활성화/상용 기능/디스크 프로젝트, native 프로젝트 전환 중 대기 요청, Burp 재시작을 넘는 설정 복원. 같은 임시 프로젝트 안에서 idle extension unload/reload와 설정 재읽기만 관찰했습니다.
- native callback/inspection/correlation/approval/evidence의 최악 용량 포화와 모든 종료 race. 이런 경로는 bounded unit/mocked adapter tests로 검사하며 native 포화 시험으로 부르지 않습니다.
- 영구 미응답 소켓의 무한 기간 보장. 실제 시험은 **늦게 오는 응답**과 그 전의 fail-closed 격리입니다.
- KISA 공식 코드별 준수나 취약점 부재. 인증/세션 기능은 애초에 제외됩니다.

개발용 smoke 결과이지 완성된 안전 경계 인증이 아닙니다. Extension 언로드 후에는 보호가 없습니다. 테스트용 프로세스/프로필/인증서는 운영 환경이 아니며 결과 정리 후 해당 작업이 만든 것만 종료·삭제합니다.
