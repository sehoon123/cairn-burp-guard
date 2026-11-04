# v2 실제 Burp 관찰과 배포 차단 사유 — 2026-11-04

> **UNRELEASED / BLOCKED. 리스너 한정 모드(H)는 FAIL·미지원입니다.**
> 아래 개별 성공을 A–H 전체 수용·최종 독립 감사·설치·배포 승인으로 합치지 않습니다.
> `guardListenerPorts=[]`인 전체 리스너 보호와, 미지원인 한정 모드를 구분하세요.

## 정확한 산출물과 허가 범위

- 직접 재로드 후 검사한 최종 로컬 JAR SHA256:
  `43750326ca57a11fdb898850729c330d579538fb7d87261e0dc7b714993637b6`.
  Java21 / Montoya2026.7, 정상 선택한 **Burp Community2026.10.1**.
- 사용자가 **이 임시 인스턴스의 약관 동의만** 명시 허가한 뒤 진행했습니다.
  이전 ‘첫 EULA에서 중단’은 허가 전 관찰입니다. 활성화/라이선스 자료를 복사하거나
  우회하지 않았고 사용자 기존 Burp/JAR/프로젝트/설정은 교체하지 않았습니다.
- 별도 HOME/XDG/preferences/tmp, 인증된 임시 X display/소유 WM, 임시 메모리 프로젝트,
  소유 numeric-loopback 두 backend와 두 inbound Proxy 포트만 사용했습니다.
  포트·설정·확장 로드·정책·해제·내보내기는 Main의 사람용 UI 조작입니다.
  외부 fixture/client에는 Burp 제어 API·license 처리·정책 변경 기능이 없습니다.
- CAIRN/Pi/model을 통한 요청이나 보고서 E2E가 아닙니다. 원본 로그·스크린샷·내보내기·
  프로필·세션·사설 경로를 이 저장소에 복사하지 않습니다.

## 이 hash에서 직접 관찰한 개별 결과

| Native phase | 논리 시나리오 / backend 도착 | 관찰 |
|---|---:|---|
| `exact` | 6 / 4 | 정확한 `/safe`의 GET/HEAD/POST와 benign delete query 허용, 범위 외 경로 및 DELETE 로컬451. GET/HEAD를 묶은 시나리오가 있어 총7개 기록 |
| `rawpaths` | 21 / 20 | 14개 matrix/dot/separator/중첩 인코딩/backslash/leading-double-slash/malformed-percent target 원형 보존. Unsupported charset·binary·multipart·encoding·malformed JSON·선택적 한계 초과 본문6종 원형 전달. Fuzzed Host와 무관한 실제 목적지 scope도 확인 |
| `intent` | 2 / 21 | 새 합성 run의 같은 intent20회 도착,21번째 typed budget451·미도착; 다른 intent는 도착 |
| `exempt` | 2 / 1 | 같은 `/broker`의 BLOCK+EXEMPT 중 EXEMPT 승리; 다른 DELETE는 RULE_BLOCK. 사람 상세에서 두 matching rule과 exempt 결과도 확인 |
| `heavy` | 3 / 2 | 5MiB 한도에서 첫6MiB 전부 도착, 다음 같은 경로 로컬 heavy451·미도착, Main의 명시적 임시 차단 해제 뒤 다음6MiB 전부 도착 |
| `circuit` | 3 / 7 | 실제503 다섯 번, circuit 로컬451, 열림1초 후 held half-open 한 건만 허용·동시 시도 거절, 성공 응답 뒤 닫힘. 테스트용 open1초이며 기본10분/실패 재개방/30초 cadence 전체 검증은 아님 |
| Main-owned WARN client | 3 / 3 | 서로 다른 소유 경로3개 도착, 실제 incident에 `FANOUT_SUSPECTED`, `distinctPaths=3`. BLOCK/PAUSE native 수용까지 주장하지 않음 |

허용 비교는 원래 request-target/method/body bytes/선택 헤더·응답 값과 소유 socket 관찰입니다.
Burp 자신의 transport/hop-by-hop 처리·모든 wire bytes·임의 네트워크 도착 pacing을
증명하지 않습니다. 객체/annotation 동일성과 native getter 호출 여부는 별도 adapter 회귀입니다.

### 사람 원문 / 실제 내보내기 / 정책 불변 관찰

- 같은 최종 JAR의 사람 원문 요청·응답 화면에서 합성 bearer/cookie/password/응답 cookie를
  확인했습니다. JSON/HAR의7건과 사람 생성 incident는 실제 파일로 파싱했고 모두0600입니다.
- 검사한 합성 비밀의 **평문·UTF-8 HEX 소/대문자·기존 Base64 변형**이 없었습니다.
  실제 fixture의 전체 `body_hex` 반사도 제거됐습니다. 모든 임의 인코딩의 완전한 DLP 증명은
  아니며, mixed-case HEX는 별도 회귀로 검사했습니다.
- 사람 생성 incident를 `--phase incident --incident-file ...`의 **network-free** 검사로 검증했습니다.
  세 종류 사건 `HEAVY_ENDPOINT_AUTO_BLOCKED`, `CIRCUIT_OPEN`, `FANOUT_SUSPECTED`,
  시간 창·보관·잘림·근사 필드와 top 배열이 유효하고 최대 관찰 bytes는6291456이었습니다.
- 자동 차단과 수동 해제 전후 사람 UI에서 읽은 canonical 정책 JSON이 같았고 revision도
  저장 없이 유지됐습니다. 이것은 **정책 내용 관찰**이며 Native 내부 저장 파일의 write/mtime
  감시를 수행했다는 뜻이 아닙니다. source 회귀는 별도로 자동 정책 저장이 없음을 검사합니다.
- Native 대용량 후보 UI에서 max bytes 내림차순, count2, 근사 p95와 마스킹 경로를 봤습니다.
  안전하지 않은 마스킹 경로의 정책 초안은 비활성화됩니다. 안전 경로 초안의 모든 native
  저장/취소 조작을 검증했다는 뜻은 아닙니다.

## 발견1 — HEX 반사 마스킹 누락: 수정 및 재검증

기존 로컬 체크포인트 `82ec781` / JAR `217730d…`의 사람 JSON 내보내기에
`synthetic-native-password`의 HEX가 남았습니다. 이는 raw 화면과 무관한 **export 결함**입니다.
기존 encoded-variant 발견은 URL/JSON escape/Base64를 다뤘지만 HEX alias가 빠졌습니다.

`Redactor`가 bounded keyed fingerprint builder에 UTF-8 HEX 소/대문자 alias를 넣고,
HEX run만 transient case-fold해 mixed-case 반사도 가리도록 수정했습니다.
일치 run은 통째로 마스킹하고 불일치 문자열의 원래 case를 유지합니다.
기존 한도 초과/불완전 발견의 opaque fail-closed, HMAC-only 보관과 raw UI 분리를 유지합니다.
Native 요청·응답·annotation이나 정책 의미는 바꾸지 않습니다.

추가6개 회귀는 수정 전6 FAIL, 수정 후 PASS입니다. 전체 body HEX, header/path/부분 반사의
소문자·대문자·mixed-case, 안전 필드 유지, raw UI 보존, JSON/HAR/TrafficEntry를 검사합니다.
최종437503… JAR을 실제 UI에 재로드해 위 사람 화면과 내보내기를 다시 확인했습니다.
기존217730… bundle은 이 결함과 아래 H 실패가 있는 **거부된 과거 후보**이며 공개하면 안 됩니다.

## 발견2 — listener 연결 가정 실패: 기능 미지원, 약한 증거 제거

기존 후보의 두 inbound listener 검사에서 선택 listener의 DELETE가 예상 `RULE_BLOCK` 대신
`LISTENER_UNVERIFIED`였습니다. 진단에서 Proxy callback ID와 HTTP callback ID가 달랐습니다
(예:3/4). API에는 두 callback의 공통 ID 보장이 없습니다. 원래 annotation 객체 identity
연결 실험도 실제 실행에서 실패했고 원복했습니다. annotation 값/identity, 숫자 offset,
FIFO/시간/content fingerprint, 목적지 포트로 추정하지 않습니다.

**실패를 덮거나 우연한 같은 숫자를 증거로 허용하지 않도록** 최종 소스의 `ListenerObserver`는
원래 request/annotations를 continuation할 뿐 ID·listener·content를 읽거나 registry에 쓰지
않습니다. Core `ListenerRegistry`/trusted seam은 합성 모델 검사에만 사용되며 실제 Montoya
producer가 없습니다. UI의 저장 확인·지속 상태·설정·도움말은 **한정 모드 미지원**과
빈 목록으로 정상 전체 보호를 복구하는 방법을 명시합니다.

최종 JAR에서 H 수용 스크립트는 여전히 **예상대로 FAIL**합니다. 추가 mitigation 검사에서
선택·미선택 두 inbound 포트 모두 typed `LISTENER_UNVERIFIED`, backend0건입니다.
이는 정상적인 ‘미선택 bypass’ 구현이 아닙니다. 원래 필수 H 조건은 충족하지 못했습니다.

- Native 진단: trusted 기록0/보관0, unknown3. 수용 실패1건+양쪽 mitigation2건입니다.
- Raw 캐시 건수67→70은 `UNKNOWN https://redacted.invalid/`와 고정 로컬451의 **생략 placeholder**입니다.
  Native 원문을 새로 캡처하지 않았으며 사람 원문 탭에서 UNKNOWN/가림 주소와 실제 DELETE/
  목적지/경로의 부재를 확인했습니다. ‘새 raw entry0건’으로 잘못 해석하지 않습니다.
- 새4개 adapter 회귀는 Proxy/HTTP 숫자가 같거나 다르고 원래 annotation이 같아도
  리스너 허가 근거가 되지 않음을 검사합니다. 이전 소스는 같은 숫자2개에서 FAIL했습니다.
  HTTP의 service/path/header/body getter를 호출하지 않은 categorical 거절을 확인합니다.

공식적으로 지원되는 공유 identity/다른 계약을 확인하기 전 H는 차단 상태입니다.
요청/응답/annotation 수정이나 fail-open으로 수용 기준을 낮추지 않습니다.

## 남은 gate와 정리

- 정확한 최종 소스에 대한 요청 모델 `ica-se-claude/claude-advantage-assist`의 독립 감사3개는
  **미완료**입니다. 세 차례 wave, 총9개 dispatch가 credential-rotator 오류로 실질적 보고서를
  내지 못했습니다. exitCode0 메타데이터여도 error가 있어 승인으로 세지 않습니다.
  모델 대체·인증/라우팅 변경은 하지 않았습니다.
- H 외에도 native OFF 중 기존 permit/대기 lifecycle, 전체 포화·프로젝트 race, health·fanout
  BLOCK/PAUSE·모든 후보 draft 조작, HTTPS/HTTP2, Professional 디스크 프로젝트,
  CAIRN/Pi/model/report E2E는 이 hash에서 미검증입니다. 합성 검사는 빈칸을 대신하지 않습니다.
- 테스트 Burp는 정상 UI 종료했고 이 작업의 Burp/WM/runner PID와 네 개 소유 listen 포트가
  사라졌음을 확인했습니다. 기존 사용자 인스턴스를 종료하거나 설치 JAR을 바꾸지 않았습니다.
- **로컬 소스 체크포인트와 재현 빌드만 유지합니다. 공개 push/tag/release/사용자 설치 없음.**
  H의 지원 가능한 설계와 남은 native 수용, 정확한 소스의 독립 감사 후에만 다음 gate로 갑니다.
