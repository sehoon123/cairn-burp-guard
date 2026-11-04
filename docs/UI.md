# 사람이 사용하는 v2 화면 — 2026-11-04

일반적인 대상·규칙·속도·자동 안전 제어·태그 예산·리스너 설정은 **JSON 없이 폼으로 작성**합니다. `Cairn Guard`는 Burp 안에서 사람이 사용하는 Swing UI입니다. 워커 제어 API, 요청 전송/재실행 도구, 인증 편집기·쿠키 주입·세션 복구 기능은 없습니다. 허용한 native 요청·응답·annotation을 수정하는 기능도 아닙니다.

## 시작과 상단 보호 상태

1. 허가받은 검증용 Burp 프로젝트에서 **개요 → 허용 대상 등록…**을 누릅니다. 빈 허용 목록은 보호 대상 요청을 전부 차단합니다.
2. HTTP(S) URL을 입력하고 **Enter / 폼에 반영**을 눌러 초안을 채웁니다. 아직 저장하지 않습니다.
3. 실제 host/scheme/port/path 미리보기를 확인하고 **저장하고 적용**합니다. 기본 경로 방식은 ‘정확히 이 경로만’입니다.
4. **규칙**의 DELETE 메서드 기본 차단과 필요한 조건을 검토하고, **설정**에서 속도·자동 안전 제어를 조정합니다.
5. Burp Proxy를 통해 요청을 보내고 **요청 기록**의 결과·검사 경고·응답을 확인합니다. ‘전송 해제’만으로 대상 도착·처리 성공을 단정하지 않습니다.

모든 탭 위에 보호 상태, 선택한 리스너, 전체 통과 누적 횟수와 **모두 통과 (보호 끔)… / 보호 다시 켜기**가 남습니다. 전체 통과는 별도의 명시 확인을 요구하며 모든 새 Proxy 요청의 범위·규칙·감지·승인·속도·태그 예산을 건너뜁니다. 새 전체 통과 요청·응답 내용은 수집하지 않고 횟수만 셉니다. 이전 보호 요청의 in-flight 추적은 유지합니다. 기존 대기를 승인하지 않고 취소합니다.

**OFF → ON에서도 이전 운영자 일시중지·자동 차단·태그 사용량·미완료 native 자리는 보존**합니다. 다시 켠 뒤 필요하면 운영자 일시중지를 별도로 재개해야 합니다. OFF는 프로젝트 전환·확장 재시작·상태 불확실성에서 끝나는 임시 상태입니다. 설정 저장은 OFF를 자동으로 켜거나 사용량을 초기화하지 않습니다. 복원 전에 트래픽을 멈추고 기존 연결 완료를 확인하세요.

**새 요청 모두 차단 / 보호 재개**는 운영자 일시중지입니다. **보호하도록 선택한 리스너**에 적용하며 미선택 리스너까지 막는 방화벽이 아닙니다. 명시적으로 설정한 GET 상태 확인 경로는 일시중지의 예외일 수 있습니다. 자동 PAUSE는 운영자 일시중지와 별개이며 자동 차단 탭에서 확인합니다.

확인/오류 창은 plain text, 선택·복사·줄바꿈·세로 스크롤·크기 조절을 지원하며 버튼은 본문 밖에 남습니다. 확인 창의 초기 Enter/Escape/닫기는 **취소**입니다. 위험 작업은 확인 버튼을 명시적으로 선택해야 합니다. 창은 사용 가능한 모니터 영역으로 제한합니다. [전체 통과 경계](PASSTHROUGH.md)

## 아홉 탭

| 탭 | 사람의 작업 |
| --- | --- |
| **개요** | typed guardState, 로컬 451/대상 5xx 구분, 이유별 누적, 자동 안전 경고, 진행·대기 수, 운영자 pause/resume, 태그 예산 초기화 |
| **대상** | 실제 연결 대상의 허용/차단 범위 폼, 사용/중지/삭제, 저장될 범위 미리보기 |
| **규칙** | 이름·동작·AND/OR 조건 폼, EXEMPT 위험 경고와 보기 상단 고정, 사용/중지/삭제 |
| **요청 기록** | **원문 화면 전용** URL·요청·응답, 결과·guardState·검사 경고·Intent/Run 검색/필터/정렬, 북마크, **마스킹** JSON/HAR 내보내기 |
| **승인 대기** | ASK 메서드·마스킹 URL·이유·기한과 보관된 마스킹 증거 검토, 한 번 승인/거절 |
| **설정** | 속도/동시성/대기, 감지기·경로 한도·태그 예산·GET 상태 확인·실제 리스너 폼, 고급 JSON, 진단·기록 비우기 |
| **자동 차단** | 메모리 overlay의 종류·마스킹 host/path·시작/만료 UTC·남은 시간·이유, 선택/전체 해제 |
| **대용량 후보** | max/p95/count/5xx/최근 통계, **미저장** 일반 BLOCK 초안, 정확한 경로별 N MiB 한도 작성, 런타임 무시 |
| **사건 내보내기** | UTC `[시작, 끝)` 창(최대24시간)의 마스킹 사건·top5xx·topBytes JSON |

상단 **사용 예시…**에는 대상 / 규칙 / 속도·결과 / 자동 안전·태그·내보내기의 읽기 전용 합성 예시가 있습니다. 안내를 열거나 선택·복사해도 저장·승인·전송하지 않습니다. 예시의 `example.test`는 실제 소유·허가한 대상으로 바꾸세요.

대상·규칙 표의 두 번 클릭/Enter는 편집, 요청·승인 표는 상세 검토를 엽니다. 선택 없는 Enter, 빈 공간의 두 번 클릭, 우클릭은 결정하지 않습니다. 저장·승인·거절은 별도 버튼입니다.

## 실제 목적지와 경로

- 범위는 **실제 transport service의 host/scheme/port + 원래 request-target path**로 검사합니다. fuzz한 `Host`/`:authority`나 header-derived URL authority로 범위를 바꾸지 않습니다. Host를 바꾸어도 실제 외부 목적지를 허용하는 방법이 되지 않습니다. URL 규칙도 실제 목적지 URL을 뜻합니다.
- **모든 경로**(빈 path regex, `/.*`, `.*`)를 명시하면 `/c/;/main.do`, `/c/%2e/main.do`, dot/matrix/separator·중첩 인코딩 pentest target도 **원문 그대로** 통과할 수 있습니다. blanket `AMBIGUOUS_PATH` 사전 sanitizer가 아닙니다. native target/헤더를 정규화·수정하지 않습니다.
- 제한 경로는 bounded raw/decoded/conservative routing aliases가 모두 허용 범위에 있어야 합니다. 명시 blocked path와 일반 BLOCK/ASK는 계속 검사합니다. `PATH_INTERPRETATION_INCOMPLETE`는 불완전 경고이지 제한 범위 검증 성공이나 경로 의존 EXEMPT 허가가 아닙니다.
- 정확한 host는 그 host만, `*.example.test`는 하위 도메인만 포함하며 루트는 제외합니다. wildcard·HTTP/HTTPS 모두·모든 포트는 명시 선택해야 합니다.
- 경로 폼은 정확한 경로 / 하위 경로 / 모든 경로 / 고급 RE2입니다. `/api` 하위는 `/apix`를 포함하지 않습니다. 저장된 고급 regex를 열었다는 이유로 다시 쓰지 않습니다.
- URL 폼의 userinfo·query·fragment는 조용히 제거하지 않고 수정하도록 안내합니다. query 조건은 규칙으로 작성합니다. 정확한 경로 작성용 폼은 모호한 설정을 자동으로 추측하지 않습니다. 이것과 모든 경로 범위의 traffic 수용은 구분합니다.
- Host mismatch·중복/없는/fuzzed 헤더·지원하지 않는 body/charset/encoding·malformed JSON·선택 capture 한도를 **형식 자체로 자동 거절하지 않습니다**. 명시한 헤더/본문 조건은 검사 가능할 때 평가하고 불가능한 검사는 경고로 보입니다. 불완전 조건으로 EXEMPT를 허가하지 않습니다. 실제 목적지 확인·정책·프로젝트·용량·종료 같은 필수 경계는 계속 fail closed입니다.

[정책과 RE2 제한](POLICY.md)

## 규칙과 EXEMPT

동작은 **EXEMPT > BLOCK > ASK > ALLOW**입니다. MONITOR는 다른 결정을 덮어쓰지 않습니다. 새 규칙 기본값은 BLOCK이고 새 정책에 EXEMPT는 없습니다. 새 정책의 기본 delete 방어는 **DELETE 메서드만**입니다. GET `deleteInfoBoardComnt.do` / `undelete` / 설명문·토큰의 delete 부분 문자열만으로 기본 차단하지 않습니다.

EXEMPT 행은 주황/적색 경고와 함께 표의 **보기에서만** 위에 고정됩니다. 다른 열을 정렬해도 위에 남지만 저장된 rules 순서를 바꾸지 않습니다. 활성 EXEMPT를 새로 만들거나 변경/활성화하면 저장 전에 **일반 BLOCK·ASK를 무시한다는 별도 확인**을 요구합니다. 범위·유효성·운영자 일시중지·자동 안전 제어·속도·태그 예산은 우회하지 않습니다. 기본 동작으로 EXEMPT를 선택할 수 없습니다.

‘빠른 시작’의 **GET /health 일반 규칙 예외 (주의)**는 정확한 METHOD GET **AND** PATH `/health` 초안입니다. 선택은 안내만, ‘예제로 폼 채우기’는 초안만 변경합니다. GET도 부작용이 있을 수 있으므로 직접 범위를 검토하세요. 이 규칙은 자동 health passthrough 옵션과 다른 기능입니다.

| 빠른 시작 | 조건 | 일치 / 불일치 |
| --- | --- | --- |
| POST /api/items 승인 요청 | METHOD POST AND PATH `/api/items` | POST 해당 경로 / GET 또는 하위 경로 |
| query operation=purge 차단 | QUERY 이름 `operation`, 값 EXACT `purge` | `?operation=purge` / 다른 이름·값 |
| JSON action=review 승인 | JSON pointer `/action`, EXACT `review` | `{"action":"review"}` / `{"other":"review"}` |

조건 추가는 기존 단일 조건을 AND로 묶고 새 조건을 선택합니다. AND/OR 트리와 selector·비교 값·대소문자를 편집하고 빈 묶음/깊이/개수/RE2 제한을 확인하세요. 기존 ID·사용 여부와 미수정 조건은 유지합니다. 값은 자동 trim하지 않으며 Enter는 비교 값에서 줄바꿈입니다. 폼 전체를 스크롤하므로 큰 폰트에서 조건 영역을 압축하지 않습니다.

## 모든 v2 설정을 폼으로 작성

숫자 예시 **천천히 1/1/1**, **기본 5/5/5**는 전체 RPS / 기본 host RPS / 동시 요청 세 값만 채웁니다. 호스트 예외·상세 시간·새 안전 제어·리스너는 유지하며 저장은 별도입니다. 동시 요청 수는 워커 수가 아니라 실제 응답 대기 수입니다. host FIFO/eligible round-robin과 전체 속도·동시성 한도는 서버 도착 간격 보장이 아닙니다.

| 폼 | 단위·의미 |
| --- | --- |
| RPS·동시 요청 | RPS 1–1000, 동시 1–100 |
| 상세 대기 | 대기열 0–10000, queue/approval/request timeout 0.001–600초, 1ms 정확도 |
| host 예외 | 최대256행, 정확한 host·1–1000RPS, canonical alias 중복 불가, 기존 authored 표기 보존 |
| 기본 응답 한도 | 0–2048 **MiB**; 0=끔, 바이트 정수로 정확히 환산되는 소수만 수용 |
| 자동 차단 유지 | 1–86400초, 1ms 정확도 |
| 5xx 회로 | 사용 체크, 창 1–3600초, threshold1–1000, 열림1–86400초; half-open=1 고정 |
| 확산 감지 | 사용 체크, 창1–3600초, 서로 다른 경로2–1000, 서비스 BLOCK / 전체 자동 PAUSE / WARN |
| Intent 예산 | `(Run, Intent)`별 최대 최종 전송 허가 0–1000000; 0=끔 |
| 상태 확인 | 사용 체크 + 최대16행의 정확한 scheme/host/port/path GET |
| 경로 응답 한도 | 최대256행, scheme/host/port/path + MiB (0=그 경로 크기 감지 끔) |
| 보호 리스너 | 빈칸=모든 Proxy 리스너; 쉼표로 최대16개 고유 포트1–65535 |

새 프로필은 기본 경로5MiB, 5xx5회/60초·열림10분, 확산100경로/60초 WARN입니다. v1 변환은 새 감지/예산/상태 확인 OFF입니다. 옵션을 껐다고 이미 열린 차단을 지우지 않습니다. 경로 표 행의 추가·편집·삭제도 저장 전까지 초안입니다. 시간·바이트를 반올림하거나 잘린 입력/이전 유효 값으로 저장하지 않습니다.

상태 확인·경로 응답 한도의 **설정 경로**는 query/fragment/userinfo·모호한 경로·중복을 거절하는 exact authored route입니다. traffic의 all-path 수용과 혼동하지 마세요.

**GET 상태 확인 통과 활성화/활성 경로 변경**에는 별도 확인이 필요합니다. 정확한 GET만 운영자 일시중지·회로를 통과합니다. 범위·일반 규칙·heavy/fanout·예산·속도는 유지하고 회로를 회복시키지 않습니다. GET도 부작용이 있을 수 있습니다.

**리스너 제한을 새로 지정/변경**하면 별도 확인합니다. 실제 Burp **인바운드 Proxy listener**이며 목적지 서비스 포트가 아닙니다. 미선택 리스너는 내용 수집·검사·일시중지·예산을 우회합니다. 리스너를 확실히 확인하지 못한 보호 콜백은 내용 수집 없이 거절할 수 있습니다. [adapter 경계](BURP_ADAPTER.md)

응답 미확인은 native permit을 임의 반환하지 않습니다. stalled host를 격리하며 다른 host는 실제 사용 가능한 전체 슬롯만 쓸 수 있습니다. 설정 저장/재개/논리 timeout으로 in-flight 자리를 재활용하지 않습니다.

## 자동 차단·후보·태그 사용량

**자동 차단**은 영구 정책과 별개인 메모리 overlay입니다. 시작/만료·남은 시간·종류·이유를 보여주며 선택/전체 해제는 확인 후 원래 프로젝트/revision으로 CAS합니다. 만료·교체된 ID가 다른 차단을 해제하지 않습니다. 정책 파일을 저장하지 않습니다. 회로의 ‘만료’는 닫힘 보장이 아니라 half-open GET/HEAD 가능 시각입니다. 서비스당 최대30초에 한 번이며 성공200–499는 닫고 5xx/응답 미확인은 다시 엽니다. 자동 PAUSE는 운영자 플래그와 별개입니다.

**대용량 후보**는 max bytes 기본 내림차순이며 p95(근사)/count/5xx/최근 시각을 보여줍니다. 보관/퇴출로 불완전할 수 있다는 안내를 표시합니다.

- **일반 BLOCK 규칙 초안…**: watcher가 제공한 안전한 no-query `policyUrl`일 때만 URL-anchored ordinary BLOCK 초안을 엽니다. hard blockScope나 자동 저장이 아닙니다. query 변형을 포함하되 다른 경로로 넓히지 않습니다. 마스킹된/안전하지 않은 URL에는 비활성화합니다. 응답으로 URL이 나중에 재마스킹되면 열린 초안의 자동 복사 저장도 거절합니다.
- **이 경로 N MiB 초과 차단…**: 경로별 watcher 한도의 미저장 초안입니다. 첫 초과 응답은 이미 전송된 뒤에 감지하므로 예방할 수 없다는 경고를 보고, 명시적 저장 확인을 거쳐 정책에 추가/교체합니다. 다른 모든 설정·리스너를 유지합니다. 기존 overlay는 별도 만료/해제가 필요합니다.
- **무시…**: 런타임 후보만 숨깁니다. 정책·사건·열린 차단을 삭제하지 않으며 프로젝트/재시작 뒤 영구 유지하지 않습니다.

`X-Cairn-Intent`/`X-Cairn-Run`은 **클라이언트 주장**이며 인증·신뢰 경계가 아닙니다. 한도를 꺼도 사용량은 유지합니다. **개요 → Intent 예산 초기화…**는 다시 예산을 쓸 수 있다는 확인과 원래 프로젝트/revision CAS 후 메모리 사용량만 지웁니다. 정책/overlay는 그대로입니다.

## 원문 요청 기록과 마스킹 내보내기의 분리

최신 사용자 요구에 따라 **요청 기록 화면은 기본 원문**입니다. 별도 bounded·project-bound·memory-only raw getter에서 URL·요청·응답·태그를 읽습니다. 인증 헤더·쿠키·grant 등 **민감정보를 포함할 수 있음**을 표시합니다. 원문을 TrafficEntry의 serializable 필드에 넣지 않습니다.

- 화면은 읽기 전용 **검사 사본**이지 wire proof가 아닙니다. 원문 존재/만료·잘림·생략·본문 표시 방식을 표시합니다. 지원하지 않는 charset/바이너리는 보관 바이트의 lossless HEX prefix일 수 있습니다. 없는 응답을 성공으로 만들지 않습니다.
- raw가 없으면 ‘원문 생략/만료/미수집’을 표시하며 URL 표에는 마스킹 메타데이터 fallback임을 명시합니다. OFF/미선택 리스너는 새 raw 내용을 수집하지 않습니다.
- 프로젝트/수명/퇴출/기록 비우기에서 raw가 폐기됩니다. 상태 확인 실패나 panel close 시 화면에 남긴 raw detail도 비웁니다. 북마크는 영구 저장·퇴출 방지가 아닙니다.
- 검색은 원문 화면 URL·method·이유 등에서 literal substring입니다. 결과·북마크·method/status/UTC/project/Intent/Run/guardState 필터는 AND 결합합니다. `.*`를 regex로 해석하지 않습니다. Intent/Run·결과/상태/검사 경고 열도 정렬할 수 있습니다.
- `exempt` / `probe_allowed` / `half_open`과 pending/queued/approval을 구분합니다. 원문 table/detail은 screen-only이며 저장할 때 screen text를 가져가지 않습니다.
- `Decision`/`TrafficEntry.inspectionWarnings`를 표와 상세에서 보여주어 미평가 헤더/본문 조건을 평가 완료로 오인하지 않게 합니다.
- 승인 탭은 별도 마스킹 증거 검토 화면입니다. 현재 프로젝트/revision의 보관된 증거가 없거나 만료/변경된 ASK는 승인하지 않습니다. 상세 열기/닫기는 결정하지 않습니다.

**JSON/HAR/사건 내보내기는 절대로 raw UI getter나 화면 텍스트를 직렬화하지 않습니다.** 보관된 sealed/masked TrafficEntry 및 watcher의 재마스킹된 incident만 사용합니다. Authorization/Cookie/X-Broker-Grant·response-learned secret의 export 마스킹은 raw 화면 요구와 별개로 유지합니다. raw를 자동으로 규칙/설정에 채집하는 기능도 없습니다.

## UTC 사건·증거·원본 정책 파일 내보내기

요청 기록 아래에서 필터가 적용된 현재 표/선택 행과 JSON/HAR를 고릅니다. 사건 탭은 UTC ISO-8601(끝 `Z`)의 `[from,to)`를 작성합니다. 양수·최대24시간·1ms 단위이며 ‘최근1시간 채우기’는 입력만 변경합니다. 사건 한 파일에는 window/events/top5xx/topBytes와 보관 유실·truncation·approximation 정보가 포함됩니다. 실제 보관된 창의 통계이지 lifetime/완전한 통신/장애 증명이 아닙니다.

모든 파일은 사람이 위치를 고릅니다. 취소는 쓰지 않고 기존 일반 파일 교체는 별도 동의가 필요합니다. 직렬화·쓰기 작업은 EDT 밖, 한 번에 하나입니다. 사건/원본은 프로젝트/revision도 다시 확인합니다.

POSIX에서는 임시/결과 파일 `0600`, 같은 디렉터리 atomic publication을 사용합니다. target symlink(깨진 링크 포함), 디렉터리·없는 부모·동의 이후 관찰 가능한 identity/size/time 변경을 거절합니다. hard link 원본에 직접 쓰지 않고 owner-only 새 inode로 교체합니다. 비원자적 fallback은 없습니다. 선택한 symlink 부모는 실제 디렉터리로 해석합니다.

공유 디렉터리의 악의적 동시 writer에 대한 sandbox나 fsync 내구성 보장은 아닙니다. 비POSIX owner-only ACL과 다른 플랫폼 atomic move는 검증하지 않았습니다. 중간 종료 시 빈 예약 파일/임시 파일이 남을 수 있습니다. 마스킹 자료도 민감하게 취급하세요. [증거 경계](EVIDENCE.md)

## v1 → v2 비교와 명시적 저장

변환 대기이면 상단에 지속 banner와 **변환 비교 / 명시적 저장…**, **v1 원본 내보내기…**가 표시됩니다. 로드는 메모리에서만 v2로 변환합니다. 기존 rules·순서·행동을 유지하며 새 heavy/circuit/fanout/intent/health 옵션은 OFF, listener 목록은 빈 값(모두)입니다. 자동 EXEMPT나 legacy delete-string 제거를 넣지 않습니다.

비교 창에는 **행 위치 비교 diff / 저장된 v1 원본 / v2 메모리 변환** 읽기 전용 탭이 있습니다. 원본은 정확히 내보낼 수 있습니다. diff는 bounded line-oriented 비교이며 긴 문서는 표시 잘림을 알리고 원본/변환 탭을 참조합니다.

‘정확한 원본 legacy delete-string 규칙만 제거’는 **기본 미선택**의 별도 옵션입니다. 선택 시 변경될 v2/diff를 다시 보여줍니다. ID·이름·활성·동작·조건 모두 원본과 정확히 같은 rule만 제거하고 수정/중지/유사 이름은 보존합니다. **v2 명시적 저장 + 확인** 후에만 저장소를 교체합니다. 변환 대기 중 일반 대상/규칙/설정 편집으로 저장할 때도 v2 전체 교체 확인을 별도로 요구합니다. 구버전 JAR가 v2를 읽지 못하므로 원본을 먼저 내보내는 것을 권합니다. 취소/열기/새로고침/다시 열기는 저장하지 않습니다.

고급 JSON도 `PolicyCodec`의 엄격한 version dispatch를 사용합니다. 붙여넣은 v1은 안전 기본값·규칙 보존 변환 뒤 명시적 전체 v2 저장 확인을 요구합니다. missing/null/unknown/duplicate/coercion/trailing/oversize를 허용하지 않습니다. v1 payload에 v2 필드/EXEMPT를 몰래 섞지 못합니다. 최대2,097,152 Java 문자이며 입력 거절 뒤 이전 유효 JSON을 대신 저장하지 않습니다. 원문 인증정보를 넣지 마세요.

## 저장·수명·검증 범위

각 작업은 **열었을 때의 프로젝트/revision**을 유지합니다. timer로 다른 프로젝트를 읽어도 열린 초안을 새 baseline으로 바꾸지 않습니다. 마지막 확인 후 CAS를 다시 검사하며 stale 저장/런타임 해제를 자동 재시도하지 않습니다. 모든 policy copy는 새 Limits 전체와 `guardListenerPorts`를 보존합니다. 변경이 같은 값이면 불필요하게 저장하지 않되 실제 migration pending의 명시적 저장은 수행합니다.

패널/폼은 EDT-only, 1초 coalescing refresh입니다. evidence/approval/overlay/candidate 표시와 입력은 bounded입니다. 이름·요청·응답·정책은 plain text(HTML 해석 없음)이고 새 요청을 보내거나 URL을 여는 viewer가 아닙니다. 오류는 고정 범주이며 원본 exception/traffic을 로그나 오류 문자열로 붙이지 않습니다. close는 자신의 timer/worker/window와 화면 사본을 정리할 뿐 controller/native permit을 임의로 닫지 않습니다.

현재 소스 UI 검증은 합성 input·mock CAS·실제 in-process controller를 사용하는 **분리된 private source copy**에서 **291 headless UI cases PASS / 27 desktop-tag Swing cases PASS**입니다 (2026-11-04). 새 회귀는 `GuardPanelV2Test` 24개, `SettingsV2Test` 4개, `GuardPanelV2DesktopTest` 7개입니다. 모든 v2 설정 roundtrip/host·preset 보존, EXEMPT 정렬·확인, overlay 만료/교체/stale 해제, 후보 초안/한도/재마스킹, raw-screen/masked-export, 태그 필터/초기화, migration cancel/manual-save/reopen/원본 export, UTC 사건/파일 안전성을 포함합니다. desktop는 자기 소유의 격리 Xvfb에서 실행했으며 실제 모달 lifecycle·14/28pt 폼·listener/GET 추가 확인·migration·threshold 저장/취소를 검사했습니다. 패키지는 scratch에만 추출했고 시스템 설치/설정 변경이나 live display 사용은 하지 않았습니다. 실행 명령은 `./gradlew --no-daemon --offline --max-workers=2 test --tests 'dev.cairnguard.ui.*'`, 별도 private display의 `./gradlew --no-daemon --offline --max-workers=2 desktopTest`입니다.

**이 문서는 v2 native Burp/두 리스너/실제 6MiB/5xx/최종 JAR 검증이나 release 승인을 주장하지 않습니다.** 이전 artifact의 native 결과와 최신 소스 UI 결과는 구분해야 합니다. [산출물별 실제 native 결과](NATIVE_BURP_RESULTS.md)
