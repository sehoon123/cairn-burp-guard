# 사람이 사용하는 v0.3.0 소스 후보 화면 — 2026-11-06

일반적인 대상·규칙·수동 속도·태그 예산은 **JSON 없이 폼으로 작성**합니다. `Cairn Guard`는 Burp 안에서 사람이 사용하는 Swing UI입니다. 워커 제어 API, 요청 전송/재실행 도구, 인증 편집기·쿠키 주입·세션 복구 기능은 없습니다. 허용한 native 요청·응답·annotation을 수정하는 기능도 아닙니다.

> **사용자가 포트별 적용(H)을 추후로 미뤘습니다.** 현재는 빈 목록으로 모든 Proxy를 보호하며 새 제한을 폼/JSON으로 저장하지 못합니다. 기존 목록은 보존·fail-closed하고, 사람이 명시 해제/전체 보호 전환을 확인해야 비웁니다. H는 현재 gate나 PASS가 아닙니다. [현재 범위·개별 검증](ALL_LISTENERS_ACCEPTANCE.md)을 따르세요.

## 시작과 상단 보호 상태

1. 허가받은 검증용 Burp 프로젝트에서 **개요 → 허용 대상 등록…**을 누릅니다. 빈 허용 목록은 보호 대상 요청을 전부 차단합니다.
2. HTTP(S) URL을 입력하고 **Enter / 폼에 반영**을 눌러 초안을 채웁니다. 아직 저장하지 않습니다.
3. 실제 host/scheme/port/path 미리보기를 확인하고 **저장하고 적용**합니다. 기본 경로 방식은 ‘정확히 이 경로만’입니다.
4. **규칙**의 DELETE 메서드 기본 차단과 필요한 조건을 검토하고, **설정**에서 명시적 속도·태그 예산을 조정합니다.
5. Burp Proxy를 통해 요청을 보내고 **요청 기록**의 결과·검사 경고·응답을 확인합니다. ‘전송 해제’만으로 대상 도착·처리 성공을 단정하지 않습니다.

모든 탭 위에 보호 상태, 선택한 리스너, 전체 통과 누적 횟수와 **모두 통과 (보호 끔)… / 보호 다시 켜기**가 남습니다. 전체 통과는 별도의 명시 확인을 요구하며 모든 새 Proxy 요청의 범위·규칙·감지·승인·속도·태그 예산을 건너뜁니다. 새 전체 통과 요청·응답 내용은 수집하지 않고 횟수만 셉니다. 이전 보호 요청의 in-flight 추적은 유지합니다. 기존 대기를 승인하지 않고 취소합니다.

**OFF → ON에서도 이전 운영자 일시중지·태그 사용량·protected 응답 로그 association은 보존**합니다. 다시 켠 뒤 필요하면 운영자 일시중지를 별도로 재개해야 합니다. OFF는 프로젝트 전환·확장 재시작·상태 불확실성에서 끝나는 임시 상태입니다. 설정 저장은 OFF를 자동으로 켜거나 사용량을 초기화하지 않습니다. 복원 전에 트래픽을 멈추고 기존 연결 완료를 확인하세요.

**새 요청 모두 차단 / 보호 재개**는 운영자 일시중지이며 전체 통과/OFF가 아닙니다. 현재 native 한정 모드는 미지원이므로 빈 목록에서 전체 보호를 사용하세요. 제한 목록에서는 pause와 무관하게 선택·미선택 모두 LISTENER_UNVERIFIED로 거절됩니다. 명시적으로 설정한 GET 상태 확인 경로는 일시중지의 예외일 수 있습니다. 자동 PAUSE 기능은 제거되었습니다.

확인/오류 창은 plain text, 선택·복사·줄바꿈·세로 스크롤·크기 조절을 지원하며 버튼은 본문 밖에 남습니다. 확인 창의 초기 Enter/Escape/닫기는 **취소**입니다. 위험 작업은 확인 버튼을 명시적으로 선택해야 합니다. 창은 사용 가능한 모니터 영역으로 제한합니다. [전체 통과 경계](PASSTHROUGH.md)

## 일곱 탭

| 탭 | 사람의 작업 |
| --- | --- |
| **개요** | typed guardState, 로컬 451/대상 5xx 구분, 이유별 누적, 수동 pacing 대기 수, 운영자 pause/resume, 태그 예산 초기화 |
| **대상** | 실제 연결 대상의 허용/차단 범위 폼, 사용/중지/삭제, 저장될 범위 미리보기 |
| **규칙** | 이름·동작·AND/OR 조건 폼, EXEMPT 위험 경고와 보기 상단 고정, 사용/중지/삭제 |
| **요청 기록** | **원문** URL·메서드·요청·응답·태그, 결과·guardState·검사 경고·Intent/Run 검색/필터/정렬, 북마크, 평문 동의 후 **원문** JSON/HAR 내보내기 |
| **승인 대기** | ASK 원문 메서드·URL·일치 규칙·기한과 보관된 원문 요청 검토(증거 UUID로만 연결), 한 번 승인/거절 |
| **설정** | 수동 속도/대기·승인 시간·태그 예산·GET 상태 확인·기존 리스너 폼, 고급 JSON, 진단·기록 비우기 |
| **사건 내보내기** | UTC `[시작, 끝)` 창(기간 상한 없음)의 사건·top5xx·topBytes, 평문 동의 후 각 행의 원문 host/path (`cairn-human-incident` v1) |

상단 **사용 예시…**에는 대상 / 규칙 / 속도·결과 / 태그·내보내기의 읽기 전용 합성 예시가 있습니다. 안내를 열거나 선택·복사해도 저장·승인·전송하지 않습니다. 예시의 `example.test`는 실제 소유·허가한 대상으로 바꾸세요.

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

EXEMPT 행은 주황/적색 경고와 함께 표의 **보기에서만** 위에 고정됩니다. 다른 열을 정렬해도 위에 남지만 저장된 rules 순서를 바꾸지 않습니다. 활성 EXEMPT를 새로 만들거나 변경/활성화하면 저장 전에 **일반 BLOCK·ASK를 무시한다는 별도 확인**을 요구합니다. 범위·유효성·운영자 일시중지·명시 속도·태그 예산은 우회하지 않습니다. 기본 동작으로 EXEMPT를 선택할 수 없습니다.

‘빠른 시작’의 **GET /health 일반 규칙 예외 (주의)**는 정확한 METHOD GET **AND** PATH `/health` 초안입니다. 선택은 안내만, ‘예제로 폼 채우기’는 초안만 변경합니다. GET도 부작용이 있을 수 있으므로 직접 범위를 검토하세요. 이 규칙은 자동 health passthrough 옵션과 다른 기능입니다.

| 빠른 시작 | 조건 | 일치 / 불일치 |
| --- | --- | --- |
| POST /api/items 승인 요청 | METHOD POST AND PATH `/api/items` | POST 해당 경로 / GET 또는 하위 경로 |
| query operation=purge 차단 | QUERY 이름 `operation`, 값 EXACT `purge` | `?operation=purge` / 다른 이름·값 |
| JSON action=review 승인 | JSON pointer `/action`, EXACT `review` | `{"action":"review"}` / `{"other":"review"}` |

조건 추가는 기존 단일 조건을 AND로 묶고 새 조건을 선택합니다. AND/OR 트리와 selector·비교 값·대소문자를 편집하고 빈 묶음/깊이/개수/RE2 제한을 확인하세요. 기존 ID·사용 여부와 미수정 조건은 유지합니다. 값은 자동 trim하지 않으며 Enter는 비교 값에서 줄바꿈입니다. 폼 전체를 스크롤하므로 큰 폰트에서 조건 영역을 압축하지 않습니다.

## 명시적 속도·대기·태그·health 설정

전체 RPS / 기본 host RPS / 각 host override는 **0=끔,1–1000**입니다. 새 프로필은
0/0이며 저장된 양수는 보존합니다. **모든 속도 제한 끄기 (초안)**는 override 행까지
모두0으로 채웁니다. host 표기·행과 다른 설정은 보존하며 저장 전에는 적용되지 않습니다.
취소하면 원래 정책 그대로이고, 저장은 원래 프로젝트/revision CAS를 사용합니다.
1/1 및5/5 예시는 두 기본 속도만 채우며 저장은 별도입니다. host override0은 그 host
간격만 끄고 양수 global은 유지합니다. global0도 양수 host 간격을 끄지 않습니다.

| 활성 설정 | 범위 / 의미 |
|---|---|
| 수동 RPS | 각 축0=끔,1–1000; exact host override 최대256행, canonical 중복 불가 |
| 최대 대기 | 0–10000;0이어도 즉시 pacing 가능 요청은 통과 |
| 대기/승인 시간 | 0.001–600초, 정확한1ms 단위 |
| Intent 예산 | 최종 handoff 횟수0=끔, 최대1000000; 클라이언트 주장 태그는 인증이 아님 |
| GET 상태 확인 | 정확한 scheme/host/port/path 최대16행; empty/no-query GET만 manual pause 통과 |

실제 native 동시 실행 수는 제한하지 않습니다. 이전 응답·콜백·추정 timeout으로 새
요청을 막거나 자리를 기다리지 않습니다. pacing은 callback 간격이지 서버 도착 시각
보장이 아닙니다. 태그 사용량은 설정/OFF로 지워지지 않고 **개요의 확인된 수동 초기화**가
별도입니다. 모든 RPS를 꺼도 태그 예산까지 바꾸지 않습니다.

**INACTIVE legacy:** maxConcurrent, requestTimeoutMillis, 응답 크기/경로 한도/TTL,
5xx/fanout 및 detector 예외 값은 strict 호환 데이터로만 보존합니다. 활성 폼·탭·해제/
예외/후보 authoring이 없으며 고급 JSON/저장/재로드로 실행되지 않습니다.

상태 확인 활성/활성 경로 변경은 GET 부작용 확인이 필요합니다. scope·일반 규칙/ASK·
정책/프로젝트/종료·rate/intent는 우회하지 않습니다. 모든 경로 traffic 수용과 달리 health
설정은 정확하고 모호하지 않아야 합니다. H는 추후 지원: 새 nonempty listener 선택은
UI/JSON에서 거절, 기존 목록은 보존하고 명시적 확인된 비우기만 전체 보호로 전환합니다.

자동 차단은 토글 뒤에 숨긴 것이 아니라 제거되었습니다.5xx·큰 응답·경로 확산·미확인
콜백은 새 정책 허용 요청을 자동 차단/일시중지하지 않습니다. 개요는 retired native
stalled/quarantine을 현재 집행 상태로 표시하지 않습니다.

## 원문 요청 기록과 사람 원문 내보내기

최신 사용자 요구(2026-11-05)에 따라 **이 확장은 어떤 화면·출력도 마스킹하지 않고 수집 한도도 두지 않습니다.** 요청 기록·승인·사건과 JSON/HAR 출력 모두 project-bound·memory-only 원문입니다. 인증 헤더·쿠키·grant 등 **평문 민감정보를 포함**하며, 건수·바이트·기간 상한 없이 지우기·프로젝트 전환·언로드 전까지 메모리에 남아 **OOM·화면 지연이 생길 수 있으므로 직접 관리**해야 합니다.

- 화면은 읽기 전용 **검사 사본**이지 wire proof가 아닙니다. 원문 존재·실제 읽기 실패(불완전)·본문 표시 방식을 표시합니다. 지원하지 않는 charset/바이너리는 보관한 모든 바이트의 lossless HEX입니다. 상세 보기는 길이 필터 없는 읽기 전용·스크롤·선택 가능한 전체 내용입니다(정책 편집기 입력 한도와 별개). 없는 응답을 성공으로 만들지 않습니다.
- 원문이 없으면 ‘원문 없음/지움/미수집’을 표시합니다. OFF/미선택 리스너는 새 내용을 수집하지 않습니다. 표는 2000행 같은 표시 상한 없이 보관된 모든 행을 보여줍니다.
- 프로젝트/수명/기록 비우기에서 원문이 폐기됩니다(퇴출 없음). 상태 확인 실패나 panel close 시 화면에 남긴 detail도 비웁니다. panel close는 승인 검토창의 기존 owned Document도 비운 뒤 창을 폐기합니다. 복사한 문자열·클립보드·내보낸 파일의 zeroization은 아닙니다. 북마크는 영구 저장이 아닙니다.
- 검색의 기본값은 **All/Literal**입니다. 위치별 Literal 또는 명시 선택한 RE2로 원문 메타데이터·헤더·본문을 검사합니다. 검색은 집행 규칙이나 승인·속도·OFF 상태를 바꾸지 않습니다.
- 결과·북마크·method/status/UTC/project/Intent/Run/guardState 필터는 계속 literal AND입니다. Literal 메타데이터 hit는 즉시, 내용 및 RE2 메타데이터 hit는 기존 background 검색 lane에서 합칩니다. ‘내용 검색 중 (pending)’은 RE2 메타데이터 작업도 포함합니다. ‘검색 실패 (불완전 결과)’도 완료가 아닙니다. 검색 중/실패 내보내기는 클릭 시점 **현재 표시된 행/선택된 표시 행만, 불완전 결과**라는 확인을 보존합니다.
- 북마크 등 immutable 행 교체로 검색 재검증을 기다릴 때는 선택 ID·lead ID만 기억하고, 검증된 현재 표시 행에만 선택을 복원합니다. 숨은 ID는 상세·이동·설정 연결·선택 내보내기의 권한이 아닙니다. 정렬은 ID/lead를 유지하며 새 사람 선택·이동·필터 편집, 해당 행의 확정 불일치·소스 폐기·프로젝트/버전 변경·실패·비우기·close는 오래된 선택 의도를 폐기합니다. 무관한 행의 pending은 확정 불일치를 보존하지 않습니다.
- 첫 11열은 유지하고 관측 응답 본문 bytes(Long, 미상은 빈 값), 요청/응답 선언 MIME, 가용성·불완전·표시 encoding 열을 추가했습니다. 헤더 drag 정렬/폭 조절, 열별 정렬은 보기 전용이며 Tool/latency/wire 길이를 만들지 않습니다. 차단 색은 보조 표시이고 텍스트가 기준입니다.
- 표 아래 세로 divider와 inline 요청·응답 가로 divider는 resize/one-touch 접기가 가능합니다. 각 쪽 Raw inspection / Headers / Body·HEX, 결과·메타데이터와 보이는 이유 strip은 읽기 전용·선택·복사 가능하며 내용 상한이 없습니다. Raw 첫 줄은 **synthetic first line / inspection projection, not original wire transcript**입니다. 별도 상세 popout은 자체 component/document를 사용하며 inline을 빼앗지 않습니다. 이전/다음은 현재 정렬·필터 순서이며 끝에서 wrap하지 않습니다. 표 키보드 선택/북마크/여러 행 export는 유지됩니다.
- `exempt` / `probe_allowed` / `unpaired_response`와 pending/queued/approval을 구분합니다. 원문 table/detail은 screen-only이며 저장할 때 screen text를 가져가지 않습니다.
- `Decision`/`TrafficEntry.inspectionWarnings`를 표와 상세에서 보여주어 미평가 헤더/본문 조건을 평가 완료로 오인하지 않게 합니다.
- 승인 탭은 보관된 원문 요청을 보여줍니다(증거 UUID로만 연결, 프로젝트 표시 문자열로 연결하지 않음). 보관된 증거가 없거나 만료/변경된 ASK는 승인하지 않습니다. 상세 열기/닫기는 결정하지 않습니다.

**JSON/HAR/사건 내보내기는 화면 텍스트를 다시 파싱하지 않고** 보관된 구조(헤더 목록·모든 본문 바이트·완전성)를 씁니다. 매번(새 파일 포함) Authorization·Cookie·토큰 평문 경고를 기본 취소로 확인한 뒤 잠금 안에서 스냅샷을 만들고, 직렬화·파일 작업은 잠금 밖·EDT 밖, 이름 바꾸기 직전 최종 확인(그 사이 짧은 경쟁은 막지 못함)으로 소유자 전용 파일에 씁니다. 원문이 없으면 ‘원문 없음’입니다. 문서 크기 상한은 없습니다(큰 선택은 그만큼 메모리가 필요). 기계용 JSON/HAR/사건 API도 원문을 담고, 상태·로그 필드에는 요청 내용을 넣지 않으며 원문을 자동으로 규칙/설정에 채집하지 않습니다.

## v0.3.0 검색 위치와 방식

위치·방식은 **상세 필터**를 접어도 표시됩니다. **필터 지우기**는 검색어를 비우고
All/Literal로 돌아가며 오류도 지웁니다. 작은 창이나 큰 글꼴에서 제어·오류·최소 검사 영역이
함께 들어가지 않으면 요청 기록 전체를 세로로 스크롤할 수 있습니다.

| 위치 | 검색 후보 |
|---|---|
| All | 기존 메타데이터 값 또는 요청·응답의 개별 헤더와 본문 |
| Metadata | 표시 원문 URL·method, UTC 시각, 상태 문자열, 원래 이유 코드·번역, 증거 ID만 |
| Request headers | 보관 요청의 각 `name: value` 헤더 줄 |
| Request body | 보관 요청의 본문 또는 연속 HEX |
| Response headers | 보관 응답의 각 `name: value` 헤더 줄 |
| Response body | 보관 응답의 본문 또는 연속 HEX |

Metadata는 Intent/Run·guardState·MIME·검사 경고·preview·synthetic first line을 포함하지
않습니다. 원문 없는 행의 기존 표시 대체값은 유지합니다. 요청 연결 없는 응답 행에서 요청을
추측하지 않습니다. 검색어·위치·방식과 모든 상세 필터 편집은 기존 refresh 경로에서
현재 프로젝트·버전·소스 membership을 확인한 뒤 결과를 공개합니다. 원문 사본만 없는
보관 행은 메타데이터 검색에서 제외하지 않으며 이 확인은 여전히 샘플 경계입니다.

Literal은 메타데이터에 `Locale.ROOT` 소문자 substring, 내용에는 기존 문자별 대소문자 접기를
사용합니다. `.*`·대괄호·`[REDACTED]`도 문자 그대로입니다. RE2는 설치된 RE2/J로 대소문자
무시 Boolean `find`를 사용합니다. `matches`나 Java backtracking regex가 아닙니다.
inline flags는 RE2 의미 그대로이며 식을 소문자화·quote·trim하지 않습니다.
lookaround·backreference는 지원하지 않습니다. 예를 들어 요청 본문에서
`(?m)^action=review$`는 한 행을 찾습니다.

각 필드를 따로 검색합니다. 중복 헤더는 별개 줄이고 `(?s)`도 헤더끼리, 메타데이터 값끼리,
헤더와 본문, 요청과 응답을 이어 붙이지 않습니다. 비어 있지 않은 UTF8_TEXT 및 HEX 본문만
후보입니다. HEX는 화면의 연속 HEX 문자 그대로이며 홀수 위치에서도 찾고 UTF-8로 추측하지
않습니다. 없는 본문·EMPTY·UNAVAILABLE은 `^` 같은 zero-width 식에도 일치하지 않습니다.
기존의 빈 메타데이터 값은 zero-width 식에 일치할 수 있으므로 본문 존재의 증거가 아닙니다.
본문이 없어도 보관 헤더는 검색하며 불완전 사본의 알려진 부분은 기존 경고와 함께 검색합니다.

빈 검색어는 모든 위치·방식에서 검색을 끕니다. 공백은 데이터입니다. 입력은 4,096 Java 문자,
RE2 source는 4,096 문자, 컴파일된 프로그램은 4,096 instructions 이하입니다. 이 값은
작성·compiler 한도이며 검색 대상·결과·수집·보관·내보내기의 상한이 아닙니다.

잘못되거나 지원하지 않는 RE2는 `BAD_RE2`, 초과 편집은 `TOO_LONG`, 초과 프로그램은
`TOO_COMPLEX`라는 고정 오류를 표시합니다. 이전 결과·선택·상세 원문을 비우고 fallback이나
자동 truncate를 하지 않습니다. 초과 편집을 거부해 이전 문자가 입력창에 남아도 검색은
중지 상태입니다. 타이머·상세 필터는 이전 검색을 되살리지 않습니다. 입력·위치·방식의 실제
편집 또는 필터 지우기로 복구합니다. 오류에 원래 식이나 library exception을 붙이지 않습니다.

pending은 현재 query의 알려진 hit만 보여주며 실패도 현재 query의 알려진 부분 결과만
남깁니다. 같은 실패 query를 매초 재시도하지 않습니다. 내보내기는 chooser·평문 확인 중
검색이 완료되거나 위치·방식이 바뀌어도 클릭 시점 행과 불완전 결과 안내를 유지합니다.
원문 소실과 기존 project/revision 검사는 여전히 내보내기를 무효화할 수 있습니다.
RE2도 CPU·heap·취소 지연의 고정 상한은 보장하지 않습니다.

## v0.3.0 Static HTML preview

응답의 preview 탭을 선택할 때만 기본 HTML 제목(h1–h6)·문단·줄바꿈·목록·표·pre·bold/italic/underline/strike/code를 투영합니다. **완전하고 present인 UTF8_TEXT(또는 완전한 empty)**, 정확히 하나의 유효한 text/html 또는 application/xhtml+xml 선언과 생략/단일 UTF-8(UTF8)/US-ASCII charset만 대상입니다. charset 생략은 저장소가 이미 엄격 검증한 UTF8_TEXT 검사 사본이지 browser encoding detection이 아닙니다. 중복/잘못된 선언·unsupported charset·HEX·미수집/생략/잘림·모호하거나 nonidentity content/transfer encoding은 고정된 불가 이유를 보입니다. sniff/decompress/dechunk/meta charset/XML 처리를 하지 않습니다.

자체 iterative scanner가 **모든 source 속성/URL/CSS/event를 버리고**, 닫힌 block/run 데이터에서 일반 JPanel/GridBag 표와 StyledEditorKit/DefaultStyledDocument 텍스트만 만듭니다. HTML/XML/browser/native Render 엔진에 raw나 생성 HTML을 넣지 않습니다. script/style/title/template 내용은 숨기고 form/frame/object/embed/SVG/media/image/control은 고정 inert placeholder로 대체합니다. 링크 label만 남고 클릭/이동/폼/이미지/JS/외부 resource·file 접근은 없습니다. `amp/lt/gt/quot/apos/nbsp/copy/reg` 및 유효 numeric scalar entity만 디코딩하며 결과를 markup으로 재해석하지 않습니다. uncommon entity·nested table은 근사, style/list 중첩64 이후는 구조를 단순화하지만 일반 텍스트나 원문을 자르지 않습니다. **CSS·이미지·JS·탐색·full-browser fidelity 없음**을 상시 표시합니다.

원문/JSON/HAR 바이트는 이 투영과 무관합니다. preview 실패는 Raw로 돌아가는 이유이지 active renderer fallback이 아닙니다. 큰 문서의 AST/components/documents/EDT layout은 heap·시간을 무제한 사용할 수 있습니다. 비용 때문에 capture/result를 clipping하거나 자동 저장하지 않습니다. Native Render는 read-only만으로 외부 요청 억제를 입증할 수 없어 사용하지 않습니다.

패널이 search/presentation 두 lane을 소유합니다. 각 lane은 실제 처리1개+교체 가능한 최신 pending1개, EDT 전달도 최신 결과 하나만 합칩니다. 취소 후 실제 처리 exit 전에 교체 작업을 시작하지 않습니다. Message identity/current query cache는 변하지 않은 multi-MiB 본문을 매초 재검색/포맷하지 않고 같은 ID의 새 응답은 무효화합니다. worker는 immutable 사본만 읽으며 access는 EDT에서만 호출합니다. 공개 직전 source snapshot·프로젝트/revision·Message identity/availability를 다시 확인합니다(샘플 경계, 원자적 권한 아님). clear는 먼저 모든 inline/popout 원문을 비우고 작업을 취소합니다. 프로젝트 변경·원문 소실·refresh 실패·close도 pending/cache/문서와 owned popout을 폐기하며 실패 뒤 typing으로 오래된 행을 되살리지 않습니다. close는 자신의 thread를 interrupt/종료 신호하고 EDT를 무한 join하지 않습니다. native/다른 작업은 취소하지 않습니다. 메모리 zeroization 보장은 아닙니다.

## UTC 사건·증거·원본 정책 파일 내보내기

요청 기록 아래에서 필터가 적용된 현재 표/선택 행과 JSON/HAR를 고릅니다. 사건 탭은 UTC ISO-8601(끝 `Z`)의 `[from,to)`를 작성합니다. 끝이 시작보다 뒤인 1ms 단위이며 기간 상한은 없고 ‘최근1시간 채우기’는 입력만 변경합니다. 사건 한 파일에는 window/events/top5xx/topBytes와 보관 시작·시계 역행·확산 누락에 따른 완전성과 approximation 정보가 포함됩니다. 실제 보관된 창의 통계이지 lifetime/완전한 통신/장애 증명이 아닙니다.

모든 파일은 사람이 위치를 고릅니다. 취소는 쓰지 않고 기존 일반 파일 교체는 별도 동의가 필요합니다. 직렬화·쓰기 작업은 EDT 밖, 한 번에 하나입니다. 사건/원본은 프로젝트/revision도 다시 확인합니다.

POSIX에서는 임시/결과 파일 `0600`, 같은 디렉터리 atomic publication을 사용합니다. target symlink(깨진 링크 포함), 디렉터리·없는 부모·동의 이후 관찰 가능한 identity/size/time 변경을 거절합니다. hard link 원본에 직접 쓰지 않고 owner-only 새 inode로 교체합니다. 비원자적 fallback은 없습니다. 선택한 symlink 부모는 실제 디렉터리로 해석합니다.

공유 디렉터리의 악의적 동시 writer에 대한 sandbox나 fsync 내구성 보장은 아닙니다. 비POSIX owner-only ACL과 다른 플랫폼 atomic move는 검증하지 않았습니다. 중간 종료 시 빈 예약 파일/임시 파일이 남을 수 있습니다. 모든 출력은 평문 비밀을 포함할 수 있으니 공유·게시하지 마세요. [증거 경계](EVIDENCE.md)

## v1 → v2 비교와 명시적 저장

변환 대기이면 상단에 지속 banner와 **변환 비교 / 명시적 저장…**, **v1 원본 내보내기…**가 표시됩니다. 로드는 메모리에서만 v2로 변환합니다. 기존 rules·순서·행동을 유지하며 새 heavy/circuit/fanout/intent/health 옵션은 OFF, listener 목록은 빈 값(모두)입니다. 자동 EXEMPT나 legacy delete-string 제거를 넣지 않습니다.

비교 창에는 **행 위치 비교 diff / 저장된 v1 원본 / v2 메모리 변환** 읽기 전용 탭이 있습니다. 원본은 정확히 내보낼 수 있습니다. diff는 bounded line-oriented 비교이며 긴 문서는 표시 잘림을 알리고 원본/변환 탭을 참조합니다.

‘정확한 원본 legacy delete-string 규칙만 제거’는 **기본 미선택**의 별도 옵션입니다. 선택 시 변경될 v2/diff를 다시 보여줍니다. ID·이름·활성·동작·조건 모두 원본과 정확히 같은 rule만 제거하고 수정/중지/유사 이름은 보존합니다. **v2 명시적 저장 + 확인** 후에만 저장소를 교체합니다. 변환 대기 중 일반 대상/규칙/설정 편집으로 저장할 때도 v2 전체 교체 확인을 별도로 요구합니다. 구버전 JAR가 v2를 읽지 못하므로 원본을 먼저 내보내는 것을 권합니다. 취소/열기/새로고침/다시 열기는 저장하지 않습니다.

고급 JSON도 `PolicyCodec`의 엄격한 version dispatch를 사용합니다. 붙여넣은 v1은 안전 기본값·규칙 보존 변환 뒤 명시적 전체 v2 저장 확인을 요구합니다. missing/null/unknown/duplicate/coercion/trailing/oversize를 허용하지 않습니다. v1 payload에 v2 필드/EXEMPT를 몰래 섞지 못합니다. 최대2,097,152 Java 문자이며 입력 거절 뒤 이전 유효 JSON을 대신 저장하지 않습니다. 원문 인증정보를 넣지 마세요.

## 저장·수명·검증 범위

각 작업은 **열었을 때의 프로젝트/revision**을 유지합니다. timer로 다른 프로젝트를 읽어도 열린 초안을 새 baseline으로 바꾸지 않습니다. 마지막 확인 후 CAS를 다시 검사하며 stale 저장/런타임 해제를 자동 재시도하지 않습니다. 모든 policy copy는 새 Limits 전체와 `guardListenerPorts`를 보존합니다. 변경이 같은 값이면 불필요하게 저장하지 않되 실제 migration pending의 명시적 저장은 수행합니다.

패널/폼은 EDT-only, 1초 coalescing refresh입니다. 원문 evidence/관측 표시는 수집 상한이 없고 정책 입력·선택 검사·승인 용량은 bounded입니다. 이름·요청·응답·정책은 plain text이고 (선택적 static preview도 HTML engine 없이 닫힌 layout으로만 투영), 새 요청을 보내거나 URL을 여는 viewer가 아닙니다. 오류는 고정 범주이며 원본 exception/traffic을 로그나 오류 문자열로 붙이지 않습니다. close는 자신의 timer/worker/window와 화면 사본을 정리할 뿐 native 작업의 완료를 추측하거나 조작하지 않습니다.

합성 headless UI와 실제 격리 display의 Swing scale1/2는 native Burp 검증과 다릅니다.
이전 overlay/candidate/timeout smoke는 과거 기록이며 현재 기능 수용 기준이 아닙니다.
정확한 멤버별 보존/적응/제거는 [테스트 지도](AUTOBLOCK_REMOVAL_TEST_MAP.md)를 보세요.
실행 기록 없이 새 JAR/native/릴리스/독립 검토 완료를 주장하지 않습니다.

응답 correlation이 모호하지만 현재 protected 출처가 확인되면 **응답만 기록 (요청 연결 불가)**
행으로 모든 응답 원문을 보관합니다. 요청 method/URL/hits/tags는 추측하지 않으며 JSON/HAR도
unavailable로 내보냅니다. OFF/혼합/이전 프로젝트/지운/알 수 없는 출처는 수집하지 않습니다.
ID 재사용 자체로 요청을 차단하지 않고 내용 없는 used-ID tombstone만 unload까지 보존합니다.
