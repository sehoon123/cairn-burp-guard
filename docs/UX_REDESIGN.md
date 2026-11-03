# UI/UX 재설계 — 2026-11-04 작업 기준

## 사용자 문제와 완료 기준

첫 버전은 JSON/내부 enum/진단 코드를 알아야 쓰는 개발자용 화면이었다. 단순 미관 수정이 아니라 일반 사용자의 흐름을 바꾼다. 기존 정책·저장 스키마·프록시 안전 경계는 변경하지 않는다.

- 처음 화면에서 현재 차단 이유와 다음 행동이 보인다. 허용 대상이 없으면 주소 등록 버튼으로 바로 진행한다.
- URL 붙여넣기/폼으로 허용·차단 대상을 추가/편집/삭제/켜기·끄기 한다. 실제 host/protocol/port/path 범위를 저장 전에 보여준다. userinfo/query/fragment를 조용히 제거하거나 host wildcard/경로 범위를 넓히지 않는다.
- 규칙은 이름, 동작, 조건 폼과 AND/OR 트리로 편집한다. JSON 지식은 필요 없다. selector, case, RE2 지원과 기존 조건은 손실 없이 유지한다.
- 각 작업의 명시적 저장은 해당 변경만 즉시 적용한다. 더 이상 서로 다른 탭의 숨은 초안까지 적용하는 Apply ALL 버튼을 요구하지 않는다. 저장 전 open-time project/revision을 유지하고 stale 저장은 거절한다.
- 대시보드는 raw JSON 대신 상태/숫자/다음 행동을 보여준다. 변경 성공과 차단/오류를 한국어로 설명하고 복구 행동을 제시한다.
- 요청 기록은 읽기 쉬운 결과/사유/필터/상세와 하나의 내보내기 흐름을 제공한다. 모든 데이터는 기존 마스킹 사본만 사용한다.
- 승인은 method/마스킹 URL/사유/남은 시간으로 판단한다. 내부 ID는 보조 상세로 이동한다. 만료/다른 프로젝트/일시중지/증거 없음 상태에서 잘못 승인하지 않는다.
- 설정의 일반 동작은 RPS·동시성 위주다. timeout은 초 단위, 호스트 override는 표/폼이다. 상세 설정은 펼쳐서 사용한다.
- Burp 테마를 따르고 색만으로 상태를 구분하지 않는다. 1100×760과 큰 기본 폰트에서도 핵심 표/버튼을 사용할 수 있어야 한다. 설정/운영 정보의 raw JSON은 명시적 고급/진단 보기이며 필수 경로가 아니다.

## 병렬 구현 계약 (기존 GuardUiAccess/GuardConfig API 변경 없음)

공통 새 패키지: `dev.cairnguard.ui.editor`.

- `EditorForm<T>`: `JComponent component()`, `T value()`. EDT-only, 검증 실패는 `FormValidationException`의 고정·행동 가능한 한국어 설명. 원본 예외/비밀/입력값을 오류에 이어 붙이지 않는다.
- `ScopeEditor(ScopeEntry initial)` (`null`=신규), implements `EditorForm<ScopeEntry>`. `static String summary(ScopeEntry)` plain display summary. URL에서 명시적으로 폼에 반영, enabled/host/scheme/port/path 모드와 실제 결과 미리보기. 정규식은 고급 선택지. 편집 시 기존 regex/host wildcard/any-port 의미 보존.
- `RuleEditor(Rule initial)` (`null`=신규), implements `EditorForm<Rule>`. 추가 컴포넌트 `ConditionEditor`는 같은 작업자가 소유. `static String summary(Condition)` plain display summary. 기존 rule ID 보존, 신규 ID 자동 생성. 시각적 LEAF/AND/OR 조합, 사용자 친화적 field/match/mode/selector labels, toggle. 예제는 synthetic만.
- `SettingsEditor(GuardConfig initial)`, implements `EditorForm<SettingsEditor.Value>`, nested `record Value(Mode defaultMode, Limits limits)`. seconds↔ms는 정확하게 보존/검증. `hostRps`는 bounded table/form, no JSON. 기존 설정을 바꾸지 않고 읽기만 했을 때 value는 같아야 한다.
- 모든 폼 위젯은 고유한 `setName`과 label/accessibility를 갖고 테스트 가능해야 한다. 동적 JLabel/tree/table renderer의 Swing HTML 해석을 끈다. 텍스트·행·트리 크기는 bounded; 기존 유효한 값을 조용히 자르지 않는다.
- 폼은 UI만, network/native Burp/storage/agent control API를 포함하지 않는다. GuardPanel이 modal 생성 시점의 config/project/revision을 캡처하고 final validation 및 compare-and-set 저장을 수행한다.

주 작업자는 `GuardPanel`, 인간용 메시지, 통합 UI 회귀 테스트, native/visual 확인 및 문서/배포를 담당한다. 하위 작업자는 자기 폼과 전용 테스트만 편집하고 commit/push/native 프로필 조작을 하지 않는다. 기존 사용자 Burp 프로젝트/라이선스/데스크톱 설정은 건드리지 않는다.

## 검증 구분

기존 backend/adapter 안전 테스트 유지 + JSON 없는 신규 사용자 경로·취소·stale dialog·기존 조건 round-trip·폼 validation·마스킹 export·EDT cleanup을 검사한다. 실제 제품/화면 검증을 하지 않았으면 headless 성공으로 대체하지 않고 미검증으로 적는다. 이전 native 결과의 JAR hash는 새 UI JAR 검증으로 재사용하지 않는다.

## 2026-11-04 최초 안내형 UI 반영/검증 기록 (이전 a924 산출물)

- 폼과 독립 저장 흐름을 연결하고 한국어 개요·실제 범위·조건 트리·초 단위 설정·별도 요청/승인 상세 창을 반영했다. 전체 정책 JSON/진단은 선택적 고급 기능이다. backend/저장/API/인증 기능은 확장하지 않았다.
- 독립 read-only 리뷰의 두 결함(숫자 입력 read-only, 실제 승인/전송 대기 vocabulary 누락)을 고쳤다. 숫자 필드7개 editable 및 실제 controller/queue/UI 회귀로 보완했다.
- 실제 Burp에서 발견한 큰 폰트의 조건 영역 접힘, 안내의 원치 않는 스크롤/포커스, 표와 상세의 공간 경쟁을 수정했다. 전체 규칙 폼을 스크롤하고 상세는 별도 창으로 연다.
- 최종 빌드771 JUnit/30 Python 자동 검사 통과. hash `a924d6c5aa08a10c3eceaf32f5e442cb5e423dc3499b3f4c2b5b9528e51eb2cc`를 다시 로드하고7 phase/12 HTTP 논리 시나리오 및 마스킹 JSON/HAR 내보내기를 확인했다. [범위와 한계](NATIVE_BURP_RESULTS.md)
- 1100×760은 설계 목표이지 native 통과 결과가 아니다. 이번 Burp의 최소 창 크기 제약으로 그 크기를 확인하지 못했다. 큰 폰트 headless 회귀를 전체 HiDPI/접근성 합격으로 해석하지 않는다. 이전54개 native matrix 전체도 새 hash에서 재실행하지 않았다.

## 2026-11-04 후속:더 짧은 조작과 이해하기 쉬운 예시

- 상단 **사용 예시…**에 대상/규칙/숫자·결과 읽기를 읽기 전용·복사 가능한 plain text로 넣었다. UI 밖으로 이동하거나 예시를 정책으로 자동 가져오지 않는다.
- 대상 URL의 Enter는 명시적 **폼 채우기**일 뿐 저장하지 않는다. 각 경로 방식에 일치/제외 예시를 표시한다.
- 규칙 예제를 고르면 일치/불일치 안내만 미리 보이고, **예제로 폼 채우기**로 이름·동작·조건을 바꾼다. ID·사용 여부는 유지한다. POST 경로 AND와 named-query 차단을 추가하고 JSON 승인 예제는 기본 delete 차단과 충돌하지 않는 `review`로 바꿨다. 기존 저장 조건은 자동 수정하지 않는다.
- 설정의1/1/1·5/5/5 버튼은 세 일반 숫자만 폼에 채운다. 상세 시간·기본 동작·호스트 예외와 저장 상태는 유지한다. 표의 두 번 클릭/Enter도 기존 guarded 편집/읽기 전용 상세 경로만 재사용하며 승인·요청 전송을 하지 않는다.
- **783 JUnit/23 suites + 32 Python** 통과. 읽기 전용·취소·stale/정렬 행·승인 비결정·예제의 양성/음성 대조·기본 차단 우선·기존 조건 보존·활성 숫자/호스트 편집·큰 폰트 스크롤을 회귀 검사했다.
- 현재 hash `c07116e051f6f49f7e582ffd8490e2ae234a91b22b6a8958bb82e55e646cf508`를 별도 Community2026.10.1에서 로드하고 **4 phase/13 HTTP 논리 시나리오**, 새 조작/예제/승인과 마스킹 JSON14건/HAR1건을 확인했다. 위 a924의12개나 더 이전54개를 합산하지 않는다. 현재 hash의 전체 backend native matrix는 재실행하지 않았다. [정확한 범위](NATIVE_BURP_RESULTS.md)
