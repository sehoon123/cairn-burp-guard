# Cairn Proxy Guard

CAIRN을 수정하지 않고 Burp를 **사람이 관리하는 중앙 HTTP/HTTPS 안전 통제 계층**으로 사용하는 독립적인 Burp Extension MVP입니다. PortSwigger/CAIRN의 공식 제품이나 기존 Independent MCP Bridge의 새 버전이 아닙니다.

> 개발용 프리뷰입니다. 합성·로컬 테스트와 실제 Burp 검증을 구분합니다. 확장 자체가 Burp에 자동 설치되거나 사용자 프로젝트/전역 설정을 변경하지 않습니다. 허용 목록의 초기값은 비어 있어 모든 검사 대상 Proxy 요청이 차단됩니다.

**[최신 개발 프리뷰 JAR 다운로드](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-04-conditions-passthrough)** · [처음 사용하는 방법](docs/UI.md) · [검증 현황](docs/VERIFICATION.md) · [실제 Burp 결과](docs/NATIVE_BURP_RESULTS.md)

2026-11-04 모달·전체 통과 후속 개선: 확인/오류 창을 **스크롤·크기 조절 가능한 본문 + 분리된 버튼**으로 바꾸고, 모든 탭 위에 **모두 통과 (보호 끔)… / 보호 다시 켜기**를 추가했습니다. 전체 통과는 새 요청의 범위·규칙·검사·승인·속도 제한을 임시로 끄며 그 요청·응답 내용을 수집하지 않습니다. 기존 대기는 자동 승인하지 않고 취소합니다. **새 요청 모두 차단**과 반대입니다. 단일 조건에서 비활성화되던 **조건 추가**도 바로 AND 생성/같은 단계 추가로 동작하도록 수정했습니다. [상태·주의점](docs/PASSTHROUGH.md). 이번 프리뷰는 Java **845개** + 실제 Swing **20개**(UI scale1/2) + Python **35개** 검사를 통과했고, 해당 수정 범위의 독립 코드 검토 및 마지막 레이아웃 수정 후속 검토를 받았습니다. **이 JAR의 실제 Burp 통합 검증은 아직 하지 않았습니다.** [확장 명세 검토 초안](docs/AVAILABILITY_REVIEW.md)은 별개입니다: 확장 검토 지정 모델3명 중1명 완료, 당시 제공자 요청 중단으로2명 미실시이며 전체 합의/EXEMPT·ResponseWatcher·schema2 구현 완료를 주장하지 않습니다. 사용자 요청에 따른 제한된 개발 프리뷰이며 새 산출물의 검증은 이전 빌드와 구분합니다.

이전 examples 릴리스(`c071…`) 개선: JSON 없이 사용하는 폼에 **화면 안의 사용 예시, 일치·불일치 미리보기, 숫자 채우기 버튼, 표의 두 번 클릭/Enter**를 더했습니다. 예제 선택이나 폼 채우기가 정책을 자동 저장하지 않습니다. Java **783개** + Python **32개** 자동 검사를 통과했고, 그 당시 JAR을 격리된 Burp Community2026.10.1에 로드하여 **13개 실제 HTTP 시나리오 / 4개 phase**와 새 예제·승인·마스킹 내보내기를 확인했습니다. 이전 두 빌드의12개·54개 native 결과는 별개입니다. 그 hash의 전체 backend native matrix, HTTPS/HTTP2, 라이브 CAIRN/Pi 보고서 E2E, Professional 디스크 프로젝트와 강제 egress는 미검증입니다. 운영 안전성을 인증한 릴리스가 아닙니다.

## 역할과 제외 범위

```text
CAIRN Native Pi workers ──HTTP(S) proxy──> Burp Proxy + Cairn Proxy Guard ──> 허용된 대상
           └─ 점검 계획·탐색·검증·한국어 Markdown 보고서 작성
사람 ──Burp extension 탭──> Scope / Rules / Limits / Approval / Evidence
```

- 워커에 Burp MCP/Pi Extension/제어 API를 제공하지 않습니다. 확장 자체도 MCP/HTTP 서버를 열거나 대상에 새 요청을 보내지 않습니다.
- **기존 native request/response 및 annotations를 그대로 전달**합니다. 정책·로그에는 별도의 검사/마스킹 사본만 사용합니다.
- **로그인·쿠키/JWT 주입·세션 공유·만료 감지·갱신·계정/역할 관리를 구현하지 않습니다.** 인증 충돌 문제는 이번 버전에서 해결하지 않습니다. 주기적 재로그인 운영을 요구하지도 않습니다.
- 일반 규칙으로 로그인·로그아웃 경로를 차단할 수 있습니다. 이는 인증 기능이 아닙니다.
- 프록시를 우회하는 접속은 통제하지 못합니다. 강제 프록시/CA 신뢰 설정은 이 프로젝트가 변경하지 않으며 별도 검증 대상입니다.

## 기능

| 탭 | 기능 |
|---|---|
| 개요 | 현재 보호/차단 이유와 다음 행동, 대상 등록, 보호 대기·실행·격리/누적 통계, 새 요청 모두 차단. 전체 통과/보호 복원은 모든 탭 상단에서 조작 |
| 대상 | URL을 폼에 반영하고 실제 범위를 미리보기. 정확한 호스트·포트·경로부터 허용/차단 목록 관리. wildcard/하위 경로/고급 RE2는 명시적으로 선택 |
| 규칙 | 이름·동작·조건 폼, 일치·불일치 미리보기가 있는 빠른 시작 예제와 AND/OR 트리. 메서드/URL/경로/query/header/body/JSON/form, selector·대소문자·문자열/RE2 옵션 유지 |
| 요청 기록 | 마스킹 결과·이유·다음 행동, 별도 요청/응답 상세 창, 검색/필터/북마크, 하나의 JSON/HAR 내보내기 흐름 |
| 승인 대기 | 주소·이유·남은 시간과 마스킹 증거 검토 후 해당 요청을1회 승인/거절. 만료/정책·프로젝트 변경은 취소 |
| 설정 | 읽기 쉬운 RPS·동시성 입력과 1/1/1·5/5/5 폼 채우기. 상세 대기 시간은 초 단위, 호스트 예외는 표. 각 작업만 저장하며 전체 정책 JSON은 선택적 고급 기능 |

### 안전 기본값 (보호 켜짐 기준)

- Global RPS **5**, 호스트별 기본 RPS **5**, in-flight **5**, 대기열 **100**.
- 대기열/승인 **30초**, 응답 없는 in-flight의 격리 기준 **60초**.
- `DELETE` 메서드 및 대소문자를 구분하지 않는 `delete` 문자열 출현을 기본 차단합니다. 보수적인 substring 규칙이므로 `undelete`, 설명문, 토큰 등에도 오탐할 수 있습니다. 사람이 규칙을 좁히거나 끄고 검토합니다.
- Scope/검사 실패는 항상 차단합니다. 규칙의 우선순위는 **Block > Ask > Allow**이며 Monitor는 기록만 합니다. Allow/Monitor/승인으로 범위 밖 요청을 통과시킬 수 없습니다.
- 차단은 대상 요청을 계속하지 않고 **로컬 451 JSON 응답**으로 구별합니다. evidence ID와 `retryable:false`를 제공하며 원본 URL/비밀/정규식 capture를 응답에 복사하지 않습니다. 지원 API 장애 시 허용하지 않고 drop합니다.
- 전역·호스트별 pacing은 모든 검사 대상 Proxy worker가 하나의 예산을 공유합니다. **Burp 콜백 admission 기준**이며 네트워크 스케줄링까지 포함한 엄격한 서버 도착 시각 보장은 아닙니다.
- 응답이 사라진 요청은 완료 여부를 모르므로 permit을 자동 재사용하지 않습니다. 격리 후 새 admission을 차단하고 늦은 실제 응답이 오면 해제합니다. 이미 시작한 요청을 취소했다고 주장하지 않습니다.

## 빌드

필요: Java **21**, 최초 실행 시 Gradle/Maven Central 접속. 설치 대상은 Montoya API **2026.7**을 제공하는 호환 Burp Community/Professional입니다. 로컬 차단 응답 API는 2026.4 이후에 추가되었으며 구버전 호환을 추정하지 않습니다.

```sh
./gradlew clean test jar
python3 scripts/verify_templates.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

산출물:

```text
build/libs/cairn-proxy-guard-0.1.0-SNAPSHOT.jar
```

의존성은 Gradle lock/verification metadata로 고정합니다. Montoya API는 compile-only이며 JAR에 포함하지 않습니다. Jackson/RE2/J 라이선스와 배포 유의사항은 [NOTICE](NOTICE)를 참고하세요. 공개 개발 저장소는 [sehoon123/cairn-burp-guard](https://github.com/sehoon123/cairn-burp-guard)입니다. 개발 소스 공개와 검증된 릴리스 배포는 별도로 구분합니다.

## Burp에서 수동으로 시작하기

1. 실제 대상과 분리된 **새 검증용 Burp 프로젝트/인스턴스**에서 시작합니다. 이 MVP는 전용 listener를 식별하지 않고 **ToolType.PROXY 전체**를 통제하므로 같은 인스턴스의 사람 브라우징도 영향을 받습니다. Repeater/Scanner/Extensions 도구에는 적용하지 않습니다.
2. `Extensions → Installed → Add → Java`에서 위 JAR을 사람이 추가합니다.
3. `Cairn Guard → 개요`에서 상태를 확인합니다. 처음의 **허용 대상 없음 · 모든 요청 차단**은 안전한 초기 상태입니다.
4. 헷갈리면 상단 **사용 예시…**를 먼저 확인하세요. **허용 대상 등록…**에서 허가받은 전체 URL을 넣고 **Enter** 또는 **폼에 반영**을 누릅니다. 호스트·연결 방식·포트·경로와 **실제 범위 미리보기**를 확인한 뒤 **저장하고 적용**합니다. 기본은 그 경로만 허용합니다. 하위/모든 경로가 필요하면 허가 범위를 확인한 뒤 직접 선택하세요. 예제 주소를 무심코 허용하지 마세요.
5. **규칙**의 기본 차단 조건과 **설정**을 확인하고 필요할 때 폼으로 바꿉니다. 각 저장은 해당 작업만 적용하며, 취소는 변경하지 않습니다. 다른 프로젝트/설정 버전에서 연 오래된 창의 저장은 거절합니다. [화면별 사용법](docs/UI.md)
6. 별도의 CAIRN 실행 환경에서 HTTP(S) 프록시와 CA 신뢰를 사람이 준비합니다. 워커에 제어 도구나 관리용 연결을 넣지 않습니다. 프록시 장애 시 직접 접속으로 fallback하지 않습니다.
7. 실제 대상 전에 [수동 smoke checklist](docs/MANUAL_BURP_SMOKE.md)를 실행하고 결과를 기록합니다.

임시로 보호를 끄려면 상단 **모두 통과 (보호 끔)…**의 경고를 확인하고 명시적으로 선택하세요. 전체 Proxy가 검사 없이 통과하므로 워커 실행 중에는 범위 밖 요청도 나갈 수 있습니다. 기존 대기는 취소되며 OFF에서 새로 시작한 요청·응답은 기록하지 않습니다. 프로젝트 전환/확장 재시작에 OFF를 저장하지 않습니다. 다시 보호를 켜기 전에 트래픽을 멈추고 OFF 연결 완료를 확인하세요.

설치·언로드·프록시 구성은 여기서 자동 실행하지 않습니다. extension을 언로드하면 더 이상 보호하지 못합니다. 일시 차단은 새 요청만 막으며 기존 Burp 작업/OS 소켓을 취소하는 kill switch가 아닙니다.

## 정책과 증거의 한계

- 정규식은 **RE2/J**입니다. Java/PCRE의 lookaround·backreference 등은 거절합니다. 잘못된 규칙을 무시하거나 원본 예외를 로그에 출력하지 않습니다.
- URL percent-decoding 최대3회, JSON/Form 해석, authority 불일치/모호한 경로 검사를 포함합니다. 지원하지 않는 binary/multipart/압축/모호한 요청은 부분 검사 후 허용하지 않고 차단합니다. 상세 형식·한계는 [POLICY.md](docs/POLICY.md).
- HTTPS TLS pass-through, HTTP CONNECT 터널 내부, WebSocket 프레임, 다른 확장/도구의 독자 소켓, 콜백에 노출되지 않는 트래픽, 직접 egress는 보호 범위 밖입니다. 검사 이후 다른 확장이 요청을 바꾸면 이 확장의 판단이 최종 wire bytes를 입증하지 않습니다.
- 확장 증거는 기본 **메모리 전용**으로 최대2000건/추정32MiB, 부분당64KiB입니다. 오래된 항목은 북마크 여부와 무관하게 퇴출됩니다. 재시작 전 사람이 필요한 마스킹 사본을 내보내야 합니다. Burp 자체의 별도 원본 history/project 저장 정책까지 바꾸지는 않습니다.
- 인증 헤더·쿠키·민감 query/form/JSON 값은 가립니다. 안전하게 가릴 수 없는 HTML/free-text/binary/잘못된 body는 전체 생략합니다. 원본 wire capture나 완전한 DLP가 아니며, 누락/잘림을 보고서에 함께 적습니다. [EVIDENCE.md](docs/EVIDENCE.md)
- `FORWARDED`는 native continuation이 허용되었다는 뜻이지 대상 수신/처리 성공 증명이 아닙니다. 로컬451을 서버 취약점/오류의 증거로 해석하지 않습니다.

## CAIRN 템플릿

[CAIRN_TEMPLATES.md](docs/CAIRN_TEMPLATES.md)에 source-unmodified 외부 prompt_group, Origin/Goal/Hints, Native Pi 실행 예제와 검증 절차가 있습니다.

- `templates/native-pi-ko/`: 승인된 범위의 비파괴 능동 점검·계획·증거·보고 프로필.
- `templates/native-pi-ko-offline/`: 네트워크 없이 합성/마스킹 증거 검토를 시험하는 별도 프로필.
- `templates/reports/`: 한국어 Markdown 보고서와 checklist.
- `docs/KISA_MAPPING.md`: KISA 주제 기반 응용. 공식 원문 전체와 코드별 적합성을 검증하지 않았으며 공식 점검 완료/준수를 주장하지 않습니다.

보고서는 **CAIRN이 작성**합니다. 사람이 extension에서 내보낸 마스킹 자료는 선택적 추가 증거일 뿐, 워커가 Burp를 호출하거나 제어하지 않습니다. Prompt-only 요청 예산·보고 완료 지시는 강제 sandbox/완료 보장이 아닙니다. 강제 종료·쓰기 실패·인증 미준비·정책 차단을 미검증 범위로 보고합니다.

## 문서

[정책](docs/POLICY.md) · [속도/승인](docs/RATE_APPROVAL.md) · [UI](docs/UI.md) · [증거](docs/EVIDENCE.md) · [Burp adapter](docs/BURP_ADAPTER.md) · [검증](docs/VERIFICATION.md) · [실제 Burp 결과](docs/NATIVE_BURP_RESULTS.md) · [수동 smoke](docs/MANUAL_BURP_SMOKE.md)
