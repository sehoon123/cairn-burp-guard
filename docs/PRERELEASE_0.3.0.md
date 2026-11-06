# v0.3.0 요청 기록 개선 개발 프리릴리즈

공개 상태와 다운로드는 [GitHub v0.3.0 릴리스 페이지](https://github.com/sehoon123/cairn-burp-guard/releases/tag/v0.3.0)에서 확인하세요. 문서나 소스 푸시만으로 공개·설치 완료를 뜻하지 않습니다. **이 exact JAR의 native Burp 로딩·callback·wire 동일성·대상 도착은 UNVERIFIED입니다.** 안정판·전체 A–G 수용·실서비스 안전 보증이 아닙니다.

**Authorization·Cookie·토큰도 평문입니다. 수집·보관·내보내기 상한이 없어 heap 증가·OOM·UI/Proxy 지연이 가능합니다.** 사용자가 메모리와 평문 파일 노출을 직접 관리해야 합니다. 원문 자동 디스크 저장·스풀은 없습니다.

## 누적 변경

이전 v0.2.0 자동 차단 제거 빌드 이후의 변경입니다.

- Logger++ 화면 흐름에서 착안한 독립 요청 기록 UI입니다. 수집은 여전히 Proxy-only이며 다른 Burp 도구 전체를 수집하는 Logger++ 대체품이 아닙니다. AGPL Logger++ 코드·자산·의존성을 포함하지 않았고 새 라이브러리도 없습니다.
- 전체·메타데이터·요청 헤더·요청 본문/HEX·응답 헤더·응답 본문/HEX의 여섯 위치에서 기본 Literal 또는 명시적 RE2 검색을 제공합니다. 필드·중복 헤더·요청/응답 경계를 이어 붙이지 않습니다. 잘못되거나 초과한 식은 고정 오류를 표시하고 이전 결과를 비웁니다. 입력·compiler 한도는 수집·결과·보관 상한이 아닙니다.
- 크기 조절·접기 가능한 inline 요청·응답 쌍과 자체 문서를 가진 별도 popout에서 Raw inspection, Headers, Body·HEX와 메타데이터를 봅니다. 이전/다음은 현재 정렬·필터 순서입니다. 관측 응답 body bytes, 선언 MIME, 사본 가용성을 추가하며 Tool·latency·wire 길이를 추측하지 않습니다. Raw 첫 줄은 synthetic inspection projection이지 wire transcript가 아닙니다.
- 선택한 탭에서만 만드는 Static HTML preview는 기본 제목·문단·목록·표·서식의 비활성 투영입니다. 완전하고 검증된 UTF8_TEXT/empty와 엄격한 HTML/XHTML 선언이 필요합니다. 자체 scanner가 속성·URL·CSS를 버리고 일반 Swing layout과 StyledEditorKit 텍스트만 만듭니다. HTML/XML/native Render 엔진, 외부 resource, JS, 이미지, 탐색, 폼은 없습니다. 복잡한 layout·일부 entity는 근사이고 큰 문서의 heap·EDT 비용은 무제한일 수 있습니다.
- 일치하는 Metadata/RE2 북마크 결과의 선택을 ID로 복원하고, 모든 필터 편집에서 현재 프로젝트·소스 membership을 다시 확인합니다. refresh 중 조정 중인 새 사람 선택을 덮어쓰지 않습니다. panel close는 승인 검토창의 같은 owned Document도 비운 뒤 폐기합니다. 복사한 문자열·클립보드·파일의 zeroization은 아닙니다.
- 자동 차단 제거는 유지합니다. 이전 5xx·대용량·fan-out·늦거나 누락된 응답이 다음 정책 허용 요청을 자동 차단하지 않습니다. 실제 목적지 scope, 명시 BLOCK/ALLOW/EXEMPT/ASK, 사람 승인·수동 pause, 수동 pacing·intent, OFF, 원문 capture와 기존 JSON/HAR/사건 형식은 그대로입니다. 검색·preview는 원문과 forwarding bytes를 바꾸지 않습니다.

세부 계약은 [UI](https://github.com/sehoon123/cairn-burp-guard/blob/v0.3.0/docs/UI.md)와 [Runtime/UI 계약](https://github.com/sehoon123/cairn-burp-guard/blob/v0.3.0/docs/RUNTIME_UI_CONTRACT.md)에 있습니다.

## 기록된 자동 검증과 검토

아래는 수용된 소스 후보의 실제 로컬 실행 기록입니다. 이 문서 작성 중 새로 실행한 suite가 아닙니다. 공개 전 독립 검증은 문서만 바뀐 최종 입력에서 같은 결과와 exact JAR을 재현해야 합니다.

| 검사 | 기록된 결과 |
|---|---|
| 전체 offline clean Java test/JAR | **1,369건 / 46 suites**, 실패·오류·skip 0 |
| Python helper fixture | **38건**, OK. native phase 검증 아님 |
| Template fixture | **18건**, OK, 두 fixture-only loader PASS. actual-upstream SKIP |
| 인증된 격리 Xvfb·owned WM의 실제 Swing, scale 1 | **38건 / 4 suites**, 실패·오류·skip 0 |
| 별도 강제 Swing 실행, scale 2 | **38건 / 4 suites**, 실패·오류·skip 0 |
| 두 clean JAR | 동일 bytes·SHA-256 |
| 원본 JAR 직접 검사 | **1,479 unique ZIP entries**, CRC 정상, **200 app classes**, class major **65**, Montoya classes **0**, 프로젝트·번들 legal 원문 일치 |

첫 정확성 검토는 새 adjusting-selection 회귀 때문에 BLOCKED였습니다. 제한된 수정과 수정 전 실패하는 회귀 검사 후, 새 비작성자 검토가 REVIEW_PASS를 반환했습니다. 검토 표기는 **GPT-6.1 Sol, independent non-author context**입니다. 검토자는 소스와 저장된 증거를 읽었고, 부모가 별도로 소스·XML·JAR hash와 unchanged exact-JAR 선택 probe를 확인했습니다. 독립 context 검토이지 모델 다양성이나 전체 v2 감사가 아닙니다. 기존 compiler warning 7건은 억제하지 않았으며 warning-free 검증이 아닙니다.

최종 commit의 CI 결과는 sealed `BUILDINFO.json`의 별도 항목입니다. CI는 로컬 두-scale Swing·exact 재현이나 native 검증을 대신하지 않습니다. 이 문서는 최종 CI 성공을 주장하지 않습니다.

## 산출물과 출처 확인

- 태그 이름은 `v0.3.0`입니다.
- JAR은 `cairn-proxy-guard-0.3.0.jar`, **3,009,472 bytes**입니다.
- SHA-256은 `570a7369f75baa729274d9d455b9f53942656a5eb28d79588fdeb4a94b7ae2a2`입니다.
- 업로드 대상은 수용된 원본의 byte-exact 사본입니다. 독립 재빌드는 동일성을 증명하며 원본을 대체하거나 재포장하지 않습니다.
- 최종 첨부 파일은 `cairn-proxy-guard-0.3.0.jar`, `BUILDINFO.json`, `RELEASE_NOTES.md`, `SOURCE-SHA256SUMS`, `SHA256SUMS`, `LICENSE`, `NOTICE`의 일곱 이름만 허용합니다. GitHub의 태그 소스 archive는 별도입니다. private snapshot·로그·보고서·템플릿은 첨부하지 않습니다.
- `BUILDINFO.json`은 검증 당시의 미커밋 165-input 집합, 그 집합 digest, raw manifest-file digest, 최종 publication commit/tree와 검증 입력을 구분합니다. publication 변경은 승인된 문서 다섯 개뿐이며 runtime·test·build·dependency·legal 입력은 수용된 후보와 동일해야 합니다. 별도 구현 commit을 만들어 주장하지 않습니다.
- `SOURCE-SHA256SUMS`는 최종 태그의 모든 Git blob bytes를 경로순으로 해시하며 mode는 Git tree에 결합됩니다. `gradlew.bat`만 canonical LF blob과 `.gitattributes`에 따른 raw CRLF checkout/archive를 구분하고 두 hash를 `BUILDINFO.json`에 기록합니다. 다른 byte 정규화는 허용하지 않습니다.
- `SHA256SUMS`는 자신을 제외한 여섯 첨부 파일을 해시합니다. 다운로드한 파일에서 `sha256sum -c SHA256SUMS`를 실행하고, JAR 크기·전체 hash와 sealed source/CI 항목도 대조하세요. 프로젝트 MIT `LICENSE`/`NOTICE`, JAR의 `META-INF/cairn-proxy-guard/` 사본과 번들 라이브러리의 원래 고지는 별개입니다. Montoya는 compile-only입니다.

## 한계와 rollback

Native Burp, callback 전달·target arrival, 전체 HTTP2 matrix, TLS pass-through·opaque CONNECT·WebSocket frames, 다른 확장의 사후 변경, live upstream/Pi/model/report-file E2E는 검증하지 않았습니다. 누락 callback 자체를 고친 것이 아니며 handoff는 도착 증거가 아닙니다. H 포트별 한정은 DEFERRED이고 빈 `guardListenerPorts=[]`로 모든 Proxy listener를 보호합니다. worker 제어·요청 replay·로그인·쿠키/JWT 주입·세션 복구·자동 설치는 없습니다.

Native 동시 실행 수는 제한하지 않습니다. provenance는 sampled 경계이며 취소 지연은 고정 상한이 아닙니다. 최종 export 검사와 rename 사이의 짧은 경쟁은 남아 있습니다. 큰 검색·preview·내보내기는 heap·UI 비용을 늘리고 이미 복사·저장한 평문은 clear로 회수할 수 없습니다. 현재 [native 체크리스트](https://github.com/sehoon123/cairn-burp-guard/blob/v0.3.0/docs/MANUAL_BURP_SMOKE.md#current-removal-aware-procedure)는 앞으로 사람이 확인할 절차이며 PASS 기록이 아닙니다.

[이전 v0.2.0 자동 차단 제거 빌드](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-06-no-auto-block-hotfix)와 [더 이전 무마스킹 빌드](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-05-v2-unmasked-unbounded)는 별도 hash의 rollback 기록입니다. 기존 release·tag·asset은 교체·삭제 대상이 아닙니다. 옛 native 관측은 이번 JAR로 옮겨오지 않습니다. rollback은 별도의 사람 작업이며 schema2를 읽지 못하는 더 오래된 JAR에는 미리 내보낸 원본 정책이 필요합니다. unload 후에는 보호가 없습니다.
