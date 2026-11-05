# v2 WARN 이력 용량 수정 — 개발 프리릴리즈, 2026-11-05

> **실험용 개발 빌드 / 전체 검증 미완료.** 사용자의 명시적 요청으로 공개합니다.
> 이 exact JAR의 제한된 native 검사와 변경 한정 리뷰는 완료했지만 전체 A–G 수용,
> 최종 전체 v2 독립 감사나 정식 배포 승인이 아닙니다. 실서비스 보호에 의존하지 마세요.

- 태그: `dev-2026-11-05-v2-warn-history`
- [프리릴리즈](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-05-v2-warn-history)
- 기능 소스: `e913178d03526f0eeee2a46f4a67d415dc0d231d`. 이후 게시용 문서는 JAR 입력을 바꾸지 않습니다.
- 최종 태그 커밋·빌드 출처·검증 범위: 첨부 `BUILDINFO.json`. 공개 소스의 canonical Git blob 해시: `SOURCE-SHA256SUMS`.
- 원본 로그·스크린샷·Burp 프로젝트/프로필·내보내기·인증서/키·라이선스/인증 자료는 첨부하지 않습니다.

## 이전 공개 체크포인트 이후 변경

- `183e106`: clear/eviction으로 더 이상 보관하지 않는 evidence 선택은 JSON/HAR 전체 내보내기를
  거절합니다. 보관 중인 과거 선택은 최신 마스킹을 사용합니다. 이미 반환한 문자열/파일을 소급 정화하지는 않습니다.
- `e913178`: 완료 WARN 경로가 공용 path 용량을 계속 점유하던 문제를 수정했습니다.
  색인 이력은 기존 전역2048개 상한, 누락은 고정 크기 상태로 관리합니다. 색인에 넣지 못한
  새 WARN 경로는 이력 예산만으로 전송을 거절하지 않고 누락 수치·불완전 경고를 표시합니다.
- WARN에서 BLOCK/PAUSE로 바꿀 때 오래된 WARN latch만 끝냅니다. 기존 강제 보호·실제
  in-flight 예약·late-ticket 소유권은 유지하며 누락 이력이 남으면 강제 모드는 fail-closed입니다.
- 새 의존성, Burp 제어 API, 인증/세션 기능, 포트별 보호(H)는 추가하지 않았습니다.

## 경로·본문 동작

- 실제 목적지 host/scheme/port가 허용된 All paths라면 `/c/;/main.do`, `/c/%2e/main.do` 등
  세미콜론·인코딩 표현 자체를 일괄 차단하지 않습니다. Guard는 전달 target을 normalize/rewrite하지 않습니다.
- 지원하지 않는 body/charset/encoding, 깨진 JSON은 그 형식 자체로 자동 차단하지 않습니다.
  규칙에 필요한 선택 검사만 best-effort로 수행하고 검사 불가 경고는 남깁니다.
  이번 게시에서 본문 파서·charset 지원이나 모호성 경고를 제거한 것은 아닙니다.
- 명시적 BLOCK/차단 대상, 실제 범위, 속도·용량·자동 안전 제어는 별개입니다. All paths는 보호 OFF가 아닙니다.

## 이 exact JAR의 검증

| 계층 | 직접 확인한 결과 / 한계 |
|---|---|
| 격리 Java21 | **1321 PASS /45 suites**, failures/errors/skips0. 작성자 및 부모의 별도 clean test/jar 실행 |
| 실제 Swing | 소유 Xvfb에서 scale1·2 각각 **27 PASS**, failures/errors/skips0. Native Burp나 모든 OS/접근성 인증이 아님 |
| Python / template | helper **32 PASS**, local-template **18 PASS**와 fixture loader2개 PASS. 실제 upstream은 **SKIP** |
| 로컬 재현 | clean 빌드4개가 아래 full JAR hash와 일치 |
| GitHub CI | [기능 커밋 CI 성공](https://github.com/sehoon123/cairn-burp-guard/actions/runs/41936618746). 다운로드 JAR도 같은 hash, XML1321/desktop27 직접 확인. CI는 Burp를 실행하지 않음 |
| 좁은 독립 리뷰 | `openai/gpt-6.1-sol`, `ica-se-claude/claude-advantage-assist`에서 차단 지적 없음. 리뷰어가 테스트/native를 실행한 것은 아니며 전체 v2 감사3개를 대체하지 않음 |

**Native:** 정상 사용자 승인 절차의 Community2026.10.1/build54773, Temurin21.0.11+10,
네트워크 비활성 격리 환경과 소유 loopback HTTP/1.1 fixture만 사용했습니다. 사람용 GUI로
로드/설정/내보내기를 수행했고 사용자 기존 Burp·프로필·활성화·전역 proxy/trust 설정은 바꾸지 않았습니다.

- 동일 설정 A/B: 기존 JAR은 완료 경로2048개 뒤2049번째를 로컬 capacity451로 거절했습니다.
  수정 JAR은 같은 실제 서비스의 순차 요청 **2200/2200 도착**, 비교한 method/target/합성
  auth·cookie/빈 body/응답 불일치0, UI **색인2048·누락152**를 확인했습니다.
- 누락 뒤 BLOCK/PAUSE는 기존 path·새 path·다른 허용 service의 요청을 미도착 거절했습니다.
  OFF/ON·같은 프로젝트 저장·감지 disable/re-enable로 누락 debt가 사라지지 않았습니다.
  별도 온전한 이력의 WARN→BLOCK/PAUSE도 실제 강제 보호로 전환됐습니다.
- 두 실제 inbound의 DELETE 차단/GET 허용, empty/exact scope, raw target/optional body,
  queue 포화·미응답 quarantine, 첫6MiB 응답·후속 heavy 차단, 회로/held half-open 대표 검사를 반복했습니다.
- GUI JSON30/HAR30과 response-only secret의 이전 URL 재마스킹을 검사했습니다.
  포화 incident는 historyComplete/complete=false, truncated=true, omitted152로 검증했습니다.
  알려진 합성 비밀의 시험 변형 검사이지 모든 인코딩의 비밀 유출 부재 증명이 아닙니다.

## 파일과 출처

`cairn-proxy-guard-0.1.0-SNAPSHOT.jar` — 이름이 같아도 과거 JAR과 내용은 다릅니다.

```text
6133f1edc2f9ff0bfc2a97c018285f54b88c604f1c82b0abaad5da44ec90aff9
```

첨부: JAR, `BUILDINFO.json`, `RELEASE_NOTES.md`, `SOURCE-SHA256SUMS`, `SHA256SUMS`, `LICENSE`, `NOTICE`.
모든 첨부를 같은 폴더에 받은 뒤 `shasum -a 256 -c SHA256SUMS`로 검증할 수 있습니다.
`SOURCE-SHA256SUMS`는 태그 소스 archive 루트의 Git blob bytes 기준입니다.
`*.bat`를 CRLF로 변환하는 일반 checkout과는 줄바꿈 해시가 다를 수 있습니다.
Java21, Montoya2026.7 compile-only, Jackson2.22.4, RE2/J1.8 및 lock/strict verification을 유지합니다.
의존성 고지는 JAR의 `META-INF/legal/`에 보존합니다. 기존 shaded JAR의 루트
`META-INF/LICENSE`/`NOTICE`는 upstream 파일이므로 프로젝트 자체 MIT `LICENSE`와
독립 프로젝트 `NOTICE`를 별도 첨부합니다. JAR과 함께 보관·재배포에 포함하세요.
이를 위해 이미 native 시험한 JAR을 다시 포장하거나 바꾸지는 않았습니다.

## 남은 제한과 시험·롤백 주의

- **WARN은 무제한 통과가 아닙니다.** 별도 host/실제 in-flight/overlay 상한은 유지합니다.
  누락 뒤 BLOCK/PAUSE는 각 누락 당시 창의 가장 늦은 만료까지 보수적으로 거절합니다.
  저장/OFF/감지 끄기·evidence/overlay 비우기는 debt를 해제하지 않으며 취소된 미전송 admission도
  보수적으로 집계될 수 있습니다. 한 시간 실제 만료·native4096-flight 상한은 시험하지 않았습니다.
- 전체 A–G 수용, 기존 지정 모델의 최종 전체 v2 감사3개, 나머지 queue/optional-capture 지적의
  전체 판정은 미완료입니다. H는 계속 별도 미래 기능이며 모든 Proxy listener를 보호합니다.
- 이번 JAR의 HTTPS/HTTP2, 모든 callback/종료/ABA/프로젝트 race, Professional/disk/migration,
  전체 OS, 실제 upstream·CAIRN/model/report E2E는 입증하지 않습니다. 이전 hash의 결과를 이전하지 않습니다.
- 최초 Docker/macOS bind-mount atomic export는 출력 없이 안전 실패했습니다. Native-local
  파일시스템 export는 성공했지만 파일시스템 간 호환성은 미확정이며 안전 장치를 완화하지 않았습니다.
- 보조 macOS Python3.9.6 template CLI는18 unit 통과 후 기존 fixture setup의 NoneType 경로
  오류가 발생했습니다. LinuxPython3.11/CI에서는 fixture 검사가 통과했고 host 문제는 수정하지 않았습니다.
- 자동 설치하지 않습니다. JAR hash를 확인하고 Java21/호환 Burp의 별도 임시 프로젝트에서만
  소유 fixture로 검토하세요. 새 정책은 빈 allowlist이며 실제 허가 대상을 직접 등록해야 합니다.
- 되돌리기 전 트래픽을 멈추고 실제 요청 완료를 확인하세요. Unload 후 보호는 없습니다.
  정책을 먼저 백업하고 schema2를 못 읽는 구버전으로 JAR만 교체해 복구된다고 가정하지 마세요.
  기존 프리릴리즈는 보존하며 정책·사용자 데이터를 자동 삭제하거나 migration하지 않습니다.

상세 근거: [검증 현황](VERIFICATION.md), [전체 Proxy 기록](ALL_LISTENERS_ACCEPTANCE.md),
[이전 공개 체크포인트](PRERELEASE_2026-11-04_V2_CHECKPOINT.md).
