# v2 전체 Proxy 개발 체크포인트 — 2026-11-04 (UTC)

> **개발용 프리릴리즈 / 검증 미완료.** 사용자의 명시적 요청에 따라 현재 작업을
> GitHub에 보관하고 검토용 빌드를 제공하는 체크포인트입니다. 전체 수용·최종 독립 검토·
> 정식 배포 승인이 아닙니다. 실서비스 보호에 의존하지 말고 분리된 시험 환경에서만 검토하세요.

- 게시 대상 태그: `dev-2026-11-04-v2-all-listeners-checkpoint`
- [프리릴리즈](https://github.com/sehoon123/cairn-burp-guard/releases/tag/dev-2026-11-04-v2-all-listeners-checkpoint)
- 기능 소스의 마지막 변경: `2afd923`; 이후 문서 변경은 JAR 입력을 바꾸지 않습니다.
- 빌드의 정확한 최종 태그/커밋과 입력 파일 해시는 첨부 `BUILDINFO.json` /
  `SOURCE-SHA256SUMS`로 확인하세요. 원본 로그·테스트 프로필·스크린샷·인증서/키는 첨부하지 않습니다.

## 포함한 변경

- Schema2 모델, EXEMPT, 실제 목적지 service/path 기준 범위, best-effort 내용 검사,
  응답 크기·5xx circuit·fanout 감지, 선택적 intent 예산, 명시적 GET health 예외.
- 사람용 unmasked 메모리 기록과 masked JSON/HAR/incident의 분리, HEX 반사 마스킹 수정,
  자동 차단/대용량 후보 화면과 수동 정책 초안.
- 전체 Proxy 보호, 별도 확인을 거치는 runtime-only 보호 OFF, 기존 pause/debt/실제 permit 보존.
- 감사 지적에 따른 EXEMPT 모든 routing-view 조건, URL 규칙의 dot/matrix/encoded alias,
  untouched native target 및 불완전 경로 처리 수정.
- Watcher도 빈/non-origin-form 첫 view와 raw control/DEL/C1/lone surrogate를 수용.
  최대9 view·각16384 code unit을 hash 전에 검사하고 lossless HMAC을 사용합니다.
  엄격한 health-probe `allMatch` 조건은 유지합니다.
- 논리 timeout 뒤 실제 late heavy/일반5xx scalar 관찰, 교체 half-open 보호,
  authorization 예외 시 확실히 미전송인 permit의 누수 방지.

허용된 native request/response와 annotations를 변경하지 않는 설계입니다. 검사 사본이나
자동화된 adapter 검사를 전체 wire equality·실제 도착·native 수용으로 간주하지 않습니다.

## 이 빌드에서 직접 확인한 자동 검사

| 검사 | 결과 / 한계 |
|---|---|
| Java21 격리 clean build / headless 검사 | **1302 PASS**, failures/errors/skips0. Unit·adapter·headless UI·소유 loopback 계층이지 실제 Burp 실행이 아님 |
| 새 회귀 | 위1302개에 watcher routing interop18개와 late scalar/permit7개 포함 |
| Python helper offline unit | **31 PASS**. Helper의 출력에 native 시나리오 이름이 있어도 실제 Burp 실행 결과가 아님 |
| Local template 계약 | **18 PASS**, fixture-only loader2개 PASS. 실제 upstream은 **SKIP** |
| Production 강제 재빌드 | 같은 JAR SHA256 재현. 독립 재현성/검토 승인이 아님 |
| 새 exact JAR의 native Burp / real Swing | **미실행**. 과거 artifact 결과를 이전하지 않음 |

파일: `cairn-proxy-guard-0.1.0-SNAPSHOT.jar`

```text
c61b7d1f869ec926c30f0e0fcc9cd188396f7fd694e9fc2cfac542a6d191f491
```

의존성/런타임: Java21, Gradle9.2.0 wrapper, Montoya API2026.7 compile-only,
Jackson2.22.4, RE2/J1.8. Lock/strict dependency verification을 유지합니다.
포함 라이브러리의 고지는 JAR의 `META-INF/NOTICE`, `META-INF/legal/`에 있습니다.

## 남은 검토 지적과 사용상 제한

- **최종 독립 구현 감사3개는 미완료**입니다. 지정 모델
  `ica-se-claude/claude-advantage-assist`의 두 cold 보고서는 **이전 `7b974de`** 소스의
  결함 보고서이지 승인서가 아닙니다. 일부 지적을 소스/회귀로 수정했지만 수정 소스의
  최종 검토는 없고, privacy/export 세 번째는 실질 보고서 없이 blocked입니다.
- Queue 포화 시 세 번째 이상 host의 공정성, fanout WARN과 공용 path-key 용량의 결합,
  불완전한 header capture/선택적 inspection-slot 경쟁에 따른 intent·명시 규칙의 분류 등은
  **감사 지적의 재현·조치·수용 판정이 아직 모두 끝나지 않았습니다.** WARN 설정이어도
  metadata 용량 제한으로 예상치 못한451이 발생할 수 있습니다. 모든 결함이 해결됐다고
  주장하지 않습니다.
- 미응답의 실제 native permit은 시간 경과로 반환하지 않습니다. 완료 callback이 없으면
  host/용량이 계속 격리될 수 있습니다. 임의 재사용으로 해결하지 않습니다.
- **포트별 한정(H)은 사용자 결정으로 추후 분리**했습니다. 현재는
  `guardListenerPorts=[]`의 **전체 Proxy 보호**입니다. 새 nonempty 제한은 저장할 수 없고,
  과거 제한은 명시적으로 확인 후 비우기 전까지 fail-closed입니다. H는 gate도 PASS도 아닙니다.
- 실제 Burp 개별 검사는 이전 `956bcf…` artifact의 역사적 결과입니다. 이 새 JAR의
  native/HTTP2/내보내기/Swing 성공이나 보안 보증으로 이전하지 않습니다.
- 전체 HTTP2, Professional 디스크 프로젝트/재시작 migration, 모든 ABA/포화/종료 race,
  opaque CONNECT/TLS pass-through/WebSocket frame, CAIRN/Pi/model/report-file E2E,
  강제 egress/인증·세션 관리/플랫폼 안전 인증을 제공하거나 입증하지 않습니다.

## 내려받기·시험·되돌리기

1. JAR과 `SHA256SUMS`를 내려받고 `sha256sum cairn-proxy-guard-0.1.0-SNAPSHOT.jar`의
   값이 위 해시와 일치하는지 확인하세요. 첨부 파일을 모두 받았다면
   `sha256sum -c SHA256SUMS`로 bundle도 확인할 수 있습니다.
2. Java21 및 호환 Montoya API를 제공하는 Burp의 **별도 임시 profile/project**를 사용하세요.
   기존 live 프로젝트/프로필/활성화 자료를 복사하거나 바꾸지 마세요. EULA·라이선스는 정상
   사용자 절차만 따르며 필요한 동의/인증에서 멈춥니다. 자동 설치는 하지 않습니다.
3. 사람이 Extensions에서 Java JAR을 추가하고 소유 loopback fixture로만 검토하세요.
   새 정책은 빈 allowlist이므로 기본적으로 아무 대상도 허용하지 않습니다. 실제 목적지와
   필요한 범위를 직접 정해야 하며 이 프리릴리즈를 실서비스 안전 경계로 사용하지 마세요.
4. 중단하려면 먼저 시험 트래픽을 멈추고 사람이 확장을 unload하세요. **Unload 후 보호는
   없습니다.** Native 완료를 확인하지 않은 상태에서 permit이 반환됐다고 간주하지 마세요.
5. v1 정책은 원본을 먼저 별도로 백업한 후 v2 저장을 명시적으로 결정하세요. 이미 저장한
   schema2를 구버전 JAR만 로드해 되돌릴 수 없습니다. 되돌리기는 백업한 원본 정책을
   별도 시험 프로젝트에서 검토·복원하는 작업이며 자동 수행하지 않습니다.

상세 근거: [전체 Proxy 검증 기록](ALL_LISTENERS_ACCEPTANCE.md),
[현재 인터페이스](INTERFACES.md), [수동 native checklist](MANUAL_BURP_SMOKE.md).
과거/현재 결과와 공개 허가·검증 완료·정식 수용은 각각 별개입니다.
