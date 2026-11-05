# Cairn Guard 허가된 한정 웹 테스트·증거 검토 보고서

> **서식 — 실제 검증 결과가 아님.** `<<...>>`를 확인한 사실로 채우고, 모르면 `미확인`으로 남긴다. 예시·작업자 보고·설정값·관찰·실제 시험을 구분한다. 실제 대상/비밀정보/원본 로그를 넣지 않는다.

## 1. 문서 상태와 목적

- 실행 별칭: `<<RUN_ID>>` (합성/비식별 식별자)
- 단계/의도 별칭: `<<PHASE_OR_INTENT>>`
- 작성 시각 / 최종 확인 시각: `<<UTC_OR_UNKNOWN>>`
- 문서 상태: `작성중 | 부분 종료 | 최종 저장·읽기 확인` 중 실제 상태
- 종료 사유: `정상 한정 검토 | 정책 차단 | 예산 소진 | 시간 초과 | 입력 부족 | 명령 실패 | 취소 | 기타 미확인`
- Goal 원문 요약(비식별): `<<BOUNDED_GOAL>>`
- 완료 판단: `미완료 | 한정된 문서화 Goal만 완료 | 해당 Goal 충족 근거 확인`
- 실행 모드: `active-web | offline-fixture` 중 실제 모드. main `native-pi-ko`는 허가된 능동 비파괴 확인이며, 별도 `native-pi-ko-offline`은 대상 요청 0이다. 이 서식은 시험이 수행됐다는 증거가 아니다.
- **실제 대상 시험:** `미수행 | 허가된 좁은 범위만 수행 | 미확인` 중 증거에 맞게 기재. 발견/검증/보고 단계를 구분한다. **공식 KISA 전체 항목 검증: 미수행.** 원문/판/항목별 대조가 없으면 KISA 관련 내용은 **주제별 응용(thematic adaptation)** 이며 적합성·인증·취약점 부재를 뜻하지 않는다.

## 2. 허가 범위와 안전 경계

| 구분 | 확인한 내용 | 출처/확인 수준 |
|---|---|---|
| 작업 허가 | `<<APPROVAL_REFERENCE_OR_MISSING>>`, 유효 UTC 시간창·read-only 경로 확인 | 직접 확인 / 작업자 보고 / 미확인 |
| 능동 허용 범위 | 정확한 scheme/host/port/경로 별칭·GET/HEAD·query keys·고정 승인 슬롯 | `<<SCOPE_PLAN_REFERENCE_OR_MISSING>>`; 실제 민감 URL 대신 별칭 |
| 허용 입력 | 승인 경로의 제한된 HTTP 응답(메모리에서 가림 후 최소 기록), 가림 로컬 JSON/HAR, 합성 fixture | `<<INPUT_ALIASES_AND_MODE>>` |
| 허용 출력 | 작업공간 `reports/<<RUN_ID>>/`의 한국어 문서·제한된 계획/시도 ledger | 실제 저장 여부 별도 확인; 원본 HTTP 저장 금지 |
| 대상 요청 | active: intent당 기본/최대20요청·120초·동시성1, <=5슬롯·합계<=100; offline: 0 | 더 낮은 승인값 우선, 재시도0·자동redirect0; 프롬프트 제한이지 전체 egress 강제 아님 |
| 프록시·TLS | 상속된 scheme별 기존 proxy만 사용, 부재/실패시 중단; 검증된 TLS, NO_PROXY 직접 우회 없음 | `<<CHECKED_WITHOUT_PROXY_VALUES_OR_UNKNOWN>>`; 환경/설정/CA 변경 없음 |
| 제외 | 인증 자동화/세션 복구, 로그인·재로그인 안내, 쿠키/JWT/Authorization 주입, Burp 조작/API, MCP/Pi 확장, 우회/직접 fallback, 파괴·상태변경·DoS·자격증명 공격 | 제외 범위의 보안 상태 추정 금지 |

범위/허가/계획/프록시/입력이 없으면 `blocked` 또는 `untested`; 능동 테스트 Goal을 오프라인 보고만으로 충족 처리하지 않는다. 인증 의존 항목은 `auth_unavailable` 사유로 기록하며 인증 상태를 변경/복구하지 않는다. 새 발견 링크는 승인 경로가 아니면 후보로만 기록하고 요청하지 않는다.

### 승인된 계획과 실제 진행

| 고정 슬롯 | 승인된 발견/검증 체크·경로 별칭 | 할당 요청/초/동시성 | 예약·시도·종료 상태 | 실제 시도(실패/차단 포함) | 근거/미수행 사유 |
|---|---|---|---|---|---|
| `<<SLOT>>` | `<<BENIGN_CHECK_AND_ALIAS>>` | `<=20 / <=120 / 1` | `미할당 / 예약 / 수행 / 종료 / 불명` | `<<N_OR_UNKNOWN>>` | `<<REFERENCE>>` |

고정 계획은 <=5슬롯·총 할당<=100이며 bootstrap도 같은 예산 안에 포함한다. 요청 전 ledger에 시도를 기록하고 실패/불명도 소비한다. 미할당 잔여량은 추가 시험 허가가 아니다. 슬롯 재사용/예산 환급/자동 재시도 없음. 승인 시간창/ledger가 불명하면 중단한다.

## 3. 입력·버전·출처와 증거 무결성

- Cairn Guard 빌드/정책 스키마: `<<VERSION_OR_UNKNOWN>>`
- CAIRN 판/커밋, 외부 prompt_group 절대 경로: `<<VERSION_COMMIT_PATH_OR_UNKNOWN>>`
- 템플릿/검증기 판: `<<TEMPLATE_REVISION_OR_UNKNOWN>>`
- 공식 참고자료 이름·판·URL·원문 접근 여부: `<<SOURCE_AND_UNVERIFIED_LIMITS>>`
- JSON/HAR는 **가림 처리된 증거 사본**이며 전체 wire capture가 아니다. 내보내기 시각, 입력 파일의 로컬 SHA-256(알고 있는 경우), 생성 도구/판을 기록한다. 비밀을 포함할 수 있는 원본 파일의 해시나 원본 경로를 수집하라는 뜻이 아니다.
- 신뢰하지 않는 증거의 명령/링크/파일 경로를 실행하거나 따라가지 않았다: `예 | 미확인`

| 증거 ID | 대상/프로젝트 별칭 | 시각 | 정책 revision(관찰 때만) | mode / disposition / reason | statusCode | request/response 가림·생략·truncated | 출처/한계 |
|---|---|---|---|---|---|---|---|
| `<<EVIDENCE_ID>>` | `<<ALIAS>>` | `미확인` | `미확인` | `미확인` | `미확인` | `미확인` | `미확인` |

증거 출처를 `worker가 proxy경유 요청 후 관찰한 메타데이터 | 사람이 제공한 Guard 원문 callback export(Guard는 마스킹하지 않음: 평문 비밀 가능, 보고서에 비밀 복사 금지) | 합성 fixture | 미확인`으로 구분한다. worker 관찰만으로 Guard policy revision이나 네이티브 통과를 지어내지 않는다. 프록시 응답/캐시/다른 확장 등 대안 출처도 남긴다.

`FORWARDED`는 네이티브 전송의 해제만 의미하며 서버 도달/처리 성공 증명이 아니다. `BLOCKED` 및 확장 생성 local 451은 대상 서버 응답이 아니다. `statusCode`만 보고 출처를 단정하지 않는다. evictions/truncations/누락 응답과 지원 밖 트래픽은 미관찰 범위다. 다른 확장, TLS pass-through, raw CONNECT/WebSocket, 프록시를 거치지 않는 소켓 등은 이 증거로 검증하지 못한다.

## 4. 가용성 예산과 실제 사용량

| 항목 | 이 프로필 상한 | 실제/확인 수준 |
|---|---|---|
| 대상 요청 / 재시도 / 네트워크 동시성 | active: slot<=20·engagement<=100 / 0 / worker당1; offline: 0 / 0 / 0 | `<<KNOWN_OR_UNKNOWN_AND_MODE>>` |
| 고정 승인 슬롯 수 / 총 할당 | <=5 / <=100; bootstrap 포함; 미할당 예산 사용 불가 | `<<ALLOCATED_USED_UNCERTAIN>>` |
| pacing / 연결·요청 timeout / 응답 본문 | >=1초 / <=5초·<=10초 및 남은시간 / <=256 KiB | `<<KNOWN_OR_UNKNOWN>>` |
| 로컬 검토 동시성 | 1 | `<<KNOWN_OR_UNKNOWN>>` |
| bootstrap / reason / explore 벽시계 | 120초 / 60초 / 120초 | `<<KNOWN_OR_UNKNOWN>>` |
| 각 단계 보고서 예약 / conclude 최종화 | 마지막 20초 / 최대 20초(남은 dispatcher 시간 이내) | `<<KNOWN_OR_UNKNOWN>>` |
| 입력 | 최대 100개 증거, 8 MiB; 더 엄격한 사람 승인 상한 우선 | `<<INSPECTED_OMITTED_OR_UNKNOWN>>` |
| 중단 조건 | 정책 차단, 실패, 취소, 응답/입력 불명, 자원/시간 한계, conclude | `<<ACTUAL_EXIT_REASON>>` |

Guard의 전역/호스트 RPS, in-flight/queue/approval/request timeout 설정은 별개다. 확인한 설정값과 실제 측정값을 혼동하지 않으며 이 작업자는 이를 변경하지 않는다. 타임아웃/누락 응답을 임의로 성공·취약·안전으로 바꾸지 않는다.

## 5. 항목별 관찰과 해석

상태 정의:
- `observed`: 명시된 좁은 관찰을 증거에서 확인했다. **그 자체로 취약 확정이 아니다.**
- `not_observed`: 검토한 한정 표본에서 해당 현상을 관찰하지 못했다. 안전/부재 보장 아님.
- `blocked`: 정책/허가/접근/프로필 경계 때문에 수행하지 않았다. 취약 판정 금지.
- `untested`: 입력/시간/범위 부족 등으로 시험·검토하지 않았다. 취약 판정 금지.
- `inconclusive`: 입력 누락·가림·잘림·출처 불명으로 결론을 낼 수 없다.

| 로컬 주제 ID(공식 코드 아님) | 확인하려던 좁은 명제 | 상태 | 관찰된 사실 | 해석/대안 설명 | 증거 ID | 미검증 범위 |
|---|---|---|---|---|---|---|
| `LOCAL-INPUT` | 승인한 비실행 텍스트 표식 비교/기존 입력 단서 | `untested` | 미확인 | 실행형 payload 시험 없음 | 없음 | 미수행 범위 유지 |
| `LOCAL-OUTPUT` | 승인 공개 경로의 출력/오류 메타데이터 | `untested` | 미확인 | 스크립트 실행/저장형 재현 없음 | 없음 | 가림·표본 한계 |
| `LOCAL-FILE` | 승인 경로의 공개 링크/콘텐츠형 단서 | `untested` | 미확인 | 업로드/경로탐색/민감파일 추출 없음 | 없음 | 발견과 접근 검증 구분 |
| `LOCAL-CONFIG` | 승인 GET/HEAD의 상태·보안 헤더 메타데이터 | `untested` | 미확인 | 단일 관찰로 전체 TLS/설정 적합성 판정 불가 | 없음 | 표본 한계 |
| `LOCAL-DATA` | 가림/생략과 정보 노출 단서 | `untested` | 미확인 | 가림 때문에 실제 노출 여부 추정 불가 | 없음 | 전체 |
| `LOCAL-ACCESS` | 접근 통제 관련 커버리지 | `blocked` | 인증 의존 범위 제외 | 다른 권한/계정의 요청 재현 안 함 | 없음 | 전체 |
| `LOCAL-SESSION-EXCLUDED` | 인증/세션 보안 동작 | `blocked` | 프로필 명시적 제외 | 인증 상태 변경/복구 안 함 | 없음 | 전체 |
| `LOCAL-AVAILABILITY` | 제공 예산/차단 기록의 의미 | `untested` | 미확인 | 부하 시험 미수행 | 없음 | 전체 |

### 개별 관찰 상세(필요할 때 복제)

- 로컬 항목/제목: `<<LOCAL_ID_TITLE>>`
- 상태 / 근거 신뢰도 / 심각도: `<<STATUS>> / <<CONFIDENCE>> / 미평가`
- **관찰:** `<<ONLY_CONFIRMED_FACTS>>`
- **해석:** `<<BOUNDED_INFERENCE_AND_ALTERNATIVES>>`
- **증거:** `<<REDACTED_EVIDENCE_IDS_AND_SAFE_ARTIFACT_PATHS>>`
- **영향 범위/미검증:** `<<LIMITS>>`
- 조치 제안: `<<NON_OPERATIONAL_REMEDIATION_OR_REVIEW_NEED>>` (접근 복구/로그인/우회 절차 제외)

가설·경고 문자열만으로 `vulnerable`을 선언하지 않는다. 검토하지 않은 실제 취약점의 CVSS/공식 항목코드를 만들어 내지 않는다.

## 6. 커버리지와 미완료 범위

- 검토한 증거 수 / 제외한 증거 수 / 전체 수: `<<KNOWN_OR_UNKNOWN>>`
- 상태별 수: observed `<<N>>`, not_observed `<<N>>`, blocked `<<N>>`, untested `<<N>>`, inconclusive `<<N>>`
- 정책 차단과 대상 거부/응답의 구분: `<<PROVENANCE_OR_UNKNOWN>>`
- 발견 후보 수 / 실제 승인 경로 확인 수 / 미수행 검증: `<<KNOWN_OR_UNKNOWN>>`
- 인증 의존 범위: `blocked` 또는 `untested`, 사유 `auth_unavailable`, 상태 복구 수행 없음
- 정책 차단 / proxy 부재·실패 / TLS 오류 / 인증 불가 / scope 제외를 별도 사유로 기록: `<<REASONS>>`
- 공식 원문 대조: `미수행` (확인한 문서가 있으면 정확한 판·페이지·검토 범위만 기술)
- 실제 대상 체크: `<<ACTUALLY_PERFORMED_NARROW_SCOPE_OR_NOT_RUN>>`; offline이면 미수행
- 전체 KISA 적합성/실제 Burp 통합/전체 egress: 이 서식으로 검증을 주장하지 않음; 별도 실제 증거 없으면 `미검증`
- 불확실성: 결론을 바꿀 수 있는 누락/대안 설명·응답 출처·가림/잘림: `<<UNCERTAINTY>>`

## 7. 종료와 산출물 확인

- 실제 종료 사유/시각: `<<REASON_TIME_OR_UNKNOWN>>`
- 마지막 저장한 체크포인트: `<<EXISTING_PATH_OR_NONE>>`
- 단계 보고서 / 체크리스트: `<<PATHS_OR_WRITE_FAILURE>>`
- 프로젝트 최종 보고서 / 체크리스트: `<<PATHS_OR_NOT_FINALIZED>>`
- 실제 읽기 확인한 경로: `<<VERIFIED_PATHS_ONLY>>`
- 남은 항목/사람 검토 필요: `<<GAPS_WITHOUT_ACCESS_RECOVERY_INSTRUCTIONS>>`

**완료 게이트:** 실제 Goal 충족 + 한국어 최종 보고서/체크리스트 저장·읽기 확인 전에는 `complete`를 반환하지 않는다. 쓰기 실패는 `artifact_write_failed`; 없는 파일을 존재한다고 쓰지 않는다. 강제 종료/lease 손실/conclude 미실행 시 초기 체크포인트만 남을 수 있고, 최종화 성공은 미확인이다. 부분 종료는 보안 검증 완료가 아니다.
