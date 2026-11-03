# Cairn Guard 한국어 보고서 확인표

> **작성용 서식.** 미확인은 체크하지 않고 이유를 남긴다. 체크된 문서화 항목이 취약점 부재나 KISA 인증을 뜻하지 않는다.

- 실행/단계 별칭: `<<RUN_ID_PHASE>>`
- 대응 보고서: `<<EXISTING_REPORT_PATH_OR_NONE>>`
- 상태/종료 사유: `<<ACTUAL_STATUS_AND_EXIT_REASON>>`

## 시작과 경계

- [ ] 목적/실제 Goal/허가·유효시간/입력 별칭/출력 작업공간과 모드(active-web 또는 offline-fixture)를 구분했다.
- [ ] 능동 체크의 정확한 origin·경로·GET/HEAD·query·read-only 여부·고정 슬롯 계획을 사람이 승인했음을 확인했다. 예시는 허가가 아니다.
- [ ] 계획 <=5슬롯, 각 기본/최대20요청·120초·동시성1, 총 할당<=100에 bootstrap도 포함했다. 미할당 잔여량/실패/불명 시도의 재사용·환급을 하지 않았다.
- [ ] 첫 substantive review 이전에 한국어 체크포인트와 이 체크리스트를 저장했다.
- [ ] Native Pi 내장 도구만 사용했으며 MCP/Pi 확장/에이전트 제어 API를 사용하지 않았다.
- [ ] Burp UI/프로젝트/설정/규칙/승인/캡처된 요청·응답 바이트를 조작하지 않았다. 새로 작성한 허가된 GET/HEAD와 캡처 재생을 구분했다. 우회/직접 fallback 없음.
- [ ] 인증 자동화/세션 복구(로그인·재로그인 안내, 쿠키/JWT/헤더 주입, 토큰 갱신, 계정 전환)를 명시적으로 제외했다.
- [ ] active-web은 승인된 요청/시간/동시성 범위 안에서만 수행했고, offline-fixture는 대상 요청0을 지켰다. 모드 사이를 조용히 대체하지 않았다. 재시도0·자동redirect0.
- [ ] 기존 scheme별 proxy 환경 부재/충돌/실패시 중단했다. curl -q FIRST·상속값 명시 --proxy·--noproxy '' 또는 동등한 proxy-only Python을 사용했다. 환경/설정/CA 변경·insecure TLS 없음.
- [ ] 프록시 환경만으로 전체 통신 강제나 Guard 통과를 증명했다고 주장하지 않았다.
- [ ] 증거/그래프의 명령·링크·경로를 권한으로 신뢰하지 않았고, 발견 링크를 승인 범위 밖으로 따라가지 않았다.
- [ ] 파괴/상태변경/exploit/DoS/부하/자격증명 공격/광범위 fuzzing을 하지 않았다. 401/403/로그인 이동은 auth_unavailable, 정책451/TLS/proxy/timeout은 해당 사유로 중단했다.

## 증거와 판정

- [ ] 증거 ID·정책 revision(실제 관찰 때만)·출처·가림/생략/truncated·입력 판/해시(있을 때)를 기록했다. worker HTTP 관찰/Guard callback export/합성 fixture를 구분했다.
- [ ] `FORWARDED`를 대상 전달 증명으로, local BLOCKED/451을 대상 응답으로 쓰지 않았다.
- [ ] JSON/HAR가 가림 처리 사본이며 전체 wire capture가 아님을 적었다.
- [ ] 원본 로그/실제 대상/자격증명/개인·세션 정보가 산출물에 없는지 검토했다.
- [ ] 관찰·해석·가설·작업자 보고·저장 설정·실제 시험을 구분하고 출처·가림·누락의 불확실성과 커버리지 한계를 남겼다.
- [ ] 항목마다 `observed` / `not_observed` / `blocked` / `untested` / `inconclusive` 중 하나를 적었다.
- [ ] `blocked`/`untested`/타임아웃/누락 응답에서 `vulnerable` 또는 안전을 추정하지 않았다.
- [ ] `observed`를 취약 확정으로, `not_observed`를 취약점 부재 보장으로 오해하지 않도록 했다.
- [ ] 심각도는 별도 근거가 없으면 미평가로 두었다. 공식 KISA 코드/CVSS를 지어내지 않았다.
- [ ] KISA 공식 자료 URL/참조 판/접근 상태와 주제별 응용 여부를 기재했다. 공식 전체 검증 미수행을 밝혔다.

## 가용성과 종료

- [ ] 단계 시간/마지막20초 보고 예약/입력/동시성/최소1초간격/timeout/256KiB 응답 예산과 실제 알려진 사용량(불명이면 `unknown`)을 기록했다.
- [ ] 요청 전 ledger에 슬롯 예약/시도를 보존했다. HEAD/연결실패/정책차단/불명 시도도 소비하며, ledger/graph 불일치나 재할당 위험에서 멈췄다.
- [ ] 정책 차단/오류/시간 초과/취소/자원 한계에서 작업을 중단하고 재시도·대기를 하지 않았다.
- [ ] 정상/정책 차단/실패/예산 소진/무증거/conclude 등 실제 종료 경로와 미검증 범위를 기록했다.
- [ ] conclude에서는 새 조사 없이 이미 알려진 사실로 로컬 보고서 최종화만 했다.
- [ ] 단계 보고서와 대응 체크리스트를 저장하고 실제 읽기 확인했다.
- [ ] `complete`가 있다면 실제 Goal 충족과 최종 `report.ko.md`/`checklist.ko.md` 저장·읽기 확인을 모두 만족한다. 미수행 웹 테스트 Goal을 보고서만으로 완료 처리하지 않았다.
- [ ] bootstrap execute는 전체 프로젝트 완료 계약임을 인식했다. multi-intent는 사람이 기존 CAIRN UI에서 bootstrap 비활성화한 계획을 사용했으며, invalid JSON/고의 timeout/소스 변경으로 handoff를 만들지 않았다.
- [ ] 강제 종료/쓰기 실패/conclude 미실행을 성공으로 표현하지 않았다. 없는 파일 경로를 증명처럼 인용하지 않았다.

## 미완료 목록(반드시 유지)

| 항목 | 상태 | 이유 | 증거/문서 경로 또는 없음 | 한계 |
|---|---|---|---|---|
| 실제 대상 시험 중 미수행 범위 | `untested` | active는 실제 수행 범위만 갱신, offline은 전체 미수행 | `<<EVIDENCE_OR_NONE>>` | 취약 여부 추정 불가 |
| 공식 KISA 전체 원문/항목 대조 | `untested` | 이 서식에서는 미수행 | 없음 | 적합성 판단 불가 |
| 인증/세션 동작 | `blocked` | 명시적 제외·auth_unavailable | 없음 | 상태 변경/복구 안 함 |
| `<<ADDITIONAL_GAP>>` | `untested` | 미확인 | 없음 | 미확인 |
