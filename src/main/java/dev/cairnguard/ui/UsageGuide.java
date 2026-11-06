package dev.cairnguard.ui;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/** Copyable synthetic examples only. No policy access, persistence, traffic or external links. */
final class UsageGuide {
    private UsageGuide() {}

    static JComponent create() {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Swing EDT required");
        JTabbedPane tabs = new JTabbedPane();
        tabs.setName("help.examples.tabs");
        tabs.putClientProperty("html.disable", Boolean.TRUE);
        page(tabs, "대상 등록", "help.examples.scope", """
                주소를 등록하는 가장 짧은 순서
                URL 붙여넣기 → Enter 또는 ‘폼에 반영’ → 실제 범위 확인 → 저장
                Enter는 폼만 채웁니다. 이 안내를 열거나 예시를 복사해도 정책은 바뀌지 않습니다.

                예시 1 · API 주소 하나만 검사
                URL: https://api.example.test/api/items
                호스트: api.example.test / HTTPS / 포트 443
                경로 방식: 정확히 이 경로만
                범위 일치: /api/items
                범위 제외: /api/items/1, /api/items-old, 다른 호스트나 포트

                예시 2 · API 하위 경로도 검사
                경로: /api / 경로 방식: 이 경로와 하위 경로
                범위 일치: /api, /api/items, /api/items/1
                범위 제외: /apix, /admin
                ‘모든 경로’는 /admin까지 넓어지므로 필요한 경우에만 선택하세요.
                모든 경로는 /c/;/main.do, /c/%2e/main.do와 중첩 인코딩도 원래 target 그대로 통과시킬 수 있습니다.
                내부 해석 뷰는 제한 경로·차단 규칙 검사에만 사용하며 전송할 경로를 정규화하지 않습니다.
                PATH_INTERPRETATION_INCOMPLETE는 해석 불완전 경고이며 제한된 범위나 경로 EXEMPT 검증 성공이 아닙니다.
                범위는 실제 transport 목적지로 판정합니다. fuzz한 Host/:authority 헤더로 범위가 바뀌지 않습니다.

                예시 3 · 소유한 로컬 연습 서버
                http://127.0.0.1:18080/safe
                실제로 소유한 서버가 있을 때만 등록하세요. 이 확장이 서버를 만들지는 않습니다.

                example.test는 설명용 주소입니다. 실제 소유·허가한 주소로 바꾸세요.
                사용자 정보·?쿼리·#조각이 있는 URL은 직접 제거해야 합니다. 쿼리 조건은 규칙으로 만듭니다.
                ‘범위 일치’는 전송 보장이 아닙니다. 차단 대상·규칙·필수 검사도 통과해야 합니다.
                """);
        page(tabs, "규칙 만들기", "help.examples.rules", """
                자주 하는 설정은 ‘빠른 시작’에서 고르세요
                예제 선택 → 일치/불일치 예 확인 → ‘예제로 폼 채우기’ → 확인 후 저장
                선택만으로 기존 조건을 덮어쓰지 않습니다. 폼 채우기도 아직 정책 저장은 아닙니다.

                예시 1 · 특정 POST만 사람에게 확인
                빠른 시작: POST /api/items 승인 요청
                동작: 승인 요청 / 조건: 메서드 POST 그리고 경로 /api/items
                일치: POST /api/items → 승인 대기
                불일치: GET /api/items, POST /api/items/1

                예시 2 · 특정 쿼리 작업 차단
                빠른 시작: 쿼리 operation=purge 차단
                동작: 차단 / 비교 항목: 쿼리 / 이름: operation / 정확히 일치: purge
                일치: /api/items?operation=purge
                불일치: /api/items?operation=view, /api/items?other=purge

                예시 3 · JSON 값 확인
                빠른 시작: JSON action=review 승인 요청
                비교 항목: JSON / 선택 경로: /action / 정확히 일치: review
                일치 본문: {"action":"review"}
                불일치 본문: {"other":"review"}

                위 결과는 해당 규칙의 일치 예시입니다. 허용 범위와 다른 규칙은 별도로 적용됩니다.
                새 정책은 DELETE 메서드만 기본 차단합니다. GET deleteInfoBoardComnt.do / undelete 문자열만으로 차단하지 않습니다.
                v1 문자열 차단은 자동 제거하지 않으며 변환 비교에서 정확한 원본 규칙 제거를 별도 선택하세요.
                EXEMPT > BLOCK > ASK > ALLOW입니다. EXEMPT 예제는 정확한 GET /health에만 일반 BLOCK·ASK를 무시합니다.
                EXEMPT는 주황색으로 위에 고정하며 저장 전 별도 확인합니다. 범위·운영자 일시중지·명시 속도·태그 예산·수명 검사는 유지됩니다.
                지원하지 않는 문자셋·본문은 형식 자체로 거절하지 않습니다. 헤더/본문 규칙은 검사 가능할 때 적용하며 경고를 확인하세요.
                ‘조건 추가’는 단일 조건에도 바로 사용할 수 있습니다. 첫 추가는 기존 조건을 AND로 묶고, 다음 추가는 같은 묶음에 넣습니다.
                새 조건이 선택되면 오른쪽의 비교 항목과 값을 수정하세요. AND/OR 묶음도 만들 수 있으며 저장은 별도입니다.
                이름·조건·대소문자 옵션을 실제 업무에 맞게 확인하세요.
                """);
        page(tabs, "속도·결과 읽기", "help.examples.limits", """
                선택적인 수동 속도 설정
                설정 → 요청 제어 설정 변경: 전체 RPS / 기본 호스트 RPS, 0=끔, 기본값 0/0
                양수는 응답 완료와 독립적인 전송 허가 간격입니다. 호스트 예외의 양수도 별도로 적용됩니다.
                ‘모든 속도 끄기’는 전체·기본 호스트·모든 호스트 예외를 0으로 바꾸는 초안 조작입니다.
                초안은 아직 적용되지 않습니다. 명시적으로 저장하며 프로젝트·버전 일치 검사 후 반영합니다.
                ‘천천히 · 1/1’ 또는 ‘수동 · 5/5’도 두 속도만 초안에 채웁니다.
                예시 숫자가 모든 대상에 적합하거나 안전하다는 보장은 아닙니다.

                예시 · 전체 5 / 호스트 2
                여러 클라이언트가 전체 초당 전송 허가 5회를 공유하며 한 호스트에는 기본 초당 2회까지 허가합니다.
                시간은 초 단위입니다: 0.080 = 80ms / 4 = 4초 / 30 = 30초.
                이는 callback 전송 허가 기준이지 서버 도착 간격의 보장이 아닙니다.
                native 동시성 상한은 없습니다. 응답 지연·누락·ID 재사용은 다음 허용 요청의 차단 근거가 아닙니다.
                전송 해제는 callback 복구나 대상 도착을 보장하지 않습니다.

                결과 읽기
                • 차단됨 / HTTP 451: 확장이 로컬에서 막은 결과입니다. 서버 오류나 취약점의 증거가 아닙니다.
                • 승인 대기: 승인 탭에서 원문 요청(보관된 화면 사본)을 검토한 뒤 한 번 승인하거나 거절하세요.
                • 전송 대기: 명시한 속도 간격을 기다립니다. 자동 재전송을 추가하지 마세요.
                • 전송 해제: Burp에 전송을 허가했다는 뜻이며 대상 도착·처리 성공의 증명은 아닙니다.
                • 보관: 북마크입니다. 영구 저장/퇴출 방지가 아니므로 필요한 증거는 직접 내보내세요 (원문 평문, 별도 확인).

                보호 켜짐 / 전체 통과 / 새 요청 차단은 다릅니다
                상단 ‘모두 통과 (보호 끔)…’: 경고 확인 후 모든 새 Proxy 요청을 검사·승인·속도 제한 없이 전송
                기존 승인·전송 대기는 자동 승인하지 않고 취소합니다. 새 전체 통과 요청·응답은 확장에 기록하지 않습니다.
                OFF는 현재 프로젝트의 임시 상태이며 프로젝트 전환·확장 재시작 후 유지하지 않습니다.
                다시 보호를 켜기 전에 요청을 멈추고 전체 통과 중 시작한 연결 완료를 확인하세요.
                ‘보호 다시 켜기’: 새 요청부터 다시 검사, 이전 운영자 일시중지도 보존
                ‘새 요청 모두 차단’: 모든 Proxy 리스너의 새 요청 차단 (상태 확인 GET은 명시 설정 시 제외)
                OFF/ON·정책 저장은 태그 사용량을 초기화하지 않습니다. native permit이나 미응답 격리는 없습니다.
                위 규칙·속도 예시는 보호 켜짐 상태 기준입니다. 워커에 이 조작 권한을 주지 않습니다.

                빠른 조작
                대상·규칙 표: 두 번 클릭 또는 Enter로 편집 창 열기
                요청 기록·승인 표: 두 번 클릭 또는 Enter로 읽기 전용 상세 열기
                이 조작은 저장·승인·요청 전송을 하지 않습니다. 결정 버튼은 별도로 눌러야 합니다.
                """);
        page(tabs, "수동 제어·태그·내보내기", "help.examples.safety", """
                정책과 운영자 결정만으로 제어합니다
                자동 차단 기능은 제거되었습니다. 5xx·응답 크기·경로 확산·회로 상태로 다음 요청을 막거나 자동 일시중지하지 않습니다.
                응답 지연·누락으로 native 자리를 격리하거나 half-open 재시도를 요구하지 않습니다.
                이전 감지·동시성·응답 대기 제한 설정은 비활성 호환 데이터로만 보존되며 저장해도 다시 활성화되지 않습니다.
                대상 범위·명시 BLOCK/ASK·사람 승인·운영자 일시중지·명시 속도·태그 예산·정책/프로젝트/종료/최종 전송 검사는 유지됩니다.
                창 열기·초안 수정·예시 선택은 저장하지 않습니다. 명시 저장과 현재 프로젝트·버전 검사가 필요합니다.

                태그·상태 확인·리스너
                X-Cairn-Intent / X-Cairn-Run은 클라이언트 주장으로 인증이 아닙니다. 예산은 같은 (Run, Intent)의 최종 전송 허가를 셉니다.
                요청 기록에서 Intent/Run·결과·보호 상태로 필터/정렬할 수 있습니다. 사용량 초기화는 개요에서 별도 확인합니다.
                GET 상태 확인은 정확한 실제 scheme/host/port/path의 query·body 없는 GET만 운영자 일시중지를 통과합니다. 범위·규칙·승인·속도·예산·수명 검사는 유지됩니다. GET도 부작용이 있어 별도 확인합니다.
                이번 범위는 모든 Proxy 리스너 보호이며 포트별 보호는 추후 지원합니다. 새 포트 제한은 저장할 수 없습니다.
                기존 포트 제한은 자동 삭제하지 않습니다. 남아 있으면 모두 LISTENER_UNVERIFIED로 거절되므로 설정에서 직접 비우고 전체 보호 전환을 확인하세요.

                화면 원문과 내보내기 (평문 동의) 안내
                요청 기록은 민감한 원문 URL·인증 헤더·본문을 메모리에 보관한 사본 전체로 보여줍니다.
                바이너리/지원하지 않는 문자셋은 captured bytes의 HEX일 수 있습니다. 읽기 실패·응답 없음 표시와 이 사본은 도착 증명이 아닙니다.
                프로젝트 전환·기록 비우기·언로드 시 원문은 사라집니다. OFF/미선택 리스너는 새 내용을 수집하지 않습니다.
                JSON/HAR/사건 내보내기는 누를 때마다 평문 비밀(Authorization·Cookie·토큰)이 파일에 들어간다는 확인을 거친 뒤 보관된 원문 구조(헤더·본문 바이트)를 저장합니다. 원문이 없으면 ‘원문 없음’입니다. 이 확장은 어떤 화면·출력도 마스킹하지 않으며 수집·보관·내보내기에 건수·크기·기간 상한이 없습니다. 메모리는 지우기·프로젝트 전환·언로드 전까지 계속 늘어나 메모리 부족(OOM)이 생길 수 있으므로 직접 관리하세요. 상태·로그의 고정 범주 코드에는 요청 내용을 넣지 않습니다.
                사건 내보내기: UTC [시작, 끝), 기간 상한 없음(지우기·프로젝트 전환 이후만 포함). 근사 표시와 완전성 표시를 함께 검토하세요.
                소유자 전용 파일 생성, 기존 파일 명시 동의, symlink/파일 교체 거절을 사용합니다.
                """);
        return tabs;
    }

    private static void page(JTabbedPane tabs, String title, String name, String text) {
        JTextArea area = new JTextArea(text, 12, 48);
        area.setName(name);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setCaret(new NonScrollingCaret());
        area.setCaretPosition(0);
        area.putClientProperty("html.disable", Boolean.TRUE);
        if (UIManager.getFont("Label.font") != null) area.setFont(UIManager.getFont("Label.font"));
        area.getAccessibleContext().setAccessibleName(title + " · 복사 가능한 읽기 전용 예시");
        JScrollPane scroll = new JScrollPane(area);
        scroll.getVerticalScrollBar().setUnitIncrement(Math.max(16, area.getFontMetrics(area.getFont()).getHeight()));
        tabs.addTab(title, scroll);
    }
}
