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
                기본 delete 차단은 승인 요청보다 우선합니다. 삭제 요청을 승인 규칙으로 우회할 수 없습니다.
                ‘조건 추가’는 단일 조건에도 바로 사용할 수 있습니다. 첫 추가는 기존 조건을 AND로 묶고, 다음 추가는 같은 묶음에 넣습니다.
                새 조건이 선택되면 오른쪽의 비교 항목과 값을 수정하세요. AND/OR 묶음도 만들 수 있으며 저장은 별도입니다.
                이름·조건·대소문자 옵션을 실제 업무에 맞게 확인하세요.
                """);
        page(tabs, "속도·결과 읽기", "help.examples.limits", """
                숫자 3개를 쉽게 시작하기
                설정 → 요청 제어 설정 변경 → ‘천천히 · 1/1/1’ 또는 ‘기본 · 5/5/5’
                순서: 전체 RPS / 기본 호스트 RPS / 최대 동시 요청 수
                버튼은 숫자 3개만 폼에 채웁니다. 호스트 예외·대기 시간·기본 동작은 유지하며 저장은 별도입니다.
                예시 숫자가 모든 대상에 적합하거나 안전하다는 보장은 아닙니다.

                예시 · 전체 5 / 호스트 2 / 동시 요청 1
                여러 클라이언트가 전체 초당 전송 허가 5회를 공유합니다.
                한 호스트에는 기본 초당 2회까지 허가합니다. 호스트 예외가 있으면 그 값도 확인하세요.
                동시 요청 1은 응답을 기다리는 요청이 하나라는 뜻입니다. 워커 수가 아닙니다.
                시간은 초 단위입니다: 0.080 = 80ms / 4 = 4초 / 30 = 30초.
                이는 callback 전송 허가 기준이지 서버 도착 간격의 보장이 아닙니다.

                결과 읽기
                • 차단됨 / HTTP 451: 확장이 로컬에서 막은 결과입니다. 서버 오류나 취약점의 증거가 아닙니다.
                • 승인 대기: 승인 탭에서 마스킹된 요청을 검토한 뒤 한 번 승인하거나 거절하세요.
                • 전송 대기: 속도·동시성 자리를 기다립니다. 자동 재전송을 추가하지 마세요.
                • 전송 해제: Burp에 전송을 허가했다는 뜻이며 대상 도착·처리 성공의 증명은 아닙니다.
                • 보관: 북마크입니다. 영구 저장/퇴출 방지가 아니므로 필요한 마스킹 증거는 직접 내보내세요.

                보호 켜짐 / 전체 통과 / 새 요청 차단은 다릅니다
                상단 ‘모두 통과 (보호 끔)…’: 경고 확인 후 모든 새 Proxy 요청을 검사·승인·속도 제한 없이 전송
                기존 승인·전송 대기는 자동 승인하지 않고 취소합니다. 새 전체 통과 요청·응답은 확장에 기록하지 않습니다.
                OFF는 현재 프로젝트의 임시 상태이며 프로젝트 전환·확장 재시작 후 유지하지 않습니다.
                다시 보호를 켜기 전에 요청을 멈추고 전체 통과 중 시작한 연결 완료를 확인하세요.
                ‘보호 다시 켜기’: 새 요청부터 다시 검사 / ‘새 요청 모두 차단’: 검사 없이 통과가 아니라 차단
                위 규칙·속도 예시는 보호 켜짐 상태 기준입니다. 워커에 이 조작 권한을 주지 않습니다.

                빠른 조작
                대상·규칙 표: 두 번 클릭 또는 Enter로 편집 창 열기
                요청 기록·승인 표: 두 번 클릭 또는 Enter로 읽기 전용 상세 열기
                이 조작은 저장·승인·요청 전송을 하지 않습니다. 결정 버튼은 별도로 눌러야 합니다.
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
