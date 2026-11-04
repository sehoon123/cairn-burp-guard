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
                EXEMPT는 주황색으로 위에 고정하며 저장 전 별도 확인합니다. 범위·일시중지·자동 차단·속도·태그 예산은 유지됩니다.
                지원하지 않는 문자셋·본문은 형식 자체로 거절하지 않습니다. 헤더/본문 규칙은 검사 가능할 때 적용하며 경고를 확인하세요.
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
                ‘보호 다시 켜기’: 새 요청부터 다시 검사, 이전 운영자 일시중지도 보존
                ‘새 요청 모두 차단’: 보호하도록 선택한 리스너만 차단 (상태 확인 GET은 명시 설정 시 제외)
                OFF/ON·정책 저장은 자동 차단·태그 사용량·미완료 native 자리를 임의로 비우지 않습니다.
                위 규칙·속도 예시는 보호 켜짐 상태 기준입니다. 워커에 이 조작 권한을 주지 않습니다.

                빠른 조작
                대상·규칙 표: 두 번 클릭 또는 Enter로 편집 창 열기
                요청 기록·승인 표: 두 번 클릭 또는 Enter로 읽기 전용 상세 열기
                이 조작은 저장·승인·요청 전송을 하지 않습니다. 결정 버튼은 별도로 눌러야 합니다.
                """);
        page(tabs, "자동 안전·태그·내보내기", "help.examples.safety", """
                모든 새 제어는 설정 → 요청 제어 설정 변경에서 폼으로 작성합니다.
                새 프로필: 경로 응답 한도 5 MiB, 5xx 5회/60초, 10분 회로, 확산 100경로/60초 경고.
                v1 변환: 새 감지·태그 예산·상태 확인은 OFF, 모든 리스너 보호, 기존 규칙은 그대로.
                창 열기·초안 수정·예시 선택은 저장하지 않습니다. v2로 명시 저장해야 영구 반영합니다.

                자동 차단 탭
                정책과 분리된 메모리 overlay, 시작/만료 시각·이유 표시. 한 항목/전체 해제는 현재 프로젝트·버전 확인 후 적용합니다.
                회로는 열림 시간이 지나도 GET/HEAD 한 번으로 재확인합니다. 최소 30초 간격, 실패/응답 미확인은 다시 열림.
                자동 PAUSE는 운영자 일시중지와 별개입니다. 기능을 꺼도 기존 차단은 만료/수동 해제까지 유지됩니다.

                대용량 후보 탭
                max/p95(근사)/count/최근/5xx를 확인하세요. 첫 초과 응답은 이미 나간 뒤 감지하며 예방할 수 없습니다.
                일반 BLOCK 규칙 초안은 안전한 마스킹 미적용 URL에만 만들고 별도 저장합니다. hard blockScope로 바꾸지 않습니다.
                ‘N MiB 초과’는 정확한 경로의 응답 한도를 별도 확인 후 저장합니다. 0은 그 경로의 크기 감지를 끕니다.
                무시는 런타임 후보만 숨기며 정책·사건·열린 자동 차단을 삭제하지 않습니다.

                태그·상태 확인·리스너
                X-Cairn-Intent / X-Cairn-Run은 클라이언트 주장으로 인증이 아닙니다. 예산은 같은 (Run, Intent)의 최종 전송 허가를 셉니다.
                요청 기록에서 Intent/Run·결과·보호 상태로 필터/정렬할 수 있습니다. 사용량 초기화는 개요에서 별도 확인합니다.
                GET 상태 확인은 정확한 경로만 운영자 일시중지·회로를 통과합니다. GET도 부작용이 있어 별도 확인합니다.
                리스너 포트는 목적지 포트가 아닌 실제 Burp 인바운드 포트입니다. 빈 목록은 모두, 제한 시 미선택은 검사·기록하지 않습니다.

                화면 원문과 마스킹 내보내기는 다릅니다
                요청 기록은 민감한 원문 URL·인증 헤더·본문을 별도 제한된 메모리 사본에서 보여줍니다.
                바이너리/지원하지 않는 문자셋은 captured bytes의 HEX일 수 있습니다. 생략/잘림/만료는 도착 증명이 아닙니다.
                프로젝트 전환·기록 비우기·퇴출 시 원문은 사라집니다. OFF/미선택 리스너는 새 내용을 수집하지 않습니다.
                JSON/HAR/사건은 원문 화면을 직렬화하지 않고 별도로 마스킹한 증거만 사용합니다.
                사건 내보내기: UTC [시작, 끝), 최대24시간. 보관 유실/근사 표시를 함께 검토하세요.
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
