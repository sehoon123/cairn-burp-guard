package dev.cairnguard.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UsageGuideTest {
    @Test void guideIsEdtOnlyBoundedPlainTextAndCopyableWithoutAnyEditableOrHtmlViewer() throws Exception {
        assertThrows(IllegalStateException.class, UsageGuide::create);
        edt(() -> {
            JTabbedPane tabs = assertInstanceOf(JTabbedPane.class, UsageGuide.create());
            assertEquals(List.of("대상 등록", "규칙 만들기", "속도·결과 읽기", "수동 제어·태그·내보내기"),
                    java.util.stream.IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
            List<JTextArea> pages = new ArrayList<>(); collect(tabs, pages);
            assertEquals(4, pages.size());
            for (JTextArea page : pages) {
                assertFalse(page.isEditable()); assertTrue(page.isFocusable());
                assertTrue(page.getText().length() < 5_000);
                assertInstanceOf(NonScrollingCaret.class, page.getCaret());
                assertNotNull(page.getAccessibleContext().getAccessibleName());
                page.select(0, 10); assertEquals(page.getText().substring(0, 10), page.getSelectedText());
            }
            assertTrue(pages.getFirst().getText().contains("api.example.test"));
            assertTrue(pages.get(1).getText().contains("{\"action\":\"review\"}"));
            assertTrue(pages.get(2).getText().contains("자동 재전송"));
            assertTrue(pages.getLast().getText().contains("JSON/HAR/사건"));
            String safety = pages.getLast().getText();
            assertTrue(safety.contains("자동 차단 기능은 제거"));
            assertTrue(safety.contains("비활성 호환 데이터") && safety.contains("운영자 일시중지"));
            assertTrue(pages.getFirst().getText().contains("/c/%2e/main.do"));
            return null;
        });
    }

    @Test void guideDescribesOptionalPacingAndRemovedAutomaticControlsWithoutNativeCeilingClaims() throws Exception {
        edt(() -> {
            List<JTextArea> pages = new ArrayList<>(); collect(UsageGuide.create(), pages);
            String text = pages.stream().map(JTextArea::getText).collect(java.util.stream.Collectors.joining("\n"));
            for (String required : List.of("0=끔", "기본값 0/0", "호스트 예외", "모든 속도 끄기", "초안", "저장", "버전", "native 동시성 상한은 없습니다", "자동 차단 기능은 제거", "비활성 호환 데이터")) {
                assertTrue(text.contains(required), required);
            }
            for (String retired : List.of("1/1/1", "5/5/5", "동시 요청 1은", "동시성 자리를", "감지 종류 선택", "자동 차단 탭", "대용량 후보 탭", "예외 검토", "미완료 native 자리", "일시중지·회로를 통과")) {
                assertFalse(text.contains(retired), retired);
            }
            return null;
        });
    }

    @Test void historyGuideExplainsLiteralHexInlinePendingExportAndSinkFreeLazyPreview() throws Exception {
        edt(() -> {
            List<JTextArea> pages = new ArrayList<>(); collect(UsageGuide.create(), pages);
            String text = pages.getLast().getText();
            for (String required : List.of("v0.3.0", "literal substring", "연속 HEX", "pending", "불완전 결과", "inline", "popout", "정렬·필터 순서", "synthetic first line", "Static HTML preview", "탭을 선택", "StyledEditorKit", "CSS·이미지·JS", "원문/내보내기를 바꾸지", "실제 exit", "zeroization")) assertTrue(text.contains(required), required);
            return null;
        });
    }

    @Test void historyGuideExplainsScopedRe2ValidationAndUnchangedHumanControls() throws Exception {
        edt(() -> {
            List<JTextArea> pages = new ArrayList<>(); collect(UsageGuide.create(), pages);
            String text = pages.getLast().getText();
            for (String required : List.of("기본 All/Literal", "Literal에서 .*는 regex가 아닙니다", "Metadata", "요청 헤더", "응답 본문", "RE2", "find", "inline flags", "lookaround", "zero-width", "빈 검색어", "공백은 데이터", "4,096자", "4,096 instructions", "상한이 아닙니다", "고정 오류", "이전 검색을 되살리지", "필터 지우기", "정책·승인·속도·OFF")) assertTrue(text.contains(required), required);
            return null;
        });
    }

    @Test void examplesRemainScrollableAtSmallOrLargeFonts() throws Exception {
        edt(() -> {
            for (float size : new float[]{14f, 28f}) {
                JTabbedPane tabs = assertInstanceOf(JTabbedPane.class, UsageGuide.create());
                font(tabs, size); tabs.setSize(900, 480); layout(tabs);
                for (int i = 0; i < tabs.getTabCount(); i++) {
                    tabs.setSelectedIndex(i); layout(tabs);
                    JScrollPane scroll = assertInstanceOf(JScrollPane.class, tabs.getComponentAt(i));
                    assertTrue(scroll.getViewport().getHeight() > 100);
                    JTextArea area = assertInstanceOf(JTextArea.class, scroll.getViewport().getView());
                    assertTrue(area.getLineWrap()); assertTrue(area.getWrapStyleWord());
                    assertTrue(area.getHeight() >= scroll.getViewport().getHeight());
                }
            }
            return null;
        });
    }

    private static void collect(Component c, List<JTextArea> pages) {
        assertFalse(c instanceof JEditorPane);
        if (c instanceof JTextArea area) pages.add(area);
        if (c instanceof Container parent) for (Component child : parent.getComponents()) collect(child, pages);
    }
    private static void font(Component c, float size) {
        if (c.getFont() != null) c.setFont(c.getFont().deriveFont(size));
        if (c instanceof Container parent) for (Component child : parent.getComponents()) font(child, size);
    }
    private static void layout(Component c) {
        if (c instanceof Container parent) { parent.doLayout(); for (Component child : parent.getComponents()) layout(child); }
    }
    private static <T> T edt(Callable<T> body) throws Exception {
        FutureTask<T> task = new FutureTask<>(body); SwingUtilities.invokeAndWait(task); return task.get();
    }
}
