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
            assertEquals(List.of("대상 등록", "규칙 만들기", "속도·결과 읽기", "자동 안전·태그·내보내기"),
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
            assertTrue(pages.getLast().getText().contains("감지 종류 선택") && pages.getLast().getText().contains("예외 검토"));
            assertTrue(pages.getLast().getText().contains("5xx 회로(기본 꺼짐)"));
            String safety = pages.getLast().getText();
            assertFalse(safety.contains("만료/수동 해제까지 유지됩니다"), "superseded retention wording");
            assertFalse(safety.contains("끄거나 ‘경고만’으로 바꾸면 그 종류의 열린 자동 차단만 즉시 풀리고 기록·진행 중 요청 자리는 남습니다") && safety.contains("기존 차단은 만료"));
            assertTrue(safety.contains("즉시"), "OFF/WARN release only that kind's open blocks at once");
            assertTrue(safety.contains("누락 부채") && safety.contains("운영자 일시중지"), "history/debt/operator pause remain");
            assertTrue(pages.getFirst().getText().contains("/c/%2e/main.do"));
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
