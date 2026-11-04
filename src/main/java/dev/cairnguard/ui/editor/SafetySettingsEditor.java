package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Bounded human-only v2 settings draft. No writes; the enclosing UI confirms and CAS-saves it. */
@SuppressWarnings("serial")
final class SafetySettingsEditor {
    private static final BigDecimal MIB = BigDecimal.valueOf(1_048_576);
    private final JPanel panel = new JPanel();
    private final JTextField heavy;
    private final JTextField ttl;
    private final JCheckBox circuit;
    private final JTextField circuitWindow;
    private final JTextField circuitThreshold;
    private final JTextField circuitOpen;
    private final JCheckBox fanout;
    private final JTextField fanoutWindow;
    private final JTextField fanoutPaths;
    private final JComboBox<FanoutAction> fanoutAction = new JComboBox<>(FanoutAction.values());
    private final JTextField intent;
    private final JCheckBox probes;
    private final JTextField listeners;
    private final RouteTable probeRoutes;
    private final RouteTable byteRoutes;
    SafetySettingsEditor(GuardConfig config) {
        Limits initial = config.limits();
        panel.setName("settings.safety");
        panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("자동 안전 제어 · 태그 예산 · 보호 리스너 (저장 전 초안)"));
        heavy = field("settings.heavyMiB", mib(initial.perPathMaxResponseBytes()));
        ttl = field("settings.autoBlockSeconds", seconds(initial.autoBlockMillis()));
        circuit = check("settings.circuit.enabled", "5xx 회로 차단 사용", initial.circuit5xx() != null);
        Circuit5xx c = initial.circuit5xx() == null ? new Circuit5xx(60_000, 5, 600_000, 1) : initial.circuit5xx();
        circuitWindow = field("settings.circuit.windowSeconds", seconds(c.windowMillis()));
        circuitThreshold = field("settings.circuit.threshold", Integer.toString(c.threshold()));
        circuitOpen = field("settings.circuit.openSeconds", seconds(c.openMillis()));
        fanout = check("settings.fanout.enabled", "서로 다른 경로 확산 감지 사용", initial.fanout() != null);
        Fanout f = initial.fanout() == null ? new Fanout(60_000, 100, FanoutAction.WARN) : initial.fanout();
        fanoutWindow = field("settings.fanout.windowSeconds", seconds(f.windowMillis()));
        fanoutPaths = field("settings.fanout.distinctPaths", Integer.toString(f.distinctPaths()));
        fanoutAction.setName("settings.fanout.action");
        fanoutAction.setRenderer(new DefaultListCellRenderer() {
            @Override public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                super.getListCellRendererComponent(list, "", index, selected, focus);
                setText(value == FanoutAction.BLOCK ? "해당 서비스 차단" : value == FanoutAction.PAUSE ? "전체 자동 차단" : "경고만");
                return this;
            }
        });
        fanoutAction.setSelectedItem(f.action());
        intent = field("settings.intent.maxRequests", Integer.toString(initial.perIntentMaxRequests()));
        probes = check("settings.probes.enabled", "명시한 GET 상태 확인 경로만 운영자 일시중지·회로 차단 통과", initial.healthProbePassthrough());
        listeners = field("settings.listenerPorts", String.join(", ", config.guardListenerPorts().stream().map(Object::toString).toList()));
        probeRoutes = new RouteTable("settings.probes", false, initial.healthProbePaths().stream()
                .map(p -> List.of(p.scheme(), p.host(), Integer.toString(p.port()), p.path())).toList());
        byteRoutes = new RouteTable("settings.pathLimits", true, initial.heavyPathLimits().stream()
                .map(p -> List.of(p.scheme(), p.host(), Integer.toString(p.port()), p.path(), mib(p.maxBytes()))).toList());
        JPanel detection = grid("응답 크기 · 일시 차단");
        row(detection, "기본 경로별 최대 응답 MiB (0=끔, 최대 2048)", heavy);
        row(detection, "자동 차단 유지 (초, 1~86400)", ttl);
        panel.add(detection);
        panel.add(note("첫 대용량 응답은 이미 전송된 뒤 감지합니다. 이후 같은 경로만 차단하며 응답 본문 길이를 사용합니다. 자동 차단·후보·사건은 메모리에만 있고 정책 자동 저장은 없습니다. 감지를 끄더라도 이미 열린 차단은 만료·수동 해제까지 유지됩니다."));
        panel.add(circuit);
        JPanel cg = grid("5xx 회로 설정 (회로가 꺼져 있으면 적용하지 않음)");
        row(cg, "관찰 창 (초, 1~3600)", circuitWindow);
        row(cg, "5xx 횟수 (1~1000)", circuitThreshold);
        row(cg, "회로 열림 (초, 1~86400)", circuitOpen);
        panel.add(cg);
        panel.add(note("회로 재확인: GET/HEAD만 한 번, 서비스당 최대 30초에 1회. 성공하면 닫고 5xx·응답 미확인이면 다시 엽니다. 미완료 native 요청의 자리는 강제로 비우지 않습니다."));
        panel.add(fanout);
        JPanel fg = grid("확산 감지 설정 (꺼져 있으면 적용하지 않음)");
        row(fg, "관찰 창 (초, 1~3600)", fanoutWindow);
        row(fg, "서로 다른 경로 (2~1000)", fanoutPaths);
        row(fg, "감지 시 동작", fanoutAction);
        panel.add(fg);
        JPanel tags = grid("클라이언트 태그 예산 · 실제 인바운드 리스너");
        row(tags, "(Run, Intent)별 전송 허가 횟수 (0=끔, 최대 1000000)", intent);
        row(tags, "보호할 Proxy 리스너 포트 (쉼표 구분, 빈칸=모두)", listeners);
        panel.add(tags);
        panel.add(note("X-Cairn-Intent / X-Cairn-Run은 클라이언트가 주장한 태그이며 인증·신뢰 경계가 아닙니다. 한도가 꺼져도 기존 사용량은 보존됩니다. 현재 네이티브 리스너 제한은 미지원입니다. 목록을 제한하면 보호 중 선택·미선택 모두 내용 검사 전에 LISTENER_UNVERIFIED로 거절됩니다. 정상적인 전체 보호는 빈칸으로 두세요. 목적지 서버 포트가 아니라 실제 Burp 인바운드 리스너 포트입니다. 최대 16개, 1~65535, 중복 불가."));
        panel.add(probes);
        panel.add(note("GET도 부작용이 있을 수 있습니다. 아래 정확한 scheme/host/port/path만 지정하세요. query·fragment·모호한 경로 불가. 상태 확인도 범위·일반 규칙·대용량/확산 차단·예산·속도는 우회하지 않습니다. 통과 응답으로 회로를 회복시키지 않습니다. 활성화/경로 변경 저장에는 별도 확인이 필요합니다."));
        panel.add(probeRoutes.panel);
        panel.add(byteRoutes.panel);
        panel.add(note("경로별 MiB는 기본 응답 한도만 대체합니다 (0=이 정확한 경로의 크기 감지 끔). 경로는 자동 후보에서 원문을 수집하지 않으며 직접 작성·검토하세요. 표의 추가·수정·삭제도 최종 저장 전에는 적용되지 않습니다."));
    }

    JComponent component() { return panel; }

    Limits limits(int global, int perHost, java.util.Map<String,Integer> hostRps, int concurrent, int queued,
                  long queueMillis, long approvalMillis, long requestMillis) {
        long maxBytes = bytes(input(heavy));
        long openMillis = duration(ttl, 86_400);
        Circuit5xx c = circuit.isSelected() ? new Circuit5xx(duration(circuitWindow, 3600),
                integer(circuitThreshold, 1, 1000), duration(circuitOpen, 86_400), 1) : null;
        Fanout f = fanout.isSelected() ? new Fanout(duration(fanoutWindow, 3600), integer(fanoutPaths, 2, 1000),
                (FanoutAction) fanoutAction.getSelectedItem()) : null;
        // Disabled routes remain authored data; disabling an option must not silently erase them.
        List<ProbePath> health = probeRoutes.values().stream().map(r -> new ProbePath(r.get(0), r.get(1), port(r.get(2)), r.get(3))).toList();
        List<PathByteLimit> paths = byteRoutes.values().stream().map(r -> new PathByteLimit(r.get(0), r.get(1), port(r.get(2)), r.get(3), bytes(r.get(4)))).toList();
        return new Limits(global, perHost, hostRps, concurrent, queued, queueMillis, approvalMillis, requestMillis,
                maxBytes, openMillis, c, f, integer(intent, 0, 1_000_000), probes.isSelected(), health, paths);
    }

    List<Integer> listenerPorts() {
        String text = input(listeners);
        if (text.isBlank()) return List.of();
        String[] parts = text.split(",", -1);
        if (parts.length > 16) throw error("보호 리스너는 최대 16개입니다.");
        List<Integer> ports = new ArrayList<>();
        HashSet<Integer> seen = new HashSet<>();
        for (String part : parts) {
            int p = port(part.strip());
            if (!seen.add(p)) throw error("보호 리스너 포트가 중복되었습니다.");
            ports.add(p);
        }
        return List.copyOf(ports);
    }

    private static int port(String text) {
        try {
            int value = decimal(text).intValueExact();
            if (value < 1 || value > 65535) throw new ArithmeticException();
            return value;
        } catch (RuntimeException e) { throw error("포트는 1~65535 정수로 입력하세요."); }
    }
    private static int integer(JTextField field, int min, int max) {
        try {
            int value = decimal(input(field)).intValueExact();
            if (value < min || value > max) throw new ArithmeticException();
            return value;
        } catch (RuntimeException e) { throw error("안전 제어 횟수·개수 범위를 확인하세요. 정수만 사용할 수 있습니다."); }
    }
    private static long duration(JTextField field, int maxSeconds) {
        try {
            long value = decimal(input(field)).movePointRight(3).longValueExact();
            if (value < 1000 || value > maxSeconds * 1000L) throw new ArithmeticException();
            return value;
        } catch (RuntimeException e) { throw error("자동 안전 제어 시간은 1초 이상, 안내된 상한 이하이며 0.001초 단위여야 합니다."); }
    }
    static long bytes(String text) {
        try {
            long value = decimal(text).multiply(MIB).longValueExact();
            if (value < 0 || value > 2_147_483_648L) throw new ArithmeticException();
            return value;
        } catch (RuntimeException e) { throw error("응답 크기는 0~2048 MiB이며 정확한 바이트 정수로 변환되는 소수만 사용할 수 있습니다."); }
    }
    private static BigDecimal decimal(String text) {
        if (text == null || text.length() > 32 || text.isEmpty()) throw new NumberFormatException();
        boolean dot = false; int digits = 0;
        for (char c : text.toCharArray()) {
            if (c >= '0' && c <= '9') digits++;
            else if (c == '.' && !dot) dot = true;
            else throw new NumberFormatException();
        }
        if (digits == 0) throw new NumberFormatException();
        return new BigDecimal(text);
    }
    private static String seconds(long millis) { return BigDecimal.valueOf(millis, 3).stripTrailingZeros().toPlainString(); }
    private static String mib(long bytes) { return BigDecimal.valueOf(bytes).divide(MIB).stripTrailingZeros().toPlainString(); }
    private static FormValidationException error(String message) { return new FormValidationException(message); }
    private static JCheckBox check(String name, String text, boolean selected) {
        JCheckBox box = new JCheckBox(text, selected); box.setName(name); box.getAccessibleContext().setAccessibleName(text); return box;
    }
    private static JTextField field(String name, String text) {
        JTextField field = new JTextField(text, 12); field.setName(name);
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new BoundedInput(field, 4096));
        return field;
    }
    private static JPanel grid(String title) { JPanel grid = new JPanel(new GridLayout(0, 1, 8, 6)); grid.setBorder(BorderFactory.createTitledBorder(title)); return grid; }
    private static void row(JPanel grid, String text, JComponent input) {
        JPanel row = new JPanel(new BorderLayout(2, 2));
        JTextArea caption = note(text); caption.setName(input.getName() + ".label");
        input.getAccessibleContext().setAccessibleName(text); input.setToolTipText(text);
        row.add(caption, BorderLayout.NORTH); row.add(input, BorderLayout.CENTER); grid.add(row);
    }
    private static String input(JTextField field) {
        if (Boolean.TRUE.equals(field.getClientProperty("inputRejected"))) throw error("입력이 너무 깁니다. 줄여서 다시 입력하세요. 이전 값이나 잘린 값으로 저장하지 않습니다.");
        return field.getText();
    }
    private static JTextArea note(String text) {
        JTextArea area = new JTextArea(text, 0, 48); area.setEditable(false); area.setFocusable(false);
        area.setLineWrap(true); area.setWrapStyleWord(true); area.setOpaque(false);
        area.setCaret(new dev.cairnguard.ui.NonScrollingCaret());
        if (UIManager.getFont("Label.font") != null) area.setFont(UIManager.getFont("Label.font"));
        return area;
    }

    private static final class RouteTable extends AbstractTableModel {
        private final List<List<String>> rows = new ArrayList<>();
        private final boolean bytes;
        private final JPanel panel = new JPanel(new BorderLayout(4, 4));
        private final JTable table;
        private final String[] columns;
        private final int max;
        RouteTable(String name, boolean bytes, List<List<String>> initial) {
            this.bytes = bytes; max = bytes ? 256 : 16;
            for (List<String> r : initial) rows.add(new ArrayList<>(r));
            columns = bytes ? new String[]{"scheme", "host", "port", "정확한 path", "MiB (0=끔)"} : new String[]{"scheme", "host", "port", "정확한 GET path"};
            table = new JTable(this);
            panel.setName(name); table.setName(name + ".table");
            panel.setBorder(BorderFactory.createTitledBorder(bytes ? "정확한 경로별 응답 크기 한도 (최대 256)" : "GET 상태 확인 경로 (최대 16)"));
            table.getTableHeader().setReorderingAllowed(false); table.setRowHeight(30);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            DefaultTableCellRenderer literal = new DefaultTableCellRenderer(); literal.putClientProperty("html.disable", true); table.setDefaultRenderer(String.class, literal);
            table.getAccessibleContext().setAccessibleName(bytes ? "경로별 응답 MiB 한도" : "GET 상태 확인 경로");
            JTextField edit = field(name + ".cell", "");
            table.setDefaultEditor(String.class, new DefaultCellEditor(edit) {
                @Override public boolean stopCellEditing() {
                    if (Boolean.TRUE.equals(edit.getClientProperty("inputRejected"))) return false;
                    return super.stopCellEditing();
                }
            });
            table.setPreferredScrollableViewportSize(new java.awt.Dimension(600, 120));
            panel.add(new JScrollPane(table), BorderLayout.CENTER);
            JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEADING));
            JButton add = new JButton("경로 추가"); add.setName(name + ".add");
            JButton remove = new JButton("선택 경로 삭제"); remove.setName(name + ".remove");
            add.addActionListener(e -> {
                if (!tryStop() || rows.size() >= max) return;
                rows.add(new ArrayList<>(bytes ? List.of("https", "", "443", "/", "5") : List.of("https", "", "443", "/")));
                fireTableDataChanged(); table.setRowSelectionInterval(rows.size()-1, rows.size()-1);
            });
            remove.addActionListener(e -> { if (!tryStop()) return; int row = table.getSelectedRow(); if (row >= 0) { rows.remove(row); fireTableDataChanged(); } });
            actions.add(add); actions.add(remove); panel.add(actions, BorderLayout.SOUTH);
        }
        private boolean tryStop() {
            if (table.isEditing() && !table.getCellEditor().stopCellEditing()) {
                table.setToolTipText("경로 입력이 너무 깁니다. 줄인 뒤 다시 시도하세요."); return false;
            }
            table.setToolTipText(null); return true;
        }
        private void stop() { if (!tryStop()) throw error("경로 표 입력을 마친 뒤 저장하세요."); }
        List<List<String>> values() { stop(); if (rows.size() > max) throw error("경로 행 개수 한도를 초과했습니다."); return rows.stream().map(List::copyOf).toList(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return bytes ? 5 : 4; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Class<?> getColumnClass(int col) { return String.class; }
        @Override public Object getValueAt(int row, int col) { return rows.get(row).get(col); }
        @Override public boolean isCellEditable(int row, int col) { return true; }
        @Override public void setValueAt(Object value, int row, int col) {
            if (!(value instanceof String text) || text.length() > 4096) throw error("경로 입력 길이를 확인하세요.");
            rows.get(row).set(col, text); fireTableCellUpdated(row, col);
        }
    }
    private static final class BoundedInput extends DocumentFilter {
        private final int max;
        private final JTextField field;
        BoundedInput(JTextField field, int max) { this.field = field; this.max = max; }
        @Override public void insertString(FilterBypass fb, int offset, String text, AttributeSet attrs) throws BadLocationException { replace(fb, offset, 0, text, attrs); }
        @Override public void remove(FilterBypass fb, int offset, int length) throws BadLocationException { replace(fb, offset, length, "", null); }
        @Override public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
            if ((long) fb.getDocument().getLength() - length + (text == null ? 0 : text.length()) > max) {
                field.putClientProperty("inputRejected", Boolean.TRUE); return;
            }
            field.putClientProperty("inputRejected", Boolean.FALSE);
            fb.replace(offset, length, text, attrs);
        }
    }
}
