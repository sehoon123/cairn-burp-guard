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
import java.util.List;

/** Bounded human-only v2 settings draft. No writes; the enclosing UI confirms and CAS-saves it. */
@SuppressWarnings("serial")
final class SafetySettingsEditor {
    private final JPanel panel = new JPanel();
    private final Limits initial;
    private final JTextField intent;
    private final JCheckBox probes;
    private final JTextField listeners;
    private final List<Integer> originalListeners;
    private final RouteTable probeRoutes;
    SafetySettingsEditor(GuardConfig config) {
        initial = config.limits();
        panel.setName("settings.safety");
        panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("명시적 태그 예산 · 상태 확인 경로"));
        intent = field("settings.intent.maxRequests", Integer.toString(initial.perIntentMaxRequests()));
        probes = check("settings.probes.enabled", "명시한 GET 상태 확인 경로만 운영자 일시중지 통과", initial.healthProbePassthrough());
        originalListeners = config.guardListenerPorts();
        listeners = field("settings.listenerPorts", listenerText());
        listeners.setEditable(!originalListeners.isEmpty());
        probeRoutes = new RouteTable("settings.probes", initial.healthProbePaths().stream()
                .map(p -> List.of(p.scheme(), p.host(), Integer.toString(p.port()), p.path())).toList(),
                "GET 상태 확인 경로 (최대 16)", "정확한 GET path", "GET 상태 확인 경로");
        panel.add(note("INACTIVE legacy: 자동 차단·대용량·5xx 회로·확산·동시 요청·응답 시간 제한과 감지 예외는 호환 데이터로만 보존되며 실행되지 않습니다."));
        JPanel tags = grid("클라이언트 태그 예산 · 전체 Proxy 보호");
        row(tags, "(Run, Intent)별 전송 허가 횟수 (0=끔, 최대 1000000)", intent);
        row(tags, "기존 리스너 제한 (빈칸=모든 Proxy 보호 · 새 제한은 추후 지원)", listeners);
        panel.add(tags);
        panel.add(note("X-Cairn-Intent / X-Cairn-Run은 클라이언트가 주장한 태그이며 인증·신뢰 경계가 아닙니다. 한도가 꺼져도 기존 사용량은 보존됩니다. 이번 범위는 모든 Proxy 리스너 보호이며 포트별 보호는 추후 지원합니다. 새 포트 제한은 저장할 수 없습니다. 기존 제한은 자동 삭제하지 않습니다. 남아 있으면 모든 새 보호 요청이 LISTENER_UNVERIFIED로 거절되므로, 직접 목록을 비우고 전체 보호 전환을 확인해 저장하세요."));
        panel.add(probes);
        panel.add(note("GET도 부작용이 있을 수 있습니다. 아래 정확한 scheme/host/port/path만 지정하세요. query·fragment·모호한 경로 불가. 상태 확인도 범위·일반 규칙·예산·수동 속도는 우회하지 않습니다. 활성화/경로 변경 저장에는 별도 확인이 필요합니다."));
        panel.add(probeRoutes.panel);

    }

    JComponent component() { return panel; }

    Limits limits(int global, int perHost, java.util.Map<String,Integer> hostRps, int queued,
                  long queueMillis, long approvalMillis) {
        List<ProbePath> health = probeRoutes.values().stream().map(r -> new ProbePath(r.get(0), r.get(1), port(r.get(2)), r.get(3))).toList();
        return new Limits(global, perHost, hostRps, initial.maxConcurrent(), queued, queueMillis, approvalMillis,
                initial.requestTimeoutMillis(), initial.perPathMaxResponseBytes(), initial.autoBlockMillis(),
                initial.circuit5xx(), initial.fanout(), integer(intent, 0, 1_000_000), probes.isSelected(), health,
                initial.heavyPathLimits(), initial.circuit5xxExceptions(), initial.heavyResponseEnabled(), initial.fanoutExceptions());
    }

    List<Integer> listenerPorts() {
        String text = input(listeners);
        if (text.isBlank()) return List.of();
        // Preserve old authored data on unrelated edits; never create/change an unsupported selection.
        if (!originalListeners.isEmpty() && text.equals(listenerText())) return originalListeners;
        throw error("포트별 보호는 추후 지원합니다. 이번 버전은 빈 목록으로 모든 Proxy 리스너를 보호합니다. 기존 제한은 직접 비운 뒤 확인해 저장하세요.");
    }
    private String listenerText() {
        return String.join(", ", originalListeners.stream().map(Object::toString).toList());
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
        private final JPanel panel = new JPanel(new BorderLayout(4, 4));
        private final JTable table;
        private final String[] columns;
        private final int max;
        RouteTable(String name, List<List<String>> initial, String title, String pathColumn, String accessibleName) {
            max = 16;
            for (List<String> r : initial) rows.add(new ArrayList<>(r));
            columns = new String[]{"scheme", "host", "port", pathColumn};
            table = new JTable(this);
            panel.setName(name); table.setName(name + ".table");
            panel.setBorder(BorderFactory.createTitledBorder(title));
            table.getTableHeader().setReorderingAllowed(false); table.setRowHeight(30);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            DefaultTableCellRenderer literal = new DefaultTableCellRenderer(); literal.putClientProperty("html.disable", true); table.setDefaultRenderer(String.class, literal);
            table.getAccessibleContext().setAccessibleName(accessibleName);
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
                rows.add(new ArrayList<>(List.of("https", "", "443", "/")));
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
        @Override public int getColumnCount() { return 4; }
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
