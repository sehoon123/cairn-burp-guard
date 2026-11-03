package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.policy.PolicyEngine;

import javax.swing.AbstractSpinnerModel;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultFormatterFactory;
import javax.swing.text.DocumentFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.math.BigDecimal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Local, EDT-only policy settings draft. No authentication, persistence, native or network actions. */
@SuppressWarnings("serial") // Swing drafts are never serialized.
public final class SettingsEditor implements EditorForm<SettingsEditor.Value> {
    public record Value(Mode defaultMode, Limits limits) {}

    private static final int MAX_HOSTS = 256;
    private static final int MAX_HOST_CHARS = 255;
    private static final int MAX_NUMBER_CHARS = 32;
    private static final String TOO_LONG = "settings.inputTooLong";
    private static final String LENGTH_ERROR = "입력이 너무 깁니다. 호스트는 255자, 숫자는 32자 이내로 다시 입력하세요.";
    private static final String TABLE_EDIT_ERROR = "호스트 표의 편집 중인 값을 확인하고 입력을 마친 뒤 다시 저장하세요.";
    private static final String HOST_ERROR = "호스트를 확인하세요. URL·포트·경로·와일드카드 없이 호스트 이름이나 IP 주소만 입력하세요.";
    private static final String DUPLICATE_ERROR = "같은 호스트를 가리키는 행이 중복되었습니다. 대소문자·끝의 점·국제 도메인·IPv6 별칭을 확인하고 한 행만 남기세요.";
    private static final String HOST_RATE_ERROR = "호스트별 초당 요청 수는 1~1,000 사이의 정수로 입력하세요.";
    private static final String TIME_ERROR = "대기 제한은 0.001~600초로 입력하세요. 소수점 셋째 자리(1밀리초)보다 작은 단위는 사용할 수 없습니다.";
    private static final String POLICY_ERROR = "설정을 저장할 수 없습니다. 범위와 규칙을 포함한 정책을 다시 불러온 뒤 설정값을 확인하세요.";

    private final GuardConfig initial;
    private final PolicyEngine engine;
    private final JScrollPane root;
    private final JSpinner globalRps;
    private final JSpinner perHostRps;
    private final JSpinner maxConcurrent;
    private final JSpinner maxQueued;
    private final JSpinner queueTimeout;
    private final JSpinner approvalTimeout;
    private final JSpinner requestTimeout;
    private final JComboBox<Mode> defaultMode;
    private final JCheckBox advancedToggle;
    private final JPanel advanced;
    private final JTextArea validation;
    private final HostModel hostModel;
    private final JTable hosts;
    private final JButton addHost;
    private final JButton removeHost;

    public SettingsEditor(GuardConfig initial) {
        requireEdt();
        engine = new PolicyEngine();
        try { engine.validate(initial); }
        catch (RuntimeException e) { throw new FormValidationException(POLICY_ERROR); }
        this.initial = initial;
        Limits limits = initial.limits();
        globalRps = number("settings.globalRps", "전체 초당 요청 수 (RPS)", limits.globalRps(), 1, 1_000, false);
        perHostRps = number("settings.perHostRps", "기본 호스트당 초당 요청 수", limits.perHostRps(), 1, 1_000, false);
        maxConcurrent = number("settings.maxConcurrent", "최대 동시 요청 수", limits.maxConcurrent(), 1, 100, false);
        maxQueued = number("settings.maxQueued", "전송 대기열 크기", limits.maxQueued(), 0, 10_000, false);
        queueTimeout = number("settings.queueTimeoutSeconds", "전송 대기 제한 (초)", seconds(limits.queueTimeoutMillis()), 0, 600, true);
        approvalTimeout = number("settings.approvalTimeoutSeconds", "승인 대기 제한 (초)", seconds(limits.approvalTimeoutMillis()), 0, 600, true);
        requestTimeout = number("settings.requestTimeoutSeconds", "응답 대기 제한 (초)", seconds(limits.requestTimeoutMillis()), 0, 600, true);
        defaultMode = named(new JComboBox<>(Mode.values()), "settings.defaultMode", "규칙에 해당하지 않을 때의 기본 동작");
        defaultMode.setRenderer(new ModeRenderer());
        defaultMode.setSelectedItem(initial.defaultMode());
        advancedToggle = named(new JCheckBox("상세 설정 펼치기 (대기열·시간·기본 동작·호스트별 속도)"),
                "settings.advanced.toggle", "상세 설정 펼치기");
        advanced = named(new JPanel(), "settings.advanced", "상세 설정");
        advanced.setLayout(new BoxLayout(advanced, BoxLayout.PAGE_AXIS));
        validation = wrapped("settings.validation", " ");
        hostModel = new HostModel(limits.hostRps());
        hosts = named(new JTable(hostModel), "settings.hostRps.table", "호스트별 초당 요청 수 표");
        hosts.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        hosts.setDefaultRenderer(String.class, new LiteralRenderer());
        hosts.getTableHeader().setReorderingAllowed(false);
        named(hosts.getTableHeader(), "settings.hostRps.header", "호스트별 속도 표 머리글");
        hosts.getColumnModel().getColumn(0).setCellEditor(cellEditor("settings.hostRps.hostEditor", "호스트", MAX_HOST_CHARS));
        hosts.getColumnModel().getColumn(1).setCellEditor(cellEditor("settings.hostRps.rateEditor", "호스트 초당 요청 수", MAX_NUMBER_CHARS));
        // Follow font changes when Burp applies its theme after creating the form, too.
        hosts.addPropertyChangeListener("font", e -> sizeHostTable());
        sizeHostTable();
        // JTable's focus-loss helper cancels an edit when stopCellEditing fails. Keep it for explicit Save validation instead.
        hosts.putClientProperty("terminateEditOnFocusLost", Boolean.FALSE);
        addHost = named(new JButton("호스트 추가"), "settings.hostRps.add", "호스트별 속도 추가");
        removeHost = named(new JButton("선택한 호스트 삭제"), "settings.hostRps.remove", "선택한 호스트별 속도 삭제");
        addHost.addActionListener(e -> editRows(() -> {
            if (hostModel.getRowCount() >= MAX_HOSTS) throw failure("호스트별 속도는 최대 256행입니다. 사용하지 않는 행을 삭제하세요.", true);
            hostModel.add();
            int row = hostModel.getRowCount() - 1;
            hosts.setRowSelectionInterval(row, row);
            hosts.scrollRectToVisible(hosts.getCellRect(row, 0, true));
            if (hosts.editCellAt(row, 0)) hosts.getEditorComponent().requestFocusInWindow();
        }));
        removeHost.addActionListener(e -> editRows(() -> {
            int selected = hosts.getSelectedRow();
            if (selected >= 0) hostModel.remove(hosts.convertRowIndexToModel(selected));
        }));
        hosts.getSelectionModel().addListSelectionListener(e -> updateHostButtons());
        hostModel.addTableModelListener(e -> updateHostButtons());

        FormPanel content = named(new FormPanel(), "settings.form", "요청 제어 설정");
        content.setLayout(new BoxLayout(content, BoxLayout.PAGE_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        content.add(wrapped("settings.guidance", "요청의 속도와 동시 실행을 제한합니다. 로그인, 쿠키·토큰 주입, 세션 갱신 기능은 없습니다. 저장 전까지 기존 설정은 바뀌지 않습니다."));
        JPanel basic = grid("settings.basic", "일반 설정");
        row(basic, 0, "전체 초당 요청 수 (RPS)", globalRps);
        row(basic, 1, "기본 호스트당 초당 요청 수", perHostRps);
        row(basic, 2, "최대 동시 요청 수", maxConcurrent);
        content.add(basic);
        content.add(wrapped("settings.basic.help", "RPS는 초당 전송할 요청 수입니다 (1~1,000). 숫자는 쉼표 없이 입력하세요. 전체 속도와 호스트별 속도를 함께 제한합니다. 동시 요청 수는 응답을 기다리는 요청의 최대 개수입니다 (1~100)."));
        content.add(advancedToggle);
        JPanel timing = grid("settings.timing", "대기와 기본 동작");
        row(timing, 0, "전송 대기열 크기 (0~10,000)", maxQueued);
        row(timing, 1, "전송 대기 제한 (초)", queueTimeout);
        row(timing, 2, "승인 대기 제한 (초)", approvalTimeout);
        row(timing, 3, "응답 대기 제한 (초)", requestTimeout);
        row(timing, 4, "규칙에 해당하지 않을 때", defaultMode);
        advanced.add(timing);
        advanced.add(wrapped("settings.timing.help", "시간은 0.001~600초, 0.001초(1밀리초) 단위입니다. 전송·승인 대기 제한이 지나면 차단합니다. 응답 대기 제한이 지나도 기존 요청을 취소하거나 동시 실행 자리를 자동으로 비우지 않습니다. 새 요청을 막고 확인을 기다립니다."));
        advanced.add(wrapped("settings.mode.help", "기본 동작은 등록한 허용 범위 안에서만 적용됩니다. 허용 대상이 없거나 필수 안전 검사에 실패하면 항상 차단합니다."));
        JPanel hostPanel = named(new JPanel(new BorderLayout(4, 4)), "settings.hostRps", "호스트별 속도");
        hostPanel.setBorder(BorderFactory.createTitledBorder("호스트별 속도 (최대 256행)"));
        hostPanel.add(wrapped("settings.hostRps.help", "기본 호스트 속도만 대체하며 전체 속도 제한과 허용 범위는 유지됩니다. URL·포트·경로·와일드카드 없이 호스트만 입력하세요. 각 속도는 1~1,000 정수입니다. 같은 호스트의 별칭은 중복할 수 없습니다. 기존 호스트 표기는 그대로 보존됩니다."), BorderLayout.NORTH);
        hostPanel.add(scroll(hosts, "settings.hostRps.scroll"), BorderLayout.CENTER);
        JPanel hostButtons = named(new JPanel(new FlowLayout(FlowLayout.LEADING)), "settings.hostRps.buttons", "호스트별 속도 작업");
        hostButtons.add(addHost);
        hostButtons.add(removeHost);
        hostPanel.add(hostButtons, BorderLayout.SOUTH);
        advanced.add(hostPanel);
        advanced.setVisible(false);
        advancedToggle.addActionListener(e -> {
            advanced.setVisible(advancedToggle.isSelected());
            advanced.revalidate();
        });
        content.add(advanced);
        content.add(validation);
        root = scroll(content, "settings.editor");
        root.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        updateHostButtons();
    }

    @Override public JComponent component() {
        requireEdt();
        return root;
    }

    @Override public Value value() {
        requireEdt();
        int global = integer(globalRps, 1, 1_000, "전체 초당 요청 수는 1~1,000 사이의 정수로 입력하세요.", false);
        int perHost = integer(perHostRps, 1, 1_000, "기본 호스트당 초당 요청 수는 1~1,000 사이의 정수로 입력하세요.", false);
        int concurrent = integer(maxConcurrent, 1, 100, "최대 동시 요청 수는 1~100 사이의 정수로 입력하세요.", false);
        int queued = integer(maxQueued, 0, 10_000, "전송 대기열 크기는 0~10,000 사이의 정수로 입력하세요.", true);
        long queueMillis = millis(queueTimeout);
        long approvalMillis = millis(approvalTimeout);
        long requestMillis = millis(requestTimeout);
        commitTable();
        Map<String, Integer> overrides = new LinkedHashMap<>();
        Set<String> canonicalHosts = new HashSet<>();
        for (HostRow row : hostModel.rows) {
            if (row.hostTooLong || row.rateTooLong) throw failure(LENGTH_ERROR, true);
            String canonical;
            try { canonical = PolicyEngine.canonicalHost(row.host); }
            catch (RuntimeException e) { throw failure(HOST_ERROR, true); }
            if (!canonicalHosts.add(canonical)) throw failure(DUPLICATE_ERROR, true);
            int rate;
            try {
                rate = decimal(row.rate).intValueExact();
                if (rate < 1 || rate > 1_000) throw new ArithmeticException();
            } catch (RuntimeException e) { throw failure(HOST_RATE_ERROR, true); }
            // Do not rewrite valid existing operator-authored aliases on merely opening/saving this form.
            overrides.put(row.host, rate);
        }
        if (!(defaultMode.getSelectedItem() instanceof Mode mode))
            throw failure("기본 동작을 목록에서 선택하세요.", true);
        Limits limits = new Limits(global, perHost, overrides, concurrent, queued, queueMillis, approvalMillis, requestMillis);
        try {
            engine.validate(new GuardConfig(initial.schemaVersion(), initial.allowScope(), initial.blockScope(), initial.rules(), mode, limits));
        } catch (RuntimeException e) { throw failure(POLICY_ERROR, true); }
        validation.setText(" ");
        return new Value(mode, limits);
    }

    private int integer(JSpinner spinner, int min, int max, String message, boolean detailed) {
        try {
            int value = committed(spinner).intValueExact();
            if (value < min || value > max) throw new ArithmeticException();
            return value;
        } catch (ParseException | RuntimeException e) { throw failure(message, detailed); }
    }

    private long millis(JSpinner spinner) {
        try {
            long value = committed(spinner).movePointRight(3).longValueExact();
            if (value < 1 || value > 600_000) throw new ArithmeticException();
            return value;
        } catch (ParseException | RuntimeException e) { throw failure(TIME_ERROR, true); }
    }

    private static BigDecimal committed(JSpinner spinner) throws ParseException {
        JFormattedTextField text = ((JSpinner.DefaultEditor) spinner.getEditor()).getTextField();
        if (Boolean.TRUE.equals(text.getClientProperty(TOO_LONG))) throw new ParseException("숫자 길이를 확인하세요.", 0);
        // PERSIST plus an exact formatter prevents focus loss or an integer formatter from reverting/rounding a draft.
        spinner.commitEdit();
        return decimal(text.getText());
    }

    private void commitTable() {
        boolean committed;
        try { committed = !hosts.isEditing() || (hosts.getCellEditor().stopCellEditing() && !hosts.isEditing()); }
        catch (RuntimeException e) { throw failure(TABLE_EDIT_ERROR, true); }
        if (!committed) throw failure(TABLE_EDIT_ERROR, true);
    }

    private void sizeHostTable() {
        int em = hosts.getFontMetrics(hosts.getFont()).charWidth('M');
        hosts.setRowHeight(hosts.getFontMetrics(hosts.getFont()).getHeight() + 10);
        hosts.getColumnModel().getColumn(0).setPreferredWidth(em * 30);
        hosts.getColumnModel().getColumn(1).setPreferredWidth(em * 18);
        hosts.setPreferredScrollableViewportSize(new Dimension(em * 48, hosts.getRowHeight() * 5));
    }

    private void editRows(Runnable edit) {
        requireEdt();
        try {
            commitTable();
            edit.run();
            validation.setText(" ");
        } catch (FormValidationException e) { validation.setText(e.getMessage()); }
        updateHostButtons();
    }

    private void updateHostButtons() {
        addHost.setEnabled(hostModel.getRowCount() < MAX_HOSTS);
        removeHost.setEnabled(hosts.getSelectedRow() >= 0);
    }

    private FormValidationException failure(String message, boolean detailed) {
        validation.setText(message);
        if (detailed) {
            advancedToggle.setSelected(true);
            advanced.setVisible(true);
            advanced.revalidate();
        }
        return new FormValidationException(message);
    }

    private DefaultCellEditor cellEditor(String name, String label, int maxChars) {
        JTextField field = named(new JTextField(), name, label);
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new LengthFilter(field, maxChars));
        DefaultCellEditor editor = new DefaultCellEditor(field) {
            @Override public Component getTableCellEditorComponent(JTable table, Object value, boolean selected, int row, int column) {
                field.setFont(table.getFont());
                return super.getTableCellEditorComponent(table, value, selected, row, column);
            }
            @Override public boolean stopCellEditing() {
                if (Boolean.TRUE.equals(field.getClientProperty(TOO_LONG))) {
                    validation.setText(LENGTH_ERROR);
                    return false;
                }
                return super.stopCellEditing();
            }
        };
        editor.setClickCountToStart(1);
        return editor;
    }

    private static JSpinner number(String name, String label, Number initial, int min, int max, boolean seconds) {
        BigDecimal lower = seconds ? new BigDecimal("0.001") : BigDecimal.valueOf(min);
        JSpinner spinner = named(new JSpinner(new ExactModel(initial, lower, BigDecimal.valueOf(max),
                seconds ? new BigDecimal("0.001") : BigDecimal.ONE)), name, label);
        JSpinner.DefaultEditor editor = named(new JSpinner.DefaultEditor(spinner), name + ".editor", label);
        JFormattedTextField text = named(editor.getTextField(), name + ".text", label);
        text.setFormatterFactory(new DefaultFormatterFactory(new ExactFormatter()));
        text.setValue(initial);
        text.setColumns(seconds ? 9 : 7);
        text.setFocusLostBehavior(JFormattedTextField.PERSIST);
        ((AbstractDocument) text.getDocument()).setDocumentFilter(new LengthFilter(text, MAX_NUMBER_CHARS));
        spinner.setEditor(editor);
        for (Component child : spinner.getComponents()) {
            if (child instanceof JButton button) {
                boolean next = "Spinner.nextButton".equals(button.getName());
                named(button, name + (next ? ".increase" : ".decrease"), label + (next ? " 늘리기" : " 줄이기"));
            }
        }
        return spinner;
    }

    private static BigDecimal seconds(long millis) { return BigDecimal.valueOf(millis, 3); }

    /** Bounded plain decimal grammar: no locale grouping, exponent, NaN, infinity or silent coercion. */
    private static BigDecimal decimal(String text) {
        if (text == null || text.isEmpty() || text.length() > MAX_NUMBER_CHARS) throw new NumberFormatException("INVALID_NUMBER");
        int digits = 0;
        boolean dot = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= '0' && c <= '9') digits++;
            else if (c == '.' && !dot) dot = true;
            else if (!(c == '-' && i == 0)) throw new NumberFormatException("INVALID_NUMBER");
        }
        if (digits == 0) throw new NumberFormatException("INVALID_NUMBER");
        return new BigDecimal(text);
    }

    private static JPanel grid(String name, String title) {
        JPanel panel = named(new JPanel(new GridBagLayout()), name, title);
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    private static void row(JPanel panel, int index, String caption, JComponent field) {
        JLabel label = named(new JLabel(caption), field.getName() + ".label", caption);
        label.putClientProperty("html.disable", Boolean.TRUE);
        label.setLabelFor(field);
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = index; c.anchor = GridBagConstraints.LINE_START; c.insets = new Insets(5, 5, 5, 12);
        panel.add(label, c);
        c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; c.insets = new Insets(5, 0, 5, 5);
        panel.add(field, c);
    }

    private static JTextArea wrapped(String name, String text) {
        JTextArea area = named(new JTextArea(text), name, text.isBlank() ? "설정 입력 안내" : text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        if (UIManager.getFont("Label.font") != null) area.setFont(UIManager.getFont("Label.font"));
        area.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        return area;
    }

    private static JScrollPane scroll(JComponent content, String name) {
        JScrollPane scroll = named(new JScrollPane(content), name, "설정 스크롤 영역");
        named(scroll.getVerticalScrollBar(), name + ".vertical", "설정 세로 스크롤");
        named(scroll.getHorizontalScrollBar(), name + ".horizontal", "설정 가로 스크롤");
        scroll.getVerticalScrollBar().setUnitIncrement(Math.max(16, content.getFontMetrics(content.getFont()).getHeight()));
        return scroll;
    }

    private static <T extends JComponent> T named(T component, String name, String label) {
        component.setName(name);
        component.getAccessibleContext().setAccessibleName(label);
        return component;
    }

    private static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("설정 폼은 UI 스레드에서만 사용할 수 있습니다.");
    }

    private static final class HostRow {
        private String host;
        private String rate;
        private boolean hostTooLong;
        private boolean rateTooLong;
        private HostRow(String host, String rate) { this.host = host; this.rate = rate; }
    }

    private final class HostModel extends AbstractTableModel {
        private final List<HostRow> rows = new ArrayList<>();
        private HostModel(Map<String, Integer> initial) {
            initial.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .forEach(e -> rows.add(new HostRow(e.getKey(), Integer.toString(e.getValue()))));
        }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int column) { return column == 0 ? "호스트 (주소만)" : "초당 요청 수 (RPS)"; }
        @Override public Class<?> getColumnClass(int column) { return String.class; }
        @Override public boolean isCellEditable(int row, int column) { return true; }
        @Override public Object getValueAt(int row, int column) { return column == 0 ? rows.get(row).host : rows.get(row).rate; }
        @Override public void setValueAt(Object value, int row, int column) {
            requireEdt();
            HostRow entry = rows.get(row);
            String text = value instanceof String s ? s : value instanceof Number n ? n.toString() : null;
            boolean tooLong = text == null || text.length() > (column == 0 ? MAX_HOST_CHARS : MAX_NUMBER_CHARS);
            if (column == 0) {
                entry.hostTooLong = tooLong;
                if (!tooLong) entry.host = text;
            } else {
                entry.rateTooLong = tooLong;
                if (!tooLong) entry.rate = text;
            }
            if (tooLong) validation.setText(LENGTH_ERROR);
            fireTableCellUpdated(row, column);
        }
        private void add() {
            if (rows.size() >= MAX_HOSTS) throw failure("호스트별 속도는 최대 256행입니다. 사용하지 않는 행을 삭제하세요.", true);
            rows.add(new HostRow("", "5"));
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }
        private void remove(int row) { rows.remove(row); fireTableRowsDeleted(row, row); }
    }

    private static final class ExactFormatter extends JFormattedTextField.AbstractFormatter {
        @Override public Object stringToValue(String text) throws ParseException {
            try { return decimal(text); }
            catch (RuntimeException e) { throw new ParseException("유효한 숫자를 입력하세요.", 0); }
        }
        @Override public String valueToString(Object value) {
            if (!(value instanceof Number)) return "";
            String text = value.toString();
            return text.length() <= MAX_NUMBER_CHARS ? text : "";
        }
    }

    /** Bounds stepping without the Double arithmetic or integer truncation in SpinnerNumberModel. */
    private static final class ExactModel extends AbstractSpinnerModel {
        private Number value;
        private final BigDecimal min;
        private final BigDecimal max;
        private final BigDecimal step;
        private ExactModel(Number value, BigDecimal min, BigDecimal max, BigDecimal step) {
            this.value = value; this.min = min; this.max = max; this.step = step;
        }
        @Override public Object getValue() { return value; }
        @Override public void setValue(Object next) {
            if (!(next instanceof Number number)) throw new IllegalArgumentException("숫자를 입력하세요.");
            if (!number.equals(value)) { value = number; fireStateChanged(); }
        }
        @Override public Object getNextValue() { return adjacent(step); }
        @Override public Object getPreviousValue() { return adjacent(step.negate()); }
        private Object adjacent(BigDecimal delta) {
            try {
                BigDecimal next = decimal(value.toString()).add(delta);
                return next.compareTo(min) >= 0 && next.compareTo(max) <= 0 ? next : null;
            } catch (RuntimeException e) { return null; }
        }
    }

    private static final class LengthFilter extends DocumentFilter {
        private final JTextField field;
        private final int max;
        private LengthFilter(JTextField field, int max) { this.field = field; this.max = max; }
        @Override public void insertString(FilterBypass fb, int offset, String text, AttributeSet attrs) throws BadLocationException {
            replace(fb, offset, 0, text, attrs);
        }
        @Override public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
            replace(fb, offset, length, "", null);
        }
        @Override public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
            if ((long) fb.getDocument().getLength() - length + (text == null ? 0 : text.length()) > max) {
                field.putClientProperty(TOO_LONG, Boolean.TRUE);
                field.setToolTipText(LENGTH_ERROR);
                return; // Reject, never truncate an input into a different valid value.
            }
            field.putClientProperty(TOO_LONG, Boolean.FALSE);
            field.setToolTipText(null);
            fb.replace(offset, length, text, attrs);
        }
    }

    private static final class LiteralRenderer extends DefaultTableCellRenderer {
        private LiteralRenderer() { putClientProperty("html.disable", Boolean.TRUE); }
    }

    private static final class ModeRenderer extends DefaultListCellRenderer {
        private ModeRenderer() { putClientProperty("html.disable", Boolean.TRUE); }
        @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focused) {
            super.getListCellRendererComponent(list, "", index, selected, focused);
            setText(value instanceof Mode mode ? switch (mode) {
                case ALLOW -> "허용 — 다른 차단 조건이 없을 때 전송";
                case BLOCK -> "차단 — 기본적으로 전송하지 않음";
                case ASK -> "승인 대기 — 사람이 확인한 뒤 전송";
                case MONITOR -> "기록 — 다른 차단 조건이 없을 때 전송";
            } : "기본 동작을 선택하세요.");
            return this;
        }
    }

    private static final class FormPanel extends JPanel implements Scrollable {
        @Override public Dimension getPreferredScrollableViewportSize() {
            Dimension preferred = getPreferredSize();
            return new Dimension(Math.min(900, preferred.width), Math.min(640, preferred.height));
        }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return getFontMetrics(getFont()).getHeight() + 6; }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return Math.max(1, visible.height - getFontMetrics(getFont()).getHeight()); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
