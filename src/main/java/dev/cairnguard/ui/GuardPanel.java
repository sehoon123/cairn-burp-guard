package dev.cairnguard.ui;

import com.fasterxml.jackson.databind.DeserializationFeature;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.policy.PolicyEngine;
import dev.cairnguard.runtime.ApprovalQueue.Pending;
import dev.cairnguard.ui.editor.EditorForm;
import dev.cairnguard.ui.editor.FormValidationException;
import dev.cairnguard.ui.editor.RuleEditor;
import dev.cairnguard.ui.editor.ScopeEditor;
import dev.cairnguard.ui.editor.SettingsEditor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import javax.swing.text.JTextComponent;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Task-oriented local human UI. No agent/network control surface; all policy writes are revision checked. */
@SuppressWarnings("serial") // Ephemeral Swing views are never serialized or persisted.
public final class GuardPanel extends JPanel implements AutoCloseable {
    private static final long serialVersionUID = 1L;
    static final int MAX_EDITOR_CHARS = 2_097_152;
    private static final int MAX_ROWS = 2_000;
    private static final String ALL_PROJECTS = "모든 프로젝트";
    private static final String EXPORT_NOTICE = "마스킹된 검사 사본만 표시·내보냅니다. 본문 생략·잘림·보관 만료가 있을 수 있으며, 완전한 통신 캡처나 대상 도착의 증명이 아닙니다.";
    private static final String SAVE_NOTICE = "저장하면 현재 Burp 프로젝트에 즉시 적용하며 기존 승인 대기를 취소합니다. 취소하면 바뀌지 않습니다.";

    private final GuardUiAccess access;
    private final Dialogs dialogs;
    private final Timer timer;
    private final JTabbedPane tabs = named(new JTabbedPane(), "tabs");
    private final JLabel message = named(new JLabel("현재 상태를 확인하고 있습니다…"), "message");
    private final JLabel version = named(new JLabel("프로젝트 확인 중"), "policy.version");
    private final JLabel stateTitle = named(new JLabel("보호 상태 확인 중"), "dashboard.state");
    private final JTextArea stateHelp = note("dashboard.guidance", "");
    private final JLabel scopeCount = named(new JLabel(), "dashboard.scopeCount");
    private final JLabel ruleCount = named(new JLabel(), "dashboard.ruleCount");
    private final JLabel gateCount = named(new JLabel(), "dashboard.gateCount");
    private final JLabel evidenceCount = named(new JLabel(), "dashboard.evidenceCount");
    private final JTextArea recentBlock = note("dashboard.recentBlock", "");
    private final JButton pause;
    private final JButton approve;
    private final JButton deny;
    private final JButton resolve;
    private final List<JButton> policyActions = new ArrayList<>();
    private final RowsModel<ScopeEntry> allowModel = scopeModel();
    private final RowsModel<ScopeEntry> blockModel = scopeModel();
    private final JTable allowTable = table("scope.allow.table", allowModel, false);
    private final JTable blockTable = table("scope.block.table", blockModel, false);
    private final JTextArea scopeState = note("scope.state", "");
    private final RowsModel<Rule> rulesModel = new RowsModel<>(new String[]{"사용", "규칙 이름", "동작", "조건"},
            new Class<?>[]{String.class, String.class, String.class, String.class},
            r -> new Object[]{r.enabled() ? "사용 중" : "중지", displayRuleName(r.name()), UiText.mode(r.mode().name()), RuleEditor.summary(r.condition())});
    private final JTable rulesTable = table("rules.table", rulesModel, false);
    private final JTextArea settingsSummary = textArea("settings.summary", false);
    private final RowsModel<TrafficEntry> trafficModel = new RowsModel<>(
            new String[]{"보관", "시각 (UTC)", "메서드", "마스킹된 URL", "결과", "HTTP", "이유"},
            new Class<?>[]{Boolean.class, String.class, String.class, String.class, String.class, Integer.class, String.class},
            e -> new Object[]{e.bookmarked(), e.timestamp(), e.method(), e.url(), UiText.outcome(e.disposition()), e.statusCode(), UiText.reason(e.reason())});
    private final JTable trafficTable = table("traffic.table", trafficModel, true);
    private final JTextField search = textField("traffic.search");
    private final JTextField methodFilter = textField("traffic.method");
    private final JTextField statusFilter = textField("traffic.status");
    private final JTextField timeFilter = textField("traffic.time");
    private final JComboBox<String> outcomeFilter = named(new JComboBox<>(new String[]{"모든 결과", "차단됨", "전송 해제", "대기 중"}), "traffic.outcome");
    private final JComboBox<String> projectFilter = named(new JComboBox<>(new String[]{ALL_PROJECTS}), "traffic.project");
    private final JCheckBox bookmarksOnly = named(new JCheckBox("보관한 요청만"), "traffic.bookmarked");
    private final JLabel trafficCount = named(new JLabel("기록 없음"), "traffic.count");
    private final JComboBox<String> exportRange = named(new JComboBox<>(new String[]{"현재 표의 요청", "선택한 요청만"}), "traffic.exportRange");
    private final JComboBox<String> exportFormat = named(new JComboBox<>(new String[]{"JSON", "HAR"}), "traffic.exportFormat");
    private final JTextArea requestDetail = textArea("traffic.request", false);
    private final JTextArea responseDetail = textArea("traffic.response", false);
    private final JTextArea trafficDetail = textArea("traffic.metadata", false);
    private JTabbedPane trafficDetails;
    private final RowsModel<Pending> approvalModel = new RowsModel<>(
            new String[]{"메서드", "마스킹된 URL", "승인 요청 이유", "남은 시간"},
            new Class<?>[]{String.class, String.class, String.class, String.class}, this::approvalValues);
    private final JTable approvalTable = table("approval.table", approvalModel, false);
    private final JTextArea approvalDetail = textArea("approval.detail", false);
    private List<TrafficEntry> traffic = List.of();
    private Snapshot view;
    private Map<String, Object> latestStatus = Map.of();
    private boolean available;
    private boolean loading;
    private int selectionUpdates;
    private boolean closed;
    private SwingWorker<Void, Void> exportWorker;

    public GuardPanel(GuardUiAccess access) { this(access, new SwingDialogs(), true); }

    // Tests substitute human dialogs only, never an agent-facing API.
    GuardPanel(GuardUiAccess access, Dialogs dialogs, boolean startTimer) {
        requireEdt();
        this.access = Objects.requireNonNull(access);
        this.dialogs = Objects.requireNonNull(dialogs);
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        pause = button("dashboard.pause", "일시중지", this::togglePause);
        approve = button("approval.approve", "한 번만 승인", () -> decide(true));
        deny = button("approval.deny", "거절", () -> decide(false));
        resolve = button("traffic.resolve", "관련 설정 열기", this::resolveSelected);
        JPanel header = new JPanel(new BorderLayout(8, 0));
        header.add(version, BorderLayout.CENTER);
        header.add(buttons(button("policy.refresh", "새로고침", () -> {
            refreshNow();
            if (available) message.setText("현재 프로젝트의 설정과 요청 기록을 다시 확인했습니다.");
        })), BorderLayout.LINE_END);
        add(header, BorderLayout.NORTH);
        tabs.addTab("개요", dashboardTab());
        tabs.addTab("대상", scopeTab());
        tabs.addTab("규칙", rulesTab());
        tabs.addTab("요청 기록", trafficTab());
        tabs.addTab("승인 대기", approvalTab());
        tabs.addTab("설정", settingsTab());
        add(tabs, BorderLayout.CENTER);
        message.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        add(message, BorderLayout.SOUTH);
        timer = new Timer(1_000, e -> refreshNow());
        timer.setCoalesce(true);
        refreshNow();
        if (startTimer) timer.start();
    }

    private JPanel dashboardTab() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.PAGE_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        stateTitle.setFont(stateTitle.getFont().deriveFont(java.awt.Font.BOLD, stateTitle.getFont().getSize2D() + 5));
        JPanel hero = new JPanel(new BorderLayout(6, 6));
        hero.setBorder(BorderFactory.createEmptyBorder(10, 10, 6, 10));
        hero.add(stateTitle, BorderLayout.NORTH);
        hero.add(stateHelp, BorderLayout.CENTER);
        hero.add(buttons(policyButton("dashboard.addTarget", "허용 대상 등록…", () -> editScope(false, true)), pause,
                button("dashboard.approvals", "승인 대기 보기", () -> tabs.setSelectedIndex(4))), BorderLayout.SOUTH);
        JPanel counts = new JPanel(new GridLayout(2, 2, 12, 8));
        counts.setBorder(BorderFactory.createTitledBorder("현재 상태"));
        for (JLabel label : List.of(scopeCount, ruleCount, gateCount, evidenceCount)) counts.add(label);
        counts.setMaximumSize(new Dimension(Integer.MAX_VALUE, 160));
        content.add(counts);
        content.add(Box.createVerticalStrut(12));
        content.add(note("dashboard.steps", "처음 사용하나요?\n1. ‘허용 대상 등록’에서 허가받은 URL과 실제 범위를 확인하고 저장하세요.\n2. 기본 차단 규칙을 ‘규칙’에서 확인하세요. 필요하면 조건과 승인 요청 규칙을 추가하세요.\n3. 이 Burp Proxy를 통해 요청을 보내고 ‘요청 기록’에서 결과와 차단 이유를 확인하세요."));
        content.add(buttons(button("dashboard.scope", "대상 확인", () -> tabs.setSelectedIndex(1)),
                button("dashboard.rules", "규칙 확인", () -> tabs.setSelectedIndex(2)),
                button("dashboard.traffic", "요청 기록 보기", () -> tabs.setSelectedIndex(3))));
        recentBlock.setBorder(BorderFactory.createTitledBorder("최근 차단 이유"));
        content.add(recentBlock);
        content.add(Box.createVerticalStrut(10));
        content.add(note("dashboard.boundary", "이 확장은 Burp Proxy에 전달된 요청만 제어합니다. 직접 연결·Proxy 우회·다른 Burp 도구의 트래픽까지 막는 네트워크 방화벽이 아닙니다. 허용한 원본 요청·응답·인증 상태를 변경하지 않습니다."));
        JPanel result = new JPanel(new BorderLayout());
        result.add(hero, BorderLayout.NORTH);
        result.add(new JScrollPane(content), BorderLayout.CENTER);
        return result;
    }

    private JPanel scopeTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(scopeState, BorderLayout.NORTH);
        JTabbedPane lists = named(new JTabbedPane(), "scope.lists");
        lists.addTab("허용 대상", scopeList(false));
        lists.addTab("차단 대상", scopeList(true));
        panel.add(lists, BorderLayout.CENTER);
        panel.add(note("scope.help", "허용 대상은 실제 호스트·연결 방식·포트·경로가 모두 맞아야 합니다. 차단 대상이 우선하며, 하위 도메인이나 모든 포트는 직접 선택해야 포함됩니다. 표의 변경은 각 작업에서 명시적으로 저장할 때만 적용됩니다."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel scopeList(boolean blocked) {
        String prefix = blocked ? "scope.block" : "scope.allow";
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(buttons(policyButton(prefix + ".add", blocked ? "차단 대상 추가…" : "허용 대상 추가…", () -> editScope(blocked, true)),
                policyButton(prefix + ".edit", "선택 항목 편집…", () -> editScope(blocked, false)),
                policyButton(prefix + ".toggle", "사용 / 중지", () -> mutateScope(blocked, false)),
                policyButton(prefix + ".delete", "삭제…", () -> mutateScope(blocked, true))), BorderLayout.NORTH);
        panel.add(new JScrollPane(blocked ? blockTable : allowTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel rulesTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        JPanel header = new JPanel(new BorderLayout());
        header.add(note("rules.help", "조건에 맞는 요청을 차단하거나 사람의 승인을 받습니다. 차단 > 승인 요청 > 허용 순서이며, ‘기록만’은 다른 동작을 바꾸지 않습니다. 허용 규칙도 대상 범위와 필수 안전 검사를 우회하지 못합니다."), BorderLayout.NORTH);
        header.add(buttons(policyButton("rules.add", "규칙 만들기…", () -> editRule(true)),
                policyButton("rules.edit", "선택 규칙 편집…", () -> editRule(false)),
                policyButton("rules.toggle", "사용 / 중지", () -> mutateRule(false)),
                policyButton("rules.delete", "삭제…", () -> mutateRule(true))), BorderLayout.SOUTH);
        panel.add(header, BorderLayout.NORTH);
        panel.add(new JScrollPane(rulesTable), BorderLayout.CENTER);
        panel.add(note("rules.defaults", "기본 규칙: DELETE 메서드와 대소문자 구분 없는 ‘delete’ 문자열을 차단합니다. 보수적인 문자열 규칙은 정상 요청에도 일치할 수 있습니다. 이름을 바꾸거나 사용 여부를 조정하기 전에 조건을 확인하세요."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel settingsTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(buttons(policyButton("settings.edit", "요청 제어 설정 변경…", this::editSettings)), BorderLayout.NORTH);
        panel.add(new JScrollPane(settingsSummary), BorderLayout.CENTER);
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(note("settings.help", "속도·동시성과 대기 시간을 설정합니다. 로그인·쿠키/토큰 주입·세션 갱신은 제공하지 않습니다. 일반 작업에는 JSON 편집이 필요하지 않습니다."), BorderLayout.NORTH);
        footer.add(buttons(policyButton("settings.policyJson", "고급: 정책 JSON 가져오기 / 복사…", this::editPolicyJson),
                button("settings.diagnostics", "진단 정보…", this::diagnostics),
                button("settings.clear", "보관 기록 비우기…", () -> {
                    if (dialogs.confirm(this, "보관된 마스킹 요청 기록을 모두 지울까요? 누적 처리 수는 남을 수 있으며 복구할 수 없습니다.")) {
                        access.clearEvidence(); refreshNow(); message.setText("보관된 마스킹 기록을 비웠습니다.");
                    }
                })), BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel trafficTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        JPanel header = new JPanel(new BorderLayout(4, 4));
        JPanel quick = new JPanel(new BorderLayout(8, 0));
        quick.add(labeled("마스킹된 URL·이유·메서드 검색", search), BorderLayout.CENTER);
        quick.add(buttons(outcomeFilter, bookmarksOnly, button("traffic.reset", "필터 지우기", this::resetFilters)), BorderLayout.LINE_END);
        header.add(quick, BorderLayout.NORTH);
        JPanel extra = new JPanel(new GridLayout(1, 4, 6, 4));
        extra.add(labeled("메서드 포함", methodFilter));
        extra.add(labeled("HTTP 상태 포함", statusFilter));
        extra.add(labeled("UTC 시각 포함", timeFilter));
        extra.add(labeled("프로젝트", projectFilter));
        extra.setVisible(false);
        JCheckBox more = named(new JCheckBox("상세 필터"), "traffic.more");
        more.addActionListener(e -> { extra.setVisible(more.isSelected()); header.revalidate(); });
        JPanel filterBottom = new JPanel(new BorderLayout());
        filterBottom.add(extra, BorderLayout.NORTH);
        filterBottom.add(buttons(more, trafficCount, button("traffic.detail", "선택 요청 상세…", this::openTrafficDetail),
                button("traffic.bookmark", "선택 요청 보관 / 해제", this::bookmarkSelected)), BorderLayout.SOUTH);
        header.add(filterBottom, BorderLayout.CENTER);
        panel.add(header, BorderLayout.NORTH);
        for (JTextField filter : List.of(search, methodFilter, statusFilter, timeFilter)) listen(filter, this::filterTraffic);
        DefaultListCellRenderer plain = new DefaultListCellRenderer();
        plain.putClientProperty("html.disable", Boolean.TRUE);
        projectFilter.setRenderer(plain);
        projectFilter.addActionListener(e -> { if (!loading) filterTraffic(); });
        outcomeFilter.addActionListener(e -> filterTraffic());
        bookmarksOnly.addItemListener(e -> filterTraffic());
        trafficTable.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting() && selectionUpdates == 0) showTrafficDetail(); });
        JTabbedPane details = named(new JTabbedPane(), "traffic.details");
        trafficDetails = details;
        JPanel explanation = new JPanel(new BorderLayout());
        explanation.add(new JScrollPane(trafficDetail), BorderLayout.CENTER);
        explanation.add(buttons(resolve), BorderLayout.SOUTH);
        details.addTab("결과와 해결 방법", explanation);
        details.addTab("마스킹된 요청 · 읽기 전용", new JScrollPane(requestDetail));
        details.addTab("마스킹된 응답 · 읽기 전용", new JScrollPane(responseDetail));
        panel.add(new JScrollPane(trafficTable), BorderLayout.CENTER);
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(buttons(exportRange, exportFormat, button("traffic.export", "내보내기…",
                () -> chooseExport(exportRange.getSelectedIndex() == 1, exportFormat.getSelectedIndex() == 1))), BorderLayout.NORTH);
        footer.add(note("traffic.exportNotice", EXPORT_NOTICE), BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel approvalTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(note("approval.help", "승인 요청 규칙에 걸린 요청만 한 번 승인할 수 있습니다. 메서드·주소·이유·마스킹된 요청을 먼저 확인하세요. 만료·설정 변경·프로젝트 변경·일시중지는 대기를 취소합니다. 필수 안전 차단은 여기에서 승인할 수 없습니다."), BorderLayout.NORTH);
        approvalTable.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting() && selectionUpdates == 0) showApprovalDetail(); });
        panel.add(new JScrollPane(approvalTable), BorderLayout.CENTER);
        panel.add(buttons(button("approval.review", "선택 요청 검토…", () -> {
            if (selected(approvalTable, approvalModel) == null) throw failure("SELECT_PENDING_APPROVAL_FIRST");
            showReadOnly("승인 요청 검토 · 마스킹된 증거", new JScrollPane(approvalDetail));
        }), approve, deny), BorderLayout.SOUTH);
        return panel;
    }

    private void editScope(boolean blocked, boolean add) {
        Snapshot base = beginEdit();
        RowsModel<ScopeEntry> model = blocked ? blockModel : allowModel;
        JTable table = blocked ? blockTable : allowTable;
        int index = add ? -1 : modelIndex(table, table.getSelectedRow(), model.rows.size());
        if (!add && index < 0) throw failure("SELECT_SCOPE_FIRST");
        List<ScopeEntry> original = blocked ? base.policy().blockScope() : base.policy().allowScope();
        if (add && original.size() >= 256) throw failure("POLICY_ROW_LIMIT");
        ScopeEditor form = new ScopeEditor(add ? null : original.get(index));
        dialogs.edit(this, (blocked ? "차단 대상" : "허용 대상") + (add ? " 추가" : " 편집"), "저장하고 적용", form, () -> {
            ScopeEntry entry = form.value();
            List<ScopeEntry> rows = new ArrayList<>(original);
            if (add) rows.add(entry); else rows.set(index, entry);
            GuardConfig old = base.policy();
            save(base, new GuardConfig(old.schemaVersion(), blocked ? old.allowScope() : rows,
                    blocked ? rows : old.blockScope(), old.rules(), old.defaultMode(), old.limits()));
        });
    }

    private void mutateScope(boolean blocked, boolean delete) {
        Snapshot base = beginEdit();
        RowsModel<ScopeEntry> model = blocked ? blockModel : allowModel;
        JTable table = blocked ? blockTable : allowTable;
        int index = modelIndex(table, table.getSelectedRow(), model.rows.size());
        if (index < 0) throw failure("SELECT_SCOPE_FIRST");
        GuardConfig old = base.policy();
        List<ScopeEntry> rows = new ArrayList<>(blocked ? old.blockScope() : old.allowScope());
        ScopeEntry entry = rows.get(index);
        if (delete) rows.remove(index);
        else rows.set(index, new ScopeEntry(!entry.enabled(), entry.host(), entry.scheme(), entry.port(), entry.pathRegex()));
        String warning = !blocked && rows.stream().noneMatch(ScopeEntry::enabled)
                ? "\n사용 중인 허용 대상이 없어 모든 새 Proxy 요청을 차단하게 됩니다." : "";
        if (!dialogs.confirm(this, (delete ? "선택한 대상을 삭제할까요?" : entry.enabled() ? "선택한 대상의 사용을 중지할까요?" : "선택한 대상을 사용할까요?")
                + warning + "\n" + SAVE_NOTICE)) return;
        save(base, new GuardConfig(old.schemaVersion(), blocked ? old.allowScope() : rows,
                blocked ? rows : old.blockScope(), old.rules(), old.defaultMode(), old.limits()));
    }

    private void editRule(boolean add) {
        Snapshot base = beginEdit();
        Rule selected = selected(rulesTable, rulesModel);
        if (!add && selected == null) throw failure("SELECT_RULE_FIRST");
        if (add && base.policy().rules().size() >= 256) throw failure("POLICY_ROW_LIMIT");
        RuleEditor form = new RuleEditor(add ? null : selected);
        dialogs.edit(this, add ? "규칙 만들기" : "규칙 편집", "저장하고 적용", form, () -> {
            Rule value = form.value();
            List<Rule> rows = new ArrayList<>(base.policy().rules());
            if (add) rows.add(value); else rows.set(rows.indexOf(selected), value);
            save(base, withRules(base.policy(), rows));
        });
    }

    private void mutateRule(boolean delete) {
        Snapshot base = beginEdit();
        Rule selected = selected(rulesTable, rulesModel);
        if (selected == null) throw failure("SELECT_RULE_FIRST");
        if (!dialogs.confirm(this, (delete ? "선택한 규칙을 삭제할까요?" : selected.enabled() ? "선택한 규칙을 중지할까요?" : "선택한 규칙을 사용할까요?")
                + "\n차단 규칙을 중지·삭제하면 해당 요청이 허용될 수 있습니다.\n" + SAVE_NOTICE)) return;
        List<Rule> rows = new ArrayList<>(base.policy().rules());
        int index = rows.indexOf(selected);
        if (delete) rows.remove(index);
        else rows.set(index, new Rule(selected.id(), selected.name(), !selected.enabled(), selected.mode(), selected.condition()));
        save(base, withRules(base.policy(), rows));
    }

    private static GuardConfig withRules(GuardConfig old, List<Rule> rows) {
        return new GuardConfig(old.schemaVersion(), old.allowScope(), old.blockScope(), rows, old.defaultMode(), old.limits());
    }

    private void editSettings() {
        Snapshot base = beginEdit();
        SettingsEditor form = new SettingsEditor(base.policy());
        dialogs.edit(this, "요청 제어 설정", "저장하고 적용", form, () -> {
            SettingsEditor.Value value = form.value();
            GuardConfig old = base.policy();
            save(base, new GuardConfig(old.schemaVersion(), old.allowScope(), old.blockScope(), old.rules(), value.defaultMode(), value.limits()));
        });
    }

    private void editPolicyJson() {
        Snapshot base = beginEdit();
        JTextArea editor = textArea("advanced.policyJson", true);
        editor.setText(boundedJson(base.policy()));
        editor.putClientProperty("inputRejected", Boolean.FALSE);
        ((AbstractDocument) editor.getDocument()).setDocumentFilter(new LengthLimit(MAX_EDITOR_CHARS,
                () -> editor.putClientProperty("inputRejected", Boolean.TRUE)));
        listen(editor, () -> editor.putClientProperty("inputRejected", Boolean.FALSE));
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(note("advanced.policyNotice", "고급 사용자를 위한 전체 정책입니다. JSON을 붙여넣거나 복사할 수 있습니다. 저장 시 대상·규칙·설정 전체를 교체합니다. 비밀 값이나 실제 인증 정보를 넣지 마세요. 일반 편집에는 이 화면이 필요하지 않습니다."), BorderLayout.NORTH);
        panel.add(new JScrollPane(editor), BorderLayout.CENTER);
        EditorForm<GuardConfig> form = new EditorForm<>() {
            @Override public JComponent component() { return panel; }
            @Override public GuardConfig value() {
                if (Boolean.TRUE.equals(editor.getClientProperty("inputRejected")))
                    throw new FormValidationException("정책 입력은 최대 2 MiB 문자입니다. 너무 긴 입력을 반영하지 않았습니다. 입력을 줄여 다시 붙여넣으세요.");
                GuardConfig value = parsePolicy(editor.getText());
                try { new PolicyEngine().validate(value); }
                catch (RuntimeException e) { throw failure("INVALID_POLICY"); }
                return value;
            }
        };
        dialogs.edit(this, "고급 · 전체 정책 JSON", "전체 정책 저장", form, () -> save(base, form.value()));
    }

    private void diagnostics() {
        JTextArea detail = textArea("diagnostics.status", false);
        detail.setText(boundedText(Json.write(latestStatus)));
        showReadOnly("진단 정보 · 읽기 전용", new JScrollPane(detail));
    }

    private void openTrafficDetail() {
        if (selected(trafficTable, trafficModel) == null) throw failure("SELECT_TRAFFIC_FIRST");
        showTrafficDetail();
        showReadOnly("요청 상세 · 마스킹된 증거", trafficDetails);
    }

    private void showReadOnly(String title, JComponent component) {
        EditorForm<Void> form = new EditorForm<>() {
            @Override public JComponent component() { return component; }
            @Override public Void value() { return null; }
        };
        dialogs.edit(this, title, "닫기", form, () -> {});
    }

    private Snapshot beginEdit() {
        if (closed) throw failure("CLOSED");
        if (!available || view == null) throw failure("PROJECT_UNAVAILABLE");
        Snapshot base = view; // The visible table's version, not a newly fetched project's baseline.
        access.refreshProject();
        Map<String, Object> current = access.status();
        if (!base.matches(current) || Boolean.TRUE.equals(current.get("closed"))) {
            refreshNow(); throw failure("STALE_POLICY");
        }
        return base;
    }

    private void save(Snapshot base, GuardConfig candidate) {
        requireEdt();
        if (closed) throw failure("CLOSED");
        access.refreshProject();
        Map<String, Object> current = access.status();
        if (!base.matches(current) || Boolean.TRUE.equals(current.get("closed"))) {
            refreshNow(); throw failure("STALE_POLICY");
        }
        try { new PolicyEngine().validate(candidate); }
        catch (RuntimeException e) { throw failure("INVALID_POLICY"); }
        boundedJson(candidate); // A saved policy must fit the strict project-load limit as a whole.
        if (candidate.equals(base.policy())) {
            message.setText("변경한 내용이 없어 기존 설정을 유지했습니다.");
            return;
        }
        try { access.updateConfig(candidate, base.projectId(), base.revision()); }
        catch (IllegalStateException e) { refreshNow(); throw failure("UPDATE_REJECTED"); }
        catch (IllegalArgumentException e) { throw failure("INVALID_POLICY"); }
        refreshNow();
        message.setText("설정을 저장했습니다. 현재 프로젝트에 적용했으며 이전 승인 대기는 취소됩니다.");
    }

    private void togglePause() {
        Snapshot base = beginEdit();
        boolean next = !Boolean.TRUE.equals(latestStatus.get("paused"));
        if (!next && view != null && view.policy().allowScope().stream().noneMatch(ScopeEntry::enabled)
                && !dialogs.confirm(this, "보호를 재개해도 허용 대상이 없어 모든 요청을 계속 차단합니다. 먼저 대상을 등록하는 것이 좋습니다. 그래도 재개할까요?")) return;
        access.refreshProject();
        if (!base.matches(access.status())) { refreshNow(); throw failure("STALE_POLICY"); }
        try { access.pause(next); }
        finally { refreshNow(); } // Failed resume must not leave a misleading toggled control.
        message.setText(next ? "일시중지했습니다. 모든 새 Proxy 요청을 차단합니다." : "보호를 재개했습니다. 대상 범위와 안전 검사는 계속 적용됩니다.");
    }

    /** EDT-only nonblocking refresh. An open modal retains its own original Snapshot. */
    void refreshNow() {
        requireEdt();
        if (closed) return;
        try {
            access.refreshProject();
            Map<String, Object> before = access.status();
            GuardConfig config = access.config();
            Map<String, Object> after = access.status();
            if (!sameVersion(before, after) || Boolean.TRUE.equals(after.get("closed"))) throw failure("PROJECT_UNAVAILABLE");
            if (view == null || !view.policy().equals(config)) new PolicyEngine().validate(config);
            view = new Snapshot(config, projectId(after), revision(after));
            latestStatus = Map.copyOf(after);
            available = true;
            allowModel.setRows(config.allowScope()); blockModel.setRows(config.blockScope());
            replaceRows(rulesTable, rulesModel, config.rules(), Rule::id);
            traffic = List.copyOf(access.traffic().stream().limit(MAX_ROWS).toList());
            updateProjects(); filterTraffic();
            replaceRows(approvalTable, approvalModel, access.approvals().stream().limit(100).toList(), Pending::id);
            approvalTable.repaint(); // Remaining time changes without mutating pending records.
            showApprovalDetail();
            updateOverview(config, after);
            updateSettings(config);
            version.setText("현재 Burp 프로젝트 · 설정 버전 " + view.revision() + " · 변경은 각 창에서 저장");
            for (JButton action : policyActions) action.setEnabled(true);
            pause.setEnabled(true);
            if (message.getText().equals("현재 상태를 확인하고 있습니다…")) message.setText("준비됐습니다. 허가받은 대상을 등록하고 보호 상태를 확인하세요.");
        } catch (RuntimeException e) {
            available = false;
            for (JButton action : policyActions) action.setEnabled(false);
            pause.setEnabled(false); approve.setEnabled(false); deny.setEnabled(false);
            version.setText("현재 프로젝트 확인 필요 · 설정 변경과 승인 불가");
            stateTitle.setText("보호 상태를 확인할 수 없습니다");
            stateHelp.setText(UiText.error("REFRESH_UNAVAILABLE"));
            message.setText("현재 상태 확인 실패 · 프로젝트를 확인하고 새로고침하세요.");
        }
    }

    private void updateOverview(GuardConfig config, Map<String, Object> status) {
        long allowed = config.allowScope().stream().filter(ScopeEntry::enabled).count();
        long blocked = config.blockScope().stream().filter(ScopeEntry::enabled).count();
        long rules = config.rules().stream().filter(Rule::enabled).count();
        Map<?, ?> gate = nested(status, "gate");
        Map<?, ?> evidence = nested(status, "evidence");
        boolean paused = Boolean.TRUE.equals(status.get("paused"));
        String note = Objects.toString(status.get("note"), "");
        if (note.equals("PROJECT_UNAVAILABLE") || note.equals("PROJECT_POLICY_INVALID_DEFAULT_DENY_PAUSED")
                || note.equals("POLICY_SAVE_UNCERTAIN_RELOAD_BEFORE_CONTINUING") || note.equals("PROJECT_CHANGED_DURING_SAVE")) {
            stateTitle.setText("프로젝트 설정 확인 필요 · 새 요청 차단");
            stateHelp.setText("프로젝트 설정을 읽거나 저장한 결과를 확인할 수 없습니다. 요청 발생을 멈추고 Burp 프로젝트를 확인한 뒤 새로고침하세요. 확인 전에는 재개하지 마세요.");
        } else if (count(gate, "stalled") > 0) {
            stateTitle.setText("응답 확인 필요 · 새 요청 차단");
            stateHelp.setText(UiText.next("IN_FLIGHT_TIMEOUT"));
        } else if (paused) {
            stateTitle.setText("일시중지 · 모든 새 요청 차단");
            stateHelp.setText("보호가 일시중지 상태입니다. 요청을 통과시키는 OFF 모드가 아닙니다. 대상과 규칙을 확인한 뒤 ‘보호 재개’를 누르세요.");
        } else if (allowed == 0) {
            stateTitle.setText("허용 대상 없음 · 모든 요청 차단");
            stateHelp.setText("아직 요청을 보낼 수 없습니다. ‘허용 대상 등록’에서 허가받은 URL을 입력하고 호스트·포트·경로를 확인하세요. 등록하지 않은 대상은 계속 차단합니다.");
        } else {
            stateTitle.setText("보호 중 · 등록한 대상만 검사 후 전송");
            stateHelp.setText("허용 대상 " + allowed + "개와 사용 중인 규칙 " + rules + "개를 적용합니다. 승인 요청은 ‘승인 대기’, 차단 이유는 ‘요청 기록’에서 확인하세요.");
        }
        pause.setText(paused ? "보호 재개" : "모든 새 요청 일시중지");
        scopeCount.setText("대상 · 허용 " + allowed + "개 / 차단 " + blocked + "개");
        ruleCount.setText("규칙 · " + rules + "개 사용 중");
        gateCount.setText("요청 · 진행 " + count(gate, "active") + " / 전송 대기 " + count(gate, "queued") + " / 승인 대기 " + approvalModel.rows.size());
        evidenceCount.setText("누적 · 차단 " + count(evidence, "blocked") + " / 전송 해제 " + count(evidence, "forwarded") + " / 보관 " + traffic.size());
        tabs.setTitleAt(4, "승인 대기" + (approvalModel.rows.isEmpty() ? "" : " (" + approvalModel.rows.size() + ")"));
        scopeState.setText(allowed == 0 ? "사용 중인 허용 대상이 없습니다. 모든 Proxy 요청을 차단합니다. ‘허용 대상 추가’로 시작하세요."
                : "허용 대상 " + allowed + "개 · 차단 대상 " + blocked + "개 사용 중. 차단 대상과 필수 안전 검사가 항상 우선합니다.");
        TrafficEntry latest = traffic.stream().filter(e -> e.projectId().equals(view.projectId()) && "BLOCKED".equals(e.disposition())).findFirst().orElse(null);
        recentBlock.setText(latest == null ? "현재 프로젝트의 보관 기록에 차단된 요청이 없습니다. 요청 결과는 ‘요청 기록’에서 확인하세요."
                : UiText.reason(latest.reason()) + "\n" + UiText.next(latest.reason()));
    }

    private void updateSettings(GuardConfig config) {
        GuardConfig.Limits l = config.limits();
        String summary = "요청 속도와 동시 실행\n\n전체 초당 요청 수: " + l.globalRps()
                + "\n기본 호스트당 초당 요청 수: " + l.perHostRps() + "\n최대 동시 요청 수: " + l.maxConcurrent()
                + "\n\n대기와 기본 동작\n\n전송 대기열 크기: " + l.maxQueued()
                + "\n전송 대기 제한: " + seconds(l.queueTimeoutMillis()) + "초"
                + "\n승인 대기 제한: " + seconds(l.approvalTimeoutMillis()) + "초"
                + "\n응답 대기 제한: " + seconds(l.requestTimeoutMillis()) + "초"
                + "\n일치하는 규칙이 없을 때: " + UiText.mode(config.defaultMode().name())
                + "\n호스트별 속도 예외: " + l.hostRps().size() + "개"
                + "\n\n기본 동작은 허용 대상 범위 안에서만 적용합니다.\n응답을 확인하지 못하면 새 요청을 막으며 진행 중 요청의 자리를 임의로 비우지 않습니다.\n\n‘요청 제어 설정 변경’에서 읽기 쉬운 폼으로 수정할 수 있습니다.";
        setDetail(settingsSummary, summary);
    }

    private static String seconds(long millis) { return java.math.BigDecimal.valueOf(millis, 3).stripTrailingZeros().toPlainString(); }
    private static Map<?, ?> nested(Map<String, Object> status, String key) { return status.get(key) instanceof Map<?, ?> map ? map : Map.of(); }
    private static long count(Map<?, ?> map, String key) { return map.get(key) instanceof Number n ? Math.max(0, n.longValue()) : 0; }

    private void updateProjects() {
        String selection = (String) projectFilter.getSelectedItem();
        Set<String> ids = new LinkedHashSet<>(); ids.add(ALL_PROJECTS);
        for (TrafficEntry entry : traffic) ids.add(entry.projectId());
        if (selection != null) ids.add(selection); // Eviction must never silently broaden the filter.
        loading = true;
        try {
            projectFilter.removeAllItems();
            for (String id : ids) projectFilter.addItem(id);
            projectFilter.setSelectedItem(selection == null ? ALL_PROJECTS : selection);
        } finally { loading = false; }
    }

    private void resetFilters() {
        search.setText(""); methodFilter.setText(""); statusFilter.setText(""); timeFilter.setText("");
        projectFilter.setSelectedItem(ALL_PROJECTS); outcomeFilter.setSelectedIndex(0); bookmarksOnly.setSelected(false);
        filterTraffic();
    }

    private void filterTraffic() {
        if (closed || loading) return;
        String project = (String) projectFilter.getSelectedItem();
        String outcome = switch (outcomeFilter.getSelectedIndex()) { case 1 -> "BLOCKED"; case 2 -> "FORWARDED"; case 3 -> "PENDING"; default -> ""; };
        List<TrafficEntry> displayed = new ArrayList<>();
        for (TrafficEntry entry : traffic) {
            String status = entry.statusCode() == null ? "" : entry.statusCode().toString();
            if (bookmarksOnly.isSelected() && !entry.bookmarked()
                    || project != null && !project.equals(ALL_PROJECTS) && !project.equals(entry.projectId())
                    || !outcome.isEmpty() && !(outcome.equals("PENDING") ? isWaiting(entry.disposition()) : outcome.equals(entry.disposition()))
                    || !contains(entry.method(), methodFilter.getText()) || !contains(status, statusFilter.getText())
                    || !contains(entry.timestamp(), timeFilter.getText())) continue;
            String needle = search.getText();
            if (!needle.isEmpty() && !(contains(entry.url(), needle) || contains(entry.method(), needle) || contains(entry.timestamp(), needle)
                    || contains(status, needle) || contains(entry.reason(), needle) || contains(UiText.reason(entry.reason()), needle) || contains(entry.id(), needle))) continue;
            displayed.add(entry);
        }
        replaceRows(trafficTable, trafficModel, displayed, TrafficEntry::id);
        boolean filtered = !search.getText().isEmpty() || !methodFilter.getText().isEmpty() || !statusFilter.getText().isEmpty()
                || !timeFilter.getText().isEmpty() || !ALL_PROJECTS.equals(project) || !outcome.isEmpty() || bookmarksOnly.isSelected();
        trafficCount.setText(displayed.size() + "개 표시 / " + traffic.size() + "개 보관" + (filtered ? " · 필터 적용 중" : ""));
        showTrafficDetail();
    }

    private static boolean isWaiting(String disposition) { return Set.of("PENDING", "AWAITING_APPROVAL", "QUEUED").contains(disposition); }
    private static boolean contains(String text, String literal) { return text != null && text.toLowerCase(Locale.ROOT).contains(literal.toLowerCase(Locale.ROOT)); }
    private List<TrafficEntry> selectedTraffic() {
        List<TrafficEntry> result = new ArrayList<>();
        for (int view : trafficTable.getSelectedRows()) {
            int model = modelIndex(trafficTable, view, trafficModel.rows.size());
            if (model >= 0) result.add(trafficModel.rows.get(model));
        }
        return List.copyOf(result);
    }

    private void showTrafficDetail() {
        TrafficEntry entry = selected(trafficTable, trafficModel);
        setDetail(trafficDetail, entry == null ? "요청을 선택하면 결과·이유·다음 행동을 볼 수 있습니다." : boundedText(metadata(entry)));
        setDetail(requestDetail, entry == null ? "" : boundedText(entry.request()));
        setDetail(responseDetail, entry == null ? "" : boundedText(entry.response()));
        resolve.setEnabled(entry != null && targetTab(entry.reason()) >= 0);
    }

    private static void setDetail(JTextArea area, String text) {
        if (!area.getText().equals(text)) { area.setText(text); area.setCaretPosition(0); }
    }

    private static String metadata(TrafficEntry entry) {
        StringBuilder result = new StringBuilder(entry.method()).append(" ").append(entry.url()).append("\n\n")
                .append(UiText.outcome(entry.disposition())).append(" · ").append(UiText.reason(entry.reason()))
                .append("\n\n다음 행동\n").append(UiText.next(entry.reason())).append("\n\n일치 규칙\n");
        if (entry.hits().isEmpty()) result.append("해당 없음 (대상 범위 또는 필수 검사에서 먼저 차단될 수 있습니다.)\n");
        for (var hit : entry.hits()) result.append("• ").append(hit.name()).append(" — ").append(UiText.mode(hit.mode().name())).append("\n");
        return result.append("\n").append(EXPORT_NOTICE).append("\n\n상세 진단\n증거 ID: ").append(entry.id())
                .append("\n프로젝트: ").append(entry.projectId()).append("\n시각 (UTC): ").append(entry.timestamp())
                .append("\n정책 동작: ").append(UiText.mode(entry.mode())).append("\n진단 코드: ").append(entry.reason())
                .append("\nHTTP 상태: ").append(entry.statusCode() == null ? "없음" : entry.statusCode())
                .append("\n정책 버전: ").append(entry.revision()).append("\n내용 잘림: ").append(entry.truncated() ? "있음" : "없음")
                .append("\n요청 본문 생략: ").append(entry.requestCapture().bodyOmitted() ? "예" : "아니오")
                .append("\n응답 본문 생략: ").append(entry.responseCapture().bodyOmitted() ? "예" : "아니오").toString();
    }

    private void resolveSelected() {
        TrafficEntry entry = selected(trafficTable, trafficModel);
        if (entry == null) throw failure("SELECT_TRAFFIC_FIRST");
        int target = targetTab(entry.reason());
        if (target >= 0) {
            tabs.setSelectedIndex(target);
            if (target == 1) ((JTabbedPane) findNamed(this, "scope.lists")).setSelectedIndex("SCOPE_BLOCKED".equals(entry.reason()) ? 1 : 0);
            if (target == 2) selectId(rulesTable, rulesModel.rows, Rule::id, entry.hits().stream().map(h -> h.id()).collect(java.util.stream.Collectors.toSet()));
            dialogs.closeEditors();
        }
    }

    private static int targetTab(String reason) {
        return switch (reason) {
            case "SCOPE_NOT_ALLOWED", "SCOPE_BLOCKED" -> 1;
            case "RULE_BLOCK", "RULE_MATCH" -> 2;
            case "ASK" -> 4;
            case "DEFAULT_BLOCK", "QUEUE_TIMEOUT", "QUEUE_FULL" -> 5;
            case "PAUSED", "IN_FLIGHT_TIMEOUT", "POLICY_CHANGED", "PROJECT_CHANGED" -> 0;
            default -> -1;
        };
    }

    private void bookmarkSelected() {
        List<TrafficEntry> selected = selectedTraffic();
        if (selected.isEmpty()) throw failure("SELECT_TRAFFIC_FIRST");
        for (TrafficEntry entry : selected) access.bookmark(entry.id(), !entry.bookmarked());
        refreshNow();
    }

    private TrafficEntry evidence(Pending pending) {
        return traffic.stream().filter(e -> e.id().equals(pending.evidenceId()) && e.projectId().equals(pending.projectId())).findFirst().orElse(null);
    }
    private Object[] approvalValues(Pending pending) {
        TrafficEntry entry = evidence(pending);
        return new Object[]{entry == null ? "—" : entry.method(), entry == null ? "증거가 보관되어 있지 않음" : entry.url(),
                entry == null ? "증거 없음 · 승인 불가" : entry.hits().isEmpty() ? UiText.reason(entry.reason()) : entry.hits().getFirst().name(),
                remaining(pending) > 0 ? remaining(pending) + "초" : "만료됨"};
    }
    private static long remaining(Pending pending) {
        try { long millis = Duration.between(Instant.now(), Instant.parse(pending.expiresAt())).toMillis(); return millis <= 0 ? 0 : (millis + 999) / 1000; }
        catch (DateTimeParseException | ArithmeticException e) { return 0; }
    }

    private boolean currentPending(Pending pending) {
        return available && !closed && view != null && pending != null && pending.projectId().equals(view.projectId())
                && !Boolean.TRUE.equals(latestStatus.get("paused")) && !Boolean.TRUE.equals(latestStatus.get("closed")) && remaining(pending) > 0;
    }

    private void showApprovalDetail() {
        Pending pending = selected(approvalTable, approvalModel);
        TrafficEntry entry = pending == null ? null : evidence(pending);
        boolean current = currentPending(pending);
        approve.setEnabled(current && entry != null && entry.revision() == view.revision());
        deny.setEnabled(current);
        if (pending == null) {
            setDetail(approvalDetail, approvalModel.rows.isEmpty() ? "승인을 기다리는 요청이 없습니다.\n차단된 요청은 여기에서 해제할 수 없습니다. ‘요청 기록’에서 차단 이유를 확인하세요."
                    : "검토할 요청을 표에서 선택하세요. 메서드·주소·이유와 마스킹된 요청을 확인한 뒤 결정하세요.");
        } else {
            setDetail(approvalDetail, boundedText("승인 기한 (UTC): " + pending.expiresAt() + " · " + (current ? "검토 가능" : "현재 승인할 수 없음")
                    + "\n승인은 이 요청에 한 번만 적용됩니다. 최종 안전 검사와 속도·동시성 제한은 유지됩니다.\n\n"
                    + (entry == null ? UiText.error("APPROVAL_EVIDENCE_MISSING") : metadata(entry) + "\n\n마스킹된 요청\n" + entry.request())
                    + "\n\n승인 ID: " + pending.id() + "\n증거 ID: " + pending.evidenceId() + "\n만료 (UTC): " + pending.expiresAt()));
        }
    }

    private void decide(boolean allow) {
        Pending pending = selected(approvalTable, approvalModel);
        if (pending == null) throw failure("SELECT_PENDING_APPROVAL_FIRST");
        access.refreshProject();
        Map<String, Object> status = access.status();
        if (!currentPending(pending) || !pending.projectId().equals(projectId(status))
                || Boolean.TRUE.equals(status.get("paused")) || Boolean.TRUE.equals(status.get("closed"))
                || access.approvals().stream().noneMatch(p -> p.equals(pending))) {
            refreshNow(); throw failure("APPROVAL_STALE_OR_EXPIRED");
        }
        if (allow) {
            // Re-read the retained masked evidence; a timer's old row is not sufficient for approval.
            TrafficEntry entry = access.traffic().stream().limit(MAX_ROWS).filter(e -> e.id().equals(pending.evidenceId()) && e.projectId().equals(pending.projectId())).findFirst().orElse(null);
            if (entry == null) { refreshNow(); throw failure("APPROVAL_EVIDENCE_MISSING"); }
            if (entry.revision() != revision(status)) { refreshNow(); throw failure("APPROVAL_STALE_OR_EXPIRED"); }
        }
        boolean decided = access.decideApproval(pending.id(), allow);
        refreshNow();
        if (!decided) throw failure("APPROVAL_STALE_OR_EXPIRED");
        message.setText(allow ? "이 요청을 한 번 승인했습니다. 최종 안전 검사와 전송 제한은 계속 적용됩니다." : "이 요청을 거절했습니다.");
    }

    private void chooseExport(boolean selectedOnly, boolean har) {
        if (exportWorker != null) throw failure("EXPORT_IN_PROGRESS");
        List<TrafficEntry> entries = selectedOnly ? selectedTraffic() : List.copyOf(trafficModel.rows);
        if (entries.isEmpty()) throw failure("NO_DISPLAYED_EVIDENCE_TO_EXPORT");
        Path selected = dialogs.chooseExport(this, har ? "har" : "json");
        if (selected == null) return;
        final ExportTarget target;
        try { target = inspectTarget(selected); }
        catch (IOException | RuntimeException e) { throw failure("EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE"); }
        if (target.existing() && !dialogs.confirm(this, "선택한 기존 파일을 마스킹된 증거로 덮어쓸까요? 저장 파일은 소유자만 읽고 쓸 수 있도록 생성합니다.\n" + EXPORT_NOTICE)) return;
        message.setText(entries.size() + "개의 마스킹된 기록을 내보내는 중입니다…");
        exportWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() throws Exception {
                String text = har ? access.exportHar(entries) : access.exportJson(entries);
                if (isCancelled()) throw new IOException("CANCELLED");
                writeAtomic(target, text); return null;
            }
            @Override protected void done() {
                exportWorker = null;
                if (closed) return;
                try { get(); message.setText("마스킹된 기록 " + entries.size() + "개를 내보냈습니다. 완전한 통신 캡처나 대상 도착의 증명이 아닙니다."); }
                catch (Exception e) { report("EXPORT_FAILED"); }
            }
        };
        exportWorker.execute();
    }

    /** Capture overwrite-consent identity before background work; do not follow a target symlink. */
    static ExportTarget inspectTarget(Path requested) throws IOException {
        Path absolute = requested.toAbsolutePath().normalize();
        if (absolute.getFileName() == null || absolute.getParent() == null) throw new IOException("INVALID_TARGET");
        Path target = absolute.getParent().toRealPath().resolve(absolute.getFileName());
        if (Files.isSymbolicLink(target)) throw new IOException("SYMLINK_TARGET");
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return new ExportTarget(target, null);
        BasicFileAttributes attrs = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile()) throw new IOException("NON_REGULAR_TARGET");
        return new ExportTarget(target, attrs);
    }

    /** Owner-only same-directory atomic publication. No non-atomic fallback or raw error logging. */
    static void writeAtomic(ExportTarget choice, String text) throws IOException {
        Objects.requireNonNull(text);
        Path target = choice.path(); Path parent = target.getParent();
        boolean posix = Files.getFileStore(parent).supportsFileAttributeView("posix");
        FileAttribute<?>[] attrs = posix ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))} : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(parent, ".cairn-guard-", ".tmp", attrs);
        BasicFileAttributes reservation = null; boolean published = false;
        try {
            BasicFileAttributes initialTemp = safeAttributes(temp);
            try (Writer out = Files.newBufferedWriter(temp, StandardCharsets.UTF_8, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) { out.write(text); }
            BasicFileAttributes writtenTemp = safeAttributes(temp);
            if (!Objects.equals(initialTemp.fileKey(), writtenTemp.fileKey()) || !initialTemp.creationTime().equals(writtenTemp.creationTime())) throw new IOException("TEMP_CHANGED");
            if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
            if (choice.existing()) {
                if (!sameFileState(choice.original(), safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            } else { Files.createFile(target, attrs); reservation = safeAttributes(target); }
            BasicFileAttributes expected = choice.existing() ? choice.original() : reservation;
            if (!sameFileState(expected, safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); published = true;
        } finally {
            Files.deleteIfExists(temp);
            if (!published && reservation != null) {
                try { if (sameFileState(reservation, safeAttributes(target))) Files.deleteIfExists(target); }
                catch (IOException ignored) { /* Never remove a replacement or expose exception content. */ }
            }
        }
    }
    private static BasicFileAttributes safeAttributes(Path target) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attrs.isSymbolicLink() || !attrs.isRegularFile()) throw new IOException("UNSAFE_TARGET");
        return attrs;
    }
    private static boolean sameFileState(BasicFileAttributes a, BasicFileAttributes b) {
        return a != null && b != null && Objects.equals(a.fileKey(), b.fileKey()) && a.size() == b.size()
                && a.lastModifiedTime().equals(b.lastModifiedTime()) && a.creationTime().equals(b.creationTime());
    }
    record ExportTarget(Path path, BasicFileAttributes original) { boolean existing() { return original != null; } }
    private record Snapshot(GuardConfig policy, String projectId, long revision) {
        boolean matches(Map<String, Object> status) { return projectId.equals(GuardPanel.projectId(status)) && revision == GuardPanel.revision(status); }
    }
    private static boolean sameVersion(Map<String, Object> a, Map<String, Object> b) { return projectId(a).equals(projectId(b)) && revision(a) == revision(b); }
    private static String projectId(Map<String, Object> status) {
        if (!(status.get("projectId") instanceof String value) || value.isBlank()) throw failure("PROJECT_UNAVAILABLE");
        return value;
    }
    private static long revision(Map<String, Object> status) {
        if (!(status.get("revision") instanceof Number value)) throw failure("PROJECT_UNAVAILABLE");
        return value.longValue();
    }
    private static GuardConfig parsePolicy(String text) {
        if (text == null || text.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        try {
            GuardConfig value = Json.MAPPER.readerFor(GuardConfig.class).with(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                    .without(DeserializationFeature.ACCEPT_FLOAT_AS_INT).readValue(text);
            if (value == null) throw new IllegalArgumentException();
            return value;
        } catch (Exception e) { throw failure("INVALID_BOUNDED_JSON"); }
    }
    private static String boundedJson(Object value) {
        String text = Json.write(value);
        if (text.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        return text;
    }
    private static String boundedText(String text) { return text.length() <= MAX_EDITOR_CHARS ? text : text.substring(0, MAX_EDITOR_CHARS - 32) + "\n[표시 길이 제한]"; }
    private static String displayRuleName(String name) {
        return switch (name) {
            case "Block DELETE method" -> "DELETE 메서드 차단";
            case "Block delete string (conservative)" -> "delete 문자열 차단 (보수적)";
            default -> name;
        };
    }

    private void guarded(Runnable action) {
        requireEdt(); if (closed) return;
        try { action.run(); }
        catch (FormValidationException e) { reportText(e.getMessage()); }
        catch (UiFailure e) { report(e.category); }
        catch (RuntimeException e) { report("ACTION_FAILED"); }
    }
    private void report(String category) { reportText(UiText.error(category)); }
    private void reportText(String text) { message.setText(text); dialogs.error(this, text); }
    private static UiFailure failure(String category) { return new UiFailure(category); }
    private static final class UiFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String category;
        UiFailure(String category) { super(null, null, false, false); this.category = category; }
    }
    private JButton button(String name, String label, Runnable action) {
        JButton result = named(new JButton(label), name);
        result.addActionListener(e -> guarded(action)); return result;
    }
    private JButton policyButton(String name, String label, Runnable action) { JButton result = button(name, label, action); policyActions.add(result); return result; }
    private static JPanel buttons(Component... children) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEADING, 6, 3));
        for (Component child : children) panel.add(child); return panel;
    }
    private static JPanel labeled(String label, JComponent field) {
        JPanel panel = new JPanel(new BorderLayout(2, 2));
        JLabel title = named(new JLabel(label), field.getName() + ".label"); title.setLabelFor(field);
        panel.add(title, BorderLayout.NORTH); panel.add(field, BorderLayout.CENTER); return panel;
    }
    private static JTextArea note(String name, String value) {
        JTextArea area = named(new JTextArea(value, 0, 36), name);
        area.setEditable(false); area.setFocusable(false); area.setCaret(new NonScrollingCaret());
        area.setLineWrap(true); area.setWrapStyleWord(true); area.setOpaque(false);
        area.setBorder(BorderFactory.createEmptyBorder(4, 3, 4, 3));
        return area;
    }
    private static JTextArea textArea(String name, boolean editable) {
        JTextArea area = named(new JTextArea(8, 38), name); area.setEditable(editable); area.setLineWrap(false);
        ((AbstractDocument) area.getDocument()).setDocumentFilter(new LengthLimit(MAX_EDITOR_CHARS)); return area;
    }
    private static JTextField textField(String name) {
        JTextField field = named(new JTextField(14), name);
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new LengthLimit(4_096)); return field;
    }
    private static RowsModel<ScopeEntry> scopeModel() {
        return new RowsModel<>(new String[]{"사용", "호스트", "연결 방식", "포트", "경로 범위"},
                new Class<?>[]{String.class, String.class, String.class, String.class, String.class},
                s -> new Object[]{s.enabled() ? "사용 중" : "중지", s.host(), s.scheme().equalsIgnoreCase("any") ? "HTTP + HTTPS" : s.scheme().toUpperCase(Locale.ROOT),
                        s.port() == 0 ? "모든 포트" : String.valueOf(s.port()), ScopeEditor.pathSummary(s)});
    }
    private static JTable table(String name, AbstractTableModel model, boolean multi) {
        JTable table = named(new JTable(model), name); table.setAutoCreateRowSorter(true);
        table.setSelectionMode(multi ? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION : ListSelectionModel.SINGLE_SELECTION);
        DefaultTableCellRenderer plain = new DefaultTableCellRenderer(); plain.putClientProperty("html.disable", Boolean.TRUE);
        table.setDefaultRenderer(String.class, plain); table.setFillsViewportHeight(true); table.getTableHeader().setReorderingAllowed(false);
        if (table.getTableHeader().getDefaultRenderer() instanceof JComponent renderer) renderer.putClientProperty("html.disable", Boolean.TRUE);
        table.addPropertyChangeListener("font", e -> table.setRowHeight(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 10)));
        table.setRowHeight(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 10));
        int[] widths = name.startsWith("scope.") ? new int[]{80, 220, 180, 90, 420}
                : name.equals("rules.table") ? new int[]{80, 250, 130, 520}
                : name.equals("approval.table") ? new int[]{90, 430, 280, 110}
                : new int[]{60, 180, 90, 330, 110, 70, 260};
        for (int col = 0; col < table.getColumnCount(); col++) table.getColumnModel().getColumn(col).setPreferredWidth(widths[col]);
        return table;
    }
    private static <T> T selected(JTable table, RowsModel<T> model) { int index = modelIndex(table, table.getSelectedRow(), model.rows.size()); return index < 0 ? null : model.rows.get(index); }
    private static int modelIndex(JTable table, int view, int size) {
        if (view < 0 || view >= table.getRowCount()) return -1;
        try { int index = table.convertRowIndexToModel(view); return index >= 0 && index < size ? index : -1; }
        catch (IndexOutOfBoundsException e) { return -1; }
    }
    private static <T> Set<String> ids(JTable table, RowsModel<T> model, java.util.function.Function<T, String> id) {
        Set<String> result = new HashSet<>();
        for (int view : table.getSelectedRows()) { int i = modelIndex(table, view, model.rows.size()); if (i >= 0) result.add(id.apply(model.rows.get(i))); }
        return result;
    }
    private <T> void replaceRows(JTable table, RowsModel<T> model, List<T> rows, java.util.function.Function<T, String> id) {
        Set<String> selection = ids(table, model, id);
        boolean adjusting = table.getSelectionModel().getValueIsAdjusting();
        selectionUpdates++;
        table.getSelectionModel().setValueIsAdjusting(true);
        try { model.setRows(rows); selectId(table, model.rows, id, selection); }
        finally {
            // JTable's sorter can itself toggle valueIsAdjusting; the panel-level guard spans all events.
            table.getSelectionModel().setValueIsAdjusting(adjusting);
            selectionUpdates--;
        }
    }
    private static <T> void selectId(JTable table, List<T> rows, java.util.function.Function<T, String> id, Set<String> wanted) {
        Set<Integer> desired = new LinkedHashSet<>();
        for (int i = 0; i < rows.size(); i++) if (wanted.contains(id.apply(rows.get(i)))) {
            int view = table.convertRowIndexToView(i); if (view >= 0) desired.add(view);
        }
        Set<Integer> actual = new HashSet<>();
        for (int view : table.getSelectedRows()) actual.add(view);
        if (actual.equals(desired)) return; // Do not reset the human's detail scroll/selection every timer tick.
        boolean adjusting = table.getSelectionModel().getValueIsAdjusting();
        table.getSelectionModel().setValueIsAdjusting(true);
        try {
            table.clearSelection();
            for (int view : desired) table.addRowSelectionInterval(view, view);
        } finally { table.getSelectionModel().setValueIsAdjusting(adjusting); }
    }
    private static void listen(JTextComponent field, Runnable changed) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { changed.run(); }
            @Override public void removeUpdate(DocumentEvent e) { changed.run(); }
            @Override public void changedUpdate(DocumentEvent e) { changed.run(); }
        });
    }
    private static <T extends JComponent> T named(T component, String name) {
        component.setName(name); component.putClientProperty("html.disable", Boolean.TRUE);
        component.getAccessibleContext().setAccessibleDescription(name); return component;
    }
    private static Component findNamed(Component root, String name) {
        if (name.equals(root.getName())) return root;
        if (root instanceof java.awt.Container container) for (Component child : container.getComponents()) {
            Component found = findNamed(child, name); if (found != null) return found;
        }
        return null;
    }
    private static void requireEdt() { if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Swing EDT required"); }

    @Override public void close() {
        requireEdt(); if (closed) return; closed = true; available = false; timer.stop();
        if (exportWorker != null) exportWorker.cancel(true);
        for (JButton action : policyActions) action.setEnabled(false);
        pause.setEnabled(false); approve.setEnabled(false); deny.setEnabled(false);
        dialogs.closeEditors();
        version.setText("확장 종료 · 설정 변경과 승인 불가");
    }

    interface Dialogs {
        boolean confirm(Component parent, String message);
        Path chooseExport(Component parent, String extension);
        void error(Component parent, String message);
        void edit(Component parent, String title, String saveLabel, EditorForm<?> form, Runnable save);
        default void closeEditors() {}
    }
    private static final class SwingDialogs implements Dialogs {
        private final Set<JDialog> editors = new HashSet<>();
        @Override public void closeEditors() { for (JDialog dialog : List.copyOf(editors)) dialog.dispose(); }
        @Override public boolean confirm(Component parent, String message) {
            return JOptionPane.showConfirmDialog(parent, note("dialog.confirm", message), "Cairn Guard · 확인", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
        }
        @Override public Path chooseExport(Component parent, String extension) {
            JFileChooser chooser = new JFileChooser(); chooser.setDialogTitle("마스킹된 요청 기록 내보내기");
            chooser.setFileFilter(new FileNameExtensionFilter("마스킹된 " + extension.toUpperCase(Locale.ROOT), extension));
            return chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath() : null;
        }
        @Override public void error(Component parent, String message) {
            JOptionPane.showMessageDialog(parent, note("dialog.error", message), "Cairn Guard · 확인 필요", JOptionPane.ERROR_MESSAGE);
        }
        @Override public void edit(Component parent, String title, String saveLabel, EditorForm<?> form, Runnable save) {
            JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(parent), "Cairn Guard · " + title, Dialog.ModalityType.APPLICATION_MODAL);
            dialog.setName("editor.dialog"); dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            JPanel content = new JPanel(new BorderLayout(8, 8)); content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            JComponent editor = form.component(); editor.setMinimumSize(new Dimension(0, 0));
            content.add(editor, BorderLayout.CENTER);
            JTextArea feedback = note("editor.feedback", saveLabel.equals("닫기") ? "이 창을 닫는 것만으로 설정을 저장하거나 요청을 승인하지 않습니다." : SAVE_NOTICE);
            JButton submit = named(new JButton(saveLabel), "editor.save");
            JButton cancel = named(new JButton(saveLabel.equals("닫기") ? "취소" : "취소 · 변경 안 함"), "editor.cancel");
            submit.addActionListener(e -> {
                try { save.run(); dialog.dispose(); }
                catch (FormValidationException failure) { feedback.setText(failure.getMessage()); }
                catch (UiFailure failure) { feedback.setText(UiText.error(failure.category)); }
                catch (RuntimeException failure) { feedback.setText(UiText.error("ACTION_FAILED")); }
            });
            cancel.addActionListener(e -> dialog.dispose());
            cancel.setVisible(!saveLabel.equals("닫기"));
            JPanel footer = new JPanel(new BorderLayout()); footer.add(feedback, BorderLayout.NORTH); footer.add(buttons(cancel, submit), BorderLayout.SOUTH);
            content.add(footer, BorderLayout.SOUTH); dialog.setContentPane(content);
            dialog.getRootPane().setDefaultButton(submit);
            dialog.getRootPane().registerKeyboardAction(e -> dialog.dispose(), KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
            Rectangle bounds = parent.getGraphicsConfiguration().getBounds();
            Insets insets = java.awt.Toolkit.getDefaultToolkit().getScreenInsets(parent.getGraphicsConfiguration());
            int width = Math.max(320, bounds.width - insets.left - insets.right - 48);
            int height = Math.max(300, bounds.height - insets.top - insets.bottom - 48);
            dialog.setMinimumSize(new Dimension(360, 300));
            dialog.setSize(Math.min(980, width), Math.min(800, height)); dialog.setLocationRelativeTo(parent);
            editors.add(dialog);
            try { dialog.setVisible(true); } finally { editors.remove(dialog); dialog.dispose(); }
        }
    }
    private static final class LengthLimit extends DocumentFilter {
        private final int max;
        private final Runnable rejected;
        LengthLimit(int max) { this(max, () -> {}); }
        LengthLimit(int max, Runnable rejected) { this.max = max; this.rejected = rejected; }
        @Override public void insertString(FilterBypass bypass, int offset, String text, AttributeSet attrs) throws BadLocationException { replace(bypass, offset, 0, text, attrs); }
        @Override public void replace(FilterBypass bypass, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
            if ((long) bypass.getDocument().getLength() - length + (text == null ? 0 : text.length()) <= max) bypass.replace(offset, length, text, attrs);
            else rejected.run();
        }
    }
    private static final class RowsModel<T> extends AbstractTableModel {
        private final String[] columns; private final Class<?>[] types; private final java.util.function.Function<T, Object[]> values;
        private List<T> rows = List.of();
        RowsModel(String[] columns, Class<?>[] types, java.util.function.Function<T, Object[]> values) { this.columns = columns; this.types = types; this.values = values; }
        void setRows(List<T> rows) { List<T> next = List.copyOf(rows); if (!this.rows.equals(next)) { this.rows = next; fireTableDataChanged(); } }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Class<?> getColumnClass(int column) { return types[column]; }
        @Override public Object getValueAt(int row, int column) { return values.apply(rows.get(row))[column]; }
        @Override public boolean isCellEditable(int row, int column) { return false; }
    }
}
