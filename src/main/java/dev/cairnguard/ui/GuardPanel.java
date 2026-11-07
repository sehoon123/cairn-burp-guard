package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.PolicyCodec;
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
import javax.swing.table.TableRowSorter;
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
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
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
    private static final String ALL_PROJECTS = "모든 프로젝트";
    private static final String EXPORT_NOTICE = "화면과 모든 JSON/HAR/사건 출력은 마스킹 없는 평문 원문(Authorization·Cookie·토큰 등 비밀 포함)입니다. 수집·보관·내보내기에는 건수·크기·기간 상한이 없고 메모리는 지우기·프로젝트 전환·언로드 전까지 계속 늘어나 메모리 부족(OOM)·화면 지연이 생길 수 있으며 직접 관리해야 합니다. 파일 저장은 매번 명시적으로 확인합니다. 원문이 없거나 지운 항목은 ‘원문 없음’으로 표시합니다. 읽기 실패·지원하지 않는 문자셋(HEX)·응답 없음은 그대로 표시하며 완전한 통신 캡처나 대상 도착의 증명이 아닙니다.";
    private static final String PLAINTEXT_CONSENT = "평문 원문 내보내기: 파일에 Authorization·Cookie·토큰 등 비밀 값이 그대로 들어갑니다. 콜백으로 받은 검사 사본이며 크기 상한 없이 전부 저장하므로 큰 파일이 될 수 있습니다. 완전한 wire 캡처나 대상 도착의 증명이 아닙니다. 소유자 전용 권한으로 저장하지만 파일을 공유·게시하지 마세요. 화면을 지워도 이미 저장한 파일은 회수되지 않습니다. 계속할까요?";
    private static final String RAW_NOTICE = "민감정보 포함 · 평문 원문 · 메모리 한정(상한 없음) · 검사 사본 (wire 증거 아님)";
    private static final String SAVE_NOTICE = "저장하면 현재 Burp 프로젝트에 즉시 적용하며 기존 승인 대기를 취소합니다. 취소하면 바뀌지 않습니다.";

    private final GuardUiAccess access;
    private final Dialogs dialogs;
    private final Timer timer;
    private final JTabbedPane tabs = named(new JTabbedPane(), "tabs");
    private final JLabel message = named(new JLabel("현재 상태를 확인하고 있습니다…"), "message");
    private final JLabel version = named(new JLabel("프로젝트 확인 중"), "policy.version");
    private final JLabel protectionState = named(new JLabel("보호 상태 확인 중"), "protection.state");
    private final JButton passthrough;
    private final JLabel passthroughCounter = named(new JLabel(), "protection.passthroughCount");
    private final JLabel stateTitle = named(new JLabel("보호 상태 확인 중"), "dashboard.state");
    private final JTextArea stateHelp = note("dashboard.guidance", "");
    private final JLabel scopeCount = named(new JLabel(), "dashboard.scopeCount");
    private final JLabel ruleCount = named(new JLabel(), "dashboard.ruleCount");
    private final JLabel gateCount = named(new JLabel(), "dashboard.gateCount");
    private final JLabel evidenceCount = named(new JLabel(), "dashboard.evidenceCount");
    private final JTextArea recentBlock = note("dashboard.recentBlock", "");
    private final JTextArea diagnosis = note("dashboard.diagnosis", "");
    private final JTextArea warnings = note("dashboard.warning", "");
    private final JTextArea reasonCounters = note("dashboard.reasonCounters", "");
    private final JPanel migrationBanner = new JPanel(new BorderLayout(4, 4));
    private Map<String,Object> migration = Map.of();
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
    private final RowsModel<Rule> rulesModel = new RowsModel<>(new String[]{"사용", "규칙 이름", "동작", "조건", "우선순위"},
            new Class<?>[]{String.class, String.class, String.class, String.class, Integer.class},
            r -> new Object[]{r.enabled() ? "사용 중" : "중지", displayRuleName(r.name()), UiText.mode(r.mode().name()), RuleEditor.summary(r.condition()), r.mode() == Mode.EXEMPT ? 0 : 1});
    private final JTable rulesTable = table("rules.table", rulesModel, false);
    private final JTextArea settingsSummary = textArea("settings.summary", false);
    private final RowsModel<TrafficEntry> trafficModel = new RowsModel<>(
            new String[]{"보관", "시각 (UTC)", "메서드", "원문 URL · 화면 전용", "결과", "HTTP", "이유", "Intent (비신뢰)", "Run (비신뢰)", "보호 상태", "검사 경고", "응답 본문 bytes (관측)", "요청 MIME (선언)", "응답 MIME (선언)", "요청 사본", "응답 사본"},
            new Class<?>[]{Boolean.class, String.class, String.class, String.class, String.class, Integer.class, String.class, String.class, String.class, String.class, String.class, Long.class, String.class, String.class, String.class, String.class},
            e -> new Object[]{e.bookmarked(), e.timestamp(), screenMethod(e), screenUrl(e), trafficOutcome(e), e.statusCode(), UiText.reason(e.reason()), screenTag(e, "intentId"), screenTag(e, "runId"), UiText.guardState(e.guardState()), UiText.warnings(e.inspectionWarnings(), false), e.responseBytes() < 0 ? null : e.responseBytes(), e.requestCapture().mimeType(), e.responseCapture().mimeType(), captureState(e, true), captureState(e, false)});
    private final JTable trafficTable = table("traffic.table", trafficModel, true);
    private final JTextField search = textField("traffic.search");
    private final JComboBox<TrafficSearch.Location> searchLocation = named(new JComboBox<>(TrafficSearch.Location.values()), "traffic.searchLocation");
    private final JComboBox<TrafficSearch.MatchMode> searchMode = named(new JComboBox<>(TrafficSearch.MatchMode.values()), "traffic.searchMode");
    private final JTextArea searchError = note("traffic.searchError", "");
    private final JTextField methodFilter = textField("traffic.method");
    private final JTextField statusFilter = textField("traffic.status");
    private final JTextField timeFilter = textField("traffic.time");
    private final JTextField intentFilter = textField("traffic.intent");
    private final JTextField runFilter = textField("traffic.run");
    private final JTextField stateFilter = textField("traffic.guardState");
    private final JComboBox<String> outcomeFilter = named(new JComboBox<>(new String[]{"모든 결과", "차단됨", "전송 해제", "대기 중", "EXEMPT 예외", "상태 확인 통과"}), "traffic.outcome");
    private final JComboBox<String> projectFilter = named(new JComboBox<>(new String[]{ALL_PROJECTS}), "traffic.project");
    private final JCheckBox bookmarksOnly = named(new JCheckBox("보관한 요청만"), "traffic.bookmarked");
    private final JLabel trafficCount = named(new JLabel("기록 없음"), "traffic.count");
    private final JComboBox<String> exportRange = named(new JComboBox<>(new String[]{"현재 표의 요청", "선택한 요청만"}), "traffic.exportRange");
    private final JComboBox<String> exportFormat = named(new JComboBox<>(new String[]{"JSON", "HAR"}), "traffic.exportFormat");
    private TrafficInspector inlineInspector;
    private TrafficInspector popoutInspector;
    private final TrafficSearch.Session contentSearch = new TrafficSearch.Session();
    private TrafficSearch.Input searchInput = TrafficSearch.compile(new TrafficSearch.Query("", TrafficSearch.Location.ALL, TrafficSearch.MatchMode.LITERAL));
    private final TrafficSearch.Pump presentation = new TrafficSearch.Pump("cairn-history-presentation");
    private PresentationKey presentationKey;
    private TrafficInspector.Content presentedContent;
    private HtmlPreview.Projection presentedPreview;
    private String previewReason;
    private boolean presenting, presentingPreview, presentationFailed;
    private long presentationGeneration;
    private record PresentationKey(String id, TrafficEntry.Message request, TrafficEntry.Message response,
                                   String requestLine, String responseLine, String metadata) {
        boolean same(PresentationKey other) {
            return other != null && id.equals(other.id) && request == other.request && response == other.response
                    && requestLine.equals(other.requestLine) && responseLine.equals(other.responseLine) && metadata.equals(other.metadata);
        }
    }
    private record PresentationResult(TrafficInspector.Content content, HtmlPreview.Projection preview, String reason) {}
    private final JTextField incidentFrom = textField("incident.from");
    private final JTextField incidentTo = textField("incident.to");
    private final RowsModel<Pending> approvalModel = new RowsModel<>(
            new String[]{"메서드 (원문)", "원문 URL", "승인 요청 이유", "남은 시간"},
            new Class<?>[]{String.class, String.class, String.class, String.class}, this::approvalValues);
    private final JTable approvalTable = table("approval.table", approvalModel, false);
    private final JTextArea approvalDetail = viewer("approval.detail");
    private List<TrafficEntry> traffic = List.of();
    private Snapshot view;
    private Map<String, Object> latestStatus = Map.of();
    private boolean available;
    private boolean loading;
    private int selectionUpdates;
    private TrafficSelection trafficSelection = new TrafficSelection(Set.of(), null);
    private record TrafficSelection(Set<String> ids, String leadId) {
        TrafficSelection {
            ids = Set.copyOf(ids);
            if (leadId != null && !ids.contains(leadId)) leadId = null;
        }
    }
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
        configureRuleView();
        pause = button("dashboard.pause", "새 요청 모두 차단", this::togglePause);
        passthrough = button("protection.passthrough", "모두 통과 (보호 끔)…", this::togglePassthrough);
        protectionState.setFont(new javax.swing.plaf.FontUIResource(protectionState.getFont().deriveFont(java.awt.Font.BOLD)));
        approve = button("approval.approve", "한 번만 승인", () -> decide(true));
        deny = button("approval.deny", "거절", () -> decide(false));
        resolve = button("traffic.resolve", "관련 설정 열기", this::resolveSelected);
        JPanel header = new JPanel(new BorderLayout(8, 2));
        header.add(version, BorderLayout.NORTH);
        header.add(buttons(protectionState, passthrough, passthroughCounter,
                button("help.examples", "사용 예시…", () -> showReadOnly("사용 예시 · 설정은 바뀌지 않음", UsageGuide.create())),
                button("policy.refresh", "새로고침", () -> {
                    refreshNow();
                    if (available) message.setText("현재 프로젝트의 설정과 요청 기록을 다시 확인했습니다.");
                })), BorderLayout.CENTER);
        migrationBanner.setName("migration.banner");
        migrationBanner.add(note("migration.notice", "v1 → v2 메모리 변환 대기 · 원본은 아직 저장소에 유지됩니다. 새 감지 기능은 OFF이며 기존 규칙을 보존합니다. 비교·원본 내보내기 후 사람이 명시적으로 저장하세요."), BorderLayout.CENTER);
        migrationBanner.add(buttons(policyButton("migration.review", "변환 비교 / 명시적 저장…", this::reviewMigration),
                button("migration.exportOriginal", "v1 원본 내보내기…", this::exportOriginal)), BorderLayout.SOUTH);
        header.add(migrationBanner, BorderLayout.SOUTH);
        add(header, BorderLayout.NORTH);
        tabs.addTab("개요", dashboardTab());
        tabs.addTab("대상", scopeTab());
        tabs.addTab("규칙", rulesTab());
        tabs.addTab("요청 기록", trafficTab());
        tabs.addTab("승인 대기", approvalTab());
        tabs.addTab("설정", settingsTab());
        tabs.addTab("사건 내보내기", incidentTab());
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
        diagnosis.setBorder(BorderFactory.createTitledBorder("로컬 차단 / 대상 응답 구분"));
        warnings.setForeground(new java.awt.Color(180, 65, 0));
        content.add(diagnosis); content.add(warnings); content.add(reasonCounters);
        content.add(buttons(policyButton("dashboard.resetIntent", "Intent 예산 초기화…", this::resetIntentBudgets)));
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
        panel.add(note("scope.help", "실제 연결 목적지의 호스트·scheme·port와 원래 요청 path로 범위를 판정합니다 (fuzz한 Host/:authority는 대상 변경이 아님). 모든 경로를 허용하면 /c/;/main.do, /c/%2e/main.do도 원문 그대로 전송할 수 있습니다. 제한된 경로는 내부 해석 뷰 모두가 범위여야 하며 해석 불완전 경고를 숨기지 않습니다. 차단 대상·명시 규칙·수동 일시중지·작성한 속도와 태그 예산은 별도입니다. 헤더/본문 형식 자체를 자동 차단하지 않으며 편집은 명시적 저장 전에는 적용되지 않습니다.\n이 허용 대상은 Burp Target Scope와 별개입니다. Burp의 ‘Drop all out-of-scope requests’가 켜져 있으면 Burp Target Scope 밖 요청은 Cairn이 허용하거나 보호가 꺼져 있어도 Burp가 전송 전에 버릴 수 있고 클라이언트에 Burp 자체 오류가 보일 수 있습니다 (Cairn은 Burp 설정을 읽거나 바꾸지 않습니다). X-Cairn-Guard 로컬 451은 Cairn 거절의 긍정 표시이지 인증된 증명이나 모든 거절 방식의 목록이 아닙니다. 451이나 Cairn 증거 행이 없다는 사실만으로는 결론을 낼 수 없고(보호 꺼짐·지우기/프로젝트 전환·drop-only/실패 경로), 행이 있어도 대상 도착을 뜻하지 않습니다."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel scopeList(boolean blocked) {
        String prefix = blocked ? "scope.block" : "scope.allow";
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(buttons(policyButton(prefix + ".add", blocked ? "차단 대상 추가…" : "허용 대상 추가…", () -> editScope(blocked, true)),
                policyButton(prefix + ".edit", "선택 항목 편집…", () -> editScope(blocked, false)),
                policyButton(prefix + ".toggle", "사용 / 중지", () -> mutateScope(blocked, false)),
                policyButton(prefix + ".delete", "삭제…", () -> mutateScope(blocked, true))), BorderLayout.NORTH);
        JTable list = blocked ? blockTable : allowTable;
        installOpenAction(list, () -> editScope(blocked, false), "두 번 클릭 또는 Enter: 선택한 대상 편집 (저장 전에는 변경하지 않음)");
        panel.add(new JScrollPane(list), BorderLayout.CENTER);
        return panel;
    }

    private JPanel rulesTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        JPanel header = new JPanel(new BorderLayout());
        header.add(note("rules.help", "EXEMPT 예외 > 차단 > 승인 요청 > 허용. 주황색 EXEMPT는 일반 BLOCK·ASK를 무시하므로 명시적 저장 확인이 필요합니다. 표에서 예외를 위로 고정해도 정책 순서는 바꾸지 않습니다. 범위·유효성·일시중지·수동 속도·예산은 예외로 우회할 수 없습니다. 헤더·본문 조건은 검사 가능할 때 적용하며 불완전 검사는 경고로 표시합니다."), BorderLayout.NORTH);
        header.add(buttons(policyButton("rules.add", "규칙 만들기…", () -> editRule(true)),
                policyButton("rules.edit", "선택 규칙 편집…", () -> editRule(false)),
                policyButton("rules.toggle", "사용 / 중지", () -> mutateRule(false)),
                policyButton("rules.delete", "삭제…", () -> mutateRule(true))), BorderLayout.SOUTH);
        panel.add(header, BorderLayout.NORTH);
        installOpenAction(rulesTable, () -> editRule(false), "두 번 클릭 또는 Enter: 선택한 규칙 편집 (저장 전에는 변경하지 않음)");
        panel.add(new JScrollPane(rulesTable), BorderLayout.CENTER);
        panel.add(note("rules.defaults", "새 정책의 기본 규칙은 DELETE 메서드 차단만 있습니다 (EXEMPT 기본값 없음). v1의 delete 문자열 규칙은 변환 시 그대로 유지합니다. GET deleteInfoBoardComnt.do / undelete 등 오탐을 검토하고 원본과 정확히 같은 기존 규칙만 별도 선택하여 제거할 수 있습니다."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel settingsTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(buttons(policyButton("settings.edit", "요청 제어 설정 변경…", this::editSettings)), BorderLayout.NORTH);
        panel.add(new JScrollPane(settingsSummary), BorderLayout.CENTER);
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(note("settings.help", "수동 속도과 대기 시간을 설정합니다. 로그인·쿠키/토큰 주입·세션 갱신은 제공하지 않습니다. 일반 작업에는 JSON 편집이 필요하지 않습니다."), BorderLayout.NORTH);
        footer.add(buttons(policyButton("settings.policyJson", "고급: 정책 JSON 가져오기 / 복사…", this::editPolicyJson),
                button("settings.diagnostics", "진단 정보…", this::diagnostics),
                button("settings.clear", "보관 기록 비우기…", () -> {
                    if (dialogs.confirm(this, "보관된 요청 기록과 화면 원문·사건 기록을 모두 지울까요? 누적 처리 수·열린 태그 사용량은 남을 수 있으며 복구할 수 없습니다.")) {
                        invalidateHistory(""); traffic = List.of(); trafficModel.setRows(List.of());
                        access.clearEvidence(); refreshNow(); message.setText("보관 기록과 화면 원문·사건을 비웠습니다. 열린 차단·태그 사용량은 별도입니다.");
                    }
                })), BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel trafficTab() {
        JPanel panel = new TrafficPanel();
        JPanel header = new JPanel(new BorderLayout(4, 4));
        JPanel quick = new JPanel(new BorderLayout(8, 0));
        quick.add(labeled("검색어 · 기본 Literal", search), BorderLayout.CENTER);
        quick.add(buttons(outcomeFilter, bookmarksOnly, button("traffic.reset", "필터 지우기", this::resetFilters)), BorderLayout.LINE_END);
        JPanel inputs = new JPanel(new BorderLayout(4, 4));
        inputs.add(quick, BorderLayout.NORTH);
        inputs.add(buttons(labeled("검색 위치", searchLocation), labeled("일치 방식", searchMode)), BorderLayout.CENTER);
        searchError.setVisible(false); inputs.add(searchError, BorderLayout.SOUTH);
        header.add(inputs, BorderLayout.NORTH);
        JPanel extra = new JPanel(new GridLayout(0, 4, 6, 4));
        extra.add(labeled("메서드 포함", methodFilter));
        extra.add(labeled("HTTP 상태 포함", statusFilter));
        extra.add(labeled("UTC 시각 포함", timeFilter));
        extra.add(labeled("프로젝트", projectFilter));
        extra.add(labeled("Intent 포함 (비신뢰 태그)", intentFilter));
        extra.add(labeled("Run 포함 (비신뢰 태그)", runFilter));
        extra.add(labeled("보호 상태 포함", stateFilter));
        extra.setVisible(false);
        JCheckBox more = named(new JCheckBox("상세 필터"), "traffic.more");
        more.addActionListener(e -> { extra.setVisible(more.isSelected()); header.revalidate(); });
        JPanel filterBottom = new JPanel(new BorderLayout());
        filterBottom.add(extra, BorderLayout.NORTH);
        filterBottom.add(buttons(more, trafficCount, resolve, button("traffic.detail", "선택 요청 상세…", this::openTrafficDetail),
                button("traffic.bookmark", "선택 요청 보관 / 해제", this::bookmarkSelected)), BorderLayout.SOUTH);
        header.add(filterBottom, BorderLayout.CENTER);
        panel.add(header, BorderLayout.NORTH);
        ((AbstractDocument) search.getDocument()).setDocumentFilter(new LengthLimit(4_096, () -> setSearchInput(TrafficSearch.Invalid.TOO_LONG)));
        listen(search, this::searchEdited);
        searchLocation.addItemListener(e -> { if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED) searchEdited(); });
        searchMode.addItemListener(e -> { if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED) searchEdited(); });
        for (JTextField filter : List.of(methodFilter, statusFilter, timeFilter, intentFilter, runFilter, stateFilter)) listen(filter, this::filtersEdited);
        DefaultListCellRenderer plain = new DefaultListCellRenderer();
        plain.putClientProperty("html.disable", Boolean.TRUE);
        projectFilter.setRenderer(plain); searchLocation.setRenderer(plain); searchMode.setRenderer(plain);
        projectFilter.addActionListener(e -> filtersEdited());
        outcomeFilter.addActionListener(e -> filtersEdited());
        bookmarksOnly.addItemListener(e -> filtersEdited());
        trafficTable.setUpdateSelectionOnSort(false);
        trafficTable.getSelectionModel().addListSelectionListener(e -> {
            if (selectionUpdates == 0) {
                rememberTrafficSelection();
                if (!e.getValueIsAdjusting()) showTrafficDetail();
            }
        });
        installOpenAction(trafficTable, this::openTrafficDetail, "두 번 클릭 또는 Enter: 민감정보가 포함된 메모리 원문 요청·응답 (화면 전용)");
        inlineInspector = new TrafficInspector(() -> stepTraffic(-1), () -> stepTraffic(1), this::showTrafficDetail);
        JSplitPane history = named(new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(trafficTable), inlineInspector), "traffic.history");
        history.setResizeWeight(0.55); history.setOneTouchExpandable(true); history.setContinuousLayout(true);
        history.setMinimumSize(new Dimension(80, 80));
        panel.add(history, BorderLayout.CENTER);
        trafficTable.getTableHeader().setReorderingAllowed(true);
        trafficTable.getRowSorter().addRowSorterListener(e -> {
            if (e.getType() == javax.swing.event.RowSorterEvent.Type.SORTED && selectionUpdates == 0) {
                replaceRows(trafficTable, trafficModel, trafficModel.rows, TrafficEntry::id);
                showTrafficDetail();
            }
        });
        trafficTable.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            { putClientProperty("html.disable", true); }
            @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(table, value, selected, focus, row, col);
                TrafficEntry entry = trafficModel.rows.get(table.convertRowIndexToModel(row));
                if (!selected) setForeground("BLOCKED".equals(entry.disposition()) ? new java.awt.Color(170, 65, 0) : table.getForeground());
                return this;
            }
        });
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(buttons(exportRange, exportFormat, button("traffic.export", "원문 내보내기 (평문)…",
                () -> chooseExport(exportRange.getSelectedIndex() == 1, exportFormat.getSelectedIndex() == 1))), BorderLayout.NORTH);
        footer.add(note("traffic.exportNotice", EXPORT_NOTICE), BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        JPanel result = new JPanel(new BorderLayout());
        JScrollPane scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder()); result.add(scroll, BorderLayout.CENTER);
        return result;
    }

    private static final class TrafficPanel extends JPanel implements Scrollable {
        TrafficPanel() { super(new BorderLayout(6, 6)); }
        @Override public Dimension getPreferredSize() {
            Dimension size = super.getPreferredSize(); BorderLayout layout = (BorderLayout) getLayout(); Insets insets = getInsets();
            size.height = layout.getLayoutComponent(BorderLayout.NORTH).getPreferredSize().height
                    + layout.getLayoutComponent(BorderLayout.SOUTH).getPreferredSize().height
                    + layout.getLayoutComponent(BorderLayout.CENTER).getMinimumSize().height + layout.getVgap() * 2 + insets.top + insets.bottom;
            return size;
        }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return getFontMetrics(getFont()).getHeight(); }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return Math.max(1, visible.height - getFontMetrics(getFont()).getHeight()); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return getParent() != null && getParent().getHeight() >= getPreferredSize().height; }
    }

    private JPanel incidentTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        JPanel form = new JPanel(new GridLayout(0, 1, 4, 6));
        form.add(note("incident.help", "보관된 응답 관측·5xx·크기 통계를 JSON 한 파일로 내보냅니다. 명시적 확인 후 각 사건·상위 경로의 원문 호스트·경로(평문)를 그 사건을 일으킨 요청의 보관 원문에서만 채우며, 원문이 없으면 ‘원문 없음’으로 표시합니다. UTC ISO-8601의 [시작, 끝) 창이며 기간 상한은 없습니다. 보관 시작 전·시계 역행·확산 누락·근사 여부는 번들에 표시되며 완전한 통신이나 대상 장애의 증거가 아닙니다."));
        form.add(labeled("시작 UTC (예: 2026-01-01T00:00:00Z)", incidentFrom));
        form.add(labeled("끝 UTC (시작 미포함 아님: [시작, 끝))", incidentTo));
        setIncidentHour();
        form.add(buttons(button("incident.lastHour", "최근 1시간 채우기", this::setIncidentHour),
                button("incident.export", "사건 JSON 내보내기 (원문 평문)…", this::exportIncident)));
        panel.add(form, BorderLayout.NORTH);
        return panel;
    }

    private void setIncidentHour() {
        Instant now = Instant.ofEpochMilli(System.currentTimeMillis());
        incidentFrom.setText(now.minusSeconds(3600).toString()); incidentTo.setText(now.toString());
    }

    private void resetIntentBudgets() {
        Snapshot base = beginEdit();
        if (!dialogs.confirm(this, "현재 프로젝트의 모든 (Run, Intent) 사용량을 초기화할까요? 이미 사용한 요청도 다시 예산을 쓸 수 있습니다. 태그는 클라이언트 주장으로 인증이 아닙니다. 명시한 정책과 속도 제한은 그대로입니다.", "사용량 초기화")) return;
        checkRuntimeVersion(base);
        access.resetIntentBudgets(base.projectId(), base.revision()); refreshNow();
        message.setText("태그 예산 사용량을 명시적으로 초기화했습니다. 정책은 저장하지 않았습니다.");
    }

    private void checkRuntimeVersion(Snapshot base) {
        access.refreshProject();
        if (closed || !base.matches(access.status())) { refreshNow(); throw failure("STALE_POLICY"); }
    }

    private static String utc(long millis) { try { return Instant.ofEpochMilli(millis).toString(); } catch (RuntimeException e) { return "—"; } }

    private void reviewMigration() {
        Snapshot base = beginEdit();
        Map<String,Object> data = Map.copyOf(access.migrationView());
        if (!Boolean.TRUE.equals(data.get("pending"))) { refreshNow(); return; }
        String original = migrationText(data, "original"); String migrated = migrationText(data, "migrated");
        JTextArea before = textArea("migration.original", false); before.setText(original);
        JTextArea after = textArea("migration.migrated", false); after.setText(migrated);
        JTextArea diff = textArea("migration.diff", false); diff.setText(migrationDiff(original, migrated));
        JCheckBox remove = named(new JCheckBox("정확한 원본 legacy delete-string 규칙만 제거 (선택 사항, 기본 미선택)"), "migration.removeLegacy");
        remove.addActionListener(e -> {
            String next = remove.isSelected() ? PolicyCodec.encode(PolicyCodec.removeLegacyDeleteString(base.policy())) : migrated;
            setDetail(after, next); setDetail(diff, migrationDiff(original, next));
        });
        JPanel content = new JPanel(new BorderLayout(4, 4));
        JTabbedPane compare = new JTabbedPane(); compare.addTab("변경 비교", new JScrollPane(diff)); compare.addTab("저장된 v1 원본", new JScrollPane(before)); compare.addTab("v2 메모리 변환", new JScrollPane(after));
        content.add(note("migration.explanation", "원본은 아직 저장소에 남아 있습니다. v2 새 감지는 OFF이며 기존 규칙은 유지합니다. 아래 제거는 별도 선택이며 원본과 정확히 같은 규칙만 제거합니다. 사용자 수정·중지·유사 이름 규칙은 그대로 둡니다. 취소/닫기는 저장하지 않습니다. 저장 후 구버전 확장은 v2를 읽지 못하므로 원본을 먼저 내보내세요."), BorderLayout.NORTH);
        content.add(compare, BorderLayout.CENTER);
        content.add(buttons(remove, button("migration.exportInReview", "원본 내보내기…", () -> exportOriginal(base, original))), BorderLayout.SOUTH);
        EditorForm<GuardConfig> form = new EditorForm<>() {
            @Override public JComponent component() { return content; }
            @Override public GuardConfig value() { return remove.isSelected() ? PolicyCodec.removeLegacyDeleteString(base.policy()) : PolicyCodec.toV2(base.policy()); }
        };
        dialogs.edit(this, "v1 → v2 변환 비교 (아직 저장 안 됨)", "v2 명시적 저장", form, () -> {
            if (!dialogs.confirm(this, "v1 원본을 v2 정책으로 교체하여 저장할까요? 기존 규칙 제거는 별도 체크한 경우만 적용합니다. 구버전 JAR는 v2 정책을 읽지 못합니다. 원본 내보내기를 먼저 권장합니다.", "v2 저장")) return;
            save(base, form.value(), true);
        });
    }
    private static String migrationText(Map<String,Object> data, String key) {
        if (!(data.get(key) instanceof String text) || text.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        return text;
    }
    private static String migrationDiff(String original, String migrated) {
        // Bounded line-oriented exact comparison, no quadratic LCS over an untrusted policy document.
        String[] before = original.split("\\R", -1); String[] after = migrated.split("\\R", -1);
        StringBuilder diff = new StringBuilder("- 저장 원본 / + 메모리 v2 (행 위치 비교; 원본·변환 탭에서 전체 확인)\n");
        for (int i = 0; i < Math.max(before.length, after.length) && diff.length() < MAX_EDITOR_CHARS - 8192; i++) {
            String a = i < before.length ? before[i] : null; String b = i < after.length ? after[i] : null;
            if (Objects.equals(a, b)) continue;
            if (a != null) diff.append("- ").append(a).append('\n');
            if (b != null) diff.append("+ ").append(b).append('\n');
        }
        if (diff.length() >= MAX_EDITOR_CHARS - 8192) diff.append("\n[비교 표시 잘림: 원본·변환 탭 참조]");
        return diff.toString();
    }
    private void exportOriginal() { Snapshot base = beginEdit(); exportOriginal(base, migrationText(access.migrationView(), "original")); }
    private void exportOriginal(Snapshot base, String original) {
        checkRuntimeVersion(base);
        if (original.isBlank()) throw failure("INVALID_BOUNDED_JSON");
        exportDocument("v1 원본 정책 (운영자 작성 값 포함)", () -> original, base);
    }

    private void exportIncident() {
        Snapshot base = beginEdit();
        long from; long to;
        try {
            String a = incidentFrom.getText(); String b = incidentTo.getText();
            if (!a.endsWith("Z") || !b.endsWith("Z")) throw new IllegalArgumentException();
            Instant start = Instant.parse(a); Instant end = Instant.parse(b);
            if (start.getNano() % 1_000_000 != 0 || end.getNano() % 1_000_000 != 0) throw new IllegalArgumentException();
            from = start.toEpochMilli(); to = end.toEpochMilli();
            if (to <= from) throw new IllegalArgumentException();
        } catch (RuntimeException e) { throw failure("INVALID_INCIDENT_WINDOW"); }
        exportHuman("사건 JSON", base, () -> access.humanIncident(from, to), "선택한 UTC 창 [" + utc(from) + ", " + utc(to) + ")의 사건");
    }

    /**
     * Explicitly consented HUMAN original export. Consent (plaintext secrets) is required even for a NEW file.
     * The immutable snapshot is created under the controller's lock; serialization and ALL filesystem work
     * run off the EDT and outside every runtime lock, with a final pre-publication checkpoint. There is an
     * unavoidable tiny race between that check and the atomic rename, and the Burp project is sampled, not
     * locked: this is a consented snapshot, not a transaction, and a clear cannot retract an exported file.
     */
    private void exportHuman(String label, Snapshot base, java.util.function.Supplier<GuardUiAccess.HumanExport> snapshot, String selection) {
        if (exportWorker != null) throw failure("EXPORT_IN_PROGRESS");
        Path choice = dialogs.chooseExport(this, label.contains("HAR") ? "har" : "json"); if (choice == null) return;
        ExportTarget target;
        try { target = inspectTarget(choice); } catch (IOException | RuntimeException e) { throw failure("EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE"); }
        if (!dialogs.confirm(this, label + " · " + selection + "\n" + PLAINTEXT_CONSENT
                + (target.existing() ? "\n선택한 기존 일반 파일을 덮어씁니다. 심볼릭 링크나 중간에 바뀐 파일은 덮어쓰지 않습니다." : "\n새 파일을 만듭니다."), "평문 원문 내보내기")) return;
        checkRuntimeVersion(base);
        final GuardUiAccess.HumanExport export;
        try { export = snapshot.get(); }
        catch (UnsupportedOperationException | IllegalArgumentException | IllegalStateException e) { throw failure("EXPORT_FAILED"); }
        message.setText(label + " 내보내는 중… (평문 원문, 크기 상한 없음)");
        exportWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() throws Exception {
                byte[] bytes;
                try { bytes = export.serialize(); }
                catch (IllegalStateException e) { throw new IOException("HUMAN_EXPORT_FAILED"); }
                if (isCancelled() || Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
                writeAtomic(target, bytes, () -> !isCancelled() && !closed && access.humanExportCurrent(export)); // project/revision/epoch/raw-generation
                return null;
            }
            @Override protected void done() {
                exportWorker = null; if (closed) return;
                try { get(); message.setText(label + " 내보내기 완료 · 평문 원문 포함 · 검사 사본이며 wire 증거가 아닙니다."); }
                catch (Exception e) { report("EXPORT_FAILED"); }
            }
        };
        exportWorker.execute();
    }

    private void exportDocument(String label, java.util.function.Supplier<String> source, Snapshot base) {
        if (exportWorker != null) throw failure("EXPORT_IN_PROGRESS");
        Path choice = dialogs.chooseExport(this, "json"); if (choice == null) return;
        ExportTarget target;
        try { target = inspectTarget(choice); } catch (IOException | RuntimeException e) { throw failure("EXPORT_TARGET_UNSAFE_OR_UNAVAILABLE"); }
        if (target.existing() && !dialogs.confirm(this, label + " 파일로 기존 일반 파일을 덮어쓸까요? 소유자 전용 권한으로 저장합니다. 심볼릭 링크나 중간에 바뀐 파일은 덮어쓰지 않습니다.")) return;
        checkRuntimeVersion(base);
        message.setText(label + " 내보내는 중…");
        exportWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() throws Exception {
                if (!base.matches(access.status())) throw new IOException("STALE_EXPORT");
                String text = source.get();
                if (isCancelled() || !base.matches(access.status())) throw new IOException("STALE_EXPORT");
                writeAtomic(target, text); return null;
            }
            @Override protected void done() {
                exportWorker = null; if (closed) return;
                try { get(); message.setText(label + " 내보내기 완료 · 화면 원문은 사용하지 않았습니다."); }
                catch (Exception e) { report("EXPORT_FAILED"); }
            }
        };
        exportWorker.execute();
    }

    private void configureRuleView() {
        TableRowSorter<RowsModel<Rule>> sorter = new TableRowSorter<>(rulesModel) {
            @Override public void setSortKeys(List<? extends RowSorter.SortKey> keys) {
                List<RowSorter.SortKey> pinned = new ArrayList<>(); pinned.add(new RowSorter.SortKey(4, SortOrder.ASCENDING));
                if (keys != null) for (var key : keys) if (key.getColumn() != 4) pinned.add(key);
                super.setSortKeys(pinned);
            }
        };
        sorter.setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.ASCENDING)));
        rulesTable.setRowSorter(sorter); rulesTable.removeColumn(rulesTable.getColumnModel().getColumn(4));
        rulesTable.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            { putClientProperty("html.disable", true); }
            @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(table, value, selected, focus, row, col);
                Rule rule = rulesModel.rows.get(table.convertRowIndexToModel(row));
                if (!selected) setForeground(rule.mode() == Mode.EXEMPT ? new java.awt.Color(180, 65, 0) : table.getForeground());
                setToolTipText(rule.mode() == Mode.EXEMPT ? "주의: 일반 BLOCK·ASK 무시. 범위와 가용성 제어는 유지됩니다." : null);
                return this;
            }
        });
    }

    private JPanel approvalTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(note("approval.help", "승인 요청 규칙에 걸린 요청만 한 번 승인할 수 있습니다. 메서드·주소·이유·원문 요청(보관된 화면 사본)을 먼저 확인하세요. 만료·설정 변경·프로젝트 변경·일시중지는 대기를 취소합니다. 필수 안전 차단은 여기에서 승인할 수 없습니다."), BorderLayout.NORTH);
        approvalTable.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting() && selectionUpdates == 0) showApprovalDetail(); });
        installOpenAction(approvalTable, this::reviewApproval, "두 번 클릭 또는 Enter: 원문 승인 증거 검토 (자동 승인하지 않음)");
        panel.add(new JScrollPane(approvalTable), BorderLayout.CENTER);
        panel.add(buttons(button("approval.review", "선택 요청 검토…", this::reviewApproval), approve, deny), BorderLayout.SOUTH);
        return panel;
    }

    private void reviewApproval() {
        if (selected(approvalTable, approvalModel) == null) throw failure("SELECT_PENDING_APPROVAL_FIRST");
        showApprovalDetail();
        showReadOnly("승인 요청 검토 · 화면 원문", new JScrollPane(approvalDetail));
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
                    blocked ? rows : old.blockScope(), old.rules(), old.defaultMode(), old.limits(), old.guardListenerPorts()));
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
                blocked ? rows : old.blockScope(), old.rules(), old.defaultMode(), old.limits(), old.guardListenerPorts()));
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
        return new GuardConfig(old.schemaVersion(), old.allowScope(), old.blockScope(), rows, old.defaultMode(), old.limits(), old.guardListenerPorts());
    }

    private void editSettings() {
        Snapshot base = beginEdit();
        SettingsEditor form = new SettingsEditor(base.policy());
        dialogs.edit(this, "요청 제어 설정", "저장하고 적용", form, () -> {
            SettingsEditor.Value value = form.value();
            GuardConfig old = base.policy();
            save(base, new GuardConfig(old.schemaVersion(), old.allowScope(), old.blockScope(), old.rules(), value.defaultMode(), value.limits(), value.guardListenerPorts()));
        });
    }

    private void editPolicyJson() {
        Snapshot base = beginEdit();
        JTextArea editor = textArea("advanced.policyJson", true);
        editor.setText(PolicyCodec.encode(base.policy()));
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
        dialogs.edit(this, "고급 · 전체 정책 JSON", "전체 정책 저장", form, () -> {
            GuardConfig value = form.value();
            if (PolicyCodec.decode(editor.getText()).migrationPending()
                    && !dialogs.confirm(this, "붙여넣은 v1 정책은 메모리에서 v2로 변환합니다. 새 감지 기능은 OFF, 기존 규칙은 그대로입니다. 전체 v2 정책을 명시적으로 저장할까요?")) return;
            save(base, value);
        });
    }

    private void diagnostics() {
        JTextArea detail = viewer("diagnostics.status");
        detail.setText(Json.write(latestStatus));
        showReadOnly("진단 정보 · 읽기 전용", new JScrollPane(detail));
    }

    private void openTrafficDetail() {
        if (selectedTrafficAnchor() == null) throw failure("SELECT_TRAFFIC_FIRST");
        if (popoutInspector != null) return;
        TrafficInspector owned = new TrafficInspector(() -> stepTraffic(-1), () -> stepTraffic(1), this::showTrafficDetail);
        popoutInspector = owned;
        try {
            showTrafficDetail();
            showReadOnly("요청 상세 · 민감정보 포함 원문 화면 (내보내기는 평문 동의 후)", owned);
        } finally {
            owned.clear("");
            if (popoutInspector == owned) popoutInspector = null;
            if (!closed) showTrafficDetail();
        }
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

    private void save(Snapshot base, GuardConfig candidate) { save(base, candidate, false); }
    private void save(Snapshot base, GuardConfig candidate, boolean migrationConfirmed) {
        requireEdt();
        if (closed) throw failure("CLOSED");
        access.refreshProject();
        Map<String, Object> current = access.status();
        if (!base.matches(current) || Boolean.TRUE.equals(current.get("closed"))) {
            refreshNow(); throw failure("STALE_POLICY");
        }
        try { candidate = PolicyCodec.toV2(candidate); new PolicyEngine().validate(candidate); }
        catch (RuntimeException e) { throw failure("INVALID_POLICY"); }
        PolicyCodec.encode(candidate); // A saved policy must fit the strict project-load limit as a whole.
        if (candidate.equals(PolicyCodec.toV2(base.policy())) && !Boolean.TRUE.equals(migration.get("pending"))) {
            message.setText("변경한 내용이 없어 기존 설정을 유지했습니다.");
            return;
        }
        if (Boolean.TRUE.equals(migration.get("pending")) && !migrationConfirmed
                && !dialogs.confirm(this, "v1 변환 대기 중입니다. 이 명시적 저장은 v2 전체 정책으로 저장소를 교체합니다. 원본 내보내기·변환 비교를 먼저 권장합니다. 기존 delete-string 제거는 자동으로 하지 않습니다. 구버전 JAR는 v2를 읽지 못합니다. 계속 저장할까요?", "v2 저장")) return;
        if (candidate.rules().stream().anyMatch(r -> r.enabled() && r.mode() == Mode.EXEMPT && !base.policy().rules().contains(r))
                && !dialogs.confirm(this, "EXEMPT 예외를 저장할까요? 일치하는 일반 BLOCK·ASK 규칙을 무시합니다. 정확한 메서드·경로 등 최소 조건인지 확인하세요. 실제 대상 범위·일시중지·속도·태그 예산은 계속 적용됩니다.", "EXEMPT 저장")) return;
        if (!candidate.guardListenerPorts().equals(base.policy().guardListenerPorts())) {
            if (!candidate.guardListenerPorts().isEmpty()) throw failure("LISTENER_SELECTION_DEFERRED");
            if (!dialogs.confirm(this, "기존 포트 제한을 해제하고 모든 Proxy 리스너를 보호할까요? 포트별 보호는 추후 지원합니다. 이제 모든 Proxy 요청이 대상 범위·규칙·안전 제어의 검사 대상이며, 전체 통과(보호 OFF)가 아닙니다. 기존 설정을 자동 삭제하지 않고 이 명시적 저장으로만 전환합니다.", "전체 Proxy 보호로 전환")) return;
        }
        if (candidate.limits().healthProbePassthrough() && (!base.policy().limits().healthProbePassthrough()
                || !candidate.limits().healthProbePaths().equals(base.policy().limits().healthProbePaths()))
                && !dialogs.confirm(this, "GET 상태 확인 통과를 저장할까요? GET도 부작용이 있을 수 있습니다. 명시한 정확한 경로만 운영자 일시중지를 통과합니다. 범위·일반 규칙·다른 속도·예산은 유지됩니다.", "GET 통과 저장")) return;
        access.refreshProject();
        if (!base.matches(access.status())) { refreshNow(); throw failure("STALE_POLICY"); }
        try { access.updateConfig(candidate, base.projectId(), base.revision()); }
        catch (IllegalStateException e) { refreshNow(); throw failure("UPDATE_REJECTED"); }
        catch (IllegalArgumentException e) { throw failure("INVALID_POLICY"); }
        refreshNow();
        message.setText(Boolean.TRUE.equals(latestStatus.get("passthrough"))
                ? "설정을 저장했습니다. 현재는 전체 통과 상태이므로 보호를 다시 켜야 검사합니다."
                : "설정을 저장했습니다. 현재 프로젝트에 적용했으며 이전 승인 대기는 취소됩니다.");
    }

    private void togglePause() {
        if (!available) {
            // Snapshot/render failures must not strand OFF without a way to block new requests.
            // This path can ONLY block, never resume or grant passthrough on stale state.
            try { access.pause(true); } finally { refreshNow(); }
            message.setText("새 요청 차단을 요청했습니다. 상태 표시가 복구될 때까지 요청 발생을 멈추고 Burp를 확인하세요.");
            return;
        }
        Snapshot base = beginEdit();
        boolean next = !Boolean.TRUE.equals(latestStatus.get("paused"));
        if (!next && view != null && view.policy().allowScope().stream().noneMatch(ScopeEntry::enabled)
                && !dialogs.confirm(this, "보호를 재개해도 허용 대상이 없어 모든 요청을 계속 차단합니다. 먼저 대상을 등록하는 것이 좋습니다. 그래도 재개할까요?")) return;
        access.refreshProject();
        if (!base.matches(access.status())) { refreshNow(); throw failure("MODE_CHANGE_REJECTED"); }
        try { access.pause(next); }
        finally { refreshNow(); } // Failed resume must not leave a misleading toggled control.
        message.setText(next ? "일시중지했습니다. 모든 Proxy 리스너의 새 요청을 차단합니다 (명시한 상태 확인 GET 제외)." : "보호를 재개했습니다. 대상 범위·속도·예산은 계속 적용됩니다.");
    }

    private void togglePassthrough() {
        Snapshot base = beginEdit();
        boolean next = !Boolean.TRUE.equals(latestStatus.get("passthrough"));
        if (next && !dialogs.confirm(this,
                "모두 통과 (보호 끔)로 전환할까요?\n\n"
                + "이 Burp의 모든 Proxy 요청이 허용 대상·차단 규칙·안전 검사·승인·속도 제한 없이 통과합니다. 빈 허용 목록이나 차단 대상도 적용하지 않습니다. 워커가 실행 중이면 범위 밖 요청도 나갈 수 있습니다.\n\n"
                + "운영자 일시중지도 전체 통과 중에는 새 요청을 막지 않습니다. ‘보호 다시 켜기’는 이전 운영자 일시중지를 보존합니다. 태그 사용량·사용량은 유지됩니다.\n\n"
                + "전환 전 승인·전송 대기 요청은 자동 승인하지 않고 취소합니다. 필요한 요청만 다시 실행하세요. 이미 전송한 요청은 취소하지 않습니다.\n\n"
                + "전체 통과 상태에서 새로 시작한 요청·응답 내용을 이 확장에서 수집·기록하지 않고 통과 횟수를 셉니다. 오인 연결 방지용 숫자 ID만 확장 수명 동안 메모리에 보존하며 내용·증거와 연결하지 않습니다. 이전에 보호하여 전송한 요청은 실제 응답까지 추적하고 화면 사본·원문 증거를 남길 수 있습니다. Burp 자체 history는 별개입니다.\n\n"
                + "현재 프로젝트의 임시 상태이며 프로젝트 전환·확장 재시작 후에는 유지하지 않습니다. 다시 보호를 켜기 전에 요청 발생을 멈추고 기존 연결이 끝났는지 확인하세요.", "모두 통과")) return;
        if (closed) throw failure("CLOSED");
        access.refreshProject();
        if (!base.matches(access.status())) { refreshNow(); throw failure("MODE_CHANGE_REJECTED"); }
        try { access.passthrough(next, base.projectId(), base.revision()); }
        catch (IllegalStateException e) { throw failure("MODE_CHANGE_REJECTED"); }
        finally { refreshNow(); }
        message.setText(next ? "전체 통과 · 보호 꺼짐. 새 요청은 검사하지 않으며 그 요청·응답 기록을 수집하지 않습니다."
                : "새 요청에 보호를 다시 적용합니다. 전체 통과 중 이미 시작한 요청을 취소하거나 추적하지는 않습니다.");
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
            if (view != null && !view.matches(after)) invalidateHistory("");
            view = new Snapshot(config, projectId(after), revision(after));
            latestStatus = Map.copyOf(after);
            migration = Map.copyOf(access.migrationView());
            if (!sameVersion(after, access.status())) throw failure("PROJECT_UNAVAILABLE");
            migrationBanner.setVisible(Boolean.TRUE.equals(migration.get("pending")));
            available = true;
            allowModel.setRows(config.allowScope()); blockModel.setRows(config.blockScope());
            replaceRows(rulesTable, rulesModel, config.rules(), Rule::id);
            traffic = List.copyOf(access.traffic());
            if (!sameVersion(after, access.status())) throw failure("PROJECT_UNAVAILABLE");
            updateProjects(); filterTraffic();
            replaceRows(approvalTable, approvalModel, access.approvals().stream().limit(100).toList(), Pending::id);
            approvalTable.repaint(); // Remaining time changes without mutating pending records.
            showApprovalDetail();
            updateOverview(config, after);
            updateSettings(config);
            if (!sameVersion(after, access.status())) throw failure("PROJECT_UNAVAILABLE");
            version.setText("현재 Burp 프로젝트 · 설정 버전 " + view.revision());
            for (JButton action : policyActions) action.setEnabled(true);
            pause.setEnabled(true);
            passthrough.setEnabled(Boolean.TRUE.equals(after.get("passthrough")) || !Boolean.FALSE.equals(after.get("passthroughAvailable")));
            if (message.getText().equals("현재 상태를 확인하고 있습니다…")) message.setText("준비됐습니다. 허가받은 대상을 등록하고 보호 상태를 확인하세요.");
        } catch (RuntimeException e) {
            available = false;
            invalidateHistory("현재 프로젝트 확인 후 요청을 다시 선택하세요.");
            traffic = List.of(); trafficModel.setRows(List.of());
            setDetail(approvalDetail, "");
            migrationBanner.setVisible(false);
            for (JButton action : policyActions) action.setEnabled(false);
            pause.setText("긴급: 새 요청 모두 차단"); pause.setEnabled(!closed);
            passthrough.setEnabled(false); approve.setEnabled(false); deny.setEnabled(false);
            protectionState.setText(Boolean.TRUE.equals(latestStatus.get("passthrough")) ? "상태 확인 불가 · 전체 통과일 수 있음" : "보호 상태 확인 불가");
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
        boolean off = Boolean.TRUE.equals(status.get("passthrough"));
        boolean ended = Boolean.TRUE.equals(status.get("passthroughEnded"));
        protectionState.setText(off ? "전체 통과 · 보호 꺼짐 · 새 기록 미수집" : (ended ? "전체 통과 자동 종료 · " : "") + (paused ? "새 요청 차단 중 (보호 리스너)" : "보호 켜짐")
                + (config.guardListenerPorts().isEmpty() ? "" : " · 이전 포트 제한 남음 (포트별 보호 추후) " + config.guardListenerPorts() + " · 새 Proxy 모두 거절"));
        protectionState.setIcon(off ? UIManager.getIcon("OptionPane.warningIcon") : null);
        passthroughCounter.setText("전체 통과 누적 " + count(status, "passthroughCount") + "건");
        passthrough.setText(off ? "보호 다시 켜기" : "모두 통과 (보호 끔)…");
        passthrough.setToolTipText(off ? "새 요청에 범위·규칙·검사·속도 제한을 다시 적용합니다."
                : Boolean.FALSE.equals(status.get("passthroughAvailable")) ? "프로젝트 정책 재확인이 필요하여 전체 통과로 전환할 수 없습니다."
                : "모든 Proxy 요청의 보호를 임시로 끕니다. 기존 대기 요청을 자동 승인하지 않습니다.");
        passthrough.getAccessibleContext().setAccessibleDescription(passthrough.getToolTipText());
        String note = Objects.toString(status.get("note"), "");
        String guard = Objects.toString(status.get("guardState"), paused ? "PAUSED_BY_OPERATOR" : "PROTECTED");
        Map<?,?> watcher = nested(status, "watchers");
        Map<?,?> intents = nested(status, "intents");
        setDetail(diagnosis, "로컬 guardState: " + UiText.guardState(guard) + " (" + guard + ") · 운영자 일시중지 보존: " + yes(status.getOrDefault("operatorPaused", status.get("paused")))
                + "\n로컬 451은 source=cairn-proxy-guard / local=true인 확장 거절이며 대상 서버의 5xx와 다릅니다. 대상 응답이 없다는 사실만으로 장애를 단정하지 마세요."
                + "\n응답 관측: " + count(watcher, "observations") + " · 태그 사용 " + count(intents, "consumed")
                + " / 거절 " + count(intents, "rejected"));
        setDetail(warnings, "자동 차단 기능은 제거되었습니다. 이전 응답·미확인 콜백은 새 요청을 차단하지 않습니다.");
        Object reasons = status.get("reasonCounters");
        setDetail(reasonCounters, "이유별 누적 (로컬 범주): " + Json.write(reasons instanceof Map<?,?> ? reasons : Map.of()));
        if (off) {
            stateTitle.setText("전체 통과 · 보호 꺼짐 · 기록 미수집");
            stateHelp.setText("이 Burp의 모든 새 Proxy 요청을 범위·규칙·안전 검사·승인·속도 제한 없이 통과시킵니다. 전체 통과 누적 "
                    + count(status, "passthroughCount") + "건 (대상 도착 증명 아님). 새 전체 통과 요청·응답 내용은 수집하지 않습니다. 표에는 이전 보호 기록이 남으며 기존 전송의 화면 사본·원문 증거가 추가될 수 있습니다. Burp 자체 history는 별개입니다.\n"
                    + "기존 승인·전송 대기는 취소되며 이미 전송한 요청은 취소하지 않습니다. 이전 운영자 일시중지·태그 사용량은 보존됩니다. 다시 보호를 켜기 전에 요청 발생을 멈추고 전체 통과 중 시작한 연결이 끝났는지 확인하세요. 상단 ‘보호 다시 켜기’로 새 요청에 보호를 재적용하거나 ‘새 요청 모두 차단’으로 전송을 막을 수 있습니다.");
        } else if (Set.of("POLICY_INVALID", "POLICY_SAVE_UNCERTAIN", "PROJECT_UNVERIFIED", "SHUTDOWN").contains(guard)) {
            stateTitle.setText("프로젝트 설정 확인 필요 · 새 요청 차단");
            stateHelp.setText("프로젝트 설정을 읽거나 저장한 결과를 확인할 수 없습니다. 요청 발생을 멈추고 Burp 프로젝트를 확인한 뒤 새로고침하세요. 확인 전에는 재개하지 마세요.");
        } else if (paused) {
            stateTitle.setText("일시중지 · 보호 리스너의 새 요청 차단");
            stateHelp.setText("보호할 새 요청을 차단합니다 (명시한 상태 확인 GET은 별도). OFF 모드가 아닙니다. 이번 범위는 전체 Proxy 보호입니다. 이전 포트 제한이 남아 있으면 모두 LISTENER_UNVERIFIED로 거절되므로 설정에서 직접 비우고 전체 보호로 전환하세요. ‘보호 재개’는 운영자 일시중지만 해제하고 기존 태그 사용량은 유지합니다. OFF 후 다시 켜도 기존 운영자 일시중지를 보존합니다.");
        } else if (allowed == 0) {
            stateTitle.setText("허용 대상 없음 · 모든 요청 차단");
            stateHelp.setText("아직 요청을 보낼 수 없습니다. ‘허용 대상 등록’에서 허가받은 URL을 입력하고 호스트·포트·경로를 확인하세요. 등록하지 않은 대상은 계속 차단합니다.");
        } else {
            stateTitle.setText("보호 중 · 등록한 대상만 검사 후 전송");
            stateHelp.setText("허용 대상 " + allowed + "개와 사용 중인 규칙 " + rules + "개를 적용합니다. 승인 요청은 ‘승인 대기’, 차단 이유는 ‘요청 기록’에서 확인하세요."
                    + (note.equals("PROTECTION_RESTORED") ? " 전체 통과 중 이미 시작한 요청은 취소·추적하지 않으며 새 요청부터 보호합니다." : ""));
        }
        if (ended) stateHelp.setText("전체 통과가 프로젝트 변경 또는 상태 불확실성으로 자동 종료되었습니다. " + stateHelp.getText());
        pause.setText(paused ? "보호 재개" : "새 요청 모두 차단");
        scopeCount.setText("대상 · 허용 " + allowed + "개 / 차단 " + blocked + "개");
        ruleCount.setText("규칙 · " + rules + "개 사용 중");
        gateCount.setText("수동 속도 전송 대기 " + count(gate, "queued") + " / 승인 대기 " + approvalModel.rows.size());
        evidenceCount.setText("누적 · 차단 " + count(evidence, "blocked") + " / 전송 해제 " + count(evidence, "forwarded") + " / 보관 " + traffic.size());
        tabs.setTitleAt(4, "승인 대기" + (approvalModel.rows.isEmpty() ? "" : " (" + approvalModel.rows.size() + ")"));
        scopeState.setText(off ? "전체 통과 · 보호 꺼짐: 아래 범위를 검사하지 않습니다. 상단 ‘보호 다시 켜기’ 후 새 요청에 적용합니다."
                : allowed == 0 ? "사용 중인 허용 대상이 없습니다. 모든 Proxy 요청을 차단합니다. ‘허용 대상 추가’로 시작하세요."
                : "허용 대상 " + allowed + "개 · 차단 대상 " + blocked + "개 사용 중. 차단 대상과 필수 안전 검사가 항상 우선합니다.");
        TrafficEntry latest = traffic.stream().filter(e -> e.projectId().equals(view.projectId()) && "BLOCKED".equals(e.disposition())).findFirst().orElse(null);
        recentBlock.setText(latest == null ? "현재 프로젝트의 보관 기록에 차단된 요청이 없습니다. 요청 결과는 ‘요청 기록’에서 확인하세요."
                : UiText.reason(latest.reason()) + "\n" + UiText.next(latest.reason()));
    }

    private void updateSettings(GuardConfig config) {
        GuardConfig.Limits l = config.limits();
        String summary = "수동 고정 속도 (0=끔)\n전체 RPS: " + l.globalRps()
                + "\n기본 호스트 RPS: " + l.perHostRps() + "\n호스트별 RPS (독립, 0=끔): " + l.hostRps()
                + "\n전송 대기열: " + l.maxQueued() + " / 제한 " + seconds(l.queueTimeoutMillis()) + "초"
                + "\n승인 대기 제한: " + seconds(l.approvalTimeoutMillis()) + "초"
                + "\n기본 동작: " + UiText.mode(config.defaultMode().name())
                + "\n(Run, Intent) 요청 예산: " + l.perIntentMaxRequests() + " (0=끔; 개요에서 명시적 초기화)"
                + "\n상태 확인 GET의 운영자 일시중지 통과: " + l.healthProbePassthrough()
                + "\n보호 Proxy 리스너: " + (config.guardListenerPorts().isEmpty() ? "모두" : config.guardListenerPorts())
                + "\n\nINACTIVE legacy: 동시 요청·응답 시간 제한·대용량·5xx 회로·확산·감지 예외 설정은 호환용으로만 보존되며 실행되지 않습니다."
                + "\n이전 요청의 응답이나 완료 콜백을 기다리지 않습니다. 실제 native 동시 실행 수는 제한하지 않습니다."
                + "\n설정 폼의 ‘모든 속도 제한 끄기’는 호스트별 값도 0으로 채우는 미저장 초안 작업입니다. 전체/기본 호스트 0만으로 양수 호스트별 값을 지우지 않습니다.";
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
        loading = true;
        try {
            search.setText(""); searchLocation.setSelectedItem(TrafficSearch.Location.ALL); searchMode.setSelectedItem(TrafficSearch.MatchMode.LITERAL);
            methodFilter.setText(""); statusFilter.setText(""); timeFilter.setText("");
            intentFilter.setText(""); runFilter.setText(""); stateFilter.setText("");
            projectFilter.setSelectedItem(ALL_PROJECTS); outcomeFilter.setSelectedIndex(0); bookmarksOnly.setSelected(false);
        } finally { loading = false; }
        searchEdited();
    }

    private void searchEdited() {
        if (closed || loading) return;
        setSearchInput(TrafficSearch.compile(new TrafficSearch.Query(search.getText(),
                (TrafficSearch.Location) searchLocation.getSelectedItem(), (TrafficSearch.MatchMode) searchMode.getSelectedItem())));
    }
    private void setSearchInput(TrafficSearch.Input input) {
        if (closed) return;
        searchInput = input;
        String error = input instanceof TrafficSearch.Invalid invalid ? switch (invalid) {
            case BAD_RE2 -> "[BAD_RE2] 지원하지 않거나 잘못된 RE2 식입니다. 결과 없음. 식을 고치거나 Literal을 선택하세요.";
            case TOO_LONG -> "[TOO_LONG] 4,096자 초과 편집을 거부하고 검색을 중지했습니다. 입력·위치·방식 편집 또는 필터 지우기로 복구하세요.";
            case TOO_COMPLEX -> "[TOO_COMPLEX] RE2 프로그램이 4,096 instructions를 넘습니다. 식을 줄이세요. 결과 없음.";
        } : "";
        setDetail(searchError, error); searchError.setVisible(!error.isEmpty());
        filtersEdited();
    }

    private void filtersEdited() {
        if (closed || loading || !available) return;
        rememberTrafficSelection();
        refreshNow();
    }

    private void rememberTrafficSelection() {
        TrafficEntry lead = selectedTrafficAnchor();
        trafficSelection = new TrafficSelection(ids(trafficTable, trafficModel, TrafficEntry::id), lead == null ? null : lead.id());
    }

    private void filterTraffic() {
        if (closed || loading || !available) return;
        if (!(searchInput instanceof TrafficSearch.CompiledQuery query)) {
            trafficSelection = new TrafficSelection(Set.of(), null);
            contentSearch.clear(); replaceRows(trafficTable, trafficModel, List.of(), TrafficEntry::id); clearPresentation("");
            resolve.setEnabled(false); updateTrafficNavigation();
            trafficCount.setText("0개 표시 / " + traffic.size() + "개 보관 · 검색 입력 오류 (invalid search)");
            return;
        }
        List<TrafficSearch.Subject> subjects = new ArrayList<>();
        for (TrafficEntry entry : traffic) subjects.add(new TrafficSearch.Subject(entry,
                Boolean.TRUE.equals(access.rawCaptureInfo(entry.id()).get("available")),
                List.of(screenUrl(entry), screenMethod(entry), entry.timestamp(), entry.statusCode() == null ? "" : entry.statusCode().toString(),
                        entry.reason(), UiText.reason(entry.reason()), entry.id())));
        contentSearch.update(query, subjects, this::refreshNow);
        String project = (String) projectFilter.getSelectedItem();
        String outcome = switch (outcomeFilter.getSelectedIndex()) { case 1 -> "BLOCKED"; case 2 -> "FORWARDED"; case 3 -> "PENDING"; case 4 -> "exempt"; case 5 -> "probe_allowed"; default -> ""; };
        List<TrafficEntry> displayed = new ArrayList<>();
        Set<String> retainedSelection = new HashSet<>();
        for (TrafficSearch.Subject subject : subjects) {
            TrafficEntry entry = subject.entry();
            String status = entry.statusCode() == null ? "" : entry.statusCode().toString();
            if (bookmarksOnly.isSelected() && !entry.bookmarked()
                    || project != null && !project.equals(ALL_PROJECTS) && !project.equals(entry.projectId())
                    || !outcome.isEmpty() && !(outcome.equals("PENDING") ? isWaiting(entry.disposition()) : outcome.equals(entry.disposition()) || outcome.equals(entry.outcome()))
                    || !contains(screenMethod(entry), methodFilter.getText()) || !contains(status, statusFilter.getText())
                    || !contains(entry.timestamp(), timeFilter.getText()) || !contains(screenTag(entry, "intentId"), intentFilter.getText())
                    || !contains(screenTag(entry, "runId"), runFilter.getText())
                    || !(contains(entry.guardState(), stateFilter.getText()) || contains(UiText.guardState(entry.guardState()), stateFilter.getText()))) continue;
            boolean hit = contentSearch.hit(subject);
            if (trafficSelection.ids().contains(entry.id()) && (hit || contentSearch.pending(subject))) retainedSelection.add(entry.id());
            if (hit) displayed.add(entry);
        }
        trafficSelection = new TrafficSelection(retainedSelection, trafficSelection.leadId());
        replaceRows(trafficTable, trafficModel, displayed, TrafficEntry::id);
        boolean filtered = !search.getText().isEmpty() || !methodFilter.getText().isEmpty() || !statusFilter.getText().isEmpty()
                || !timeFilter.getText().isEmpty() || !intentFilter.getText().isEmpty() || !runFilter.getText().isEmpty() || !stateFilter.getText().isEmpty()
                || !ALL_PROJECTS.equals(project) || !outcome.isEmpty() || bookmarksOnly.isSelected();
        trafficCount.setText(displayed.size() + "개 표시 / " + traffic.size() + "개 보관" + (filtered ? " · 필터 적용 중" : "")
                + (contentSearch.failed() ? " · 검색 실패: 불완전 결과 (search failed)" : contentSearch.pending() ? " · 내용 검색 중 (pending)" : ""));
        showTrafficDetail();
    }

    private static boolean isWaiting(String disposition) { return Set.of("PENDING", "AWAITING_APPROVAL", "QUEUED").contains(disposition); }
    private static String trafficOutcome(TrafficEntry entry) {
        return UiText.outcome(isWaiting(entry.disposition()) || "ERROR".equals(entry.disposition()) || entry.outcome().isEmpty() ? entry.disposition() : entry.outcome());
    }
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
        if (inlineInspector == null || closed) return;
        TrafficEntry entry = selectedTrafficAnchor();
        if (!available || entry == null) {
            clearPresentation("");
            inlineInspector.metadata("요청을 선택하면 결과·이유·다음 행동을 볼 수 있습니다.");
            resolve.setEnabled(false); updateTrafficNavigation(); return;
        }
        boolean original = Boolean.TRUE.equals(access.rawCaptureInfo(entry.id()).get("available"));
        String metadata = screenMetadata(entry);
        resolve.setEnabled(targetTab(entry.reason()) >= 0);
        if (!original) {
            clearPresentation(""); inlineInspector.unavailable(); inlineInspector.metadata(metadata);
            if (popoutInspector != null) { popoutInspector.unavailable(); popoutInspector.metadata(metadata); }
            updateTrafficNavigation(); return;
        }
        PresentationKey key = new PresentationKey(entry.id(), entry.requestCapture(), entry.responseCapture(),
                screenMethod(entry) + " " + screenUrl(entry) + " HTTP/1.1 (inspection copy)",
                "HTTP/1.1 " + (entry.statusCode() == null ? "unknown" : entry.statusCode()) + " (inspection copy)", metadata);
        if (!key.same(presentationKey)) {
            clearPresentation("선택한 원문 사본 처리 중…"); presentationKey = key;
        }
        inlineInspector.metadata(metadata); inlineInspector.reason(trafficOutcome(entry) + " · " + UiText.reason(entry.reason()));
        if (popoutInspector != null) { popoutInspector.metadata(metadata); popoutInspector.reason(trafficOutcome(entry) + " · " + UiText.reason(entry.reason())); }
        updateTrafficNavigation();
        if (presentationFailed) return;
        boolean wantPreview = inlineInspector.wantsPreview() || popoutInspector != null && popoutInspector.wantsPreview();
        if (presenting && presentingPreview != wantPreview) { presentation.cancel(); presentationGeneration++; presenting = false; }
        if (presentedContent != null) {
            inlineInspector.install(presentedContent); if (popoutInspector != null) popoutInspector.install(presentedContent);
            if (wantPreview && (presentedPreview != null || previewReason != null)) { installPreview(); return; }
            if (!wantPreview) return;
        }
        if (presenting) return;
        presenting = true; presentingPreview = wantPreview;
        TrafficInspector.Content ready = presentedContent;
        if (wantPreview) { inlineInspector.previewMessage("Static preview pending…"); if (popoutInspector != null) popoutInspector.previewMessage("Static preview pending…"); }
        long generation = ++presentationGeneration; Snapshot source = view;
        presentation.submit(cancelled -> {
            TrafficInspector.Content content = ready != null ? ready : TrafficInspector.project(key.request(), key.response(), key.requestLine(), key.responseLine(), cancelled);
            String reason = wantPreview ? HtmlPreview.unavailable(key.response(), cancelled) : null;
            HtmlPreview.Projection preview = wantPreview && reason == null ? HtmlPreview.scan(key.response().body(), cancelled) : null;
            return new PresentationResult(content, preview, reason);
        }, result -> {
            if (closed || generation != presentationGeneration) return;
            // Refresh immutable source/availability and bracket project/revision on the EDT before publication.
            refreshNow();
            if (!available || !source.matches(latestStatus) || generation != presentationGeneration || !key.same(presentationKey)) return;
            presenting = false;
            if (result.failed()) {
                presentationFailed = true;
                inlineInspector.clear("Inspection presentation unavailable (processing failed).");
                if (popoutInspector != null) popoutInspector.clear("Inspection presentation unavailable (processing failed).");
                return;
            }
            PresentationResult output = (PresentationResult) result.value();
            presentedContent = output.content(); presentedPreview = output.preview(); previewReason = output.reason();
            inlineInspector.install(presentedContent); if (popoutInspector != null) popoutInspector.install(presentedContent);
            if (wantPreview) installPreview();
        });
    }
    private void installPreview() {
        if (presentedPreview != null) {
            if (inlineInspector.wantsPreview()) inlineInspector.preview(presentedPreview);
            if (popoutInspector != null && popoutInspector.wantsPreview()) popoutInspector.preview(presentedPreview);
        } else if (previewReason != null) {
            inlineInspector.previewMessage("Static preview unavailable: " + previewReason);
            if (popoutInspector != null) popoutInspector.previewMessage("Static preview unavailable: " + previewReason);
        }
    }
    private void clearPresentation(String reason) {
        presentationGeneration++; presentation.cancel(); presentationKey = null; presentedContent = null;
        presentedPreview = null; previewReason = null; presenting = false; presentationFailed = false;
        if (inlineInspector != null) inlineInspector.clear(reason);
        if (popoutInspector != null) popoutInspector.clear(reason);
    }
    private void invalidateHistory(String reason) {
        trafficSelection = new TrafficSelection(Set.of(), null);
        contentSearch.clear(); clearPresentation(reason);
        if (popoutInspector != null && SwingUtilities.getWindowAncestor(popoutInspector) instanceof JDialog dialog) dialog.dispose();
    }
    private int trafficAnchorRow() {
        int lead = trafficTable.getSelectionModel().getLeadSelectionIndex();
        return lead >= 0 && lead < trafficTable.getRowCount() && trafficTable.isRowSelected(lead) ? lead : -1;
    }
    private TrafficEntry selectedTrafficAnchor() {
        int index = modelIndex(trafficTable, trafficAnchorRow(), trafficModel.rows.size());
        return index < 0 ? null : trafficModel.rows.get(index);
    }
    private void updateTrafficNavigation() {
        if (inlineInspector == null) return;
        int lead = trafficAnchorRow();
        boolean anchor = lead >= 0;
        inlineInspector.navigation(anchor && lead > 0, anchor && lead + 1 < trafficTable.getRowCount());
        if (popoutInspector != null) popoutInspector.navigation(anchor && lead > 0, anchor && lead + 1 < trafficTable.getRowCount());
    }
    private void stepTraffic(int delta) {
        int lead = trafficAnchorRow(), next = lead + delta;
        if (closed || !available || lead < 0 || next < 0 || next >= trafficTable.getRowCount()) return;
        trafficTable.setRowSelectionInterval(next, next); trafficTable.scrollRectToVisible(trafficTable.getCellRect(next, 0, true));
    }
    private String captureState(TrafficEntry entry, boolean request) {
        if (!Boolean.TRUE.equals(access.rawCaptureInfo(entry.id()).get("available"))) return "원문 없음";
        TrafficEntry.Message message = request ? entry.requestCapture() : entry.responseCapture();
        return (!message.present() ? "없음" : message.truncated() || message.bodyOmitted() ? "불완전" : "보관됨") + " · " + message.bodyEncoding();
    }

    private static void setDetail(JTextArea area, String text) {
        if (!area.getText().equals(text)) { area.setText(text); area.setCaretPosition(0); }
    }

    private String screenUrl(TrafficEntry entry) {
        String raw = access == null ? null : access.rawUrl(entry.id());
        return raw == null ? "[원문 사본 없음] " + entry.url() : raw;
    }
    private String screenTag(TrafficEntry entry, String key) {
        Map<String,Object> info = access == null ? Map.of() : access.rawCaptureInfo(entry.id());
        Object raw = info.get(key);
        return raw instanceof String value ? value : "[원문 없음] " + (key.equals("intentId") ? entry.intentId() : entry.runId());
    }
    private String screenMethod(TrafficEntry entry) {
        Object raw = access == null ? null : access.rawCaptureInfo(entry.id()).get("method");
        return raw instanceof String value ? value : "[원문 없음] " + entry.method();
    }
    private String screenContent(String id, boolean request) {
        String text = request ? access.rawRequest(id) : access.rawResponse(id);
        return RAW_NOTICE + "\n\n" + (text == null ? "[원문 없음/지움/미수집 · OFF/미선택 리스너는 새 내용을 수집하지 않음]" : text);
    }
    private String screenMetadata(TrafficEntry entry) {
        Map<String,Object> info = access.rawCaptureInfo(entry.id());
        return screenUrl(entry) + "\n" + RAW_NOTICE + "\n"
                + "화면 원문 보관: " + (Boolean.TRUE.equals(info.get("available")) ? "있음" : "없음/만료")
                + " · 요청 잘림 " + yes(info.get("requestTruncated")) + " · 요청 생략 " + yes(info.get("requestOmitted"))
                + " · 응답 잘림 " + yes(info.get("responseTruncated")) + " · 응답 생략 " + yes(info.get("responseOmitted"))
                + "\n본문 표시: " + Objects.toString(info.get("requestBodyDisplay"), "미수집") + " / " + Objects.toString(info.get("responseBodyDisplay"), "미수집")
                + " (지원하지 않는 문자셋/바이너리는 보관한 바이트의 HEX일 수 있음)"
                + "\n비신뢰 Intent: " + screenTag(entry, "intentId") + " · Run: " + screenTag(entry, "runId")
                + "\n\n진단 메타데이터 (화면 원문 · 없으면 ‘원문 없음’)\n" + metadata(entry, info);
    }
    private static String yes(Object value) { return value instanceof Boolean b ? b ? "예" : "아니오" : "확인 불가"; }

    private String metadata(TrafficEntry entry, Map<String, Object> info) {
        boolean original = Boolean.TRUE.equals(info.get("available"));
        StringBuilder result = new StringBuilder(screenMethod(entry)).append(" ").append(screenUrl(entry)).append("\n\n")
                .append(trafficOutcome(entry)).append(" · ").append(UiText.reason(entry.reason()))
                .append("\n\n다음 행동\n").append(UiText.next(entry.reason())).append("\n\n일치 규칙\n");
        List<?> rawHits = original && info.get("hits") instanceof List<?> list ? list : null;
        if (rawHits == null) result.append("원문 없음/만료 · 일치 규칙 원문을 표시할 수 없습니다.\n");
        else if (rawHits.isEmpty()) result.append("해당 없음 (대상 범위 또는 필수 검사에서 먼저 차단될 수 있습니다.)\n");
        else for (Object hit : rawHits) {
            Map<?, ?> h = (Map<?, ?>) hit;
            result.append("• ").append(h.get("name")).append(" — ").append(UiText.mode(String.valueOf(h.get("mode")))).append("\n");
        }
        return result.append("\n").append(EXPORT_NOTICE).append("\n\n상세 진단\n증거 ID: ").append(entry.id())
                .append("\n프로젝트: ").append(original ? Objects.toString(info.get("projectId"), "") + " / " + Objects.toString(info.get("projectName"), "") : "[원문 없음]").append("\n시각 (UTC): ").append(entry.timestamp())
                .append("\n정책 동작: ").append(UiText.mode(entry.mode())).append("\n진단 코드: ").append(entry.reason())
                .append("\nHTTP 상태: ").append(entry.statusCode() == null ? "없음" : entry.statusCode())
                .append("\n정책 버전: ").append(entry.revision())
                .append("\n보호 상태: ").append(UiText.guardState(entry.guardState())).append(" / ").append(entry.guardState())
                .append("\n결과: ").append(entry.outcome()).append("\n이전 형식 자동 차단 ID (현재 비활성): ").append(entry.overlayId())
                .append("\n실제 응답 본문 bytes: ").append(entry.responseBytes())
                .append("\n검사 경고: ").append(UiText.warnings(entry.inspectionWarnings(), true))
                .append("\n헤더/본문 규칙은 검사 가능할 때만 평가합니다. 검사 불가를 평가 완료로 간주하지 않으며 불완전 조건으로 EXEMPT를 부여하지 않습니다.")
                .append("\n내용 잘림: ").append(entry.truncated() ? "있음" : "없음")
                .append("\n요청 본문 생략: ").append(entry.requestCapture().bodyOmitted() ? "예" : "아니오")
                .append("\n응답 본문 생략: ").append(entry.responseCapture().bodyOmitted() ? "예" : "아니오").toString();
    }

    private void resolveSelected() {
        TrafficEntry entry = selectedTrafficAnchor();
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
            case "RULE_BLOCK", "RULE_MATCH", "EXEMPT" -> 2;
            case "ASK" -> 4;
            case "DEFAULT_BLOCK", "QUEUE_TIMEOUT", "QUEUE_FULL", "INTENT_BUDGET_EXCEEDED", "INTENT_TAG_INVALID", "INVALID_INTENT_TAG", "LISTENER_UNVERIFIED" -> 5;
            case "PAUSED", "POLICY_CHANGED", "PROJECT_CHANGED" -> 0;
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
        // Controller-issued evidence UUID is the identity; never join on a project label.
        return traffic.stream().filter(e -> e.id().equals(pending.evidenceId())).findFirst().orElse(null);
    }
    private Object[] approvalValues(Pending pending) {
        TrafficEntry entry = evidence(pending);
        Map<String, Object> info = entry == null ? Map.of() : access.rawCaptureInfo(entry.id());
        List<?> hits = info.get("hits") instanceof List<?> list ? list : List.of();
        return new Object[]{entry == null ? "—" : screenMethod(entry), entry == null ? "증거가 보관되어 있지 않음" : screenUrl(entry),
                entry == null ? "증거 없음 · 승인 불가" : !hits.isEmpty() ? String.valueOf(((Map<?, ?>) hits.getFirst()).get("name")) : UiText.reason(entry.reason()),
                remaining(pending) > 0 ? remaining(pending) + "초" : "만료됨"};
    }
    private static long remaining(Pending pending) {
        try { long millis = Duration.between(Instant.now(), Instant.parse(pending.expiresAt())).toMillis(); return millis <= 0 ? 0 : (millis + 999) / 1000; }
        catch (DateTimeParseException | ArithmeticException e) { return 0; }
    }

    private boolean currentPending(Pending pending) {
        return available && !closed && view != null && pending != null && pending.projectId().equals(view.projectId())
                && !Boolean.TRUE.equals(latestStatus.get("paused")) && !Boolean.TRUE.equals(latestStatus.get("passthrough"))
                && !Boolean.TRUE.equals(latestStatus.get("closed")) && remaining(pending) > 0;
    }

    private void showApprovalDetail() {
        Pending pending = selected(approvalTable, approvalModel);
        TrafficEntry entry = pending == null ? null : evidence(pending);
        boolean current = currentPending(pending);
        approve.setEnabled(current && entry != null && entry.revision() == view.revision());
        deny.setEnabled(current);
        if (pending == null) {
            setDetail(approvalDetail, approvalModel.rows.isEmpty() ? "승인을 기다리는 요청이 없습니다.\n차단된 요청은 여기에서 해제할 수 없습니다. ‘요청 기록’에서 차단 이유를 확인하세요."
                    : "검토할 요청을 표에서 선택하세요. 메서드·주소·이유와 원문 요청을 확인한 뒤 결정하세요.");
        } else {
            setDetail(approvalDetail, ("승인 기한 (UTC): " + pending.expiresAt() + " · " + (current ? "검토 가능" : "현재 승인할 수 없음")
                    + "\n승인은 이 요청에 한 번만 적용됩니다. 최종 안전 검사와 수동 속도 제한은 유지됩니다.\n\n"
                    + (entry == null ? UiText.error("APPROVAL_EVIDENCE_MISSING") : metadata(entry, access.rawCaptureInfo(entry.id())) + "\n\n" + screenContent(entry.id(), true))
                    + "\n\n승인 ID: " + pending.id() + "\n증거 ID: " + pending.evidenceId() + "\n만료 (UTC): " + pending.expiresAt()));
        }
    }

    private void decide(boolean allow) {
        Pending pending = selected(approvalTable, approvalModel);
        if (pending == null) throw failure("SELECT_PENDING_APPROVAL_FIRST");
        access.refreshProject();
        Map<String, Object> status = access.status();
        if (!currentPending(pending) || !pending.projectId().equals(projectId(status))
                || Boolean.TRUE.equals(status.get("paused")) || Boolean.TRUE.equals(status.get("passthrough")) || Boolean.TRUE.equals(status.get("closed"))
                || access.approvals().stream().noneMatch(p -> p.equals(pending))) {
            refreshNow(); throw failure("APPROVAL_STALE_OR_EXPIRED");
        }
        if (allow) {
            // Re-read the retained evidence; a timer's old row is not sufficient for approval.
            TrafficEntry entry = access.traffic().stream().filter(e -> e.id().equals(pending.evidenceId())).findFirst().orElse(null);
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
        Snapshot base = beginEdit();
        List<String> ids = entries.stream().map(TrafficEntry::id).toList();
        exportHuman(har ? "HAR 1.2" : "JSON", base, () -> access.humanExport(ids, har), entries.size() + "개 요청 (현재 표 선택)"
                + (contentSearch.pending() || contentSearch.failed() ? " · search pending/failed: only currently visible rows (or selected visible rows), results incomplete · 검색 중/실패: 현재 표시된 요청만, 불완전 결과" : ""));
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
        writeAtomic(choice, Objects.requireNonNull(text).getBytes(StandardCharsets.UTF_8), () -> true);
    }
    static void writeAtomic(ExportTarget choice, byte[] content, java.util.function.BooleanSupplier stillCurrent) throws IOException {
        Objects.requireNonNull(content);
        Path target = choice.path(); Path parent = target.getParent();
        boolean posix = Files.getFileStore(parent).supportsFileAttributeView("posix");
        FileAttribute<?>[] attrs = posix ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))} : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(parent, ".cairn-guard-", ".tmp", attrs);
        BasicFileAttributes reservation = null; boolean published = false;
        try {
            BasicFileAttributes initialTemp = safeAttributes(temp);
            try (java.io.OutputStream out = Files.newOutputStream(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) { out.write(content); }
            BasicFileAttributes writtenTemp = safeAttributes(temp);
            // Known file keys survive provider creation-time drift; absent keys retain the timestamp fallback.
            if (!Objects.equals(initialTemp.fileKey(), writtenTemp.fileKey())
                    || initialTemp.fileKey() == null && !initialTemp.creationTime().equals(writtenTemp.creationTime())) throw new IOException("TEMP_CHANGED");
            if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
            if (choice.existing()) {
                if (!sameFileState(choice.original(), safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            } else { Files.createFile(target, attrs); reservation = safeAttributes(target); }
            BasicFileAttributes expected = choice.existing() ? choice.original() : reservation;
            if (!sameFileState(expected, safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            // Final pre-publication checkpoint (briefly takes the controller lock, released BEFORE the rename).
            // A transition observed here aborts and removes only this task's temp/reservation; a change after
            // this check but before the atomic rename cannot be prevented.
            if (!stillCurrent.getAsBoolean()) throw new IOException("STALE_EXPORT");
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
        if (text == null || text.isBlank() || text.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        try { return PolicyCodec.decode(text).config(); }
        catch (Exception e) { throw failure("INVALID_BOUNDED_JSON"); }
    }
    private static String boundedJson(Object value) {
        String text = Json.write(value);
        if (text.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        return text;
    }
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
        JPanel panel = new JPanel(new WrappingFlowLayout(FlowLayout.LEADING, 6, 3));
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
    /** Read-only full-content viewer for retained originals: scrollable, selectable, NO length filter. */
    private static JTextArea viewer(String name) {
        JTextArea area = named(new JTextArea(8, 38), name); area.setEditable(false); area.setLineWrap(false); return area;
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
        if (name.equals("traffic.table")) table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setSelectionMode(multi ? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION : ListSelectionModel.SINGLE_SELECTION);
        DefaultTableCellRenderer plain = new DefaultTableCellRenderer(); plain.putClientProperty("html.disable", Boolean.TRUE);
        table.setDefaultRenderer(String.class, plain); table.setFillsViewportHeight(true); table.getTableHeader().setReorderingAllowed(false);
        if (table.getTableHeader().getDefaultRenderer() instanceof JComponent renderer) renderer.putClientProperty("html.disable", Boolean.TRUE);
        table.addPropertyChangeListener("font", e -> table.setRowHeight(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 10)));
        table.setRowHeight(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 10));
        int[] widths = name.startsWith("scope.") ? new int[]{80, 220, 180, 90, 420}
                : name.equals("rules.table") ? new int[]{80, 250, 220, 520}
                : name.equals("approval.table") ? new int[]{90, 430, 280, 110}
                : new int[]{60, 190, 100, 460, 160, 90, 340, 180, 180, 180, 260};
        for (int col = 0; col < table.getColumnCount(); col++) table.getColumnModel().getColumn(col).setPreferredWidth(col < widths.length ? widths[col] : 180);
        return table;
    }
    /** Local navigation only: Enter/double-click opens the same guarded editor/review as its button. */
    private void installOpenAction(JTable table, Runnable action, String hint) {
        table.setToolTipText(hint);
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "guard.openRow");
        table.getActionMap().put("guard.openRow", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent event) {
                if (table.getSelectedRow() >= 0) guarded(action);
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent event) {
                int row = table.rowAtPoint(event.getPoint());
                if (!closed && SwingUtilities.isLeftMouseButton(event) && event.getClickCount() == 2 && row >= 0) {
                    table.setRowSelectionInterval(row, row);
                    guarded(action);
                }
            }
        });
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
        Set<String> selection = table == trafficTable ? trafficSelection.ids() : ids(table, model, id);
        String leadId = table == trafficTable ? trafficSelection.leadId() : null;
        boolean adjusting = table.getSelectionModel().getValueIsAdjusting();
        selectionUpdates++;
        table.getSelectionModel().setValueIsAdjusting(true);
        try {
            model.setRows(rows); selectId(table, model.rows, id, selection);
            if (leadId != null) for (int i = 0; i < trafficModel.rows.size(); i++) if (leadId.equals(trafficModel.rows.get(i).id())) {
                int row = trafficTable.convertRowIndexToView(i);
                if (row >= 0 && trafficTable.isRowSelected(row)) ((DefaultListSelectionModel) trafficTable.getSelectionModel()).moveLeadSelectionIndex(row);
                break;
            }
        }
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
        if (component instanceof AbstractButton button) component.getAccessibleContext().setAccessibleDescription(button.getText());
        return component;
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
        pause.setEnabled(false); passthrough.setEnabled(false); approve.setEnabled(false); deny.setEnabled(false);
        protectionState.setText("확장 종료 · 보호 상태 확인 불가");
        invalidateHistory(""); contentSearch.close(); presentation.close();
        trafficModel.setRows(List.of()); traffic = List.of();
        setDetail(approvalDetail, "");
        migration = Map.of();
        dialogs.closeEditors();
        version.setText("확장 종료 · 설정 변경과 승인 불가");
    }

    interface Dialogs {
        boolean confirm(Component parent, String message);
        default boolean confirm(Component parent, String message, String confirmLabel) { return confirm(parent, message); }
        Path chooseExport(Component parent, String extension);
        void error(Component parent, String message);
        void edit(Component parent, String title, String saveLabel, EditorForm<?> form, Runnable save);
        default void closeEditors() {}
    }
    static final class SwingDialogs implements Dialogs {
        private final Set<JDialog> editors = new HashSet<>();
        @Override public void closeEditors() { for (JDialog dialog : List.copyOf(editors)) dialog.dispose(); }
        @Override public boolean confirm(Component parent, String message) { return confirm(parent, message, "확인"); }
        @Override public boolean confirm(Component parent, String message, String confirmLabel) {
            boolean[] accepted = {false};
            JDialog dialog = messageDialog(parent, confirmLabel.equals("모두 통과") ? "경고 · 보호를 끄고 모두 통과" : "확인");
            JButton cancel = named(new JButton("취소"), "dialog.cancel");
            JButton confirm = named(new JButton(confirmLabel), "dialog.confirm");
            cancel.addActionListener(e -> dialog.dispose());
            confirm.addActionListener(e -> { accepted[0] = true; dialog.dispose(); });
            dialog.setContentPane(new MessagePane(message, cancel, confirm));
            dialog.getRootPane().setDefaultButton(cancel); // Enter must never accidentally disable protection.
            showMessage(dialog, parent);
            return accepted[0];
        }
        @Override public Path chooseExport(Component parent, String extension) {
            JFileChooser chooser = new JFileChooser(); chooser.setDialogTitle("Cairn Guard · 로컬 파일 내보내기");
            chooser.setFileFilter(new FileNameExtensionFilter(extension.toUpperCase(Locale.ROOT), extension));
            return chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath() : null;
        }
        @Override public void error(Component parent, String message) {
            JDialog dialog = messageDialog(parent, "확인 필요");
            JButton close = named(new JButton("닫기"), "dialog.close");
            close.addActionListener(e -> dialog.dispose());
            dialog.setContentPane(new MessagePane(message, close));
            dialog.getRootPane().setDefaultButton(close);
            showMessage(dialog, parent);
        }
        private static JDialog messageDialog(Component parent, String title) {
            JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(parent), "Cairn Guard · " + title, Dialog.ModalityType.APPLICATION_MODAL);
            dialog.setName("message.dialog"); dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            dialog.setResizable(true);
            dialog.getRootPane().registerKeyboardAction(e -> dialog.dispose(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
            return dialog;
        }
        private void showMessage(JDialog dialog, Component parent) {
            dialog.pack();
            fitDialog(dialog, parent, Math.min(760, dialog.getWidth()), 520);
            dialog.validate();
            MessagePane pane = (MessagePane) dialog.getContentPane();
            int height = pane.heightForWidth(pane.getWidth()) + dialog.getInsets().top + dialog.getInsets().bottom;
            fitDialog(dialog, parent, dialog.getWidth(), Math.min(520, height));
            editors.add(dialog);
            try { dialog.setVisible(true); } finally { editors.remove(dialog); dialog.dispose(); }
        }
        private static void fitDialog(JDialog dialog, Component parent, int preferredWidth, int preferredHeight) {
            var gc = parent.getGraphicsConfiguration();
            if (gc == null) gc = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration();
            Rectangle bounds = gc.getBounds();
            Insets insets = java.awt.Toolkit.getDefaultToolkit().getScreenInsets(gc);
            int width = Math.max(1, bounds.width - insets.left - insets.right - 32);
            int height = Math.max(1, bounds.height - insets.top - insets.bottom - 32);
            dialog.setMinimumSize(new Dimension(Math.min(360, width), Math.min(220, height)));
            dialog.setSize(Math.min(Math.max(360, preferredWidth), width), Math.min(Math.max(220, preferredHeight), height));
            dialog.setLocationRelativeTo(parent);
            int x = Math.max(bounds.x + insets.left, Math.min(dialog.getX(), bounds.x + bounds.width - insets.right - dialog.getWidth()));
            int y = Math.max(bounds.y + insets.top, Math.min(dialog.getY(), bounds.y + bounds.height - insets.bottom - dialog.getHeight()));
            dialog.setLocation(x, y);
        }
        @Override public void edit(Component parent, String title, String saveLabel, EditorForm<?> form, Runnable save) {
            JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(parent), "Cairn Guard · " + title, Dialog.ModalityType.APPLICATION_MODAL);
            dialog.setName("editor.dialog"); dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            JPanel content = new JPanel(new BorderLayout(8, 8)); content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            JComponent editor = form.component(); editor.setMinimumSize(new Dimension(0, 0));
            content.add(editor, BorderLayout.CENTER);
            JTextArea feedback = note("editor.feedback", saveLabel.equals("닫기") ? "이 창을 닫는 것만으로 설정을 저장하거나 요청을 승인하지 않습니다." : SAVE_NOTICE);
            JButton submit = named(new JButton(saveLabel), "editor.save");
            JButton cancel = named(new JButton("취소"), "editor.cancel");
            cancel.setToolTipText("변경하지 않고 닫기");
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
            fitDialog(dialog, parent, 980, 800);
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
