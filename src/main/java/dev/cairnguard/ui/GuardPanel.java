package dev.cairnguard.ui;

import com.fasterxml.jackson.databind.DeserializationFeature;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.runtime.ApprovalQueue.Pending;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
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
import java.awt.FlowLayout;
import java.awt.GridLayout;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Local human controls only. All access except redacted export serialization/writes stays on the EDT. */
@SuppressWarnings("serial") // Swing runtime objects are deliberately never serialized or persisted.
public final class GuardPanel extends JPanel implements AutoCloseable {
    private static final long serialVersionUID = 1L;
    static final int MAX_EDITOR_CHARS = 2_097_152;
    private static final int MAX_ROWS = 2_000;
    private static final String ALL_PROJECTS = "All projects";
    private static final String EXPORT_NOTICE = "REDACTED evidence only: bounded callback inspection copies, NOT complete wire capture or proof of delivery. "
            + "Credentials are masked; bodies may be omitted and entries truncated/evicted. Export only the displayed filtered or selected rows.";

    private final GuardUiAccess access;
    private final Dialogs dialogs;
    private final Timer timer;
    private final JLabel message = named(new JLabel("Ready"), "message");
    private final JLabel baselineLabel = named(new JLabel("No policy draft loaded"), "draft.baseline");
    private final JButton apply = named(new JButton("Apply ALL policy drafts"), "draft.apply");
    private final JTextArea dashboard = textArea("dashboard.status", false);
    private final JCheckBox paused = named(new JCheckBox("Pause new Proxy requests (fail closed)"), "dashboard.paused");
    private final JTextArea rulesEditor = textArea("rules.json", true);
    private final JTextArea allowEditor = textArea("scope.allow", true);
    private final JTextArea blockEditor = textArea("scope.block", true);
    private final JTextArea hostEditor = textArea("settings.hostRps", true);
    private final JComboBox<Mode> defaultMode = named(new JComboBox<>(Mode.values()), "settings.defaultMode");
    private final JComboBox<Mode> ruleMode = named(new JComboBox<>(Mode.values()), "rules.mode");
    private final JSpinner globalRps = spinner("settings.globalRps", 5, 1, 1_000);
    private final JSpinner perHostRps = spinner("settings.perHostRps", 5, 1, 1_000);
    private final JSpinner maxConcurrent = spinner("settings.maxConcurrent", 5, 1, 100);
    private final JSpinner maxQueued = spinner("settings.maxQueued", 100, 0, 10_000);
    private final JSpinner queueTimeout = spinner("settings.queueTimeoutMillis", 30_000, 1, 600_000);
    private final JSpinner approvalTimeout = spinner("settings.approvalTimeoutMillis", 30_000, 1, 600_000);
    private final JSpinner requestTimeout = spinner("settings.requestTimeoutMillis", 60_000, 1, 600_000);
    private final RowsModel<Rule> rulesModel = new RowsModel<>(
            new String[]{"Enabled", "ID", "Name", "Mode"},
            new Class<?>[]{Boolean.class, String.class, String.class, String.class},
            r -> new Object[]{r.enabled(), r.id(), r.name(), r.mode() == null ? "" : r.mode().name()});
    private final JTable rulesTable = table("rules.table", rulesModel, false);
    private final RowsModel<TrafficEntry> trafficModel = new RowsModel<>(
            new String[]{"Bookmark", "Time (UTC)", "Method", "Masked URL", "Status", "Mode", "Disposition", "Project"},
            new Class<?>[]{Boolean.class, String.class, String.class, String.class, Integer.class, String.class, String.class, String.class},
            e -> new Object[]{e.bookmarked(), e.timestamp(), e.method(), e.url(), e.statusCode(), e.mode(), e.disposition(), e.projectId()});
    private final JTable trafficTable = table("traffic.table", trafficModel, true);
    private final JTextField search = textField("traffic.search");
    private final JTextField methodFilter = textField("traffic.method");
    private final JTextField statusFilter = textField("traffic.status");
    private final JTextField timeFilter = textField("traffic.time");
    private final JComboBox<String> projectFilter = named(new JComboBox<>(new String[]{ALL_PROJECTS}), "traffic.project");
    private final JCheckBox bookmarksOnly = named(new JCheckBox("Bookmarked only"), "traffic.bookmarked");
    private final JTextArea requestDetail = textArea("traffic.request", false);
    private final JTextArea responseDetail = textArea("traffic.response", false);
    private final JTextArea trafficDetail = textArea("traffic.metadata", false);
    private final RowsModel<Pending> approvalModel = new RowsModel<>(
            new String[]{"Approval ID", "Evidence ID", "Project", "Created", "Expires"},
            new Class<?>[]{String.class, String.class, String.class, String.class, String.class},
            p -> new Object[]{p.id(), p.evidenceId(), p.projectId(), p.createdAt(), p.expiresAt()});
    private final JTable approvalTable = table("approval.table", approvalModel, false);
    private final JTextArea approvalDetail = textArea("approval.detail", false);
    private List<TrafficEntry> traffic = List.of();
    private GuardConfig baseline;
    private String baselineProjectId;
    private long baselineRevision;
    private boolean dirty;
    private boolean stale;
    private boolean loading;
    private boolean closed;
    private SwingWorker<Void, Void> exportWorker;

    public GuardPanel(GuardUiAccess access) {
        this(access, new SwingDialogs(), true);
    }

    // In-process headless tests can replace only human dialogs; not an agent/network API.
    GuardPanel(GuardUiAccess access, Dialogs dialogs, boolean startTimer) {
        requireEdt();
        this.access = Objects.requireNonNull(access);
        this.dialogs = Objects.requireNonNull(dialogs);
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JPanel header = new JPanel(new BorderLayout());
        header.add(baselineLabel, BorderLayout.CENTER);
        header.add(buttons(button("draft.reload", "Reload policy / discard drafts", this::reloadRequested), apply), BorderLayout.EAST);
        apply.addActionListener(e -> guarded(this::applyDraft));
        add(header, BorderLayout.NORTH);
        JTabbedPane tabs = named(new JTabbedPane(), "tabs");
        tabs.addTab("Dashboard", dashboardTab());
        tabs.addTab("Rules", rulesTab());
        tabs.addTab("Scope", scopeTab());
        tabs.addTab("Traffic", trafficTab());
        tabs.addTab("Approval", approvalTab());
        tabs.addTab("Settings", settingsTab());
        add(tabs, BorderLayout.CENTER);
        add(message, BorderLayout.SOUTH);
        installDraftTracking();
        timer = new Timer(1_000, e -> refreshNow());
        timer.setCoalesce(true);
        refreshNow();
        if (startTimer) timer.start();
    }

    private JPanel dashboardTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        paused.addActionListener(e -> guarded(() -> {
            access.pause(paused.isSelected());
            refreshNow();
        }));
        panel.add(buttons(paused, button("dashboard.refresh", "Refresh", this::refreshNow),
                button("dashboard.clear", "Clear retained evidence…", () -> {
                    if (dialogs.confirm(this, "Clear retained redacted evidence? Aggregate counters may remain; this cannot be undone.")) {
                        access.clearEvidence();
                        refreshNow();
                    }
                })), BorderLayout.NORTH);
        panel.add(new JScrollPane(dashboard), BorderLayout.CENTER);
        panel.add(note("FORWARDED means native release, not confirmed delivery. A stalled in-flight request closes new admissions; "
                + "never reset permits to guess completion. Quiesce native traffic before starting a fresh run."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel rulesTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(buttons(button("rules.preview", "Parse / preview draft", this::previewRules),
                button("rules.add", "Add disabled rule", this::addRule),
                button("rules.delete", "Delete selected", () -> mutateRule(null)),
                button("rules.toggle", "Toggle selected", () -> mutateRule(r -> new Rule(r.id(), r.name(), !r.enabled(), r.mode(), r.condition()))),
                ruleMode, button("rules.setMode", "Set selected mode", () -> mutateRule(r -> new Rule(r.id(), r.name(), r.enabled(),
                        (Mode) ruleMode.getSelectedItem(), r.condition())))), BorderLayout.NORTH);
        rulesTable.getSelectionModel().addListSelectionListener(e -> {
            Rule rule = selected(rulesTable, rulesModel);
            if (rule != null) ruleMode.setSelectedItem(rule.mode());
        });
        panel.add(split(new JScrollPane(rulesTable), titled("Full rules JSON list — edit names, LEAF / AND / OR conditions, then Apply ALL drafts", rulesEditor), 0.3), BorderLayout.CENTER);
        panel.add(note("Rule changes are LOCAL DRAFTS until Apply. Mode: BLOCK > ASK > ALLOW; MONITOR never overrides a hard block. "
                + "Use field METHOD / URL / PATH / QUERY / HEADER / BODY / JSON / FORM / ANY; RE2 REGEX, EXACT or CONTAINS. "
                + "AND / OR use children. JSON selectors use RFC6901 pointers. No request or authentication editor."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel scopeTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(note("An empty or fully disabled allowlist BLOCKS ALL traffic. Block scope dominates allow. "
                + "Edit enabled, exact host (or explicit *.subdomains), scheme (http/https/any), port (0=any), pathRegex (full path only). "
                + "New examples are disabled, exact example.test / HTTPS:443 / path '/'; no automatic broad wildcard."), BorderLayout.NORTH);
        JPanel allow = new JPanel(new BorderLayout());
        allow.add(buttons(button("scope.addAllow", "Add disabled allow example", () -> addScope(allowEditor))), BorderLayout.NORTH);
        allow.add(titled("Allow scope JSON list", allowEditor), BorderLayout.CENTER);
        JPanel block = new JPanel(new BorderLayout());
        block.add(buttons(button("scope.addBlock", "Add disabled block example", () -> addScope(blockEditor))), BorderLayout.NORTH);
        block.add(titled("Block scope JSON list", blockEditor), BorderLayout.CENTER);
        panel.add(split(allow, block, 0.5), BorderLayout.CENTER);
        return panel;
    }

    private JPanel settingsTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        JPanel fields = new JPanel(new GridLayout(0, 2, 6, 4));
        addField(fields, "Global requests / second (1–1000)", globalRps);
        addField(fields, "Default per-host requests / second (1–1000)", perHostRps);
        addField(fields, "Max concurrent (1–100)", maxConcurrent);
        addField(fields, "Max queued (0–10000)", maxQueued);
        addField(fields, "Queue timeout ms (1–600000)", queueTimeout);
        addField(fields, "Approval timeout ms (1–600000)", approvalTimeout);
        addField(fields, "In-flight timeout ms (1–600000; closes gate, never frees permits)", requestTimeout);
        addField(fields, "Default rule mode (scope/inspection blocks still mandatory)", defaultMode);
        panel.add(fields, BorderLayout.NORTH);
        panel.add(titled("Exact-host overrides JSON: {\"hostRps\":{\"example.test\":2}}; empty map uses per-host default", hostEditor), BorderLayout.CENTER);
        panel.add(note("Apply ALL drafts validates atomically and updates the live shared limiter; it cancels old pending approvals. "
                + "Pacing has no idle burst credit. Lower concurrency does not revoke existing sends. "
                + "All editors are bounded to 2 MiB characters. Project/revision changes require an explicit reload."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel trafficTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        JPanel filters = new JPanel(new GridLayout(0, 2, 4, 4));
        addField(filters, "Literal search (masked URL / method / time / status / reason / ID)", search);
        addField(filters, "Method contains", methodFilter);
        addField(filters, "Status contains", statusFilter);
        addField(filters, "Timestamp contains (ISO UTC)", timeFilter);
        addField(filters, "Project ID", projectFilter);
        filters.add(bookmarksOnly);
        filters.add(button("traffic.bookmark", "Toggle selected bookmark(s)", this::bookmarkSelected));
        panel.add(filters, BorderLayout.NORTH);
        for (JTextField filter : List.of(search, methodFilter, statusFilter, timeFilter))
            listen(filter, this::filterTraffic);
        DefaultListCellRenderer projectRenderer = new DefaultListCellRenderer();
        projectRenderer.putClientProperty("html.disable", Boolean.TRUE);
        projectFilter.setRenderer(projectRenderer);
        projectFilter.addActionListener(e -> { if (!loading) filterTraffic(); });
        bookmarksOnly.addActionListener(e -> filterTraffic());
        trafficTable.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showTrafficDetail(); });
        JTabbedPane details = named(new JTabbedPane(), "traffic.details");
        details.addTab("Metadata / rule hits", new JScrollPane(trafficDetail));
        details.addTab("Masked request (read only)", new JScrollPane(requestDetail));
        details.addTab("Masked response (read only)", new JScrollPane(responseDetail));
        panel.add(split(new JScrollPane(trafficTable), details, 0.5), BorderLayout.CENTER);
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(note(EXPORT_NOTICE), BorderLayout.CENTER);
        footer.add(buttons(button("traffic.filteredJson", "Export FILTERED JSON…", () -> chooseExport(false, false)),
                button("traffic.filteredHar", "Export FILTERED HAR…", () -> chooseExport(false, true)),
                button("traffic.selectedJson", "Export SELECTED JSON…", () -> chooseExport(true, false)),
                button("traffic.selectedHar", "Export SELECTED HAR…", () -> chooseExport(true, true))), BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel approvalTab() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(note("Human-only, one-shot decisions for currently pending ASK requests. Hard scope/inspection BLOCKS cannot be approved. "
                + "Timeout, changed policy/project, pause and shutdown deny pending work. No rate/concurrency permits are held while waiting."), BorderLayout.NORTH);
        approvalTable.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showApprovalDetail(); });
        panel.add(split(new JScrollPane(approvalTable), new JScrollPane(approvalDetail), 0.4), BorderLayout.CENTER);
        panel.add(buttons(button("approval.approve", "Approve selected ONCE", () -> decide(true)),
                button("approval.deny", "Deny selected", () -> decide(false))), BorderLayout.SOUTH);
        return panel;
    }

    private void installDraftTracking() {
        for (JTextArea editor : List.of(rulesEditor, allowEditor, blockEditor, hostEditor)) {
            ((AbstractDocument) editor.getDocument()).setDocumentFilter(new LengthLimit(MAX_EDITOR_CHARS,
                    () -> message.setText("EDITOR_LENGTH_LIMIT — input rejected; max 2 MiB characters")));
            listen(editor, this::markDirty);
        }
        for (JSpinner spinner : limitSpinners()) spinner.addChangeListener(e -> markDirty());
        defaultMode.addActionListener(e -> markDirty());
    }

    private List<JSpinner> limitSpinners() {
        return List.of(globalRps, perHostRps, maxConcurrent, maxQueued, queueTimeout, approvalTimeout, requestTimeout);
    }

    private void markDirty() {
        if (!loading) { dirty = true; updateBaselineLabel(); }
    }

    private void reloadRequested() {
        if (!dirty || dialogs.confirm(this, "Discard ALL unsaved policy drafts and reload the current project policy?")) {
            access.refreshProject();
            loadDraft();
            refreshNow();
        }
    }

    private void loadDraft() {
        // Pair config with a coherent status; never assign the new project's baseline to an old config.
        Map<String, Object> before = access.status();
        GuardConfig config = access.config();
        Map<String, Object> after = access.status();
        if (!sameVersion(before, after) || Boolean.TRUE.equals(after.get("closed"))) throw failure("RELOAD_UNAVAILABLE");
        String rules = boundedJson(config.rules());
        String allow = boundedJson(config.allowScope());
        String block = boundedJson(config.blockScope());
        String hosts = boundedJson(new HostRates(config.limits().hostRps()));
        loading = true;
        try {
            rulesEditor.setText(rules);
            allowEditor.setText(allow);
            blockEditor.setText(block);
            hostEditor.setText(hosts);
            Limits limits = config.limits();
            int[] values = {limits.globalRps(), limits.perHostRps(), limits.maxConcurrent(), limits.maxQueued(),
                    Math.toIntExact(limits.queueTimeoutMillis()), Math.toIntExact(limits.approvalTimeoutMillis()), Math.toIntExact(limits.requestTimeoutMillis())};
            List<JSpinner> spinners = limitSpinners();
            for (int i = 0; i < values.length; i++) spinners.get(i).setValue(values[i]);
            defaultMode.setSelectedItem(config.defaultMode());
            rulesModel.setRows(config.rules());
            baseline = config;
            baselineProjectId = projectId(after);
            baselineRevision = revision(after);
            dirty = false;
            stale = false;
            message.setText("POLICY_DRAFT_LOADED — review before applying");
        } finally {
            loading = false;
            updateBaselineLabel();
        }
    }

    private void applyDraft() {
        if (baseline == null || stale) throw failure("STALE_POLICY_DRAFT_RELOAD_REQUIRED");
        access.refreshProject();
        Map<String, Object> current = access.status();
        if (!matchesBaseline(current) || Boolean.TRUE.equals(current.get("closed"))) {
            stale = true;
            updateBaselineLabel();
            throw failure("STALE_POLICY_DRAFT_RELOAD_REQUIRED");
        }
        List<Rule> rules = parseRules();
        List<ScopeEntry> allow = parseScopes(allowEditor);
        List<ScopeEntry> block = parseScopes(blockEditor);
        HostRates hosts = parse(hostEditor.getText(), HostRates.class);
        if (hosts == null || hosts.hostRps() == null || hosts.hostRps().values().stream().anyMatch(Objects::isNull))
            throw failure("INVALID_SETTINGS_JSON");
        if (hosts.hostRps().size() > 256) throw failure("POLICY_ROW_LIMIT");
        for (JSpinner spinner : limitSpinners()) {
            try { spinner.commitEdit(); }
            catch (java.text.ParseException e) { throw failure("INVALID_LIMIT_VALUE"); }
        }
        Limits limits = new Limits(number(globalRps), number(perHostRps), hosts.hostRps(), number(maxConcurrent), number(maxQueued),
                number(queueTimeout), number(approvalTimeout), number(requestTimeout));
        GuardConfig candidate = new GuardConfig(baseline.schemaVersion(), allow, block, rules, (Mode) defaultMode.getSelectedItem(), limits);
        try {
            // Original editor baseline ONLY. Controller performs the final atomic compare-and-set.
            access.updateConfig(candidate, baselineProjectId, baselineRevision);
        } catch (IllegalStateException e) {
            stale = true;
            updateBaselineLabel();
            throw failure("POLICY_UPDATE_REJECTED_RELOAD_REQUIRED");
        } catch (IllegalArgumentException e) {
            throw failure("INVALID_POLICY");
        }
        loadDraft();
        refreshNow();
        message.setText("POLICY_APPLIED — all drafts; live limits updated");
    }

    private void previewRules() {
        Rule selected = selected(rulesTable, rulesModel);
        rulesModel.setRows(parseRules());
        if (selected != null) selectId(rulesTable, rulesModel.rows, Rule::id, Set.of(selected.id()));
        message.setText("RULE_DRAFT_PARSED — final policy validation occurs on Apply ALL drafts");
    }

    private void addRule() {
        List<Rule> rules = new ArrayList<>(parseRules());
        Rule added = new Rule("rule-" + UUID.randomUUID(), "New disabled rule", false, Mode.BLOCK,
                Condition.leaf(Field.PATH, Match.EXACT, "/example"));
        if (rules.size() >= 256) throw failure("POLICY_ROW_LIMIT");
        rules.add(added);
        setRules(rules);
        selectId(rulesTable, rulesModel.rows, Rule::id, Set.of(added.id()));
    }

    private void mutateRule(java.util.function.UnaryOperator<Rule> change) {
        Rule selected = selected(rulesTable, rulesModel);
        if (selected == null) throw failure("SELECT_RULE_FIRST");
        List<Rule> rules = new ArrayList<>(parseRules());
        int found = -1;
        for (int i = 0; i < rules.size(); i++) if (Objects.equals(rules.get(i).id(), selected.id())) {
            if (found >= 0) throw failure("RULE_SELECTION_STALE_PARSE_AGAIN");
            found = i;
        }
        if (found < 0) throw failure("RULE_SELECTION_STALE_PARSE_AGAIN");
        if (change == null) rules.remove(found); else rules.set(found, change.apply(rules.get(found)));
        setRules(rules);
        selectId(rulesTable, rulesModel.rows, Rule::id, Set.of(selected.id()));
    }

    private void setRules(List<Rule> rules) {
        rulesEditor.setText(boundedJson(rules));
        rulesModel.setRows(rules);
    }

    private List<Rule> parseRules() {
        Rule[] rules = parse(rulesEditor.getText(), Rule[].class);
        if (rules == null) throw failure("INVALID_RULES_JSON");
        if (rules.length > 256) throw failure("POLICY_ROW_LIMIT");
        try { return List.of(rules); }
        catch (RuntimeException e) { throw failure("INVALID_RULES_JSON"); }
    }

    private List<ScopeEntry> parseScopes(JTextArea editor) {
        ScopeEntry[] rows = parse(editor.getText(), ScopeEntry[].class);
        if (rows == null) throw failure("INVALID_SCOPE_JSON");
        if (rows.length > 256) throw failure("POLICY_ROW_LIMIT");
        try { return List.of(rows); }
        catch (RuntimeException e) { throw failure("INVALID_SCOPE_JSON"); }
    }

    private void addScope(JTextArea editor) {
        List<ScopeEntry> scopes = new ArrayList<>(parseScopes(editor));
        if (scopes.size() >= 256) throw failure("POLICY_ROW_LIMIT");
        scopes.add(new ScopeEntry(false, "example.test", "https", 443, "/"));
        editor.setText(boundedJson(scopes));
    }

    /** Timer and test refresh; never waits for HTTP or approvals. */
    void refreshNow() {
        requireEdt();
        if (closed) return;
        try {
            access.refreshProject();
            Map<String, Object> status = access.status();
            dashboard.setText(boundedText(Json.write(status)));
            paused.setSelected(Boolean.TRUE.equals(status.get("paused")));
            paused.setEnabled(!Boolean.TRUE.equals(status.get("closed")));
            if (baseline == null && !dirty) loadDraft();
            if (!matchesBaseline(status) || Boolean.TRUE.equals(status.get("closed"))) stale = true;
            updateBaselineLabel();
            traffic = List.copyOf(access.traffic().stream().limit(MAX_ROWS).toList());
            updateProjects();
            filterTraffic();
            Pending old = selected(approvalTable, approvalModel);
            approvalModel.setRows(access.approvals().stream().limit(100).toList());
            if (old != null) selectId(approvalTable, approvalModel.rows, Pending::id, Set.of(old.id()));
            showApprovalDetail();
        } catch (RuntimeException e) {
            stale = true;
            updateBaselineLabel();
            // A recurring timer must not open recurring modal dialogs, nor show exception content.
            message.setText("REFRESH_UNAVAILABLE — policy drafts disabled; reload after recovery");
        }
    }

    private void updateProjects() {
        String selected = (String) projectFilter.getSelectedItem();
        Set<String> ids = new LinkedHashSet<>();
        ids.add(ALL_PROJECTS);
        for (TrafficEntry entry : traffic) ids.add(entry.projectId());
        if (selected != null) ids.add(selected); // Do not silently broaden a filter after eviction/clear.
        loading = true;
        try {
            projectFilter.removeAllItems();
            for (String id : ids) projectFilter.addItem(id);
            projectFilter.setSelectedItem(selected == null ? ALL_PROJECTS : selected);
        } finally { loading = false; }
    }

    private void filterTraffic() {
        if (closed) return;
        Set<String> selection = new HashSet<>();
        for (TrafficEntry entry : selectedTraffic()) selection.add(entry.id());
        String project = (String) projectFilter.getSelectedItem();
        List<TrafficEntry> displayed = new ArrayList<>();
        for (TrafficEntry entry : traffic) {
            String status = entry.statusCode() == null ? "" : entry.statusCode().toString();
            if (bookmarksOnly.isSelected() && !entry.bookmarked()
                    || project != null && !project.equals(ALL_PROJECTS) && !project.equals(entry.projectId())
                    || !contains(entry.method(), methodFilter.getText()) || !contains(status, statusFilter.getText())
                    || !contains(entry.timestamp(), timeFilter.getText())) continue;
            String needle = search.getText();
            if (!needle.isEmpty() && !(contains(entry.url(), needle) || contains(entry.method(), needle)
                    || contains(entry.timestamp(), needle) || contains(status, needle)
                    || contains(entry.reason(), needle) || contains(entry.id(), needle))) continue;
            displayed.add(entry);
        }
        trafficModel.setRows(displayed);
        selectId(trafficTable, trafficModel.rows, TrafficEntry::id, selection);
        showTrafficDetail();
    }

    private static boolean contains(String text, String literal) {
        return text.toLowerCase(Locale.ROOT).contains(literal.toLowerCase(Locale.ROOT));
    }

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
        trafficDetail.setText(entry == null ? "" : boundedText(metadata(entry)));
        requestDetail.setText(entry == null ? "" : boundedText(entry.request()));
        responseDetail.setText(entry == null ? "" : boundedText(entry.response()));
        requestDetail.setCaretPosition(0);
        responseDetail.setCaretPosition(0);
        trafficDetail.setCaretPosition(0);
    }

    private static String metadata(TrafficEntry entry) {
        return "Redacted callback-copy evidence — not complete wire capture or proof of delivery\n"
                + "ID: " + entry.id() + "\nProject: " + entry.projectId() + "\nTime: " + entry.timestamp()
                + "\nMode: " + entry.mode() + "\nDisposition: " + entry.disposition() + "\nReason: " + entry.reason()
                + "\nStatus: " + entry.statusCode() + "\nPolicy revision: " + entry.revision()
                + "\nBookmarked: " + entry.bookmarked() + "\nTruncated: " + entry.truncated()
                + "\nRequest body omitted: " + entry.requestCapture().bodyOmitted()
                + "\nResponse body omitted: " + entry.responseCapture().bodyOmitted()
                + "\nRule hits:\n" + Json.write(entry.hits());
    }

    private void bookmarkSelected() {
        List<TrafficEntry> selected = selectedTraffic();
        if (selected.isEmpty()) throw failure("SELECT_TRAFFIC_FIRST");
        for (TrafficEntry entry : selected) access.bookmark(entry.id(), !entry.bookmarked());
        refreshNow();
    }

    private void showApprovalDetail() {
        Pending pending = selected(approvalTable, approvalModel);
        if (pending == null) { approvalDetail.setText(""); return; }
        TrafficEntry evidence = null;
        for (TrafficEntry entry : traffic)
            if (entry.id().equals(pending.evidenceId()) && entry.projectId().equals(pending.projectId())) { evidence = entry; break; }
        String detail = "Approval: " + pending.id() + "\nEvidence: " + pending.evidenceId() + "\nProject: " + pending.projectId()
                + "\nCreated: " + pending.createdAt() + "\nExpires: " + pending.expiresAt() + "\n\n";
        approvalDetail.setText(boundedText(detail + (evidence == null ? "EVIDENCE_NOT_RETAINED (expired or evicted); no raw fallback is available."
                : metadata(evidence) + "\n\nMASKED REQUEST\n" + evidence.request() + "\n\nMASKED RESPONSE\n" + evidence.response())));
        approvalDetail.setCaretPosition(0);
    }

    private void decide(boolean allow) {
        Pending pending = selected(approvalTable, approvalModel);
        if (pending == null) throw failure("SELECT_PENDING_APPROVAL_FIRST");
        access.refreshProject();
        Map<String, Object> current = access.status();
        if (!pending.projectId().equals(projectId(current)) || Boolean.TRUE.equals(current.get("closed"))
                || Boolean.TRUE.equals(current.get("paused")))
            throw failure("APPROVAL_STALE_OR_EXPIRED");
        boolean decided = access.decideApproval(pending.id(), allow);
        refreshNow();
        if (!decided) throw failure("APPROVAL_STALE_OR_EXPIRED");
        message.setText(allow ? "APPROVAL_ALLOWED_ONCE — final policy/rate gates still apply" : "APPROVAL_DENIED");
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
        if (target.existing() && !dialogs.confirm(this, "Overwrite the selected existing file with owner-only REDACTED evidence?")) return;
        message.setText("EXPORT_IN_PROGRESS — redacted callback copies only");
        exportWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() throws Exception {
                String text = har ? access.exportHar(entries) : access.exportJson(entries);
                if (isCancelled()) throw new IOException("CANCELLED");
                writeAtomic(target, text);
                return null;
            }
            @Override protected void done() {
                exportWorker = null;
                if (closed) return;
                try { get(); message.setText("EXPORT_COMPLETE — redacted / possibly omitted or truncated callback copies only"); }
                catch (Exception e) { report("EXPORT_FAILED"); }
            }
        };
        exportWorker.execute();
    }

    /** Capture overwrite consent identity before background work. Resolve the chosen parent, not the target symlink. */
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

    /** Same-directory atomic publication. No non-atomic fallback and no raw log/exception output. */
    static void writeAtomic(ExportTarget choice, String text) throws IOException {
        Objects.requireNonNull(text);
        Path target = choice.path();
        Path parent = target.getParent();
        boolean posix = Files.getFileStore(parent).supportsFileAttributeView("posix");
        FileAttribute<?>[] attrs = posix ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(parent, ".cairn-guard-", ".tmp", attrs);
        BasicFileAttributes reservation = null;
        boolean published = false;
        try {
            BasicFileAttributes initialTemp = safeAttributes(temp);
            try (Writer out = Files.newBufferedWriter(temp, StandardCharsets.UTF_8,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) { out.write(text); }
            BasicFileAttributes writtenTemp = safeAttributes(temp);
            if (!Objects.equals(initialTemp.fileKey(), writtenTemp.fileKey())
                    || !initialTemp.creationTime().equals(writtenTemp.creationTime())) throw new IOException("TEMP_CHANGED");
            if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
            if (choice.existing()) {
                if (!sameFileState(choice.original(), safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            } else {
                // Java ATOMIC_MOVE alone may overwrite even without REPLACE_EXISTING. Claim a new name
                // exclusively first; only our empty owner-only reservation may be atomically replaced.
                Files.createFile(target, attrs);
                reservation = safeAttributes(target);
            }
            BasicFileAttributes expected = choice.existing() ? choice.original() : reservation;
            if (!sameFileState(expected, safeAttributes(target))) throw new IOException("TARGET_CHANGED");
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            published = true;
        } finally {
            Files.deleteIfExists(temp);
            if (!published && reservation != null) {
                try {
                    if (sameFileState(reservation, safeAttributes(target))) Files.deleteIfExists(target);
                } catch (IOException ignored) { /* Never remove a replacement file or expose exception content. */ }
            }
        }
    }

    private static BasicFileAttributes safeAttributes(Path target) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attrs.isSymbolicLink() || !attrs.isRegularFile()) throw new IOException("UNSAFE_TARGET");
        return attrs;
    }

    private static boolean sameFileState(BasicFileAttributes a, BasicFileAttributes b) {
        return a != null && b != null && Objects.equals(a.fileKey(), b.fileKey())
                && a.size() == b.size() && a.lastModifiedTime().equals(b.lastModifiedTime())
                && a.creationTime().equals(b.creationTime());
    }

    record ExportTarget(Path path, BasicFileAttributes original) {
        boolean existing() { return original != null; }
    }

    /** Typed wrapper keeps host override parsing on model.Json's strict, bounded configuration mapper. */
    public record HostRates(Map<String, Integer> hostRps) {}

    private boolean matchesBaseline(Map<String, Object> status) {
        return Objects.equals(baselineProjectId, projectId(status)) && baselineRevision == revision(status);
    }

    private static boolean sameVersion(Map<String, Object> a, Map<String, Object> b) {
        return projectId(a).equals(projectId(b)) && revision(a) == revision(b);
    }

    private static String projectId(Map<String, Object> status) {
        Object id = status.get("projectId");
        if (!(id instanceof String value) || value.isBlank()) throw failure("PROJECT_UNAVAILABLE");
        return value;
    }

    private static long revision(Map<String, Object> status) {
        Object revision = status.get("revision");
        if (!(revision instanceof Number value)) throw failure("PROJECT_UNAVAILABLE");
        return value.longValue();
    }

    private void updateBaselineLabel() {
        baselineLabel.setText(baseline == null ? "No policy draft loaded — reload required"
                : "Draft revision " + baselineRevision + " (project "
                + baselineProjectId.substring(0, Math.min(32, baselineProjectId.length())) + ")"
                + (stale ? " — STALE: RELOAD REQUIRED" : dirty ? " — unsaved changes" : " — current"));
        baselineLabel.setToolTipText(null); // Do not render operator/config/traffic strings as Swing HTML.
        apply.setEnabled(!closed && baseline != null && !stale);
    }

    private void guarded(Runnable action) {
        requireEdt();
        if (closed) return;
        try { action.run(); }
        catch (UiFailure e) { report(e.category); }
        catch (RuntimeException e) { report("ACTION_FAILED"); }
    }

    private void report(String category) {
        message.setText(category);
        dialogs.error(this, category);
    }

    private static UiFailure failure(String category) { return new UiFailure(category); }
    private static final class UiFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String category;
        UiFailure(String category) { super(null, null, false, false); this.category = category; }
    }

    private static <T> T parse(String value, Class<T> type) {
        if (value == null || value.length() > MAX_EDITOR_CHARS) throw failure("INVALID_BOUNDED_JSON");
        try {
            // Inherit the shared mapper's duplicate/unknown/trailing/depth guards, without mutating it.
            // Do not silently turn a null/missing scope port into any-port, or truncate fractional RPS/ports.
            return Json.MAPPER.readerFor(type).with(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                    .without(DeserializationFeature.ACCEPT_FLOAT_AS_INT).readValue(value);
        } catch (Exception e) { throw failure("INVALID_BOUNDED_JSON"); }
    }

    private static String boundedJson(Object value) {
        String json = Json.write(value);
        if (json.length() > MAX_EDITOR_CHARS) throw failure("EDITOR_LENGTH_LIMIT");
        return json;
    }

    private static String boundedText(String text) {
        return text.length() <= MAX_EDITOR_CHARS ? text : text.substring(0, MAX_EDITOR_CHARS - 32) + "\n[DISPLAY TRUNCATED]";
    }

    private static int number(JSpinner spinner) { return ((Number) spinner.getValue()).intValue(); }

    private JButton button(String name, String label, Runnable action) {
        JButton button = named(new JButton(label), name);
        button.addActionListener(e -> guarded(action));
        return button;
    }

    private static JPanel buttons(Component... children) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        for (Component child : children) panel.add(child);
        return panel;
    }

    private static void addField(JPanel panel, String label, Component field) {
        panel.add(new JLabel(label));
        panel.add(field);
    }

    private static JTextArea note(String value) {
        JTextArea area = new JTextArea(value, 3, 40);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        return area;
    }

    private static JTextArea textArea(String name, boolean editable) {
        JTextArea area = named(new JTextArea(8, 50), name);
        area.setEditable(editable);
        area.setLineWrap(false);
        ((AbstractDocument) area.getDocument()).setDocumentFilter(new LengthLimit(MAX_EDITOR_CHARS));
        return area;
    }

    private static JTextField textField(String name) {
        JTextField field = named(new JTextField(18), name);
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new LengthLimit(4_096));
        return field;
    }

    private static JSpinner spinner(String name, int value, int min, int max) {
        JSpinner spinner = named(new JSpinner(new SpinnerNumberModel(value, min, max, 1)), name);
        JSpinner.DefaultEditor editor = (JSpinner.DefaultEditor) spinner.getEditor();
        ((AbstractDocument) editor.getTextField().getDocument()).setDocumentFilter(new LengthLimit(32));
        return spinner;
    }

    private static JScrollPane titled(String title, JTextArea editor) {
        JScrollPane pane = new JScrollPane(editor);
        pane.setBorder(BorderFactory.createTitledBorder(title));
        return pane;
    }

    private static JSplitPane split(Component top, Component bottom, double weight) {
        JSplitPane pane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom);
        pane.setResizeWeight(weight);
        return pane;
    }

    private static JTable table(String name, AbstractTableModel model, boolean multi) {
        JTable table = named(new JTable(model), name);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(multi ? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION : ListSelectionModel.SINGLE_SELECTION);
        DefaultTableCellRenderer plain = new DefaultTableCellRenderer();
        plain.putClientProperty("html.disable", Boolean.TRUE);
        table.setDefaultRenderer(String.class, plain);
        table.setFillsViewportHeight(true);
        return table;
    }

    private static <T> T selected(JTable table, RowsModel<T> model) {
        int index = modelIndex(table, table.getSelectedRow(), model.rows.size());
        return index >= 0 ? model.rows.get(index) : null;
    }

    private static int modelIndex(JTable table, int view, int size) {
        if (view < 0 || view >= table.getRowCount()) return -1;
        // Selection notifications can arrive while JTable is rebuilding its sorter for new rows.
        try {
            int index = table.convertRowIndexToModel(view);
            return index >= 0 && index < size ? index : -1;
        } catch (IndexOutOfBoundsException e) { return -1; }
    }

    private static <T> void selectId(JTable table, List<T> rows, java.util.function.Function<T, String> id, Set<String> wanted) {
        table.clearSelection();
        for (int i = 0; i < rows.size(); i++) if (wanted.contains(id.apply(rows.get(i)))) {
            int view = table.convertRowIndexToView(i);
            if (view >= 0) table.addRowSelectionInterval(view, view);
        }
    }

    private static void listen(JTextComponent field, Runnable changed) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { changed.run(); }
            @Override public void removeUpdate(DocumentEvent e) { changed.run(); }
            @Override public void changedUpdate(DocumentEvent e) { changed.run(); }
        });
    }

    private static <T extends JComponent> T named(T component, String name) {
        component.setName(name);
        // JLabel-based renderers must not interpret operator/evidence strings as HTML.
        component.putClientProperty("html.disable", Boolean.TRUE);
        return component;
    }

    private static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Swing EDT required");
    }

    @Override public void close() {
        requireEdt();
        if (closed) return;
        closed = true;
        timer.stop();
        if (exportWorker != null) exportWorker.cancel(true);
        updateBaselineLabel();
    }

    interface Dialogs {
        boolean confirm(Component parent, String message);
        Path chooseExport(Component parent, String extension);
        void error(Component parent, String category);
    }

    private static final class SwingDialogs implements Dialogs {
        @Override public boolean confirm(Component parent, String message) {
            return JOptionPane.showConfirmDialog(parent, message, "Cairn Guard — human confirmation",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
        }
        @Override public Path chooseExport(Component parent, String extension) {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Export REDACTED callback-copy evidence — not complete wire capture");
            chooser.setFileFilter(new FileNameExtensionFilter("Redacted " + extension.toUpperCase(Locale.ROOT), extension));
            return chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath() : null;
        }
        @Override public void error(Component parent, String category) {
            JOptionPane.showMessageDialog(parent, category, "Cairn Guard", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static final class LengthLimit extends DocumentFilter {
        private final int max;
        private final Runnable rejected;
        LengthLimit(int max) { this(max, () -> {}); }
        LengthLimit(int max, Runnable rejected) { this.max = max; this.rejected = rejected; }
        @Override public void insertString(FilterBypass bypass, int offset, String text, AttributeSet attrs) throws BadLocationException {
            replace(bypass, offset, 0, text, attrs);
        }
        @Override public void replace(FilterBypass bypass, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
            int added = text == null ? 0 : text.length();
            if ((long) bypass.getDocument().getLength() - length + added <= max)
                bypass.replace(offset, length, text, attrs);
            else rejected.run();
        }
    }

    private static final class RowsModel<T> extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private final String[] columns;
        private final Class<?>[] types;
        private final java.util.function.Function<T, Object[]> values;
        private List<T> rows = List.of();
        RowsModel(String[] columns, Class<?>[] types, java.util.function.Function<T, Object[]> values) {
            this.columns = columns; this.types = types; this.values = values;
        }
        void setRows(List<T> rows) { this.rows = List.copyOf(rows); fireTableDataChanged(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Class<?> getColumnClass(int column) { return types[column]; }
        @Override public Object getValueAt(int row, int column) { return values.apply(rows.get(row))[column]; }
        @Override public boolean isCellEditable(int row, int column) { return false; }
    }
}
