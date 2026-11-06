package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry.Message;
import dev.cairnguard.model.RequestData.Header;
import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Sink-free static inspection projection: captured markup never reaches an HTML/XML/native engine. */
final class HtmlPreview {
    private HtmlPreview() {}
    static final String LIMITS = "Static inspection projection · no CSS/images/JS/navigation/forms/browser fidelity. Complex layouts/entities are approximations; raw/export is authoritative. Large layouts may consume unbounded heap/time.";
    private static final Set<String> HIDDEN = Set.of("script", "style", "title", "template");
    private static final Set<String> OMITTED = Set.of("form", "frame", "iframe", "object", "embed", "svg", "math", "audio", "video", "img", "input", "select", "textarea", "button", "canvas", "applet", "link", "base", "meta", "source", "track");
    private static final Set<String> BLOCKS = Set.of("p", "div", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "li", "caption");
    record Run(String text, int style) {}
    record Block(String kind, int indent, List<Run> runs) {}
    record Table(List<List<Block>> rows) {}
    record Projection(List<Object> blocks) {}
    private static final int BOLD = 1, ITALIC = 2, UNDERLINE = 4, STRIKE = 8, CODE = 16;

    static String unavailable(Message message) { return unavailable(message, () -> false); }
    static String unavailable(Message message, BooleanSupplier cancelled) {
        TrafficSearch.Work work = new TrafficSearch.Work(cancelled); work.check();
        if (!message.present()) return "No retained response.";
        if (message.bodyOmitted() || message.truncated()) return "Incomplete or omitted response inspection copy.";
        if (!(message.bodyEncoding().equals("UTF8_TEXT") || message.bodyEncoding().equals("EMPTY") && message.body().isEmpty())) return "Body is unavailable or displayed as HEX; no charset guessing.";
        String type = null; int types = 0, content = 0, transfer = 0;
        for (Header h : message.headers()) {
            work.unit();
            if ("content-type".equalsIgnoreCase(h.name())) { if (++types > 1) return "Duplicate Content-Type declarations."; type = h.value(); }
            if ("content-encoding".equalsIgnoreCase(h.name())) { if (++content > 1 || h.value() == null || !"identity".equalsIgnoreCase(trim(h.value(), work))) return "Unsupported or ambiguous Content-Encoding."; }
            if ("transfer-encoding".equalsIgnoreCase(h.name())) { if (++transfer > 1 || h.value() == null || !"identity".equalsIgnoreCase(trim(h.value(), work))) return "Unsupported or ambiguous Transfer-Encoding."; }
        }
        if (types == 0) return "No declared HTML Content-Type.";
        if (type == null) return "Malformed Content-Type declaration.";
        List<String> parts = parts(type, work);
        if (parts == null) return "Malformed Content-Type declaration.";
        String mime = trim(parts.getFirst(), work);
        if (!mime.equalsIgnoreCase("text/html") && !mime.equalsIgnoreCase("application/xhtml+xml")) return "Declared content is not HTML/XHTML.";
        String charset = null;
        for (int i = 1; i < parts.size(); i++) {
            work.unit(); String p = trim(parts.get(i), work); int eq = p.indexOf('=');
            if (eq <= 0 || eq == p.length() - 1) return "Malformed Content-Type parameter.";
            String key = p.substring(0, eq); String value = p.substring(eq + 1);
            if (!token(key, work)) return "Malformed Content-Type parameter.";
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                value = value.substring(1, value.length() - 1);
                for (int j = 0; j < value.length(); j++) {
                    work.unit(); char c = value.charAt(j);
                    if (c == '"' || c == '\\' || Character.isISOControl(c)) return "Malformed Content-Type parameter.";
                }
            }
            else if (!token(value, work)) return "Malformed Content-Type parameter.";
            if (key.regionMatches(true, 0, "charset*", 0, 8)) return "Unsupported declared charset parameter.";
            if (key.equalsIgnoreCase("charset")) { if (charset != null) return "Duplicate charset parameters."; charset = value; }
        }
        if (charset != null && !charset.equalsIgnoreCase("utf-8") && !charset.equalsIgnoreCase("utf8") && !charset.equalsIgnoreCase("us-ascii")) return "Unsupported declared charset.";
        if (charset != null && charset.equalsIgnoreCase("us-ascii")) for (int i = 0; i < message.body().length(); i++) { work.unit(); if (message.body().charAt(i) > 127) return "Declared US-ASCII is not ASCII."; }
        work.check();
        // Absent charset uses the store's already strictly validated UTF8_TEXT inspection copy, not browser detection.
        return null;
    }
    private static String trim(String s, TrafficSearch.Work work) {
        int start = 0, end = s.length();
        while (start < end && ows(s.charAt(start))) { work.unit(); start++; }
        while (end > start && ows(s.charAt(end - 1))) { work.unit(); end--; }
        return s.substring(start, end);
    }
    private static boolean token(String s, TrafficSearch.Work work) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) { work.unit(); char c = s.charAt(i); if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) return false; }
        return true;
    }
    private static boolean ows(char c) { return c == ' ' || c == '\t'; }
    private static List<String> parts(String s, TrafficSearch.Work work) {
        List<String> out = new ArrayList<>(); int start = 0; boolean quoted = false;
        for (int i = 0; i < s.length(); i++) {
            work.unit(); char c = s.charAt(i);
            if (Character.isISOControl(c) && c != '\t') return null;
            if (c == '"') quoted = !quoted;
            if (c == ';' && !quoted) { out.add(s.substring(start, i)); start = i + 1; }
        }
        if (quoted) return null;
        out.add(s.substring(start)); return out;
    }

    static Projection scan(String input, BooleanSupplier cancelled) { return new Scanner(input, cancelled).scan(); }
    private static final class Scanner {
        final String input; final TrafficSearch.Work work;
        final List<Object> blocks = new ArrayList<>();
        final List<Run> runs = new ArrayList<>(); final StringBuilder text = new StringBuilder();
        final List<String> styleTags = new ArrayList<>(); final List<Integer> styles = new ArrayList<>();
        final List<String> lists = new ArrayList<>(); final List<Integer> numbers = new ArrayList<>();
        int style, indent, tableDepth; String kind = "p", hidden = ""; int hiddenDepth;
        List<List<Block>> rows; List<Block> row;
        boolean cell, whitespace;
        Scanner(String input, BooleanSupplier cancelled) { this.input = input; work = new TrafficSearch.Work(cancelled); }
        Projection scan() {
            work.check(); int i = 0;
            while (i < input.length()) {
                work.unit(); char c = input.charAt(i);
                if (c == '<') {
                    if (input.startsWith("<!--", i)) {
                        i += 4;
                        while (i < input.length() && !input.startsWith("-->", i)) { work.unit(); i++; }
                        i = Math.min(input.length(), i + 3); continue;
                    }
                    int end = i + 1; char quote = 0;
                    for (; end < input.length(); end++) {
                        work.unit(); char t = input.charAt(end);
                        if (quote != 0) { if (quote == t) quote = 0; }
                        else if (t == '\'' || t == '"') quote = t;
                        else if (t == '>') break;
                    }
                    if (end == input.length()) { if (hidden.isEmpty()) append(input.substring(i)); break; }
                    int at = i + 1; boolean closing = at < end && input.charAt(at) == '/'; if (closing) at++;
                    int start = at;
                    while (at < end && asciiName(input.charAt(at))) { work.unit(); at++; }
                    if (at == start) { if (input.charAt(i + 1) != '!' && input.charAt(i + 1) != '?' && hidden.isEmpty()) append(input.substring(i, end + 1)); }
                    else {
                        String tag = input.substring(start, at).toLowerCase(Locale.ROOT);
                        if (!hidden.isEmpty()) { if (tag.equals(hidden)) { if (closing) { if (--hiddenDepth == 0) hidden = ""; } else hiddenDepth++; } }
                        else if (HIDDEN.contains(tag) && !closing) { hidden = tag; hiddenDepth = 1; }
                        else tag(tag, closing);
                    }
                    i = end + 1; continue;
                }
                if (!hidden.isEmpty()) { i++; continue; }
                if (c == '&') {
                    int end = i + 1;
                    while (end < input.length() && end - i <= 32 && input.charAt(end) != ';' && input.charAt(end) != '<' && !Character.isWhitespace(input.charAt(end))) { work.unit(); end++; }
                    if (end < input.length() && input.charAt(end) == ';') {
                        String decoded = entity(input.substring(i + 1, end));
                        if (decoded != null) { append(decoded); i = end + 1; continue; }
                    }
                }
                append(c); i++;
            }
            finish(); finishTable(); work.check(); return new Projection(List.copyOf(blocks));
        }
        static boolean asciiName(char c) { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'; }
        void append(String s) { for (int i = 0; i < s.length(); i++) { work.unit(); append(s.charAt(i)); } }
        void append(char c) {
            if (!kind.equals("pre") && Character.isWhitespace(c)) { if (!whitespace) text.append(' '); whitespace = true; }
            else { text.append(c); whitespace = false; }
        }
        void lineBreak() { flush(); runs.add(new Run("\n", style)); whitespace = true; }
        void flush() { if (!text.isEmpty()) { runs.add(new Run(text.toString(), style)); text.setLength(0); } }
        void finish() {
            flush();
            if (!runs.isEmpty()) {
                Block block = new Block(kind, indent, List.copyOf(runs));
                if (rows == null) blocks.add(block);
                else { if (row == null) { row = new ArrayList<>(); rows.add(row); } row.add(block); }
                runs.clear();
            }
            whitespace = false;
        }
        void finishTable() {
            if (rows != null) { blocks.add(new Table(rows.stream().map(List::copyOf).toList())); rows = null; row = null; cell = false; tableDepth = 0; }
        }
        void tag(String tag, boolean closing) {
            int bit = switch (tag) { case "b", "strong" -> BOLD; case "i", "em" -> ITALIC; case "u" -> UNDERLINE; case "s", "strike" -> STRIKE; case "code" -> CODE; default -> 0; };
            if (bit != 0) {
                flush();
                if (!closing && styleTags.size() < 64) { styleTags.add(tag); styles.add(style); style |= bit; }
                else if (closing) { int at = styleTags.lastIndexOf(tag); if (at >= 0) { style = styles.get(at); styleTags.subList(at, styleTags.size()).clear(); styles.subList(at, styles.size()).clear(); } }
                return;
            }
            if (OMITTED.contains(tag)) { if (!closing) append(" [inert omitted element] "); return; }
            if (tag.equals("table")) {
                if (!closing) { if (tableDepth++ == 0) { finish(); rows = new ArrayList<>(); row = null; } else append(" [nested table approximated] "); }
                else if (tableDepth > 0 && --tableDepth == 0) { finish(); finishTable(); }
                return;
            }
            if (rows != null && tableDepth == 1 && tag.equals("tr")) { finish(); if (!closing) { row = new ArrayList<>(); rows.add(row); } else row = null; cell = false; return; }
            if (rows != null && tableDepth == 1 && (tag.equals("td") || tag.equals("th"))) {
                finish(); cell = !closing; kind = tag.equals("th") ? "th" : "p"; return;
            }
            if (tag.equals("ul") || tag.equals("ol")) {
                finish(); if (!closing && lists.size() < 64) { lists.add(tag); numbers.add(0); }
                else if (closing && !lists.isEmpty()) { lists.removeLast(); numbers.removeLast(); }
                indent = lists.size(); return;
            }
            if (tag.equals("br")) { lineBreak(); return; }
            if (tag.equals("hr")) { finish(); blocks.add(new Block("hr", 0, List.of(new Run("────────", 0)))); return; }
            if (BLOCKS.contains(tag)) {
                // Within a table cell, retain paragraphs as line breaks rather than inventing extra columns.
                if (rows != null && cell) { lineBreak(); return; }
                finish(); kind = closing ? "p" : tag;
                if (!closing && tag.equals("li")) {
                    if (!lists.isEmpty() && lists.getLast().equals("ol")) { int n = numbers.getLast() + 1; numbers.set(numbers.size() - 1, n); append(n + ". "); }
                    else append("• ");
                }
            }
        }
    }
    private static String entity(String name) {
        if (name.startsWith("#")) {
            try {
                boolean hex = name.length() > 2 && (name.charAt(1) == 'x' || name.charAt(1) == 'X');
                int n = Integer.parseInt(name.substring(hex ? 2 : 1), hex ? 16 : 10);
                return Character.isValidCodePoint(n) && !(n >= 0xd800 && n <= 0xdfff) && n != 0 ? new String(Character.toChars(n)) : null;
            } catch (NumberFormatException ignored) { return null; }
        }
        return switch (name) { case "amp" -> "&"; case "lt" -> "<"; case "gt" -> ">"; case "quot" -> "\""; case "apos" -> "'"; case "nbsp" -> "\u00a0"; case "copy" -> "©"; case "reg" -> "®"; default -> null; };
    }

    static JPanel component(Projection projection) {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("EDT_REQUIRED");
        JPanel root = new PreviewPanel(); root.setName("traffic.preview.document");
        int index = 0;
        for (Object object : projection.blocks()) {
            JComponent child;
            if (object instanceof Block b) child = leaf(b);
            else {
                Table table = (Table) object; JPanel grid = new JPanel(new GridBagLayout()); grid.setName("traffic.preview.table");
                for (int y = 0; y < table.rows().size(); y++) {
                    List<Block> cells = table.rows().get(y);
                    for (int x = 0; x < cells.size(); x++) {
                        JTextPane pane = leaf(cells.get(x)); pane.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Color.GRAY), BorderFactory.createEmptyBorder(4, 6, 4, 6)));
                        GridBagConstraints c = constraints(x, y); c.weightx = 1; c.fill = GridBagConstraints.BOTH; grid.add(pane, c);
                    }
                }
                child = grid;
            }
            GridBagConstraints c = constraints(0, index++); c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; root.add(child, c);
        }
        GridBagConstraints tail = constraints(0, index); tail.weighty = 1; root.add(new JPanel(), tail);
        return root;
    }
    private static GridBagConstraints constraints(int x, int y) { GridBagConstraints c = new GridBagConstraints(); c.gridx = x; c.gridy = y; c.anchor = GridBagConstraints.NORTHWEST; return c; }
    private static JTextPane leaf(Block block) {
        JTextPane pane = new TextLeaf(); pane.setEditorKit(new StyledEditorKit());
        DefaultStyledDocument document = new DefaultStyledDocument(); pane.setDocument(document); pane.setEditable(false);
        pane.setName("traffic.preview." + block.kind()); pane.putClientProperty("html.disable", true);
        pane.setMinimumSize(new Dimension(24, 16));
        pane.setBorder(BorderFactory.createEmptyBorder(4, 4 + block.indent() * 16, 6, 4));
        for (Run run : block.runs()) {
            SimpleAttributeSet a = new SimpleAttributeSet();
            StyleConstants.setFontFamily(a, block.kind().equals("pre") || (run.style() & CODE) != 0 ? Font.MONOSPACED : Font.SANS_SERIF);
            int heading = block.kind().length() == 2 && block.kind().charAt(0) == 'h' && block.kind().charAt(1) >= '1' && block.kind().charAt(1) <= '6' ? block.kind().charAt(1) - '0' : 0;
            StyleConstants.setFontSize(a, heading == 0 ? 14 : 30 - heading * 2);
            StyleConstants.setBold(a, heading > 0 || block.kind().equals("th") || (run.style() & BOLD) != 0);
            StyleConstants.setItalic(a, (run.style() & ITALIC) != 0); StyleConstants.setUnderline(a, (run.style() & UNDERLINE) != 0); StyleConstants.setStrikeThrough(a, (run.style() & STRIKE) != 0);
            try { document.insertString(document.getLength(), run.text(), a); } catch (BadLocationException impossible) { throw new IllegalStateException("PREVIEW_LAYOUT_FAILED"); }
        }
        return pane;
    }
    @SuppressWarnings("serial")
    private static final class TextLeaf extends JTextPane {
        @Override public Dimension getPreferredSize() {
            int width = getWidth() > 24 ? getWidth() : 400;
            setSize(width, 100);
            Dimension preferred = super.getPreferredSize();
            return new Dimension(24, preferred.height);
        }
    }
    @SuppressWarnings("serial")
    private static final class PreviewPanel extends JPanel implements Scrollable {
        PreviewPanel() { super(new GridBagLayout()); }
        @Override public Dimension getPreferredSize() {
            int width = getParent() instanceof JViewport viewport && viewport.getExtentSize().width > 0 ? viewport.getExtentSize().width : 400;
            for (Component child : getComponents()) {
                child.setSize(width, child.getHeight());
                if (child instanceof JPanel grid && grid.getLayout() instanceof GridBagLayout layout) {
                    int columns = 1;
                    for (Component cell : grid.getComponents()) columns = Math.max(columns, layout.getConstraints(cell).gridx + 1);
                    for (Component cell : grid.getComponents()) cell.setSize(Math.max(24, width / columns), cell.getHeight());
                    grid.invalidate();
                }
            }
            ((GridBagLayout) getLayout()).invalidateLayout(this);
            return super.getPreferredSize();
        }
        public Dimension getPreferredScrollableViewportSize() { return new Dimension(400, 240); }
        public int getScrollableUnitIncrement(Rectangle r, int o, int d) { return 16; }
        public int getScrollableBlockIncrement(Rectangle r, int o, int d) { return Math.max(16, r.height - 16); }
        public boolean getScrollableTracksViewportWidth() { return true; }
        public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
