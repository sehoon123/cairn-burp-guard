package dev.cairnguard.ui;

import dev.cairnguard.evidence.TrafficEntry.Message;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static dev.cairnguard.ui.GuardPanelV2Test.edt;
import static org.junit.jupiter.api.Assertions.*;

class HtmlPreviewTest {
    @TempDir Path directory;
    private static final AtomicInteger OBJECT_CONSTRUCTORS = new AtomicInteger();
    @SuppressWarnings("serial")
    public static final class ObjectTrap extends JPanel {
        public ObjectTrap() { OBJECT_CONSTRUCTORS.incrementAndGet(); }
    }
    static Message html(String type, String body) { return new Message(List.of(new Header("Content-Type", type)), body, type, false, false, true, "UTF8_TEXT"); }
    @Test void eligibilityIsDeclaredCompleteValidatedTextNotBrowserGuessing() {
        for (String type : List.of("text/html", "application/xhtml+xml", "text/html; charset=UTF-8", "text/html; charset=\"utf8\"", "text/html; charset=US-ASCII")) assertNull(HtmlPreview.unavailable(html(type, "<p>ASCII</p>")), type);
        for (String type : List.of("text/plain", "text/html; charset=latin1", "text/html; charset=UTF-8; charset=UTF-8", "text/html; charset=", "text/html; charset=\"utf-8", "text/html; broken", "text/html, text/html", "text/html; charset=US-ASCII")) assertNotNull(HtmlPreview.unavailable(html(type, "한글")), type);
        Message base = html("text/html", "ok");
        for (String name : List.of("Content-Type", "Content-Encoding", "Transfer-Encoding")) {
            var headers = new java.util.ArrayList<>(base.headers()); headers.add(new Header(name, name.equals("Content-Type") ? "text/html" : "gzip"));
            assertNotNull(HtmlPreview.unavailable(new Message(headers, "ok", "", false, false, true, "UTF8_TEXT")));
        }
        for (Message m : List.of(Message.EMPTY, new Message(base.headers(), "00", "", false, false, true, "HEX"), new Message(base.headers(), "ok", "", true, false, true, "UTF8_TEXT"), new Message(base.headers(), "ok", "", false, true, true, "UTF8_TEXT"))) assertNotNull(HtmlPreview.unavailable(m));
        assertNotNull(HtmlPreview.unavailable(new Message(List.of(), "<p>not sniffed</p>", "text/html", false, false, true, "UTF8_TEXT")));
        assertNull(HtmlPreview.unavailable(new Message(List.of(new Header("Content-Type", "text/html"), new Header("Transfer-Encoding", "identity")), "", "text/html", false, false, true, "EMPTY")));
    }
    @Test void htmlViewDetectorRejectsAnIndependentResourceFreePositiveControl() throws Exception {
        edt(() -> {
            DefaultStyledDocument plain = new DefaultStyledDocument(); plain.insertString(0, "constant control", null);
            var htmlView = new javax.swing.text.html.BlockView(plain.getDefaultRootElement(), javax.swing.text.View.Y_AXIS);
            assertThrows(AssertionError.class, () -> safeViews(htmlView), "the same detector must reject a live HTML View");
            safe(HtmlPreview.component(HtmlPreview.scan("<p>safe text</p>", () -> false))); return null;
        });
    }
    private static Message retained(List<Header> headers, byte[] body) {
        var store = new dev.cairnguard.evidence.EvidenceStore();
        String id = store.begin("p", "Synthetic", new dev.cairnguard.model.RequestData("GET", "https://example.test/preview", "example.test", 443, true, List.of(), new byte[0]),
                new dev.cairnguard.model.Decision(dev.cairnguard.model.GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 7);
        store.response(id, 200, headers, body);
        return store.snapshot().getFirst().responseCapture();
    }
    @Test void actualRetainedHtmlAllowsQuotedParameterDelimiters() {
        for (String type : List.of("text/html; note=\"a;b\"", "text/html; note=\"a=b\"; charset=UTF-8", "application/xhtml+xml; charset=\"UTF8\"; note=\"a;b=c\"")) {
            Message message = retained(List.of(new Header("Content-Type", type)), "<p>validated text</p>".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals("UTF8_TEXT", message.bodyEncoding(), "the actual store already validates this declaration");
            assertNull(HtmlPreview.unavailable(message), type);
        }
    }
    @Test void actualEmptyRetainedHtmlCannotBypassCompleteDeclarationValidation() {
        for (String type : List.of("text/html; note=\"a\"b\"", "text/html; note=\"unbalanced", "text/html; note=\"a\\b\"", "text/html; note=\"a\u0001b\"", "text/html\r\n", "text/html; charset*=UTF-8", "text/html; charset*0*=utf-8", "text/html; charset=UTF-8; charset=UTF-8")) {
            Message message = retained(List.of(new Header("Content-Type", type)), new byte[0]);
            assertEquals("EMPTY", message.bodyEncoding()); assertNotNull(HtmlPreview.unavailable(message), type);
        }
        Message duplicate = retained(List.of(new Header("Content-Type", "text/html"), new Header("Content-Type", "text/html")), new byte[0]);
        assertEquals("EMPTY", duplicate.bodyEncoding()); assertNotNull(HtmlPreview.unavailable(duplicate));
        // EvidenceStore rejects null values before yielding a Message; exercise this UI trust boundary directly.
        for (List<Header> declarations : List.of(List.of(new Header("Content-Type", null)), List.of(new Header("Content-Type", null), new Header("Content-Type", "text/html"))))
            assertNotNull(HtmlPreview.unavailable(new Message(declarations, "", "", false, false, true, "EMPTY")));
    }
    @Test void genuineHeadingListsTablesFormattingEntitiesAndPaintedWrapping() throws Exception {
        var projection = HtmlPreview.scan("<h1>Heading</h1><p>" + "wrapping words ".repeat(80) + "<b>bold</b><i>italic</i></p><ol><li>one</li><li>two</li></ol><table><tr><th>Key</th><th>Value</th></tr><tr><td>A</td><td>B</td></tr></table><pre>a  b\n c</pre><p>&lt;img src=x&gt; &#x1f642; &amp; &copy;</p>", () -> false);
        edt(() -> {
            JPanel root = HtmlPreview.component(projection); JScrollPane scroll = new JScrollPane(root); scroll.setSize(450, 900); layout(scroll);
            safe(root);
            var heading = (JTextPane) GuardPanelV2Test.find(root, "traffic.preview.h1");
            assertTrue(StyleConstants.getFontSize(heading.getStyledDocument().getCharacterElement(0).getAttributes()) > 20);
            var table = (JPanel) GuardPanelV2Test.find(root, "traffic.preview.table"); assertNotNull(table); assertEquals(4, table.getComponentCount());
            assertTrue(table.getComponent(1).getX() > table.getComponent(0).getX()); assertTrue(table.getComponent(2).getY() > table.getComponent(0).getY());
            assertTrue(allText(root).contains("1. one")); assertTrue(allText(root).contains("2. two")); assertTrue(allText(root).contains("<img src=x> 🙂 & ©"));
            var list = (JTextPane) GuardPanelV2Test.find(root, "traffic.preview.li"); assertTrue(list.getInsets().left > heading.getInsets().left);
            JTextPane paragraph = (JTextPane) GuardPanelV2Test.find(root, "traffic.preview.p");
            assertTrue(paragraph.getHeight() > 35, "ordinary paragraphs actually wrap: pane=" + paragraph.getSize() + " preferred=" + paragraph.getPreferredSize() + " root=" + root.getSize() + " scroll=" + scroll.getViewport().getExtentSize());
            BufferedImage image = new BufferedImage(450, 900, BufferedImage.TYPE_INT_RGB); Graphics2D g = image.createGraphics(); try { scroll.paint(g); } finally { g.dispose(); }
            assertNotEquals(image.getRGB(0, 0), image.getRGB(20, 20), "real painting changed pixels"); return null;
        });
    }
    @Test void lineBreakPreInlineStylesAndEligibilityCancellationAreRealProjections() throws Exception {
        var projection = HtmlPreview.scan("<p>first<br>second <b>bold</b><i>italic</i><u>underline</u><s>strike</s><code>code</code></p><pre>a  b\n c</pre>", () -> false);
        edt(() -> {
            JPanel root = HtmlPreview.component(projection); String text = allText(root);
            assertTrue(text.contains("first\nsecond")); assertTrue(text.contains("a  b\n c"));
            JTextPane p = (JTextPane) GuardPanelV2Test.find(root, "traffic.preview.p");
            for (String word : List.of("bold", "italic", "underline", "strike", "code")) {
                AttributeSet a = p.getStyledDocument().getCharacterElement(p.getText().indexOf(word)).getAttributes();
                switch (word) { case "bold" -> assertTrue(StyleConstants.isBold(a)); case "italic" -> assertTrue(StyleConstants.isItalic(a)); case "underline" -> assertTrue(StyleConstants.isUnderline(a)); case "strike" -> assertTrue(StyleConstants.isStrikeThrough(a)); default -> assertEquals(Font.MONOSPACED, StyleConstants.getFontFamily(a)); }
            }
            return null;
        });
        AtomicInteger checks = new AtomicInteger();
        assertThrows(CancellationException.class, () -> HtmlPreview.unavailable(html("text/html; charset=us-ascii", "a".repeat(2_100_000)), () -> checks.incrementAndGet() > 3));
    }
    @Test void deepMalformedAndLargeDocumentsKeepOrdinaryTextAndCancel() {
        var p = HtmlPreview.scan("<div>".repeat(20000) + "ordinary" + "</div>".repeat(20000) + "<table><tr><td><table><tr><td>nested</td></tr></table></td></tr></table><p>" + "x".repeat(2_100_000) + "FULL-END", () -> false);
        StringBuilder all = new StringBuilder(); for (Object o : p.blocks()) if (o instanceof HtmlPreview.Block b) for (var r : b.runs()) all.append(r.text());
        assertTrue(all.toString().contains("ordinary")); assertTrue(all.toString().endsWith("FULL-END"));
        AtomicInteger count = new AtomicInteger(); assertThrows(CancellationException.class, () -> HtmlPreview.scan("a".repeat(2_100_000), () -> count.incrementAndGet() > 3));
        var malformed = HtmlPreview.scan("<p>&lt;script&gt;literal&lt;/script&gt;<img src='unterminated", () -> false);
        assertTrue(malformed.toString().contains("<script>literal</script>"));
    }
    @Test void hostileHttpFileAndFifoHaveLivePositiveControlsButNoRendererAccess() throws Exception {
        int objectBefore = OBJECT_CONSTRUCTORS.get();
        edt(() -> { Class.forName(ObjectTrap.class.getName()).getConstructor().newInstance(); return null; });
        assertEquals(objectBefore + 1, OBJECT_CONSTRUCTORS.get(), "classid constructor canary has a live reflection control");
        Path file = directory.resolve("sentinel.txt"), fifo = directory.resolve("open-canary.fifo");
        Files.writeString(file, "synthetic-sentinel-original");
        Process mkfifo = new ProcessBuilder("mkfifo", fifo.toString()).start(); assertTrue(mkfifo.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, mkfifo.exitValue());
        // Linux IN_OPEN observes reads as well as writes, including a blocked FIFO reader. Positive controls prove liveness.
        String monitor = """
            import os,sys,ctypes,select,struct
            libc=ctypes.CDLL(None,use_errno=True)
            fd=libc.inotify_init1(os.O_NONBLOCK)
            assert fd>=0
            watches={}
            for name,path in [('FILE',sys.argv[1]),('FIFO',sys.argv[2])]:
                wd=libc.inotify_add_watch(fd,os.fsencode(path),0x20)
                assert wd>=0
                watches[wd]=name
            def drain():
                while True:
                    try: data=os.read(fd,65536)
                    except BlockingIOError: break
                    at=0
                    while at<len(data):
                        wd,mask,cookie,size=struct.unpack_from('iIII',data,at);at+=16+size
                        if mask&0x20: print(watches[wd]+'_OPEN',flush=True)
            print('READY',flush=True)
            while True:
                ready,_,_=select.select([fd,sys.stdin],[],[])
                if fd in ready: drain()
                if sys.stdin in ready:
                    line=sys.stdin.readline()
                    if not line: break
                    drain();print(line.strip(),flush=True)
            os.close(fd)
            """;
        Process watcher = new ProcessBuilder("python3", "-u", "-c", monitor, file.toString(), fifo.toString()).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        BlockingQueue<String> events = new LinkedBlockingQueue<>();
        Thread reader = new Thread(() -> { try (var in = watcher.inputReader()) { String line; while ((line = in.readLine()) != null) events.add(line); } catch (IOException ignored) {} }, "owned-canary-events"); reader.start();
        try (ServerSocket server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress())) {
            assertEquals("READY", events.poll(5, TimeUnit.SECONDS));
            assertEquals("synthetic-sentinel-original", Files.readString(file)); assertEquals("FILE_OPEN", events.poll(5, TimeUnit.SECONDS));
            FutureTask<Integer> readFifo = new FutureTask<>(() -> { try (var in = Files.newInputStream(fifo)) { return in.read(); } });
            Thread fifoReader = new Thread(readFifo, "owned-positive-fifo"); fifoReader.start();
            try (var out = Files.newOutputStream(fifo)) { out.write(42); }
            assertEquals(42, readFifo.get(5, TimeUnit.SECONDS)); fifoReader.join(5000); assertFalse(fifoReader.isAlive());
            barrier(watcher, events, "POSITIVE", true);
            try (Socket control = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort()); Socket accepted = server.accept()) { assertTrue(control.isConnected()); assertTrue(accepted.isConnected()); }
            server.setSoTimeout(200);
            String http = "http://127.0.0.1:" + server.getLocalPort() + "/synthetic-trap";
            String hostile = "<!DOCTYPE html [<!ENTITY external SYSTEM '" + file.toUri() + "'>]><html><head><base href='" + http + "'><meta http-equiv=refresh content='0;url=" + http + "'><link rel=stylesheet href='" + http + "'><style>@import '" + http + "';p{background:url(" + fifo.toUri() + ")}</style><script>fetch('" + http + "')</script></head><body background='" + file.toUri() + "'>";
            for (String url : List.of(http, file.toUri().toString(), fifo.toUri().toString(), "javascript:alert(1)", "data:text/html,<script>active</script>")) {
                hostile += "<h1 onclick='active()'>safe heading</h1><img src='" + url + "'><a href='" + url + "'>inert label</a><iframe src='" + url + "'></iframe><frame src='" + url + "'><object classid='" + url + "' data='" + url + "'></object><embed src='" + url + "'><form action='" + url + "'><input src='" + url + "'><button>control</button></form><svg><image href='" + url + "'/></svg><video src='" + url + "'></video>";
            }
            hostile += "<object classid='" + ObjectTrap.class.getName() + "'>inert classid</object>";
            hostile += "<p>&lt;img src='" + http + "'&gt; &#60;object&#62; &external;</p><!-- unterminated <img src='" + http + "'>";
            var projection = HtmlPreview.scan(hostile, () -> false);
            edt(() -> { JPanel root = HtmlPreview.component(projection); safe(root); assertTrue(allText(root).contains("inert label")); root.setSize(600, 800); layout(root); var image = new BufferedImage(600, 800, BufferedImage.TYPE_INT_RGB); var g = image.createGraphics(); try { root.paint(g); } finally { g.dispose(); } return null; });
            assertThrows(SocketTimeoutException.class, server::accept, "no HTTP/resource request");
            barrier(watcher, events, "NEGATIVE", false);
            assertEquals(objectBefore + 1, OBJECT_CONSTRUCTORS.get(), "captured object classid is data, not a constructor sink");
        } finally {
            watcher.getOutputStream().close(); assertTrue(watcher.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, watcher.exitValue()); reader.join(5000); assertFalse(reader.isAlive());
        }
    }
    static void barrier(Process p, BlockingQueue<String> events, String name, boolean positive) throws Exception {
        p.getOutputStream().write((name + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII)); p.getOutputStream().flush();
        int fifo = 0;
        while (true) { String e = events.poll(5, TimeUnit.SECONDS); assertNotNull(e, "live canary barrier"); if (e.equals(name)) break; if (positive) { assertEquals("FIFO_OPEN", e); fifo++; } else fail("renderer accessed canary: " + e); }
        if (positive) assertTrue(fifo > 0, "FIFO open positive control must be observed");
    }
    static void layout(Container c) { c.doLayout(); for (Component child : c.getComponents()) if (child instanceof Container nested) layout(nested); }
    static String allText(Component c) { StringBuilder s = new StringBuilder(); if (c instanceof JTextPane t) s.append(t.getText()); if (c instanceof Container p) for (Component child : p.getComponents()) s.append(allText(child)); return s.toString(); }
    static void safeViews(javax.swing.text.View view) {
        assertFalse(view.getClass().getName().startsWith("javax.swing.text.html."), "no HTML ViewFactory result");
        for (int i = 0; i < view.getViewCount(); i++) safeViews(view.getView(i));
    }
    static void safe(Component c) {
        if (c instanceof JTextPane t) {
            safeViews(t.getUI().getRootView(t));
            assertEquals(StyledEditorKit.class, t.getEditorKit().getClass()); assertEquals(DefaultStyledDocument.class, t.getDocument().getClass()); assertEquals("text/plain", t.getContentType()); assertEquals(0, t.getHyperlinkListeners().length); assertFalse(t.isEditable());
            for (int i = 0; i < t.getDocument().getLength(); i++) { AttributeSet a = t.getStyledDocument().getCharacterElement(i).getAttributes(); assertNull(StyleConstants.getIcon(a)); assertNull(StyleConstants.getComponent(a)); }
        } else assertTrue(c instanceof JPanel, "only ordinary panels and styled text leaves: " + c.getClass());
        if (c instanceof Container p) for (Component child : p.getComponents()) safe(child);
    }
}
