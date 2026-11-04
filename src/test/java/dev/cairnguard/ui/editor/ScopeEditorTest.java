package dev.cairnguard.ui.editor;

import com.google.re2j.Pattern;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.basic.BasicHTML;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ScopeEditorTest {
    private static final ScopeEntry ORIGINAL = new ScopeEntry(true, "example.test", "https", 443, "/safe(?:/.*)?");
    private static final String SECRET = "synthetic-secret-never-echo";

    @Test void editorRequiresEdtAndNewFormHasNoImplicitHostOrAnyPort() throws Exception {
        assertThrows(IllegalStateException.class, () -> new ScopeEditor(null));
        ScopeEditor editor = edt(() -> new ScopeEditor(null));
        assertThrows(IllegalStateException.class, editor::component);
        assertThrows(IllegalStateException.class, editor::value);
        edt(() -> {
            assertEquals("", get(editor, "scope.host", JTextField.class).getText());
            assertEquals("443", get(editor, "scope.port", JTextField.class).getText());
            assertFalse(get(editor, "scope.anyPort", JCheckBox.class).isSelected());
            assertTrue(get(editor, "scope.enabled", JCheckBox.class).isSelected());
            assertEquals(0, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertNotNull(assertThrows(FormValidationException.class, editor::value).getMessage());
            get(editor, "scope.host", JTextField.class).setText("example.test");
            ScopeEntry result = editor.value();
            assertEquals("example.test", result.host());
            assertTrue(matches(result, "/"));
            assertFalse(matches(result, "/other"));
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("포트: 443"));
            return null;
        });
    }

    @Test void pastedUrlRequiresExplicitApplicationAndNeverUsesAnyPortOrAllPaths() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            JTextField input = get(editor, "scope.url", JTextField.class);
            input.setText("http://Sub.Example.test:8080/api/v1/item.+(test)$");
            assertEquals("example.test", get(editor, "scope.host", JTextField.class).getText());
            assertTrue(assertThrows(FormValidationException.class, editor::value).getMessage().contains("폼에 반영"));
            click(editor, "scope.fillUrl");
            ScopeEntry entry = editor.value();
            assertEquals("Sub.Example.test", entry.host());
            assertEquals("http", entry.scheme());
            assertEquals(8080, entry.port());
            assertEquals("/api/v1/item.+(test)$", get(editor, "scope.path", JTextField.class).getText());
            assertEquals(0, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertTrue(matches(entry, "/api/v1/item.+(test)$"));
            assertFalse(matches(entry, "/api/v1/itemXXtest"));
            assertFalse(matches(entry, "/api/v1/item.+(test)$/child"));
            assertFalse(matches(entry, "/"));
            assertEquals(entry, new ScopeEditor(entry).value());
            assertEquals(input.getText(), get(editor, "scope.url", JTextField.class).getText());
            return null;
        });
    }

    @Test void enterExplicitlyFillsExactScopeAndStillRejectsSensitiveUrlWithoutAnImplicitOldSave() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            JTextField input = get(editor, "scope.url", JTextField.class);
            input.setText("http://127.0.0.1:18080/safe");
            input.postActionEvent();
            ScopeEntry result = editor.value();
            assertEquals("127.0.0.1", result.host()); assertEquals(18080, result.port());
            assertTrue(matches(result, "/safe")); assertFalse(matches(result, "/safe/child"));
            assertTrue(get(editor, "scope.urlGuidance", JTextArea.class).getText().contains("Enter"));
            assertTrue(get(editor, "scope.pathGuidance", JTextArea.class).getText().contains("/api/items/1"));
            input.setText("https://user:" + SECRET + "@example.test/api");
            input.postActionEvent();
            assertEquals("127.0.0.1", get(editor, "scope.host", JTextField.class).getText());
            assertThrows(FormValidationException.class, editor::value);
            assertFalse(get(editor, "scope.message", JTextArea.class).getText().contains(SECRET));
            return null;
        });
    }

    @Test void defaultPortsRootAndRawEncodedPathAreKeptWithoutDecodingOrNormalization() throws Exception {
        edt(() -> {
            for (String address : List.of("https://example.test", "http://example.test/", "https://example.test:8443/a%2Fb/")) {
                ScopeEditor editor = new ScopeEditor(null);
                get(editor, "scope.url", JTextField.class).setText(address);
                click(editor, "scope.fillUrl");
                ScopeEntry entry = editor.value();
                assertEquals(address.startsWith("https") ? "https" : "http", entry.scheme());
                assertEquals(address.contains("8443") ? 8443 : address.startsWith("https") ? 443 : 80, entry.port());
                String expectedPath = address.contains("%2F") ? "/a%2Fb/" : "/";
                assertEquals(expectedPath, get(editor, "scope.path", JTextField.class).getText());
                assertTrue(matches(entry, expectedPath));
                assertFalse(matches(entry, expectedPath + "extra"));
                if (address.contains("%2F")) {
                    assertFalse(matches(entry, "/a/b/"));
                    assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("디코딩된 모든 경로"));
                    assertEquals(Mode.BLOCK, evaluate(entry, address, "example.test", 8443, true));
                }
            }
            return null;
        });
    }

    @Test void sensitiveOrUnrepresentableUrlPartsAreRejectedAtomicallyWithFixedGuidance() throws Exception {
        edt(() -> {
            List<String> invalid = List.of(
                    "https://operator:" + SECRET + "@example.test/safe",
                    "https://@example.test/safe",
                    "https://example.test/safe?token=" + SECRET,
                    "https://example.test/safe?",
                    "https://example.test/safe#" + SECRET,
                    "https://example.test/safe#",
                    "ftp://example.test/safe", "example.test/safe", "https:///safe",
                    "https://example.test:/safe", "https://example.test:0/safe", "https://example.test:65536/safe",
                    "https://example.test:+443/safe", "https://*.example.test/safe", "https://127.1/safe",
                    "https://example.test/a/../safe", "https://example.test/a/./safe", "https://example.test/a;safe",
                    "https://example.test/bad%ZZ", " https://example.test/safe", "https://example.test/safe\n");
            for (String address : invalid) {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                get(editor, "scope.url", JTextField.class).setText(address);
                click(editor, "scope.fillUrl");
                String guidance = get(editor, "scope.message", JTextArea.class).getText();
                assertFalse(guidance.contains(SECRET), guidance);
                assertFalse(guidance.contains(address), guidance);
                assertTrue(guidance.chars().anyMatch(c -> c >= '가' && c <= '힣'), guidance);
                assertThrows(FormValidationException.class, editor::value, address);
                assertEquals("example.test", get(editor, "scope.host", JTextField.class).getText(), address);
                assertEquals("443", get(editor, "scope.port", JTextField.class).getText(), address);
                get(editor, "scope.url", JTextField.class).setText("");
                assertEquals(ORIGINAL, editor.value(), address);
            }
            return null;
        });
    }

    @Test void rejectedUrlCannotBecomeAnImplicitOldSaveOrPartialOverwrite() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            get(editor, "scope.url", JTextField.class).setText("http://another.example.test:8080/changed?" + SECRET);
            click(editor, "scope.fillUrl");
            assertThrows(FormValidationException.class, editor::value);
            assertEquals("example.test", get(editor, "scope.host", JTextField.class).getText());
            assertEquals(0, get(editor, "scope.scheme", JComboBox.class).getSelectedIndex());
            assertEquals(3, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertEquals(ORIGINAL.pathRegex(), get(editor, "scope.regex", JTextArea.class).getText());
            get(editor, "scope.url", JTextField.class).setText("http://another.example.test:8080/changed");
            click(editor, "scope.fillUrl");
            get(editor, "scope.host", JTextField.class).setText("manual.example.test");
            assertEquals("manual.example.test", editor.value().host());
            assertEquals("http", editor.value().scheme());
            assertTrue(matches(editor.value(), "/changed"));
            return null;
        });
    }

    @Test void existingWildcardsAnyPortAnySchemeAndArbitraryRegexRoundTripByteForByte() throws Exception {
        edt(() -> {
            for (String expression : List.of("", ".*", "/", "/safe(?:/.*)?", "(?i)/safe/[a-z]+", "/line\n\r\t", "/value\\Q.+\\E")) {
                for (String target : List.of("*.Example.test.", "bücher.example", "[2001:db8::1]", "127.0.0.1")) {
                    ScopeEntry entry = new ScopeEntry(false, target, "AnY", 0, expression);
                    validate(entry);
                    ScopeEditor editor = new ScopeEditor(entry);
                    assertEquals(entry, editor.value());
                    assertEquals(expression, entry.pathRegex().isEmpty() ? editor.value().pathRegex()
                            : get(editor, "scope.regex", JTextArea.class).getText());
                    click(editor, "scope.enabled");
                    assertEquals(new ScopeEntry(true, target, "AnY", 0, expression), editor.value());
                }
            }
            return null;
        });
    }

    @Test void hostPreviewExplainsCanonicalAuthorityAndWildcardExcludesBaseDomain() throws Exception {
        edt(() -> {
            ScopeEntry entry = new ScopeEntry(true, "*.Example.test.", "HTTPS", 0, ".*");
            ScopeEditor editor = new ScopeEditor(entry);
            assertEquals(entry, editor.value());
            String preview = get(editor, "scope.preview", JTextArea.class).getText();
            assertTrue(preview.contains("*.example.test"));
            assertTrue(preview.contains("기본 도메인 제외"));
            assertTrue(preview.contains("모든 포트"));
            assertEquals(Mode.ALLOW, evaluate(entry, "https://child.example.test/", "child.example.test", 443, true));
            assertEquals(Mode.BLOCK, evaluate(entry, "https://example.test/", "example.test", 443, true));
            get(editor, "scope.url", JTextField.class).setText("https://[2001:db8::1]:8443/safe");
            click(editor, "scope.fillUrl");
            assertEquals("[2001:db8::1]", editor.value().host());
            assertEquals(8443, editor.value().port());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("[2001:db8:0:0:0:0:0:1]"));
            return null;
        });
    }

    @Test void exactAndSubpathModesEscapeRegexAndDoNotWidenHostOrSiblingPath() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(null);
            get(editor, "scope.host", JTextField.class).setText("example.test");
            get(editor, "scope.path", JTextField.class).setText("/api/v1/item.+(test)$");
            ScopeEntry exact = editor.value();
            validate(exact);
            assertTrue(matches(exact, "/api/v1/item.+(test)$"));
            assertFalse(matches(exact, "/api/v1/itemXXtest"));
            assertFalse(matches(exact, "/api/v1/item.+(test)$/child"));
            assertEquals(Mode.BLOCK, evaluate(exact, "https://other.example.test/api/v1/item.+(test)$", "other.example.test", 443, true));
            assertEquals(Mode.ALLOW, evaluate(exact, "https://example.test/api/v1/item.+(test)$", "example.test", 443, true));
            get(editor, "scope.path", JTextField.class).setText("/api");
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(1);
            ScopeEntry prefix = editor.value();
            validate(prefix);
            assertTrue(matches(prefix, "/api"));
            assertTrue(matches(prefix, "/api/"));
            assertTrue(matches(prefix, "/api/child"));
            assertFalse(matches(prefix, "/apix"));
            assertFalse(matches(prefix, "/api.json"));
            assertEquals(prefix, new ScopeEditor(prefix).value());
            get(editor, "scope.path", JTextField.class).setText("/api/");
            ScopeEntry slashPrefix = editor.value();
            assertFalse(matches(slashPrefix, "/api"));
            assertTrue(matches(slashPrefix, "/api/child"));
            assertEquals(slashPrefix, new ScopeEditor(slashPrefix).value());
            get(editor, "scope.path", JTextField.class).setText("/");
            assertTrue(matches(editor.value(), "/any/child"));
            assertEquals(editor.value(), new ScopeEditor(editor.value()).value());
            return null;
        });
    }

    @Test void allPathsAndAdvancedRegexRequireExplicitChoicesAndKeepFullMatchSemantics() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            get(editor, "scope.regex", JTextArea.class).setText("");
            assertTrue(assertThrows(FormValidationException.class, editor::value).getMessage().contains("모든 경로"));
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(2);
            assertEquals("", editor.value().pathRegex());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("제한 없음"));
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(3);
            get(editor, "scope.regex", JTextArea.class).setText("/safe/[0-9]+");
            ScopeEntry entry = editor.value();
            assertTrue(matches(entry, "/safe/123"));
            assertFalse(matches(entry, "/prefix/safe/123"));
            assertFalse(matches(entry, "/safe/123/child"));
            for (String invalid : List.of("(?<=/safe/)" + SECRET, "(a)\\1", "[" + SECRET)) {
                get(editor, "scope.regex", JTextArea.class).setText(invalid);
                FormValidationException error = assertThrows(FormValidationException.class, editor::value);
                assertTrue(error.getMessage().contains("RE2"));
                assertFalse(error.getMessage().contains(SECRET));
                assertNull(error.getCause());
                assertFalse(get(editor, "scope.message", JTextArea.class).getText().contains(SECRET));
            }
            return null;
        });
    }

    @Test void boundedDocumentsRejectOversizeInputWithoutSilentlySavingPreviousContent() throws Exception {
        edt(() -> {
            for (String name : List.of("scope.host", "scope.url", "scope.port", "scope.path", "scope.regex")) {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                int maximum = switch (name) {
                    case "scope.host" -> 257;
                    case "scope.url" -> 16_384;
                    case "scope.port" -> 5;
                    default -> 2_048;
                };
                javax.swing.text.JTextComponent field = get(editor, name, javax.swing.text.JTextComponent.class);
                String before = field.getText();
                field.setText("x".repeat(maximum + 1));
                assertEquals(before, field.getText());
                assertTrue(field.getDocument().getLength() <= maximum);
                assertThrows(FormValidationException.class, editor::value);
                assertFalse(get(editor, "scope.message", JTextArea.class).getText().contains("x".repeat(20)));
                if (name.equals("scope.url")) click(editor, "scope.clearUrl");
                else field.setText(before);
                assertEquals(ORIGINAL, editor.value());
            }
            ScopeEntry longest = new ScopeEntry(true, "example.test", "https", 443, "a".repeat(2_048));
            validate(longest);
            ScopeEditor editor = new ScopeEditor(longest);
            assertEquals(longest, editor.value());
            assertEquals(2_048, get(editor, "scope.regex", JTextArea.class).getText().length());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains(longest.pathRegex()));
            assertThrows(FormValidationException.class, () -> new ScopeEditor(new ScopeEntry(true, "example.test", "https", 443, "a".repeat(2_049))));
            return null;
        });
    }

    @Test void generatedPatternBoundsAreCheckedAfterQuotingAndNeverTruncatePath() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(null);
            get(editor, "scope.host", JTextField.class).setText("example.test");
            String tooLong = "/" + "a".repeat(2_047);
            get(editor, "scope.path", JTextField.class).setText(tooLong);
            assertEquals(tooLong, get(editor, "scope.path", JTextField.class).getText());
            assertThrows(FormValidationException.class, editor::value);
            get(editor, "scope.path", JTextField.class).setText("/" + "a".repeat(2_039));
            ScopeEntry limit = editor.value();
            assertEquals(2_048, limit.pathRegex().length());
            validate(limit);
            assertEquals(limit, new ScopeEditor(limit).value());
            return null;
        });
    }

    @Test void invalidManualHostPortAndPathCannotCoerceAnyScopeEvenWhenDisabled() throws Exception {
        edt(() -> {
            for (String invalid : List.of("*", "*.127.0.0.1", "*.[::1]", "https://example.test", "example.test:443", "example.test/path", " example.test", "127.1", "example.test\n")) {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                get(editor, "scope.host", JTextField.class).setText(invalid);
                click(editor, "scope.enabled");
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            for (String invalid : List.of("", "0", "-1", "+443", "1.5", "65536", "443\n")) {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                get(editor, "scope.port", JTextField.class).setText(invalid);
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            for (String invalid : List.of("", "relative", "/a/../b", "/a/./b", "/a?query", "/a#fragment", "/a;b", "/a\\b", "/a\n", "/a b", "/bad%ZZ")) {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(0);
                get(editor, "scope.path", JTextField.class).setText(invalid);
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            click(editor, "scope.anyPort");
            assertEquals(0, editor.value().port());
            assertFalse(get(editor, "scope.port", JTextField.class).isEnabled());
            get(editor, "scope.scheme", JComboBox.class).setSelectedIndex(2);
            assertEquals("any", editor.value().scheme());
            return null;
        });
    }

    @Test void literalUnicodePlusAndRepeatedSlashesAreNotNormalizedOrExpanded() throws Exception {
        edt(() -> {
            for (String literal : List.of("/한글/😀", "/a+b", "//example.test//path", "/file.(draft)$")) {
                ScopeEditor editor = new ScopeEditor(null);
                get(editor, "scope.host", JTextField.class).setText("example.test");
                get(editor, "scope.path", JTextField.class).setText(literal);
                ScopeEntry entry = editor.value();
                assertTrue(matches(entry, literal));
                assertFalse(matches(entry, literal + "/child"));
                assertEquals(literal.startsWith("//") ? Mode.BLOCK : Mode.ALLOW,
                        evaluate(entry, "https://example.test" + literal, "example.test", 443, true),
                        "A restricted scope must cover internal routing aliases too; the native target is never rewritten.");
                assertEquals(entry, new ScopeEditor(entry).value());
            }
            return null;
        });
    }

    @Test void longestValidHostAndRegexThatResemblesGeneratedSyntaxRemainLossless() throws Exception {
        edt(() -> {
            String hostname = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
            ScopeEntry longest = new ScopeEntry(false, "*." + hostname + ".", "HTTP", 65_535, "/.*");
            validate(longest);
            assertEquals(longest, new ScopeEditor(longest).value());
            String expression = "\\A\\Q/a\\E.*\\Q/b\\E\\z";
            ScopeEntry advanced = new ScopeEntry(true, "example.test", "https", 443, expression);
            validate(advanced);
            ScopeEditor editor = new ScopeEditor(advanced);
            assertEquals(3, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertEquals(advanced, editor.value());
            assertTrue(matches(advanced, "/a/anything/b"));
            return null;
        });
    }

    @Test void excessiveRe2ProgramsAndUnsupportedSchemeSpellingsHaveFixedErrors() throws Exception {
        edt(() -> {
            assertThrows(FormValidationException.class, () -> new ScopeEditor(new ScopeEntry(true, "example.test", "httpſ", 443, ".*")));
            ScopeEditor editor = new ScopeEditor(ORIGINAL);
            get(editor, "scope.regex", JTextArea.class).setText("(?:abcde){1000}");
            FormValidationException error = assertThrows(FormValidationException.class, editor::value);
            assertTrue(error.getMessage().contains("너무 복잡"));
            assertFalse(error.getMessage().contains("abcde"));
            assertNull(error.getCause());
            return null;
        });
    }

    @Test void namesLabelsAndRenderersAreAccessibleAndNeverInterpretOperatorHtml() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(new ScopeEntry(true, "example.test", "https", 443, "<html><b>synthetic</b></html>"));
            Map<String, JComponent> names = new LinkedHashMap<>();
            for (Component item : descendants(editor.component())) {
                if (!(item instanceof JComponent control) || control.getName() == null) continue;
                assertNull(names.put(control.getName(), control), control.getName());
                assertNotNull(control.getAccessibleContext().getAccessibleName(), control.getName());
                if (control instanceof JLabel label) {
                    assertEquals(Boolean.TRUE, label.getClientProperty("html.disable"));
                    assertNull(label.getClientProperty(BasicHTML.propertyKey));
                    assertNotNull(label.getLabelFor());
                }
                if (control instanceof AbstractButton button)
                    assertEquals(Boolean.TRUE, button.getClientProperty("html.disable"));
            }
            assertTrue(names.keySet().containsAll(List.of("scope.editor", "scope.url", "scope.fillUrl", "scope.host",
                    "scope.scheme", "scope.port", "scope.anyPort", "scope.pathMode", "scope.path", "scope.regex",
                    "scope.enabled", "scope.preview", "scope.message")));
            JTextArea preview = get(editor, "scope.preview", JTextArea.class);
            assertFalse(preview.isEditable());
            assertTrue(preview.getText().contains("<html><b>synthetic</b></html>"));
            assertNull(preview.getClientProperty(BasicHTML.propertyKey));
            assertFalse(get(editor, "scope.message", JTextArea.class).isEditable());
            assertEquals(get(editor, "scope.regex", JTextArea.class), get(editor, "scope.path.label", JLabel.class).getLabelFor());
            for (String name : List.of("scope.scheme", "scope.pathMode")) assertLiteralRenderer(get(editor, name, JComboBox.class));
            return null;
        });
        String summary = ScopeEditor.summary(new ScopeEntry(false, "<html>" + "x".repeat(2_000), "any", 0, "a".repeat(2_048)));
        assertTrue(summary.length() < 220);
        assertFalse(summary.startsWith("<html>"));
        assertTrue(summary.contains("고급 RE2"));
        assertTrue(summary.contains("모든 포트"));
        assertEquals("대상 없음", ScopeEditor.summary(null));
    }

    @Test void scrollableFormKeepsControlsUsableWithLargeBurpThemeFonts() throws Exception {
        edt(() -> {
            Map<String, Object> saved = new LinkedHashMap<>();
            for (String key : List.of("Label.font", "TextArea.font", "TextField.font", "Button.font", "ComboBox.font", "CheckBox.font", "Panel.font")) {
                saved.put(key, UIManager.get(key));
                UIManager.put(key, new FontUIResource(Font.DIALOG, Font.PLAIN, 28));
            }
            try {
                ScopeEditor editor = new ScopeEditor(ORIGINAL);
                JScrollPane root = (JScrollPane) editor.component();
                root.setSize(1_000, 620);
                for (int i = 0; i < 4; i++) layout(root);
                assertEquals(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER, root.getHorizontalScrollBarPolicy());
                assertTrue(root.getViewport().getView().getHeight() > root.getViewport().getHeight());
                for (String name : List.of("scope.host", "scope.url", "scope.port", "scope.fillUrl", "scope.scheme", "scope.pathMode")) {
                    JComponent control = get(editor, name, JComponent.class);
                    assertTrue(control.getHeight() >= control.getFontMetrics(control.getFont()).getHeight(), name + " height");
                    assertTrue(control.getWidth() > 0, name + " width");
                }
                JButton fill = get(editor, "scope.fillUrl", JButton.class);
                assertTrue(fill.getWidth() >= fill.getPreferredSize().width);
                get(editor, "scope.url", JTextField.class).setText("https://example.test/safe");
                click(editor, "scope.fillUrl");
                assertTrue(matches(editor.value(), "/safe"));
            } finally {
                saved.forEach(UIManager::put);
            }
            return null;
        });
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static void assertLiteralRenderer(JComboBox combo) {
        JLabel rendered = (JLabel) combo.getRenderer().getListCellRendererComponent(new JList<>(), "<html><b>synthetic</b></html>", 0, false, false);
        assertEquals("<html><b>synthetic</b></html>", rendered.getText());
        assertEquals(Boolean.TRUE, rendered.getClientProperty("html.disable"));
        assertNull(rendered.getClientProperty(BasicHTML.propertyKey));
    }

    private static boolean matches(ScopeEntry entry, String path) {
        return entry.pathRegex().isEmpty() || Pattern.compile(entry.pathRegex()).matcher(path).matches();
    }

    private static GuardConfig policy(ScopeEntry entry) {
        GuardConfig defaults = GuardConfig.defaults();
        return new GuardConfig(1, List.of(entry), List.of(), List.of(), Mode.ALLOW, defaults.limits());
    }

    private static void validate(ScopeEntry entry) { new PolicyEngine().validate(policy(entry)); }

    private static Mode evaluate(ScopeEntry entry, String url, String host, int port, boolean secure) {
        return new PolicyEngine().evaluate(policy(entry), new RequestData("GET", url, host, port, secure, List.of(), new byte[0])).mode();
    }

    private static void click(ScopeEditor editor, String name) { get(editor, name, AbstractButton.class).doClick(); }

    private static <T extends Component> T get(ScopeEditor editor, String name, Class<T> type) {
        for (Component child : descendants(editor.component())) if (name.equals(child.getName())) return type.cast(child);
        throw new AssertionError("Missing component: " + name);
    }

    private static List<Component> descendants(Component root) {
        List<Component> result = new ArrayList<>();
        result.add(root);
        if (root instanceof Container container) for (Component child : container.getComponents()) result.addAll(descendants(child));
        return result;
    }

    private static void layout(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) if (child instanceof Container nested) layout(nested);
    }

    private static <T> T edt(Callable<T> call) throws Exception {
        AtomicReference<T> value = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { value.set(call.call()); }
            catch (Throwable failure) { error.set(failure); }
        });
        if (error.get() instanceof Error failure) throw failure;
        if (error.get() instanceof Exception failure) throw failure;
        return value.get();
    }
}
