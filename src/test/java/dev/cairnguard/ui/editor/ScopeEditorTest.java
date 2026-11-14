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
        assertThrows(IllegalStateException.class, () -> new ScopeEditor(List.of(), List.of()));
        ScopeEditor editor = edt(() -> new ScopeEditor(List.of(), List.of()));
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
            ScopeEntry result = single(editor);
            assertEquals("example.test", result.host());
            assertTrue(matches(result, "/"));
            assertFalse(matches(result, "/other"));
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("포트: 443"));
            return null;
        });
    }

    @Test void pastedUrlRequiresExplicitApplicationAndNeverUsesAnyPortOrAllPaths() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
            JTextField input = get(editor, "scope.url", JTextField.class);
            input.setText("http://Sub.Example.test:8080/api/v1/item.+(test)$");
            assertEquals("example.test", get(editor, "scope.host", JTextField.class).getText());
            assertTrue(assertThrows(FormValidationException.class, editor::value).getMessage().contains("폼에 반영"));
            click(editor, "scope.fillUrl");
            ScopeEntry entry = single(editor);
            assertEquals("Sub.Example.test", entry.host());
            assertEquals("http", entry.scheme());
            assertEquals(8080, entry.port());
            assertEquals("/api/v1/item.+(test)$", get(editor, "scope.path", JTextArea.class).getText());
            assertEquals(0, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertTrue(matches(entry, "/api/v1/item.+(test)$"));
            assertFalse(matches(entry, "/api/v1/itemXXtest"));
            assertFalse(matches(entry, "/api/v1/item.+(test)$/child"));
            assertFalse(matches(entry, "/"));
            assertEquals(entry, single(new ScopeEditor(List.of(entry), List.of(0))));
            assertEquals(input.getText(), get(editor, "scope.url", JTextField.class).getText());
            return null;
        });
    }

    @Test void enterExplicitlyFillsExactScopeAndStillRejectsSensitiveUrlWithoutAnImplicitOldSave() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
            JTextField input = get(editor, "scope.url", JTextField.class);
            input.setText("http://127.0.0.1:18080/safe");
            input.postActionEvent();
            ScopeEntry result = single(editor);
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
                ScopeEditor editor = new ScopeEditor(List.of(), List.of());
                get(editor, "scope.url", JTextField.class).setText(address);
                click(editor, "scope.fillUrl");
                ScopeEntry entry = single(editor);
                assertEquals(address.startsWith("https") ? "https" : "http", entry.scheme());
                assertEquals(address.contains("8443") ? 8443 : address.startsWith("https") ? 443 : 80, entry.port());
                String expectedPath = address.contains("%2F") ? "/a%2Fb/" : "/";
                assertEquals(expectedPath, get(editor, "scope.path", JTextArea.class).getText());
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
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
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
                assertEquals(ORIGINAL, single(editor), address);
            }
            return null;
        });
    }

    @Test void rejectedUrlCannotBecomeAnImplicitOldSaveOrPartialOverwrite() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
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
            assertEquals("manual.example.test", single(editor).host());
            assertEquals("http", single(editor).scheme());
            assertTrue(matches(single(editor), "/changed"));
            return null;
        });
    }

    @Test void existingWildcardsAnyPortAnySchemeAndArbitraryRegexRoundTripByteForByte() throws Exception {
        edt(() -> {
            for (String expression : List.of("", ".*", "/", "/safe(?:/.*)?", "(?i)/safe/[a-z]+", "/line\n\r\t", "/value\\Q.+\\E")) {
                for (String target : List.of("*.Example.test.", "bücher.example", "[2001:db8::1]", "127.0.0.1")) {
                    ScopeEntry entry = new ScopeEntry(false, target, "AnY", 0, expression);
                    validate(entry);
                    ScopeEditor editor = new ScopeEditor(List.of(entry), List.of(0));
                    assertEquals(entry, single(editor));
                    assertEquals(expression, entry.pathRegex().isEmpty() ? single(editor).pathRegex()
                            : get(editor, "scope.regex", JTextArea.class).getText());
                    click(editor, "scope.enabled");
                    assertEquals(new ScopeEntry(true, target, "AnY", 0, expression), single(editor));
                }
            }
            return null;
        });
    }

    @Test void hostPreviewExplainsCanonicalAuthorityAndWildcardExcludesBaseDomain() throws Exception {
        edt(() -> {
            ScopeEntry entry = new ScopeEntry(true, "*.Example.test.", "HTTPS", 0, ".*");
            ScopeEditor editor = new ScopeEditor(List.of(entry), List.of(0));
            assertEquals(entry, single(editor));
            String preview = get(editor, "scope.preview", JTextArea.class).getText();
            assertTrue(preview.contains("*.example.test"));
            assertTrue(preview.contains("기본 도메인 제외"));
            assertTrue(preview.contains("모든 포트"));
            assertEquals(Mode.ALLOW, evaluate(entry, "https://child.example.test/", "child.example.test", 443, true));
            assertEquals(Mode.BLOCK, evaluate(entry, "https://example.test/", "example.test", 443, true));
            get(editor, "scope.url", JTextField.class).setText("https://[2001:db8::1]:8443/safe");
            click(editor, "scope.fillUrl");
            assertEquals("[2001:db8::1]", single(editor).host());
            assertEquals(8443, single(editor).port());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("[2001:db8:0:0:0:0:0:1]"));
            return null;
        });
    }

    @Test void exactAndSubpathModesEscapeRegexAndDoNotWidenHostOrSiblingPath() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(), List.of());
            get(editor, "scope.host", JTextField.class).setText("example.test");
            get(editor, "scope.path", JTextArea.class).setText("/api/v1/item.+(test)$");
            ScopeEntry exact = single(editor);
            validate(exact);
            assertTrue(matches(exact, "/api/v1/item.+(test)$"));
            assertFalse(matches(exact, "/api/v1/itemXXtest"));
            assertFalse(matches(exact, "/api/v1/item.+(test)$/child"));
            assertEquals(Mode.BLOCK, evaluate(exact, "https://other.example.test/api/v1/item.+(test)$", "other.example.test", 443, true));
            assertEquals(Mode.ALLOW, evaluate(exact, "https://example.test/api/v1/item.+(test)$", "example.test", 443, true));
            get(editor, "scope.path", JTextArea.class).setText("/api");
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(1);
            ScopeEntry prefix = single(editor);
            validate(prefix);
            assertTrue(matches(prefix, "/api"));
            assertTrue(matches(prefix, "/api/"));
            assertTrue(matches(prefix, "/api/child"));
            assertFalse(matches(prefix, "/apix"));
            assertFalse(matches(prefix, "/api.json"));
            assertEquals(prefix, single(new ScopeEditor(List.of(prefix), List.of(0))));
            get(editor, "scope.path", JTextArea.class).setText("/api/");
            ScopeEntry slashPrefix = single(editor);
            assertFalse(matches(slashPrefix, "/api"));
            assertTrue(matches(slashPrefix, "/api/child"));
            assertEquals(slashPrefix, single(new ScopeEditor(List.of(slashPrefix), List.of(0))));
            get(editor, "scope.path", JTextArea.class).setText("/");
            assertTrue(matches(single(editor), "/any/child"));
            assertEquals(single(editor), single(new ScopeEditor(List.of(single(editor)), List.of(0))));
            return null;
        });
    }

    @Test void allPathsAndAdvancedRegexRequireExplicitChoicesAndKeepFullMatchSemantics() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
            get(editor, "scope.regex", JTextArea.class).setText("");
            assertTrue(assertThrows(FormValidationException.class, editor::value).getMessage().contains("모든 경로"));
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(2);
            assertEquals("", single(editor).pathRegex());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains("제한 없음"));
            get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(3);
            get(editor, "scope.regex", JTextArea.class).setText("/safe/[0-9]+");
            ScopeEntry entry = single(editor);
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
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
                int maximum = switch (name) {
                    case "scope.host" -> 257;
                    case "scope.url" -> 16_384;
                    case "scope.port" -> 2_048;
                    case "scope.path" -> 66_048;
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
                assertEquals(ORIGINAL, single(editor));
            }
            ScopeEntry longest = new ScopeEntry(true, "example.test", "https", 443, "a".repeat(2_048));
            validate(longest);
            ScopeEditor editor = new ScopeEditor(List.of(longest), List.of(0));
            assertEquals(longest, single(editor));
            assertEquals(2_048, get(editor, "scope.regex", JTextArea.class).getText().length());
            assertTrue(get(editor, "scope.preview", JTextArea.class).getText().contains(longest.pathRegex()));
            assertThrows(FormValidationException.class, () -> new ScopeEditor(List.of(new ScopeEntry(true, "example.test", "https", 443, "a".repeat(2_049))), List.of(0)));
            return null;
        });
    }

    @Test void generatedPatternBoundsAreCheckedAfterQuotingAndNeverTruncatePath() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(), List.of());
            get(editor, "scope.host", JTextField.class).setText("example.test");
            String tooLong = "/" + "a".repeat(2_047);
            get(editor, "scope.path", JTextArea.class).setText(tooLong);
            assertEquals(tooLong, get(editor, "scope.path", JTextArea.class).getText());
            assertThrows(FormValidationException.class, editor::value);
            get(editor, "scope.path", JTextArea.class).setText("/" + "a".repeat(2_039));
            ScopeEntry limit = single(editor);
            assertEquals(2_048, limit.pathRegex().length());
            validate(limit);
            assertEquals(limit, single(new ScopeEditor(List.of(limit), List.of(0))));
            return null;
        });
    }

    @Test void invalidManualHostPortAndPathCannotCoerceAnyScopeEvenWhenDisabled() throws Exception {
        edt(() -> {
            for (String invalid : List.of("*", "*.127.0.0.1", "*.[::1]", "https://example.test", "example.test:443", "example.test/path", " example.test", "127.1", "example.test\n")) {
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
                get(editor, "scope.host", JTextField.class).setText(invalid);
                click(editor, "scope.enabled");
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            for (String invalid : List.of("", "0", "-1", "+443", "1.5", "65536", "443\n")) {
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
                get(editor, "scope.port", JTextField.class).setText(invalid);
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            for (String invalid : List.of("", "relative", "/a/../b", "/a/./b", "/a?query", "/a#fragment", "/a;b", "/a\\b", "/a\n\n/b", "/a\r", "/a\n\n", "/a\t", "/a\u0001", "/a b", "/bad%ZZ")) {
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
                get(editor, "scope.pathMode", JComboBox.class).setSelectedIndex(0);
                get(editor, "scope.path", JTextArea.class).setText(invalid);
                assertThrows(FormValidationException.class, editor::value, invalid);
            }
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
            click(editor, "scope.anyPort");
            assertEquals(0, single(editor).port());
            assertFalse(get(editor, "scope.port", JTextField.class).isEnabled());
            get(editor, "scope.scheme", JComboBox.class).setSelectedIndex(2);
            assertEquals("any", single(editor).scheme());
            return null;
        });
    }

    @Test void literalUnicodePlusAndRepeatedSlashesAreNotNormalizedOrExpanded() throws Exception {
        edt(() -> {
            for (String literal : List.of("/한글/😀", "/a+b", "//example.test//path", "/file.(draft)$")) {
                ScopeEditor editor = new ScopeEditor(List.of(), List.of());
                get(editor, "scope.host", JTextField.class).setText("example.test");
                get(editor, "scope.path", JTextArea.class).setText(literal);
                ScopeEntry entry = single(editor);
                assertTrue(matches(entry, literal));
                assertFalse(matches(entry, literal + "/child"));
                assertEquals(literal.startsWith("//") ? Mode.BLOCK : Mode.ALLOW,
                        evaluate(entry, "https://example.test" + literal, "example.test", 443, true),
                        "A restricted scope must cover internal routing aliases too; the native target is never rewritten.");
                assertEquals(entry, single(new ScopeEditor(List.of(entry), List.of(0))));
            }
            return null;
        });
    }

    @Test void longestValidHostAndRegexThatResemblesGeneratedSyntaxRemainLossless() throws Exception {
        edt(() -> {
            String hostname = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
            ScopeEntry longest = new ScopeEntry(false, "*." + hostname + ".", "HTTP", 65_535, "/.*");
            validate(longest);
            assertEquals(longest, single(new ScopeEditor(List.of(longest), List.of(0))));
            String expression = "\\A\\Q/a\\E.*\\Q/b\\E\\z";
            ScopeEntry advanced = new ScopeEntry(true, "example.test", "https", 443, expression);
            validate(advanced);
            ScopeEditor editor = new ScopeEditor(List.of(advanced), List.of(0));
            assertEquals(3, get(editor, "scope.pathMode", JComboBox.class).getSelectedIndex());
            assertEquals(advanced, single(editor));
            assertTrue(matches(advanced, "/a/anything/b"));
            return null;
        });
    }

    @Test void excessiveRe2ProgramsAndUnsupportedSchemeSpellingsHaveFixedErrors() throws Exception {
        edt(() -> {
            assertThrows(FormValidationException.class, () -> new ScopeEditor(List.of(new ScopeEntry(true, "example.test", "httpſ", 443, ".*")), List.of(0)));
            ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
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
            ScopeEditor editor = new ScopeEditor(List.of(new ScopeEntry(true, "example.test", "https", 443, "<html><b>synthetic</b></html>")), List.of(0));
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
                ScopeEditor editor = new ScopeEditor(List.of(ORIGINAL), List.of(0));
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
                assertTrue(matches(single(editor), "/safe"));
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

    @Test void finalLfOrCrLfIsListFormattingAndNeverChangesExactPathMeaning() throws Exception {
        edt(() -> {
            for (String ending : List.of("\n", "\r\n")) {
                ScopeEditor editor = new ScopeEditor(List.of(), List.of());
                get(editor, "scope.host", JTextField.class).setText("example.test");
                get(editor, "scope.path", JTextArea.class).setText("/a" + ending);
                ScopeEntry entry = single(editor);
                assertTrue(matches(entry, "/a"));
                for (String outside : List.of("/apix", "/a/child", "/admin")) assertFalse(matches(entry, outside));
            }
            return null;
        });
    }

    @Test void realListsPreviewEveryPairAndReopenWithoutAnImplicitSchemeChange() throws Exception {
        edt(() -> {
            ScopeEditor editor = new ScopeEditor(List.of(), List.of());
            get(editor, "scope.host", JTextField.class).setText("example.test");
            get(editor, "scope.port", JTextField.class).setText("80,443");
            get(editor, "scope.path", JTextArea.class).setText("/api\n/manager");
            List<ScopeEntry> rows = editor.value();
            assertEquals(4, rows.size());
            assertTrue(rows.stream().allMatch(entry -> entry.scheme().equals("https")));
            String preview = get(editor, "scope.preview", JTextArea.class).getText();
            assertTrue(preview.contains("모든 4쌍"));
            assertTrue(preview.contains("포트: 80") && preview.contains("포트: 443"));
            for (ScopeEntry row : rows) assertTrue(preview.contains(row.pathRegex()));
            ScopeEditor reopened = new ScopeEditor(rows, List.of(0, 1, 2, 3));
            assertEquals(rows, reopened.value());
            assertEquals("80,443", get(reopened, "scope.port", JTextField.class).getText());
            assertEquals("/api\n/manager", get(reopened, "scope.path", JTextArea.class).getText());
            get(reopened, "scope.path", JTextArea.class).setText("/api");
            assertEquals(2, reopened.value().size());
            assertTrue(get(reopened, "scope.preview", JTextArea.class).getText().contains("제거·교체 2개"));
            get(reopened, "scope.scheme", JComboBox.class).setSelectedIndex(2);
            assertTrue(reopened.value().stream().allMatch(entry -> entry.scheme().equals("any")));
            assertTrue(get(reopened, "scope.preview", JTextArea.class).getText().contains("각 포트에 두 방식"));
            get(reopened, "scope.port", JTextField.class).setText("80,080");
            assertThrows(FormValidationException.class, reopened::value);
            assertTrue(get(reopened, "scope.message", JTextArea.class).getText().contains("중복"));
            return null;
        });
    }

    @Test void irregularMembersRequireExplicitApplyAndRejectDirtySwitchingUntilReset() throws Exception {
        edt(() -> {
            ScopeEntry first = new ScopeEntry(true, "example.test", "https", 80, "\\A\\Q/api\\E\\z");
            ScopeEntry second = new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/manager\\E\\z");
            List<ScopeEntry> original = List.of(first, second);
            ScopeEditor editor = new ScopeEditor(original, List.of(0, 1));
            javax.swing.JTable table = get(editor, "scope.members.table", javax.swing.JTable.class);
            assertFalse(table.isCellEditable(0, 0));
            table.clearSelection(); assertEquals(0, table.getSelectedRow(), "the current draft member stays visibly selected");
            assertEquals(original, editor.value());
            get(editor, "scope.port", JTextField.class).setText("80,443");
            click(editor, "scope.member.apply");
            assertTrue(get(editor, "scope.message", JTextArea.class).getText().contains("하나"));
            assertThrows(FormValidationException.class, editor::value);
            table.setRowSelectionInterval(1, 1);
            assertEquals(0, table.getSelectedRow(), "dirty input must not be silently discarded");
            click(editor, "scope.member.reset");
            get(editor, "scope.url", JTextField.class).setText("https://example.test/changed");
            assertThrows(FormValidationException.class, editor::value);
            click(editor, "scope.member.reset");
            get(editor, "scope.port", JTextField.class).setText("8080");
            click(editor, "scope.member.apply");
            table.setRowSelectionInterval(1, 1);
            assertEquals("443", get(editor, "scope.port", JTextField.class).getText());
            get(editor, "scope.path", JTextArea.class).setText("/manager2");
            assertThrows(FormValidationException.class, editor::value);
            click(editor, "scope.member.apply");
            List<ScopeEntry> revised = editor.value();
            assertEquals(2, revised.size());
            assertEquals(8080, revised.getFirst().port());
            assertTrue(matches(revised.getFirst(), "/api")); assertFalse(matches(revised.getFirst(), "/manager2"));
            assertEquals(443, revised.getLast().port());
            assertTrue(matches(revised.getLast(), "/manager2")); assertFalse(matches(revised.getLast(), "/api"));
            return null;
        });
    }

    @Test void selectedLegacyMembersAndEncodedPredicatesRemainSeparateAndLossless() throws Exception {
        edt(() -> {
            List<ScopeEntry> legacy = List.of(new ScopeEntry(false, "*.Example.test.", "AnY", 0, "(?i)/line\n\r\t"),
                    new ScopeEntry(false, "[2001:db8::1]", "HTTPS", 443, "\\A\\Q/a\\E.*\\Q/b\\E\\z"));
            ScopeEditor editor = new ScopeEditor(legacy, List.of(0, 1));
            assertEquals(legacy, editor.value());
            javax.swing.JTable table = get(editor, "scope.members.table", javax.swing.JTable.class);
            table.setRowSelectionInterval(1, 1);
            assertEquals(legacy.getLast().pathRegex(), get(editor, "scope.regex", JTextArea.class).getText());
            assertEquals(legacy, editor.value());
            List<ScopeEntry> encoded = List.of(new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/%61pi\\E\\z"),
                    new ScopeEntry(true, "example.test", "https", 443, "\\A\\Q/api\\E\\z"));
            ScopeEditor pairs = new ScopeEditor(encoded, List.of(0, 1));
            assertEquals(encoded, pairs.value());
            GuardConfig config = new GuardConfig(2, pairs.value(), List.of(), List.of(), Mode.ALLOW, GuardConfig.defaults().limits());
            assertEquals(Mode.BLOCK, new PolicyEngine().evaluate(config, new RequestData("GET", "https://display.invalid/", "example.test", 443, true, List.of(), new byte[0], true, true, "/%61pi")).mode());
            return null;
        });
    }

    private static ScopeEntry single(ScopeEditor editor) {
        List<ScopeEntry> section = editor.value();
        assertEquals(1, section.size(), "a single-entry form must never hide extra permissions");
        return section.getFirst();
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
