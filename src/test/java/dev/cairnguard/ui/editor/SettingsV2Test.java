package dev.cairnguard.ui.editor;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import static org.junit.jupiter.api.Assertions.*;

/** Human draft editing, with all schema-2 components exercised (not JSON-only configuration). */
class SettingsV2Test {
    static GuardConfig configured() {
        Limits l = new Limits(9, 4, Map.of("Example.TEST.", 3), 2, 21, 3001, 4002, 5003,
                1_048_577, 123_456, new Circuit5xx(23_456, 7, 54_321, 1),
                new Fanout(12_345, 42, FanoutAction.BLOCK), 123, true,
                List.of(new ProbePath("https", "Example.TEST.", 443, "/health")),
                List.of(new PathByteLimit("https", "Example.TEST.", 443, "/large", 1)));
        return new GuardConfig(2, List.of(), List.of(), GuardConfig.defaults().rules(), Mode.ASK, l, List.of(8080, 8081));
    }

    @Test void everyV2ComponentRoundTripsLosslesslyAcrossBasicHostPresetAndReopen() throws Exception {
        edt(() -> {
            GuardConfig original = configured();
            SettingsEditor editor = new SettingsEditor(original);
            assertEquals(original.limits(), editor.value().limits());
            assertEquals(original.guardListenerPorts(), editor.value().guardListenerPorts());
            get(editor, "settings.preset.slow", JButton.class).doClick(0);
            get(editor, "settings.hostRps.table", JTable.class).setValueAt("6", 0, 1);
            SettingsEditor.Value value = editor.value();
            Limits old = original.limits();
            Limits expected = new Limits(1, 1, Map.of("Example.TEST.", 6), 1, old.maxQueued(), old.queueTimeoutMillis(), old.approvalTimeoutMillis(), old.requestTimeoutMillis(),
                    old.perPathMaxResponseBytes(), old.autoBlockMillis(), old.circuit5xx(), old.fanout(), old.perIntentMaxRequests(), old.healthProbePassthrough(), old.healthProbePaths(), old.heavyPathLimits());
            assertEquals(expected, value.limits());
            assertEquals(new SettingsEditor.Value(original.defaultMode(), expected, original.guardListenerPorts()),
                    new SettingsEditor(new GuardConfig(2, original.allowScope(), original.blockScope(), original.rules(), value.defaultMode(), value.limits(), value.guardListenerPorts())).value());
            assertEquals(configured(), original, "draft actions cannot mutate policy");
            return null;
        });
    }

    @Test void allSafetyControlsAuthorActualModelsAndActiveRouteEditsAreCommitted() throws Exception {
        edt(() -> {
            SettingsEditor editor = new SettingsEditor(GuardConfig.defaults());
            text(editor, "heavyMiB", "2.5"); text(editor, "autoBlockSeconds", "1.001");
            text(editor, "circuit.windowSeconds", "3.001"); text(editor, "circuit.threshold", "2"); text(editor, "circuit.openSeconds", "4.005");
            text(editor, "fanout.windowSeconds", "5.006"); text(editor, "fanout.distinctPaths", "7");
            get(editor, "settings.fanout.action", JComboBox.class).setSelectedItem(FanoutAction.PAUSE);
            text(editor, "intent.maxRequests", "20");
            assertFalse(get(editor, "settings.listenerPorts", JTextField.class).isEditable());
            get(editor, "settings.probes.enabled", JCheckBox.class).setSelected(true);
            get(editor, "settings.probes.add", JButton.class).doClick(0);
            JTable probes = get(editor, "settings.probes.table", JTable.class);
            probes.setValueAt("example.test", 0, 1); probes.setValueAt("/health", 0, 3);
            assertTrue(probes.editCellAt(0, 3)); ((JTextField) probes.getEditorComponent()).setText("/ready");
            get(editor, "settings.pathLimits.add", JButton.class).doClick(0);
            JTable paths = get(editor, "settings.pathLimits.table", JTable.class);
            paths.setValueAt("http", 0, 0); paths.setValueAt("example.test", 0, 1); paths.setValueAt("80", 0, 2); paths.setValueAt("/large", 0, 3); paths.setValueAt("0.00000095367431640625", 0, 4);
            SettingsEditor.Value result = editor.value(); Limits l = result.limits();
            assertFalse(probes.isEditing()); assertEquals(2_621_440, l.perPathMaxResponseBytes()); assertEquals(1001, l.autoBlockMillis());
            assertEquals(new Circuit5xx(3001, 2, 4005, 1), l.circuit5xx());
            assertEquals(new Fanout(5006, 7, FanoutAction.PAUSE), l.fanout()); assertEquals(20, l.perIntentMaxRequests());
            assertTrue(result.guardListenerPorts().isEmpty(), "Per-port protection is deferred; new settings protect all listeners");
            assertEquals(List.of(new ProbePath("https", "example.test", 443, "/ready")), l.healthProbePaths());
            assertEquals(List.of(new PathByteLimit("http", "example.test", 80, "/large", 1)), l.heavyPathLimits());
            get(editor, "settings.probes.enabled", JCheckBox.class).setSelected(false);
            get(editor, "settings.circuit.enabled", JCheckBox.class).setSelected(false);
            get(editor, "settings.fanout.enabled", JCheckBox.class).setSelected(false);
            Limits off = editor.value().limits(); assertFalse(off.healthProbePassthrough()); assertNull(off.circuit5xx()); assertNull(off.fanout());
            assertEquals(l.healthProbePaths(), off.healthProbePaths()); assertEquals(l.heavyPathLimits(), off.heavyPathLimits());
            return null;
        });
    }

    @Test void invalidThresholdsWindowsCountersListenersAndRoutesCannotBecomeSilentDefaults() throws Exception {
        edt(() -> {
            for (var test : Map.of(
                    "heavyMiB", List.of("-1", "2048.1", "0.1", "1e3", "NaN"),
                    "autoBlockSeconds", List.of("0.999", "86400.001"),
                    "circuit.threshold", List.of("0", "1.5", "1001"),
                    "circuit.windowSeconds", List.of("0", "3600.001"),
                    "fanout.distinctPaths", List.of("1", "1001"),
                    "intent.maxRequests", List.of("-1", "1000001"),
                    "listenerPorts", List.of("8080", "8080, 8081", "8080,8080", "0", "65536", "8080,", "+8080", "80.1")
            ).entrySet()) for (String invalid : test.getValue()) {
                SettingsEditor editor = new SettingsEditor(GuardConfig.defaults()); text(editor, test.getKey(), invalid);
                assertThrows(FormValidationException.class, editor::value, test.getKey() + ": " + invalid);
            }
            for (String invalid : List.of("/h?secret=synthetic", "/h/../ready", "/h;v", "/%2e/ready", "/h#x")) {
                SettingsEditor editor = new SettingsEditor(configured());
                get(editor, "settings.probes.table", JTable.class).setValueAt(invalid, 0, 3);
                assertThrows(FormValidationException.class, editor::value);
            }
            SettingsEditor editor = new SettingsEditor(configured());
            JTextField ports = get(editor, "settings.listenerPorts", JTextField.class); ports.setText("x".repeat(4097));
            assertThrows(FormValidationException.class, editor::value, "overlong rejection must not save the previous valid input");
            ports.setText(""); assertTrue(editor.value().guardListenerPorts().isEmpty());
            return null;
        });
    }

    @Test void noExemptDefaultAndV1SafeDefaultsRemainOffOnSimpleEdits() throws Exception {
        edt(() -> {
            GuardConfig d = GuardConfig.defaults();
            Limits old = new Limits(5,5,Map.of(),5,100,30_000,30_000,60_000);
            SettingsEditor editor = new SettingsEditor(new GuardConfig(2,List.of(),List.of(),d.rules(),Mode.ALLOW,old));
            JComboBox<?> modes = get(editor, "settings.defaultMode", JComboBox.class);
            for (int i=0;i<modes.getItemCount();i++) assertNotEquals(Mode.EXEMPT,modes.getItemAt(i));
            get(editor, "settings.preset.slow", JButton.class).doClick(0);
            Limits result = editor.value().limits(); assertEquals(0,result.perPathMaxResponseBytes()); assertNull(result.circuit5xx()); assertNull(result.fanout());
            assertEquals(0,result.perIntentMaxRequests()); assertFalse(result.healthProbePassthrough());
            return null;
        });
    }

    private static void text(SettingsEditor editor, String suffix, String value) { get(editor,"settings."+suffix,JTextField.class).setText(value); }
    private static <T> T get(SettingsEditor e,String name,Class<T> type) { return type.cast(find(e.component(),name)); }
    static Component find(Component c,String name) { if(name.equals(c.getName()))return c; if(c instanceof Container p)for(Component child:p.getComponents()){Component found=find(child,name);if(found!=null)return found;} return null; }
    private static <T>T edt(Callable<T> c)throws Exception { FutureTask<T> f=new FutureTask<>(c); SwingUtilities.invokeAndWait(f); return f.get(); }
}
