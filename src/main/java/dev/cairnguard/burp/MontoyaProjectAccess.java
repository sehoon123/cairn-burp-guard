package dev.cairnguard.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.project.Project;
import dev.cairnguard.runtime.ProjectAccess;
import java.util.Objects;

/** Operator-authored JSON only, in Montoya's project-scoped extensionData (never global preferences). */
public final class MontoyaProjectAccess implements ProjectAccess {
    static final String KEY_PREFIX = "cairn-proxy-guard.policy.v1.";
    static final int MAX_CONFIG_CHARS = 2_097_152;
    private final MontoyaApi api;

    public MontoyaProjectAccess(MontoyaApi api) { this.api = Objects.requireNonNull(api); }

    @Override public Ref current() {
        try { return readCurrent(); }
        catch (RuntimeException | LinkageError e) { throw failure(); }
    }

    private Ref readCurrent() {
        Project project = api.project();
        String id = project.id();
        String name = project.name();
        if (id == null || id.isBlank() || id.length() > 512) throw failure();
        // Native IDs are opaque metadata, not free-form UI/traffic. Reject unexpected controls/markup.
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.')) throw failure();
        }
        if (name == null || name.length() > 512) throw failure();
        return new Ref(id, name);
    }

    @Override public String load() {
        try {
            Ref before = current();
            PersistedObject data = api.persistence().extensionData();
            sameProject(before);
            String json = data.getString(KEY_PREFIX + before.id());
            sameProject(before);
            if (json != null && json.length() > MAX_CONFIG_CHARS) throw failure();
            return json;
        } catch (RuntimeException | LinkageError e) { throw failure(); }
    }

    @Override public void save(String json) {
        if (json == null || json.length() > MAX_CONFIG_CHARS) throw failure();
        try {
            Ref before = current();
            PersistedObject data = api.persistence().extensionData();
            sameProject(before);
            // Also namespace the project-local key by ID: a switch during a native call must never
            // make the old editor's draft load as the new project's configuration.
            data.setString(KEY_PREFIX + before.id(), json);
            sameProject(before);
        } catch (RuntimeException | LinkageError e) { throw failure(); }
    }

    private void sameProject(Ref expected) { if (!expected.id().equals(current().id())) throw failure(); }
    private static IllegalStateException failure() { return new IllegalStateException("PROJECT_STORAGE_UNAVAILABLE"); }
}
