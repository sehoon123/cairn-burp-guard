package dev.cairnguard.runtime;

/** Project-local operator policy persistence; no filesystem or network/agent control API. */
public interface ProjectAccess {
    record Ref(String id, String name) {}
    Ref current();
    String load();
    void save(String json);
}
