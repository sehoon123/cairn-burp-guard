package dev.cairnguard;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import dev.cairnguard.burp.BurpLifecycle;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Montoya 2026.7 entry point. Only Proxy callbacks and local human UI controls are registered. */
public final class GuardExtension implements BurpExtension, AutoCloseable {
    private final AtomicBoolean initialized = new AtomicBoolean();
    private final AtomicReference<BurpLifecycle> lifecycle = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    @Override public void initialize(MontoyaApi api) {
        if (!initialized.compareAndSet(false, true)) throw new IllegalStateException("ALREADY_INITIALIZED");
        if (closed.get()) throw new IllegalStateException("SHUTDOWN");
        BurpLifecycle created = new BurpLifecycle(api);
        lifecycle.set(created);
        if (closed.get()) { created.close(); return; }
        created.initialize();
    }

    @Override public void close() {
        closed.set(true);
        BurpLifecycle old = lifecycle.getAndSet(null);
        if (old != null) old.close();
    }
}
