package dev.cairnguard.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import dev.cairnguard.runtime.GuardController;
import dev.cairnguard.ui.GuardPanel;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;

/** Owns registrations and the local human tab. No polling/watcher/executor threads are created. */
public final class BurpLifecycle implements AutoCloseable {
    private final MontoyaApi api;
    private final GuardController controller;
    private final ProxyGuardHandler handler;
    private final AtomicBoolean initialized = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicReference<Registration> httpRegistration = new AtomicReference<>();
    private final AtomicReference<Registration> tabRegistration = new AtomicReference<>();
    private final AtomicReference<Registration> unloadRegistration = new AtomicReference<>();
    private final AtomicReference<GuardPanel> panel = new AtomicReference<>();

    public BurpLifecycle(MontoyaApi api) {
        this.api = Objects.requireNonNull(api);
        controller = new GuardController(new MontoyaProjectAccess(api));
        handler = new ProxyGuardHandler(controller);
    }

    public void initialize() {
        if (!initialized.compareAndSet(false, true)) throw new IllegalStateException("ALREADY_INITIALIZED");
        if (closed.get()) throw new IllegalStateException("SHUTDOWN");
        try {
            api.extension().setName("Cairn Proxy Guard (independent)");
            install(unloadRegistration, api.extension().registerUnloadingHandler(this::close));
            onEdt(() -> {
                if (closed.get()) return;
                GuardPanel created = new GuardPanel(controller);
                panel.set(created);
                if (closed.get()) { stopPanel(); return; }
                install(tabRegistration, api.userInterface().registerSuiteTab("Cairn Guard", created));
                if (closed.get()) stopPanel();
            });
            if (!closed.get()) install(httpRegistration, api.http().registerHttpHandler(handler));
        } catch (RuntimeException | LinkageError e) {
            close();
            // Native/project/config exceptions can contain uncontrolled data. Do not log/chain them.
            throw new IllegalStateException("CAIRN_GUARD_INITIALIZATION_FAILED");
        }
    }

    private void install(AtomicReference<Registration> target, Registration registration) {
        Objects.requireNonNull(registration);
        target.set(registration);
        // Handles unloading during a native registration call, including synchronous reentrancy.
        if (closed.get()) deregister(target);
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        try { handler.close(); }
        finally {
            deregister(httpRegistration);
            try {
                onEdt(() -> {
                    try { stopPanel(); }
                    finally { deregister(tabRegistration); }
                });
            } finally { deregister(unloadRegistration); }
        }
        // Outstanding true native permits intentionally remain outstanding. No timeout or unload
        // can prove target completion. Late callbacks to the handler can still close them.
    }

    private void stopPanel() {
        GuardPanel old = panel.getAndSet(null);
        if (old != null) old.close(); // Always on EDT; stops its Swing refresh timer/export worker.
    }
    private static void deregister(AtomicReference<Registration> reference) {
        Registration registration = reference.getAndSet(null);
        if (registration != null) {
            try { registration.deregister(); }
            catch (RuntimeException | LinkageError ignored) { /* Best effort, categorical only; controller is closed. */ }
        }
    }

    private static void onEdt(Runnable action) {
        if (SwingUtilities.isEventDispatchThread()) { action.run(); return; }
        FutureTask<Void> task = new FutureTask<>(action, null);
        SwingUtilities.invokeLater(task);
        boolean interrupted = false;
        try {
            while (true) {
                try { task.get(); return; }
                catch (InterruptedException e) { interrupted = true; }
                catch (ExecutionException e) { throw new IllegalStateException("UI_LIFECYCLE_FAILED"); }
            }
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }
}
