package dev.cairnguard.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.project.Project;
import burp.api.montoya.ui.UserInterface;
import dev.cairnguard.GuardExtension;
import dev.cairnguard.ui.GuardPanel;
import dev.cairnguard.ui.GuardUiAccess;
import java.lang.reflect.Field;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Montoya mocks and actual headless Swing only. NOT real Burp initialization/unload or licensing. */
class BurpLifecycleTest {
    private static final class Fixture {
        final MontoyaApi api = mock(MontoyaApi.class);
        final Extension extension = mock(Extension.class);
        final Http http = mock(Http.class);
        final UserInterface ui = mock(UserInterface.class);
        final Persistence persistence = mock(Persistence.class);
        final Project project = mock(Project.class);
        final PersistedObject data = mock(PersistedObject.class);
        final Registration httpRegistration = mock(Registration.class);
        final Registration tabRegistration = mock(Registration.class);
        final Registration unloadRegistration = mock(Registration.class);
        final AtomicReference<ExtensionUnloadingHandler> unload = new AtomicReference<>();
        final AtomicReference<GuardPanel> panel = new AtomicReference<>();
        final AtomicReference<HttpHandler> handler = new AtomicReference<>();
        Fixture() {
            when(api.extension()).thenReturn(extension); when(api.http()).thenReturn(http); when(api.userInterface()).thenReturn(ui);
            when(api.project()).thenReturn(project); when(api.persistence()).thenReturn(persistence); when(persistence.extensionData()).thenReturn(data);
            when(project.id()).thenReturn("fixture-project"); when(project.name()).thenReturn("Synthetic project");
            when(extension.registerUnloadingHandler(any())).thenAnswer(i -> { unload.set(i.getArgument(0)); return unloadRegistration; });
            when(http.registerHttpHandler(any())).thenAnswer(i -> { handler.set(i.getArgument(0)); return httpRegistration; });
            when(ui.registerSuiteTab(anyString(), any())).thenAnswer(i -> {
                assertTrue(SwingUtilities.isEventDispatchThread()); panel.set(i.getArgument(1)); assertTrue(panel.get() instanceof GuardPanel); return tabRegistration;
            });
        }
        GuardUiAccess access() throws Exception {
            Field f = GuardPanel.class.getDeclaredField("access"); f.setAccessible(true); return (GuardUiAccess) f.get(panel.get());
        }
        boolean timerRunning() throws Exception {
            AtomicReference<Boolean> result = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                try { Field f = GuardPanel.class.getDeclaredField("timer"); f.setAccessible(true); result.set(((Timer) f.get(panel.get())).isRunning()); }
                catch (ReflectiveOperationException e) { throw new AssertionError(e); }
            });
            return result.get();
        }
        void verifyReleased() throws Exception {
            verify(httpRegistration).deregister(); verify(tabRegistration).deregister(); verify(unloadRegistration).deregister();
            assertFalse(timerRunning()); assertEquals(true, access().status().get("closed"));
        }
    }
    @Test void realEntryPointRegistersOnlyHttpHandlerAndHumanGuardPanelOnEdt() throws Exception {
        Fixture f = new Fixture(); GuardExtension extension = new GuardExtension();
        assertInstanceOf(BurpExtension.class, extension);
        try {
            extension.initialize(f.api); assertInstanceOf(ProxyGuardHandler.class, f.handler.get()); assertTrue(f.timerRunning());
            verify(f.extension).setName("Cairn Proxy Guard (independent)"); verify(f.ui).registerSuiteTab(eq("Cairn Guard"), same(f.panel.get()));
            assertTrue(mockingDetails(f.http).getInvocations().stream().allMatch(i -> i.getMethod().getName().equals("registerHttpHandler")));
            assertTrue(mockingDetails(f.api).getInvocations().stream().allMatch(i -> Set.of("extension", "http", "userInterface", "project", "persistence").contains(i.getMethod().getName())));
            verify(f.persistence, never()).preferences(); verify(f.data, never()).setString(anyString(), anyString());
        } finally { extension.close(); }
        f.verifyReleased(); extension.close(); f.unload.get().extensionUnloaded(); f.verifyReleased();
    }
    @Test void nativeUnloadingHandlerStopsControllerAndTimerAndDeregisters() throws Exception {
        Fixture f = new Fixture(); GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        f.unload.get().extensionUnloaded(); f.verifyReleased(); extension.close(); f.verifyReleased();
    }
    @Test void entryPointAlsoInitializesAndUnloadsOnEdtWithoutDeadlock() throws Exception {
        Fixture f = new Fixture(); GuardExtension extension = new GuardExtension();
        SwingUtilities.invokeAndWait(() -> { extension.initialize(f.api); f.unload.get().extensionUnloaded(); });
        f.verifyReleased(); extension.close();
    }
    @Test void failedSuiteTabRegistrationRollsBackPanelControllerAndUnloadingRegistration() throws Exception {
        Fixture f = new Fixture();
        doAnswer(i -> {
            f.panel.set(i.getArgument(1)); throw new IllegalStateException("SYNTHETIC-UI-SECRET");
        }).when(f.ui).registerSuiteTab(anyString(), any());
        GuardExtension extension = new GuardExtension();
        IllegalStateException error = assertThrows(IllegalStateException.class, () -> extension.initialize(f.api));
        assertEquals("CAIRN_GUARD_INITIALIZATION_FAILED", error.getMessage()); assertNull(error.getCause());
        assertFalse(f.timerRunning()); assertEquals(true, f.access().status().get("closed"));
        verify(f.unloadRegistration).deregister(); verifyNoInteractions(f.http); extension.close();
    }
    @Test void failedHttpRegistrationRollsBackAllExistingResources() throws Exception {
        Fixture f = new Fixture(); when(f.http.registerHttpHandler(any())).thenThrow(new IllegalStateException("SYNTHETIC-HTTP-SECRET"));
        GuardExtension extension = new GuardExtension();
        IllegalStateException error = assertThrows(IllegalStateException.class, () -> extension.initialize(f.api));
        assertEquals("CAIRN_GUARD_INITIALIZATION_FAILED", error.getMessage()); assertNull(error.getCause());
        verify(f.tabRegistration).deregister(); verify(f.unloadRegistration).deregister(); assertFalse(f.timerRunning());
        assertEquals(true, f.access().status().get("closed")); extension.close();
    }
    @Test void unloadReentrantDuringSuiteTabRegistrationCannotLeaveLateRegistrationOrTimer() throws Exception {
        Fixture f = new Fixture();
        doAnswer(i -> {
            f.panel.set(i.getArgument(1)); f.unload.get().extensionUnloaded(); return f.tabRegistration;
        }).when(f.ui).registerSuiteTab(anyString(), any());
        GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        verify(f.tabRegistration).deregister(); verify(f.unloadRegistration).deregister(); verifyNoInteractions(f.http);
        assertFalse(f.timerRunning()); assertEquals(true, f.access().status().get("closed")); extension.close();
    }
    @Test void unloadDuringNativeHttpRegistrationDeregistersLateReturnedHandle() throws Exception {
        Fixture f = new Fixture();
        when(f.http.registerHttpHandler(any())).thenAnswer(i -> { f.handler.set(i.getArgument(0)); f.unload.get().extensionUnloaded(); return f.httpRegistration; });
        GuardExtension extension = new GuardExtension(); extension.initialize(f.api); f.verifyReleased(); extension.close();
    }
    @Test void unloadDuringUnloadingHandlerRegistrationNeverCreatesATabOrHandler() {
        Fixture f = new Fixture();
        when(f.extension.registerUnloadingHandler(any())).thenAnswer(i -> { ExtensionUnloadingHandler unloading = i.getArgument(0); unloading.extensionUnloaded(); return f.unloadRegistration; });
        GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        verify(f.unloadRegistration).deregister(); verifyNoInteractions(f.ui, f.http); extension.close();
    }
    @Test void deregistrationErrorsDoNotPreventControllerAndPanelShutdown() throws Exception {
        Fixture f = new Fixture(); GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        doThrow(new IllegalStateException("SYNTHETIC-SECRET")).when(f.httpRegistration).deregister();
        doThrow(new IllegalStateException("SYNTHETIC-SECRET")).when(f.tabRegistration).deregister();
        doThrow(new IllegalStateException("SYNTHETIC-SECRET")).when(f.unloadRegistration).deregister();
        assertDoesNotThrow(extension::close); f.verifyReleased();
    }
    @Test void interruptedUnloadStillSynchronouslyStopsSwingTimerAndPreservesInterrupt() throws Exception {
        Fixture f = new Fixture(); GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        try {
            Thread.currentThread().interrupt(); extension.close(); assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
        f.verifyReleased();
    }
    @Test void closeBeforeInitializeAndDoubleInitializeCannotCreateExtraRegistrations() throws Exception {
        Fixture f = new Fixture(); GuardExtension closed = new GuardExtension(); closed.close();
        assertThrows(IllegalStateException.class, () -> closed.initialize(f.api)); verifyNoInteractions(f.api);
        GuardExtension extension = new GuardExtension(); extension.initialize(f.api);
        assertThrows(IllegalStateException.class, () -> extension.initialize(f.api));
        verify(f.http).registerHttpHandler(any()); verify(f.ui).registerSuiteTab(anyString(), any()); extension.close(); f.verifyReleased();
    }
    @Test void repeatedInitializeUnloadLeavesNoOwnedWatcherOrLiveRefreshTimer() throws Exception {
        Fixture first = new Fixture(); // Load Mockito before measuring lifecycle-owned thread creation.
        Set<Long> before = Thread.getAllStackTraces().keySet().stream().map(Thread::threadId).collect(Collectors.toSet());
        for (int i = 0; i < 5; i++) {
            Fixture f = i == 0 ? first : new Fixture(); GuardExtension extension = new GuardExtension();
            extension.initialize(f.api); f.unload.get().extensionUnloaded(); f.verifyReleased(); extension.close();
        }
        Set<String> unexpected = Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive)
                .filter(t -> !before.contains(t.threadId())).map(Thread::getName)
                .filter(name -> !name.startsWith("AWT-") && !name.equals("TimerQueue") && !name.equals("Java2D Disposer"))
                .collect(Collectors.toSet());
        assertEquals(Set.of(), unexpected, "Lifecycle must not create watcher/executor threads");
    }
}
