package dev.cairnguard.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.project.Project;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Fake project-scoped native storage only, not a user's Burp project or filesystem persistence. */
class MontoyaProjectAccessTest {
    private final MontoyaApi api = mock(MontoyaApi.class);
    private final Persistence persistence = mock(Persistence.class);
    private final PersistedObject data = mock(PersistedObject.class);
    private final Project project = mock(Project.class);
    private final AtomicReference<String> id = new AtomicReference<>("fixture-project");
    private final MontoyaProjectAccess access;
    MontoyaProjectAccessTest() {
        when(api.project()).thenReturn(project); when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(data);
        when(project.id()).thenAnswer(i -> id.get()); when(project.name()).thenReturn("Synthetic project");
        access = new MontoyaProjectAccess(api);
    }
    @Test void usesActualProjectIdNameAndOnlyProjectLocalExtensionDataString() {
        assertEquals("fixture-project", access.current().id()); assertEquals("Synthetic project", access.current().name());
        when(data.getString(MontoyaProjectAccess.KEY_PREFIX + "fixture-project")).thenReturn("{\"fixture\":true}");
        assertEquals("{\"fixture\":true}", access.load()); access.save("{\"changed\":true}");
        verify(data).setString(MontoyaProjectAccess.KEY_PREFIX + "fixture-project", "{\"changed\":true}");
        verify(persistence, never()).preferences();
        assertTrue(mockingDetails(data).getInvocations().stream().allMatch(i -> STRING_METHODS.contains(i.getMethod().getName())));
        assertTrue(mockingDetails(api).getInvocations().stream().allMatch(i -> i.getMethod().getName().equals("project") || i.getMethod().getName().equals("persistence")));
    }
    private static final java.util.Set<String> STRING_METHODS = java.util.Set.of("getString", "setString");
    @Test void freshProjectIdentityIsNeverACachedOrGlobalConfigKey() {
        access.load(); id.set("another-project"); access.load();
        verify(data).getString(MontoyaProjectAccess.KEY_PREFIX + "fixture-project");
        verify(data).getString(MontoyaProjectAccess.KEY_PREFIX + "another-project");
    }
    @ParameterizedTest @NullAndEmptySource @ValueSource(strings = {" ", "with space", "<html>", "line\nbreak", "secret@name", "a/b"})
    void malformedNativeIdentityFailsWithoutEchoingIt(String value) {
        id.set(value);
        IllegalStateException error = assertThrows(IllegalStateException.class, access::current);
        assertEquals("PROJECT_STORAGE_UNAVAILABLE", error.getMessage()); assertNull(error.getCause()); verifyNoInteractions(data);
    }
    @Test void oversizedNativeIdentityOrNameIsRejected() {
        id.set("x".repeat(513)); assertThrows(IllegalStateException.class, access::current);
        id.set("fixture-project"); when(project.name()).thenReturn("x".repeat(513)); assertThrows(IllegalStateException.class, access::current);
    }
    @Test void policyLengthIsBoundedOnReadAndBeforeWrite() {
        String huge = "x".repeat(MontoyaProjectAccess.MAX_CONFIG_CHARS + 1);
        when(data.getString(anyString())).thenReturn(huge);
        assertThrows(IllegalStateException.class, access::load); assertThrows(IllegalStateException.class, () -> access.save(huge));
        assertThrows(IllegalStateException.class, () -> access.save(null)); verify(data, never()).setString(anyString(), anyString());
    }
    @Test void nativeProjectAndStorageExceptionsNeverEscapeWithRawContentOrCauses() {
        when(project.name()).thenThrow(new IllegalStateException("SYNTHETIC-NAME-SECRET"));
        assertSafeError(access::current);
        doReturn("Synthetic project").when(project).name();
        when(data.getString(anyString())).thenThrow(new IllegalStateException("SYNTHETIC-STORAGE-SECRET"));
        assertSafeError(access::load);
        doThrow(new IllegalStateException("SYNTHETIC-WRITE-SECRET")).when(data).setString(anyString(), anyString());
        assertSafeError(() -> access.save("{}"));
    }
    private static void assertSafeError(org.junit.jupiter.api.function.Executable action) {
        IllegalStateException error = assertThrows(IllegalStateException.class, action);
        assertEquals("PROJECT_STORAGE_UNAVAILABLE", error.getMessage()); assertNull(error.getCause());
    }
    @Test void projectSwitchDuringDataLookupRejectsBeforeWrite() {
        when(persistence.extensionData()).thenAnswer(i -> { id.set("changed-project"); return data; });
        assertThrows(IllegalStateException.class, () -> access.save("{}")); verifyNoInteractions(data);
    }
    @Test void projectSwitchDuringReadFailsClosed() {
        when(data.getString(anyString())).thenAnswer(i -> { id.set("changed-project"); return "{}"; });
        assertThrows(IllegalStateException.class, access::load);
    }
    @Test void projectSwitchDuringWriteIsDetectedAndKeyRemainsOldProjectNamespaced() {
        doAnswer(i -> { id.set("changed-project"); return null; }).when(data).setString(anyString(), anyString());
        assertThrows(IllegalStateException.class, () -> access.save("{}"));
        verify(data).setString(MontoyaProjectAccess.KEY_PREFIX + "fixture-project", "{}");
        verify(data, never()).setString(MontoyaProjectAccess.KEY_PREFIX + "changed-project", "{}");
    }
}
