package dev.cairnguard.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

/** Synthetic local filesystem only; no Burp/native or network calls. */
class GuardPanelExportTest {
    @TempDir Path directory;

    @Test void newTargetPublishesExactUtf8OwnerOnlyAndRemovesTemporaryFile() throws Exception {
        Path target = directory.resolve("evidence.json");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        assertFalse(choice.existing());
        String text = "{\"label\":\"가려진 증거 [REDACTED]\"}\n";
        GuardPanel.writeAtomic(choice, text);
        assertEquals(text, Files.readString(target));
        assertOwnerOnly(target);
        assertEquals(List.of(target), children());
    }

    @Test void confirmedExistingFileIsAtomicallyReplacedNotWrittenThroughHardLinks() throws Exception {
        Path target = directory.resolve("evidence.har");
        Path other = directory.resolve("other-link");
        Files.writeString(target, "old");
        Files.createLink(other, target);
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        assertTrue(choice.existing());
        GuardPanel.writeAtomic(choice, "redacted replacement");
        assertEquals("redacted replacement", Files.readString(target));
        assertEquals("old", Files.readString(other));
        assertOwnerOnly(target);
        assertEquals(2, children().size());
    }

    @Test void fileAppearingAfterNewTargetChoiceCannotBeSilentlyOverwritten() throws Exception {
        Path target = directory.resolve("race.json");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Files.writeString(target, "unconfirmed file");
        assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, "replacement"));
        assertEquals("unconfirmed file", Files.readString(target));
        assertEquals(List.of(target), children());
    }

    @Test void changedConfirmedFileRequiresNewConsentAndLeavesNoTemp() throws Exception {
        Path target = directory.resolve("changed.json");
        Files.writeString(target, "confirmed contents");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Files.writeString(target, "longer unconfirmed contents");
        assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, "replacement"));
        assertEquals("longer unconfirmed contents", Files.readString(target));
        assertEquals(List.of(target), children());
    }

    @Test void symlinkSwappedAfterOverwriteConsentNeverTouchesDestination() throws Exception {
        Path target = directory.resolve("swapped.json");
        Path protectedFile = directory.resolve("protected");
        Files.writeString(target, "confirmed");
        Files.writeString(protectedFile, "protected contents");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Files.delete(target);
        Files.createSymbolicLink(target, protectedFile);
        assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, "replacement"));
        assertTrue(Files.isSymbolicLink(target));
        assertEquals("protected contents", Files.readString(protectedFile));
        assertEquals(2, children().size());
    }

    @Test void danglingSymlinkAndDirectoriesAndMissingParentsAreRejected() throws Exception {
        Path dangling = directory.resolve("dangling");
        Files.createSymbolicLink(dangling, directory.resolve("absent"));
        assertThrows(IOException.class, () -> GuardPanel.inspectTarget(dangling));
        assertThrows(IOException.class, () -> GuardPanel.inspectTarget(directory));
        assertThrows(IOException.class, () -> GuardPanel.inspectTarget(directory.resolve("absent-parent/file.json")));
        assertFalse(Files.exists(dangling));
        assertTrue(Files.exists(dangling, LinkOption.NOFOLLOW_LINKS));
    }

    @Test void replacedConfirmedFileWithSameLengthCannotReuseOldConsent() throws Exception {
        Path target = directory.resolve("identity.json");
        Files.writeString(target, "original");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Path replacement = directory.resolve("new-file");
        Files.writeString(replacement, "different");
        Files.move(replacement, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, "export"));
        assertEquals("different", Files.readString(target));
        assertEquals(List.of(target), children());
    }

    @Test void interruptedWriteDoesNotPublishOrLeaveTemporaryReservation() throws Exception {
        Path target = directory.resolve("interrupted.json");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Thread.currentThread().interrupt();
        try { assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, "redacted")); }
        finally { Thread.interrupted(); }
        assertFalse(Files.exists(target));
        assertTrue(children().isEmpty());
    }

    @Test void selectedParentMayBeAnExplicitHumanSymlinkButTargetIsNeverDereferenced() throws Exception {
        Path realDirectory = Files.createDirectory(directory.resolve("real"));
        Path linkDirectory = directory.resolve("chosen-directory-link");
        Files.createSymbolicLink(linkDirectory, realDirectory);
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(linkDirectory.resolve("chosen.json"));
        assertEquals(realDirectory.resolve("chosen.json"), choice.path());
        GuardPanel.writeAtomic(choice, "redacted");
        assertEquals("redacted", Files.readString(realDirectory.resolve("chosen.json")));
    }

    private List<Path> children() throws IOException {
        try (var files = Files.list(directory)) { return files.sorted().toList(); }
    }

    private static void assertOwnerOnly(Path target) throws IOException {
        if (Files.getFileStore(target).supportsFileAttributeView("posix"))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target));
    }

    @Test void finalCheckpointRefusalPublishesNothingAndRemovesOnlyTheTaskTempAndReservation() throws Exception {
        Path target = directory.resolve("checkpoint.json");
        GuardPanel.ExportTarget fresh = GuardPanel.inspectTarget(target);
        IOException refused = assertThrows(IOException.class, () -> GuardPanel.writeAtomic(fresh, "plaintext".getBytes(java.nio.charset.StandardCharsets.UTF_8), () -> false));
        assertEquals("STALE_EXPORT", refused.getMessage());
        assertFalse(Files.exists(target));
        assertEquals(List.of(), children());
        Files.writeString(target, "keep");
        GuardPanel.ExportTarget existing = GuardPanel.inspectTarget(target);
        assertThrows(IOException.class, () -> GuardPanel.writeAtomic(existing, "new".getBytes(java.nio.charset.StandardCharsets.UTF_8), () -> false));
        assertEquals("keep", Files.readString(target));
        assertEquals(List.of(target), children());
        // accepted checkpoint publishes the exact bytes, owner-only
        byte[] binary = {0, 1, (byte) 0xff, 'x'};
        GuardPanel.writeAtomic(existing, binary, () -> true);
        assertArrayEquals(binary, Files.readAllBytes(target));
        assertOwnerOnly(target);
    }

    @Test void relevantRawSourceClearThroughTheRealControllerPredicateAbortsPublicationLeavesNothingAndKeepsUnrelatedTargets() throws Exception {
        dev.cairnguard.model.GuardConfig config = new dev.cairnguard.model.GuardConfig(2,
                List.of(new dev.cairnguard.model.GuardConfig.ScopeEntry(true, "owned.test", "https", 443, "")), List.of(), List.of(),
                dev.cairnguard.model.GuardConfig.Mode.ALLOW, dev.cairnguard.model.GuardConfig.defaults().limits());
        String[] stored = {dev.cairnguard.model.PolicyCodec.encode(config)};
        dev.cairnguard.runtime.GuardController controller = new dev.cairnguard.runtime.GuardController(new dev.cairnguard.runtime.ProjectAccess() {
            @Override public Ref current() { return new Ref("p", "Synthetic"); }
            @Override public String load() { return stored[0]; }
            @Override public void save(String value) { stored[0] = value; }
        });
        try {
            var prepared = controller.prepare(new dev.cairnguard.model.RequestData("GET", "https://owned.test/original", "owned.test", 443, true, List.of(), new byte[0]));
            var admission = controller.authorize(prepared);
            assertTrue(admission.allowed(), admission.reason());
            assertTrue(controller.commitDetailed(prepared).allowed());
            controller.response(prepared.evidenceId(), 200, List.of(), "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8), 2);
            var export = controller.humanExport(List.of(prepared.evidenceId()), false);
            byte[] bytes = export.serialize();
            Path target = directory.resolve("evicted.json");
            Path unrelated = directory.resolve("unrelated.json"); Files.writeString(unrelated, "keep");
            GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
            for (int i = 0; i < 2000; i++) controller.prepareRejected("CAPTURE_FAILED"); // ordinary traffic evicts nothing (no quota)
            assertEquals(Boolean.TRUE, controller.rawCaptureInfo(prepared.evidenceId()).get("available"));
            assertTrue(controller.humanExportCurrent(export));
            controller.clearEvidence(); // an explicit clear releases the original
            assertEquals(Boolean.FALSE, controller.rawCaptureInfo(prepared.evidenceId()).get("available"));
            IOException refused = assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice, bytes, () -> controller.humanExportCurrent(export)));
            assertEquals("STALE_EXPORT", refused.getMessage());
            assertFalse(Files.exists(target));
            assertEquals(List.of(unrelated), children(), "no publication, no leftover task-owned temp, unrelated target untouched");
            assertEquals("keep", Files.readString(unrelated));
        } finally { controller.close(); }
    }

    @ParameterizedTest(name = "{0}, existing={1}")
    @MethodSource("temporaryIdentityCases")
    void simulatedTemporaryIdentityPublishesOnlyAcceptedKeyAndTimePairs(TemporaryIdentityCase identity, boolean existing) throws Exception {
        Path target = directory.resolve("identity-matrix.json");
        Path unrelated = directory.resolve("unrelated");
        Files.writeString(unrelated, "keep unrelated");
        if (existing) Files.writeString(target, "keep existing");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        byte[] payload = "{\"original\":\"한글 [REDACTED]\"}\n".getBytes(StandardCharsets.UTF_8);
        AtomicInteger observations = new AtomicInteger();
        AtomicInteger checkpoints = new AtomicInteger();
        MockedStatic<Files> files = mockStatic(Files.class, invocation -> {
            Object actual = invocation.callRealMethod();
            if (invocation.getMethod().getName().equals("readAttributes")
                    && invocation.getArgument(1) == BasicFileAttributes.class
                    && isTaskTemporary(invocation.getArgument(0))) {
                int observation = observations.getAndIncrement();
                assertTrue(observation < 2, "Only the two temporary attribute observations may be substituted");
                return new TemporaryAttributes((BasicFileAttributes) actual,
                        observation == 0 ? identity.initialKey() : identity.writtenKey(),
                        observation == 0 ? identity.initialTime() : identity.writtenTime());
            }
            return actual;
        });
        try {
            if (identity.publishes()) {
                GuardPanel.writeAtomic(choice, payload, () -> { checkpoints.incrementAndGet(); return true; });
            } else {
                IOException refused = assertThrows(IOException.class,
                        () -> GuardPanel.writeAtomic(choice, payload, () -> { checkpoints.incrementAndGet(); return true; }));
                assertEquals("TEMP_CHANGED", refused.getMessage());
            }
        } finally { files.close(); }
        assertEquals(2, observations.get());
        assertEquals(identity.publishes() ? 1 : 0, checkpoints.get());
        if (identity.publishes()) {
            assertArrayEquals(payload, Files.readAllBytes(target));
            assertOwnerOnly(target);
        } else if (existing) {
            assertEquals("keep existing", Files.readString(target));
            assertEquals(choice.original().fileKey(), Files.readAttributes(target, BasicFileAttributes.class).fileKey());
        } else {
            assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS));
        }
        assertEquals("keep unrelated", Files.readString(unrelated));
        assertEquals(identity.publishes() || existing ? List.of(target, unrelated) : List.of(unrelated), children());
    }

    private static Stream<Arguments> temporaryIdentityCases() {
        FileTime ordinary = FileTime.fromMillis(1_600_000_000_000L);
        FileTime drifted = FileTime.fromMillis(1_600_000_001_234L);
        FileTime epoch = FileTime.fromMillis(0);
        return Stream.of(
                new TemporaryIdentityCase("known-equal-time-equal", "known-key", new String("known-key"), ordinary, ordinary, true),
                new TemporaryIdentityCase("known-equal-time-drift", "known-key", new String("known-key"), ordinary, drifted, true),
                new TemporaryIdentityCase("known-different-time-equal", "initial-key", "written-key", ordinary, ordinary, false),
                new TemporaryIdentityCase("null-to-known-time-equal", null, "written-key", ordinary, ordinary, false),
                new TemporaryIdentityCase("known-to-null-time-equal", "initial-key", null, ordinary, ordinary, false),
                new TemporaryIdentityCase("null-null-time-equal", null, null, ordinary, ordinary, true),
                new TemporaryIdentityCase("null-null-time-drift", null, null, ordinary, drifted, false),
                new TemporaryIdentityCase("null-null-epoch-equal", null, null, epoch, epoch, true),
                new TemporaryIdentityCase("null-null-epoch-to-ordinary", null, null, epoch, ordinary, false),
                new TemporaryIdentityCase("null-null-ordinary-to-epoch", null, null, ordinary, epoch, false)
        ).flatMap(identity -> Stream.of(Arguments.of(identity, false), Arguments.of(identity, true)));
    }

    @Test void equalByteLengthReplacementWithMatchedMtimeCannotReuseOverwriteConsent() throws Exception {
        Path target = directory.resolve("matched-mtime.json");
        Path sibling = directory.resolve("original-link");
        Path replacement = directory.resolve("replacement");
        Files.writeString(target, "original");
        Files.createLink(sibling, target);
        Files.writeString(replacement, "changed!");
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        Files.setLastModifiedTime(replacement, choice.original().lastModifiedTime());
        assertEquals(choice.original().size(), Files.size(replacement));
        assertEquals(choice.original().lastModifiedTime(), Files.getLastModifiedTime(replacement));
        assertNotNull(choice.original().fileKey());
        assertNotEquals(choice.original().fileKey(), Files.readAttributes(replacement, BasicFileAttributes.class).fileKey());
        Files.move(replacement, target, StandardCopyOption.REPLACE_EXISTING);
        AtomicInteger checkpoints = new AtomicInteger();
        IOException refused = assertThrows(IOException.class, () -> GuardPanel.writeAtomic(choice,
                "export".getBytes(StandardCharsets.UTF_8), () -> { checkpoints.incrementAndGet(); return true; }));
        assertEquals("TARGET_CHANGED", refused.getMessage());
        assertEquals(0, checkpoints.get());
        assertEquals("changed!", Files.readString(target));
        assertEquals(choice.original().size(), Files.size(target));
        assertEquals(choice.original().lastModifiedTime(), Files.getLastModifiedTime(target));
        assertEquals("original", Files.readString(sibling));
        assertEquals(List.of(target, sibling), children());
    }

    @ParameterizedTest(name = "existing={0}")
    @ValueSource(booleans = {false, true})
    void unsupportedAtomicMoveNeverFallsBackOrDestroysExistingOrUnrelatedFiles(boolean existing) throws Exception {
        Path target = directory.resolve("atomic-refusal.json");
        Path sibling = directory.resolve("original-link");
        Path unrelated = directory.resolve("unrelated");
        Files.writeString(unrelated, "keep unrelated");
        if (existing) {
            Files.writeString(target, "keep existing");
            Files.createLink(sibling, target);
        }
        GuardPanel.ExportTarget choice = GuardPanel.inspectTarget(target);
        AtomicInteger moves = new AtomicInteger();
        AtomicInteger checkpoints = new AtomicInteger();
        MockedStatic<Files> files = mockStatic(Files.class, invocation -> {
            if (invocation.getMethod().getName().equals("move")
                    && target.equals(invocation.getArgument(1)) && isTaskTemporary(invocation.getArgument(0))) {
                moves.incrementAndGet();
                assertArrayEquals(new CopyOption[]{StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING},
                        (CopyOption[]) invocation.getRawArguments()[2]);
                throw new AtomicMoveNotSupportedException(invocation.getArgument(0).toString(), target.toString(), "simulated refusal");
            }
            return invocation.callRealMethod();
        });
        try {
            assertThrows(AtomicMoveNotSupportedException.class, () -> GuardPanel.writeAtomic(choice,
                    "export".getBytes(StandardCharsets.UTF_8), () -> { checkpoints.incrementAndGet(); return true; }));
        } finally { files.close(); }
        assertEquals(1, moves.get(), "No non-atomic retry");
        assertEquals(1, checkpoints.get());
        if (existing) {
            assertEquals("keep existing", Files.readString(target));
            assertEquals("keep existing", Files.readString(sibling));
            BasicFileAttributes actual = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            assertEquals(choice.original().fileKey(), actual.fileKey());
            assertEquals(choice.original().size(), actual.size());
            assertEquals(choice.original().creationTime(), actual.creationTime());
            assertEquals(choice.original().lastModifiedTime(), actual.lastModifiedTime());
        } else {
            assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS));
        }
        assertEquals("keep unrelated", Files.readString(unrelated));
        assertEquals(existing ? List.of(target, sibling, unrelated) : List.of(unrelated), children());
    }

    private boolean isTaskTemporary(Path path) {
        String name = path.getFileName().toString();
        return directory.equals(path.getParent()) && name.startsWith(".cairn-guard-") && name.endsWith(".tmp");
    }

    private record TemporaryIdentityCase(String id, Object initialKey, Object writtenKey,
                                         FileTime initialTime, FileTime writtenTime, boolean publishes) {
        @Override public String toString() { return id; }
    }

    private record TemporaryAttributes(BasicFileAttributes actual, Object fileKey, FileTime creationTime) implements BasicFileAttributes {
        @Override public FileTime lastModifiedTime() { return actual.lastModifiedTime(); }
        @Override public FileTime lastAccessTime() { return actual.lastAccessTime(); }
        @Override public boolean isRegularFile() { return actual.isRegularFile(); }
        @Override public boolean isDirectory() { return actual.isDirectory(); }
        @Override public boolean isSymbolicLink() { return actual.isSymbolicLink(); }
        @Override public boolean isOther() { return actual.isOther(); }
        @Override public long size() { return actual.size(); }
    }
}
