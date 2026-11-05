package dev.cairnguard.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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
}
