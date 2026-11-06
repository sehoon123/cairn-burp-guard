package dev.cairnguard.ui;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.evidence.TrafficEntry.Message;
import dev.cairnguard.model.RequestData.Header;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Inspection-copy search and two-owner UI job scheduling; no runtime/controller access. */
final class TrafficSearch {
    private TrafficSearch() {}

    enum Location {
        ALL("전체 (All)"), METADATA("메타데이터 (Metadata)"),
        REQUEST_HEADERS("요청 헤더 (Request headers)"), REQUEST_BODY("요청 본문/HEX (Request body)"),
        RESPONSE_HEADERS("응답 헤더 (Response headers)"), RESPONSE_BODY("응답 본문/HEX (Response body)");
        private final String label;
        Location(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    enum MatchMode {
        LITERAL("Literal (기본)"), RE2("RE2");
        private final String label;
        MatchMode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    record Query(String text, Location location, MatchMode mode) {
        Query { Objects.requireNonNull(text); Objects.requireNonNull(location); Objects.requireNonNull(mode); }
    }
    record Subject(TrafficEntry entry, boolean originalAvailable, List<String> metadata) {
        Subject { metadata = List.copyOf(metadata); }
    }
    sealed interface Input permits CompiledQuery, Invalid {}
    enum Invalid implements Input { BAD_RE2, TOO_LONG, TOO_COMPLEX }

    static Input compile(Query key) {
        if (key.mode() == MatchMode.LITERAL || key.text().isEmpty()) return new CompiledQuery(key, null);
        if (key.text().length() > 4_096) return Invalid.TOO_LONG;
        try {
            Pattern pattern = Pattern.compile(key.text(), Pattern.CASE_INSENSITIVE);
            return pattern.programSize() > 4_096 ? Invalid.TOO_COMPLEX : new CompiledQuery(key, pattern);
        } catch (PatternSyntaxException | IllegalArgumentException invalid) {
            return Invalid.BAD_RE2;
        }
    }

    static final class CompiledQuery implements Input {
        private final Query key;
        private final Pattern pattern;
        private final String metadataNeedle;
        private CompiledQuery(Query key, Pattern pattern) {
            this.key = key; this.pattern = pattern;
            metadataNeedle = key.mode() == MatchMode.LITERAL ? key.text().toLowerCase(Locale.ROOT) : null;
        }
        Query key() { return key; }
        private boolean metadataSelected() { return key.location() == Location.ALL || key.location() == Location.METADATA; }
        private boolean requestSelected() { return key.location() == Location.ALL || key.location() == Location.REQUEST_HEADERS || key.location() == Location.REQUEST_BODY; }
        private boolean responseSelected() { return key.location() == Location.ALL || key.location() == Location.RESPONSE_HEADERS || key.location() == Location.RESPONSE_BODY; }
        private boolean advancedMetadata() { return metadataSelected() && key.mode() == MatchMode.RE2 && !key.text().isEmpty(); }
        private boolean metadata(Subject subject, Work work) {
            for (String field : subject.metadata()) {
                work.check();
                if (key.mode() == MatchMode.LITERAL ? field.toLowerCase(Locale.ROOT).contains(metadataNeedle) : find(new Field(field, work), work)) return true;
            }
            work.check(); return false;
        }
        private boolean find(Field field, Work work) {
            work.check();
            boolean hit = pattern == null ? literal(field, key.text(), work) : pattern.matcher(field).find();
            work.check(); return hit;
        }
    }

    static boolean contains(Message message, CompiledQuery query, BooleanSupplier cancelled) {
        return contains(message, query, new Work(cancelled));
    }
    private static boolean contains(Message message, CompiledQuery query, Work work) {
        work.check();
        if (!message.present()) return false;
        Location location = query.key().location();
        if (location == Location.ALL || location == Location.REQUEST_HEADERS || location == Location.RESPONSE_HEADERS) {
            for (Header header : message.headers()) if (query.find(new Field(header, work), work)) return true;
        }
        return (location == Location.ALL || location == Location.REQUEST_BODY || location == Location.RESPONSE_BODY)
                && !message.body().isEmpty() && (message.bodyEncoding().equals("UTF8_TEXT") || message.bodyEncoding().equals("HEX"))
                && query.find(new Field(message.body(), work), work);
    }
    static boolean literal(CharSequence text, String query, Work work) {
        work.check();
        if (query.isEmpty()) return true;
        int end = text.length() - query.length();
        for (int i = 0; i <= end; i++) {
            int j = 0;
            while (j < query.length()) {
                work.unit();
                char a = text.charAt(i + j), b = query.charAt(j);
                if (a != b && Character.toUpperCase(a) != Character.toUpperCase(b)
                        && Character.toLowerCase(Character.toUpperCase(a)) != Character.toLowerCase(Character.toUpperCase(b))) break;
                j++;
            }
            if (j == query.length()) return true;
        }
        work.check(); return false;
    }
    private static final class Field implements CharSequence {
        private final String first, second;
        private final int start, end;
        private final Work work;
        Field(String text, Work work) { first = text; second = null; start = 0; end = text.length(); this.work = work; }
        Field(Header header, Work work) {
            first = String.valueOf(header.name()); second = String.valueOf(header.value()); start = 0;
            end = Math.addExact(Math.addExact(first.length(), 2), second.length()); this.work = work;
        }
        private Field(Field source, int from, int to) {
            first = source.first; second = source.second; work = source.work;
            start = source.start + from; end = source.start + to;
        }
        @Override public int length() { return end - start; }
        @Override public char charAt(int index) {
            Objects.checkIndex(index, length()); work.unit(); int i = start + index;
            if (second == null || i < first.length()) return first.charAt(i);
            return i == first.length() ? ':' : i == first.length() + 1 ? ' ' : second.charAt(i - first.length() - 2);
        }
        @Override public CharSequence subSequence(int from, int to) {
            Objects.checkFromToIndex(from, to, length()); return new Field(this, from, to);
        }
        @Override public String toString() {
            StringBuilder text = new StringBuilder(length());
            for (int i = 0; i < length(); i++) text.append(charAt(i));
            return text.toString();
        }
    }
    static final class Work {
        private final BooleanSupplier cancelled;
        private int units;
        Work(BooleanSupplier cancelled) { this.cancelled = cancelled; }
        void unit() { if (++units == 4096) { units = 0; check(); } }
        void check() { if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new CancellationException(); }
    }

    /** One processing thread, one latest input and one coalesced EDT result; replacement follows actual exit. */
    static final class Pump implements AutoCloseable {
        interface Task { Object run(BooleanSupplier cancelled); }
        record Result(Object value, boolean failed) {}
        private record Job(long generation, Task task, Consumer<Result> accept) {}
        private record Delivery(long generation, Consumer<Result> accept, Result result) {}
        private final Thread thread;
        private long generation;
        private Job pending;
        private Delivery delivery;
        private boolean drainScheduled, closed, started;

        Pump(String name) {
            thread = new Thread(this::loop, name);
            thread.setDaemon(true);
        }
        synchronized void submit(Task task, Consumer<Result> accept) {
            if (closed) return;
            generation++; pending = new Job(generation, task, accept); delivery = null;
            if (!started) { started = true; thread.start(); }
            thread.interrupt(); notifyAll();
        }
        synchronized void cancel() {
            generation++; pending = null; delivery = null; thread.interrupt(); notifyAll();
        }
        private synchronized boolean cancelled(long id) { return closed || generation != id; }
        private void loop() {
            while (true) {
                Job job;
                synchronized (this) {
                    while (!closed && pending == null) {
                        try { wait(); } catch (InterruptedException ignored) { /* Recheck mailbox/close. */ }
                    }
                    if (closed) return;
                    job = pending; pending = null; Thread.interrupted();
                }
                Result result = null;
                long id = job.generation();
                try { result = new Result(job.task().run(() -> cancelled(id)), false); }
                catch (CancellationException ignored) { /* No publication. */ }
                catch (RuntimeException failure) { result = new Result(null, true); }
                finally {
                    // This point is reached only AFTER task processing has exited, never Future.cancel/done.
                    synchronized (this) {
                        if (result != null && !cancelled(job.generation())) {
                            delivery = new Delivery(job.generation(), job.accept(), result);
                            if (!drainScheduled) { drainScheduled = true; SwingUtilities.invokeLater(this::drain); }
                        }
                    }
                    job = null; result = null;
                }
            }
        }
        private void drain() {
            Delivery next;
            synchronized (this) { next = delivery; delivery = null; drainScheduled = false; }
            if (next != null && !cancelled(next.generation())) next.accept().accept(next.result());
        }
        @Override public synchronized void close() { if (!closed) { closed = true; cancel(); } }
        boolean awaitExit(long millis) throws InterruptedException {
            if (SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("JOIN_OFF_EDT");
            thread.join(millis); return !thread.isAlive();
        }
        synchronized boolean retainsPending() { return pending != null || delivery != null; }
    }

    /** EDT-owned identity caches for exactly one query. Results never use record equality as a key. */
    static final class Session implements AutoCloseable {
        private final Pump pump = new Pump("cairn-history-search");
        private final IdentityHashMap<Message, Boolean> cache = new IdentityHashMap<>();
        private final IdentityHashMap<Message, Boolean> retained = new IdentityHashMap<>();
        private final IdentityHashMap<Message, Boolean> scanning = new IdentityHashMap<>();
        private final IdentityHashMap<TrafficEntry, MetadataResult> metadataCache = new IdentityHashMap<>();
        private final IdentityHashMap<TrafficEntry, Subject> metadataRetained = new IdentityHashMap<>();
        private final IdentityHashMap<TrafficEntry, Subject> metadataScanning = new IdentityHashMap<>();
        private record MetadataResult(Subject subject, boolean hit) {}
        private record Matches(IdentityHashMap<Message, Boolean> content, IdentityHashMap<TrafficEntry, MetadataResult> metadata) {}
        private CompiledQuery query;
        private long generation;
        private boolean failed, closed;
        boolean hit(Subject subject) {
            if (query == null) return false;
            if (query.key().text().isEmpty()) return true;
            MetadataResult metadata = metadataCache.get(subject.entry());
            return query.metadataSelected() && (query.advancedMetadata()
                    ? metadata != null && sameSnapshot(metadata.subject(), subject) && metadata.hit()
                    : query.metadata(subject, new Work(() -> false)))
                    || subject.originalAvailable() && (query.requestSelected() && Boolean.TRUE.equals(cache.get(subject.entry().requestCapture()))
                    || query.responseSelected() && Boolean.TRUE.equals(cache.get(subject.entry().responseCapture())));
        }
        boolean failed() { return failed; }
        boolean pending(Subject subject) {
            if (query == null || query.key().text().isEmpty() || failed) return false;
            return query.advancedMetadata() && sameSnapshot(subject, metadataRetained.get(subject.entry()))
                    && !metadataCache.containsKey(subject.entry())
                    || subject.originalAvailable() && (query.requestSelected()
                    && retained.containsKey(subject.entry().requestCapture()) && !cache.containsKey(subject.entry().requestCapture())
                    || query.responseSelected() && retained.containsKey(subject.entry().responseCapture()) && !cache.containsKey(subject.entry().responseCapture()));
        }
        boolean pending() {
            return query != null && !query.key().text().isEmpty() && !failed
                    && (cache.size() < retained.size() || metadataCache.size() < metadataRetained.size());
        }
        void update(CompiledQuery next, List<Subject> subjects, Runnable complete) {
            if (closed) return;
            if (query == null || !query.key().equals(next.key())) { clear(); query = next; }
            retained.clear(); metadataRetained.clear();
            for (Subject subject : subjects) {
                if (subject.originalAvailable()) {
                    if (query.requestSelected()) retained.put(subject.entry().requestCapture(), true);
                    if (query.responseSelected()) retained.put(subject.entry().responseCapture(), true);
                }
                if (query.advancedMetadata()) metadataRetained.put(subject.entry(), subject);
            }
            cache.keySet().removeIf(m -> !retained.containsKey(m));
            metadataCache.entrySet().removeIf(e -> !sameSnapshot(e.getValue().subject(), metadataRetained.get(e.getKey())));
            if (scanning.keySet().stream().anyMatch(m -> !retained.containsKey(m))
                    || metadataScanning.entrySet().stream().anyMatch(e -> !sameSnapshot(e.getValue(), metadataRetained.get(e.getKey())))) {
                generation++; pump.cancel(); scanning.clear(); metadataScanning.clear();
            }
            if (query.key().text().isEmpty() || failed || !scanning.isEmpty() || !metadataScanning.isEmpty()) return;
            List<Message> missing = new ArrayList<>();
            for (Message m : retained.keySet()) if (!cache.containsKey(m)) { missing.add(m); scanning.put(m, true); }
            List<Subject> missingMetadata = new ArrayList<>();
            for (Subject subject : metadataRetained.values()) if (!metadataCache.containsKey(subject.entry())) {
                missingMetadata.add(subject); metadataScanning.put(subject.entry(), subject);
            }
            if (missing.isEmpty() && missingMetadata.isEmpty()) return;
            long version = generation; CompiledQuery needle = query;
            pump.submit(cancelled -> {
                Work work = new Work(cancelled);
                IdentityHashMap<Message, Boolean> matches = new IdentityHashMap<>();
                for (Message m : missing) { work.check(); matches.put(m, contains(m, needle, work)); }
                IdentityHashMap<TrafficEntry, MetadataResult> metadata = new IdentityHashMap<>();
                for (Subject subject : missingMetadata) {
                    work.check(); metadata.put(subject.entry(), new MetadataResult(subject, needle.metadata(subject, work)));
                }
                work.check(); return new Matches(matches, metadata);
            }, result -> {
                if (closed || generation != version) return;
                scanning.clear(); metadataScanning.clear();
                if (result.failed()) failed = true;
                else {
                    Matches matches = (Matches) result.value();
                    for (var e : matches.content().entrySet()) if (retained.containsKey(e.getKey())) cache.put(e.getKey(), e.getValue());
                    for (var e : matches.metadata().entrySet()) if (sameSnapshot(e.getValue().subject(), metadataRetained.get(e.getKey()))) metadataCache.put(e.getKey(), e.getValue());
                }
                complete.run();
            });
        }
        private static boolean sameSnapshot(Subject a, Subject b) {
            return b != null && a.entry() == b.entry() && a.originalAvailable() == b.originalAvailable() && a.metadata().equals(b.metadata());
        }
        void clear() {
            generation++; pump.cancel(); query = null; cache.clear(); retained.clear(); scanning.clear();
            metadataCache.clear(); metadataRetained.clear(); metadataScanning.clear(); failed = false;
        }
        @Override public void close() { if (!closed) { clear(); closed = true; pump.close(); } }
        boolean awaitExit(long millis) throws InterruptedException { return pump.awaitExit(millis); }
    }
}
