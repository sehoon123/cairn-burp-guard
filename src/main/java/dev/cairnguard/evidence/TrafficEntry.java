package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.RequestData.Header;

import java.util.List;
import java.util.Objects;

/** An immutable, redacted observation, not a wire transcript or proof of delivery. */
public record TrafficEntry(String id, String projectId, String projectName, String timestamp,
                           String method, String url, String mode, String disposition, String reason,
                           Integer statusCode, List<Decision.RuleHit> hits, long revision,
                           boolean bookmarked, Message requestCapture, Message responseCapture,
                           boolean truncated, String provenanceSeal,
                           String intentId, String runId, String outcome, String guardState,
                           String overlayId, long responseBytes, List<String> inspectionWarnings) {
    public TrafficEntry {
        Objects.requireNonNull(id);
        Objects.requireNonNull(projectId);
        Objects.requireNonNull(projectName);
        Objects.requireNonNull(timestamp);
        Objects.requireNonNull(method);
        Objects.requireNonNull(url);
        Objects.requireNonNull(mode);
        Objects.requireNonNull(disposition);
        Objects.requireNonNull(reason);
        hits = List.copyOf(hits);
        Objects.requireNonNull(requestCapture);
        Objects.requireNonNull(responseCapture);
        Objects.requireNonNull(provenanceSeal);
        Objects.requireNonNull(intentId);
        Objects.requireNonNull(runId);
        Objects.requireNonNull(outcome);
        Objects.requireNonNull(guardState);
        Objects.requireNonNull(overlayId);
        inspectionWarnings = List.copyOf(inspectionWarnings);
    }

    /** Original constructor retained for integrations and fixtures; only EvidenceStore can seal it. */
    public TrafficEntry(String id, String projectId, String projectName, String timestamp,
                        String method, String url, String mode, String disposition, String reason,
                        Integer statusCode, List<Decision.RuleHit> hits, long revision,
                        boolean bookmarked, Message requestCapture, Message responseCapture,
                        boolean truncated, String provenanceSeal) {
        this(id, projectId, projectName, timestamp, method, url, mode, disposition, reason, statusCode,
                hits, revision, bookmarked, requestCapture, responseCapture, truncated, provenanceSeal,
                "-", "-", "FORWARDED".equals(disposition) ? "forwarded" : "BLOCKED".equals(disposition)
                        ? "blocked" : "pending", "", "", -1, List.of());
    }

    public TrafficEntry(String id, String projectId, String projectName, String timestamp,
                        String method, String url, String mode, String disposition, String reason,
                        Integer statusCode, List<Decision.RuleHit> hits, long revision,
                        boolean bookmarked, Message requestCapture, Message responseCapture,
                        boolean truncated, String provenanceSeal, String intentId, String runId,
                        String outcome, String guardState, String overlayId, long responseBytes) {
        this(id, projectId, projectName, timestamp, method, url, mode, disposition, reason, statusCode,
                hits, revision, bookmarked, requestCapture, responseCapture, truncated, provenanceSeal,
                intentId, runId, outcome, guardState, overlayId, responseBytes, List.of());
    }

    public String request() {
        return method + " " + url + " HTTP/1.1 (inspection copy)\n" + requestCapture.text();
    }

    public String response() {
        return !responseCapture.present() ? "" : "HTTP/1.1 "
                + (statusCode == null ? "unknown" : statusCode) + " (inspection copy)\n"
                + responseCapture.text();
    }

    /** Only sanitized copies belong here. EMPTY distinguishes no response from an empty body. */
    public record Message(List<Header> headers, String body, String mimeType,
                          boolean bodyOmitted, boolean truncated, boolean present) {
        public static final Message EMPTY = new Message(List.of(), "", "", false, false, false);
        public Message {
            headers = List.copyOf(headers);
            Objects.requireNonNull(body);
            Objects.requireNonNull(mimeType);
        }
        public String text() {
            StringBuilder out = new StringBuilder();
            for (Header h : headers) out.append(h.name()).append(": ").append(h.value()).append('\n');
            return out.append('\n').append(body).toString();
        }
    }
}
