package dev.cairnguard.model;

import java.util.List;

/** Untrusted accounting labels, never authentication or authorization. Headers are not modified. */
public record RequestAttribution(String intentId, String runId, boolean valid) {
    public static final String ABSENT = "-";
    public static final String INVALID = "?";

    public RequestAttribution {
        // Keep even directly constructed instances bounded; callers cannot forge a valid label.
        boolean intentOk = label(intentId);
        boolean runOk = label(runId);
        valid = valid && intentOk && runOk;
        if (!intentOk) intentId = INVALID;
        if (!runOk) runId = INVALID;
    }

    public static RequestAttribution parse(List<RequestData.Header> headers) {
        String intent = ABSENT;
        String run = ABSENT;
        boolean sawIntent = false;
        boolean sawRun = false;
        if (headers == null) return new RequestAttribution(INVALID, INVALID, false);
        for (RequestData.Header header : headers) {
            if (header == null || header.name() == null) continue;
            if (headerName(header.name(), "X-Cairn-Intent")) {
                intent = sawIntent || !label(header.value()) ? INVALID : header.value();
                sawIntent = true;
            } else if (headerName(header.name(), "X-Cairn-Run")) {
                run = sawRun || !label(header.value()) ? INVALID : header.value();
                sawRun = true;
            }
        }
        return new RequestAttribution(intent, run, !intent.equals(INVALID) && !run.equals(INVALID));
    }

    private static boolean headerName(String value, String expected) {
        if (value.length() != expected.length()) return false;
        // HTTP field names are ASCII: Unicode case folding must not create an alias/duplicate.
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) > 127) return false;
        return value.equalsIgnoreCase(expected);
    }

    private static boolean label(String value) {
        if (value == null || value.isEmpty() || value.length() > 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
                    || c == '.' || c == '_' || c == ':' || c == '-')) return false;
        }
        return true;
    }
}
