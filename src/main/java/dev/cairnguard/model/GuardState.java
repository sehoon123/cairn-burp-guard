package dev.cairnguard.model;

/** Typed local guard cause, separate from free-form UI notes and target HTTP status. */
public enum GuardState {
    PROTECTED, PAUSED_BY_OPERATOR, POLICY_INVALID, POLICY_SAVE_UNCERTAIN, PROJECT_UNVERIFIED,
    SHUTDOWN, CIRCUIT_OPEN, OVERLAY_BLOCK, INTENT_BUDGET, LISTENER_UNVERIFIED, CAPACITY,
    IN_FLIGHT_STALLED
}
