package com.eatthepath.otp;

import java.time.Instant;
import java.util.Objects;

/**
 * An immutable audit record for a single one-time password verification attempt. Every call to
 * {@link OneTimePasswordVerifier#verify} produces exactly one audit event whose status, timestamp, and time step are
 * consistent with the {@link VerificationResult} returned to the caller. Events deliberately contain only a
 * fingerprint of the secret key—never the key itself and never the submitted password—so they are safe to persist or
 * forward to an audit log.
 *
 * @see VerificationAuditListener
 * @see OneTimePasswordVerifier
 */
public final class VerificationAuditEvent {

    private final VerificationStatus status;
    private final Instant timestamp;
    private final long timeStep;
    private final String keyFingerprint;

    VerificationAuditEvent(final VerificationStatus status, final Instant timestamp, final long timeStep,
            final String keyFingerprint) {

        this.status = Objects.requireNonNull(status, "Status must not be null");
        this.timestamp = Objects.requireNonNull(timestamp, "Timestamp must not be null");
        this.timeStep = timeStep;
        this.keyFingerprint = keyFingerprint;
    }

    /**
     * Returns the classification of the verification attempt; identical to the status of the
     * {@link VerificationResult} returned to the caller for the same attempt.
     *
     * @return the classification of the verification attempt
     */
    public VerificationStatus getStatus() {
        return this.status;
    }

    /**
     * Returns the time at which the attempt was evaluated.
     *
     * @return the time at which the attempt was evaluated
     */
    public Instant getTimestamp() {
        return this.timestamp;
    }

    /**
     * Returns the time step (counter value) against which the password matched, or {@code -1} if the password did
     * not match any allowable time step.
     *
     * @return the matching time step, or {@code -1} if there was no match
     */
    public long getTimeStep() {
        return this.timeStep;
    }

    /**
     * Returns a non-reversible fingerprint (SHA-256, hexadecimal) of the secret key used for the attempt, which
     * allows audit records to be correlated per credential without exposing the secret itself.
     *
     * @return a fingerprint of the secret key, or {@code null} if no usable key was supplied
     */
    public String getKeyFingerprint() {
        return this.keyFingerprint;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof VerificationAuditEvent)) {
            return false;
        }

        final VerificationAuditEvent that = (VerificationAuditEvent) o;
        return this.timeStep == that.timeStep && this.status == that.status &&
                this.timestamp.equals(that.timestamp) && Objects.equals(this.keyFingerprint, that.keyFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.status, this.timestamp, this.timeStep, this.keyFingerprint);
    }

    @Override
    public String toString() {
        return "VerificationAuditEvent{status=" + this.status + ", timestamp=" + this.timestamp +
                ", timeStep=" + this.timeStep + ", keyFingerprint=" + this.keyFingerprint + '}';
    }
}
