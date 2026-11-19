package com.eatthepath.otp;

import java.time.Instant;
import java.util.Objects;

/**
 * The immutable outcome of a single one-time password verification attempt. A result always carries a
 * {@link VerificationStatus} so callers can distinguish between bad secrets, wrong codes, replayed time steps, and
 * retry-limit rejections instead of treating every failure as an undifferentiated "try again."
 *
 * @see OneTimePasswordVerifier
 */
public final class VerificationResult {

    private final VerificationStatus status;
    private final Instant timestamp;
    private final long timeStep;

    VerificationResult(final VerificationStatus status, final Instant timestamp, final long timeStep) {
        this.status = Objects.requireNonNull(status, "Status must not be null");
        this.timestamp = Objects.requireNonNull(timestamp, "Timestamp must not be null");
        this.timeStep = timeStep;
    }

    /**
     * Returns the classification of this verification attempt.
     *
     * @return the classification of this verification attempt; never {@code null}
     */
    public VerificationStatus getStatus() {
        return this.status;
    }

    /**
     * Returns whether this verification attempt succeeded. This is exactly equivalent to
     * {@code getStatus() == VerificationStatus.SUCCESS}; all other statuses are denials.
     *
     * @return {@code true} if and only if the attempt succeeded
     */
    public boolean isSuccess() {
        return this.status == VerificationStatus.SUCCESS;
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
     * not match any allowable time step. For {@link VerificationStatus#REPLAYED_TIME_STEP} results, this is the
     * already-consumed time step the password was valid for.
     *
     * @return the matching time step, or {@code -1} if there was no match
     */
    public long getTimeStep() {
        return this.timeStep;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof VerificationResult)) {
            return false;
        }

        final VerificationResult that = (VerificationResult) o;
        return this.timeStep == that.timeStep && this.status == that.status && this.timestamp.equals(that.timestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.status, this.timestamp, this.timeStep);
    }

    @Override
    public String toString() {
        return "VerificationResult{status=" + this.status + ", timestamp=" + this.timestamp +
                ", timeStep=" + this.timeStep + '}';
    }
}
