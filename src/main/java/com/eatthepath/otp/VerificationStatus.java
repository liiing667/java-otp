package com.eatthepath.otp;

/**
 * Classifies the outcome of a one-time password verification attempt. Verification never "fails open": every
 * non-{@link #SUCCESS} status is a denial, and callers should treat all non-success statuses as authentication
 * failures.
 *
 * @see OneTimePasswordVerifier
 * @see VerificationResult
 */
public enum VerificationStatus {

    /**
     * The provided one-time password matched an unconsumed time step within the validation window, and the attempt
     * was within the caller-configured retry policy.
     */
    SUCCESS,

    /**
     * The provided one-time password did not match the password for any allowable time step. This category covers
     * wrong codes as well as malformed codes (codes that are {@code null}, have the wrong number of digits, or cannot
     * be parsed as a number).
     */
    INVALID_CODE,

    /**
     * The provided secret key could not be used to generate one-time passwords (for example, because it is
     * {@code null} or is inappropriate for the generator's HMAC algorithm). Verification fails closed in this case.
     */
    INVALID_SECRET,

    /**
     * The provided one-time password was valid for a time step that has already been consumed by a previous
     * successful verification. Replayed passwords are always rejected.
     */
    REPLAYED_TIME_STEP,

    /**
     * The caller-configured retry policy rejected the attempt before (or regardless of) password validation because
     * too many failed attempts have been recorded inside the retry window. Verification fails closed in this case:
     * even a correct password is rejected until the retry window permits new attempts.
     */
    RETRY_LIMIT_EXCEEDED
}
