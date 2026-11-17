/* Copyright (c) 2016 Jon Chambers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. */

package com.eatthepath.otp;

import java.util.Optional;

/**
 * The outcome of an attempt to verify a one-time password. In addition to indicating whether the verification attempt
 * succeeded, a verification result categorizes the reason for any failure so that callers can distinguish between, for
 * example, a key that cannot be used to generate passwords and a one-time password that simply does not match.
 * <p>
 * When verification succeeds, the result also reports the counter value (for HMAC-based one-time passwords) or time
 * step (for time-based one-time passwords) against which the supplied one-time password was verified.
 *
 * @see HmacOneTimePasswordGenerator#verifyOneTimePassword(javax.crypto.SecretKey, long, String)
 * @see TimeBasedOneTimePasswordGenerator#verifyOneTimePassword(javax.crypto.SecretKey, java.time.Instant, String)
 */
public class OneTimePasswordVerificationResult {

    /**
     * The reasons for which a one-time password verification attempt might fail.
     */
    public enum FailureReason {

        /**
         * The given one-time password did not match the password generated for the given key and counter value or
         * timestamp.
         */
        MISMATCH,

        /**
         * The given one-time password could not be interpreted as a one-time password. For string-based verification,
         * this means the string did not have the expected number of digits or could not be parsed as an integer.
         */
        MALFORMED_ONE_TIME_PASSWORD,

        /**
         * The given key was inappropriate for initializing the {@link javax.crypto.Mac} used to generate the expected
         * one-time password. This generally indicates a misconfigured or corrupted credential rather than an
         * incorrectly-entered password.
         */
        INVALID_KEY
    }

    private final boolean successful;
    private final FailureReason failureReason;
    private final long matchedCounter;

    private OneTimePasswordVerificationResult(final boolean successful, final FailureReason failureReason, final long matchedCounter) {
        this.successful = successful;
        this.failureReason = failureReason;
        this.matchedCounter = matchedCounter;
    }

    static OneTimePasswordVerificationResult success(final long matchedCounter) {
        return new OneTimePasswordVerificationResult(true, null, matchedCounter);
    }

    static OneTimePasswordVerificationResult failure(final FailureReason failureReason, final long counter) {
        return new OneTimePasswordVerificationResult(false, failureReason, counter);
    }

    /**
     * Returns whether the one-time password matched the password generated for the given key and counter value or
     * timestamp.
     *
     * @return {@code true} if and only if verification succeeded
     */
    public boolean isSuccessful() {
        return this.successful;
    }

    /**
     * Returns the reason verification failed, or an empty {@link Optional} if verification succeeded.
     *
     * @return the reason verification failed, or an empty {@link Optional} if verification succeeded
     */
    public Optional<FailureReason> getFailureReason() {
        return Optional.ofNullable(this.failureReason);
    }

    /**
     * Returns the counter value or time step against which the one-time password was verified. For
     * {@link HmacOneTimePasswordGenerator}, this is the counter value passed to the verification method. For
     * {@link TimeBasedOneTimePasswordGenerator}, this is the time step derived from the timestamp passed to the
     * verification method (i.e. the number of time steps between the epoch and that timestamp). The value is reported
     * for both successful and failed verification attempts.
     *
     * @return the counter value or time step against which the one-time password was verified
     */
    public long getMatchedCounter() {
        return this.matchedCounter;
    }

    @Override
    public String toString() {
        if (this.successful) {
            return "OneTimePasswordVerificationResult{successful, matchedCounter=" + this.matchedCounter + "}";
        }

        return "OneTimePasswordVerificationResult{failed, failureReason=" + this.failureReason +
                ", counter=" + this.matchedCounter + "}";
    }
}
