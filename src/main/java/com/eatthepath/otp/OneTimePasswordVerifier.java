package com.eatthepath.otp;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Verifies time-based one-time passwords with classified results, replay protection, a bounded retry policy, and
 * audit events. Whereas {@link TimeBasedOneTimePasswordGenerator#validateOneTimePassword} answers only "does this
 * password match right now," a {@code OneTimePasswordVerifier} answers the questions a caller actually needs to
 * close out an authentication flow:
 *
 * <ul>
 *     <li><em>Why did verification fail?</em> Every attempt yields a {@link VerificationResult} whose
 *     {@link VerificationStatus} distinguishes bad secrets ({@link VerificationStatus#INVALID_SECRET}), wrong or
 *     malformed codes ({@link VerificationStatus#INVALID_CODE}), replayed time steps
 *     ({@link VerificationStatus#REPLAYED_TIME_STEP}), and retry-limit rejections
 *     ({@link VerificationStatus#RETRY_LIMIT_EXCEEDED}).</li>
 *     <li><em>Has this time step been used before?</em> A time step consumed by a successful verification can never
 *     be used again, so a captured password cannot be replayed.</li>
 *     <li><em>Can an attacker retry forever?</em> No. Failed attempts are counted in a sliding retry window; once
 *     the limit is reached, verification fails closed—even for otherwise-correct passwords—until old failures age
 *     out of the window.</li>
 *     <li><em>Where is the evidence?</em> Every attempt produces exactly one {@link VerificationAuditEvent}
 *     delivered to registered listeners, consistent with the result returned to the caller.</li>
 * </ul>
 *
 * <p>All policy knobs (validation window, retry limit, retry window, clock, audit listeners) are supplied by the
 * caller through {@link #builder(TimeBasedOneTimePasswordGenerator)}. {@code OneTimePasswordVerifier} instances are
 * thread-safe and may be shared between threads.</p>
 *
 * @see TimeBasedOneTimePasswordGenerator
 * @see VerificationResult
 * @see VerificationStatus
 */
public class OneTimePasswordVerifier {

    /**
     * The default number of time steps on either side of the current step whose passwords are accepted (0: only the
     * current time step is accepted).
     */
    public static final int DEFAULT_VALIDATION_WINDOW = 0;

    /**
     * The default maximum number of failed attempts permitted within the retry window before verification fails
     * closed (5).
     */
    public static final int DEFAULT_MAX_ATTEMPTS = 5;

    /**
     * The default sliding window in which failed attempts are counted against the retry limit (5 minutes).
     */
    public static final Duration DEFAULT_RETRY_WINDOW = Duration.ofMinutes(5);

    private final TimeBasedOneTimePasswordGenerator generator;
    private final int validationWindow;
    private final int maxAttempts;
    private final Duration retryWindow;
    private final Clock clock;
    private final List<VerificationAuditListener> auditListeners;

    private final ConcurrentMap<String, KeyState> keyStates = new ConcurrentHashMap<>();

    private static final class KeyState {
        private long lastConsumedTimeStep = -1;
        private final Deque<Instant> failureTimestamps = new ArrayDeque<>();
    }

    /**
     * Constructs a new verifier with default policy: only passwords for the current time step are accepted, at most
     * {@value #DEFAULT_MAX_ATTEMPTS} failed attempts are permitted per
     * {@link #DEFAULT_RETRY_WINDOW}, and no audit listeners are registered.
     *
     * @param generator the TOTP generator with which to validate passwords; must not be {@code null}
     */
    public OneTimePasswordVerifier(final TimeBasedOneTimePasswordGenerator generator) {
        this(builder(generator));
    }

    private OneTimePasswordVerifier(final Builder builder) {
        this.generator = builder.generator;
        this.validationWindow = builder.validationWindow;
        this.maxAttempts = builder.maxAttempts;
        this.retryWindow = builder.retryWindow;
        this.clock = builder.clock;
        this.auditListeners = Collections.unmodifiableList(new ArrayList<>(builder.auditListeners));
    }

    /**
     * Returns a new builder for constructing a verifier with caller-configured policy.
     *
     * @param generator the TOTP generator with which to validate passwords; must not be {@code null}
     *
     * @return a new builder
     */
    public static Builder builder(final TimeBasedOneTimePasswordGenerator generator) {
        return new Builder(generator);
    }

    /**
     * Builds {@link OneTimePasswordVerifier} instances with caller-configured verification policy.
     */
    public static final class Builder {

        private final TimeBasedOneTimePasswordGenerator generator;
        private final List<VerificationAuditListener> auditListeners = new ArrayList<>();

        private int validationWindow = DEFAULT_VALIDATION_WINDOW;
        private int maxAttempts = DEFAULT_MAX_ATTEMPTS;
        private Duration retryWindow = DEFAULT_RETRY_WINDOW;
        private Clock clock = Clock.systemUTC();

        private Builder(final TimeBasedOneTimePasswordGenerator generator) {
            this.generator = Objects.requireNonNull(generator, "Generator must not be null");
        }

        /**
         * Sets the number of time steps on either side of the current step whose passwords are accepted, to
         * compensate for clock drift between the client and server. The default is
         * {@link #DEFAULT_VALIDATION_WINDOW} (only the current time step).
         *
         * @param validationWindow the number of adjacent time steps to accept; must not be negative
         *
         * @return this builder
         */
        public Builder validationWindow(final int validationWindow) {
            if (validationWindow < 0) {
                throw new IllegalArgumentException("Validation window must not be negative");
            }

            this.validationWindow = validationWindow;
            return this;
        }

        /**
         * Sets the maximum number of failed verification attempts permitted per key within the retry window before
         * verification fails closed. The default is {@link #DEFAULT_MAX_ATTEMPTS}.
         *
         * @param maxAttempts the maximum number of failed attempts; must be at least 1
         *
         * @return this builder
         */
        public Builder maxAttempts(final int maxAttempts) {
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("Maximum attempts must be at least 1");
            }

            this.maxAttempts = maxAttempts;
            return this;
        }

        /**
         * Sets the sliding window in which failed attempts are counted against the retry limit. The default is
         * {@link #DEFAULT_RETRY_WINDOW}.
         *
         * @param retryWindow the retry window; must be positive
         *
         * @return this builder
         */
        public Builder retryWindow(final Duration retryWindow) {
            Objects.requireNonNull(retryWindow, "Retry window must not be null");

            if (retryWindow.isNegative() || retryWindow.isZero()) {
                throw new IllegalArgumentException("Retry window must be positive");
            }

            this.retryWindow = retryWindow;
            return this;
        }

        /**
         * Sets the clock used to determine the current time. The default is the system UTC clock.
         *
         * @param clock the clock to use; must not be {@code null}
         *
         * @return this builder
         */
        public Builder clock(final Clock clock) {
            this.clock = Objects.requireNonNull(clock, "Clock must not be null");
            return this;
        }

        /**
         * Registers a listener to receive an audit event for every verification attempt.
         *
         * @param auditListener the listener to register; must not be {@code null}
         *
         * @return this builder
         */
        public Builder auditListener(final VerificationAuditListener auditListener) {
            this.auditListeners.add(Objects.requireNonNull(auditListener, "Audit listener must not be null"));
            return this;
        }

        /**
         * Constructs a new verifier with the policy configured on this builder.
         *
         * @return a new verifier
         */
        public OneTimePasswordVerifier build() {
            return new OneTimePasswordVerifier(this);
        }
    }

    /**
     * Verifies a user-provided one-time password against the current time.
     *
     * @param key the secret key for the credential being verified; a {@code null} or unusable key yields
     * {@link VerificationStatus#INVALID_SECRET}
     * @param oneTimePassword the user-provided one-time password; a {@code null} or malformed password yields
     * {@link VerificationStatus#INVALID_CODE}
     *
     * @return the classified result of the attempt; never {@code null}
     */
    public VerificationResult verify(final SecretKey key, final String oneTimePassword) {
        return this.verify(key, oneTimePassword, Instant.now(this.clock));
    }

    /**
     * Verifies a user-provided one-time password against the given timestamp.
     *
     * @param key the secret key for the credential being verified; a {@code null} or unusable key yields
     * {@link VerificationStatus#INVALID_SECRET}
     * @param oneTimePassword the user-provided one-time password; a {@code null} or malformed password yields
     * {@link VerificationStatus#INVALID_CODE}
     * @param timestamp the time at which to evaluate the password; must not be {@code null}
     *
     * @return the classified result of the attempt; never {@code null}
     *
     * @throws NullPointerException if the given timestamp is {@code null}
     */
    public VerificationResult verify(final SecretKey key, final String oneTimePassword, final Instant timestamp) {
        Objects.requireNonNull(timestamp, "Timestamp must not be null");

        final VerificationResult result;
        final String keyFingerprint;

        if (key == null) {
            keyFingerprint = null;
            result = new VerificationResult(VerificationStatus.INVALID_SECRET, timestamp, -1);
        } else if (oneTimePassword == null) {
            keyFingerprint = fingerprint(key);
            result = new VerificationResult(VerificationStatus.INVALID_CODE, timestamp, -1);
        } else {
            keyFingerprint = fingerprint(key);
            result = this.verifyWithState(key, oneTimePassword, timestamp,
                    this.keyStates.computeIfAbsent(keyFingerprint, k -> new KeyState()));
        }

        final VerificationAuditEvent event =
                new VerificationAuditEvent(result.getStatus(), timestamp, result.getTimeStep(), keyFingerprint);

        // Notify listeners outside of any locks so listeners may safely interact with this verifier
        for (final VerificationAuditListener listener : this.auditListeners) {
            listener.onVerificationEvent(event);
        }

        return result;
    }

    private VerificationResult verifyWithState(final SecretKey key, final String oneTimePassword,
            final Instant timestamp, final KeyState keyState) {

        synchronized (keyState) {
            pruneFailures(keyState, timestamp);

            if (keyState.failureTimestamps.size() >= this.maxAttempts) {
                // Fail closed: do not evaluate the password at all, so even a correct password is rejected until
                // failures age out of the retry window.
                return new VerificationResult(VerificationStatus.RETRY_LIMIT_EXCEEDED, timestamp, -1);
            }

            final long currentTimeStep = this.getTimeStep(timestamp);
            long matchingTimeStep = -1;

            try {
                for (long candidate = currentTimeStep - this.validationWindow;
                        candidate <= currentTimeStep + this.validationWindow; candidate++) {

                    if (candidate < 0) {
                        continue;
                    }

                    if (this.generator.validateOneTimePassword(key, this.getTimestamp(candidate), oneTimePassword)) {
                        matchingTimeStep = candidate;
                        break;
                    }
                }
            } catch (final InvalidKeyException e) {
                recordFailure(keyState, timestamp);
                return new VerificationResult(VerificationStatus.INVALID_SECRET, timestamp, -1);
            }

            if (matchingTimeStep < 0) {
                recordFailure(keyState, timestamp);
                return new VerificationResult(VerificationStatus.INVALID_CODE, timestamp, -1);
            }

            if (matchingTimeStep <= keyState.lastConsumedTimeStep) {
                recordFailure(keyState, timestamp);
                return new VerificationResult(VerificationStatus.REPLAYED_TIME_STEP, timestamp, matchingTimeStep);
            }

            keyState.lastConsumedTimeStep = matchingTimeStep;
            keyState.failureTimestamps.clear();

            return new VerificationResult(VerificationStatus.SUCCESS, timestamp, matchingTimeStep);
        }
    }

    /**
     * Verifies a user-provided one-time password, given as an integer, against the current time.
     *
     * @param key the secret key for the credential being verified
     * @param oneTimePassword the user-provided one-time password
     *
     * @return the classified result of the attempt; never {@code null}
     */
    public VerificationResult verify(final SecretKey key, final int oneTimePassword) {
        return this.verify(key, oneTimePassword, Instant.now(this.clock));
    }

    /**
     * Verifies a user-provided one-time password, given as an integer, against the given timestamp.
     *
     * @param key the secret key for the credential being verified
     * @param oneTimePassword the user-provided one-time password
     * @param timestamp the time at which to evaluate the password; must not be {@code null}
     *
     * @return the classified result of the attempt; never {@code null}
     *
     * @throws NullPointerException if the given timestamp is {@code null}
     */
    public VerificationResult verify(final SecretKey key, final int oneTimePassword, final Instant timestamp) {
        return this.verify(key,
                String.format(Locale.ROOT, "%0" + this.generator.getPasswordLength() + "d", oneTimePassword),
                timestamp);
    }

    private void pruneFailures(final KeyState keyState, final Instant now) {
        final Instant cutoff = now.minus(this.retryWindow);

        while (!keyState.failureTimestamps.isEmpty() && !keyState.failureTimestamps.peekFirst().isAfter(cutoff)) {
            keyState.failureTimestamps.pollFirst();
        }
    }

    private static void recordFailure(final KeyState keyState, final Instant timestamp) {
        keyState.failureTimestamps.addLast(timestamp);
    }

    private long getTimeStep(final Instant timestamp) {
        return timestamp.toEpochMilli() / this.generator.getTimeStep().toMillis();
    }

    private Instant getTimestamp(final long timeStep) {
        return Instant.ofEpochMilli(timeStep * this.generator.getTimeStep().toMillis());
    }

    private static String fingerprint(final SecretKey key) {
        final byte[] encodedKey = key.getEncoded();

        if (encodedKey == null) {
            return "unencoded-key-" + System.identityHashCode(key);
        }

        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256").digest(encodedKey);
            final StringBuilder builder = new StringBuilder(digest.length * 2);

            for (final byte b : digest) {
                builder.append(Character.forDigit((b >> 4) & 0x0f, 16));
                builder.append(Character.forDigit(b & 0x0f, 16));
            }

            return builder.toString();
        } catch (final NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to support SHA-256.
            throw new AssertionError("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Returns the number of adjacent time steps on either side of the current step whose passwords are accepted.
     *
     * @return the validation window, in time steps
     */
    public int getValidationWindow() {
        return this.validationWindow;
    }

    /**
     * Returns the maximum number of failed attempts permitted per key within the retry window.
     *
     * @return the maximum number of failed attempts
     */
    public int getMaxAttempts() {
        return this.maxAttempts;
    }

    /**
     * Returns the sliding window in which failed attempts are counted against the retry limit.
     *
     * @return the retry window
     */
    public Duration getRetryWindow() {
        return this.retryWindow;
    }
}
