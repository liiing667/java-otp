package com.eatthepath.otp;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.util.Objects;

/**
 * <p>A stateful, one-time-consuming verifier for time-based one-time passwords (TOTP) as specified in
 * <a href="https://www.rfc-editor.org/rfc/rfc6238">RFC&nbsp;6238</a>. Unlike
 * {@link TimeBasedOneTimePasswordGenerator#validateOneTimePassword(SecretKey, Instant, int)}, which only checks whether
 * a password matches a given timestamp, a verifier remembers the most recently consumed time step for a single key and
 * <em>consumes</em> a time step whenever a password is accepted. A password for any time step at or before the last
 * consumed time step can never be accepted again, which closes the replay window left open by a plain equality
 * check.</p>
 *
 * <p>To compensate for clock drift, the verifier searches a bounded window of time steps around the current step:
 * {@code backwardDriftWindow} steps in the past and {@code forwardDriftWindow} steps in the future. If the presented
 * password does not match any as-yet-unconsumed time step in that window, verification fails and the verifier's state
 * is left completely unchanged. Note that a match in the past still consumes that time step, so a later, older
 * password cannot be replayed; a password matching a step at or before the last consumed step is always rejected.</p>
 *
 * <p>Verification is synchronized, so concurrent attempts against the same verifier instance are atomic: at most one
 * attempt can consume any given time step. A verifier instance holds all state for a single key (for example, a single
 * user account); applications that manage multiple keys must use one verifier per key.</p>
 *
 * @see TimeBasedOneTimePasswordGenerator
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class TimeBasedOneTimePasswordVerifier {

    private final TimeBasedOneTimePasswordGenerator generator;
    private final SecretKey key;
    private final int backwardDriftWindow;
    private final int forwardDriftWindow;

    private long lastConsumedTimeStep = Long.MIN_VALUE;

    /**
     * Creates a new TOTP verifier for the given generator and key with a symmetric drift window.
     *
     * @param generator the generator used to produce expected one-time passwords
     * @param key the secret key identifying the account whose passwords this verifier tracks
     * @param driftWindow the number of time steps, in both directions, to search around the current time step when
     * compensating for clock drift; must not be negative, and should be small (RFC&nbsp;6238 recommends no more than
     * one time step of forward drift) to limit the impact of brute-force attempts
     *
     * @throws NullPointerException if the given generator or key is {@code null}
     * @throws IllegalArgumentException if the given drift window is negative
     */
    public TimeBasedOneTimePasswordVerifier(final TimeBasedOneTimePasswordGenerator generator, final SecretKey key,
                                            final int driftWindow) {
        this(generator, key, driftWindow, driftWindow);
    }

    /**
     * Creates a new TOTP verifier for the given generator and key with separate backward and forward drift windows.
     *
     * @param generator the generator used to produce expected one-time passwords
     * @param key the secret key identifying the account whose passwords this verifier tracks
     * @param backwardDriftWindow the number of time steps before the current time step to search when compensating for
     * a client clock that runs behind; must not be negative
     * @param forwardDriftWindow the number of time steps after the current time step to search when compensating for a
     * client clock that runs ahead; must not be negative
     *
     * @throws NullPointerException if the given generator or key is {@code null}
     * @throws IllegalArgumentException if either drift window is negative
     */
    public TimeBasedOneTimePasswordVerifier(final TimeBasedOneTimePasswordGenerator generator, final SecretKey key,
                                            final int backwardDriftWindow, final int forwardDriftWindow) {

        this.generator = Objects.requireNonNull(generator, "TOTP generator must not be null");
        this.key = Objects.requireNonNull(key, "Key must not be null");

        if (backwardDriftWindow < 0) {
            throw new IllegalArgumentException("Backward drift window must not be negative");
        }

        if (forwardDriftWindow < 0) {
            throw new IllegalArgumentException("Forward drift window must not be negative");
        }

        this.backwardDriftWindow = backwardDriftWindow;
        this.forwardDriftWindow = forwardDriftWindow;
    }

    /**
     * Checks the given one-time password against every as-yet-unconsumed time step in the drift window around the time
     * step for the given timestamp and, if it matches, atomically consumes the matching time step. A password for a
     * time step at or before the last consumed time step can never be accepted again.
     *
     * @param timestamp the timestamp at which the password is being verified
     * @param oneTimePassword the user-provided one-time password to verify
     *
     * @return {@code true} if and only if the given password matched an unconsumed time step in the drift window;
     * returns {@code false} without changing verifier state otherwise
     *
     * @throws InvalidKeyException if the verifier's key is inappropriate for initializing the underlying
     * {@link javax.crypto.Mac}
     * @throws NullPointerException if the given timestamp is {@code null}
     */
    public boolean consumeOneTimePassword(final Instant timestamp, final int oneTimePassword) throws InvalidKeyException {
        return consume(timestamp, candidateTimeStep ->
                this.generator.validateOneTimePassword(this.key, timestampForStep(candidateTimeStep), oneTimePassword));
    }

    /**
     * Checks the given one-time password against every as-yet-unconsumed time step in the drift window around the time
     * step for the given timestamp and, if it matches, atomically consumes the matching time step. A password for a
     * time step at or before the last consumed time step can never be accepted again.
     *
     * @param timestamp the timestamp at which the password is being verified
     * @param oneTimePassword the user-provided one-time password to verify
     *
     * @return {@code true} if and only if the given password matched an unconsumed time step in the drift window;
     * returns {@code false} without changing verifier state otherwise
     *
     * @throws InvalidKeyException if the verifier's key is inappropriate for initializing the underlying
     * {@link javax.crypto.Mac}
     * @throws NullPointerException if the given timestamp or one-time password is {@code null}
     */
    public boolean consumeOneTimePassword(final Instant timestamp, final String oneTimePassword) throws InvalidKeyException {
        Objects.requireNonNull(oneTimePassword, "One-time password must not be null");

        return consume(timestamp, candidateTimeStep ->
                this.generator.validateOneTimePassword(this.key, timestampForStep(candidateTimeStep), oneTimePassword));
    }

    private boolean consume(final Instant timestamp, final OneTimePasswordCheck oneTimePasswordCheck)
            throws InvalidKeyException {

        Objects.requireNonNull(timestamp, "Timestamp must not be null");

        synchronized (this) {
            final long currentTimeStep = this.generator.getCounterValue(timestamp);

            final long firstUnconsumedTimeStep =
                    this.lastConsumedTimeStep == Long.MAX_VALUE ? Long.MAX_VALUE : this.lastConsumedTimeStep + 1;

            final long earliestCandidate =
                    Math.max(Math.subtractExact(currentTimeStep, this.backwardDriftWindow), firstUnconsumedTimeStep);

            final long latestCandidate = Math.addExact(currentTimeStep, this.forwardDriftWindow);

            long candidateTimeStep = earliestCandidate;

            while (candidateTimeStep <= latestCandidate) {
                if (oneTimePasswordCheck.matches(candidateTimeStep)) {
                    this.lastConsumedTimeStep = candidateTimeStep;
                    return true;
                }

                if (candidateTimeStep == Long.MAX_VALUE) {
                    break;
                }

                candidateTimeStep++;
            }

            return false;
        }
    }

    private Instant timestampForStep(final long timeStep) {
        return Instant.ofEpochMilli(Math.multiplyExact(timeStep, this.generator.getTimeStep().toMillis()));
    }

    /**
     * Returns the most recently consumed time step, or {@link Long#MIN_VALUE} if no password has been consumed yet.
     * Passwords for time steps at or before the returned value are always rejected.
     *
     * @return the most recently consumed time step, or {@link Long#MIN_VALUE} if no password has been consumed yet
     */
    public synchronized long getLastConsumedTimeStep() {
        return this.lastConsumedTimeStep;
    }

    @FunctionalInterface
    private interface OneTimePasswordCheck {
        boolean matches(long timeStep) throws InvalidKeyException;
    }
}
