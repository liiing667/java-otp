package com.eatthepath.otp;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Objects;

/**
 * <p>A stateful, one-time-consuming verifier for HMAC-based one-time passwords (HOTP) as specified in
 * <a href="https://www.rfc-editor.org/rfc/rfc4226">RFC&nbsp;4226</a>. Unlike
 * {@link HmacOneTimePasswordGenerator#validateOneTimePassword(SecretKey, long, int)}, which only checks whether a
 * password matches a given counter value, a verifier tracks the next expected counter value for a single key and
 * <em>consumes</em> a counter value whenever a password is accepted. A password that has already been consumed can
 * never be accepted again.</p>
 *
 * <p>On a successful verification, the verifier advances its counter to one past the consumed counter value. If the
 * presented password does not match any counter value within the configured lookahead window, verification fails and
 * the verifier's state is left completely unchanged. The lookahead window allows a caller to resynchronize with a
 * client that has advanced its counter ahead of the server, as discussed in
 * <a href="https://www.rfc-editor.org/rfc/rfc4226#section-7.2">RFC&nbsp;4226, section&nbsp;7.2</a>.</p>
 *
 * <p>Verification is synchronized, so concurrent attempts against the same verifier instance are atomic: at most one
 * attempt can consume any given counter value. A verifier instance holds all state for a single key (for example, a
 * single user account); applications that manage multiple keys must use one verifier per key.</p>
 *
 * @see HmacOneTimePasswordGenerator
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class HmacOneTimePasswordVerifier {

    private final HmacOneTimePasswordGenerator generator;
    private final SecretKey key;
    private final int lookaheadWindow;

    private long counter;

    /**
     * Creates a new HOTP verifier for the given generator and key.
     *
     * @param generator the generator used to produce expected one-time passwords
     * @param key the secret key identifying the account whose passwords this verifier tracks
     * @param initialCounter the counter value expected for the next presented password; must not be negative
     * @param lookaheadWindow the number of counter values beyond the expected counter value that may be searched for a
     * matching password; must not be negative, and should be small (RFC&nbsp;4226 suggests a window of no more than
     * about five counter values) to limit the impact of brute-force attempts
     *
     * @throws NullPointerException if the given generator or key is {@code null}
     * @throws IllegalArgumentException if the given initial counter or lookahead window is negative
     */
    public HmacOneTimePasswordVerifier(final HmacOneTimePasswordGenerator generator, final SecretKey key,
                                       final long initialCounter, final int lookaheadWindow) {

        this.generator = Objects.requireNonNull(generator, "HOTP generator must not be null");
        this.key = Objects.requireNonNull(key, "Key must not be null");

        if (initialCounter < 0) {
            throw new IllegalArgumentException("Initial counter must not be negative");
        }

        if (lookaheadWindow < 0) {
            throw new IllegalArgumentException("Lookahead window must not be negative");
        }

        this.counter = initialCounter;
        this.lookaheadWindow = lookaheadWindow;
    }

    /**
     * Checks the given one-time password against every counter value in the lookahead window and, if it matches,
     * atomically consumes the matching counter value. A consumed password (and any password for an earlier counter
     * value) can never be accepted again.
     *
     * @param oneTimePassword the user-provided one-time password to verify
     *
     * @return {@code true} if and only if the given password matched a counter value in the lookahead window that had
     * not already been consumed; returns {@code false} without changing verifier state otherwise
     *
     * @throws InvalidKeyException if the verifier's key is inappropriate for initializing the underlying
     * {@link javax.crypto.Mac}
     */
    public boolean consumeOneTimePassword(final int oneTimePassword) throws InvalidKeyException {
        return consume(candidateCounter ->
                this.generator.validateOneTimePassword(this.key, candidateCounter, oneTimePassword));
    }

    /**
     * Checks the given one-time password against every counter value in the lookahead window and, if it matches,
     * atomically consumes the matching counter value. A consumed password (and any password for an earlier counter
     * value) can never be accepted again.
     *
     * @param oneTimePassword the user-provided one-time password to verify
     *
     * @return {@code true} if and only if the given password matched a counter value in the lookahead window that had
     * not already been consumed; returns {@code false} without changing verifier state otherwise
     *
     * @throws InvalidKeyException if the verifier's key is inappropriate for initializing the underlying
     * {@link javax.crypto.Mac}
     * @throws NullPointerException if the given one-time password is {@code null}
     */
    public boolean consumeOneTimePassword(final String oneTimePassword) throws InvalidKeyException {
        Objects.requireNonNull(oneTimePassword, "One-time password must not be null");

        return consume(candidateCounter ->
                this.generator.validateOneTimePassword(this.key, candidateCounter, oneTimePassword));
    }

    private boolean consume(final OneTimePasswordCheck oneTimePasswordCheck) throws InvalidKeyException {
        synchronized (this) {
            for (int offset = 0; offset <= this.lookaheadWindow; offset++) {
                final long candidateCounter = Math.addExact(this.counter, offset);

                if (oneTimePasswordCheck.matches(candidateCounter)) {
                    this.counter = Math.addExact(candidateCounter, 1);
                    return true;
                }
            }

            return false;
        }
    }

    /**
     * Returns the next counter value expected by this verifier. The counter starts at the initial counter value given
     * at construction time and advances to one past the consumed counter value after every successful verification;
     * failed verification attempts do not move the counter.
     *
     * @return the next counter value expected by this verifier
     */
    public synchronized long getCounter() {
        return this.counter;
    }

    @FunctionalInterface
    private interface OneTimePasswordCheck {
        boolean matches(long counter) throws InvalidKeyException;
    }
}
