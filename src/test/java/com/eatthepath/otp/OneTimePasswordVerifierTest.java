package com.eatthepath.otp;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OneTimePasswordVerifierTest {

    private static final byte[] KEY_BYTES = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private static final SecretKey KEY =
            new SecretKeySpec(KEY_BYTES, TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1);

    // A timestamp of 1970-01-01T00:18:00Z with a default TOTP generator produces "003784" for KEY
    private static final Instant TIMESTAMP = Instant.parse("1970-01-01T00:18:00Z");
    private static final String VALID_CODE = "003784";

    private static final TimeBasedOneTimePasswordGenerator GENERATOR = new TimeBasedOneTimePasswordGenerator();

    private static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(final Instant instant) {
            this.instant = instant;
        }

        void setInstant(final Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.instant;
        }
    }

    private static OneTimePasswordVerifier verifier() {
        return new OneTimePasswordVerifier(GENERATOR);
    }

    @Test
    void verifySuccess() {
        final VerificationResult result = verifier().verify(KEY, VALID_CODE, TIMESTAMP);

        assertEquals(VerificationStatus.SUCCESS, result.getStatus());
        assertTrue(result.isSuccess());
        assertEquals(TIMESTAMP, result.getTimestamp());
        assertEquals(TIMESTAMP.toEpochMilli() / GENERATOR.getTimeStep().toMillis(), result.getTimeStep());
    }

    @Test
    void verifySuccessIntOverload() {
        assertEquals(VerificationStatus.SUCCESS, verifier().verify(KEY, 3784, TIMESTAMP).getStatus());
    }

    @Test
    void verifyInvalidCode() {
        final OneTimePasswordVerifier verifier = verifier();

        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, "000000", TIMESTAMP).getStatus());
        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, "3784", TIMESTAMP).getStatus());
        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, "cursed", TIMESTAMP).getStatus());
        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, null, TIMESTAMP).getStatus());

        final VerificationResult result = verifier.verify(KEY, "000000", TIMESTAMP);
        assertFalse(result.isSuccess());
        assertEquals(-1, result.getTimeStep());
    }

    @Test
    void verifyInvalidSecret() {
        final OneTimePasswordVerifier verifier = verifier();

        assertEquals(VerificationStatus.INVALID_SECRET, verifier.verify(null, VALID_CODE, TIMESTAMP).getStatus());

        final VerificationResult result = verifier.verify(unreadableKey(), VALID_CODE, TIMESTAMP);
        assertEquals(VerificationStatus.INVALID_SECRET, result.getStatus());
        assertFalse(result.isSuccess());
    }

    /**
     * Returns a key whose encoded form cannot be read; the underlying Mac rejects such keys with an
     * {@link java.security.InvalidKeyException}, and verification must fail closed and classify the failure rather
     * than throwing.
     */
    private static SecretKey unreadableKey() {
        return new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "HmacSHA1";
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }
        };
    }

    @Test
    void verifyRejectsReplayedTimeStep() throws Exception {
        final OneTimePasswordVerifier verifier = verifier();

        assertEquals(VerificationStatus.SUCCESS, verifier.verify(KEY, VALID_CODE, TIMESTAMP).getStatus());

        // The same password for the same (now consumed) time step must be rejected as a replay
        final VerificationResult replay = verifier.verify(KEY, VALID_CODE, TIMESTAMP);
        assertEquals(VerificationStatus.REPLAYED_TIME_STEP, replay.getStatus());
        assertFalse(replay.isSuccess());
        assertEquals(TIMESTAMP.toEpochMilli() / GENERATOR.getTimeStep().toMillis(), replay.getTimeStep());

        // A password for a later, unconsumed time step is still accepted
        final Instant later = TIMESTAMP.plus(GENERATOR.getTimeStep());
        final String laterCode = GENERATOR.generateOneTimePasswordString(KEY, later);
        assertEquals(VerificationStatus.SUCCESS, verifier.verify(KEY, laterCode, later).getStatus());

        // With a validation window, a consumed password that still falls inside the window is rejected as a replay
        final OneTimePasswordVerifier windowed =
                OneTimePasswordVerifier.builder(GENERATOR).validationWindow(1).build();

        assertEquals(VerificationStatus.SUCCESS, windowed.verify(KEY, laterCode, later).getStatus());
        assertEquals(VerificationStatus.REPLAYED_TIME_STEP,
                windowed.verify(KEY, laterCode, later.plus(GENERATOR.getTimeStep())).getStatus());
    }

    @Test
    void verifyEnforcesRetryWindowAndFailsClosed() {
        final MutableClock clock = new MutableClock(TIMESTAMP);

        final OneTimePasswordVerifier verifier = OneTimePasswordVerifier.builder(GENERATOR)
                .maxAttempts(2)
                .retryWindow(Duration.ofSeconds(10))
                .clock(clock)
                .build();

        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, "000000").getStatus());
        assertEquals(VerificationStatus.INVALID_CODE, verifier.verify(KEY, "000000").getStatus());

        // The retry limit is now exhausted; even a correct password is rejected (fail closed) and is not consumed
        assertEquals(VerificationStatus.RETRY_LIMIT_EXCEEDED, verifier.verify(KEY, VALID_CODE).getStatus());

        // Once old failures age out of the retry window (but within the same time step), verification resumes and
        // the previously-rejected correct password still works because it was never consumed
        clock.setInstant(TIMESTAMP.plus(Duration.ofSeconds(11)));
        assertEquals(VerificationStatus.SUCCESS, verifier.verify(KEY, VALID_CODE).getStatus());
    }

    @Test
    void verifyFailuresCountTowardRetryLimit() {
        final OneTimePasswordVerifier verifier = OneTimePasswordVerifier.builder(GENERATOR)
                .maxAttempts(1)
                .retryWindow(Duration.ofMinutes(5))
                .clock(Clock.fixed(TIMESTAMP, ZoneId.of("UTC")))
                .build();

        // Bad-secret failures are throttled just like wrong codes: callers cannot retry indefinitely
        final SecretKey badKey = unreadableKey();

        assertEquals(VerificationStatus.INVALID_SECRET, verifier.verify(badKey, VALID_CODE).getStatus());
        assertEquals(VerificationStatus.RETRY_LIMIT_EXCEEDED, verifier.verify(badKey, VALID_CODE).getStatus());
    }

    @Test
    void verifyEmitsConsistentAuditEvents() {
        final List<VerificationAuditEvent> events = new ArrayList<>();

        final OneTimePasswordVerifier verifier = OneTimePasswordVerifier.builder(GENERATOR)
                .auditListener(events::add)
                .build();

        final VerificationResult success = verifier.verify(KEY, VALID_CODE, TIMESTAMP);
        final VerificationResult replay = verifier.verify(KEY, VALID_CODE, TIMESTAMP);
        final VerificationResult invalid = verifier.verify(KEY, "cursed", TIMESTAMP);
        final VerificationResult badSecret = verifier.verify(null, VALID_CODE, TIMESTAMP);

        assertEquals(4, events.size());

        final VerificationResult[] results = { success, replay, invalid, badSecret };

        for (int i = 0; i < results.length; i++) {
            final VerificationAuditEvent event = events.get(i);

            // Audit evidence must be consistent with the result returned to the caller
            assertEquals(results[i].getStatus(), event.getStatus());
            assertEquals(results[i].getTimestamp(), event.getTimestamp());
            assertEquals(results[i].getTimeStep(), event.getTimeStep());
        }

        assertEquals(VerificationStatus.SUCCESS, events.get(0).getStatus());
        assertEquals(VerificationStatus.REPLAYED_TIME_STEP, events.get(1).getStatus());
        assertEquals(VerificationStatus.INVALID_CODE, events.get(2).getStatus());
        assertEquals(VerificationStatus.INVALID_SECRET, events.get(3).getStatus());

        // Events carry a stable, non-secret fingerprint for the key; attempts without a usable key carry none
        assertNotNull(events.get(0).getKeyFingerprint());
        assertEquals(events.get(0).getKeyFingerprint(), events.get(1).getKeyFingerprint());
        assertNull(events.get(3).getKeyFingerprint());
    }

    @Test
    void verifyHonorsValidationWindow() {
        final OneTimePasswordVerifier strict = verifier();
        final OneTimePasswordVerifier lenient =
                OneTimePasswordVerifier.builder(GENERATOR).validationWindow(1).build();

        final Instant oneStepLater = TIMESTAMP.plus(GENERATOR.getTimeStep());

        assertEquals(VerificationStatus.INVALID_CODE, strict.verify(KEY, VALID_CODE, oneStepLater).getStatus());

        final VerificationResult result = lenient.verify(KEY, VALID_CODE, oneStepLater);
        assertEquals(VerificationStatus.SUCCESS, result.getStatus());
        assertEquals(TIMESTAMP.toEpochMilli() / GENERATOR.getTimeStep().toMillis(), result.getTimeStep());
    }

    @Test
    void verifierPolicyAccessors() {
        final OneTimePasswordVerifier verifier = OneTimePasswordVerifier.builder(GENERATOR)
                .validationWindow(2)
                .maxAttempts(3)
                .retryWindow(Duration.ofMinutes(1))
                .build();

        assertEquals(2, verifier.getValidationWindow());
        assertEquals(3, verifier.getMaxAttempts());
        assertEquals(Duration.ofMinutes(1), verifier.getRetryWindow());

        final OneTimePasswordVerifier defaults = verifier();
        assertEquals(OneTimePasswordVerifier.DEFAULT_VALIDATION_WINDOW, defaults.getValidationWindow());
        assertEquals(OneTimePasswordVerifier.DEFAULT_MAX_ATTEMPTS, defaults.getMaxAttempts());
        assertEquals(OneTimePasswordVerifier.DEFAULT_RETRY_WINDOW, defaults.getRetryWindow());
    }

    @Test
    void builderRejectsInvalidPolicy() {
        final OneTimePasswordVerifier.Builder builder = OneTimePasswordVerifier.builder(GENERATOR);

        assertThrows(IllegalArgumentException.class, () -> builder.validationWindow(-1));
        assertThrows(IllegalArgumentException.class, () -> builder.maxAttempts(0));
        assertThrows(IllegalArgumentException.class, () -> builder.retryWindow(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> builder.retryWindow(Duration.ofSeconds(-1)));

        assertThrows(NullPointerException.class, () -> OneTimePasswordVerifier.builder(null));
        assertThrows(NullPointerException.class, () -> builder.retryWindow(null));
        assertThrows(NullPointerException.class, () -> builder.clock(null));
        assertThrows(NullPointerException.class, () -> builder.auditListener(null));
    }

    @Test
    void verifyRejectsNullTimestamp() {
        final OneTimePasswordVerifier verifier = verifier();

        assertThrows(NullPointerException.class, () -> verifier.verify(KEY, VALID_CODE, null));
        assertThrows(NullPointerException.class, () -> verifier.verify(KEY, 3784, null));
    }
}
