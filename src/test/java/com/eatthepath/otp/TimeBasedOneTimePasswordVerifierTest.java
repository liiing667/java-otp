package com.eatthepath.otp;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimeBasedOneTimePasswordVerifierTest {

    private static final Duration TIME_STEP = Duration.ofSeconds(30);

    private static final SecretKey TOTP_KEY =
            new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII),
                    TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1);

    private static final Instant TIMESTAMP = Instant.parse("2020-01-01T00:00:00Z");

    private static TimeBasedOneTimePasswordGenerator newGenerator() {
        return new TimeBasedOneTimePasswordGenerator(TIME_STEP);
    }

    private static int passwordAtStep(final TimeBasedOneTimePasswordGenerator generator, final Instant timestamp,
                                      final int stepOffset) throws InvalidKeyException {
        return generator.generateOneTimePassword(TOTP_KEY, timestamp.plus(TIME_STEP.multipliedBy(stepOffset)));
    }

    @Test
    void consumeOneTimePasswordForCurrentStep() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 1);

        final int password = generator.generateOneTimePassword(TOTP_KEY, TIMESTAMP);

        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, password));
        assertEquals(generator.getCounterValue(TIMESTAMP), verifier.getLastConsumedTimeStep());

        // The same password cannot be consumed a second time.
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, password));
    }

    @Test
    void backwardDriftWindowAcceptsSlightlyOldPassword() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 1);

        final int previousStepPassword = passwordAtStep(generator, TIMESTAMP, -1);

        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, previousStepPassword));
        assertEquals(generator.getCounterValue(TIMESTAMP) - 1, verifier.getLastConsumedTimeStep());

        // The current-step password is still fresh, but the old password can never be replayed.
        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, 0)));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, previousStepPassword));
    }

    @Test
    void forwardDriftWindowAcceptsSlightlyNewPassword() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 0, 1);

        final int nextStepPassword = passwordAtStep(generator, TIMESTAMP, 1);

        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, nextStepPassword));
        assertEquals(generator.getCounterValue(TIMESTAMP) + 1, verifier.getLastConsumedTimeStep());

        // Once a future step has been consumed, the current step is in the past and cannot be replayed.
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, 0)));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, nextStepPassword));
    }

    @Test
    void passwordOutsideWindowIsRejectedAndStateIsUnchanged() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 0);

        assertEquals(Long.MIN_VALUE, verifier.getLastConsumedTimeStep());

        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, -1)));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, 1)));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, "not-a-password"));

        assertEquals(Long.MIN_VALUE, verifier.getLastConsumedTimeStep());

        // The legitimate current-step password still works after all of the failed attempts.
        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, 0)));
    }

    @Test
    void asymmetricDriftWindows() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 2, 0);

        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, passwordAtStep(generator, TIMESTAMP, -2)));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP.plus(TIME_STEP.multipliedBy(2)),
                passwordAtStep(generator, TIMESTAMP, 3)));
    }

    @Test
    void consumeOneTimePasswordString() throws InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator generator =
                new TimeBasedOneTimePasswordGenerator(TIME_STEP, 8);
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 0);

        final String password = generator.generateOneTimePasswordString(TOTP_KEY, TIMESTAMP);

        assertTrue(verifier.consumeOneTimePassword(TIMESTAMP, password));
        assertFalse(verifier.consumeOneTimePassword(TIMESTAMP, password));

        assertThrows(NullPointerException.class, () -> verifier.consumeOneTimePassword(TIMESTAMP, (String) null));
        assertThrows(NullPointerException.class, () -> verifier.consumeOneTimePassword(null, password));
    }

    @Test
    void invalidConstructorArguments() {
        final TimeBasedOneTimePasswordGenerator generator = newGenerator();

        assertThrows(NullPointerException.class, () ->
                new TimeBasedOneTimePasswordVerifier(null, TOTP_KEY, 0));
        assertThrows(NullPointerException.class, () ->
                new TimeBasedOneTimePasswordVerifier(generator, null, 0));
        assertThrows(IllegalArgumentException.class, () ->
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, -1));
        assertThrows(IllegalArgumentException.class, () ->
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, -1, 0));
        assertThrows(IllegalArgumentException.class, () ->
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 0, -1));
    }

    @Test
    void concurrentConsumptionSucceedsExactlyOnce() throws InterruptedException, InvalidKeyException {
        final int threadCount = Runtime.getRuntime().availableProcessors() * 4;
        final int attemptsPerThread = 100;
        final CyclicBarrier cyclicBarrier = new CyclicBarrier(threadCount);
        final ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        final AtomicInteger successes = new AtomicInteger(0);

        final TimeBasedOneTimePasswordGenerator generator = newGenerator();
        final TimeBasedOneTimePasswordVerifier verifier =
                new TimeBasedOneTimePasswordVerifier(generator, TOTP_KEY, 0);

        final int password = generator.generateOneTimePassword(TOTP_KEY, TIMESTAMP);

        @SuppressWarnings("unchecked")
        final CompletableFuture<Void>[] futures = new CompletableFuture[threadCount];

        for (int thread = 0; thread < threadCount; thread++) {
            futures[thread] = CompletableFuture.runAsync(() -> {
                try {
                    cyclicBarrier.await();

                    for (int attempt = 0; attempt < attemptsPerThread; attempt++) {
                        if (verifier.consumeOneTimePassword(TIMESTAMP, password)) {
                            successes.incrementAndGet();
                        }
                    }
                } catch (final InterruptedException | BrokenBarrierException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
            }, executorService);
        }

        CompletableFuture.allOf(futures).join();

        assertEquals(1, successes.get());
        assertEquals(generator.getCounterValue(TIMESTAMP), verifier.getLastConsumedTimeStep());

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(1, TimeUnit.SECONDS));
    }
}
