package com.eatthepath.otp;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

class HmacOneTimePasswordVerifierTest {

    private static final SecretKey HOTP_KEY =
            new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII),
                    HmacOneTimePasswordGenerator.HOTP_HMAC_ALGORITHM);

    private static final int[] TEST_VECTORS = new int[] {
            755224,
            287082,
            359152,
            969429,
            338314,
            254676,
            287922,
            162583,
            399871,
            520489
    };

    @Test
    void consumeOneTimePasswordAdvancesCounter() throws InvalidKeyException {
        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 2);

        for (int counter = 0; counter < TEST_VECTORS.length; counter++) {
            assertEquals(counter, verifier.getCounter());
            assertTrue(verifier.consumeOneTimePassword(TEST_VECTORS[counter]));
            assertEquals(counter + 1, verifier.getCounter());
        }
    }

    @Test
    void consumedPasswordCannotBeReplayed() throws InvalidKeyException {
        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 2);

        assertTrue(verifier.consumeOneTimePassword(TEST_VECTORS[0]));
        assertFalse(verifier.consumeOneTimePassword(TEST_VECTORS[0]));
        assertEquals(1, verifier.getCounter());

        // Even a password for an older counter value is rejected forever.
        assertFalse(verifier.consumeOneTimePassword(String.valueOf(TEST_VECTORS[0])));
        assertEquals(1, verifier.getCounter());
    }

    @Test
    void failedAttemptDoesNotAdvanceCounter() throws InvalidKeyException {
        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 2);

        assertFalse(verifier.consumeOneTimePassword(0));
        assertFalse(verifier.consumeOneTimePassword("not-a-password"));
        assertEquals(0, verifier.getCounter());

        // The legitimate password still works after the failed attempts.
        assertTrue(verifier.consumeOneTimePassword(TEST_VECTORS[0]));
        assertEquals(1, verifier.getCounter());
    }

    @Test
    void lookaheadWindowResynchronizesCounter() throws InvalidKeyException {
        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 3);

        // The client has skipped ahead to counter 3; the verifier catches up in a single successful verification.
        assertTrue(verifier.consumeOneTimePassword(TEST_VECTORS[3]));
        assertEquals(4, verifier.getCounter());

        // Skipped-over passwords are now treated as consumed and cannot be replayed.
        assertFalse(verifier.consumeOneTimePassword(TEST_VECTORS[1]));
        assertFalse(verifier.consumeOneTimePassword(TEST_VECTORS[2]));

        // A password outside the lookahead window is rejected without changing state.
        assertFalse(verifier.consumeOneTimePassword(TEST_VECTORS[9]));
        assertEquals(4, verifier.getCounter());
    }

    @Test
    void consumeOneTimePasswordString() throws InvalidKeyException {
        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 36, 0);

        assertTrue(verifier.consumeOneTimePassword("003784"));
        assertEquals(37, verifier.getCounter());
        assertFalse(verifier.consumeOneTimePassword("3784"));

        assertThrows(NullPointerException.class, () -> verifier.consumeOneTimePassword((String) null));
    }

    @Test
    void invalidConstructorArguments() {
        final HmacOneTimePasswordGenerator generator = new HmacOneTimePasswordGenerator();

        assertThrows(NullPointerException.class, () ->
                new HmacOneTimePasswordVerifier(null, HOTP_KEY, 0, 0));
        assertThrows(NullPointerException.class, () ->
                new HmacOneTimePasswordVerifier(generator, null, 0, 0));
        assertThrows(IllegalArgumentException.class, () ->
                new HmacOneTimePasswordVerifier(generator, HOTP_KEY, -1, 0));
        assertThrows(IllegalArgumentException.class, () ->
                new HmacOneTimePasswordVerifier(generator, HOTP_KEY, 0, -1));
    }

    @Test
    void concurrentConsumptionSucceedsExactlyOnce() throws InterruptedException {
        final int threadCount = Runtime.getRuntime().availableProcessors() * 4;
        final int attemptsPerThread = 100;
        final CyclicBarrier cyclicBarrier = new CyclicBarrier(threadCount);
        final ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        final AtomicInteger successes = new AtomicInteger(0);

        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 0);

        @SuppressWarnings("unchecked")
        final CompletableFuture<Void>[] futures = new CompletableFuture[threadCount];

        for (int thread = 0; thread < threadCount; thread++) {
            futures[thread] = CompletableFuture.runAsync(() -> {
                try {
                    cyclicBarrier.await();

                    for (int attempt = 0; attempt < attemptsPerThread; attempt++) {
                        if (verifier.consumeOneTimePassword(TEST_VECTORS[0])) {
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
        assertEquals(1, verifier.getCounter());

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(1, TimeUnit.SECONDS));
    }

    @Test
    void concurrentConsumptionIsOrderedAndNeverReplays() throws InterruptedException {
        final int threadCount = Runtime.getRuntime().availableProcessors() * 4;
        final CyclicBarrier cyclicBarrier = new CyclicBarrier(threadCount);
        final ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        final AtomicInteger successes = new AtomicInteger(0);

        final HmacOneTimePasswordVerifier verifier =
                new HmacOneTimePasswordVerifier(new HmacOneTimePasswordGenerator(), HOTP_KEY, 0, 0);

        @SuppressWarnings("unchecked")
        final CompletableFuture<Void>[] futures = new CompletableFuture[threadCount];

        for (int thread = 0; thread < threadCount; thread++) {
            futures[thread] = CompletableFuture.runAsync(() -> {
                try {
                    cyclicBarrier.await();

                    for (int counter = 0; counter < TEST_VECTORS.length; counter++) {
                        if (verifier.consumeOneTimePassword(TEST_VECTORS[counter])) {
                            successes.incrementAndGet();
                        }
                    }
                } catch (final InterruptedException | BrokenBarrierException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
            }, executorService);
        }

        CompletableFuture.allOf(futures).join();

        // Each of the ten passwords is consumed exactly once, no matter how many threads raced for it.
        assertEquals(TEST_VECTORS.length, successes.get());
        assertEquals(TEST_VECTORS.length, verifier.getCounter());

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(1, TimeUnit.SECONDS));
    }
}
