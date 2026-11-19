package com.eatthepath.otp;

/**
 * Receives an audit event for every one-time password verification attempt. Listeners are registered with
 * {@link OneTimePasswordVerifier.Builder#auditListener(VerificationAuditListener)} and are notified after each
 * attempt has been fully evaluated; the event's status always matches the result returned to the caller.
 *
 * <p>Listener implementations should be fast and non-blocking. Exceptions thrown by a listener do not affect the
 * verification result and prevent subsequently-registered listeners from being notified for that event.</p>
 *
 * @see OneTimePasswordVerifier
 * @see VerificationAuditEvent
 */
@FunctionalInterface
public interface VerificationAuditListener {

    /**
     * Receives an audit event for a completed verification attempt.
     *
     * @param event the audit event describing the attempt; never {@code null}
     */
    void onVerificationEvent(VerificationAuditEvent event);
}
