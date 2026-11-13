java-otp is a Java library for generating [HOTP (RFC 4226)](https://tools.ietf.org/html/rfc4226) or [TOTP (RFC 6238)](https://tools.ietf.org/html/rfc6238) one-time passwords.

## Getting java-otp

java-otp requires Java 8 or newer.

You can download java-otp as a jar file (it has no dependencies) from the [GitHub releases page](https://github.com/jchambers/java-otp/releases) and add it to your project's classpath. If you're using Maven (or something that understands Maven dependencies) to build your project, you can add java-otp as a dependency:

```xml
<dependency>
  <groupId>com.eatthepath</groupId>
  <artifactId>java-otp</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Documentation

The latest API docs are available at https://jchambers.github.io/java-otp/apidocs/latest/.

## Usage

To demonstrate generating one-time passwords, we'll focus on the TOTP algorithm. To create a TOTP generator with a default password length (6 digits), time step (30 seconds), and HMAC algorithm (HMAC-SHA1):

```java
final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
```

To actually generate time-based one-time passwords, you'll need a key and a timestamp. Secure key management is beyond the scope of this document; for the purposes of an example, though, we'll generate a random key:

```java
final SecretKey key;
{
    final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

    // Key length should match the length of the HMAC output (160 bits for SHA-1, 256 bits
    // for SHA-256, and 512 bits for SHA-512). Note that while Mac#getMacLength() returns a
    // length in _bytes,_ KeyGenerator#init(int) takes a key length in _bits._
    final int macLengthInBytes = Mac.getInstance(totp.getAlgorithm()).getMacLength();
    keyGenerator.init(macLengthInBytes * 8);

    key = keyGenerator.generateKey();
}
```

Armed with a key, we can deterministically generate one-time passwords for any timestamp:

```java
final Instant now = Instant.now();
final Instant later = now.plus(totp.getTimeStep());

System.out.println("Current password: " + totp.generateOneTimePasswordString(key, now));
System.out.println("Future password:  " + totp.generateOneTimePasswordString(key, later));
```

…which produces (for one randomly-generated key):

```
Current password: 164092
Future password:  046148
```

To validate a one-time password:

```java
// In a real-world scenario, this might come from an HTTP request or some other remote channel
final int userSuppliedOneTimePassword = 164092;

if (totp.validateOneTimePassword(key, now, userSuppliedOneTimePassword)) {
    System.out.println("Password was correct");
} else {
    System.out.println("Password was incorrect");
}
```

> [!CAUTION]
> Please note that `validateOneTimePassword` simply checks equality of one-time passwords; compensating for clock drift,  throttling/rate-limiting password validation attempts, clock resynchronization, and so on are all beyond java-otp's scope and callers must address those concerns on their own. For more information, please see ["TOTP: Time-Based One-Time Password Algorithm (RFC 6238) - Security Considerations"](https://datatracker.ietf.org/doc/html/rfc6238#section-5) (and ["HOTP: An HMAC-Based One-Time Password Algorithm (RFC 4226) - Security Requirements"](https://datatracker.ietf.org/doc/html/rfc4226#section-7) for HOTP).

### Consuming one-time passwords

`validateOneTimePassword` only checks whether a password matches; it does not keep track of which passwords have already been used, so the same password can be submitted more than once. For login flows that need genuine one-time semantics, java-otp provides stateful verifiers that atomically consume a counter value (HOTP) or time step (TOTP). A verifier instance tracks a single key (for example, a single user account), and concurrent attempts are synchronized so that exactly one attempt can ever succeed.

For HOTP, a verifier holds the next expected counter value and searches a bounded lookahead window to resynchronize with a client whose counter has drifted ahead. A successful verification advances the counter past the consumed value; a failed verification leaves the counter untouched.

```java
final HmacOneTimePasswordGenerator hotp = new HmacOneTimePasswordGenerator();

// One verifier per key/account; the client's next expected counter value is 0, and we allow up to
// two counter values of drift within the lookahead window.
final HmacOneTimePasswordVerifier verifier =
        new HmacOneTimePasswordVerifier(hotp, key, 0, 2);

if (verifier.consumeOneTimePassword(userSuppliedOneTimePassword)) {
    // Success; verifier.getCounter() has advanced past the consumed counter value, and presenting
    // the same password again will always fail.
} else {
    // The password matched no counter value in the lookahead window; the counter has not moved.
}
```

For TOTP, a verifier remembers the most recently consumed time step and accepts passwords within a bounded drift window (in both directions) around the current step. Any password for a time step at or before the last consumed step is always rejected, which closes the replay window and compensates for modest clock drift.

```java
final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

// Accept passwords from one time step in the past through one time step in the future.
final TimeBasedOneTimePasswordVerifier verifier =
        new TimeBasedOneTimePasswordVerifier(totp, key, 1);

if (verifier.consumeOneTimePassword(Instant.now(), userSuppliedOneTimePassword)) {
    // Success; the matching time step has been consumed and the same password can never be accepted again.
}
```

Verifiers keep their state in memory. Applications that need state to survive a restart should persist the HOTP counter (`HmacOneTimePasswordVerifier#getCounter()`) or the last consumed TOTP time step (`TimeBasedOneTimePasswordVerifier#getLastConsumedTimeStep()`) alongside the account and reconstruct the verifier after startup. Throttling and rate-limiting of verification attempts remain the caller's responsibility.

## Performance and best practices

One-time password generators are thread-safe and reusable. Generally, applications should treat one-time password generator instances as long-lived resources (as opposed to creating new generators for each password-generation call).

## License and copyright

java-otp is published under the [MIT License](https://opensource.org/licenses/MIT).
