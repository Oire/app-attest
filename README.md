# Oire App Attest, Verification of Apple App Attest Attestations and Assertions in PHP

[![Latest version of oire/app-attest on Packagist](https://img.shields.io/packagist/v/oire/app-attest.svg?style=flat-square)](https://packagist.org/packages/oire/app-attest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/Oire/app-attest/blob/master/LICENSE)
[![CI status of the master branch](https://github.com/Oire/app-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/Oire/app-attest/actions/workflows/ci.yml)

Oire App Attest verifies Apple App Attest attestations and assertions on your PHP server: the certificate
chain, the nonce, the key id, the app id and the counter. It verifies and nothing else. It keeps no state,
stores no keys, issues no challenges, makes no network call and writes no log: you pass in what you stored,
and you store what it returns.

## What App Attest Is

[App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) lets
your server confirm that a request comes from a genuine copy of your iOS app running on a genuine Apple
device. The app generates a key pair in the device's Secure Enclave and asks Apple to vouch for it once:
the result is an **attestation**, a CBOR document holding a certificate chain up to Apple's App Attest root
and a nonce that binds the key to a challenge your server issued. Your server verifies the attestation and
stores the public key.

From then on the app signs its requests with that key: each signature is an **assertion**, a CBOR document
holding the signature and a counter that grows with every assertion. Your server verifies the signature
with the stored public key, checks that the counter grew, and stores the new counter. Apple specifies both
checks in [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server);
this library performs them step by step.

## Requirements

PHP 8.3 or later with the _GMP_, _Mbstring_, _OpenSSL_ and _Sodium_ extensions. GMP is required, not just
suggested, because decoding a large number from untrusted CBOR without it takes time quadratic in the
number's length, and every attestation is untrusted input.

The library depends on [phpseclib](https://phpseclib.com/) for X.509, on
[spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) for CBOR, and on
[psr/clock](https://www.php-fig.org/psr/psr-20/) for the clock interface.

## Installation

Install via [Composer](https://getcomposer.org/):

```shell
composer require oire/app-attest
```

## The Flow at a Glance

1. **Registration.** Your server issues a single-use challenge. The app generates a key with
   `DCAppAttestService.generateKey()`, hashes the challenge into a `clientDataHash`, calls
   `attestKey(_:clientDataHash:)` and sends the key id and the attestation. Your server verifies the
   attestation with `AttestationVerifier` and stores the returned `AttestedKey`.
2. **Every protected request.** Your server issues a single-use challenge. The app builds its client data
   (for example the request body, with the challenge inside), hashes it with SHA-256, calls
   `generateAssertion(_:clientDataHash:)` and sends the key id, the client data and the assertion. Your
   server verifies the assertion with `AssertionVerifier`, checks and consumes the challenge inside the
   client data, and stores the new counter.

## Encoding What the Client Sends

Both verifiers take **raw bytes**. Send binary values as unpadded base64url and decode them with Sodium:

```php
$keyId = sodium_base642bin($request['keyId'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
```

`sodium_base642bin()` throws a `SodiumException` on malformed input; treat it as a bad request.

Apple's `generateKey()` hands the app its key id in **standard** base64, not base64url, so the app converts
it before sending it. The same conversion turns the attestation and the assertion, which are `Data`, into
base64url:

```swift
func base64Url(_ standardBase64: String) -> String {
    standardBase64
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

let keyIdToSend = base64Url(keyId)
let attestationToSend = base64Url(attestation.base64EncodedString())
```

## Registering a Key: Verifying an Attestation

In the examples, `$logger` stands for your PSR-3 logger and `Response` for your framework's response class.

```php
use Oire\AppAttest\AttestationVerifier;
use Oire\AppAttest\Exception\AttestationException;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;

$app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));
$verifier = new AttestationVerifier();

$keyId = sodium_base642bin($request['keyId'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
$attestation = sodium_base642bin($request['attestation'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

// $challenge is the challenge you issued for this registration; look it up and consume it.
// Form the hash exactly as your app does: here, the SHA-256 of the challenge.
$clientDataHash = hash('sha256', $challenge, true);

try {
    $key = $verifier->verify($attestation, $clientDataHash, $keyId, $app, [Environment::Production]);
} catch (AttestationException $e) {
    $logger->notice('App Attest attestation refused', ['reason' => $e->reason->name, 'message' => $e->getMessage()]);

    return new Response('', 401);
}

// Store these for the key, indexed by the key id:
// $key->keyIdBase64Url(), $key->publicKeyPem, $key->environment->value, $key->counter (0) and $key->receipt
```

`verify(string $attestationCbor, string $clientDataHash, string $keyId, AppIdentity $app, array $allowed): AttestedKey`
performs Apple's attestation steps in order:

1. The document is an `apple-appattest` object with `attStmt.x5c`, `attStmt.receipt` and `authData`, and
   `authData` is long enough for its layout.
2. `x5c` holds exactly two certificates, the credential certificate and an intermediate. The intermediate
   is a CA issued by the trust anchor, the credential certificate is issued by the intermediate, and all
   three are valid at the clock's time.
3. The nonce, the SHA-256 of `authData` followed by `clientDataHash`, equals the one inside the credential
   certificate's extension `1.2.840.113635.100.8.2`.
4. The SHA-256 of the credential certificate's public key (its raw 65-byte uncompressed point) equals
   `$keyId`.
5. The `rpIdHash` in `authData` is the SHA-256 of your app id, `<team id>.<bundle id>`.
6. The counter in `authData` is 0.
7. The `aaguid` in `authData` names an environment in `$allowed`.
8. The `credentialId` in `authData` equals the key id.

`$clientDataHash` may be any length: the verifier hashes whatever bytes you pass, so it only has to match
what the app passed to `attestKey()`. Most apps pass the SHA-256 of the challenge; Apple's own sample in
the [attestation object validation guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
passes the raw 24-byte challenge.

The returned `AttestedKey` is a readonly value object:

* `string $keyId` — the key id, raw 32 bytes.
* `string $publicKeyPem` — the public key as one `PUBLIC KEY` PEM block. Store it unchanged and pass it to
  `AssertionVerifier`.
* `Environment $environment` — `Environment::Production` or `Environment::Development`.
* `string $receipt` — Apple's App Attest receipt, raw bytes, for your own use with Apple's fraud metric
  service; this library does not contact Apple.
* `int $counter` — always 0 for a freshly attested key.
* `keyIdBase64Url(): string` — the key id as unpadded base64url, for storing or indexing it as text.

## Verifying a Request: Assertions

```php
use Oire\AppAttest\AssertionVerifier;
use Oire\AppAttest\Exception\AssertionException;

$assertion = sodium_base642bin($request['assertion'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
// The exact bytes the app hashed into clientDataHash, for example the request body
$clientData = sodium_base642bin($request['clientData'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

// Look up the stored key by $request['keyId']: its public key PEM and its counter
$stored = $keys->find($request['keyId']);

try {
    $counter = (new AssertionVerifier())->verify($assertion, $clientData, $stored->publicKeyPem, $stored->counter, $app);
} catch (AssertionException $e) {
    $logger->notice('App Attest assertion refused', ['reason' => $e->reason->name, 'message' => $e->getMessage()]);

    return new Response('', 401);
}

// Now check that the challenge inside $clientData is one you issued, consume it,
// and store $counter for the key atomically (see What You Must Do Yourself)
```

`verify(string $assertionCbor, string $clientData, string $publicKeyPem, int $previousCounter, AppIdentity $app): int`
performs Apple's assertion steps 1 to 5 and returns the new counter:

1. The document is an object with a `signature` and an `authenticatorData` of at least 37 bytes.
2. The signature is a valid ECDSA P-256 signature, with SHA-256, over the nonce: the SHA-256 of
   `authenticatorData` followed by the SHA-256 of `$clientData`. The device signs the nonce, so the nonce
   is hashed once more by ECDSA itself.
3. The `rpIdHash` in `authenticatorData` is the SHA-256 of your app id.
4. The counter in `authenticatorData` is strictly greater than `$previousCounter`.

`$clientData` is raw bytes and is never parsed: what it holds is your protocol, not this library's.

`$publicKeyPem` must be the stored `AttestedKey::$publicKeyPem`, passed unchanged. Only a single
`PUBLIC KEY` PEM block holding an uncompressed P-256 key is accepted: never a file path, a certificate, a
private key or a key of another type. `$previousCounter` is the counter you stored for the key, 0 right
after its attestation.

`AssertionVerifier` has no constructor arguments: an assertion carries no certificate and no time.

## Failures

### Exception Hierarchy

* `Oire\AppAttest\Exception\AppAttestException` — abstract, extends `RuntimeException`. Catch it to handle
  a failure of either verifier in one place.
  * `AttestationException` — thrown by `AttestationVerifier::verify()`, with
    `public readonly AttestationFailureReason $reason`.
  * `AssertionException` — thrown by `AssertionVerifier::verify()`, with
    `public readonly AssertionFailureReason $reason`.

Each exception's `$reason` is an enum case, so you can map a failure to a response or a metric without
parsing the message. Messages name the failed check and never contain key material, so they are safe to
log. Do not send them to the client: refuse with a generic answer.

### Attestation Failure Reasons

`Oire\AppAttest\Exception\AttestationFailureReason`:

* `Format` — the document is not a well-formed `apple-appattest` object, `authData` is too short, or the
  credential certificate does not hold an uncompressed P-256 key. The document must be one CBOR map with
  nothing after it, the keys of every map in it distinct text strings, `x5c` an array, `fmt` a text
  string, and `x5c`'s entries, `receipt` and `authData` byte strings.
* `CertificateChain` — the chain is not exactly two certificates, does not lead to the trust anchor, has
  an intermediate that is not a CA, or is not valid at the clock's time; or a certificate is not exactly
  one DER `SEQUENCE` with nothing after it, or is longer than 4096 bytes (Apple's are about 1 KiB).
* `Nonce` — the credential certificate has no nonce extension, or its nonce does not match `authData` and
  `$clientDataHash`. A `clientDataHash` formed differently from the app's ends here.
* `KeyId` — the credential certificate's key, or the `credentialId` in `authData`, does not match the key
  id.
* `RpIdHash` — the key belongs to another team or bundle.
* `Counter` — the counter in `authData` is not 0.
* `Environment` — the `aaguid` names an environment not in `$allowed`, or none at all.

### Assertion Failure Reasons

`Oire\AppAttest\Exception\AssertionFailureReason`:

* `Format` — the document is not an object with a `signature` and 37 bytes of `authenticatorData`. It
  must be one CBOR map with nothing after it, the keys of every map in it distinct text strings and both
  members byte strings.
* `Signature` — the signature does not verify with the public key over this client data.
* `RpIdHash` — the assertion was made for another team or bundle.
* `Counter` — the counter did not grow: a replayed or reordered assertion.

### Caller Errors

A mistake in what your code passes is an `InvalidArgumentException`, never an `AppAttestException`, so it
cannot be mistaken for a forged request:

* a `TeamId` that is not exactly 10 uppercase letters and digits;
* a `BundleId` that is empty or holds anything but ASCII letters, digits, hyphens and periods;
* a `$publicKeyPem` that is not one uncompressed P-256 `PUBLIC KEY` PEM block;
* a `$previousCounter` outside 0 to 2^32 − 1;
* a `TrustAnchor::fromPem()` argument that is not exactly one PEM certificate.

A broken installation or a misconfigured process is a `LogicException`, not a failed verification:

* `TrustAnchor::apple()`, which `AttestationVerifier` calls when you pass no trust anchor, throws one if the
  bundled Apple root is missing or does not match its pinned fingerprint;
* `AttestationVerifier::verify()` throws one if your process has registered another phpseclib ASN.1 map for
  the nonce extension, OID `1.2.840.113635.100.8.2` (see Using phpseclib Elsewhere in Your Application).

## What You Must Do Yourself

The library verifies; everything around verification is yours:

* **Issue single-use challenges.** Generate them randomly on the server, give each a short lifetime, and
  accept each one once.
* **Compute `clientDataHash` the way your app does.** The verifier cannot guess how the app formed it; a
  mismatch is a `Nonce` failure.
* **Store the key.** Keep the key id, the public key PEM, the environment and the counter, indexed by the
  key id. Keep the receipt if you plan to use Apple's fraud metric.
* **Check the challenge inside `clientData` and consume it.** This is Apple's assertion step 6. The library
  never parses `clientData`, so it cannot tell a fresh request from an old one replayed with its original
  assertion; only your challenge check can.
* **Update the counter atomically.** Two concurrent requests can carry two valid assertions with the same
  previous counter; both verify, and only one may pass. Store the new counter with a compare-and-set and
  refuse the request if no row changed:

  ```sql
  UPDATE app_attest_keys
  SET counter = :newCounter
  WHERE key_id = :keyId AND counter = :previousCounter
  ```

* **Decide which environments to accept,** and pass them as `$allowed`.

## Development and Production Keys

An attestation from a development build carries the `appattestdevelop` `aaguid`, one from a TestFlight or
App Store build the production `aaguid`. Accepting `Environment::Development` keys is safe in the sense
that matters: the `rpIdHash` check ties every key to your team id and bundle id, and only builds signed
with your team's certificates can produce keys for your app id. Another developer's app, development or
not, can never pass. Pass `[Environment::Production]` alone if your production server should refuse your
own development builds, and `[Environment::Production, Environment::Development]` while you develop.

## Clocks

The certificate checks need the current time. `AttestationVerifier` takes any
[PSR-20](https://www.php-fig.org/psr/psr-20/) `ClockInterface` as its second argument, Symfony's
`symfony/clock` included, and uses the system time through its own `SystemClock` when you pass none:

```php
use Oire\AppAttest\AttestationVerifier;
use Symfony\Component\Clock\MockClock;

$verifier = new AttestationVerifier(clock: new MockClock('2026-10-09T12:00:00Z'));
```

## Trust Anchor

By default the chain must lead to Apple's App Attest root, bundled in
`resources/Apple_App_Attestation_Root_CA.pem` and checked against its pinned SHA-256 fingerprint
(`TrustAnchor::APPLE_ROOT_SHA256`) every time it is loaded. Tests that sign their own chains pass their
own root:

```php
use Oire\AppAttest\AttestationVerifier;
use Oire\AppAttest\TrustAnchor;

$verifier = new AttestationVerifier(TrustAnchor::fromPem($testRootPem));
```

## Using phpseclib Elsewhere in Your Application

`AttestationVerifier` changes two process-wide settings of phpseclib's `X509` class. Both are static, so
they affect every `X509` object in the same process, not only this library's:

* it calls `X509::disableURLFetch()`, so phpseclib no longer downloads issuer certificates from the
  `authorityInfoAccess` URLs of the certificates it validates;
* it registers an ASN.1 map for the App Attest nonce extension, OID `1.2.840.113635.100.8.2`, with
  `X509::registerExtension()`, so phpseclib decodes that extension into an array for every certificate it
  loads.

Both happen on every call to `AttestationVerifier::verify()`, not once. If your own code relies on
phpseclib fetching issuer certificates, call `X509::enableURLFetch()` again after each verification,
before your code validates its own certificates.

Do not register a map for `1.2.840.113635.100.8.2` yourself. If one other than the library's is already
registered, phpseclib refuses the library's map, and `verify()` throws a `LogicException` that names the
conflict instead of verifying.

## Testing Your Own Code

To test code that calls `AssertionVerifier`, sign assertions yourself with a P-256 key, the way a device
does: build a 37-byte `authenticatorData` (your app's `rpIdHash`, the flags byte `0x40` genuine assertions
carry, which the verifier does not read, and the counter as a big-endian 32-bit integer), form the nonce,
the SHA-256 of `authenticatorData` followed by the SHA-256 of `clientData`, sign **the nonce** with ECDSA
over SHA-256, and CBOR-encode the two members:

```php
use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\TextStringObject;
use Oire\AppAttest\AssertionVerifier;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\TeamId;

$app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));
$clientData = '{"challenge":"c2VydmVyIGNoYWxsZW5nZQ"}';
$previousCounter = 0;

$privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
$publicKeyPem = openssl_pkey_get_details($privateKey)['key'];

$authenticatorData = $app->rpIdHash() . "\x40" . pack('N', $previousCounter + 1);
$nonce = hash('sha256', $authenticatorData . hash('sha256', $clientData, true), true);
openssl_sign($nonce, $signature, $privateKey, OPENSSL_ALGO_SHA256);

$assertion = (string) MapObject::create()
    ->add(TextStringObject::create('signature'), ByteStringObject::create($signature))
    ->add(TextStringObject::create('authenticatorData'), ByteStringObject::create($authenticatorData));

$counter = (new AssertionVerifier())->verify($assertion, $clientData, $publicKeyPem, $previousCounter, $app); // 1
```

A signature over the bare `authenticatorData` followed by the SHA-256 of `clientData`, without hashing
them into the nonce first, is refused with `Signature`. The `CBOR` classes come from `spomky-labs/cbor-php`, which this library
already requires.

Attestations are harder to make, because they need a certificate chain with the nonce extension. This
repository's test-only
[AttestationBuilder](https://github.com/Oire/app-attest/blob/master/tests/Support/AttestationBuilder.php)
shows how to sign one with phpseclib and verify it against `TrustAnchor::fromPem()` of its own root. The
test code is not part of the Composer package.

## API Reference

`Oire\AppAttest`:

* `AttestationVerifier::__construct(?TrustAnchor $root = null, ?ClockInterface $clock = null)`
* `AttestationVerifier::verify(string $attestationCbor, string $clientDataHash, string $keyId, AppIdentity $app, array $allowed): AttestedKey`,
  where `$allowed` is a list of `Environment` cases
* `AssertionVerifier::verify(string $assertionCbor, string $clientData, string $publicKeyPem, int $previousCounter, AppIdentity $app): int`
* `TrustAnchor::apple(): TrustAnchor` and `TrustAnchor::fromPem(string $pem): TrustAnchor`
* `TrustAnchor::APPLE_ROOT_SHA256`, the pinned fingerprint as lowercase hexadecimal, and
  `TrustAnchor::$pem`, the root certificate as PEM
* `SystemClock`, the PSR-20 clock used when none is passed

`Oire\AppAttest\Value`:

* `TeamId::__construct(string $value)`, with `public readonly string $value`
* `BundleId::__construct(string $value)`, with `public readonly string $value`
* `AppIdentity::__construct(TeamId $teamId, BundleId $bundleId)`, with `appId(): string` (`<team id>.<bundle id>`)
  and `rpIdHash(): string` (its SHA-256, raw bytes)
* `Environment`, a string-backed enum with the cases `Production` (`'production'`) and `Development`
  (`'development'`), `aaguid(): string` and `Environment::tryFromAaguid(string $aaguid): ?Environment`
* `AttestedKey::__construct(string $keyId, string $publicKeyPem, Environment $environment, string $receipt)`,
  described under Registering a Key

`Oire\AppAttest\Exception`: `AppAttestException`, `AttestationException`, `AttestationFailureReason`,
`AssertionException` and `AssertionFailureReason`, described under Failures.

Everything under `Oire\AppAttest\Internal`, and every member marked `@internal`, such as
`TrustAnchor::fromPinnedPem()`, is not part of the public API and may change in any release.

## Development

```shell
composer install
composer test
composer lint
```

`composer test` runs PHPUnit; `composer lint` runs PHP CS Fixer with Oire's code style in dry-run mode,
then Psalm at level 1. Without a local PHP, the repository's container gives PHP 8.5 with every required
extension:

```shell
docker compose run --rm php composer test
docker compose run --rm php composer lint
```

The same Dockerfile builds PHP 8.3, the lowest supported version:

```shell
docker build --build-arg PHP_VERSION=8.3 -t app-attest-php83 .
docker run --rm -v "$PWD":/app app-attest-php83 composer test
docker run --rm -v "$PWD":/app app-attest-php83 composer lint
```

The tests verify genuine attestations and assertions signed by Apple, used byte for byte as the reference
implementations ship them, and reach every failure through the verifiers' inputs or through test-only
builders, never by editing a signed vector. Their origins are listed in
[the golden vectors' README](tests/fixtures/README.md).

## Credits

The checks are ported from two reference implementations, whose test data are this library's golden
vectors:

* [veehaitch/devicecheck-appattest](https://github.com/veehaitch/devicecheck-appattest), in Kotlin,
  licensed under the Apache License, Version 2.0;
* [takimoto3/app-attest](https://github.com/takimoto3/app-attest), in Go, licensed under the MIT License.

Their license texts are in `tests/fixtures/LICENSE-veehaitch` and `tests/fixtures/LICENSE-takimoto3`. One
attestation vector is the sample Apple publishes in its attestation object validation guide.

## License

Copyright © 2026 André Polykanine, Oire Software. Licensed under the Apache License, Version 2.0. See
[the LICENSE file](LICENSE).
