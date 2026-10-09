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

The library depends on [phpseclib](https://phpseclib.com/) 4 for X.509, on
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

`verify(string $attestationCbor, string $clientDataHash, string $keyId, AppIdentity $app, array $allowed, ?LaunchPolicy $launchPolicy = null): AttestedKey`
performs Apple's attestation steps in order:

1. The document is at most 16384 bytes, an `apple-appattest` object with `attStmt.x5c`, `attStmt.receipt`
   and `authData`, and `authData` is long enough for its layout, with one CBOR map, the COSE key, as the
   credential public key after the `credentialId`.
2. `x5c` holds exactly two certificates, the credential certificate and an intermediate. The intermediate
   is a CA issued by the trust anchor, the credential certificate is issued by the intermediate, each
   signed by its issuer with ECDSA, as Apple's are, and all three are valid at the clock's time.
3. The nonce, the SHA-256 of `authData` followed by `clientDataHash`, equals the one inside the credential
   certificate's extension `1.2.840.113635.100.8.2`.
4. The SHA-256 of the credential certificate's public key (its raw 65-byte uncompressed point) equals
   `$keyId`.
5. The `rpIdHash` in `authData` is the SHA-256 of your app id, `<team id>.<bundle id>`.
6. The counter in `authData` is 0.
7. The `aaguid` in `authData` names an environment in `$allowed`.
8. The `credentialId` in `authData` equals the key id.
9. Only if you pass a `LaunchPolicy`: the validation category and the bundle version in `authData` pass it
   (see Launch Category and Bundle Version).

`$allowed` lists the environments a key may come from, as `Environment` cases; it must not be empty.

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
* `?int $validationCategory` — the raw launch validation category in `authData`, or null if the device
  sent none; kept as a number, so one Apple has not named yet is still reported.
* `?string $bundleVersion` — the app's bundle version in `authData`, or null if the device sent none.
* `validationCategory(): ?ValidationCategory` — the category as an enum case, or null if it is absent or a
  number with no case.
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
    $result = (new AssertionVerifier())->verify($assertion, $clientData, $stored->publicKeyPem, $stored->counter, $app);
} catch (AssertionException $e) {
    $logger->notice('App Attest assertion refused', ['reason' => $e->reason->name, 'message' => $e->getMessage()]);

    return new Response('', 401);
}

// Now check that the challenge inside $clientData is one you issued, consume it,
// and store $result->counter for the key atomically (see What You Must Do Yourself)
```

`verify(string $assertionCbor, string $clientData, string $publicKeyPem, int $previousCounter, AppIdentity $app, ?LaunchPolicy $launchPolicy = null): VerifiedAssertion`
performs Apple's assertion steps 1 to 5 and returns a `VerifiedAssertion`:

1. The document is at most 4096 bytes, an object with a `signature` and an `authenticatorData` of at least
   37 bytes.
2. The signature is a valid ECDSA P-256 signature, with SHA-256, over the nonce: the SHA-256 of
   `authenticatorData` followed by the SHA-256 of `$clientData`. The device signs the nonce, so the nonce
   is hashed once more by ECDSA itself.
3. The `rpIdHash` in `authenticatorData` is the SHA-256 of your app id.
4. The counter in `authenticatorData` is strictly greater than `$previousCounter`.
5. Only if you pass a `LaunchPolicy`: the validation category and the bundle version in
   `authenticatorData` pass it (Apple's steps 7 and 8, see Launch Category and Bundle Version).

`$clientData` is raw bytes and is never parsed: what it holds is your protocol, not this library's.

`$publicKeyPem` must be the stored `AttestedKey::$publicKeyPem`, passed unchanged. Only a single
`PUBLIC KEY` PEM block holding an uncompressed P-256 key is accepted: never a file path, a certificate, a
private key or a key of another type. `$previousCounter` is the counter you stored for the key, 0 right
after its attestation.

`AssertionVerifier` has no constructor arguments: an assertion carries no certificate and no time.

The returned `Oire\AppAttest\Value\VerifiedAssertion` is a readonly value object:

* `int $counter` — the new counter, to store for the key.
* `?int $validationCategory` — the raw launch validation category in `authenticatorData`, or null if the
  device sent none; kept as a number, so one Apple has not named yet is still reported.
* `?string $bundleVersion` — the app's bundle version in `authenticatorData`, or null if the device sent
  none.
* `validationCategory(): ?ValidationCategory` — the category as an enum case, or null if it is absent or a
  number with no case.

Without a `LaunchPolicy` the launch values are only reported; with one, they have passed it.

## Launch Category and Bundle Version

Apple's list of attestation steps ends with "Verify the `apple_validation_category_01` value" and "Verify
the `apple_bundle_version_01` value", both "within the `extensions` CBOR dictionary in the authenticator
data", and its assertion steps 7 and 8 say the same of `validationCategory` and `bundleVersion`. Newer OS
versions append this map to `authData` after the credential public key, and to an assertion's
`authenticatorData` after its 37 bytes:

* the **validation category**, a `UInt32` that Apple calls "the launch `ValidationCategory` of your app":
  how the executable was signed and distributed, numbered as in Apple's
  [Defining launch environment and library constraints](https://developer.apple.com/documentation/security/defining-launch-environment-and-library-constraints);
* the **bundle version**, a string "representing the version of the distributed App".

Apple names no value you must accept and says nothing of a device that sends neither, and older devices
do send neither: none of the iOS 14 vectors this library is tested with carries them. So the library
reports the values on `AttestedKey` and `VerifiedAssertion` and enforces them only when you ask. Without a
policy, nothing about them is checked, and an extensions area that is missing or malformed is ignored.

`Oire\AppAttest\Value\ValidationCategory` is an int-backed enum: `Platform` (1, an operating system
executable), `TestFlight` (2), `Development` (3, signed by a development identity), `AppStore` (4),
`Enterprise` (5, an enterprise provisioning profile or ad hoc distribution), `DeveloperId` (6) and `None`
(10, a signing identity that matches no other category). Apple keeps 7 to 9 for binaries the system
generates in restricted situations and names none of them, so they have no case: `AttestedKey` and
`VerifiedAssertion` still report such a number in `$validationCategory`, and no policy allows it.
`ValidationCategory::tryFromRaw(?int $value)` gives the case for a reported number, or null.

Pass a `LaunchPolicy` as the last argument of `AttestationVerifier::verify()` to enforce them:

```php
use Oire\AppAttest\Value\LaunchPolicy;
use Oire\AppAttest\Value\ValidationCategory;

$policy = LaunchPolicy::allowing(ValidationCategory::AppStore, ValidationCategory::TestFlight)
    ->withBundleVersion(static fn(string $version): bool => version_compare($version, '2.0', '>='));

$key = $verifier->verify($attestation, $clientDataHash, $keyId, $app, [Environment::Production], $policy);
```

`AssertionVerifier::verify()` takes a policy the same way, but think twice before you pass one: no genuine
assertion with these values has been published to test against (see below). If a device puts them in its
attestation but not in its assertions, or spells them otherwise, every later assertion from it fails with
`ValidationCategory` or `BundleVersion`. Enforcing the policy once, on the attestation, does not have
this risk; to see what assertions carry first, verify them without a policy and read the values on the
`VerifiedAssertion`.

* `LaunchPolicy::allowing(ValidationCategory ...$categories)` allows these categories and leaves the
  bundle version unchecked. It needs at least one category: called with none, for example with an empty
  array from your configuration spread into it, it throws an `InvalidArgumentException` rather than turn
  the category check off.
* `new LaunchPolicy()` checks nothing, and `new LaunchPolicy($categories, $acceptsBundleVersion)` takes
  both parts at once. Its empty category list means that the category is not checked at all: every
  category passes, an absent one too. If you build that list from configuration, refuse an empty one
  yourself.
* `withBundleVersion(Closure $accepts)` returns a copy that also requires a bundle version for which the
  closure returns `true`.
* With a policy that lists categories, a category that is absent, has no enum case or is not listed fails
  with `ValidationCategory`. With a bundle version closure, a bundle version that is absent or that the
  closure does not accept fails with `BundleVersion`. Both checks run after every other check, the
  category first.

The values are read leniently, because Apple documents only their names and types. The category counts
when it is four little-endian bytes (as in Apple's sample) or a CBOR unsigned integer of at most
2^32 − 1; the bundle version when it is a text string. Both verifiers accept both spellings,
`apple_validation_category_01` or `validationCategory` and `apple_bundle_version_01` or `bundleVersion`;
when both hold a usable value, the `apple_…_01` one wins. A value of another type, or an extensions area
that is not exactly one CBOR map with distinct text-string keys and nothing after it, counts as absent.
That rule applies to the keys of the extensions map itself: a map nested in another entry, whatever its
keys, does not hide the launch values.

Apple's own attestation sample carries category 1 and bundle version `"1"`, and the library reports both.
No genuine assertion sample with these values exists, so the assertion side is tested only with
assertions the test builders sign, and with Apple's iOS 14 assertions, which carry none. Before you
enforce a policy in production, check what your own users' devices send: verify without a policy for a
while and look at `$validationCategory` and `$bundleVersion` on `AttestedKey` and `VerifiedAssertion`. `version_compare()`, as in the
example, treats `"1"` as lower than `"1.0"`, so compare versions the way your app numbers them.

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

* `Format` — the document is longer than 16384 bytes (Apple's are about 6 KB) or not a well-formed
  `apple-appattest` object, `authData` is too short or its credential public key is not one CBOR map, or
  the credential certificate does not hold an uncompressed P-256 key. The document must be one CBOR map with nothing after it, the keys of every map
  in it distinct text strings, `x5c` an array, `fmt` a text string, and `x5c`'s entries, `receipt` and
  `authData` byte strings.
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
* `ValidationCategory` — only with a `LaunchPolicy` that lists categories: the validation category in
  `authData` is absent, has no `ValidationCategory` case, or is not listed.
* `BundleVersion` — only with a `LaunchPolicy` that checks the bundle version: the bundle version in
  `authData` is absent or refused by the policy's closure.

### Assertion Failure Reasons

`Oire\AppAttest\Exception\AssertionFailureReason`:

* `Format` — the document is longer than 4096 bytes (Apple's are about 140) or not an object with a
  `signature` and at least 37 bytes of `authenticatorData`. It must be one CBOR map with nothing after it,
  the keys of every map in it distinct text strings and both members byte strings.
* `Signature` — the signature does not verify with the public key over this client data.
* `RpIdHash` — the assertion was made for another team or bundle.
* `Counter` — the counter did not grow: a replayed or reordered assertion.
* `ValidationCategory` and `BundleVersion` — only with a `LaunchPolicy`, as for attestations, about the
  values in `authenticatorData`.

### Caller Errors

A mistake in what your code passes is an `InvalidArgumentException`, never an `AppAttestException`, so it
cannot be mistaken for a forged request:

* a `TeamId` that is not exactly 10 uppercase letters and digits;
* a `BundleId` that is empty or holds anything but ASCII letters, digits, hyphens and periods;
* a `$publicKeyPem` that is not one uncompressed P-256 `PUBLIC KEY` PEM block;
* a `$previousCounter` outside 0 to 2^32 − 1;
* an `$allowed` that is empty or holds anything but `Environment` cases, such as the strings
  `'production'` or `'development'`;
* a `LaunchPolicy` category list holding anything but `ValidationCategory` cases, and
  `LaunchPolicy::allowing()` called with no category;
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
  previous counter; both verify, and only one may pass. Store the new counter, `$result->counter`, with a
  compare-and-set and refuse the request if no row changed:

  ```sql
  UPDATE app_attest_keys
  SET counter = :newCounter
  WHERE key_id = :keyId AND counter = :previousCounter
  ```

* **Decide which environments to accept,** and pass them as `$allowed`.
* **Decide whether to enforce the launch values,** and pass a `LaunchPolicy` if you do (see Launch Category
  and Bundle Version).

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

Like Apple's, a test chain must use EC keys, sign with ECDSA over SHA-256, SHA-384 or SHA-512, and give its
root and intermediate the `keyCertSign` key usage.

## Using phpseclib Elsewhere in Your Application

The library needs phpseclib 4. phpseclib 3 and 4 are the same Composer package, so your application can
use only phpseclib 4 alongside it.

`AttestationVerifier` changes no process-wide phpseclib setting. phpseclib's `X509` class keeps its CA
store, validation date, CRL and URL-fetch callbacks and extension maps in static properties, shared by every
`X509` object in the process, so the library checks the chain without them: it loads each certificate as
DER, verifies each issuer's ECDSA signature itself, and never calls `X509::validateSignature()`. It
neither reads nor adds to the store filled by `X509::addCA()`, and never reaches phpseclib's download of
issuer certificates from `authorityInfoAccess` URLs, which resolves the host name before it asks the
callback set with `X509::setURLFetchCallback()`. It decodes the App Attest nonce extension itself and
registers no ASN.1 map.

Two process-wide settings of yours still matter:

* Do not register a map for the nonce extension, OID `1.2.840.113635.100.8.2`, with
  `X509::registerExtension()`. phpseclib would decode the extension of every credential certificate with
  it, so if another map is registered, `verify()` throws a `LogicException` that names the conflict instead
  of verifying.
* `X509::ignoreKeyUsage()` and `X509::looseDNComparison()` relax phpseclib's matching of a certificate to
  its issuer, which the library uses. The issuer's signature is still checked, so neither lets a forged
  chain through.

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

$result = (new AssertionVerifier())->verify($assertion, $clientData, $publicKeyPem, $previousCounter, $app); // $result->counter is 1
```

A signature over the bare `authenticatorData` followed by the SHA-256 of `clientData`, without hashing
them into the nonce first, is refused with `Signature`. To test a `LaunchPolicy`, append a CBOR map such as
`{"validationCategory": 4, "bundleVersion": "2.1"}` to the 37 bytes of `authenticatorData` before forming
the nonce. The `CBOR` classes come from `spomky-labs/cbor-php`, which this library already requires.

Attestations are harder to make, because they need a certificate chain with the nonce extension. This
repository's test-only
[AttestationBuilder](https://github.com/Oire/app-attest/blob/master/tests/Support/AttestationBuilder.php)
shows how to sign one with phpseclib and verify it against `TrustAnchor::fromPem()` of its own root. The
test code is not part of the Composer package.

## API Reference

`Oire\AppAttest`:

* `AttestationVerifier::__construct(?TrustAnchor $root = null, ?ClockInterface $clock = null)`
* `AttestationVerifier::verify(string $attestationCbor, string $clientDataHash, string $keyId, AppIdentity $app, array $allowed, ?LaunchPolicy $launchPolicy = null): AttestedKey`,
  where `$allowed` is a non-empty list of `Environment` cases
* `AssertionVerifier::verify(string $assertionCbor, string $clientData, string $publicKeyPem, int $previousCounter, AppIdentity $app, ?LaunchPolicy $launchPolicy = null): VerifiedAssertion`
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
* `AttestedKey::__construct(string $keyId, string $publicKeyPem, Environment $environment, string $receipt, ?int $validationCategory = null, ?string $bundleVersion = null)`,
  described under Registering a Key
* `VerifiedAssertion::__construct(int $counter, ?int $validationCategory = null, ?string $bundleVersion = null)`,
  described under Verifying a Request
* `ValidationCategory`, an int-backed enum: `Platform` (1), `TestFlight` (2), `Development` (3),
  `AppStore` (4), `Enterprise` (5), `DeveloperId` (6) and `None` (10), with
  `ValidationCategory::tryFromRaw(?int $value): ?ValidationCategory`
* `LaunchPolicy::__construct(array $validationCategories = [], ?Closure $acceptsBundleVersion = null)`, with
  `public readonly array $validationCategories` (a list of `ValidationCategory` cases),
  `public readonly ?Closure $acceptsBundleVersion`, `LaunchPolicy::allowing(ValidationCategory ...$categories): LaunchPolicy`,
  `withBundleVersion(Closure $accepts): LaunchPolicy`, `allowsValidationCategory(?int $category): bool` and
  `acceptsBundleVersion(?string $bundleVersion): bool`, described under Launch Category and Bundle Version

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
