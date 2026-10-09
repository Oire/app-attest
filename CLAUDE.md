# CLAUDE.md - Oire App Attest

## Project Overview

`oire/app-attest` verifies Apple App Attest attestations and assertions in PHP, following Apple's
"Validating apps that connect to your server". It verifies and nothing else: no state, no key storage, no
challenges, no network, no logging. Namespace `Oire\AppAttest\` (PSR-4 mapped to `src/`); tests
`Oire\AppAttest\Tests\`. Apache-2.0. The implementation plan is `docs/plans/completed/001-app-attest-library.md`.

## Quick Reference

```bash
composer install
composer test    # phpunit
composer lint    # php-cs-fixer fix --dry-run --diff, then psalm --no-cache
```

Without a local PHP: `docker compose run --rm php composer test` and
`docker compose run --rm php composer lint` (PHP 8.5 CLI with gmp). Check PHP 8.3 too: the Dockerfile
takes a `PHP_VERSION` build argument, and the stock `php:8.3-cli` image has neither gmp nor Composer.

```bash
docker build --build-arg PHP_VERSION=8.3 -t app-attest-php83 .
docker run --rm -v "$PWD":/app app-attest-php83 composer test
docker run --rm -v "$PWD":/app app-attest-php83 composer lint
```

Always run both commands on both versions before committing. If the local PHP lacks gmp, use Docker.
Never regenerate the lock with `--ignore-platform-req` beyond `ext-gmp`.

Psalm is pinned to `dev-master` and `config.platform.php` is 8.3.16, so CI and contributors run
`composer install` from the lock, never `composer update`; Dependabot keeps the lock current.

## Project Structure

```text
src/
  AttestationVerifier.php   # Apple's attestation steps, returns AttestedKey
  AssertionVerifier.php     # Apple's assertion steps 1-5 (7-8 with a LaunchPolicy), returns a VerifiedAssertion
  TrustAnchor.php           # Bundled Apple root, pinned SHA-256 checked on every load; fromPem() for tests
  SystemClock.php           # Default PSR-20 clock
  Value/                    # TeamId, BundleId, AppIdentity, Environment, AttestedKey, VerifiedAssertion, ValidationCategory, LaunchPolicy
  Exception/                # AppAttestException (abstract), Attestation/AssertionException + reason enums
  Internal/                 # @internal: Cbor, CborStream, CborText, CborMap, AuthenticatorData, Extensions,
                            # CertificateChain, Der, EcPoint, NonceExtension, Pem, ErrorGuard
resources/
  Apple_App_Attestation_Root_CA.pem   # Read at run time, so never export-ignored
tests/
  *Test.php                 # Verifier, value, exception and trust anchor tests; Internal/ is tested through the verifiers
  Internal/                 # ErrorGuardTest: the one internal class whose contract is tested directly
  Fixtures.php              # Loads golden vectors and their sidecars, with a MockClock at the vector's time
  Support/                  # Test-only AttestationBuilder, AssertionBuilder and helpers; never shipped
  fixtures/                 # Genuine vectors, byte-for-byte source copies, licenses, README with origins
```

## Conventions

- PHP 8.3+, extensions gmp, mbstring, openssl, sodium. `declare(strict_types=1);` everywhere.
- phpseclib 4 only (namespace `phpseclib4\`); phpseclib 3 is not supported.
- Final classes (abstract exception base excepted), readonly value objects. Public API classes carry
  `@psalm-api`, implementation details live in `Internal/` and are `@internal`.
- **Verification only.** No state, no I/O: no network, no filesystem except reading the bundled root, no
  logging. Storage, challenges, the `clientData` check and the counter race belong to the caller.
- **8-bit binary handling.** Bytes are sliced and measured with `mb_substr`/`mb_strlen` and the `'8bit'`
  encoding, or read with `unpack()` (`'N'`, `'n'`): the code style's risky `mb_str_functions` rule rewrites
  `substr`/`strlen` into `mb_*` calls without an encoding, which under UTF-8 corrupts byte offsets.
- Hashes and ids are compared with `hash_equals`, never `===`.
- **`openssl_verify` succeeds only when it returns `=== 1`**: it returns `1`, `0`, `-1` or `false`, and
  `-1` is truthy.
- **Imports.** Every class, global ones included, is imported with `use` and written unqualified
  (`use InvalidArgumentException;`). Native functions are called unqualified: no `use function`, no
  leading backslash.
- **Base64url** wherever the library or its documentation encodes bytes as text (sidecars,
  `AttestedKey::keyIdBase64Url()`, README examples), unpadded, through `ext-sodium`. The verifiers take raw
  bytes.
- Failures are exceptions with a typed `$reason`, never `false` or a bare message. Messages name the check
  and never echo key material. Caller errors (bad PEM, counter outside 0..2^32−1, invalid team or bundle
  id, an `$allowed` that is empty or holds anything but `Environment` cases, a `LaunchPolicy` category that
  is not a `ValidationCategory`, `LaunchPolicy::allowing()` with no category, a `TrustAnchor::fromPem()`
  argument that is not one certificate or cannot anchor a chain) are `InvalidArgumentException`, never an
  `AppAttestException`.
- Psalm dev-master's purity model reports `MissingPureAnnotation` and `MissingImmutableAnnotation`.
  Annotate as the issue suggests (`@psalm-pure`, `@psalm-immutable`, or `@psalm-capabilities read-props`
  on methods and promoted constructors that read properties) and never suppress it.
- LF line endings, American English, a final newline in every file, no whitespace on blank lines.

## Testing

- Genuine vectors are used **only unchanged**. Every `authData` field is bound into the signed nonce and
  the nonce sits in a signed certificate, so an edited vector fails at the nonce or the chain, not at the
  check under test. Reach failures through the verifiers' inputs or through the builders in
  `tests/Support/`.
- PHPUnit fails on warnings, notices, deprecations and risky tests: malformed input must raise a typed
  failure, never a PHP warning.
- Builders sign with phpseclib 4 (`PrivateKey::sign(X509)`) and write DER with `toString(['binary' => true])`:
  the default output, PEM, is a process-wide setting. Issuers need a key usage with `keyCertSign`, and an
  `authorityKeyIdentifier`, when present, must equal the issuer's `subjectKeyIdentifier`. phpseclib writes
  an RSA subject key as RSASSA-PSS unless the key has PKCS #1 padding, and keeps one extension per OID, so
  `tests/Support/SignedCertificate` takes certificates apart, edits the `tbsCertificate` and signs it again.
- phpseclib's `X509` and `ASN1` settings are static and PHPUnit runs every test in one process: a test that
  changes one (an extension map, the CA store, the target date, a callback, an OID name) restores it in
  `finally`, through reflection where phpseclib has no setter.
- `phpunit.xml.dist` sets `memory_limit` to 128M, but a test of input built to exhaust memory must not
  rely on it: CI may run with unlimited memory. Assert with `HostileInput::peakMemoryGrowthOf()` that the
  input is refused before it is parsed.

## Things That Were Wrong Once

- An assertion's signature is ECDSA P-256 with SHA-256 over the **nonce**
  SHA-256(`authenticatorData` ‖ SHA-256(`clientData`)), not over the bare concatenation.
- The key id is the SHA-256 of the raw 65-byte uncompressed EC point from the SubjectPublicKeyInfo, never of
  `openssl_pkey_get_details()`'s `x`/`y`, which drop leading zero bytes.
- `clientDataHash` may be any length (Apple's guide sample uses a raw 24-byte challenge), and attestation
  `authData` may carry bytes after the credential public key.
- phpseclib 4's `X509::validateSignature()` trusts the process-wide CA store of `X509::addCA()`, checks a
  process-wide target date, calls the CRL callback, resolves `caIssuers` host names (DNS) before it asks the
  URL-fetch callback, and does not check an issuer's `basicConstraints` `cA` flag. `CertificateChain`
  never calls it. It first maps each certificate without X509's rules,
  `ASN1::map(ASN1::decodeBER($der), Certificate::MAP)`, and checks each issuer's ECDSA signature with
  `openssl_verify()` over the original `tbsCertificate` bytes:
  the certificate must be exactly the DER of its three parts, the signature BIT STRING must declare no
  unused bits, the outer `signatureAlgorithm` must equal the signed one byte for byte and be
  ecdsa-with-SHA256/384/512 without parameters, and the issuer's key must be EC (OpenSSL reports Edwards
  keys as another type). Only then does it call `X509::load($der, ASN1::FORMAT_DER)` for `isIssuerOf()`,
  then checks the validity periods (`validateDate()` is private in 4) and the intermediate's `cA` flag.
  `disableURLFetch()` and `loadCA()` no longer exist; do not bring the CA store back.
- phpseclib 4 decodes lazily: a malformed field throws only when it is read, reading a missing key of a
  `Constructed` creates it and drops the cached encoding, and `X509::load()` runs the SubjectPublicKeyInfo
  through `PublicKeyLoader` (every key format, then X.509 auto-detection) and replaces it with a key
  object. Hence no signature is checked through `X509::getSignableSection()`, which re-encodes the
  certificate once its cache is gone, and nothing untrusted reaches `X509::load()` before its signature
  verifies. The nonce, the SubjectPublicKeyInfo and `basicConstraints` are read from the rule-less map and
  matched by dotted OID, never by phpseclib's names, which `ASN1::loadOIDs()` can change. phpseclib still
  warns on some malformed DER, such as an empty OID (hence `ErrorGuard`), and throws
  `phpseclib4\Exception\*` exceptions.
- phpseclib keeps extension maps process-wide, `registerExtension()` refuses an OID registered before, even
  with the same map, and a registered map that fails on a value throws out of `getExtension()`. So the
  library registers no map for the nonce extension; `Internal\NonceExtension` decodes it, and any map
  registered for its OID, or for a name `ASN1::loadOIDs()` gave it, is a `LogicException`. A credential
  certificate with the nonce extension twice fails the nonce.
- `X509::isIssuerOf()` on a certificate from `X509::load()` (not `addCA()`) requires the issuer to carry a
  key usage extension with `keyCertSign`, so `TrustAnchor::fromPem()` refuses a root without it, or without
  an EC key: no chain could lead to such a root. phpseclib's own `basicConstraints` check there compares an
  array with a string and never runs, hence `CertificateChain`'s `cA` check.
- `ErrorGuard` throws only for warnings and notices; deprecations and `@`-silenced warnings go on to the
  previous handler. It must not obey a lowered `error_reporting()`: PHPUnit lowers it for every test while
  its own handler still reports warnings, so such a guard would be off in the whole suite.
- The CBOR decoder keeps only strings, unsigned integers, lists and maps, so an integer or a tag where a
  byte string belongs is `Format`. Byte strings decode to strings and text strings to `Internal\CborText`,
  so neither passes for the other; maps decode to `Internal\CborMap`, never to PHP arrays, so a map keyed
  `"0"`, `"1"` cannot pass for a list. A key that is not a text string, a key twice, or bytes after the
  top-level map make it refuse the whole document. Only the extensions area is decoded with
  `lenientNestedMaps`, where such a nested map becomes null instead, so an unrelated entry cannot hide the
  launch values.
- cbor-php builds an object for every item, about 220 bytes of memory per input byte, so an unbounded
  document stops PHP with an uncatchable out-of-memory error. Both verifiers refuse a document over their
  `MAX_LENGTH` (16384 bytes for an attestation, 4096 for an assertion) before decoding it.
- `apple_validation_category_01` and `apple_bundle_version_01` (`validationCategory` and `bundleVersion` in
  assertions) are entries of the `extensions` CBOR map in the authenticator data, after the COSE key, not
  certificate extensions. Only Apple's guide sample carries them (the category as four little-endian
  bytes), so both verifiers always report them (`AttestedKey`, `VerifiedAssertion`) and enforce them only
  with a `LaunchPolicy`; a missing or malformed extensions area is never a failure without one.
  `Cbor::tryMapLength()` skips the COSE key, which must be one CBOR map or the attestation is `Format`
  (it is not matched against the certificate's key: the nonce already binds `authData` to Apple's
  signature); `Cbor::tryDecodeMap()` reads the area after it, strict about the top-level keys and lenient
  about nested maps.
- Only a single uncompressed P-256 `PUBLIC KEY` PEM is accepted by `AssertionVerifier`, decoded by the
  library itself, so OpenSSL never reads a file path.
- Before a release, re-fetch Apple's root and compare its fingerprint with `TrustAnchor::APPLE_ROOT_SHA256`.

## Releasing

Update `CHANGELOG.md`, re-fetch Apple's root and compare its fingerprint with
`TrustAnchor::APPLE_ROOT_SHA256`, then push a `vX.Y.Z` tag. `release.yml` creates the GitHub Release with
generated notes; it needs the tag to exist on GitHub (`--verify-tag`). Packagist updates through its
GitHub webhook, not through the workflow.
