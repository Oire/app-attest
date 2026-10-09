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
                            # CertificateChain, Certificate, Der, DerElement, EcPoint, NonceExtension, Pem,
                            # ErrorGuard
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
- phpseclib 4 only (namespace `phpseclib4\`); phpseclib 3 is not supported. `src/` calls no phpseclib code:
  the test builders do.
- **No process-wide state decides a result.** Certificates are read with `Internal\Der`, `DerElement` and
  `Certificate`, the library's own strict DER reader, never with phpseclib's `ASN1`/`X509`, whose settings
  are static and shared by the whole process. Do not bring phpseclib back into `src/`, and do not fix such a
  dependency by saving a setting and restoring it in `finally`.
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
- Malformed certificates are made with `AttestationBuilder::withIntermediateTbsCertificate()` and
  `withCredentialTbsCertificate()`, which edit the `tbsCertificate` (helpers in `SignedCertificate`:
  `withFields()`, `withExtensions()`, `withExtensionValue()`) and sign it again, so only the structure under
  test can fail.
- `testNoProcessWideSettingChangesAnOutcome` flips each process-wide phpseclib setting and checks that every
  case (built and genuine chains, malformed and forged ones, `TrustAnchor::fromPem()`) ends as without it.
  A new case or a new phpseclib setting goes there.
- Builders sign with phpseclib 4 (`PrivateKey::sign(X509)`) and write DER with `toString(['binary' => true])`:
  the default output, PEM, is a process-wide setting. Issuers need a key usage with `keyCertSign`, an
  `authorityKeyIdentifier`, when present, must equal the issuer's `subjectKeyIdentifier`, and a certificate's
  issuer Name must be the bytes of its issuer's subject Name. phpseclib writes an RSA subject key as
  RSASSA-PSS unless the key has PKCS #1 padding, and keeps one extension per OID, so
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
  URL-fetch callback, and does not check an issuer's `basicConstraints` `cA` flag; `X509::isIssuerOf()` reads
  `X509::ignoreKeyUsage()`, `X509::looseDNComparison()` and `X509::ignoreBasicConstraints()`. Under
  `ASN1::enableBlobsOnBadDecodes()` phpseclib's mapper turns a malformed element into a blob or drops what
  follows it instead of throwing: a `basicConstraints` with `cA` true and an extra element passed for a CA,
  an unmappable extension was skipped, an unknown field before the extensions dropped them. Even without it
  the mapper accepted a field after the extensions, UTCTime without seconds and BER lengths. After three
  such findings the library stopped calling phpseclib in `src/`. `Internal\Certificate::tryParse()` reads
  each certificate with `Internal\Der` and refuses anything that is not DER where it reads: indefinite or
  longer than needed lengths, high tag numbers, bytes after an element, booleans other than `0x00`/`0xFF`,
  integers and OIDs not in their shortest form, bit strings with set unused bits, times other than RFC 5280's
  (UTC, seconds, no fraction; UTCTime years 50 to 99 are 19xx), fields out of order or after the extensions,
  an empty extension list, an Extension of other than two or three fields.
- The chain is checked signature first: each issuer's ECDSA signature with `openssl_verify()` over the
  original `tbsCertificate` bytes, the signature BIT STRING declaring no unused bits, the outer
  `signatureAlgorithm` equal byte for byte to the signed one and ecdsa-with-SHA256/384/512 without
  parameters, and the issuer's key EC (OpenSSL reports Edwards keys as another type). Then the validity
  periods, each issuer and the intermediate's `cA` flag. Extensions are matched by the OID's encoded bytes.
  The issuer Name must equal the issuer's subject Name byte for byte (the encoding RFC 5280 requires a CA to
  reuse; Apple's chain does); the issuer needs exactly one key usage, a DER KeyUsage (trailing zero bits
  removed, nothing past `decipherOnly`) with `keyCertSign`; an `authorityKeyIdentifier` must name the
  issuer's `subjectKeyIdentifier` when the issuer has one and its serial number when it holds one, as
  `isIssuerOf()` did; the intermediate needs exactly one `basicConstraints`, `SEQUENCE { TRUE, [INTEGER
  >= 0] }`. A key usage, key identifier or `basicConstraints` extension twice fails. `TrustAnchor::fromPem()`
  refuses a root that `Certificate::tryParse()` refuses, without `keyCertSign`, or without an EC key: no
  chain could lead to such a root.
- The nonce extension is decoded by `Internal\NonceExtension` with the same reader, exactly
  `SEQUENCE { [1] { OCTET STRING } }`; no map is registered with phpseclib, so a map the process registered
  for its OID changes nothing. Do not bring back a guard that reads the registered maps. A credential
  certificate with the nonce extension twice fails the nonce.
- Audit of phpseclib 4's process-wide settings (static properties with public setters): `ASN1`
  `blobsOnBadDecodes`, `recursionDepth` (a depth of 3 or less made the old `TrustAnchor::fromPem()` refuse a
  valid root), `oids`/`reverseOIDs` (`loadOIDs()`), `invalidateCache`, `useEncodedCache`,
  `use64BitOIDHandling`; `X509` CA store, target date, CRL and URL callbacks, `recur_limit`, extension maps,
  `checkKeyUsage`, `strictDNComparison`, `checkBasicConstraints`, `binary`; `CSR`/`CRL`/`SPKAC`/`PFX`
  output settings; `PKCS::$format`, `AsymmetricKey` plugins, config path and `forceEngine()` per key class,
  EC curve settings, RSA blinding and salt settings, `BigInteger::setEngine()`. None is on a code path
  of `src/` any more, so none changes a result. `testNoProcessWideSettingChangesAnOutcome` flips 17 of them;
  the CRL and URL callbacks have tests of their own. cbor-php keeps no static state.
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
