# CLAUDE.md - Oire App Attest

## Project Overview

`oire/app-attest` verifies Apple App Attest attestations and assertions in PHP, following Apple's
"Validating apps that connect to your server". It verifies and nothing else: no state, no key storage, no
challenges, no network, no logging. Namespace `Oire\AppAttest\` (PSR-4 mapped to `src/`); tests
`Oire\AppAttest\Tests\`. Apache-2.0. The implementation plan is `docs/plans/001-app-attest-library.md`.

## Quick Reference

```bash
composer install
composer test    # phpunit
composer lint    # php-cs-fixer fix --dry-run --diff, then psalm --no-cache
```

Without a local PHP: `docker compose run --rm php composer test` and
`docker compose run --rm php composer lint` (PHP 8.5 CLI with gmp). Check PHP 8.3 too, for example in a
`php:8.3-cli` container with gmp installed. Always run both commands before committing.

Psalm is pinned to `dev-master` and `config.platform.php` is 8.3.16, so CI and contributors run
`composer install` from the lock, never `composer update`; Dependabot keeps the lock current.

## Project Structure

```text
src/
  AttestationVerifier.php   # Apple's attestation steps, returns AttestedKey
  AssertionVerifier.php     # Apple's assertion steps 1-5, returns the new counter
  TrustAnchor.php           # Bundled Apple root, pinned SHA-256 checked on every load; fromPem() for tests
  SystemClock.php           # Default PSR-20 clock
  Value/                    # TeamId, BundleId, AppIdentity, Environment, AttestedKey
  Exception/                # AppAttestException (abstract), Attestation/AssertionException + reason enums
  Internal/                 # @internal: Cbor, AuthenticatorData, CertificateChain, EcPoint, NonceExtension, ErrorGuard
resources/
  Apple_App_Attestation_Root_CA.pem   # Read at run time, so never export-ignored
tests/
  *Test.php                 # Verifier, value, exception and trust anchor tests; Internal/ is tested through the verifiers
  Fixtures.php              # Loads golden vectors and their sidecars, with a MockClock at the vector's time
  Support/                  # Test-only AttestationBuilder, AssertionBuilder and helpers; never shipped
  fixtures/                 # Genuine vectors, byte-for-byte source copies, licenses, README with origins
```

## Conventions

- PHP 8.3+, extensions gmp, mbstring, openssl, sodium. `declare(strict_types=1);` everywhere.
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
  id) are `InvalidArgumentException`, never an `AppAttestException`.
- LF line endings, American English, a final newline in every file, no whitespace on blank lines.

## Testing

- Genuine vectors are used **only unchanged**. Every `authData` field is bound into the signed nonce and
  the nonce sits in a signed certificate, so an edited vector fails at the nonce or the chain, not at the
  check under test. Reach failures through the verifiers' inputs or through the builders in
  `tests/Support/`.
- PHPUnit fails on warnings and notices: malformed input must raise a typed failure, never a PHP warning.

## Things That Were Wrong Once

- An assertion's signature is ECDSA P-256 with SHA-256 over the **nonce**
  SHA-256(`authenticatorData` ‖ SHA-256(`clientData`)), not over the bare concatenation.
- The key id is the SHA-256 of the raw 65-byte uncompressed EC point from the SubjectPublicKeyInfo, never of
  `openssl_pkey_get_details()`'s `x`/`y`, which drop leading zero bytes.
- `clientDataHash` may be any length (Apple's guide sample uses a raw 24-byte challenge), and attestation
  `authData` may carry bytes after the credential public key.
- phpseclib does not check an intermediate's `basicConstraints` `cA` flag (`CertificateChain` does), fetches
  `caIssuers` URLs unless `X509::disableURLFetch()` is called, warns on malformed DER (hence
  `ErrorGuard`), and keeps extension maps globally (hence one shared `Internal\NonceExtension`).
- The CBOR decoder keeps only strings, lists and maps, so an integer or a tag where a byte string belongs
  is `Format`.
- Only a single uncompressed P-256 `PUBLIC KEY` PEM is accepted by `AssertionVerifier`, decoded by the
  library itself, so OpenSSL never reads a file path.
- Before a release, re-fetch Apple's root and compare its fingerprint with `TrustAnchor::APPLE_ROOT_SHA256`.
