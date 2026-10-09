# App Attest verification library for PHP

## Overview

Apple's App Attest lets a server confirm that a request comes from a genuine copy of its iOS app on a
genuine Apple device: the app attests a key once (an **attestation**, a CBOR document with a certificate
chain to Apple's App Attest root) and later signs requests with it (an **assertion**). Verifying both
takes a dozen precise checks, and there is **no maintained PHP library** for it — only references in
other languages: `veehaitch/devicecheck-appattest` (Kotlin) and `takimoto3/app-attest` (Go).

This plan builds one: **`oire/app-attest`**, namespace `Oire\AppAttest`, Apache-2.0, published on Packagist,
following Oire's PHP conventions (`oire/iridium` is the model, with the deviations Task 1 states). Its
first client is AccessMind, which needs the first stable release.

The library **verifies and nothing else**: it keeps no state, stores no keys, issues no challenges and
makes no network call. Storage, challenge issuance, the `clientData` check and the counter race belong
to the caller, who passes the stored public key and counter in and stores the new counter.

## Done when

- [ ] `AttestationVerifier::verify` accepts every genuine attestation in the golden vectors and rejects
      each documented failure with its own `$reason`: `CertificateChain`, `Nonce`, `KeyId`, `RpIdHash`,
      `Counter`, `Environment`, `Format` — each failure reached through the verifier's inputs or through
      the test-only `AttestationBuilder` (Task 3), never by editing a signed vector
- [ ] `AssertionVerifier::verify` accepts every genuine assertion, returns the new counter, and rejects
      a bad signature, a wrong `rpIdHash`, a counter not above the previous one and a malformed document,
      each with its own `$reason`
- [x] the pinned Apple App Attest root's SHA-256 fingerprint is checked when the root is loaded and
      asserted by a test, so a swapped file fails loudly
- [ ] time-dependent checks use an injected PSR-20 clock, so the golden vectors verify at their own
      time
- [ ] all binary handling is 8-bit-safe under Oire's code style (Development approach)
- [ ] Psalm level 1, PHP CS Fixer with Oire's rules and PHPUnit pass in CI on PHP 8.3, 8.4 and 8.5
- [ ] Dependabot watches Composer and GitHub Actions; pushing a `v*` tag creates the GitHub Release
- [ ] README documents installation, both verifiers, the reasons, and what the caller must do itself
- [ ] `v1.0.0` is tagged, the package is on Packagist, and the repository's description and topics are
      set
- [ ] all validation commands pass

## Validation commands

- install: `composer install`
- test: `composer test` (`phpunit`)
- lint and static analysis: `composer lint` (`php-cs-fixer fix --dry-run --diff`, then `psalm --no-cache`)
- CI: `.github/workflows/ci.yml`, green on PHP 8.3, 8.4 and 8.5

The repository's `compose.yaml` gives a PHP 8.5 CLI container for machines without a local PHP:
`docker compose run --rm php composer test`.

## Context

- **Model repository:** `C:/repos/Oire/iridium-php` — `composer.json` (`"php": ">=8.3"`, `ext-mbstring`,
  the `oire/php-code-style` VCS repository, `authors`, `support` and `funding`; it has **no** `scripts`
  section, so this plan writes its own), `psalm.xml.dist` (`errorLevel="1"`, unused-code checks, the
  PHPUnit plugin), `phpunit.xml.dist`, `CHANGELOG.md`, `CLAUDE.md`, the Apache-2.0 `LICENSE`, the
  `export-ignore` rules in `.gitattributes`, `.github/dependabot.yml` and `.github/release.yml`, and the
  layout of `src/` into `Exception/`, `Key/` and `Storage/` with an `IridiumException` base. Its CI is
  three workflows running through `docker compose` with a `PHP_VERSION` build argument, and its
  Dockerfile is FrankenPHP with MariaDB; this library needs neither a server nor a database, so it
  deliberately uses **one** `ci.yml` with `shivammathur/setup-php` and a matrix, and a plain
  `php:8.5-cli` Dockerfile (plan review, 2026-10-08). One iridium lesson is kept: Psalm is pinned to
  `dev-master`, so CI runs `composer install` from the lock, never `composer update`.
- **Supported PHP versions** (php.net/supported-versions, checked 2026-10-09): 8.3 is security-only
  until 2027-12-31, 8.4 until 2028-12-31, 8.5 is active. None is past end of life, so all three stay;
  8.2 (end of life 2026-12-31) is not supported.
- **Code style:** `oire/php-code-style` (not on Packagist, pulled as a VCS repository). The repository's
  `.php-cs-fixer.dist.php` only builds the finder and returns `Oire\Helpers\CsFixerRules::style($finder)`;
  every rule lives in the package. It enables `setRiskyAllowed(true)` and the risky **`mb_str_functions`**
  rule, which rewrites `substr`/`strlen` into `mb_substr`/`mb_strlen` with no encoding argument — under
  the default UTF-8 that corrupts byte offsets in `authenticatorData`. Iridium copes by requiring
  `ext-mbstring` and always passing `'8bit'` (`Crypt::STRING_ENCODING_8BIT`); so does this library. It
  also enables `global_namespace_import` and `fully_qualified_strict_types`, which back the import rule
  in Development approach.
- **References to port from**, with their test data as golden vectors:
  `veehaitch/devicecheck-appattest` (Kotlin, Apache-2.0) and `takimoto3/app-attest` (Go, MIT). Port the
  checks, not the code structure. Record each vector's origin (repository, commit, path) in
  `tests/fixtures/README.md`, and copy the Apache-2.0 license text and any `NOTICE` file beside the
  vectors taken from veehaitch, and the MIT license beside takimoto3's.
- **Apple's documentation:** "Validating apps that connect to your server" (the attestation steps
  1-9 and the assertion steps 1-6) is the specification; the references are how to read it.
- **Apple App Attest root:** `Apple_App_Attestation_Root_CA.pem` from
  `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem`.
- **`authenticatorData` layout** (big-endian): `rpIdHash` 32 bytes | flags 1 | signCount 4 | then, in an
  attestation only, `aaguid` 16 | credentialId length 2 | credentialId | the COSE public key. An
  assertion's is exactly 37 bytes. Anything shorter than its layout requires is `Format`.
- **The nonce extension** (OID `1.2.840.113635.100.8.2`) holds DER `SEQUENCE { [1] EXPLICIT OCTET STRING
  (32 bytes) }`, not a bare octet string, and phpseclib does not know the OID.
- **Apple identifiers:** a team id is 10 uppercase letters and digits; a bundle id is non-empty and
  holds only `A-Z`, `a-z`, `0-9`, `-` and `.`.
- The repository is new: it holds nothing yet but this plan. Its GitHub description is a placeholder
  ("PHP library for managing Apple App Attest.") and it has no topics.

Dependencies (Composer; versions pinned to majors):

- `spomky-labs/cbor-php` `^3.4` — CBOR decoding and, in tests, encoding. It requires `ext-mbstring` and
  `brick/math` and only *suggests* `ext-gmp`; this library **requires** `ext-gmp` anyway, because
  cbor-php's own suggestion says decoding untrusted input without it is quadratic in a big number's
  length, and every attestation is untrusted input.
- `phpseclib/phpseclib` `^3.0` — X.509 parsing, chain validation against an in-memory CA with an
  injected validation date, the nonce extension (registered with `X509::registerExtension` and an ASN.1
  map, or decoded with `ASN1::decodeBER`), and, in tests, certificate signing. Considered and rejected:
  `openssl_x509_verify` + `openssl_x509_parse` + a hand-written DER reader, which drops a dependency but
  cannot validate at a past date (the golden vectors' certificates have expired) and puts DER parsing in
  this library.
- `psr/clock` `^1.0` — the clock interface; the library ships a small `SystemClock` used when none is
  passed. `symfony/clock` is **not** a runtime dependency, so consumers outside Symfony do not pull it
  in; any PSR-20 clock, Symfony's included, can be passed.
- `ext-openssl` — ECDSA P-256 verification and key export. `ext-mbstring`, `ext-gmp`. `ext-sodium` —
  base64url (`sodium_bin2base64` / `sodium_base642bin` with `SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING`);
  `oire/iridium`'s `Base64` was considered and rejected, because it would bring `ext-pdo` and a token
  storage layer this library never uses.
- Dev: `phpunit/phpunit`, `vimeo/psalm` with `psalm/plugin-phpunit`, `friendsofphp/php-cs-fixer`,
  `oire/php-code-style`, `symfony/clock` `^7.4 || ^8.0` (its `MockClock` pins the vectors' times; the
  8.3 platform resolves 7.4).

## Development approach

- One task at a time; the validation commands pass before the next task starts.
- Every check comes with a test for its success and failure path. Failures are reached through the
  verifier's **inputs** (a different `clientDataHash`, key id, `AppIdentity`, environment list, clock or
  trust anchor) or through attestations the test-only `AttestationBuilder` signs itself (Task 3) —
  **never by editing a genuine vector**: every field of `authenticatorData` is bound into the signed
  nonce, and the nonce sits inside a signed certificate, so an edited vector fails at the nonce or the
  chain, not at the check under test (plan review, 2026-10-08).
- Failures are exceptions carrying a typed `$reason`, never `false` and never a bare message, so a
  caller maps them without parsing text. Messages name the check, never echo key material. A caller
  error — an unparsable `$publicKeyPem`, a `$previousCounter` outside 0..2^32−1, an invalid team or
  bundle id — is an `InvalidArgumentException`, never a verification failure.
- **Binary safety:** bytes are sliced with `mb_substr(…, '8bit')`, measured with `mb_strlen(…, '8bit')`,
  or read with `unpack()` (`'N'` and `'n'` for the big-endian counter and length); hashes and ids are
  compared with `hash_equals`. A plain `substr` would be rewritten by the code style.
- **Base64url wherever the library or its documentation encodes bytes as text** — fixture sidecars,
  `AttestedKey::keyIdBase64Url()`, README examples of what a client sends — always without padding,
  through `ext-sodium`. The verifiers themselves take raw bytes (Public API).
- `openssl_verify` counts as success **only when it returns `=== 1`**: it returns `1`, `0`, `-1` or
  `false`, and `-1` is truthy.
- **Imports:** every class, global ones included, is imported with `use` and written unqualified
  (`use DateTimeImmutable;`, `use InvalidArgumentException;`), never as `\DateTimeImmutable`. Native
  functions are called unqualified: never `use function`, never a leading backslash.
- No I/O: no network, no filesystem except reading the bundled root certificate, no logging.
- `declare(strict_types=1)` everywhere; final classes (the abstract exception base excepted); readonly
  value objects.
- LF everywhere, American English.
- When scope changes, update this plan: new tasks get a "➕" prefix, blockers a "⚠️" prefix.

## Implementation steps

### Task 1: Repository scaffold and CI

#### Files
- Create: `composer.json`, `composer.lock`, `CHANGELOG.md`, `CLAUDE.md` (stub)
- Modify: `README.md` (GitHub's stub). `LICENSE` already exists: the repository was created on
  2026-10-08 as public with **Apache-2.0** (maintainer's choice, as in `oire/iridium`), which also
  matches the Apache-2.0 `veehaitch/devicecheck-appattest` whose vectors the tests copy; keep it as is
- Create: `phpunit.xml.dist`, `psalm.xml.dist`, `.php-cs-fixer.dist.php`
- Create: `Dockerfile` (`php:8.5-cli` plus `install-php-extensions gmp`; no database), `compose.yaml`
- Create: `.gitignore`, `.gitattributes`, `.editorconfig`
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`,
  `.github/release.yml`
- Create: `src/SystemClock.php` (so `src/` is not empty for Psalm and the autoloader),
  `tests/SmokeTest.php`

#### Steps
- [x] `composer.json`: name `oire/app-attest`, description, `"license": "Apache-2.0"`, `"php": ">=8.3"`,
      `ext-gmp`, `ext-mbstring`, `ext-openssl`, `ext-sodium`, the dependencies from Context, `authors`,
      `support` (pointing at `Oire/app-attest`) and `funding` as in iridium, PSR-4 `Oire\AppAttest\` →
      `src/` and `Oire\AppAttest\Tests\` → `tests/`, the `oire/php-code-style` VCS repository, scripts
      written out: `"test": "phpunit"` and `"lint": ["php-cs-fixer fix --dry-run --diff", "psalm
      --no-cache"]`, and `"config": {"platform": {"php": "8.3.16"}, "sort-packages": true}` so the
      committed lock resolves for the oldest supported PHP and the 8.3 job can install it (a lock made on
      8.5 with open dev constraints would pull packages that need 8.4); commit `composer.lock`.
      ⚠️ The platform is 8.3.16, not 8.3.0: `vimeo/psalm` `dev-master` requires `~8.3.16` on 8.3,
      so 8.3.0 cannot resolve; CI's 8.3 job gets the latest 8.3 patch release (plan execution, 2026-10-09)
- [x] `.gitattributes`: `* text=auto eol=lf`; `tests/fixtures/** binary`; iridium-style `export-ignore`
      for `tests/`, `docs/`, `.github/`, the Docker and tool config files — and **not** for
      `resources/`, which holds the Apple root `TrustAnchor::apple()` reads at run time
- [x] Psalm, PHPUnit and CS Fixer configured as in `oire/iridium`; the finder covers `src` and `tests`
- [x] `SystemClock` implements `Psr\Clock\ClockInterface` and returns `new DateTimeImmutable()`, with
      `use DateTimeImmutable;` (Development approach, imports)
- [x] CI on `ubuntu-latest`, `permissions: contents: read`, a matrix over PHP 8.3, 8.4 and 8.5
      (`shivammathur/setup-php` with `gmp`, `mbstring` and `sodium`), running `composer install` (never
      `update`), lint and test
- [x] `.github/dependabot.yml` copied from iridium: `composer` and `github-actions`, daily at 04:00
      Europe/Berlin, assigned to `Menelion`. Because CI never runs `composer update`, Dependabot's lock
      updates are what keep the dependencies current
- [x] `.github/release.yml` copied from iridium (release-note categories, Dependabot excluded);
      `.github/workflows/release.yml` runs on `push` of tags `v*` with `permissions: contents: write` and
      creates the release with `gh release create "$GITHUB_REF_NAME" --verify-tag --generate-notes`.
      Packagist is updated by its webhook, not by this workflow (Post-completion)
- [x] a smoke test that autoloads the namespace and reads the time from `SystemClock`
- [x] validation commands pass, CI green (CI: checked on the pull request)

### Task 2: Value types, exceptions and the trust anchor

#### Files
- Create: `src/Value/TeamId.php`, `src/Value/BundleId.php`, `src/Value/AppIdentity.php`,
  `src/Value/Environment.php`, `src/Value/AttestedKey.php`
- Create: `src/Exception/AppAttestException.php`, `src/Exception/AttestationException.php`,
  `src/Exception/AttestationFailureReason.php`, `src/Exception/AssertionException.php`,
  `src/Exception/AssertionFailureReason.php`
- Create: `src/TrustAnchor.php`, `resources/Apple_App_Attestation_Root_CA.pem`
- Create: `tests/TrustAnchorTest.php`, `tests/Value/TeamIdTest.php`, `tests/Value/BundleIdTest.php`,
  `tests/Value/AppIdentityTest.php`, `tests/Value/AttestedKeyTest.php`, `tests/Exception/ExceptionsTest.php`,
  `tests/Value/EnvironmentTest.php`

Layout, iridium-style: the verifiers, `TrustAnchor` and `SystemClock` at the root of `src/`; value
objects in `Value/`; exceptions and their reason enums in `Exception/`; implementation details in
`Internal/` (Task 4).

#### Steps
- [x] `TeamId` (readonly, `public string $value`): exactly 10 characters of `A-Z0-9`, else
      `InvalidArgumentException`
- [x] `BundleId` (readonly, `public string $value`): non-empty, only `A-Za-z0-9`, `-` and `.`, else
      `InvalidArgumentException`
- [x] `AppIdentity(TeamId $teamId, BundleId $bundleId)` with `appId()` = `"<teamId>.<bundleId>"` and
      `rpIdHash()` = SHA-256 of it (raw bytes); with valid parts it cannot be invalid, so it validates
      nothing itself
- [x] `Environment` enum (`production`, `development`) with the `aaguid` each stands for: `appattest`
      followed by seven zero bytes, and `appattestdevelop`; `Environment::tryFromAaguid()` maps an aaguid
      back for Task 4
- [x] `AttestedKey` (readonly): `keyId` (raw 32 bytes), `publicKeyPem`, `environment`, `receipt` (raw
      bytes), `counter` (always 0 from an attestation), and `keyIdBase64Url()` — the key id as unpadded
      base64url, for callers that store or index it as text
- [x] `AppAttestException` is `abstract` and extends `RuntimeException`, so one `catch` covers both
      verifiers; `AttestationException` and `AssertionException` (`final`) extend it and carry
      `public readonly AttestationFailureReason $reason` / `public readonly AssertionFailureReason $reason`
      and a message naming the check. Attestation reasons: `Format`, `CertificateChain`, `Nonce`,
      `KeyId`, `RpIdHash`, `Counter`, `Environment`; assertion reasons: `Format`, `Signature`,
      `RpIdHash`, `Counter` — exactly the cases in the public API below
- [x] `TrustAnchor::apple()` loads the bundled root and **checks its SHA-256 fingerprint against the
      constant on every load**, throwing a `LogicException` on a mismatch; `TrustAnchor::fromPem()` exists
      for the tests' own chains. The constant sits beside the file with a comment saying where it came
      from and when it was fetched. The check itself is the `@internal` `TrustAnchor::fromPinnedPem($pem,
      $sha256)`, which the tamper test calls; PEM is decoded to DER without `openssl_x509_read`, which
      warns on garbage, and `fromPem()` parses with phpseclib in DER mode (plan execution, 2026-10-09)
- [x] Psalm's `findUnusedCode` would flag public API members only consumers use (`AttestedKey::$receipt`,
      `AttestedKey::keyIdBase64Url()`, `TrustAnchor::fromPem`): mark public API classes `@psalm-api`
      rather than inventing test reads
- [x] tests: the bundled root's fingerprint equals the constant; a tampered PEM handed to the loader's
      check fails; `AppIdentity::rpIdHash()` for the neutral `ABCDE12345.com.example.app` equals a
      pinned value; team ids that are short, long, lowercase or contain punctuation and bundle ids that
      are empty or contain a space or `_` are refused; `keyIdBase64Url()` round-trips through
      `sodium_base642bin` and has no padding; each exception carries the reason it was built with and is
      an `AppAttestException`
- [x] validation commands pass

### Task 3: Golden vectors and the test-only builders

#### Files
- Create: `tests/fixtures/attestation/*`, `tests/fixtures/assertion/*`, `tests/fixtures/README.md`,
  `tests/fixtures/LICENSE-*` (the references' licenses, and veehaitch's `NOTICE` if any)
- Create: `tests/Fixtures.php` (loads a vector: bytes, team id, bundle id, key id, challenge or
  `clientDataHash`, the time it is valid at, the expected result)
- Create: `tests/Support/AttestationBuilder.php`, `tests/Support/AssertionBuilder.php`
- Create: `tests/FixturesTest.php`, `tests/Support/BuildersTest.php`

#### Steps
- [ ] collect every **genuine** attestation and assertion vector the two references test with, as files,
      each with a JSON sidecar naming its inputs, how its `clientDataHash` was formed (SHA-256 of a UTF-8
      challenge string, or a raw value — consumers need to know which), its environment, and the time to
      verify it at. Binary values in the sidecars (key id, `clientDataHash`, expected counter bytes) are
      unpadded base64url, converted from whatever the reference used; the vector files themselves stay
      byte-for-byte as the references ship them. Genuine vectors are used **only unchanged**
- [ ] `Fixtures` hands each vector's time to the verifier as a Symfony `MockClock`
- [ ] failure cases that genuine vectors reach through the verifier's inputs are listed, not built
      (Task 4 uses them): `Nonce` — another `clientDataHash`; `KeyId` — another key id; `RpIdHash` —
      another `AppIdentity`; `Environment` — `allowed` without the vector's environment;
      `CertificateChain` — a clock past the leaf's validity, or another `TrustAnchor`; `Format` —
      garbage, a wrong `fmt`, a missing `x5c`, a truncated `authData`
- [ ] `AttestationBuilder` (test code, never shipped) makes what genuine vectors cannot: a root, an
      intermediate CA and a leaf on P-256, signed with phpseclib; the nonce extension on the leaf as DER
      `SEQUENCE { [1] EXPLICIT OCTET STRING }`; `authData` with any `rpIdHash`, counter, `aaguid` and
      `credentialId`; the CBOR document encoded with cbor-php's encoder. Its attestations verify against
      `TrustAnchor::fromPem()` of its own root. It covers the cases no input can trigger: a non-zero
      counter (`Counter`), a `credentialId` differing from the key id (`KeyId`), a **production** `aaguid`
      accepted and refused (the references' vectors may all be development builds — record in the
      sidecars which they are), a chain whose intermediate is not a CA (`CertificateChain`), and a missing
      nonce extension (`Nonce`)
- [ ] `AssertionBuilder` (test code) generates a P-256 key and signs `authenticatorData ‖
      SHA-256(clientData)` for any `rpIdHash`, counter and `clientData`, CBOR-encoding
      `{signature, authenticatorData}` — the same recipe consumers use for their own tests
- [ ] `tests/fixtures/README.md` lists each vector's origin (repository, commit, path) and license
- [ ] tests: every sidecar parses, its base64url fields decode, and it names an existing file; a builder
      attestation verifies with the builder's root (a smoke check of the builders themselves)
- [ ] validation commands pass

### Task 4: `AttestationVerifier`

#### Files
- Create: `src/AttestationVerifier.php`, `src/Internal/Cbor.php`, `src/Internal/AuthenticatorData.php`,
  `src/Internal/CertificateChain.php`, `src/Internal/EcPoint.php`
- Create: `tests/AttestationVerifierTest.php`

#### Steps
- [ ] `verify(attestationCbor, clientDataHash, keyId, app, allowed)` in Apple's order, each failure an
      `AttestationException` with the reason named:
      1. decode CBOR `{fmt: "apple-appattest", attStmt: {x5c, receipt}, authData}` — any decoder
         exception, a wrong `fmt`, a missing member or a short `authData` is `Format`;
      2. `x5c` holds **exactly two** certificates (credential, intermediate); build the chain to the
         trust anchor with phpseclib, each certificate valid at the clock's time, the intermediate a CA
         (phpseclib's `validateSignature()` checks CA status by default — never turn it off) — else
         `CertificateChain`;
      3. nonce = SHA-256(`authData` ‖ `clientDataHash`) must equal (`hash_equals`) the 32-byte octet
         string inside the credential certificate's extension `1.2.840.113635.100.8.2`, read through
         its ASN.1 layout (Context); an absent or malformed extension is `Nonce`;
      4. key id = SHA-256 of the credential certificate's **raw 65-byte uncompressed EC point** — the
         BIT STRING contents of its SubjectPublicKeyInfo (for P-256 the last 65 bytes of the 91-byte DER),
         **not** `openssl_pkey_get_details()`'s `x`/`y`, which drop leading zero bytes and would give a
         wrong id for about one key in 128. Assert 65 bytes, first byte `0x04`, curve `prime256v1` (else
         `Format`); the id must equal `keyId` — else `KeyId`;
      5. `authData`'s `rpIdHash` = `app->rpIdHash()` — else `RpIdHash`;
      6. counter = 0 — else `Counter`;
      7. `aaguid` names an environment in `allowed` — else `Environment`;
      8. `credentialId` = key id — else `KeyId`
- [ ] newer extensions on the credential certificate (`apple_validation_category_01`,
      `apple_bundle_version_01` and any unknown one) are ignored, never required
- [ ] returns `AttestedKey` with the public key as PEM, the environment, the receipt bytes and counter 0
- [ ] tests: every genuine vector accepted with the expected key; each input-triggered failure (Task 3's
      list) and each builder-made failure raises its own reason; production accepted and refused through
      the builder; a garbage document is `Format`, never a PHP warning; a key whose `x` coordinate starts
      with a zero byte (the builder generates keys until one does) gets the right id
- [ ] validation commands pass

### Task 5: `AssertionVerifier`

#### Files
- Create: `src/AssertionVerifier.php`
- Create: `tests/AssertionVerifierTest.php`

#### Steps
- [ ] `verify(assertionCbor, clientData, publicKeyPem, previousCounter, app)`: reject an unparsable PEM or
      a `previousCounter` outside 0..2^32−1 with `InvalidArgumentException`; then, each failure an
      `AssertionException` with the reason named: decode CBOR `{signature, authenticatorData}` (a decoder
      exception, a missing member or an `authenticatorData` shorter than 37 bytes is `Format`); verify
      the ECDSA P-256 signature with
      `openssl_verify(authenticatorData ‖ SHA-256(clientData), signature, key, OPENSSL_ALGO_SHA256)` —
      pass the concatenation, **not** its hash, or it is hashed twice — accepted only when the result is
      `=== 1`, else `Signature`; `rpIdHash` = `app->rpIdHash()` — else `RpIdHash`; the counter (read
      with `unpack('N', …)`) strictly greater than `previousCounter` — else `Counter`; return the new
      counter
- [ ] `clientData` is the caller's raw bytes; the library never parses it (what it contains is the
      caller's protocol — Apple's assertion step 6, checking the challenge inside it, is the caller's)
- [ ] tests: every genuine vector accepted with its counter; builder assertions accepted; a flipped
      signature byte; a foreign key; another bundle; an equal and a lower previous counter; a garbage
      document; an invalid PEM and a negative counter are `InvalidArgumentException`
- [ ] validation commands pass

### Task 6: Documentation, repository metadata and the first release

#### Files
- Modify: `README.md`, `CHANGELOG.md`, `CLAUDE.md`

#### Steps
- [ ] README: what App Attest is in two paragraphs; installation; registration and assertion examples,
      in which the client sends the key id, attestation and assertion as unpadded base64url and the
      server decodes them with `sodium_base642bin(…, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)` (noting
      that Apple's `generateKey()` returns the key id in standard base64, so the client converts it);
      the exception hierarchy, the failure reasons and the `$reason` property; **what the caller must do
      itself** — issue single-use challenges; compute `clientDataHash` the way its client does; store
      the key, environment and counter; **verify that the challenge inside `clientData` is one it issued
      and consume it (Apple's assertion step 6)**; update the counter atomically so two concurrent
      assertions cannot both pass; why development keys are safe to accept (the `rpIdHash` ties a key
      to the team and bundle); that any PSR-20 clock can be passed (Symfony's included); the test
      builders' recipe for consumers who need their own assertions; credits and licenses of the two
      references
- [ ] `CHANGELOG.md` `1.0.0`; `CLAUDE.md` with the conventions, the 8-bit rule (and why: the code style's
      `mb_str_functions`), the import rule, the base64url rule, `openssl_verify === 1`, and the
      "verification only, no state, no I/O" rule
- [ ] repository metadata through `gh repo edit Oire/app-attest`: `--description "Verify Apple App Attest
      attestations and assertions in PHP: certificate chain, nonce, key id, counter. Stateless, no I/O."`,
      `--homepage https://packagist.org/packages/oire/app-attest`, and `--add-topic` for `php`,
      `app-attest`, `apple`, `ios`, `devicecheck`, `attestation`, `security`, `cbor`, `x509`,
      `php-library`; confirm with `gh repo view Oire/app-attest --json description,homepageUrl,repositoryTopics`
- [ ] validation commands pass

## Technical details

### Public API

```php
namespace Oire\AppAttest;

use Psr\Clock\ClockInterface;

final class AttestationVerifier {
    public function __construct(?TrustAnchor $root = null, ?ClockInterface $clock = null);
    /** @param list<Environment> $allowed  @throws AttestationException */
    public function verify(string $attestationCbor, string $clientDataHash, string $keyId,
                           AppIdentity $app, array $allowed): AttestedKey;
}

final class AssertionVerifier {
    /** @throws AssertionException */
    public function verify(string $assertionCbor, string $clientData, string $publicKeyPem,
                           int $previousCounter, AppIdentity $app): int; // the new counter
}

final class TrustAnchor { public static function apple(): self; public static function fromPem(string $pem): self; }
```

```php
namespace Oire\AppAttest\Value;

final class TeamId { public function __construct(public readonly string $value) } // 10 × A-Z0-9
final class BundleId { public function __construct(public readonly string $value) } // A-Za-z0-9 - .
final class AppIdentity { public function __construct(TeamId $teamId, BundleId $bundleId) }
enum Environment: string { case Production = 'production'; case Development = 'development'; }
final class AttestedKey {
    string $keyId; string $publicKeyPem; Environment $environment; string $receipt; int $counter;
    public function keyIdBase64Url(): string;
}
```

```php
namespace Oire\AppAttest\Exception;

use RuntimeException;

abstract class AppAttestException extends RuntimeException {}
final class AttestationException extends AppAttestException { public readonly AttestationFailureReason $reason; }
enum AttestationFailureReason { case Format; case CertificateChain; case Nonce; case KeyId; case RpIdHash; case Counter; case Environment; }
final class AssertionException extends AppAttestException { public readonly AssertionFailureReason $reason; }
enum AssertionFailureReason { case Format; case Signature; case RpIdHash; case Counter; }
```

`$keyId` and `$clientDataHash` are raw bytes; callers decode their transport encoding — base64url, as
the README recommends — before calling. Apple's `generateKey()` hands the app its key id in standard
base64; converting it is the client's job. A malformed `$publicKeyPem`, a `$previousCounter` outside
0..2^32−1, or an invalid `TeamId` or `BundleId` is an `InvalidArgumentException` (a caller error), never
an `AppAttestException`. The library keeps no state: storage, challenges and the counter race are the
caller's.

## Post-completion

- `Oire/app-attest` exists on GitHub (public, Apache-2.0, created 2026-10-08); push and confirm CI is
  green.
- Tag `v1.0.0` and push the tag; confirm the release workflow created the GitHub Release.
- Submit the package: sign in at https://packagist.org, choose **Submit**, enter
  `https://github.com/Oire/app-attest`, and confirm.
- Add the Packagist webhook so pushes and tags update the package without clicking **Update**:
  1. On https://packagist.org/profile/ note your username and click **Show Safe API Token**. Use the
     **Safe** token: the GitHub hook endpoint accepts it (Packagist's `ApiController` checks the
     signature against both tokens), and it only reaches safe APIs such as package updates, so a leak
     is harmless; the main API token can also create and edit packages.
  2. Either on GitHub (`Oire/app-attest` → Settings → Webhooks → Add webhook: Payload URL
     `https://packagist.org/api/github?username=<username>`, Content type `application/json`, Secret
     the Safe API token, "Just the push event", Active), or in your own terminal:
     `gh api repos/Oire/app-attest/hooks -f name=web -f "config[url]=https://packagist.org/api/github?username=<username>" -f "config[content_type]=json" -f "config[secret]=<token>" -F active=true -f "events[]=push"`
  3. Check: the hook's **Recent Deliveries** shows a 2xx response after the next push, and the package
     page on Packagist no longer warns that it is not auto-updated.
- Tell AccessMind the version to require.
- Before a later release: re-fetch Apple's root and compare its fingerprint with the constant.
- When PHP 8.3 reaches end of life (2027-12-31): drop it from the CI matrix and raise `"php"` and
  `config.platform.php` to 8.4 in a minor release.
