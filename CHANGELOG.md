# Version 2.0.0 (Unreleased)

The library no longer depends on phpseclib: it takes certificates apart with its own strict DER reader and
checks signatures and keys with OpenSSL, so no process-wide phpseclib setting changes a verification result.
The verifiers' method signatures and return types are unchanged, and Apple's genuine chains verify as before;
test chains and roots that do not look like Apple's may now be refused (see Breaking Changes).

## Breaking Changes

* **phpseclib is no longer a runtime dependency:** `phpseclib/phpseclib` leaves `require`. The library calls
  no phpseclib code and works next to any phpseclib version, or none, so an application that uses phpseclib
  and relied on this library to install it must require it directly. Its own dependencies,
  `paragonie/constant_time_encoding` and `paragonie/random_compat`, are no longer installed either.
* **`TrustAnchor::fromPem()` is stricter:** it throws an `InvalidArgumentException` for a root without an EC
  key (RSA, Ed25519 and Ed448 included), for a root without a key usage extension that includes
  `keyCertSign`, and for a root that is not DER where the library reads it, a v1 certificate included. 1.0
  accepted such roots and verified chains signed by them; 2.0 can chain to none of them.
* **Test chains must look like Apple's.** 1.0 accepted any signature algorithm phpseclib 3 knew, RSA
  included, and did not look at an issuer's key usage. 2.0 requires each certificate to be signed with ECDSA
  over SHA-256, SHA-384 or SHA-512, each issuer to have exactly one key usage extension that includes
  `keyCertSign`, each certificate's issuer Name to be byte for byte its issuer's subject Name, and an
  authority key identifier, when present, to name the issuer's subject key identifier and, if it holds one,
  the issuer's serial number. Each certificate may mark critical only the extensions the library processes
  for it, as RFC 5280 requires: `basicConstraints`, key usage and the key identifiers for the intermediate,
  these and the nonce extension for the credential certificate. The credential certificate's key usage, if
  any, must be well-formed and its `basicConstraints`, if any, the empty `SEQUENCE` Apple's carries (`cA`
  false, no path length), critical or not, and every key identifier must be well-formed even where no match
  reads it. Each certificate must be a v3 certificate and DER where the library reads it: lengths in their
  shortest form, nothing after the extensions, booleans `0x00` or `0xFF`, an extension's critical flag left
  out rather than written as FALSE, integers and OIDs in their shortest form, validity times in UTC with
  seconds and without fractions, the key usage without trailing zero bits or bits past `decipherOnly`, and
  each of the key usage, key identifier, `basicConstraints` and nonce extensions at most once. A chain that 1.0 accepted otherwise fails with `CertificateChain`, or `Nonce` for a malformed nonce
  extension.
* **The library no longer changes phpseclib for the rest of the application.** 1.0 disabled URL fetching
  and registered the nonce extension's map process-wide. Applications no longer need to call
  `X509::enableURLFetch()` after each verification, as the 1.0 README advised, and phpseclib no longer
  decodes the nonce extension of certificates your own code loads. If your own code validates certificates
  with phpseclib and depended on fetching being off, call `X509::disableURLFetch()` yourself: 2.0 no longer
  turns it off for you, and phpseclib 3 fetches `caIssuers` URLs by default.

## Changes

* **Any phpseclib version, or none.** Without phpseclib at run time, the library works next to phpseclib 3,
  phpseclib 4 or neither, where 1.x forced phpseclib 3 on the whole application. phpseclib is now a
  development dependency, used only by the repository's test builders. `TrustAnchor::fromPem()` stays
  stricter, as listed above.
* **No phpseclib setting changes a result.** 1.0 parsed certificates with phpseclib 3 and depended on its
  process-wide state (the extension map it registered, URL fetching). 2.0 reads each certificate with its own
  strict DER reader and checks each link itself, the signature first: the issuer's ECDSA signature over the
  original `tbsCertificate` bytes, then the issuer Name byte for byte, the issuer's `keyCertSign`, the key
  identifiers, the validity periods and, as before, the intermediate's `cA` flag. Extensions and the
  signature algorithm are matched by their encoded OIDs.
* The nonce extension is decoded by the library itself, without `X509::registerExtension()`, so a
  phpseclib map registered for its OID no longer matters: 1.0 threw a `LogicException` for any map other
  than its own.
* A credential certificate with the nonce extension twice fails the nonce; an issuer with its key usage or
  subject key identifier twice, a certificate with its authority key identifier twice and an intermediate
  with its `basicConstraints` twice fail the chain. A signature that is not strict DER, unused bits declared
  in the signature, a `signatureAlgorithm` with parameters or other than the one inside `tbsCertificate`, or
  a length in a longer form than needed fails the chain.

# Version 1.0.0

The first release: verification of Apple App Attest attestations and assertions, following Apple's
"Validating apps that connect to your server".

## Changes

* **`AttestationVerifier`** checks an attestation in Apple's order: the `apple-appattest` format, a
  two-certificate chain to the trust anchor valid at the clock's time with a CA intermediate, the nonce
  in the credential certificate, the key id, the `rpIdHash`, a zero counter, the environment and the
  `credentialId`. The credential public key in `authData` must be one CBOR map (a COSE key), else
  `Format`. Each certificate must be exactly one DER `SEQUENCE` of at most 4096 bytes before
  phpseclib reads it, and each issuer is checked as the certificate already parsed. It returns an
  `AttestedKey` with the key id, the public key as PEM, the environment, the receipt and counter 0.
  `clientDataHash` may be any length, as in Apple's own sample.
* Both verifiers refuse with `Format`, before decoding it, an attestation longer than 16384 bytes or an
  assertion longer than 4096 bytes, so hostile input cannot exhaust memory. They also refuse with
  `Format` a document that is not exactly one CBOR map with nothing after it, a map in it with a key that
  is not a text string or a key twice, and any member of the wrong type: `fmt` must be a text string,
  `x5c` an array, the certificates, `receipt`, `authData`, `signature` and `authenticatorData` byte
  strings.
* **`AssertionVerifier`** checks an assertion's ECDSA P-256 signature over the nonce, the SHA-256 of
  `authenticatorData` followed by the SHA-256 of `clientData`, its `rpIdHash` and a counter strictly
  greater than the previous one, and returns a `VerifiedAssertion` with the new counter and the launch
  values. `clientData` is never parsed.
* **Launch category and bundle version**, opt-in: both verifiers read the `extensions` CBOR map Apple
  appends to the authenticator data, after the credential public key in an attestation and after the 37
  bytes of an assertion, for the validation category (`apple_validation_category_01` or
  `validationCategory`, four little-endian bytes or an unsigned integer) and the bundle version
  (`apple_bundle_version_01` or `bundleVersion`, a text string). `AttestedKey` and `VerifiedAssertion`
  report them as `$validationCategory`, `$bundleVersion` and `validationCategory()`. A `LaunchPolicy`,
  passed as the optional last argument of either `verify()`, enforces them with the reasons
  `ValidationCategory` and `BundleVersion`; without one both verifiers only report them, and a missing or
  malformed extensions area is ignored. `LaunchPolicy::allowing()` needs at least one category.
  `ValidationCategory` is an int-backed enum with Apple's launch-constraint numbering, and
  `ValidationCategory::tryFromRaw()` maps a reported number to its case.
* **Typed failures:** `AttestationException` and `AssertionException`, both extending the abstract
  `AppAttestException`, carry a `$reason` enum case naming the failed check. Caller errors, such as an
  invalid team id or public key, or an `$allowed` list that is empty or not of `Environment` cases, are
  `InvalidArgumentException`. A broken installation or another phpseclib map registered for the nonce
  extension is a `LogicException`.
* **`TrustAnchor`** bundles Apple's App Attest root and checks its pinned SHA-256 fingerprint on every
  load; `TrustAnchor::fromPem()` takes a test root.
* **Value objects:** `TeamId`, `BundleId`, `AppIdentity`, the `Environment` and `ValidationCategory`
  enums, `AttestedKey`, `VerifiedAssertion` and `LaunchPolicy`.
* **`SystemClock`**, the PSR-20 clock used when none is passed; any PSR-20 clock can be injected.
* No state and no I/O: no network, no key storage, no challenges, no logging. `AttestationVerifier`
  disables phpseclib's URL fetching and registers the App Attest nonce extension with phpseclib, both
  process-wide.
* Tested against genuine vectors from `veehaitch/devicecheck-appattest` and `takimoto3/app-attest`, on
  PHP 8.3, 8.4 and 8.5.
