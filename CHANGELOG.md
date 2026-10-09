# Version 2.0.0 (Unreleased)

The library moves to phpseclib 4 and no longer reads certificates with phpseclib at all: it takes them apart
with its own strict DER reader and checks signatures and keys with OpenSSL, so no process-wide phpseclib
setting changes a verification result. The verifiers' signatures and results are unchanged, and Apple's
genuine chains verify as before.

## Breaking Changes

* **phpseclib 4 is required:** `phpseclib/phpseclib` `^4.0` replaces `^3.0.57`. phpseclib 3 and 4 are the
  same Composer package, so this version forces phpseclib 4 on the whole application; an application that
  needs phpseclib 3 stays on 1.x.
* **`TrustAnchor::fromPem()` is stricter:** it throws an `InvalidArgumentException` for a root without an
  EC key (Ed25519 and Ed448 included) or without a key usage extension that includes `keyCertSign`, test
  roots that 1.0 accepted although no chain could lead to them, and for a root that is not DER where the
  library reads it.
* **Test chains must look like Apple's:** each certificate signed with ECDSA over SHA-256, SHA-384 or
  SHA-512, each issuer with a key usage extension that includes `keyCertSign` whatever
  `X509::ignoreKeyUsage()` says, and each certificate naming its issuer with exactly the bytes of the
  issuer's subject name, whatever `X509::looseDNComparison()` says. Each certificate must be DER where the
  library reads it: lengths in their shortest form, nothing after the extensions, booleans `0x00` or `0xFF`,
  integers and OIDs in their shortest form, validity times in UTC with seconds and without fractions, the
  key usage without trailing zero bits or bits past `decipherOnly`, and each of the key usage, key
  identifier, `basicConstraints` and nonce extensions at most once. A chain that 1.0 accepted otherwise fails
  with `CertificateChain`, or `Nonce` for a malformed nonce extension.
* **The library no longer changes phpseclib for the rest of the application.** 1.0 disabled URL fetching
  and registered the nonce extension's map process-wide. Applications that called `X509::enableURLFetch()`
  after each verification, as the 1.0 README advised, must drop the call (phpseclib 4 has no such method),
  and phpseclib no longer decodes the nonce extension of certificates your own code loads.

## Changes

* **No phpseclib setting changes a result.** phpseclib keeps its settings process-wide: 4's
  `X509::validateSignature()` trusts a process-wide CA store, checks a process-wide validation date, calls
  the CRL callback and resolves `caIssuers` host names before it asks the URL-fetch callback,
  `X509::isIssuerOf()` obeys `X509::ignoreKeyUsage()` and `X509::looseDNComparison()`, and under
  `ASN1::enableBlobsOnBadDecodes()` its ASN.1 mapper turns a malformed element into a partial result, so
  that, for example, a `basicConstraints` with `cA` true and an unexpected element passed for a CA. The
  library therefore calls none of them. It checks each link itself, the signature first: the issuer's ECDSA
  signature over the certificate's original `tbsCertificate` bytes, then the issuer name byte for byte, the
  issuer's `keyCertSign`, the authority and subject key identifiers as phpseclib matched them, the validity
  periods and, as before, the intermediate's `basicConstraints` `cA` flag. Extensions and the signature
  algorithm are matched by their encoded OIDs.
* The nonce extension is decoded by the library itself, without `X509::registerExtension()`, so a
  phpseclib map registered for its OID no longer matters: 1.0 threw a `LogicException` for any map other
  than its own.
* Neither verification nor `TrustAnchor::fromPem()` touches ASN.1 cache invalidation any more.
* A credential certificate with the nonce extension twice fails the nonce; an issuer with its key usage or
  subject key identifier twice, a certificate with its authority key identifier twice and an intermediate
  with its `basicConstraints` twice fail the chain. A
  signature that is not strict DER, unused bits declared in the signature, a `signatureAlgorithm` with
  parameters or other than the one inside `tbsCertificate`, or a length in a longer form than needed fails
  the chain.

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
