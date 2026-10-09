# Version 1.0.0

The first release: verification of Apple App Attest attestations and assertions, following Apple's
"Validating apps that connect to your server".

## Changes

* **`AttestationVerifier`** checks an attestation in Apple's order: the `apple-appattest` format, a
  two-certificate chain to the trust anchor valid at the clock's time with a CA intermediate, the nonce
  in the credential certificate, the key id, the `rpIdHash`, a zero counter, the environment and the
  `credentialId`. Each certificate must be exactly one DER `SEQUENCE` of at most 4096 bytes before
  phpseclib reads it, and each issuer is checked as the certificate already parsed. It returns an `AttestedKey` with the key id, the public key as PEM, the environment, the
  receipt and counter 0. `clientDataHash` may be any length, as in Apple's own sample.
* Both verifiers refuse with `Format` a document that is not exactly one CBOR map with nothing after it,
  and any member of the wrong string type: keys and `fmt` must be text strings, the certificates,
  `receipt`, `authData`, `signature` and `authenticatorData` byte strings.
* **`AssertionVerifier`** checks an assertion's ECDSA P-256 signature over the nonce, the SHA-256 of
  `authenticatorData` followed by the SHA-256 of `clientData`, its `rpIdHash` and a counter strictly
  greater than the previous one, and returns the new counter. `clientData` is never parsed.
* **Typed failures:** `AttestationException` and `AssertionException`, both extending the abstract
  `AppAttestException`, carry a `$reason` enum case naming the failed check. Caller errors, such as an
  invalid team id or public key, are `InvalidArgumentException`. A broken installation or another
  phpseclib map registered for the nonce extension is a `LogicException`.
* **`TrustAnchor`** bundles Apple's App Attest root and checks its pinned SHA-256 fingerprint on every
  load; `TrustAnchor::fromPem()` takes a test root.
* **Value objects:** `TeamId`, `BundleId`, `AppIdentity`, the `Environment` enum and `AttestedKey`.
* **`SystemClock`**, the PSR-20 clock used when none is passed; any PSR-20 clock can be injected.
* No state and no I/O: no network, no key storage, no challenges, no logging. `AttestationVerifier`
  disables phpseclib's URL fetching and registers the App Attest nonce extension with phpseclib, both
  process-wide.
* Tested against genuine vectors from `veehaitch/devicecheck-appattest` and `takimoto3/app-attest`, on
  PHP 8.3, 8.4 and 8.5.
