# Golden vectors

Genuine App Attest attestations and assertions, signed by Apple, taken from the test data of two
reference implementations. They are used **only unchanged**: every field of `authData` is bound into the
signed nonce, and the nonce sits inside a signed certificate, so an edited vector fails at the nonce or
the chain, not at the check a test means to reach. Failures the vectors cannot reach are made by
`tests/Support/AttestationBuilder.php` and `tests/Support/AssertionBuilder.php`.

## Layout

- `attestation/<name>.cbor` and `assertion/<name>.cbor`: the attestation or assertion object, the exact
  bytes the reference ships base64-encoded in its source file.
- `attestation/<name>.json` and `assertion/<name>.json`: the sidecar naming the vector's inputs.
- `source/`: byte-for-byte copies of the reference files the vectors were decoded from, so anyone can check
  that a `.cbor` file holds exactly what the reference ships (`FixturesTest` does).
- `LICENSE-veehaitch` (Apache-2.0) and `LICENSE-takimoto3` (MIT): the references' licenses, copied
  unchanged. `veehaitch/devicecheck-appattest` has no `NOTICE` file.

`tests/Fixtures.php` loads the sidecars and hands each attestation's time to the verifier as a Symfony
`MockClock`.

## Sidecars

Binary values are unpadded base64url. Times are UTC with milliseconds.

- `vector`: the `.cbor` file beside the sidecar.
- `origin`: `repository`, `commit`, `path` in that repository, `copy` under `source/`, `license`, and
  where in the file the vector sits (`documentId` and `field` of a YAML document, or a Go `constant`).
- `teamId`, `bundleId`: the app the key belongs to.
- `keyId`: the key id, raw bytes.
- `environment`: `development` or `production`, read from the `aaguid`.
- `verifyAt`, `verifyAtSource`: the time to verify at, and whether the reference gave it or it was inferred.
- Attestations: `clientDataHash` with `formedAs` (`sha256`: the SHA-256 of the UTF-8 `challenge`; `raw`:
  the UTF-8 `challenge` itself), `challenge` and `value` (the bytes passed to the verifier), and
  `expected` with `result`, `publicKeyPem` and `counter`.
- Assertions: `attestation` (the vector that attested the key), `clientData` (the bytes the device
  signed), `challenge` (what the caller checks inside `clientData`), `publicKeyPem`, `previousCounter`,
  and `expected` with `result` and `counter`. The counter is a JSON number, not bytes.

## Vectors

From `veehaitch/devicecheck-appattest` (https://github.com/veehaitch/devicecheck-appattest), commit
`cb26211f63c1e2e7949deafe2efdf352daca27fa`, Apache-2.0. Each file `src/test/resources/ios-<version>.yaml`
holds one attestation and one assertion of the same key, all made by a development build of team
`6MURL8TA57`, bundle `de.vincent-haupert.apple-appattest-poc`, with the client data `wurzelpfropf`; the
attestation's `clientDataHash` is its SHA-256, the assertion's challenge is `wurzel`, and the times are the
documents' `timestamp` fields.

- `veehaitch-ios-14.2`: attestation and assertion, from `src/test/resources/ios-14.2.yaml`
- `veehaitch-ios-14.3-beta-2`: attestation and assertion, from `src/test/resources/ios-14.3-beta-2.yaml`
- `veehaitch-ios-14.3-beta-3`: attestation and assertion, from `src/test/resources/ios-14.3-beta-3.yaml`
- `veehaitch-ios-14.3`: attestation and assertion, from `src/test/resources/ios-14.3.yaml`
- `veehaitch-ios-14.4-beta-1`: attestation and assertion, from `src/test/resources/ios-14.4-beta-1.yaml`
- `veehaitch-ios-14.4-beta-2`: attestation and assertion, from `src/test/resources/ios-14.4-beta-2.yaml`
- `veehaitch-ios-14.4`: attestation and assertion, from `src/test/resources/ios-14.4.yaml`

From `takimoto3/app-attest` (https://github.com/takimoto3/app-attest), commit
`9d7551c05804d3e35d5477b5aed1d82d8f8a2035`, MIT:

- `takimoto3-apple-guide`: attestation only, the constant `appleGuideAttestationObjectBase64` in
  `apple_guide_test.go`. It is the sample Apple publishes in its "Attestation object validation guide"
  (https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide): a
  **production** key of team `1234567890`, bundle `com.example.myapp`, with the newer credential
  certificate extensions and the `apple_validation_category_01` and `apple_bundle_version_01` entries in
  `authData`. As the guide shows, its nonce is formed from the **raw** challenge
  `example_server_challenge` (24 bytes), not from its SHA-256. The guide gives no time: `verifyAt` is
  inferred as one day after the credential certificate's `notBefore` (valid 2026-04-20T18:13:12Z to
  2026-04-23T18:13:12Z).

`takimoto3/app-attest` also tests with `testdata/ios-14.4.json` and the constants in
`attestation_test.go` and `assertion_test.go`; they hold the same bytes as `veehaitch-ios-14.4` and are not
collected twice.

## Failures reached through the verifier's inputs

Listed here, not built: a genuine vector verified with one input changed.

- `Nonce`: another `clientDataHash`.
- `KeyId`: another key id.
- `RpIdHash`: another `AppIdentity`.
- `Environment`: an `allowed` list without the vector's environment.
- `CertificateChain`: a clock past the credential certificate's validity, or another `TrustAnchor`.
- `Format`: garbage instead of the document.

## Failures made by the builders

- `AttestationBuilder`: a non-zero counter (`Counter`); a `credentialId` other than the key id (`KeyId`);
  a production or an unknown `aaguid` (`Environment`, and production accepted); an intermediate that is
  not a CA (`CertificateChain`); a missing or malformed nonce extension (`Nonce`); a wrong `fmt`, a missing
  `x5c` and a truncated `authData` (`Format`); a credential key whose x coordinate starts with a zero byte.
- `AssertionBuilder`: any `rpIdHash`, counter and client data, signed with a fresh key.
