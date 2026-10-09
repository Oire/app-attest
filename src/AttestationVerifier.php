<?php

declare(strict_types=1);

namespace Oire\AppAttest;

use Oire\AppAttest\Exception\AttestationException;
use Oire\AppAttest\Exception\AttestationFailureReason;
use Oire\AppAttest\Internal\AuthenticatorData;
use Oire\AppAttest\Internal\Cbor;
use Oire\AppAttest\Internal\CertificateChain;
use Oire\AppAttest\Internal\EcPoint;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\AttestedKey;
use Oire\AppAttest\Value\Environment;
use Psr\Clock\ClockInterface;

/**
 * Oire App Attest, verification of Apple App Attest attestations and assertions
 * Copyright © 2026 André Polykanine, Oire Software, https://oire.org/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Verifies an App Attest attestation, following the steps of Apple's "Validating apps that connect to your
 * server".
 *
 * @psalm-api
 */
final readonly class AttestationVerifier
{
    private const string FORMAT = 'apple-appattest';
    private TrustAnchor $root;
    private ClockInterface $clock;

    /**
     * @param ?TrustAnchor    $root  the root the chain must lead to; Apple's App Attest root if null
     * @param ?ClockInterface $clock the time the certificates must be valid at; the system clock if null
     */
    public function __construct(?TrustAnchor $root = null, ?ClockInterface $clock = null)
    {
        $this->root = $root ?? TrustAnchor::apple();
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * @param string            $attestationCbor the attestation object as raw bytes
     * @param string            $clientDataHash  raw bytes, formed the way the app formed them
     * @param string            $keyId           raw bytes, as the app reported it
     * @param list<Environment> $allowed         the environments a key may come from
     *
     * @throws AttestationException if the attestation fails a check; its reason names the check
     */
    public function verify(string $attestationCbor, string $clientDataHash, string $keyId, AppIdentity $app, array $allowed): AttestedKey
    {
        $document = Cbor::tryDecodeMap($attestationCbor) ?? [];
        $attStmt = $document['attStmt'] ?? null;
        $certificates = is_array($attStmt) ? self::certificates($attStmt['x5c'] ?? null) : null;
        $receipt = is_array($attStmt) ? $attStmt['receipt'] ?? null : null;
        $authDataBytes = $document['authData'] ?? null;

        if (
            ($document['fmt'] ?? null) !== self::FORMAT
            || $certificates === null
            || !is_string($receipt)
            || !is_string($authDataBytes)
        ) {
            throw self::failure(AttestationFailureReason::Format, 'The attestation is not an apple-appattest object with x5c, receipt and authData.');
        }

        $authData = AuthenticatorData::tryFromAttestation($authDataBytes)
            ?? throw self::failure(AttestationFailureReason::Format, 'The authenticator data is shorter than its layout requires.');

        $chain = CertificateChain::tryValidate($certificates, $this->root, $this->clock->now())
            ?? throw self::failure(AttestationFailureReason::CertificateChain, 'The certificate chain does not lead to the trust anchor or is not valid at this time.');

        if ($chain->nonce === null || !hash_equals(hash('sha256', $authDataBytes . $clientDataHash, true), $chain->nonce)) {
            throw self::failure(AttestationFailureReason::Nonce, 'The nonce in the credential certificate does not match the authenticator data and client data hash.');
        }

        $point = EcPoint::tryFromSubjectPublicKeyInfo($chain->subjectPublicKeyInfo)
            ?? throw self::failure(AttestationFailureReason::Format, 'The credential certificate does not hold an uncompressed P-256 public key.');

        if (!hash_equals($point->keyId(), $keyId)) {
            throw self::failure(AttestationFailureReason::KeyId, 'The credential certificate public key does not match the key id.');
        }

        if (!hash_equals($app->rpIdHash(), $authData->rpIdHash)) {
            throw self::failure(AttestationFailureReason::RpIdHash, 'The authenticator data rpIdHash does not match the app id.');
        }

        if ($authData->counter !== 0) {
            throw self::failure(AttestationFailureReason::Counter, 'The authenticator data counter of an attestation must be 0.');
        }

        $environment = Environment::tryFromAaguid($authData->aaguid);

        if ($environment === null || !in_array($environment, $allowed, true)) {
            throw self::failure(AttestationFailureReason::Environment, 'The authenticator data aaguid does not name an allowed environment.');
        }

        if (!hash_equals($point->keyId(), $authData->credentialId)) {
            throw self::failure(AttestationFailureReason::KeyId, 'The authenticator data credentialId does not match the key id.');
        }

        return new AttestedKey($point->keyId(), $point->publicKeyPem(), $environment, $receipt);
    }

    /**
     * @return list<string>|null
     *
     * @psalm-pure
     */
    private static function certificates(mixed $x5c): ?array
    {
        if (!is_array($x5c) || !array_is_list($x5c)) {
            return null;
        }

        $certificates = [];

        foreach ($x5c as $certificate) {
            if (!is_string($certificate)) {
                return null;
            }

            $certificates[] = $certificate;
        }

        return $certificates;
    }

    /**
     * @psalm-pure
     */
    private static function failure(AttestationFailureReason $reason, string $message): AttestationException
    {
        return new AttestationException($reason, $message);
    }
}
