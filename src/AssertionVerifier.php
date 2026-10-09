<?php

declare(strict_types=1);

namespace Oire\AppAttest;

use InvalidArgumentException;
use Oire\AppAttest\Exception\AssertionException;
use Oire\AppAttest\Exception\AssertionFailureReason;
use Oire\AppAttest\Internal\AuthenticatorData;
use Oire\AppAttest\Internal\Cbor;
use Oire\AppAttest\Internal\EcPoint;
use Oire\AppAttest\Internal\Extensions;
use Oire\AppAttest\Internal\Pem;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\LaunchPolicy;

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
 * Verifies an App Attest assertion, following the steps of Apple's "Validating apps that connect to your
 * server". Checking the challenge inside the client data is the caller's job, as is storing the new counter.
 *
 * @psalm-api
 */
final readonly class AssertionVerifier
{
    private const int MAX_LENGTH = 4096;

    /**
     * @param string        $assertionCbor   the assertion object as raw bytes
     * @param string        $clientData      the client data the app signed, as raw bytes; never parsed here
     * @param string        $publicKeyPem    the key's public key, as AttestedKey::$publicKeyPem returned it
     * @param int           $previousCounter the counter stored for the key, 0 after its attestation
     * @param ?LaunchPolicy $launchPolicy    the launch values the authenticator data must carry; none checked if null
     *
     * @throws InvalidArgumentException if the public key is not a PEM-encoded P-256 key or the previous
     *                                  counter is outside 0..2^32−1
     * @throws AssertionException       if the assertion fails a check; its reason names the check
     *
     * @return int the new counter, to store for the key
     */
    public function verify(string $assertionCbor, string $clientData, string $publicKeyPem, int $previousCounter, AppIdentity $app, ?LaunchPolicy $launchPolicy = null): int
    {
        $point = self::pointOf($publicKeyPem)
            ?? throw new InvalidArgumentException('The public key must be a PEM-encoded uncompressed P-256 public key.');

        if ($previousCounter < 0 || $previousCounter > AuthenticatorData::MAX_UINT32) {
            throw new InvalidArgumentException('The previous counter must be between 0 and 2^32 - 1.');
        }

        if (mb_strlen($assertionCbor, '8bit') > self::MAX_LENGTH) {
            throw new AssertionException(AssertionFailureReason::Format, 'The assertion is longer than ' . self::MAX_LENGTH . ' bytes.');
        }

        $document = Cbor::tryDecodeMap($assertionCbor);
        $signature = $document?->get('signature');
        $authenticatorData = $document?->get('authenticatorData');
        $authData = is_string($authenticatorData) ? AuthenticatorData::tryFromAssertion($authenticatorData) : null;

        if (!is_string($signature) || !is_string($authenticatorData) || $authData === null) {
            throw new AssertionException(
                AssertionFailureReason::Format,
                'The assertion is not an object with a signature and at least ' . AuthenticatorData::ASSERTION_LENGTH . ' bytes of authenticatorData.',
            );
        }

        $nonce = hash('sha256', $authenticatorData . hash('sha256', $clientData, true), true);

        if (!self::isSignedBy($nonce, $signature, $point)) {
            throw new AssertionException(AssertionFailureReason::Signature, 'The assertion signature does not verify with the public key.');
        }

        if (!hash_equals($app->rpIdHash(), $authData->rpIdHash)) {
            throw new AssertionException(AssertionFailureReason::RpIdHash, 'The authenticator data rpIdHash does not match the app id.');
        }

        if ($authData->counter <= $previousCounter) {
            throw new AssertionException(AssertionFailureReason::Counter, 'The authenticator data counter is not greater than the previous counter.');
        }

        if ($launchPolicy !== null) {
            self::enforce($launchPolicy, $authData->extensions);
        }

        return $authData->counter;
    }

    /**
     * @throws AssertionException if the launch values do not pass the policy
     */
    private static function enforce(LaunchPolicy $launchPolicy, Extensions $extensions): void
    {
        if (!$launchPolicy->allowsValidationCategory($extensions->validationCategory)) {
            throw new AssertionException(AssertionFailureReason::ValidationCategory, 'The authenticator data carries no validation category the launch policy allows.');
        }

        if (!$launchPolicy->acceptsBundleVersion($extensions->bundleVersion)) {
            throw new AssertionException(AssertionFailureReason::BundleVersion, 'The authenticator data carries no bundle version the launch policy accepts.');
        }
    }

    /**
     * @psalm-capabilities read-props
     */
    private static function pointOf(string $publicKeyPem): ?EcPoint
    {
        $der = Pem::tryDecode($publicKeyPem, Pem::PUBLIC_KEY);

        return $der === null ? null : EcPoint::tryFromSubjectPublicKeyInfo($der);
    }

    /**
     * The device signs the nonce itself with ECDSA over SHA-256, so the nonce is hashed once more here.
     *
     * @psalm-capabilities read-props
     */
    private static function isSignedBy(string $nonce, string $signature, EcPoint $point): bool
    {
        return openssl_verify($nonce, $signature, $point->publicKeyPem(), OPENSSL_ALGO_SHA256) === 1;
    }
}
