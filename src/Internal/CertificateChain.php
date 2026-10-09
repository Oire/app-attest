<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use DateTimeInterface;
use LogicException;
use Oire\AppAttest\TrustAnchor;
use phpseclib3\File\X509;
use Throwable;

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
 * An attestation's x5c, validated: the credential certificate issued by the intermediate, the intermediate
 * a CA issued by the trust anchor, each certificate valid at the given time. Holds what the verifier reads
 * from the credential certificate.
 *
 * phpseclib does not check that an issuer is a CA, so the intermediate's basicConstraints are checked here,
 * and its fetching of caIssuers URLs is turned off on every call: verification makes no network call.
 *
 * @internal
 */
final readonly class CertificateChain
{
    private const int LENGTH = 2;

    /**
     * @param ?string $nonce                the octet string inside the nonce extension, if well-formed
     * @param string  $subjectPublicKeyInfo the credential certificate's SubjectPublicKeyInfo as DER
     *
     * @psalm-capabilities read-props
     */
    private function __construct(public ?string $nonce, public string $subjectPublicKeyInfo) {}

    /**
     * The validated chain, or null if the certificates do not form one.
     *
     * @param list<string> $certificates DER, the credential certificate first
     *
     * @throws LogicException if the process has registered another phpseclib map for the nonce extension
     */
    public static function tryValidate(array $certificates, TrustAnchor $anchor, DateTimeInterface $time): ?self
    {
        if (count($certificates) !== self::LENGTH || !isset($certificates[0], $certificates[1])) {
            return null;
        }

        $credentialDer = $certificates[0];
        $intermediateDer = $certificates[1];
        X509::disableURLFetch();
        NonceExtension::register();

        try {
            return ErrorGuard::call(static function() use ($credentialDer, $intermediateDer, $anchor, $time): ?self {
                $root = new X509();

                if (!is_array($root->loadX509($anchor->pem)) || !$root->validateDate($time)) {
                    return null;
                }

                $intermediate = self::issuedAndValid($intermediateDer, $anchor->pem, $time);

                if ($intermediate === null || !self::isCa($intermediate)) {
                    return null;
                }

                $credential = self::issuedAndValid($credentialDer, $intermediateDer, $time);

                return $credential === null ? null : new self(self::nonceOf($credential), self::subjectPublicKeyInfoOf($credential));
            });
        } catch (Throwable) {
            return null;
        }
    }

    private static function issuedAndValid(string $der, string $issuer, DateTimeInterface $time): ?X509
    {
        $certificate = new X509();

        if (
            !$certificate->loadCA($issuer)
            || !is_array($certificate->loadX509($der, X509::FORMAT_DER))
            || $certificate->validateSignature() !== true
            || !$certificate->validateDate($time)
        ) {
            return null;
        }

        return $certificate;
    }

    private static function isCa(X509 $certificate): bool
    {
        return self::member($certificate->getExtension('id-ce-basicConstraints'), 'cA') === true;
    }

    private static function nonceOf(X509 $credential): ?string
    {
        return self::stringOrNull(self::member($credential->getExtension(NonceExtension::OID), 'nonce'));
    }

    /**
     * @psalm-capabilities read-props
     */
    private static function subjectPublicKeyInfoOf(X509 $credential): string
    {
        $pem = self::stringOrNull(self::member(self::member(self::member($credential->getCurrentCert(), 'tbsCertificate'), 'subjectPublicKeyInfo'), 'subjectPublicKey')) ?? '';

        return Pem::tryDecode($pem, Pem::PUBLIC_KEY) ?? '';
    }

    /**
     * @psalm-pure
     */
    private static function member(mixed $value, string $key): mixed
    {
        return is_array($value) ? $value[$key] ?? null : null;
    }

    /**
     * @psalm-pure
     */
    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
