<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use ArrayAccess;
use DateTimeInterface;
use LogicException;
use Oire\AppAttest\TrustAnchor;
use phpseclib4\Crypt\EC\PublicKey as EcPublicKey;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps\Certificate;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\Boolean;
use phpseclib4\File\ASN1\Types\Choice;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\File\X509;
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
 * phpseclib's validateSignature() trusts a process-wide CA store, checks dates against a process-wide target
 * date, may resolve caIssuers hosts and calls a process-wide CRL callback, and does not check that an issuer
 * is a CA. So each link is checked here instead: the issuer's ECDSA signature over the original
 * tbsCertificate bytes, phpseclib's issuer matching (names and key identifiers), the validity period and the
 * intermediate's basicConstraints. Verification makes no network call and leaves phpseclib's CA store alone.
 *
 * Every certificate must be exactly one DER SEQUENCE, and an x5c entry at most MAX_LENGTH bytes, before
 * phpseclib reads it: phpseclib ignores bytes after the first element. Each certificate is loaded as DER,
 * never with PEM auto-detection.
 *
 * @internal
 */
final readonly class CertificateChain
{
    private const int LENGTH = 2;
    private const int MAX_LENGTH = 4096;
    private const array SIGNATURE_HASHES = [
        'ecdsa-with-SHA256' => 'sha256',
        'ecdsa-with-SHA384' => 'sha384',
        'ecdsa-with-SHA512' => 'sha512',
    ];
    private const array EDWARDS_CURVES = ['Ed25519', 'Ed448'];

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
        $rootDer = Pem::tryDecode($anchor->pem, Pem::CERTIFICATE);

        if (
            $rootDer === null
            || !Der::isOneSequence($rootDer)
            || !Der::isOneSequence($intermediateDer, self::MAX_LENGTH)
            || !Der::isOneSequence($credentialDer, self::MAX_LENGTH)
        ) {
            return null;
        }

        NonceExtension::assertNoOtherMap();

        try {
            return ErrorGuard::call(static function() use ($credentialDer, $intermediateDer, $rootDer, $time): ?self {
                $root = X509::load($rootDer, ASN1::FORMAT_DER);
                $intermediate = X509::load($intermediateDer, ASN1::FORMAT_DER);
                $credential = X509::load($credentialDer, ASN1::FORMAT_DER);

                if (
                    !self::isValidAt($root, $time)
                    || !self::isIssuedBy($intermediate, $root, $time)
                    || !self::isCa($intermediate)
                    || !self::isIssuedBy($credential, $intermediate, $time)
                ) {
                    return null;
                }

                return self::readCredential($credentialDer);
            });
        } catch (Throwable) {
            return null;
        }
    }

    private static function isIssuedBy(X509 $certificate, X509 $issuer, DateTimeInterface $time): bool
    {
        return self::isSignedBy($certificate, $issuer) && $issuer->isIssuerOf($certificate) && self::isValidAt($certificate, $time);
    }

    private static function isSignedBy(X509 $certificate, X509 $issuer): bool
    {
        $key = $issuer->getPublicKey();
        $algorithm = self::at($certificate, OID::class, 'signatureAlgorithm', 'algorithm');
        $hash = $algorithm === null ? null : self::SIGNATURE_HASHES[(string) $algorithm] ?? null;
        $signature = self::at($certificate, BitString::class, 'signature');

        if (!$key instanceof EcPublicKey || in_array($key->getCurve(), self::EDWARDS_CURVES, true) || $hash === null || $signature === null) {
            return false;
        }

        return $key->withHash($hash)->verify($certificate->getSignableSection(), mb_substr($signature->value, 1, null, '8bit'));
    }

    private static function isValidAt(X509 $certificate, DateTimeInterface $time): bool
    {
        $notBefore = self::timeOf(self::at($certificate, Choice::class, 'tbsCertificate', 'validity', 'notBefore'));
        $notAfter = self::timeOf(self::at($certificate, Choice::class, 'tbsCertificate', 'validity', 'notAfter'));

        return $notBefore !== null && $notAfter !== null && $time >= $notBefore && $time <= $notAfter;
    }

    private static function isCa(X509 $certificate): bool
    {
        return self::at($certificate->getExtension('id-ce-basicConstraints'), Boolean::class, 'extnValue', 'cA')?->value === true;
    }

    /**
     * The nonce and the SubjectPublicKeyInfo, read from the credential certificate's original bytes:
     * X509::load() replaces the key with a key object, which would encode it again, and decodes extensions
     * with phpseclib's process-wide maps.
     */
    private static function readCredential(string $credentialDer): self
    {
        $tbsCertificate = self::at(ASN1::map(ASN1::decodeBER($credentialDer), Certificate::MAP), Constructed::class, 'tbsCertificate');

        return new self(
            self::nonceIn(self::at($tbsCertificate, Constructed::class, 'extensions')),
            self::at($tbsCertificate, Constructed::class, 'subjectPublicKeyInfo')?->getEncoded() ?? '',
        );
    }

    private static function nonceIn(?Constructed $extensions): ?string
    {
        $count = $extensions === null ? 0 : count($extensions);

        for ($index = 0; $index < $count; ++$index) {
            $id = self::at($extensions, OID::class, $index, 'extnId');

            if ($id !== null && ASN1::getOIDFromName((string) $id) === NonceExtension::OID) {
                $value = self::at($extensions, OctetString::class, $index, 'extnValue');

                return $value === null ? null : NonceExtension::tryDecode($value->value);
            }
        }

        return null;
    }

    private static function timeOf(?Choice $time): ?DateTimeInterface
    {
        return $time === null ? null : self::at($time->value, DateTimeInterface::class);
    }

    /**
     * The value at the path through arrays and phpseclib's ArrayAccess objects, if it is of the class.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return ?T
     */
    private static function at(mixed $value, string $class, int|string ...$path): ?object
    {
        $key = array_shift($path);

        if ($key === null) {
            return $value instanceof $class ? $value : null;
        }

        if (is_array($value)) {
            return self::at($value[$key] ?? null, $class, ...$path);
        }

        return $value instanceof ArrayAccess && $value->offsetExists($key) ? self::at($value[$key], $class, ...$path) : null;
    }
}
