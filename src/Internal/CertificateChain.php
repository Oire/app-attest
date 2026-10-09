<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use ArrayAccess;
use DateTimeInterface;
use LogicException;
use Oire\AppAttest\TrustAnchor;
use OpenSSLAsymmetricKey;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps\BasicConstraints;
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
 * is a CA. So each link is checked here instead, signatures first: the issuer's ECDSA signature over the
 * original tbsCertificate bytes, then phpseclib's issuer matching (names, key identifiers, key usage), the
 * validity period and the intermediate's basicConstraints. Verification makes no network call and leaves
 * phpseclib's CA store alone.
 *
 * Every certificate must be exactly one DER SEQUENCE, and an x5c entry at most MAX_LENGTH bytes, before
 * phpseclib reads it: phpseclib ignores bytes after the first element. The signatures are checked on a
 * rule-less ASN1::map() of each certificate, and only then is it loaded with X509::load(), which hands the
 * SubjectPublicKeyInfo to phpseclib's key parsers. A certificate must also be exactly the DER encoding of its
 * three parts and its signature strict DER, so its bytes cannot be altered and still pass, ECDSA's own choice
 * of s or n - s aside.
 *
 * @internal
 */
final readonly class CertificateChain
{
    private const int LENGTH = 2;
    private const int MAX_LENGTH = 4096;
    private const string SEQUENCE_TAG = "\x30";
    private const string BIT_STRING_TAG = "\x03";
    private const string NO_UNUSED_BITS = "\x00";
    private const string BASIC_CONSTRAINTS_OID = '2.5.29.19';

    /**
     * Hashes by the DER AlgorithmIdentifier of ecdsa-with-SHA256, -SHA384 and -SHA512, with the parameters
     * absent as RFC 5758 requires.
     */
    private const array SIGNATURE_HASHES = [
        "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02" => 'sha256',
        "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03" => 'sha384',
        "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04" => 'sha512',
    ];

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
     * @throws LogicException if the process has registered a phpseclib map for the nonce extension
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

        NonceExtension::assertNoRegisteredMap();

        try {
            return ErrorGuard::call(static function() use ($credentialDer, $intermediateDer, $rootDer, $time): ?self {
                $root = self::mapped($rootDer);
                $intermediate = self::mapped($intermediateDer);
                $credential = self::mapped($credentialDer);

                if (!self::isSignedBy($intermediateDer, $intermediate, $root) || !self::isSignedBy($credentialDer, $credential, $intermediate)) {
                    return null;
                }

                $intermediateCertificate = X509::load($intermediateDer, ASN1::FORMAT_DER);

                if (
                    !self::isValidAt($root, $time)
                    || !self::isValidAt($intermediate, $time)
                    || !self::isValidAt($credential, $time)
                    || !X509::load($rootDer, ASN1::FORMAT_DER)->isIssuerOf($intermediateCertificate)
                    || !self::isCa($intermediate)
                    || !$intermediateCertificate->isIssuerOf(X509::load($credentialDer, ASN1::FORMAT_DER))
                ) {
                    return null;
                }

                return new self(
                    self::nonceIn($credential),
                    self::at($credential, Constructed::class, 'tbsCertificate', 'subjectPublicKeyInfo')?->getEncoded() ?? '',
                );
            });
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Whether the certificate can anchor a chain: it holds an EC key other than an Edwards one, and its key
     * usage includes keyCertSign, which phpseclib's isIssuerOf() requires of an issuer.
     */
    public static function canAnchor(string $rootDer): bool
    {
        try {
            return ErrorGuard::call(static function() use ($rootDer): bool {
                $keyUsage = self::at(X509::load($rootDer, ASN1::FORMAT_DER)->getExtension('id-ce-keyUsage'), BitString::class, 'extnValue');

                return self::ecKeyOf(self::mapped($rootDer)) !== null && $keyUsage?->contains('keyCertSign') === true;
            });
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The certificate mapped without phpseclib's X509 rules, so nothing in it is parsed as a key and its
     * parts keep their original bytes.
     */
    private static function mapped(string $der): ?Constructed
    {
        $certificate = ASN1::map(ASN1::decodeBER($der), Certificate::MAP);

        return $certificate instanceof Constructed ? $certificate : null;
    }

    /**
     * Whether the issuer's EC key signed the certificate with ECDSA. The certificate must be exactly the DER
     * encoding of its parts, with the same AlgorithmIdentifier inside and outside the signed tbsCertificate,
     * and openssl_verify() refuses a signature that is not strict DER.
     */
    private static function isSignedBy(string $der, ?Constructed $certificate, ?Constructed $issuer): bool
    {
        $tbsCertificate = self::at($certificate, Constructed::class, 'tbsCertificate');
        $signedAlgorithm = self::at($tbsCertificate, Constructed::class, 'signature')?->getEncoded();
        $algorithm = self::at($certificate, Constructed::class, 'signatureAlgorithm')?->getEncoded();
        $bitString = self::at($certificate, BitString::class, 'signature');
        $signature = self::signatureBytesOf($bitString);
        $hash = $algorithm === null ? null : self::SIGNATURE_HASHES[$algorithm] ?? null;
        $key = self::ecKeyOf($issuer);

        if ($tbsCertificate === null || $algorithm === null || $bitString === null || $signature === null || $hash === null || $key === null || $signedAlgorithm !== $algorithm) {
            return false;
        }

        $tbsDer = $tbsCertificate->getEncoded();

        return $der === self::encoded(self::SEQUENCE_TAG, $tbsDer . $algorithm . self::encoded(self::BIT_STRING_TAG, $bitString->value))
            && openssl_verify($tbsDer, $signature, $key, $hash) === 1;
    }

    /**
     * The signature BIT STRING's bytes, or null unless its leading unused-bits octet declares none.
     *
     * @psalm-capabilities read-props
     */
    private static function signatureBytesOf(?BitString $signature): ?string
    {
        if ($signature === null || mb_substr($signature->value, 0, 1, '8bit') !== self::NO_UNUSED_BITS) {
            return null;
        }

        return mb_substr($signature->value, 1, null, '8bit');
    }

    /**
     * The certificate's public key, if it is an EC key: OpenSSL reports Edwards keys as another type.
     */
    private static function ecKeyOf(?Constructed $certificate): ?OpenSSLAsymmetricKey
    {
        $subjectPublicKeyInfo = self::at($certificate, Constructed::class, 'tbsCertificate', 'subjectPublicKeyInfo');
        $key = $subjectPublicKeyInfo === null ? false : openssl_pkey_get_public(Pem::encode($subjectPublicKeyInfo->getEncoded(), Pem::PUBLIC_KEY));
        $details = $key === false ? false : openssl_pkey_get_details($key);

        return $key !== false && is_array($details) && ($details['type'] ?? null) === OPENSSL_KEYTYPE_EC ? $key : null;
    }

    private static function encoded(string $tag, string $content): string
    {
        return $tag . ASN1::encodeLength(mb_strlen($content, '8bit')) . $content;
    }

    private static function isValidAt(?Constructed $certificate, DateTimeInterface $time): bool
    {
        $notBefore = self::timeOf(self::at($certificate, Choice::class, 'tbsCertificate', 'validity', 'notBefore'));
        $notAfter = self::timeOf(self::at($certificate, Choice::class, 'tbsCertificate', 'validity', 'notAfter'));

        return $notBefore !== null && $notAfter !== null && $time >= $notBefore && $time <= $notAfter;
    }

    private static function isCa(?Constructed $certificate): bool
    {
        $basicConstraints = self::extensionValues($certificate, self::BASIC_CONSTRAINTS_OID)[0] ?? null;

        return $basicConstraints !== null
            && self::at(ASN1::map(ASN1::decodeBER($basicConstraints), BasicConstraints::MAP), Boolean::class, 'cA')?->value === true;
    }

    /**
     * The nonce, or null unless the credential certificate holds exactly one nonce extension.
     */
    private static function nonceIn(?Constructed $credential): ?string
    {
        $values = self::extensionValues($credential, NonceExtension::OID);

        return count($values) === 1 && isset($values[0]) ? NonceExtension::tryDecode($values[0]) : null;
    }

    /**
     * The value of every extension with the OID, matched by the dotted OID rather than phpseclib's name.
     *
     * @return list<?string>
     */
    private static function extensionValues(?Constructed $certificate, string $oid): array
    {
        $extensions = self::at($certificate, Constructed::class, 'tbsCertificate', 'extensions');
        $count = $extensions === null ? 0 : count($extensions);
        $values = [];

        for ($index = 0; $index < $count; ++$index) {
            $id = self::at($extensions, OID::class, $index, 'extnId');

            if ($id !== null && ASN1::getOIDFromName((string) $id) === $oid) {
                $values[] = self::at($extensions, OctetString::class, $index, 'extnValue')?->value;
            }
        }

        return $values;
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
