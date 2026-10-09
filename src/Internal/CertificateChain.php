<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use DateTimeInterface;
use Oire\AppAttest\TrustAnchor;
use OpenSSLAsymmetricKey;
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
 * Each certificate is taken apart by the library's own strict DER reader, not by a general X.509 library
 * whose process-wide settings (a CA store, a target date, callbacks, looser issuer matching, lenient decoding)
 * another component could change, so no setting of any library changes what a certificate decodes to or
 * whether a chain passes. Each link is checked signature first: the issuer's ECDSA signature over the
 * original tbsCertificate bytes, then the issuer Name, key usage and key identifiers, the validity period and
 * the intermediate's basicConstraints. Verification makes no network call.
 *
 * Every certificate must be DER, and an x5c entry at most MAX_LENGTH bytes, so its bytes cannot be altered
 * and still pass, ECDSA's own choice of s or n - s aside.
 *
 * @internal
 */
final readonly class CertificateChain
{
    private const int LENGTH = 2;
    private const int MAX_LENGTH = 4096;
    private const string NO_UNUSED_BITS = "\x00";
    private const string BASIC_CONSTRAINTS = "\x55\x1d\x13";
    private const string KEY_USAGE = "\x55\x1d\x0f";
    private const string SUBJECT_KEY_IDENTIFIER = "\x55\x1d\x0e";
    private const string AUTHORITY_KEY_IDENTIFIER = "\x55\x1d\x23";
    private const int KEY_CERT_SIGN = 5;
    private const int KEY_USAGE_BITS = 9;
    private const int KEY_IDENTIFIER_TAG = 0x80;
    private const int AUTHORITY_CERT_ISSUER_TAG = 0xA1;
    private const int AUTHORITY_CERT_SERIAL_NUMBER_TAG = 0x82;

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
     */
    public static function tryValidate(array $certificates, TrustAnchor $anchor, DateTimeInterface $time): ?self
    {
        if (count($certificates) !== self::LENGTH || !isset($certificates[0], $certificates[1])) {
            return null;
        }

        $credentialDer = $certificates[0];
        $intermediateDer = $certificates[1];
        $rootDer = Pem::tryDecode($anchor->pem, Pem::CERTIFICATE);

        if ($rootDer === null || !Der::isOneSequence($intermediateDer, self::MAX_LENGTH) || !Der::isOneSequence($credentialDer, self::MAX_LENGTH)) {
            return null;
        }

        try {
            return ErrorGuard::call(static function() use ($credentialDer, $intermediateDer, $rootDer, $time): ?self {
                $root = Certificate::tryParse($rootDer);
                $intermediate = Certificate::tryParse($intermediateDer);
                $credential = Certificate::tryParse($credentialDer);

                if ($root === null || $intermediate === null || $credential === null) {
                    return null;
                }

                if (!self::isSignedBy($intermediate, $root) || !self::isSignedBy($credential, $intermediate)) {
                    return null;
                }

                if (
                    !self::isValidAt($root, $time)
                    || !self::isValidAt($intermediate, $time)
                    || !self::isValidAt($credential, $time)
                    || !self::isIssuerOf($root, $intermediate)
                    || !self::isCa($intermediate)
                    || !self::isIssuerOf($intermediate, $credential)
                ) {
                    return null;
                }

                return new self(self::nonceIn($credential), $credential->subjectPublicKeyInfo);
            });
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Whether the bytes are a certificate that can anchor a chain: it holds an EC key other than an Edwards
     * one, and its key usage includes keyCertSign, which the chain requires of every issuer.
     */
    public static function canAnchor(string $rootDer): bool
    {
        try {
            return ErrorGuard::call(static function() use ($rootDer): bool {
                $root = Certificate::tryParse($rootDer);

                return $root !== null && self::ecKeyOf($root) !== null && self::canSignCertificates($root);
            });
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Whether the issuer's EC key signed the certificate with ECDSA, under the same AlgorithmIdentifier
     * inside and outside the signed tbsCertificate. openssl_verify() refuses a signature that is not strict
     * DER.
     *
     * @psalm-pure
     */
    private static function isSignedBy(Certificate $certificate, Certificate $issuer): bool
    {
        $hash = self::SIGNATURE_HASHES[$certificate->signatureAlgorithm] ?? null;
        $key = self::ecKeyOf($issuer);

        return $hash !== null
            && $key !== null
            && $certificate->signedAlgorithm === $certificate->signatureAlgorithm
            && mb_substr($certificate->signature, 0, 1, '8bit') === self::NO_UNUSED_BITS
            && openssl_verify($certificate->tbsCertificate, mb_substr($certificate->signature, 1, null, '8bit'), $key, $hash) === 1;
    }

    /**
     * The certificate's public key, if it is an EC key: OpenSSL reports Edwards keys as another type.
     *
     * @psalm-pure
     */
    private static function ecKeyOf(Certificate $certificate): ?OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public(Pem::encode($certificate->subjectPublicKeyInfo, Pem::PUBLIC_KEY));
        $details = $key === false ? false : openssl_pkey_get_details($key);

        return $key !== false && is_array($details) && ($details['type'] ?? null) === OPENSSL_KEYTYPE_EC ? $key : null;
    }

    /**
     * @psalm-pure
     */
    private static function isValidAt(Certificate $certificate, DateTimeInterface $time): bool
    {
        return $time >= $certificate->notBefore && $time <= $certificate->notAfter;
    }

    /**
     * Whether the issuer issued the certificate, its signature aside. The certificate's issuer Name must be
     * byte for byte the issuer's subject Name, as RFC 5280 requires a CA to encode it, rather than equal after
     * a normalization: no setting can loosen the match, and the bytes are those the signatures cover. The
     * issuer's key usage must include keyCertSign. An authority key identifier must name the issuer's subject
     * key identifier when the issuer has one, and the issuer's serial number when it holds one. Each of these
     * extensions may appear only once, as RFC 5280 requires.
     *
     * @psalm-capabilities read-props
     */
    private static function isIssuerOf(Certificate $issuer, Certificate $certificate): bool
    {
        return $issuer->subject === $certificate->issuer
            && self::canSignCertificates($issuer)
            && self::keyIdentifiersMatch($issuer, $certificate);
    }

    /**
     * Whether the certificate has one key usage extension, a KeyUsage BIT STRING in DER with its trailing
     * zero bits removed and none past decipherOnly, and it includes keyCertSign.
     *
     * @psalm-capabilities read-props
     */
    private static function canSignCertificates(Certificate $certificate): bool
    {
        $values = $certificate->extensionValues(self::KEY_USAGE);
        $keyUsage = count($values) === 1 && isset($values[0]) ? Der::tryOne($values[0]) : null;

        if (!Der::isBitString($keyUsage)) {
            return false;
        }

        $bits = Der::bitCount($keyUsage);

        return $bits <= self::KEY_USAGE_BITS && Der::isBitSet($keyUsage, self::KEY_CERT_SIGN) && Der::isBitSet($keyUsage, $bits - 1);
    }

    /**
     * @psalm-capabilities read-props
     */
    private static function keyIdentifiersMatch(Certificate $issuer, Certificate $certificate): bool
    {
        $authorityKeyIdentifiers = $certificate->extensionValues(self::AUTHORITY_KEY_IDENTIFIER);
        $subjectKeyIdentifiers = $issuer->extensionValues(self::SUBJECT_KEY_IDENTIFIER);

        if (count($authorityKeyIdentifiers) > 1 || count($subjectKeyIdentifiers) > 1) {
            return false;
        }

        if (!isset($authorityKeyIdentifiers[0])) {
            return true;
        }

        $authority = self::authorityKeyIdentifierOf($authorityKeyIdentifiers[0]);

        if ($authority === null) {
            return false;
        }

        [$keyIdentifier, $serialNumber] = $authority;

        if ($serialNumber !== null && $serialNumber !== $issuer->serialNumber) {
            return false;
        }

        if (!isset($subjectKeyIdentifiers[0])) {
            return true;
        }

        $subjectKeyIdentifier = Der::tryOne($subjectKeyIdentifiers[0]);

        return $keyIdentifier !== null && Der::hasTag($subjectKeyIdentifier, Der::OCTET_STRING) && hash_equals($subjectKeyIdentifier->content, $keyIdentifier);
    }

    /**
     * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL,
     * authorityCertIssuer [1] IMPLICIT GeneralNames OPTIONAL, authorityCertSerialNumber [2] IMPLICIT INTEGER
     * OPTIONAL }, as its key identifier and serial number content, or null if the value is not one.
     *
     * @return ?array{?string, ?string}
     *
     * @psalm-pure
     */
    private static function authorityKeyIdentifierOf(string $value): ?array
    {
        $fields = Der::tryOne($value)?->children(Der::SEQUENCE);

        if ($fields === null) {
            return null;
        }

        $keyIdentifier = Der::hasTag($fields[0] ?? null, self::KEY_IDENTIFIER_TAG) ? array_shift($fields)?->content : null;

        if (($fields[0] ?? null)?->children(self::AUTHORITY_CERT_ISSUER_TAG) !== null) {
            array_shift($fields);
        }

        $serialNumber = Der::isInteger($fields[0] ?? null, self::AUTHORITY_CERT_SERIAL_NUMBER_TAG) ? array_shift($fields)?->content : null;

        return $fields === [] ? [$keyIdentifier, $serialNumber] : null;
    }

    /**
     * Whether the certificate has one basicConstraints extension, BasicConstraints ::= SEQUENCE { cA BOOLEAN
     * DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL } in DER, with cA true.
     *
     * @psalm-capabilities read-props
     */
    private static function isCa(Certificate $certificate): bool
    {
        $values = $certificate->extensionValues(self::BASIC_CONSTRAINTS);
        $fields = count($values) === 1 && isset($values[0]) ? Der::tryOne($values[0])?->children(Der::SEQUENCE) : null;

        return $fields !== null
            && count($fields) <= 2
            && Der::isTrue($fields[0] ?? null)
            && (count($fields) === 1 || Der::isNonNegativeInteger($fields[1] ?? null));
    }

    /**
     * The nonce, or null unless the credential certificate holds exactly one nonce extension.
     *
     * @psalm-capabilities read-props
     */
    private static function nonceIn(Certificate $credential): ?string
    {
        $values = $credential->extensionValues(NonceExtension::OBJECT_IDENTIFIER);

        return count($values) === 1 && isset($values[0]) ? NonceExtension::tryDecode($values[0]) : null;
    }
}
