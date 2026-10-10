<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use DateTimeInterface;
use ErrorException;
use Oire\AppAttest\TrustAnchor;
use OpenSSLAsymmetricKey;

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
 * the intermediate's basicConstraints. The credential certificate, an end entity, may hold one well-formed
 * keyUsage and one basicConstraints that leaves cA FALSE, and every key identifier of the intermediate and
 * the credential certificate must be well-formed. Each certificate may mark critical only the
 * extensions the chain processes for it, as RFC 5280 requires: basicConstraints, key usage and the key
 * identifiers for the intermediate, these and the nonce extension for the credential certificate. The root, a
 * trust anchor, is not checked for them. Verification makes no network call.
 *
 * Every certificate must be DER, and an x5c entry at most MAX_LENGTH bytes, so its bytes cannot be altered
 * and still pass, ECDSA's own choice of s or n - s aside.
 *
 * The checks run under ErrorGuard, which turns a warning OpenSSL might raise on hostile input into a refused
 * chain; any other exception, such as Der's LogicException for a broken invariant, is not caught.
 *
 * @internal
 */
final readonly class CertificateChain
{
    private const int LENGTH = 2;
    private const int MAX_LENGTH = 4096;
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
     * The extensions the chain processes for the intermediate, the only ones it may mark critical.
     */
    private const array INTERMEDIATE_EXTENSIONS = [
        self::BASIC_CONSTRAINTS,
        self::KEY_USAGE,
        self::SUBJECT_KEY_IDENTIFIER,
        self::AUTHORITY_KEY_IDENTIFIER,
    ];

    /**
     * The extensions the chain processes for the credential certificate, the only ones it may mark critical.
     */
    private const array CREDENTIAL_EXTENSIONS = [
        self::BASIC_CONSTRAINTS,
        self::KEY_USAGE,
        self::SUBJECT_KEY_IDENTIFIER,
        self::AUTHORITY_KEY_IDENTIFIER,
        NonceExtension::OBJECT_IDENTIFIER,
    ];

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

        if ($rootDer === null || mb_strlen($intermediateDer, '8bit') > self::MAX_LENGTH || mb_strlen($credentialDer, '8bit') > self::MAX_LENGTH) {
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
                    !self::marksCriticalOnly($intermediate, self::INTERMEDIATE_EXTENSIONS)
                    || !self::marksCriticalOnly($credential, self::CREDENTIAL_EXTENSIONS)
                    || !self::isValidAt($root, $time)
                    || !self::isValidAt($intermediate, $time)
                    || !self::isValidAt($credential, $time)
                    || !self::isIssuerOf($root, $intermediate)
                    || !self::isCa($intermediate)
                    || !self::hasWellFormedKeyIdentifiers($intermediate)
                    || !self::isIssuerOf($intermediate, $credential)
                    || !self::isEndEntity($credential)
                    || !self::hasWellFormedKeyIdentifiers($credential)
                ) {
                    return null;
                }

                return new self(self::nonceIn($credential), $credential->subjectPublicKeyInfo);
            });
        } catch (ErrorException) {
            return null;
        }
    }

    /**
     * Whether the certificate can anchor a chain: it holds an EC key other than an Edwards one, and its key
     * usage includes keyCertSign, which the chain requires of every issuer.
     */
    public static function canAnchor(Certificate $root): bool
    {
        try {
            return ErrorGuard::call(static fn(): bool => self::ecKeyOf($root) !== null && self::canSignCertificates($root));
        } catch (ErrorException) {
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
            && openssl_verify($certificate->tbsCertificate, $certificate->signature, $key, $hash) === 1;
    }

    /**
     * @param list<string> $processed the extensions the chain processes for this certificate
     *
     * @psalm-capabilities read-props
     */
    private static function marksCriticalOnly(Certificate $certificate, array $processed): bool
    {
        return array_diff($certificate->criticalExtensionIdentifiers(), $processed) === [];
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
        return hash_equals($issuer->subject, $certificate->issuer)
            && self::canSignCertificates($issuer)
            && self::keyIdentifiersMatch($issuer, $certificate);
    }

    /**
     * Whether the certificate has one key usage extension, well-formed, and it includes keyCertSign.
     *
     * @psalm-capabilities read-props
     */
    private static function canSignCertificates(Certificate $certificate): bool
    {
        $values = $certificate->extensionValues(self::KEY_USAGE);
        $keyUsage = count($values) === 1 && isset($values[0]) ? self::keyUsageOf($values[0]) : null;

        return $keyUsage !== null && Der::isBitSet($keyUsage, self::KEY_CERT_SIGN);
    }

    /**
     * A KeyUsage BIT STRING in DER, its trailing zero bits removed, at least one bit set and none past
     * decipherOnly, or null if the value is not one.
     *
     * @psalm-pure
     */
    private static function keyUsageOf(string $value): ?DerElement
    {
        $keyUsage = Der::tryOne($value);

        if (!Der::isBitString($keyUsage)) {
            return null;
        }

        $bits = Der::bitCount($keyUsage);

        return $bits <= self::KEY_USAGE_BITS && Der::isBitSet($keyUsage, $bits - 1) ? $keyUsage : null;
    }

    /**
     * Whether the certificate holds at most one subject key identifier, a DER OCTET STRING, and at most one
     * authority key identifier, a DER AuthorityKeyIdentifier, whether or not the chain matches them.
     *
     * @psalm-capabilities read-props
     */
    private static function hasWellFormedKeyIdentifiers(Certificate $certificate): bool
    {
        $subjectKeyIdentifiers = $certificate->extensionValues(self::SUBJECT_KEY_IDENTIFIER);
        $authorityKeyIdentifiers = $certificate->extensionValues(self::AUTHORITY_KEY_IDENTIFIER);

        return count($subjectKeyIdentifiers) <= 1
            && count($authorityKeyIdentifiers) <= 1
            && (!isset($subjectKeyIdentifiers[0]) || Der::hasTag(Der::tryOne($subjectKeyIdentifiers[0]), Der::OCTET_STRING))
            && (!isset($authorityKeyIdentifiers[0]) || self::authorityKeyIdentifierOf($authorityKeyIdentifiers[0]) !== null);
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

        if ($serialNumber !== null && !hash_equals($issuer->serialNumber, $serialNumber)) {
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
     * Whether the certificate has one basicConstraints extension, well-formed, with cA TRUE.
     *
     * @psalm-capabilities read-props
     */
    private static function isCa(Certificate $certificate): bool
    {
        $values = $certificate->extensionValues(self::BASIC_CONSTRAINTS);
        $basicConstraints = count($values) === 1 && isset($values[0]) ? self::basicConstraintsOf($values[0]) : null;

        return $basicConstraints !== null && $basicConstraints[0];
    }

    /**
     * Whether the certificate holds at most one key usage extension and at most one basicConstraints
     * extension, each well-formed, critical or not, and its basicConstraints, if any, is empty: cA FALSE and no
     * pathLenConstraint, which RFC 5280 allows only with cA TRUE.
     *
     * @psalm-capabilities read-props
     */
    private static function isEndEntity(Certificate $certificate): bool
    {
        $keyUsages = $certificate->extensionValues(self::KEY_USAGE);
        $basicConstraints = $certificate->extensionValues(self::BASIC_CONSTRAINTS);

        return count($keyUsages) <= 1
            && count($basicConstraints) <= 1
            && (!isset($keyUsages[0]) || self::keyUsageOf($keyUsages[0]) !== null)
            && (!isset($basicConstraints[0]) || self::basicConstraintsOf($basicConstraints[0]) === [false, false]);
    }

    /**
     * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
     * in DER, which leaves out a FALSE cA, as whether cA is TRUE and whether a pathLenConstraint is present,
     * or null if the value is not one.
     *
     * @return ?array{bool, bool}
     *
     * @psalm-pure
     */
    private static function basicConstraintsOf(string $value): ?array
    {
        $fields = Der::tryOne($value)?->children(Der::SEQUENCE);

        if ($fields === null) {
            return null;
        }

        $ca = Der::isTrue($fields[0] ?? null);

        if ($ca) {
            array_shift($fields);
        }

        $pathLength = Der::isNonNegativeInteger($fields[0] ?? null);

        if ($pathLength) {
            array_shift($fields);
        }

        return $fields === [] ? [$ca, $pathLength] : null;
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
