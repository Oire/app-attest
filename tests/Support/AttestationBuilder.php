<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use DateTimeImmutable;
use Oire\AppAttest\Internal\NonceExtension;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\Environment;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\EC\PrivateKey as EcPrivateKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PublicKey as RsaPublicKey;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\X509;
use phpseclib4\Math\BigInteger;
use RuntimeException;

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
 * Makes attestations no genuine vector can provide: its own root, intermediate CA and credential certificate
 * on P-256, and any authenticator data. Test code only, never shipped.
 */
final class AttestationBuilder
{
    public const string DEFAULT_TIME = '2026-01-15T12:00:00Z';
    public const string RECEIPT = 'oire-test-receipt';
    public const string FORMAT = 'apple-appattest';
    public const string KEY_USAGE_OID = '2.5.29.15';
    public const string SUBJECT_KEY_IDENTIFIER_OID = '2.5.29.14';
    public const string AUTHORITY_KEY_IDENTIFIER_OID = '2.5.29.35';
    private const int FLAGS = 0x40;
    private const string NONCE_OID_DER = "\x06\x09\x2a\x86\x48\x86\xf7\x63\x64\x08\x02";

    /**
     * 1.2.840.113635.100.8.99, as long as the nonce extension's OID, which takes its place once phpseclib has
     * written the certificate: phpseclib keeps one extension per OID.
     */
    private const string NONCE_PLACEHOLDER_OID = '1.2.840.113635.100.8.99';
    private const string NONCE_PLACEHOLDER_OID_DER = "\x06\x09\x2a\x86\x48\x86\xf7\x63\x64\x08\x63";

    /**
     * 2.5.29.99, as long as the OIDs of the key usage and key identifier extensions, one of which takes its
     * place once phpseclib has written the certificate.
     */
    private const string REPEATED_PLACEHOLDER_OID = '2.5.29.99';
    private const string REPEATED_PLACEHOLDER_OID_DER = "\x06\x03\x55\x1d\x63";
    private const array REPEATABLE_OID_DER = [
        self::KEY_USAGE_OID => "\x06\x03\x55\x1d\x0f",
        self::SUBJECT_KEY_IDENTIFIER_OID => "\x06\x03\x55\x1d\x0e",
        self::AUTHORITY_KEY_IDENTIFIER_OID => "\x06\x03\x55\x1d\x23",
    ];
    private AppIdentity $app;
    private string $clientDataHash;
    private DateTimeImmutable $time;
    private int $counter = 0;
    private string $aaguid;
    private ?string $credentialId = null;
    private bool $leadingZeroX = false;
    private bool $intermediateIsCa = true;
    private bool $nonceExtension = true;
    private ?string $nonceExtensionDer = null;
    private string $format = self::FORMAT;
    private bool $certificates = true;
    private ?int $authDataLength = null;
    private ?string $credentialPublicKeyPem = null;
    private bool $rootExpired = false;
    private string $intermediateNotBefore = '-1 year';
    private string $intermediateNotAfter = '+5 years';
    private ?BigInteger $intermediateSerialNumber = null;
    private bool $credentialNamingAnotherKey = false;
    private ?BigInteger $credentialAuthorityCertSerialNumber = null;
    private ?string $intermediateExtensionTwice = null;
    private bool $credentialAuthorityKeyIdentifierTwice = false;
    private ?string $unlistedIssuerUrl = null;
    private string $extensions = '';
    private ?string $coseKey = null;
    private bool $intermediateSignedByAnotherKey = false;
    private bool $credentialSignedByAnotherKey = false;
    private ?string $intermediateIssuerName = null;
    private ?string $credentialIssuerName = null;

    /**
     * @var ?list<string>
     */
    private ?array $intermediateKeyUsage = null;
    private bool $rootKeyUsage = true;
    private string $nonceExtensionSuffix = '';
    private bool $nonceExtensionTwice = false;
    private ?string $earlierNonceExtensionDer = null;
    private string $credentialSignatureHash = 'sha256';
    private ?PrivateKey $intermediateKey = null;
    private ?string $credentialSignedAlgorithm = null;

    private function __construct()
    {
        $this->app = TestApp::identity();
        $this->clientDataHash = hash('sha256', 'challenge', true);
        $this->time = new DateTimeImmutable(self::DEFAULT_TIME);
        $this->aaguid = Environment::Development->aaguid();
    }

    public static function create(): self
    {
        return new self();
    }

    public function withApp(AppIdentity $app): self
    {
        $builder = clone $this;
        $builder->app = $app;

        return $builder;
    }

    public function withClientDataHash(string $clientDataHash): self
    {
        $builder = clone $this;
        $builder->clientDataHash = $clientDataHash;

        return $builder;
    }

    /**
     * The time the certificates are valid at; the credential certificate is valid for a day either side.
     */
    public function withTime(DateTimeImmutable $time): self
    {
        $builder = clone $this;
        $builder->time = $time;

        return $builder;
    }

    public function withCounter(int $counter): self
    {
        $builder = clone $this;
        $builder->counter = $counter;

        return $builder;
    }

    public function withEnvironment(Environment $environment): self
    {
        return $this->withAaguid($environment->aaguid());
    }

    public function withAaguid(string $aaguid): self
    {
        $builder = clone $this;
        $builder->aaguid = $aaguid;

        return $builder;
    }

    /**
     * A credentialId other than the key id.
     */
    public function withCredentialId(string $credentialId): self
    {
        $builder = clone $this;
        $builder->credentialId = $credentialId;

        return $builder;
    }

    /**
     * A credential key whose x coordinate starts with a zero byte.
     */
    public function withLeadingZeroX(): self
    {
        $builder = clone $this;
        $builder->leadingZeroX = true;

        return $builder;
    }

    /**
     * An intermediate without basicConstraints that still claims the keyCertSign key usage, so only the CA
     * check refuses the chain.
     */
    public function withIntermediateNotCa(): self
    {
        $builder = clone $this;
        $builder->intermediateIsCa = false;

        return $builder;
    }

    public function withoutNonceExtension(): self
    {
        $builder = clone $this;
        $builder->nonceExtension = false;

        return $builder;
    }

    /**
     * Any DER as the nonce extension's value, such as a malformed one.
     */
    public function withNonceExtensionDer(string $der): self
    {
        $builder = clone $this;
        $builder->nonceExtensionDer = $der;

        return $builder;
    }

    public function withFormat(string $format): self
    {
        $builder = clone $this;
        $builder->format = $format;

        return $builder;
    }

    public function withoutCertificates(): self
    {
        $builder = clone $this;
        $builder->certificates = false;

        return $builder;
    }

    public function withAuthDataTruncatedTo(int $length): self
    {
        $builder = clone $this;
        $builder->authDataLength = $length;

        return $builder;
    }

    /**
     * A credential certificate for another public key than the one authData and the key id are made from,
     * such as an RSA or a P-384 key.
     */
    public function withCredentialPublicKeyPem(string $publicKeyPem): self
    {
        $builder = clone $this;
        $builder->credentialPublicKeyPem = $publicKeyPem;

        return $builder;
    }

    /**
     * A root that expired the day before the builder's time, while the intermediate and the credential
     * certificate are still valid.
     */
    public function withExpiredRoot(): self
    {
        $builder = clone $this;
        $builder->rootExpired = true;

        return $builder;
    }

    /**
     * An intermediate that expired the day before the builder's time, while the root and the credential
     * certificate are still valid.
     */
    public function withExpiredIntermediate(): self
    {
        $builder = clone $this;
        $builder->intermediateNotBefore = '-2 years';
        $builder->intermediateNotAfter = '-1 day';

        return $builder;
    }

    /**
     * An intermediate valid from the day after the builder's time, while the root and the credential
     * certificate are already valid.
     */
    public function withIntermediateNotYetValid(): self
    {
        $builder = clone $this;
        $builder->intermediateNotBefore = '+1 day';
        $builder->intermediateNotAfter = '+5 years';

        return $builder;
    }

    public function withIntermediateSerialNumber(BigInteger $serialNumber): self
    {
        $builder = clone $this;
        $builder->intermediateSerialNumber = $serialNumber;

        return $builder;
    }

    /**
     * A credential certificate signed by the intermediate's key under the intermediate's name, whose
     * authority key identifier names another key.
     */
    public function withCredentialNamingAnotherKey(): self
    {
        $builder = clone $this;
        $builder->credentialNamingAnotherKey = true;

        return $builder;
    }

    /**
     * A credential certificate whose authority key identifier also names this serial number of its issuer.
     */
    public function withCredentialAuthorityCertSerialNumber(BigInteger $serialNumber): self
    {
        $builder = clone $this;
        $builder->credentialAuthorityCertSerialNumber = $serialNumber;

        return $builder;
    }

    /**
     * An intermediate signed by the root with its key usage, or its subject key identifier, twice, with the
     * same value both times.
     */
    public function withIntermediateExtensionTwice(string $oid): self
    {
        if ($oid !== self::KEY_USAGE_OID && $oid !== self::SUBJECT_KEY_IDENTIFIER_OID) {
            throw new RuntimeException('Only the key usage or the subject key identifier can come twice.');
        }

        $builder = clone $this;
        $builder->intermediateExtensionTwice = $oid;

        return $builder;
    }

    /**
     * A credential certificate signed by the intermediate with its authority key identifier twice, naming
     * the intermediate's key both times.
     */
    public function withCredentialAuthorityKeyIdentifierTwice(): self
    {
        $builder = clone $this;
        $builder->credentialAuthorityKeyIdentifierTwice = true;

        return $builder;
    }

    /**
     * A credential certificate issued by a CA the chain does not hold, pointing to it with an
     * authorityInfoAccess caIssuers URL.
     */
    public function withCredentialFromAnUnlistedIssuer(string $caIssuersUrl): self
    {
        $builder = clone $this;
        $builder->unlistedIssuerUrl = $caIssuersUrl;

        return $builder;
    }

    /**
     * Bytes in authData in place of the COSE key the builder encodes for the credential public key.
     */
    public function withCoseKey(string $bytes): self
    {
        $builder = clone $this;
        $builder->coseKey = $bytes;

        return $builder;
    }

    /**
     * Bytes after the credential public key in authData, such as an extensions map (ExtensionsMap).
     */
    public function withExtensions(string $bytes): self
    {
        $builder = clone $this;
        $builder->extensions = $bytes;

        return $builder;
    }

    /**
     * An intermediate that names the root as its issuer, with the root's key identifier, but is signed by
     * another key.
     */
    public function withIntermediateSignedByAnotherKey(): self
    {
        $builder = clone $this;
        $builder->intermediateSignedByAnotherKey = true;

        return $builder;
    }

    /**
     * A credential certificate that names the intermediate as its issuer, with the intermediate's key
     * identifier, but is signed by another key.
     */
    public function withCredentialSignedByAnotherKey(): self
    {
        $builder = clone $this;
        $builder->credentialSignedByAnotherKey = true;

        return $builder;
    }

    /**
     * An intermediate signed by the root's key that names another issuer.
     */
    public function withIntermediateIssuerName(string $commonName): self
    {
        $builder = clone $this;
        $builder->intermediateIssuerName = $commonName;

        return $builder;
    }

    /**
     * A credential certificate signed by the intermediate's key that names another issuer.
     */
    public function withCredentialIssuerName(string $commonName): self
    {
        $builder = clone $this;
        $builder->credentialIssuerName = $commonName;

        return $builder;
    }

    /**
     * A CA intermediate with this key usage in place of the one phpseclib's makeCA() gives it, such as one
     * without keyCertSign.
     *
     * @param list<string> $keyUsage
     */
    public function withIntermediateKeyUsage(array $keyUsage): self
    {
        $builder = clone $this;
        $builder->intermediateKeyUsage = $keyUsage;

        return $builder;
    }

    public function withRootWithoutKeyUsage(): self
    {
        $builder = clone $this;
        $builder->rootKeyUsage = false;

        return $builder;
    }

    /**
     * Bytes after the correct value of the nonce extension.
     */
    public function withNonceExtensionSuffix(string $bytes): self
    {
        $builder = clone $this;
        $builder->nonceExtensionSuffix = $bytes;

        return $builder;
    }

    /**
     * A second nonce extension before the correct one, with this DER as its value or, by default, the correct
     * value again.
     */
    public function withNonceExtensionTwice(?string $earlierDer = null): self
    {
        $builder = clone $this;
        $builder->nonceExtensionTwice = true;
        $builder->earlierNonceExtensionDer = $earlierDer;

        return $builder;
    }

    /**
     * The hash of the intermediate's ECDSA signature on the credential certificate, such as sha1 or sha512.
     */
    public function withCredentialSignatureHash(string $hash): self
    {
        $builder = clone $this;
        $builder->credentialSignatureHash = $hash;

        return $builder;
    }

    /**
     * An intermediate holding this key, such as an RSA or an Ed25519 one, which signs the credential
     * certificate; the signature is still labelled ecdsa-with-SHA256.
     */
    public function withIntermediateKey(PrivateKey $key): self
    {
        $builder = clone $this;
        $builder->intermediateKey = $key;

        return $builder;
    }

    /**
     * A credential certificate whose signed tbsCertificate holds this signature AlgorithmIdentifier (DER)
     * while its signatureAlgorithm is ecdsa-with-SHA256, signed by the intermediate with SHA-256.
     */
    public function withCredentialSignedAlgorithm(string $algorithm): self
    {
        $builder = clone $this;
        $builder->credentialSignedAlgorithm = $algorithm;

        return $builder;
    }

    /**
     * The DER of the nonce extension's value for a nonce.
     *
     * @psalm-pure
     */
    public static function nonceExtensionDer(string $nonce): string
    {
        return "\x30\x24\xa1\x22\x04\x20" . $nonce;
    }

    public function build(): BuiltAttestation
    {
        $rootKey = EcKey::generate();
        $intermediateKey = EcKey::generate();
        $credentialKey = $this->leadingZeroX ? EcKey::generateWithLeadingZeroX() : EcKey::generate();
        $keyId = $credentialKey->keyId();

        $authData = $this->authData($keyId, $credentialKey);
        $nonce = hash('sha256', $authData . $this->clientDataHash, true);

        $rootDn = ['id-at-commonName' => 'Oire Test App Attestation Root CA'];
        $intermediateDn = ['id-at-commonName' => 'Oire Test App Attestation CA'];
        $intermediatePublicKeyPem = $this->intermediateKey?->getPublicKey()->toString('PKCS8') ?? $intermediateKey->publicKeyPem;
        $intermediateExtensions = $this->intermediateExtensions();

        if ($this->intermediateExtensionTwice !== null) {
            $intermediateExtensions[self::REPEATED_PLACEHOLDER_OID] = self::octetString(match ($this->intermediateExtensionTwice) {
                self::KEY_USAGE_OID => "\x03\x02\x01\x86",
                default => "\x04\x14" . self::keyIdentifierOf($intermediatePublicKeyPem),
            });
        }

        $rootDer = self::certificate(
            $rootDn,
            $rootKey->publicKeyPem,
            $rootDn,
            $rootKey->publicKeyPem,
            self::signer($rootKey),
            true,
            $this->time->modify($this->rootExpired ? '-2 years' : '-1 year'),
            $this->time->modify($this->rootExpired ? '-1 day' : '+10 years'),
            $this->rootKeyUsage ? [] : ['id-ce-keyUsage' => null],
        );
        $intermediateDer = self::certificate(
            $intermediateDn,
            $intermediatePublicKeyPem,
            ['id-at-commonName' => $this->intermediateIssuerName ?? $rootDn['id-at-commonName']],
            $rootKey->publicKeyPem,
            self::signer($this->intermediateSignedByAnotherKey ? EcKey::generate() : $rootKey),
            $this->intermediateIsCa,
            $this->time->modify($this->intermediateNotBefore),
            $this->time->modify($this->intermediateNotAfter),
            $intermediateExtensions,
            $this->intermediateSerialNumber,
        );

        if ($this->intermediateExtensionTwice !== null) {
            $intermediateDer = SignedCertificate::signed(
                str_replace(self::REPEATED_PLACEHOLDER_OID_DER, self::REPEATABLE_OID_DER[$this->intermediateExtensionTwice], SignedCertificate::split($intermediateDer)[0]),
                SignedCertificate::ECDSA_WITH_SHA256,
                self::signer($rootKey),
            );
        }

        $credentialExtensions = [];
        $correctNonce = ($this->nonceExtensionDer ?? self::nonceExtensionDer($nonce)) . $this->nonceExtensionSuffix;

        if ($this->nonceExtensionTwice) {
            $credentialExtensions[self::NONCE_PLACEHOLDER_OID] = self::octetString($this->earlierNonceExtensionDer ?? $correctNonce);
        }

        if ($this->nonceExtension) {
            $credentialExtensions[NonceExtension::OID] = self::octetString($correctNonce);
        }

        if ($this->unlistedIssuerUrl !== null) {
            $credentialExtensions['id-pe-authorityInfoAccess'] = [[
                'accessMethod' => 'id-ad-caIssuers',
                'accessLocation' => ['uniformResourceIdentifier' => $this->unlistedIssuerUrl],
            ]];
        }

        if ($this->credentialNamingAnotherKey || $this->credentialAuthorityCertSerialNumber !== null) {
            $authorityKeyIdentifier = ['keyIdentifier' => new OctetString(self::keyIdentifierOf($this->credentialNamingAnotherKey ? EcKey::generate()->publicKeyPem : $intermediatePublicKeyPem))];

            if ($this->credentialAuthorityCertSerialNumber !== null) {
                $authorityKeyIdentifier['authorityCertSerialNumber'] = $this->credentialAuthorityCertSerialNumber;
            }

            $credentialExtensions['id-ce-authorityKeyIdentifier'] = $authorityKeyIdentifier;
        }

        if ($this->credentialAuthorityKeyIdentifierTwice) {
            $credentialExtensions[self::REPEATED_PLACEHOLDER_OID] = self::octetString("\x30\x16\x80\x14" . self::keyIdentifierOf($intermediatePublicKeyPem));
        }

        $unlistedIssuerKey = EcKey::generate();
        $credentialDer = self::certificate(
            ['id-at-commonName' => bin2hex($keyId)],
            $this->credentialPublicKeyPem ?? $credentialKey->publicKeyPem,
            ['id-at-commonName' => $this->unlistedIssuerUrl === null ? $this->credentialIssuerName ?? $intermediateDn['id-at-commonName'] : 'Oire Test Unlisted CA'],
            $this->unlistedIssuerUrl === null ? $intermediatePublicKeyPem : $unlistedIssuerKey->publicKeyPem,
            self::signer(match (true) {
                $this->unlistedIssuerUrl !== null => $unlistedIssuerKey,
                $this->credentialSignedByAnotherKey => EcKey::generate(),
                default => $intermediateKey,
            }, $this->credentialSignatureHash),
            false,
            $this->time->modify('-1 day'),
            $this->time->modify('+1 day'),
            $credentialExtensions,
        );

        if ($this->intermediateKey !== null || $this->credentialSignedAlgorithm !== null || $this->nonceExtensionTwice || $this->credentialAuthorityKeyIdentifierTwice) {
            $tbsCertificate = str_replace(
                [self::NONCE_PLACEHOLDER_OID_DER, self::REPEATED_PLACEHOLDER_OID_DER],
                [self::NONCE_OID_DER, self::REPEATABLE_OID_DER[self::AUTHORITY_KEY_IDENTIFIER_OID]],
                SignedCertificate::split($credentialDer)[0],
            );
            $credentialDer = SignedCertificate::signed(
                $this->credentialSignedAlgorithm === null ? $tbsCertificate : SignedCertificate::withSignedAlgorithm($tbsCertificate, $this->credentialSignedAlgorithm),
                SignedCertificate::ECDSA_WITH_SHA256,
                $this->intermediateKey ?? self::signer($intermediateKey),
            );
        }

        $attStmt = MapObject::create();

        if ($this->certificates) {
            $attStmt->add(
                TextStringObject::create('x5c'),
                ListObject::create([ByteStringObject::create($credentialDer), ByteStringObject::create($intermediateDer)]),
            );
        }

        $attStmt->add(TextStringObject::create('receipt'), ByteStringObject::create(self::RECEIPT));

        if ($this->authDataLength !== null) {
            $authData = mb_substr($authData, 0, $this->authDataLength, '8bit');
        }

        $cbor = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create($this->format))
            ->add(TextStringObject::create('attStmt'), $attStmt)
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return new BuiltAttestation(
            (string) $cbor,
            $keyId,
            $credentialKey->publicKeyPem,
            $this->clientDataHash,
            $this->app,
            $authData,
            self::RECEIPT,
            Pem::fromDer($rootDer, Pem::CERTIFICATE),
            $intermediateDer,
            $credentialDer,
            $this->time,
        );
    }

    /**
     * The COSE key of a P-256 public key as authData carries it: kty EC2, alg ES256, crv P-256, x and y.
     */
    public static function coseKey(EcKey $key): string
    {
        return (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($key->x()))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($key->y()));
    }

    private function authData(string $keyId, EcKey $credentialKey): string
    {
        $credentialId = $this->credentialId ?? $keyId;

        return $this->app->rpIdHash()
            . chr(self::FLAGS)
            . pack('N', $this->counter)
            . $this->aaguid
            . pack('n', mb_strlen($credentialId, '8bit'))
            . $credentialId
            . ($this->coseKey ?? self::coseKey($credentialKey))
            . $this->extensions;
    }

    /**
     * @return array<string, array<array-key, mixed>|null>
     *
     * @psalm-capabilities read-props
     */
    private function intermediateExtensions(): array
    {
        if ($this->intermediateKeyUsage !== null) {
            return ['id-ce-keyUsage' => $this->intermediateKeyUsage];
        }

        return $this->intermediateIsCa ? [] : ['id-ce-keyUsage' => ['keyCertSign']];
    }

    private static function signer(EcKey $key, string $hash = 'sha256'): EcPrivateKey
    {
        $signer = PublicKeyLoader::loadPrivateKey($key->privateKeyPem);

        if (!$signer instanceof EcPrivateKey) {
            throw new RuntimeException('The generated key is not an EC key.');
        }

        return $signer->withHash($hash);
    }

    private static function keyIdentifierOf(string $publicKeyPem): string
    {
        return (new X509(PublicKeyLoader::loadPublicKey($publicKeyPem)))->createSubjectKeyIdentifier();
    }

    private static function octetString(string $der): Element
    {
        return new Element(ASN1::encodeDER($der, ['type' => ASN1::TYPE_OCTET_STRING]));
    }

    /**
     * @param array<string, string>                               $subjectDn
     * @param array<string, string>                               $issuerDn
     * @param string                                              $subjectPublicKeyPem an RSA key is written as rsaEncryption, not phpseclib's RSASSA-PSS
     * @param string                                              $issuerPublicKeyPem  the key the authority key identifier names
     * @param array<string, Element|array<array-key, mixed>|null> $extensions          values by extension id, null to remove one
     * @param ?BigInteger                                         $serialNumber        phpseclib's random one if null
     */
    private static function certificate(
        array $subjectDn,
        string $subjectPublicKeyPem,
        array $issuerDn,
        string $issuerPublicKeyPem,
        PrivateKey $signer,
        bool $ca,
        DateTimeImmutable $notBefore,
        DateTimeImmutable $notAfter,
        array $extensions = [],
        ?BigInteger $serialNumber = null,
    ): string {
        $subjectKey = PublicKeyLoader::loadPublicKey($subjectPublicKeyPem);
        $certificate = new X509($subjectKey instanceof RsaPublicKey ? $subjectKey->withPadding(RSA::SIGNATURE_PKCS1) : $subjectKey);
        $certificate->setSubjectDN($subjectDn);
        $certificate->setIssuerDN($issuerDn);
        $certificate->setStartDate($notBefore);
        $certificate->setEndDate($notAfter);
        $certificate->setAuthorityKeyIdentifier(self::keyIdentifierOf($issuerPublicKeyPem));

        if ($serialNumber !== null) {
            $certificate->setSerialNumber($serialNumber);
        }

        if ($ca) {
            $certificate->makeCA();
        }

        foreach ($extensions as $id => $value) {
            if ($value === null) {
                $certificate->removeExtension($id);
            } else {
                $certificate->setExtension($id, $value);
            }
        }

        $signer->sign($certificate);

        return $certificate->toString(['binary' => true]);
    }
}
