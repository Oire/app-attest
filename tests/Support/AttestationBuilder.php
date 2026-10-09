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
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\X509;
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
    public const string NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';

    /**
     * The nonce extension's value: SEQUENCE { [1] EXPLICIT OCTET STRING }.
     */
    public const array NONCE_EXTENSION_MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'nonce' => [
                'constant' => 1,
                'explicit' => true,
                'type' => ASN1::TYPE_OCTET_STRING,
            ],
        ],
    ];
    public const string DEFAULT_TIME = '2026-01-15T12:00:00Z';
    public const string RECEIPT = 'oire-test-receipt';
    private const string FORMAT = 'apple-appattest';
    private const int FLAGS = 0x40;
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

    private function __construct()
    {
        $this->app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));
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
        X509::registerExtension(self::NONCE_EXTENSION_OID, self::NONCE_EXTENSION_MAP);

        $rootKey = EcKey::generate();
        $intermediateKey = EcKey::generate();
        $credentialKey = $this->leadingZeroX ? EcKey::generateWithLeadingZeroX() : EcKey::generate();
        $keyId = $credentialKey->keyId();

        $authData = $this->authData($keyId, $credentialKey);
        $nonce = hash('sha256', $authData . $this->clientDataHash, true);

        $rootDn = ['id-at-commonName' => 'Oire Test App Attestation Root CA'];
        $intermediateDn = ['id-at-commonName' => 'Oire Test App Attestation CA'];
        $rootDer = self::certificate($rootDn, $rootKey, $rootDn, $rootKey, true, $this->time->modify('-1 year'), $this->time->modify('+10 years'));
        $intermediateDer = self::certificate(
            $intermediateDn,
            $intermediateKey,
            $rootDn,
            $rootKey,
            $this->intermediateIsCa,
            $this->time->modify('-1 year'),
            $this->time->modify('+5 years'),
        );
        $credentialDer = self::certificate(
            ['id-at-commonName' => bin2hex($keyId)],
            $credentialKey,
            $intermediateDn,
            $intermediateKey,
            false,
            $this->time->modify('-1 day'),
            $this->time->modify('+1 day'),
            $this->nonceExtension ? $this->nonceExtensionDer ?? self::nonceExtensionDer($nonce) : null,
        );

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
            self::pem($rootDer),
            $intermediateDer,
            $credentialDer,
            $this->time,
        );
    }

    private function authData(string $keyId, EcKey $credentialKey): string
    {
        $credentialId = $this->credentialId ?? $keyId;
        $coseKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($credentialKey->x()))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($credentialKey->y()));

        return $this->app->rpIdHash()
            . chr(self::FLAGS)
            . pack('N', $this->counter)
            . $this->aaguid
            . pack('n', mb_strlen($credentialId, '8bit'))
            . $credentialId
            . (string) $coseKey;
    }

    /**
     * @param array<string, string> $subjectDn
     * @param array<string, string> $issuerDn
     */
    private static function certificate(
        array $subjectDn,
        EcKey $subjectKey,
        array $issuerDn,
        EcKey $issuerKey,
        bool $ca,
        DateTimeImmutable $notBefore,
        DateTimeImmutable $notAfter,
        ?string $nonceExtensionDer = null,
    ): string {
        $publicKey = PublicKeyLoader::loadPublicKey($subjectKey->publicKeyPem);
        $privateKey = PublicKeyLoader::loadPrivateKey($issuerKey->privateKeyPem);

        if (!$publicKey instanceof PublicKey || !$privateKey instanceof PrivateKey) {
            throw new RuntimeException('Cannot load the generated keys into phpseclib.');
        }

        $subject = new X509();
        $subject->setDN($subjectDn);
        $subject->setPublicKey($publicKey);

        $issuer = new X509();
        $issuer->setDN($issuerDn);
        $issuer->setPrivateKey($privateKey);

        $certificate = new X509();
        $certificate->setStartDate($notBefore);
        $certificate->setEndDate($notAfter);

        if ($ca) {
            $certificate->makeCA();
        }

        if ($nonceExtensionDer !== null) {
            $certificate->setExtensionValue(self::NONCE_EXTENSION_OID, new Element($nonceExtensionDer));
        }

        return self::der($certificate, $certificate->sign($issuer, $subject));
    }

    private static function der(X509 $certificate, mixed $signed): string
    {
        $der = is_array($signed) ? $certificate->saveX509($signed, X509::FORMAT_DER) : false;

        if (!is_string($der)) {
            throw new RuntimeException('Cannot sign the test certificate.');
        }

        return $der;
    }

    /**
     * @psalm-pure
     */
    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }
}
