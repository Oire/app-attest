<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use Closure;
use InvalidArgumentException;
use LogicException;
use Oire\AppAttest\Tests\Support\AttestationBuilder;
use Oire\AppAttest\Tests\Support\Damage;
use Oire\AppAttest\Tests\Support\Damaged;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\Tests\Support\RsaKey;
use Oire\AppAttest\TrustAnchor;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\EC;
use phpseclib4\File\X509;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

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
final class TrustAnchorTest extends TestCase
{
    private const string BUNDLED_ROOT_PATH = __DIR__ . '/../resources/Apple_App_Attestation_Root_CA.pem';
    private const string APPLE_ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932';

    public function testBundledRootMatchesThePinnedFingerprint(): void
    {
        self::assertSame(self::APPLE_ROOT_SHA256, TrustAnchor::APPLE_ROOT_SHA256);
        self::assertSame(TrustAnchor::APPLE_ROOT_SHA256, openssl_x509_fingerprint(self::bundledRoot(), 'sha256'));
    }

    public function testAppleLoadsTheBundledRoot(): void
    {
        self::assertSame(self::bundledRoot(), TrustAnchor::apple()->pem);
    }

    public function testTamperedRootFailsThePinnedCheck(): void
    {
        $der = Pem::toDer(self::bundledRoot());
        $der[-1] = chr(ord($der[-1]) ^ 0x01);
        $tampered = Pem::fromDer($der, Pem::CERTIFICATE);

        self::assertNotFalse(openssl_x509_read($tampered));

        $this->expectException(LogicException::class);
        TrustAnchor::fromPinnedPem($tampered, TrustAnchor::APPLE_ROOT_SHA256);
    }

    public function testGarbageFailsThePinnedCheck(): void
    {
        $this->expectException(LogicException::class);
        TrustAnchor::fromPinnedPem('garbage', TrustAnchor::APPLE_ROOT_SHA256);
    }

    public function testFromPemKeepsTheCertificate(): void
    {
        self::assertSame(self::bundledRoot(), TrustAnchor::fromPem(self::bundledRoot())->pem);
    }

    #[DataProvider('provideInvalidPem')]
    public function testFromPemRefusesAnythingButOneCertificate(string $pem): void
    {
        $this->expectException(InvalidArgumentException::class);
        TrustAnchor::fromPem($pem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidPem(): iterable
    {
        yield 'empty' => [''];
        yield 'garbage' => ['garbage'];
        yield 'not base64' => ["-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"];
        yield 'not a certificate' => ["-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n"];
        yield 'two certificates' => [self::bundledRoot() . self::bundledRoot()];
        yield 'a certificate with a trailing byte' => [Pem::fromDer(Pem::toDer(self::bundledRoot()) . "\x00", Pem::CERTIFICATE)];
        yield 'an indefinite-length certificate' => [Pem::fromDer("\x30\x80" . mb_substr(Pem::toDer(self::bundledRoot()), 4, null, '8bit') . "\x00\x00", Pem::CERTIFICATE)];
        yield 'an empty sequence' => [Pem::fromDer("\x30\x00", Pem::CERTIFICATE)];
        yield 'a sequence holding an integer' => [Pem::fromDer("\x30\x03\x02\x01\x00", Pem::CERTIFICATE)];
    }

    public function testFromPemAcceptsAnEcRootThatCanSignCertificates(): void
    {
        $root = self::selfSignedRoot(EC::createKey('secp384r1')->withHash('sha384'));

        self::assertSame($root, TrustAnchor::fromPem($root)->pem);
    }

    /**
     * @return iterable<string, array{Closure(): string}>
     */
    public static function provideRootsNoChainCanLeadTo(): iterable
    {
        yield 'an RSA root' => [static fn(): string => self::selfSignedRoot(RsaKey::generate())];
        yield 'an Ed25519 root' => [static fn(): string => self::selfSignedRoot(EC::createKey('Ed25519'))];
        yield 'an EC root without key usage' => [static fn(): string => AttestationBuilder::create()->withRootWithoutKeyUsage()->build()->rootPem];
        yield 'an EC root whose key usage lacks keyCertSign' => [static fn(): string => self::selfSignedRoot(EC::createKey('secp256r1')->withHash('sha256'), ['digitalSignature', 'cRLSign'])];
    }

    /**
     * @param Closure(): string $root
     */
    #[DataProvider('provideRootsNoChainCanLeadTo')]
    public function testFromPemRefusesARootNoChainCanLeadTo(Closure $root): void
    {
        $pem = $root();

        self::assertNotFalse(openssl_x509_read($pem));

        $this->expectException(InvalidArgumentException::class);
        TrustAnchor::fromPem($pem);
    }

    public function testDamagedRootIsRefusedWithoutAPhpError(): void
    {
        $outcomes = Damage::withoutPhpErrors(static fn(): array => array_map(
            static fn(Damaged $d): string => self::fromPemOutcome(Pem::fromDer($d->bytes, Pem::CERTIFICATE)),
            Damage::of(Pem::toDer(self::bundledRoot()), [0x01, 0x80, 0xFF], 3),
        ));

        self::assertContains('refused', $outcomes);
    }

    private static function fromPemOutcome(string $pem): string
    {
        try {
            TrustAnchor::fromPem($pem);

            return 'accepted';
        } catch (InvalidArgumentException) {
            return 'refused';
        }
    }

    /**
     * @param ?list<string> $keyUsage in place of the one phpseclib's makeCA() gives
     */
    private static function selfSignedRoot(PrivateKey $key, ?array $keyUsage = null): string
    {
        $dn = ['id-at-commonName' => 'Oire Test Root CA'];
        $certificate = new X509($key->getPublicKey());
        $certificate->setSubjectDN($dn);
        $certificate->setIssuerDN($dn);
        $certificate->makeCA();

        if ($keyUsage !== null) {
            $certificate->setExtension('id-ce-keyUsage', $keyUsage);
        }

        $key->sign($certificate);

        return Pem::fromDer($certificate->toString(['binary' => true]), Pem::CERTIFICATE);
    }

    private static function bundledRoot(): string
    {
        $pem = file_get_contents(self::BUNDLED_ROOT_PATH);
        self::assertIsString($pem);

        return $pem;
    }
}
