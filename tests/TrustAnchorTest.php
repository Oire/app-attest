<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use InvalidArgumentException;
use LogicException;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\TrustAnchor;
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
    }

    private static function bundledRoot(): string
    {
        $pem = file_get_contents(self::BUNDLED_ROOT_PATH);
        self::assertIsString($pem);

        return $pem;
    }
}
