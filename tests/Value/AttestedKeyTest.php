<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use Oire\AppAttest\Value\AttestedKey;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\ValidationCategory;
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
final class AttestedKeyTest extends TestCase
{
    private const string PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----\n";

    public function testKeepsWhatItWasBuiltWithAndStartsAtCounterZero(): void
    {
        $keyId = hash('sha256', 'key', true);
        $key = new AttestedKey($keyId, self::PUBLIC_KEY_PEM, Environment::Development, 'receipt');

        self::assertSame($keyId, $key->keyId);
        self::assertSame(self::PUBLIC_KEY_PEM, $key->publicKeyPem);
        self::assertSame(Environment::Development, $key->environment);
        self::assertSame('receipt', $key->receipt);
        self::assertSame(0, $key->counter);
        self::assertNull($key->validationCategory);
        self::assertNull($key->validationCategory());
        self::assertNull($key->bundleVersion);
    }

    public function testKeepsItsLaunchValues(): void
    {
        $key = new AttestedKey('id', self::PUBLIC_KEY_PEM, Environment::Production, 'receipt', 4, '2.1');

        self::assertSame(4, $key->validationCategory);
        self::assertSame(ValidationCategory::AppStore, $key->validationCategory());
        self::assertSame('2.1', $key->bundleVersion);
    }

    public function testUnknownValidationCategoryIsKeptRawButNamesNoCase(): void
    {
        $key = new AttestedKey('id', self::PUBLIC_KEY_PEM, Environment::Production, 'receipt', 8);

        self::assertSame(8, $key->validationCategory);
        self::assertNull($key->validationCategory());
        self::assertNull($key->bundleVersion);
    }

    public function testKeyIdBase64UrlRoundTripsWithoutPadding(): void
    {
        $keyId = str_repeat("\xfb\xff", 16);
        $encoded = (new AttestedKey($keyId, self::PUBLIC_KEY_PEM, Environment::Production, ''))->keyIdBase64Url();

        self::assertSame(43, mb_strlen($encoded, '8bit'));
        self::assertStringNotContainsString('=', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
        self::assertSame($keyId, sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
    }
}
