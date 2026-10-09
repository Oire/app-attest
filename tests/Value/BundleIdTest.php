<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use InvalidArgumentException;
use Oire\AppAttest\Value\BundleId;
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
final class BundleIdTest extends TestCase
{
    #[DataProvider('provideValidBundleIds')]
    public function testValidBundleIdIsKept(string $value): void
    {
        self::assertSame($value, (new BundleId($value))->value);
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideValidBundleIds(): iterable
    {
        yield 'reverse domain' => ['com.example.app'];
        yield 'mixed case with hyphen and digit' => ['com.Example-App.v2'];
    }

    #[DataProvider('provideInvalidBundleIds')]
    public function testInvalidBundleIdIsRefused(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        new BundleId($value);
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideInvalidBundleIds(): iterable
    {
        yield 'empty' => [''];
        yield 'space' => ['com.example app'];
        yield 'underscore' => ['com.example_app'];
        yield 'non-ASCII letter' => ['com.exämple.app'];
        yield 'trailing newline' => ["com.example.app\n"];
    }
}
