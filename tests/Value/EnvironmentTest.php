<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use Oire\AppAttest\Value\Environment;
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
final class EnvironmentTest extends TestCase
{
    public function testAaguidsAreApplesValues(): void
    {
        self::assertSame('61707061747465737400000000000000', bin2hex(Environment::Production->aaguid()));
        self::assertSame('617070617474657374646576656c6f70', bin2hex(Environment::Development->aaguid()));
    }

    public function testAaguidNamesItsEnvironment(): void
    {
        foreach (Environment::cases() as $environment) {
            self::assertSame($environment, Environment::tryFromAaguid($environment->aaguid()));
        }
    }

    public function testUnknownAaguidNamesNoEnvironment(): void
    {
        self::assertNull(Environment::tryFromAaguid('appattest'));
        self::assertNull(Environment::tryFromAaguid(str_repeat("\x00", 16)));
    }
}
