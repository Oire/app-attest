<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use Oire\AppAttest\Value\ValidationCategory;
use Oire\AppAttest\Value\VerifiedAssertion;
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
final class VerifiedAssertionTest extends TestCase
{
    public function testKeepsItsCounterAndReportsNoLaunchValuesByDefault(): void
    {
        $verified = new VerifiedAssertion(7);

        self::assertSame(7, $verified->counter);
        self::assertNull($verified->validationCategory);
        self::assertNull($verified->validationCategory());
        self::assertNull($verified->bundleVersion);
    }

    public function testKeepsItsLaunchValues(): void
    {
        $verified = new VerifiedAssertion(3, 2, '4.2');

        self::assertSame(3, $verified->counter);
        self::assertSame(2, $verified->validationCategory);
        self::assertSame(ValidationCategory::TestFlight, $verified->validationCategory());
        self::assertSame('4.2', $verified->bundleVersion);
    }

    public function testUnknownValidationCategoryIsKeptRawButNamesNoCase(): void
    {
        $verified = new VerifiedAssertion(1, 8);

        self::assertSame(8, $verified->validationCategory);
        self::assertNull($verified->validationCategory());
    }
}
