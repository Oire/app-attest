<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

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
final class ValidationCategoryTest extends TestCase
{
    public function testCasesCarryApplesLaunchConstraintNumbers(): void
    {
        self::assertSame(
            ['Platform' => 1, 'TestFlight' => 2, 'Development' => 3, 'AppStore' => 4, 'Enterprise' => 5, 'DeveloperId' => 6, 'None' => 10],
            array_combine(
                array_map(static fn(ValidationCategory $category): string => $category->name, ValidationCategory::cases()),
                array_map(static fn(ValidationCategory $category): int => $category->value, ValidationCategory::cases()),
            ),
        );
    }

    public function testRestrictedNumbersNameNoCategory(): void
    {
        foreach ([0, 7, 8, 9, 11] as $number) {
            self::assertNull(ValidationCategory::tryFrom($number));
            self::assertNull(ValidationCategory::tryFromRaw($number));
        }
    }

    public function testRawValueNamesItsCategoryAndAbsenceNamesNone(): void
    {
        self::assertSame(ValidationCategory::AppStore, ValidationCategory::tryFromRaw(4));
        self::assertSame(ValidationCategory::None, ValidationCategory::tryFromRaw(10));
        self::assertNull(ValidationCategory::tryFromRaw(null));
    }
}
