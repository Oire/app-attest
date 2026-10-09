<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use InvalidArgumentException;
use Oire\AppAttest\Value\LaunchPolicy;
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
final class LaunchPolicyTest extends TestCase
{
    public function testEmptyPolicyChecksNothing(): void
    {
        $policy = new LaunchPolicy();

        self::assertSame([], $policy->validationCategories);
        self::assertNull($policy->acceptsBundleVersion);
        self::assertTrue($policy->allowsValidationCategory(null));
        self::assertTrue($policy->allowsValidationCategory(42));
        self::assertTrue($policy->acceptsBundleVersion(null));
        self::assertTrue($policy->acceptsBundleVersion(''));
    }

    public function testAllowsOnlyItsKnownCategories(): void
    {
        $policy = LaunchPolicy::allowing(ValidationCategory::AppStore, ValidationCategory::TestFlight);

        self::assertSame([ValidationCategory::AppStore, ValidationCategory::TestFlight], $policy->validationCategories);
        self::assertTrue($policy->allowsValidationCategory(4));
        self::assertTrue($policy->allowsValidationCategory(2));
        self::assertFalse($policy->allowsValidationCategory(3));
        self::assertFalse($policy->allowsValidationCategory(8));
        self::assertFalse($policy->allowsValidationCategory(null));
        self::assertTrue($policy->acceptsBundleVersion(null));
    }

    public function testBundleVersionPassesOnlyWhenTheClosureReturnsTrue(): void
    {
        $seen = [];
        $policy = LaunchPolicy::allowing(ValidationCategory::AppStore)
            ->withBundleVersion(static function(string $version) use (&$seen): bool {
                $seen[] = $version;

                return $version === '2.0';
            });

        self::assertSame([ValidationCategory::AppStore], $policy->validationCategories);
        self::assertTrue($policy->acceptsBundleVersion('2.0'));
        self::assertFalse($policy->acceptsBundleVersion('2.0.1'));
        self::assertFalse($policy->acceptsBundleVersion(null));
        self::assertSame(['2.0', '2.0.1'], $seen);
    }

    public function testClosureResultOtherThanTrueRefuses(): void
    {
        /** @psalm-suppress InvalidArgument */
        $policy = (new LaunchPolicy())->withBundleVersion(static fn(): int => 1);

        self::assertFalse($policy->acceptsBundleVersion('1'));
    }

    public function testWithBundleVersionLeavesTheOriginalUnchanged(): void
    {
        $policy = LaunchPolicy::allowing(ValidationCategory::Platform);
        $withVersion = $policy->withBundleVersion(static fn(): bool => false);

        self::assertNotSame($policy, $withVersion);
        self::assertNull($policy->acceptsBundleVersion);
        self::assertFalse($withVersion->acceptsBundleVersion('1'));
    }

    public function testCategoryThatIsNotAValidationCategoryIsACallerError(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @psalm-suppress InvalidArgument */
        new LaunchPolicy([4]);
    }
}
