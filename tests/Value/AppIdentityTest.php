<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\TeamId;
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
final class AppIdentityTest extends TestCase
{
    private const string RP_ID_HASH_HEX = '78fac4e89cefcde20ecc77ec10d0db108e4ec3348b0c8cbafdf92cb4583f9882';

    public function testAppIdJoinsTeamIdAndBundleId(): void
    {
        $app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));

        self::assertSame('ABCDE12345.com.example.app', $app->appId());
    }

    public function testRpIdHashIsTheRawSha256OfTheAppId(): void
    {
        $app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));

        self::assertSame(self::RP_ID_HASH_HEX, bin2hex($app->rpIdHash()));
    }
}
