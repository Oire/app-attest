<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\TeamId;

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
 * The app the builders make attestations and assertions for unless told otherwise.
 *
 * @psalm-pure
 */
final class TestApp
{
    public const string TEAM_ID = 'ABCDE12345';
    public const string BUNDLE_ID = 'com.example.app';

    /**
     * @psalm-pure
     */
    public static function identity(): AppIdentity
    {
        return new AppIdentity(new TeamId(self::TEAM_ID), new BundleId(self::BUNDLE_ID));
    }
}
