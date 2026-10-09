<?php

declare(strict_types=1);

namespace Oire\AppAttest\Value;

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
 * How an app's executable was signed and distributed, as numbered in Apple's "Defining launch environment and
 * library constraints" and named as in Apple's ValidationCategory.Value. Apple keeps 7 to 9 for binaries the
 * system generates in restricted situations and names none of them, so they have no case here.
 *
 * @psalm-api
 */
enum ValidationCategory: int
{
    /**
     * An operating system executable.
     */
    case Platform = 1;

    case TestFlight = 2;

    /**
     * An executable signed by a development code signing identity.
     */
    case Development = 3;

    case AppStore = 4;

    /**
     * An executable distributed with an enterprise provisioning profile, or ad hoc.
     */
    case Enterprise = 5;

    case DeveloperId = 6;

    /**
     * An executable signed with an identity that matches no other category.
     */
    case None = 10;

    /**
     * The category a raw reported value names, or null if the value is absent or a number Apple names no
     * category for.
     *
     * @psalm-pure
     */
    public static function tryFromRaw(?int $value): ?self
    {
        return $value === null ? null : self::tryFrom($value);
    }
}
