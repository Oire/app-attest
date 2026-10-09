<?php

declare(strict_types=1);

namespace Oire\AppAttest\Value;

use InvalidArgumentException;

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
 * An app's bundle id: non-empty, made of ASCII letters, digits, hyphens and periods.
 *
 * @psalm-api
 * @psalm-immutable
 */
final readonly class BundleId
{
    /**
     * @throws InvalidArgumentException if the value is not a bundle id
     *
     * @psalm-pure
     */
    public function __construct(public string $value)
    {
        if (preg_match('/^[A-Za-z0-9.-]+$/D', $value) !== 1) {
            throw new InvalidArgumentException('A bundle id must be non-empty and hold only ASCII letters, digits, hyphens and periods.');
        }
    }
}
