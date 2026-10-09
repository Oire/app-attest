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
 * An assertion that passed verification: the counter to store for the key and the launch values its
 * authenticator data reports.
 *
 * @psalm-api
 * @psalm-immutable
 */
final readonly class VerifiedAssertion
{
    /**
     * @param int     $counter            the new sign counter, to store for the key
     * @param ?int    $validationCategory the raw launch validation category in the authenticator data, null if absent
     * @param ?string $bundleVersion      the bundle version in the authenticator data, null if absent
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        public int $counter,
        public ?int $validationCategory = null,
        public ?string $bundleVersion = null,
    ) {}

    /**
     * The validation category, or null if it is absent or a number Apple names no category for.
     *
     * @psalm-capabilities read-props
     */
    public function validationCategory(): ?ValidationCategory
    {
        return ValidationCategory::tryFromRaw($this->validationCategory);
    }
}
