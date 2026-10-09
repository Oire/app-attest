<?php

declare(strict_types=1);

namespace Oire\AppAttest\Value;

use Closure;
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
 * The launch values an attestation or assertion must carry in its authenticator data extensions: the
 * validation categories allowed and a check of the bundle version. Each part is checked only when set.
 *
 * @psalm-api
 */
final readonly class LaunchPolicy
{
    /**
     * @var list<ValidationCategory>
     */
    public array $validationCategories;

    /**
     * @param list<ValidationCategory> $validationCategories the categories allowed; empty if the category is not checked
     * @param ?Closure(string): bool   $acceptsBundleVersion whether a bundle version is accepted; null if it is not checked
     *
     * @throws InvalidArgumentException if a category is not a ValidationCategory
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        array $validationCategories = [],
        public ?Closure $acceptsBundleVersion = null,
    ) {
        foreach ($validationCategories as $category) {
            if (!$category instanceof ValidationCategory) {
                throw new InvalidArgumentException('Each allowed validation category must be a ValidationCategory.');
            }
        }

        $this->validationCategories = $validationCategories;
    }

    /**
     * A policy allowing these categories and not checking the bundle version.
     *
     * @psalm-pure
     */
    public static function allowing(ValidationCategory ...$categories): self
    {
        return new self(array_values($categories));
    }

    /**
     * This policy, also requiring a bundle version the closure accepts.
     *
     * @param Closure(string): bool $accepts
     *
     * @psalm-capabilities read-props
     */
    public function withBundleVersion(Closure $accepts): self
    {
        return new self($this->validationCategories, $accepts);
    }

    /**
     * Whether this raw category passes: always if no category is checked, else only a known, allowed one.
     *
     * @psalm-capabilities read-props
     */
    public function allowsValidationCategory(?int $category): bool
    {
        if ($this->validationCategories === []) {
            return true;
        }

        $known = $category === null ? null : ValidationCategory::tryFrom($category);

        return $known !== null && in_array($known, $this->validationCategories, true);
    }

    /**
     * Whether this bundle version passes: always if it is not checked, else only one the closure accepts.
     */
    public function acceptsBundleVersion(?string $bundleVersion): bool
    {
        if ($this->acceptsBundleVersion === null) {
            return true;
        }

        return $bundleVersion !== null && ($this->acceptsBundleVersion)($bundleVersion) === true;
    }
}
