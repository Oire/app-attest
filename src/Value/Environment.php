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
 * The App Attest environment a key was attested in, told apart by the aaguid in authenticatorData.
 *
 * @psalm-api
 */
enum Environment: string
{
    case Production = 'production';
    case Development = 'development';

    /**
     * The 16-byte aaguid that stands for this environment.
     *
     * @psalm-capabilities read-props
     */
    public function aaguid(): string
    {
        return match ($this) {
            self::Production => 'appattest' . str_repeat("\x00", 7),
            self::Development => 'appattestdevelop',
        };
    }

    /**
     * @psalm-capabilities read-props
     */
    public static function tryFromAaguid(string $aaguid): ?self
    {
        foreach (self::cases() as $environment) {
            if ($environment->aaguid() === $aaguid) {
                return $environment;
            }
        }

        return null;
    }
}
