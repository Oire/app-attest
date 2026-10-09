<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

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
 * PEM armor: exactly one block with the expected label, its body strict base64.
 *
 * @internal
 *
 * @psalm-pure
 */
final class Pem
{
    public const string CERTIFICATE = 'CERTIFICATE';
    public const string PUBLIC_KEY = 'PUBLIC KEY';

    /**
     * The DER inside the block, or null if the text is not one non-empty block with this label.
     *
     * @psalm-pure
     */
    public static function tryDecode(string $pem, string $label): ?string
    {
        $quoted = preg_quote($label, '/');

        if (preg_match('/^\\s*-----BEGIN ' . $quoted . '-----([A-Za-z0-9+\\/=\\s]+)-----END ' . $quoted . '-----\\s*$/D', $pem, $matches) !== 1 || !isset($matches[1])) {
            return null;
        }

        $der = base64_decode($matches[1], true);

        return $der === false || $der === '' ? null : $der;
    }

    /**
     * @psalm-pure
     */
    public static function encode(string $der, string $label): string
    {
        return '-----BEGIN ' . $label . "-----\n" . chunk_split(base64_encode($der), 64, "\n") . '-----END ' . $label . "-----\n";
    }
}
