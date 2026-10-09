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
 * Apple's nonce extension on the credential certificate, OID 1.2.840.113635.100.8.2:
 * SEQUENCE { [1] EXPLICIT OCTET STRING }.
 *
 * The library decodes the extension's value itself with its own DER reader, so it registers no map with
 * phpseclib, which keeps extension maps process-wide, and nothing the process sets in phpseclib changes the
 * nonce it reads.
 *
 * @internal
 *
 * @psalm-immutable
 */
final class NonceExtension
{
    public const string OID = '1.2.840.113635.100.8.2';

    /**
     * The OID's content octets, as Certificate::extensionValues() takes it.
     */
    public const string OBJECT_IDENTIFIER = "\x2a\x86\x48\x86\xf7\x63\x64\x08\x02";
    private const int NONCE_TAG = 0xA1;

    /**
     * The octet string inside the extension's value, or null if the value is not exactly the SEQUENCE.
     *
     * @psalm-pure
     */
    public static function tryDecode(string $value): ?string
    {
        $fields = Der::tryOne($value)?->children(Der::SEQUENCE) ?? [];
        $explicit = count($fields) === 1 ? ($fields[0] ?? null)?->children(self::NONCE_TAG) ?? [] : [];
        $nonce = count($explicit) === 1 ? $explicit[0] ?? null : null;

        return Der::hasTag($nonce, Der::OCTET_STRING) ? $nonce->content : null;
    }
}
