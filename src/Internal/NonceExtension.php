<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Types\OctetString;
use Throwable;

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
 * The library decodes the extension's value itself, from the certificate mapped without phpseclib's X509
 * rules, so it registers no map with phpseclib, which keeps extension maps process-wide, and a map the
 * process registered for the OID changes nothing.
 *
 * @internal
 */
final class NonceExtension
{
    public const string OID = '1.2.840.113635.100.8.2';
    private const array MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'nonce' => [
                'constant' => 1,
                'explicit' => true,
                'type' => ASN1::TYPE_OCTET_STRING,
            ],
        ],
    ];

    /**
     * The octet string inside the extension's value, or null if the value is not exactly the SEQUENCE.
     */
    public static function tryDecode(string $value): ?string
    {
        if (!Der::isOneSequence($value)) {
            return null;
        }

        try {
            $decoded = ASN1::map(ASN1::decodeBER($value), self::MAP);

            return $decoded instanceof Constructed && $decoded->offsetExists('nonce') ? self::octetsOf($decoded['nonce']) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @psalm-capabilities read-props
     */
    private static function octetsOf(mixed $value): ?string
    {
        return $value instanceof OctetString ? $value->value : null;
    }
}
