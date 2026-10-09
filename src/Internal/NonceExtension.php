<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

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
 * phpseclib keeps extension maps globally, so the verifier and the test builders register this one map.
 *
 * @internal
 */
final class NonceExtension
{
    public const string OID = '1.2.840.113635.100.8.2';
    public const array MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'nonce' => [
                'constant' => 1,
                'explicit' => true,
                'type' => ASN1::TYPE_OCTET_STRING,
            ],
        ],
    ];

    public static function register(): void
    {
        X509::registerExtension(self::OID, self::MAP);
    }
}
