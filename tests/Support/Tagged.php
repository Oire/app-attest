<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use CBOR\CBORObject;
use CBOR\Tag;
use CBOR\Tag\GenericTag;

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
 * Wraps a CBOR item in tag 1000, a number no decoder gives a meaning, encoded as "d9 03 e8".
 */
final class Tagged
{
    private const int TWO_BYTE_ARGUMENT = 25;
    private const int TAG = 1000;

    public static function of(CBORObject $object): Tag
    {
        return GenericTag::createFromLoadedData(self::TWO_BYTE_ARGUMENT, pack('n', self::TAG), $object);
    }
}
