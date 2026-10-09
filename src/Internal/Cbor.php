<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
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
 * Decodes untrusted CBOR without letting a decoder error or a PHP warning escape.
 *
 * Only what App Attest documents hold survives decoding: byte and text strings become strings, lists become
 * lists, maps become arrays keyed by their string keys. Any other value, such as an integer, becomes null,
 * so it cannot pass for a string.
 *
 * @internal
 */
final class Cbor
{
    /**
     * The map the bytes encode, or null if they do not encode a map.
     *
     * @return array<string, string|array<array-key, mixed>|null>|null
     */
    public static function tryDecodeMap(string $bytes): ?array
    {
        try {
            return ErrorGuard::call(static function() use ($bytes): ?array {
                $object = Decoder::create()->decode(StringStream::create($bytes));

                return $object instanceof MapObject || $object instanceof IndefiniteLengthMapObject ? self::convertMap($object) : null;
            });
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return string|array<array-key, mixed>|null
     */
    private static function convert(CBORObject $object): array|string|null
    {
        return match (true) {
            $object instanceof ByteStringObject,
            $object instanceof IndefiniteLengthByteStringObject,
            $object instanceof TextStringObject,
            $object instanceof IndefiniteLengthTextStringObject => $object->getValue(),
            $object instanceof ListObject,
            $object instanceof IndefiniteLengthListObject => self::convertList($object),
            $object instanceof MapObject,
            $object instanceof IndefiniteLengthMapObject => self::convertMap($object),
            default => null,
        };
    }

    /**
     * @param iterable<CBORObject> $list
     *
     * @return list<string|array<array-key, mixed>|null>
     */
    private static function convertList(iterable $list): array
    {
        $converted = [];

        foreach ($list as $item) {
            $converted[] = self::convert($item);
        }

        return $converted;
    }

    /**
     * @param iterable<MapItem> $map
     *
     * @return array<string, string|array<array-key, mixed>|null>
     */
    private static function convertMap(iterable $map): array
    {
        $converted = [];

        foreach ($map as $item) {
            $key = self::convert($item->getKey());

            if (is_string($key)) {
                $converted[$key] = self::convert($item->getValue());
            }
        }

        return $converted;
    }
}
