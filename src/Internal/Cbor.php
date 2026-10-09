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
use InvalidArgumentException;
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
 * Only what App Attest documents hold survives decoding: byte strings become strings, text strings become
 * CborText, lists become lists, maps become arrays keyed by their text-string keys. Any other value, such as
 * an integer, becomes null, and any other key is dropped, so neither can pass for what the document needs.
 *
 * @internal
 */
final class Cbor
{
    /**
     * The map the bytes encode, or null if they do not encode exactly one map with nothing after it.
     *
     * @return array<string, string|CborText|array<array-key, mixed>|null>|null
     */
    public static function tryDecodeMap(string $bytes): ?array
    {
        try {
            return ErrorGuard::call(static function() use ($bytes): ?array {
                $stream = StringStream::create($bytes);
                $object = Decoder::create()->decode($stream);

                if (self::hasMore($stream) || !($object instanceof MapObject || $object instanceof IndefiniteLengthMapObject)) {
                    return null;
                }

                return self::convertMap($object);
            });
        } catch (Throwable) {
            return null;
        }
    }

    private static function hasMore(StringStream $stream): bool
    {
        try {
            $stream->read(1);
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * @return string|CborText|array<array-key, mixed>|null
     */
    private static function convert(CBORObject $object): array|CborText|string|null
    {
        return match (true) {
            $object instanceof ByteStringObject,
            $object instanceof IndefiniteLengthByteStringObject => $object->getValue(),
            $object instanceof TextStringObject,
            $object instanceof IndefiniteLengthTextStringObject => new CborText($object->getValue()),
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
     * @return list<string|CborText|array<array-key, mixed>|null>
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
     * @return array<string, string|CborText|array<array-key, mixed>|null>
     */
    private static function convertMap(iterable $map): array
    {
        $converted = [];

        foreach ($map as $item) {
            $key = self::convert($item->getKey());

            if ($key instanceof CborText) {
                $converted[$key->value] = self::convert($item->getValue());
            }
        }

        return $converted;
    }
}
