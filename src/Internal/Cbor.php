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
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Throwable;
use UnexpectedValueException;

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
 * CborText, unsigned integers that fit become ints, lists become lists and maps become CborMap, so a map
 * never passes for a list whatever its keys. Any other value, such as a negative integer or a tag, becomes
 * null, so it cannot pass for what the document needs. A map with a key that is not a text string, or with
 * the same key twice, makes the whole document refused.
 *
 * @internal
 */
final class Cbor
{
    /**
     * The map the bytes encode, or null if they do not encode exactly one map with nothing after it, or if
     * any map in it has a key that is not a text string or a key twice.
     */
    public static function tryDecodeMap(string $bytes): ?CborMap
    {
        try {
            return ErrorGuard::call(static function() use ($bytes): ?CborMap {
                $stream = new CborStream($bytes);
                $object = Decoder::create()->decode($stream);

                if ($stream->hasMore() || !($object instanceof MapObject || $object instanceof IndefiniteLengthMapObject)) {
                    return null;
                }

                return self::convertMap($object);
            });
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The number of bytes the CBOR item at the start of the bytes takes, whatever it holds and whatever follows
     * it, or null if no item decodes there.
     */
    public static function tryItemLength(string $bytes): ?int
    {
        try {
            return ErrorGuard::call(static function() use ($bytes): int {
                $stream = new CborStream($bytes);
                Decoder::create()->decode($stream);

                return $stream->offset();
            });
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @throws UnexpectedValueException if a map in it has a key that is not a text string or a key twice
     *
     * @return string|int|CborText|CborMap|list<mixed>|null
     */
    private static function convert(CBORObject $object): array|CborMap|CborText|int|string|null
    {
        return match (true) {
            $object instanceof UnsignedIntegerObject => filter_var($object->getValue(), FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE),
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
     * @throws UnexpectedValueException if a map in it has a key that is not a text string or a key twice
     *
     * @return list<string|int|CborText|CborMap|list<mixed>|null>
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
     * @throws UnexpectedValueException if the map has a key that is not a text string or a key twice
     */
    private static function convertMap(iterable $map): CborMap
    {
        $entries = [];

        foreach ($map as $item) {
            $key = self::convert($item->getKey());

            if (!$key instanceof CborText) {
                throw new UnexpectedValueException('A map key is not a text string.');
            }

            if (array_key_exists($key->value, $entries)) {
                throw new UnexpectedValueException('A map has the same key twice.');
            }

            $entries[$key->value] = self::convert($item->getValue());
        }

        return new CborMap($entries);
    }
}
