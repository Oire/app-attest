<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\MapObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;

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
 * Encodes the extensions map of authenticator data, the way Apple's guide sample does or otherwise.
 */
final class ExtensionsMap
{
    public const string VALIDATION_CATEGORY = 'apple_validation_category_01';
    public const string BUNDLE_VERSION = 'apple_bundle_version_01';
    public const string SHORT_VALIDATION_CATEGORY = 'validationCategory';
    public const string SHORT_BUNDLE_VERSION = 'bundleVersion';

    /**
     * Apple's guide sample encoding: the category as four little-endian bytes, the version as text.
     */
    public static function apple(int $validationCategory, string $bundleVersion): string
    {
        return self::of([
            self::BUNDLE_VERSION => TextStringObject::create($bundleVersion),
            self::VALIDATION_CATEGORY => self::categoryBytes($validationCategory),
        ]);
    }

    /**
     * @param array<string, CBORObject> $entries by text-string key
     */
    public static function of(array $entries): string
    {
        $map = MapObject::create();

        foreach ($entries as $key => $value) {
            $map->add(TextStringObject::create($key), $value);
        }

        return (string) $map;
    }

    public static function categoryBytes(int $validationCategory): ByteStringObject
    {
        return ByteStringObject::create(pack('V', $validationCategory));
    }

    public static function categoryInteger(int $validationCategory): UnsignedIntegerObject
    {
        return UnsignedIntegerObject::create($validationCategory);
    }

    public static function text(string $value): TextStringObject
    {
        return TextStringObject::create($value);
    }

    /**
     * Malformed extension areas: none of them is exactly one well-formed map with text-string keys.
     *
     * @return array<string, string>
     */
    public static function malformed(): array
    {
        $apple = self::apple(4, '1.0');

        return [
            'truncated map' => mb_substr($apple, 0, -1, '8bit'),
            'map followed by a byte' => $apple . "\x00",
            'map twice' => $apple . $apple,
            'list' => "\x82\x01\x02",
            'byte string' => (string) self::categoryBytes(4),
            'break byte' => "\xff",
            'integer key' => (string) MapObject::create()->add(UnsignedIntegerObject::create(1), self::categoryInteger(4)),
            'byte-string key' => (string) MapObject::create()->add(ByteStringObject::create(self::VALIDATION_CATEGORY), self::categoryInteger(4)),
            'repeated key' => "\xa2" . (string) self::text(self::VALIDATION_CATEGORY) . "\x04" . (string) self::text(self::VALIDATION_CATEGORY) . "\x04",
        ];
    }
}
