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
 * The launch values in the extensions map of authenticator data: the validation category, a UInt32 given as
 * four little-endian bytes or as an unsigned integer, and the bundle version, a text string. A value of any
 * other type, or an extensions area that is not exactly one well-formed map with distinct text-string keys,
 * counts as absent. A nested map in another entry may have keys of any type: it never hides the launch
 * values. Each value is read under its first spelling that holds a usable one.
 *
 * @internal
 */
final readonly class Extensions
{
    private const array VALIDATION_CATEGORY_KEYS = ['apple_validation_category_01', 'validationCategory'];
    private const array BUNDLE_VERSION_KEYS = ['apple_bundle_version_01', 'bundleVersion'];
    private const int UINT32_LENGTH = 4;

    /**
     * @psalm-capabilities read-props
     */
    private function __construct(
        public ?int $validationCategory,
        public ?string $bundleVersion,
    ) {}

    /**
     * @psalm-pure
     */
    public static function none(): self
    {
        return new self(null, null);
    }

    /**
     * The launch values in the bytes after what the authenticator data layout fixes.
     */
    public static function fromArea(string $bytes): self
    {
        $map = $bytes === '' ? null : Cbor::tryDecodeMap($bytes, lenientNestedMaps: true);

        if ($map === null) {
            return self::none();
        }

        $validationCategory = null;
        $bundleVersion = null;

        foreach (self::VALIDATION_CATEGORY_KEYS as $key) {
            $validationCategory ??= self::uint32($map->get($key));
        }

        foreach (self::BUNDLE_VERSION_KEYS as $key) {
            $value = $map->get($key);
            $bundleVersion ??= $value instanceof CborText ? $value->value : null;
        }

        return new self($validationCategory, $bundleVersion);
    }

    /**
     * @psalm-pure
     */
    private static function uint32(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value <= AuthenticatorData::MAX_UINT32 ? $value : null;
        }

        if (!is_string($value) || mb_strlen($value, '8bit') !== self::UINT32_LENGTH) {
            return null;
        }

        $unpacked = unpack('V', $value);

        return $unpacked === false || !isset($unpacked[1]) || !is_int($unpacked[1]) ? null : $unpacked[1];
    }
}
