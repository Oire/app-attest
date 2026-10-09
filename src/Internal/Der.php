<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use LogicException;

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
 * A strict, self-contained DER reader for the few structures the library reads, so that no process-wide
 * setting of a third-party ASN.1 parser can change what they decode to. It refuses indefinite lengths,
 * lengths in a longer form than needed, high tag numbers and bytes after the last element, and its type checks
 * follow DER: booleans are 0x00 or 0xFF, integers and object identifiers in their shortest form, bit strings
 * with their unused bits zero.
 *
 * @internal
 *
 * @psalm-pure
 */
final class Der
{
    public const int BOOLEAN = 0x01;
    public const int INTEGER = 0x02;
    public const int BIT_STRING = 0x03;
    public const int OCTET_STRING = 0x04;
    public const int OBJECT_IDENTIFIER = 0x06;
    public const int UTC_TIME = 0x17;
    public const int GENERALIZED_TIME = 0x18;
    public const int SEQUENCE = 0x30;
    private const int HIGH_TAG_NUMBER = 0x1F;
    private const int LONG_FORM = 0x80;
    private const int LENGTH_BYTES_MASK = 0x7F;
    private const int MAX_LENGTH_BYTES = 4;
    private const int HEADER_LENGTH = 2;
    private const int MORE_SUBIDENTIFIER_OCTETS = 0x80;
    private const int MAX_UNUSED_BITS = 7;

    /**
     * Whether the bytes are one SEQUENCE with a definite length in its shortest form, nothing after it, and
     * at most $maxLength bytes in all.
     *
     * @psalm-pure
     */
    public static function isOneSequence(string $der, int $maxLength = PHP_INT_MAX): bool
    {
        return mb_strlen($der, '8bit') <= $maxLength && self::hasTag(self::tryOne($der), self::SEQUENCE);
    }

    /**
     * The element the bytes are, or null unless they are exactly one element.
     *
     * @psalm-pure
     */
    public static function tryOne(string $der): ?DerElement
    {
        $elements = self::tryAll($der);

        return $elements !== null && count($elements) === 1 ? $elements[0] ?? null : null;
    }

    /**
     * The elements the bytes are, one after another, or null unless the bytes are exactly such elements.
     *
     * @return ?list<DerElement>
     *
     * @psalm-pure
     */
    public static function tryAll(string $bytes): ?array
    {
        $length = mb_strlen($bytes, '8bit');
        $elements = [];
        $offset = 0;

        while ($offset < $length) {
            $element = self::tryElementAt($bytes, $offset, $length);

            if ($element === null) {
                return null;
            }

            $elements[] = $element;
            $offset += mb_strlen($element->encoded, '8bit');
        }

        return $elements;
    }

    /**
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function hasTag(?DerElement $element, int $tag): bool
    {
        return $element !== null && $element->tag === $tag;
    }

    /**
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isBoolean(?DerElement $element): bool
    {
        return self::hasTag($element, self::BOOLEAN) && ($element->content === "\x00" || $element->content === "\xff");
    }

    /**
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isTrue(?DerElement $element): bool
    {
        return self::isBoolean($element) && $element->content === "\xff";
    }

    /**
     * Whether the element is an INTEGER, or holds an integer under another tag, in its shortest form.
     *
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isInteger(?DerElement $element, int $tag = self::INTEGER): bool
    {
        if (!self::hasTag($element, $tag) || $element->content === '') {
            return false;
        }

        if (mb_strlen($element->content, '8bit') === 1) {
            return true;
        }

        $first = self::byteAt($element->content, 0);
        $second = self::byteAt($element->content, 1);

        return !($first === 0x00 && $second < 0x80) && !($first === 0xFF && $second >= 0x80);
    }

    /**
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isNonNegativeInteger(?DerElement $element): bool
    {
        return self::isInteger($element) && self::byteAt($element->content, 0) < 0x80;
    }

    /**
     * Whether the element is an OBJECT IDENTIFIER with every subidentifier in its shortest form.
     *
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isObjectIdentifier(?DerElement $element): bool
    {
        if (!self::hasTag($element, self::OBJECT_IDENTIFIER) || $element->content === '') {
            return false;
        }

        $length = mb_strlen($element->content, '8bit');
        $startsSubidentifier = true;

        for ($offset = 0; $offset < $length; ++$offset) {
            $byte = self::byteAt($element->content, $offset);

            if ($startsSubidentifier && $byte === self::MORE_SUBIDENTIFIER_OCTETS) {
                return false;
            }

            $startsSubidentifier = $byte < self::MORE_SUBIDENTIFIER_OCTETS;
        }

        return $startsSubidentifier;
    }

    /**
     * Whether the element is a BIT STRING whose leading octet declares at most seven unused bits, none when
     * no octet follows, and whose unused bits are zero; or that holds such a bit string under another tag.
     *
     * @psalm-assert-if-true !null $element
     *
     * @psalm-pure
     */
    public static function isBitString(?DerElement $element, int $tag = self::BIT_STRING): bool
    {
        if (!self::hasTag($element, $tag) || $element->content === '') {
            return false;
        }

        $length = mb_strlen($element->content, '8bit');
        $unusedBits = self::byteAt($element->content, 0);

        if ($length === 1) {
            return $unusedBits === 0;
        }

        return $unusedBits <= self::MAX_UNUSED_BITS && (self::byteAt($element->content, $length - 1) & ((1 << $unusedBits) - 1)) === 0;
    }

    /**
     * The number of bits a valid BIT STRING holds.
     *
     * @psalm-pure
     */
    public static function bitCount(DerElement $bitString): int
    {
        return (mb_strlen($bitString->content, '8bit') - 1) * 8 - self::byteAt($bitString->content, 0);
    }

    /**
     * Whether bit $bit, counted from the most significant bit of the first octet after the unused-bits octet,
     * is set in a valid BIT STRING.
     *
     * @psalm-pure
     */
    public static function isBitSet(DerElement $bitString, int $bit): bool
    {
        return $bit >= 0 && $bit < self::bitCount($bitString) && (self::byteAt($bitString->content, 1 + intdiv($bit, 8)) & (0x80 >> ($bit % 8))) !== 0;
    }

    /**
     * @psalm-pure
     */
    private static function tryElementAt(string $bytes, int $offset, int $length): ?DerElement
    {
        if ($length - $offset < self::HEADER_LENGTH) {
            return null;
        }

        $tag = self::byteAt($bytes, $offset);
        $first = self::byteAt($bytes, $offset + 1);

        if (($tag & self::HIGH_TAG_NUMBER) === self::HIGH_TAG_NUMBER || $first === self::LONG_FORM) {
            return null;
        }

        $headerLength = self::HEADER_LENGTH;
        $contentLength = $first;

        if ($first > self::LONG_FORM) {
            $lengthBytes = $first & self::LENGTH_BYTES_MASK;

            if ($lengthBytes > self::MAX_LENGTH_BYTES || $length - $offset < self::HEADER_LENGTH + $lengthBytes || self::byteAt($bytes, $offset + self::HEADER_LENGTH) === 0) {
                return null;
            }

            $contentLength = 0;

            for ($index = 0; $index < $lengthBytes; ++$index) {
                $contentLength = ($contentLength << 8) | self::byteAt($bytes, $offset + self::HEADER_LENGTH + $index);
            }

            if ($contentLength < self::LONG_FORM) {
                return null;
            }

            $headerLength += $lengthBytes;
        }

        if ($contentLength > $length - $offset - $headerLength) {
            return null;
        }

        return new DerElement(
            $tag,
            mb_substr($bytes, $offset + $headerLength, $contentLength, '8bit'),
            mb_substr($bytes, $offset, $headerLength + $contentLength, '8bit'),
        );
    }

    /**
     * @throws LogicException if the offset is outside the bytes, which every caller has checked
     *
     * @psalm-pure
     */
    private static function byteAt(string $bytes, int $offset): int
    {
        $unpacked = unpack('C', $bytes, $offset);

        if ($unpacked === false || !isset($unpacked[1]) || !is_int($unpacked[1])) {
            throw new LogicException('A length-checked DER byte could not be read.');
        }

        return $unpacked[1];
    }
}
