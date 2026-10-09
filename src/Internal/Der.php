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
 * The outer shape of DER, checked before phpseclib reads the bytes: phpseclib ignores bytes after the first
 * element and accepts indefinite lengths.
 *
 * @internal
 *
 * @psalm-pure
 */
final class Der
{
    private const int SEQUENCE_TAG = 0x30;
    private const int HEADER_LENGTH = 2;
    private const int LONG_FORM = 0x80;
    private const int LENGTH_BYTES_MASK = 0x7F;
    private const int MAX_LENGTH_BYTES = 4;

    /**
     * Whether the bytes are one SEQUENCE with a definite length, nothing after it, and at most $maxLength
     * bytes in all.
     *
     * @psalm-pure
     */
    public static function isOneSequence(string $der, int $maxLength = PHP_INT_MAX): bool
    {
        $length = mb_strlen($der, '8bit');

        if ($length < self::HEADER_LENGTH || $length > $maxLength) {
            return false;
        }

        if (self::byteAt($der, 0) !== self::SEQUENCE_TAG) {
            return false;
        }

        $first = self::byteAt($der, 1);

        if ($first < self::LONG_FORM) {
            return $length === self::HEADER_LENGTH + $first;
        }

        $lengthBytes = $first & self::LENGTH_BYTES_MASK;

        if ($lengthBytes === 0 || $lengthBytes > self::MAX_LENGTH_BYTES || $length < self::HEADER_LENGTH + $lengthBytes) {
            return false;
        }

        $contentLength = 0;

        for ($offset = self::HEADER_LENGTH; $offset < self::HEADER_LENGTH + $lengthBytes; ++$offset) {
            $contentLength = ($contentLength << 8) | self::byteAt($der, $offset);
        }

        return $length === self::HEADER_LENGTH + $lengthBytes + $contentLength;
    }

    /**
     * @throws LogicException if the offset is outside the bytes, which every caller has checked
     *
     * @psalm-pure
     */
    private static function byteAt(string $der, int $offset): int
    {
        $unpacked = unpack('C', $der, $offset);

        if ($unpacked === false || !isset($unpacked[1]) || !is_int($unpacked[1])) {
            throw new LogicException('A length-checked DER byte could not be read.');
        }

        return $unpacked[1];
    }
}
