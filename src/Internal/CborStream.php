<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use CBOR\Stream;
use InvalidArgumentException;
use Override;

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
 * Bytes the CBOR decoder reads from, telling how many of them it has read.
 *
 * @internal
 */
final class CborStream implements Stream
{
    private int $offset = 0;
    private readonly int $length;

    /**
     * @psalm-capabilities read-props
     */
    public function __construct(
        private readonly string $bytes,
    ) {
        $this->length = mb_strlen($bytes, '8bit');
    }

    /**
     * @throws InvalidArgumentException if fewer bytes are left than asked for
     *
     * @psalm-capabilities read-props|write-this-props|write-refs
     */
    #[Override]
    public function read(int $length): string
    {
        if ($length < 0 || $length > $this->length - $this->offset) {
            throw new InvalidArgumentException('The CBOR data ends before the item does.');
        }

        $read = mb_substr($this->bytes, $this->offset, $length, '8bit');
        $this->offset += $length;

        return $read;
    }

    /**
     * @psalm-capabilities read-props
     */
    public function offset(): int
    {
        return $this->offset;
    }

    /**
     * @psalm-capabilities read-props
     */
    public function hasMore(): bool
    {
        return $this->offset < $this->length;
    }
}
