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
 * One DER element: its identifier octet, its content and its whole encoding.
 *
 * @internal
 *
 * @psalm-immutable
 */
final readonly class DerElement
{
    private const int CONSTRUCTED = 0x20;

    /**
     * @psalm-pure
     */
    public function __construct(public int $tag, public string $content, public string $encoded) {}

    /**
     * The elements inside, or null unless this element has the tag, a constructed one, and its content is
     * exactly DER elements.
     *
     * @return ?list<DerElement>
     *
     * @psalm-capabilities read-props
     */
    public function children(int $tag): ?array
    {
        return $this->tag === $tag && ($tag & self::CONSTRUCTED) !== 0 ? Der::tryAll($this->content) : null;
    }
}
