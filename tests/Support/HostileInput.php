<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use Closure;

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
 * Input built to exhaust memory, and the peak memory an operation adds, so a test can tell that such input
 * was refused before it was parsed whatever the host's memory_limit: with unlimited memory, a refusal after
 * parsing still has the expected outcome.
 */
final class HostileInput
{
    /**
     * Less than this, in bytes, is what refusing input before parsing it costs. A verification of a
     * well-formed attestation adds about 0.5 MB, parsing the hostile inputs the tests use tens of MB.
     */
    public const int CHEAP_REFUSAL_MEMORY = 8_000_000;

    /**
     * How many bytes the operation adds to the peak over what is in use when it starts.
     */
    public static function peakMemoryGrowthOf(Closure $operation): int
    {
        memory_reset_peak_usage();
        $before = memory_get_usage();
        $operation();

        return memory_get_peak_usage() - $before;
    }

    /**
     * An indefinite-length list of empty lists: about 220 bytes of decoded memory for each input byte.
     *
     * @psalm-pure
     */
    public static function indefiniteListOfEmptyLists(int $count): string
    {
        return "\x9f" . str_repeat("\x80", $count) . "\xff";
    }
}
