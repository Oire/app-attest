<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use Closure;
use PHPUnit\Framework\Assert;

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
 * Damages bytes, and runs code that must not raise a PHP warning or notice on the damaged copies.
 */
final class Damage
{
    /**
     * Every truncation and every byte XORed with each mask, at every $step-th offset.
     *
     * @param list<int> $masks
     *
     * @return list<Damaged>
     *
     * @psalm-pure
     */
    public static function of(string $bytes, array $masks = [0xFF], int $step = 1, bool $truncations = true): array
    {
        $length = mb_strlen($bytes, '8bit');
        $damaged = [];

        for ($offset = 0; $offset < $length; $offset += $step) {
            if ($truncations) {
                $damaged[] = new Damaged($offset, null, mb_substr($bytes, 0, $offset, '8bit'));
            }

            foreach ($masks as $mask) {
                $damaged[] = new Damaged($offset, $mask, self::flipped($bytes, $offset, $mask));
            }
        }

        return $damaged;
    }

    /**
     * @psalm-pure
     */
    public static function flipped(string $bytes, int $offset, int $mask): string
    {
        return mb_substr($bytes, 0, $offset, '8bit') . chr(ord($bytes[$offset]) ^ $mask) . mb_substr($bytes, $offset + 1, null, '8bit');
    }

    /**
     * Runs the operation and fails the test if it raises a PHP warning or notice. Deprecations are left to
     * the host's error handler by design, so they are not collected.
     *
     * @template T
     *
     * @param Closure(): T $operation
     *
     * @return T
     */
    public static function withoutPhpErrors(Closure $operation): mixed
    {
        $errors = [];
        set_error_handler(static function(int $severity, string $message) use (&$errors): bool {
            if (($severity & (E_DEPRECATED | E_USER_DEPRECATED)) === 0) {
                $errors[] = $severity . ': ' . $message;
            }

            return true;
        });

        try {
            $result = $operation();
        } finally {
            restore_error_handler();
        }

        Assert::assertSame([], $errors);

        return $result;
    }
}
