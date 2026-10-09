<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use Closure;
use ErrorException;

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
 * Runs third-party parsing of untrusted bytes with PHP warnings and notices turned into exceptions,
 * so none of them escapes to the caller.
 *
 * @internal
 */
final class ErrorGuard
{
    /**
     * @template T
     *
     * @param Closure(): T $operation
     *
     * @throws ErrorException
     * @return T
     */
    public static function call(Closure $operation): mixed
    {
        set_error_handler(static function(int $severity, string $message, string $file, int $line): never {
            throw new ErrorException($message, 0, $severity, $file, $line);
        });

        try {
            return $operation();
        } finally {
            restore_error_handler();
        }
    }
}
