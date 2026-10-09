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
 * so none of them escapes to the caller. Deprecations, and warnings silenced with @, go on to the error
 * handler that was active before, so a dependency's deprecation never turns into a failed verification.
 *
 * A lowered error_reporting() level alone does not disable the guard: hosts such as PHPUnit lower it while
 * their own handler still reports every warning.
 *
 * @internal
 */
final class ErrorGuard
{
    private const int THROWN = E_WARNING | E_NOTICE | E_USER_WARNING | E_USER_NOTICE;
    private const int UNSUPPRESSIBLE = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR;

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
        $previous = set_error_handler(null);
        restore_error_handler();

        set_error_handler(static function(int $severity, string $message, string $file, int $line) use ($previous): bool {
            if (($severity & self::THROWN) !== 0 && (error_reporting() & ~self::UNSUPPRESSIBLE) !== 0) {
                throw new ErrorException($message, 0, $severity, $file, $line);
            }

            return $previous !== null && $previous($severity, $message, $file, $line) !== false;
        });

        try {
            return $operation();
        } finally {
            restore_error_handler();
        }
    }
}
