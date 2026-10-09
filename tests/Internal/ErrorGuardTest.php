<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Internal;

use ErrorException;
use Oire\AppAttest\Internal\ErrorGuard;
use Override;
use PHPUnit\Framework\TestCase;

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
final class ErrorGuardTest extends TestCase
{
    /**
     * @var list<string>
     */
    private array $passedOn = [];

    #[Override]
    protected function setUp(): void
    {
        set_error_handler(function(int $severity, string $message): bool {
            $this->passedOn[] = $severity . ': ' . $message;

            return true;
        });
    }

    #[Override]
    protected function tearDown(): void
    {
        restore_error_handler();
    }

    public function testWarningAbortsTheOperation(): void
    {
        try {
            ErrorGuard::call(static function(): string {
                trigger_error('a warning', E_USER_WARNING);

                return 'finished';
            });
            self::fail('The warning did not abort the operation.');
        } catch (ErrorException $e) {
            self::assertSame('a warning', $e->getMessage());
            self::assertSame(E_USER_WARNING, $e->getSeverity());
        }

        self::assertSame([], $this->passedOn);
    }

    public function testNoticeAbortsTheOperation(): void
    {
        $this->expectException(ErrorException::class);
        ErrorGuard::call(static fn(): bool => trigger_error('a notice', E_USER_NOTICE));
    }

    public function testDeprecationGoesToThePreviousHandlerAndTheOperationFinishes(): void
    {
        $passedOnInside = ErrorGuard::call(function(): int {
            trigger_error('a deprecation', E_USER_DEPRECATED);

            return count($this->passedOn);
        });

        self::assertSame(1, $passedOnInside);
        self::assertSame([E_USER_DEPRECATED . ': a deprecation'], $this->passedOn);
    }

    public function testSilencedWarningGoesToThePreviousHandlerAndTheOperationFinishes(): void
    {
        $passedOnInside = ErrorGuard::call(function(): int {
            @trigger_error('a silenced warning', E_USER_WARNING);

            return count($this->passedOn);
        });

        self::assertSame(1, $passedOnInside);
        self::assertSame([E_USER_WARNING . ': a silenced warning'], $this->passedOn);
    }

    public function testWarningAbortsTheOperationEvenWhenErrorReportingLeavesItOut(): void
    {
        $reporting = error_reporting(E_ALL & ~E_USER_WARNING);

        try {
            $this->expectException(ErrorException::class);
            ErrorGuard::call(static fn(): bool => trigger_error('an unreported warning', E_USER_WARNING));
        } finally {
            error_reporting($reporting);
        }
    }

    public function testThePreviousHandlerIsRestored(): void
    {
        ErrorGuard::call(static fn(): string => 'finished');
        trigger_error('after the guard', E_USER_WARNING);

        self::assertSame([E_USER_WARNING . ': after the guard'], $this->passedOn);
    }
}
