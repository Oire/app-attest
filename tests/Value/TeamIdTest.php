<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Value;

use InvalidArgumentException;
use Oire\AppAttest\Value\TeamId;
use PHPUnit\Framework\Attributes\DataProvider;
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
final class TeamIdTest extends TestCase
{
    public function testValidTeamIdIsKept(): void
    {
        self::assertSame('ABCDE12345', (new TeamId('ABCDE12345'))->value);
    }

    #[DataProvider('provideInvalidTeamIds')]
    public function testInvalidTeamIdIsRefused(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TeamId($value);
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideInvalidTeamIds(): iterable
    {
        yield 'empty' => [''];
        yield 'short' => ['ABCDE1234'];
        yield 'long' => ['ABCDE123456'];
        yield 'lowercase' => ['abcde12345'];
        yield 'punctuation' => ['ABCDE-1234'];
        yield 'trailing newline' => ["ABCDE12345\n"];
    }
}
