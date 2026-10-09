<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Exception;

use Oire\AppAttest\Exception\AppAttestException;
use Oire\AppAttest\Exception\AssertionException;
use Oire\AppAttest\Exception\AssertionFailureReason;
use Oire\AppAttest\Exception\AttestationException;
use Oire\AppAttest\Exception\AttestationFailureReason;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

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
final class ExceptionsTest extends TestCase
{
    #[DataProvider('provideAttestationReasons')]
    public function testAttestationExceptionCarriesItsReason(AttestationFailureReason $reason): void
    {
        $previous = new RuntimeException('cause');
        $exception = new AttestationException($reason, 'The check failed.', $previous);

        self::assertInstanceOf(AppAttestException::class, $exception);
        self::assertSame($reason, $exception->reason);
        self::assertSame('The check failed.', $exception->getMessage());
        self::assertSame($previous, $exception->getPrevious());
    }

    /**
     * @return iterable<string, array{AttestationFailureReason}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideAttestationReasons(): iterable
    {
        foreach (AttestationFailureReason::cases() as $reason) {
            yield $reason->name => [$reason];
        }
    }

    #[DataProvider('provideAssertionReasons')]
    public function testAssertionExceptionCarriesItsReason(AssertionFailureReason $reason): void
    {
        $exception = new AssertionException($reason, 'The check failed.');

        self::assertInstanceOf(AppAttestException::class, $exception);
        self::assertSame($reason, $exception->reason);
        self::assertSame('The check failed.', $exception->getMessage());
        self::assertNull($exception->getPrevious());
    }

    /**
     * @return iterable<string, array{AssertionFailureReason}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideAssertionReasons(): iterable
    {
        foreach (AssertionFailureReason::cases() as $reason) {
            yield $reason->name => [$reason];
        }
    }

    public function testReasonsAreExactlyThePublicApiCases(): void
    {
        self::assertSame(
            ['Format', 'CertificateChain', 'Nonce', 'KeyId', 'RpIdHash', 'Counter', 'Environment', 'ValidationCategory', 'BundleVersion'],
            array_map(static fn(AttestationFailureReason $reason): string => $reason->name, AttestationFailureReason::cases()),
        );
        self::assertSame(
            ['Format', 'Signature', 'RpIdHash', 'Counter', 'ValidationCategory', 'BundleVersion'],
            array_map(static fn(AssertionFailureReason $reason): string => $reason->name, AssertionFailureReason::cases()),
        );
    }
}
