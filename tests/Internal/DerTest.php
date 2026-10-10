<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Internal;

use Oire\AppAttest\Internal\Der;
use Oire\AppAttest\Internal\DerElement;
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
final class DerTest extends TestCase
{
    /**
     * @return iterable<string, array{string, ?int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideElementSequences(): iterable
    {
        yield 'nothing' => ['', 0];
        yield 'one NULL' => ["\x05\x00", 1];
        yield 'two NULLs' => ["\x05\x00\x05\x00", 2];
        yield 'a length in long form over 127' => ["\x04\x81\x80" . str_repeat("\x00", 128), 1];
        yield 'a length in three octets' => ["\x04\x83\x01\x00\x00" . str_repeat("\x00", 65536), 1];
        yield 'an indefinite length followed by exactly 128 octets' => ["\x04\x80" . str_repeat("\x00", 128), null];
        yield 'a length in long form under 128' => ["\x04\x81\x7f" . str_repeat("\x00", 127), null];
        yield 'a long-form length with a leading zero octet' => ["\x04\x82\x00\x80" . str_repeat("\x00", 128), null];
        yield 'a length in five octets' => ["\x04\x85\x00\x00\x00\x00\x01\x00", null];
        yield 'a long-form length without its octets' => ["\x04\x81", null];
        yield 'a content shorter than its length' => ["\x04\x02\x00", null];
        yield 'a lone identifier octet' => ["\x04", null];
        yield 'a high tag number' => ["\x1f\x01\x00", null];
        yield 'a NULL and a truncated element' => ["\x05\x00\x04\x01", null];
    }

    #[DataProvider('provideElementSequences')]
    public function testTryAllReadsOnlyCompleteDerElements(string $bytes, ?int $count): void
    {
        $elements = Der::tryAll($bytes);

        self::assertSame($count, $elements === null ? null : count($elements));
    }

    public function testTryOneReadsExactlyOneElement(): void
    {
        $element = Der::tryOne("\x04\x02\xab\xcd");

        self::assertNotNull($element);
        self::assertSame(Der::OCTET_STRING, $element->tag);
        self::assertSame("\xab\xcd", $element->content);
        self::assertSame("\x04\x02\xab\xcd", $element->encoded);
        self::assertNull(Der::tryOne(''));
        self::assertNull(Der::tryOne("\x05\x00\x05\x00"));
    }

    /**
     * @return iterable<string, array{string, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideBooleans(): iterable
    {
        yield 'FALSE' => ["\x01\x01\x00", true];
        yield 'TRUE' => ["\x01\x01\xff", true];
        yield '0x01' => ["\x01\x01\x01", false];
        yield 'two octets' => ["\x01\x02\xff\xff", false];
        yield 'no octet' => ["\x01\x00", false];
        yield 'an INTEGER' => ["\x02\x01\xff", false];
    }

    #[DataProvider('provideBooleans')]
    public function testIsBooleanAcceptsOnlyDerBooleans(string $der, bool $expected): void
    {
        self::assertSame($expected, Der::isBoolean(self::element($der)));
    }

    public function testIsTrueAcceptsOnlyTrue(): void
    {
        self::assertTrue(Der::isTrue(self::element("\x01\x01\xff")));
        self::assertFalse(Der::isTrue(self::element("\x01\x01\x00")));
        self::assertFalse(Der::isTrue(self::element("\x01\x01\x01")));
        self::assertFalse(Der::isTrue(self::element("\x02\x01\xff")));
        self::assertFalse(Der::isTrue(null));
    }

    /**
     * @return iterable<string, array{string, bool, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideIntegers(): iterable
    {
        yield 'zero' => ["\x02\x01\x00", true, true];
        yield 'minus one' => ["\x02\x01\xff", true, false];
        yield '127' => ["\x02\x01\x7f", true, true];
        yield '128' => ["\x02\x02\x00\x80", true, true];
        yield '-129' => ["\x02\x02\xff\x7f", true, false];
        yield 'no octet' => ["\x02\x00", false, false];
        yield '127 with a redundant leading zero' => ["\x02\x02\x00\x7f", false, false];
        yield '-128 with a redundant leading 0xFF' => ["\x02\x02\xff\x80", false, false];
        yield 'an OCTET STRING' => ["\x04\x01\x00", false, false];
    }

    #[DataProvider('provideIntegers')]
    public function testIntegersMustBeInTheirShortestForm(string $der, bool $integer, bool $nonNegative): void
    {
        self::assertSame($integer, Der::isInteger(self::element($der)));
        self::assertSame($nonNegative, Der::isNonNegativeInteger(self::element($der)));
    }

    public function testIntegerUnderAnotherTagIsCheckedAgainstThatTag(): void
    {
        self::assertTrue(Der::isInteger(self::element("\x82\x01\x05"), 0x82));
        self::assertFalse(Der::isInteger(self::element("\x82\x02\x00\x05"), 0x82));
        self::assertFalse(Der::isInteger(self::element("\x82\x01\x05")));
    }

    /**
     * @return iterable<string, array{string, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideObjectIdentifiers(): iterable
    {
        yield 'basicConstraints' => ["\x06\x03\x55\x1d\x13", true];
        yield 'Apple\'s nonce extension' => ["\x06\x09\x2a\x86\x48\x86\xf7\x63\x64\x08\x02", true];
        yield 'no octet' => ["\x06\x00", false];
        yield 'a last subidentifier cut off' => ["\x06\x02\x55\x81", false];
        yield 'a subidentifier padded with 0x80' => ["\x06\x03\x55\x80\x01", false];
        yield 'a first subidentifier padded with 0x80' => ["\x06\x02\x80\x01", false];
        yield 'an OCTET STRING' => ["\x04\x03\x55\x1d\x13", false];
    }

    #[DataProvider('provideObjectIdentifiers')]
    public function testObjectIdentifiersMustBeInTheirShortestForm(string $der, bool $expected): void
    {
        self::assertSame($expected, Der::isObjectIdentifier(self::element($der)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideBitStrings(): iterable
    {
        yield 'empty' => ["\x03\x01\x00", true];
        yield 'one bit' => ["\x03\x02\x07\x80", true];
        yield 'sixteen bits' => ["\x03\x03\x00\xff\xff", true];
        yield 'no octet' => ["\x03\x00", false];
        yield 'empty, declaring an unused bit' => ["\x03\x01\x01", false];
        yield 'eight unused bits' => ["\x03\x02\x08\x00", false];
        yield 'an unused bit set' => ["\x03\x02\x01\x01", false];
        yield 'constructed' => ["\x23\x03\x03\x01\x00", false];
    }

    #[DataProvider('provideBitStrings')]
    public function testBitStringsMustHaveTheirUnusedBitsZero(string $der, bool $expected): void
    {
        self::assertSame($expected, Der::isBitString(self::element($der)));
    }

    public function testBitsAreCountedAndReadFromTheFirstOctet(): void
    {
        $empty = self::element("\x03\x01\x00");
        $sevenBits = self::element("\x03\x02\x01\xa4");
        $eightBits = self::element("\x03\x02\x00\xa5");

        self::assertSame(0, Der::bitCount($empty));
        self::assertSame(7, Der::bitCount($sevenBits));
        self::assertSame(8, Der::bitCount($eightBits));
        self::assertSame([true, false, true, false, false, true, false], array_map(static fn(int $bit): bool => Der::isBitSet($sevenBits, $bit), range(0, 6)));
        self::assertTrue(Der::isBitSet($eightBits, 7));
        self::assertFalse(Der::isBitSet($eightBits, -1));
        self::assertFalse(Der::isBitSet($eightBits, 8));
        self::assertFalse(Der::isBitSet($sevenBits, 7));
        self::assertFalse(Der::isBitSet($empty, 0));
    }

    public function testChildrenAreReadOnlyFromAConstructedElementWithTheTag(): void
    {
        $sequence = self::element("\x30\x04\x05\x00\x05\x00");

        self::assertCount(2, $sequence->children(Der::SEQUENCE) ?? []);
        self::assertNull($sequence->children(0x31));
        self::assertNull(self::element("\x30\x01\x05")->children(Der::SEQUENCE));
        self::assertNull((new DerElement(Der::OCTET_STRING, "\x05\x00", "\x04\x02\x05\x00"))->children(Der::OCTET_STRING));
    }

    /**
     * The element the bytes are, without the reader's own checks, so that a type check alone decides.
     *
     * @psalm-pure
     */
    private static function element(string $der): DerElement
    {
        $first = ord($der[1] ?? "\x00");
        $header = $first < 0x80 ? 2 : 2 + ($first & 0x7F);

        return new DerElement(ord($der[0] ?? "\x00"), mb_substr($der, $header, null, '8bit'), $der);
    }
}
