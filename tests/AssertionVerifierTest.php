<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Normalizable;
use CBOR\StringStream;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use InvalidArgumentException;
use Oire\AppAttest\AssertionVerifier;
use Oire\AppAttest\Exception\AssertionException;
use Oire\AppAttest\Exception\AssertionFailureReason;
use Oire\AppAttest\Tests\Support\AssertionBuilder;
use Oire\AppAttest\Tests\Support\AssertionParts;
use Oire\AppAttest\Tests\Support\AssertionVector;
use Oire\AppAttest\Tests\Support\AuthDataLayout;
use Oire\AppAttest\Tests\Support\Damage;
use Oire\AppAttest\Tests\Support\Damaged;
use Oire\AppAttest\Tests\Support\EcKey;
use Oire\AppAttest\Tests\Support\ExtensionsMap;
use Oire\AppAttest\Tests\Support\HostileInput;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\Tests\Support\Tagged;
use Oire\AppAttest\Tests\Support\TestApp;
use Oire\AppAttest\TrustAnchor;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\LaunchPolicy;
use Oire\AppAttest\Value\TeamId;
use Oire\AppAttest\Value\ValidationCategory;
use Oire\AppAttest\Value\VerifiedAssertion;
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
final class AssertionVerifierTest extends TestCase
{
    private const string CLIENT_DATA = '{"challenge":"c2luZ2xlLXVzZQ","action":"test"}';
    private const string MUTATED_VECTOR = 'veehaitch-ios-14.4';
    private const int MAX_COUNTER = 0xFFFFFFFF;
    private const int MAX_UINT32 = 0xFFFFFFFF;
    private const int MAX_LENGTH = 4096;
    private const int HOSTILE_ITEMS = 600_000;

    /**
     * @return iterable<string, array{AssertionVector}>
     */
    public static function provideGenuineVectors(): iterable
    {
        foreach (Fixtures::assertions() as $name => $vector) {
            yield $name => [$vector];
        }
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorIsAcceptedWithItsCounter(AssertionVector $vector): void
    {
        self::assertSame($vector->expectedCounter, self::verifyVector($vector)->counter);
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorReportsNoLaunchValues(AssertionVector $vector): void
    {
        $verified = self::verifyVector($vector);

        self::assertNull($verified->validationCategory);
        self::assertNull($verified->validationCategory());
        self::assertNull($verified->bundleVersion);
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherClientDataFailsTheSignature(AssertionVector $vector): void
    {
        self::assertFailure(AssertionFailureReason::Signature, static fn() => self::verifyVector($vector, clientData: $vector->clientData . 'x'));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAForeignKeyFailsTheSignature(AssertionVector $vector): void
    {
        $foreignKey = AssertionBuilder::create()->publicKeyPem();

        self::assertFailure(AssertionFailureReason::Signature, static fn() => self::verifyVector($vector, publicKeyPem: $foreignKey));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherAppFailsTheRpIdHash(AssertionVector $vector): void
    {
        $app = new AppIdentity(new TeamId($vector->teamId), new BundleId($vector->bundleId . '.other'));

        self::assertFailure(AssertionFailureReason::RpIdHash, static fn() => self::verifyVector($vector, app: $app));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testCounterNotAboveThePreviousOneFails(AssertionVector $vector): void
    {
        self::assertFailure(AssertionFailureReason::Counter, static fn() => self::verifyVector($vector, previousCounter: $vector->expectedCounter));
        self::assertFailure(AssertionFailureReason::Counter, static fn() => self::verifyVector($vector, previousCounter: $vector->expectedCounter + 1));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testVectorKeyAsAttestedIsAccepted(AssertionVector $vector): void
    {
        $attested = Fixtures::attestation($vector->attestation);

        self::assertSame($vector->keyId, $attested->keyId);
        self::assertSame($vector->expectedCounter, self::verifyVector($vector, publicKeyPem: $attested->expectedPublicKeyPem)->counter);
    }

    public function testBuiltAssertionIsAccepted(): void
    {
        $builder = AssertionBuilder::create()->withCounter(5);

        self::assertSame(5, self::verifyBuilt($builder, previousCounter: 0)->counter);
        self::assertSame(5, self::verifyBuilt($builder, previousCounter: 4)->counter);
    }

    public function testTheLargestCounterIsAccepted(): void
    {
        $builder = AssertionBuilder::create()->withCounter(self::MAX_COUNTER);

        self::assertSame(self::MAX_COUNTER, self::verifyBuilt($builder, previousCounter: self::MAX_COUNTER - 1)->counter);
    }

    public function testBuiltAssertionWithAnEqualOrLowerCounterFails(): void
    {
        $builder = AssertionBuilder::create()->withCounter(5);

        self::assertFailure(AssertionFailureReason::Counter, static fn() => self::verifyBuilt($builder, previousCounter: 5));
        self::assertFailure(AssertionFailureReason::Counter, static fn() => self::verifyBuilt($builder, previousCounter: 6));
        self::assertFailure(AssertionFailureReason::Counter, static fn() => self::verifyBuilt($builder, previousCounter: self::MAX_COUNTER));
    }

    public function testBuiltAssertionForAnotherBundleFailsTheRpIdHash(): void
    {
        $builder = AssertionBuilder::create()->withApp(new AppIdentity(new TeamId(TestApp::TEAM_ID), new BundleId('com.example.other')));

        self::assertFailure(AssertionFailureReason::RpIdHash, static fn() => self::verifyBuilt($builder));
    }

    public function testBuiltAssertionWithAForeignKeyFailsTheSignature(): void
    {
        $builder = AssertionBuilder::create();

        self::assertFailure(AssertionFailureReason::Signature, static fn() => self::verifyBuilt($builder, publicKeyPem: AssertionBuilder::create()->publicKeyPem()));
    }

    /**
     * @return iterable<string, array{callable(AssertionParts): string}>
     */
    public static function provideTamperedAssertions(): iterable
    {
        yield 'flipped signature byte' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create(Damage::flipped($a->signature, mb_strlen($a->signature, '8bit') - 1, 0x01)),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'flipped authenticatorData flags' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            ByteStringObject::create(Damage::flipped($a->authenticatorData, AuthDataLayout::FLAGS_OFFSET, 0x01)),
        )];
        yield 'truncated signature' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create(mb_substr($a->signature, 0, 20, '8bit')),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'empty signature' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create(''),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'garbage signature' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create(str_repeat("\xff", mb_strlen($a->signature, '8bit'))),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'raised counter' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            ByteStringObject::create(mb_substr($a->authenticatorData, 0, AuthDataLayout::COUNTER_OFFSET, '8bit') . pack('N', 1000)),
        )];
    }

    /**
     * @param callable(AssertionParts): string $tamper
     */
    #[DataProvider('provideTamperedAssertions')]
    public function testTamperedAssertionFailsTheSignature(callable $tamper): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));

        self::assertFailure(AssertionFailureReason::Signature, static fn() => self::verifyBuilt($builder, cbor: $tamper($parts)));
    }

    public function testSignatureOverTheUnhashedNonceInputFails(): void
    {
        $key = EcKey::generate();
        $authenticatorData = TestApp::identity()->rpIdHash() . "\x40" . pack('N', 1);
        $signed = openssl_sign($authenticatorData . hash('sha256', self::CLIENT_DATA, true), $signature, $key->privateKeyPem, OPENSSL_ALGO_SHA256);
        self::assertTrue($signed);
        $cbor = self::assertionObject(ByteStringObject::create($signature), ByteStringObject::create($authenticatorData));

        self::assertFailure(AssertionFailureReason::Signature, static fn() => self::verifyBuilt(AssertionBuilder::create(), publicKeyPem: $key->publicKeyPem, cbor: $cbor));
    }

    public function testReassembledBuiltAssertionIsAccepted(): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));
        $cbor = self::assertionObject(ByteStringObject::create($parts->signature), ByteStringObject::create($parts->authenticatorData));

        self::assertSame(1, self::verifyBuilt($builder, cbor: $cbor)->counter);
    }

    /**
     * @return iterable<string, array{callable(AssertionParts): string}>
     */
    public static function provideMalformedDocuments(): iterable
    {
        yield 'no signature' => [static fn(AssertionParts $a): string => self::assertionObject(null, ByteStringObject::create($a->authenticatorData))];
        yield 'no authenticatorData' => [static fn(AssertionParts $a): string => self::assertionObject(ByteStringObject::create($a->signature), null)];
        yield 'empty authenticatorData' => [static fn(AssertionParts $a): string => self::assertionObject(ByteStringObject::create($a->signature), ByteStringObject::create(''))];
        yield 'one byte short of authenticatorData' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            ByteStringObject::create(mb_substr($a->authenticatorData, 0, AuthDataLayout::ASSERTION_LENGTH - 1, '8bit')),
        )];
        yield 'signature an integer' => [static fn(AssertionParts $a): string => self::assertionObject(UnsignedIntegerObject::create(1), ByteStringObject::create($a->authenticatorData))];
        yield 'authenticatorData a list' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            ListObject::create([ByteStringObject::create($a->authenticatorData)]),
        )];
        yield 'signature tagged' => [static fn(AssertionParts $a): string => self::assertionObject(
            Tagged::of(ByteStringObject::create($a->signature)),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'authenticatorData tagged' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            Tagged::of(ByteStringObject::create($a->authenticatorData)),
        )];
        yield 'truncated' => [static fn(AssertionParts $a): string => mb_substr(
            self::assertionObject(ByteStringObject::create($a->signature), ByteStringObject::create($a->authenticatorData)),
            0,
            40,
            '8bit',
        )];
    }

    /**
     * @param callable(AssertionParts): string $document
     */
    #[DataProvider('provideMalformedDocuments')]
    public function testMalformedDocumentFails(callable $document): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder, cbor: $document($parts)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGarbage(): iterable
    {
        yield 'empty' => [''];
        yield 'text' => ['garbage'];
        yield 'bytes' => [str_repeat(hash('sha512', 'garbage', true), 4)];
        yield 'a list' => [(string) ListObject::create([TextStringObject::create('signature')])];
        yield 'a byte string' => [(string) ByteStringObject::create(str_repeat("\x01", AuthDataLayout::ASSERTION_LENGTH))];
    }

    #[DataProvider('provideGarbage')]
    public function testGarbageIsMalformed(string $cbor): void
    {
        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt(AssertionBuilder::create(), cbor: $cbor));
    }

    public function testAssertionWithinTheSizeLimitIsAccepted(): void
    {
        $builder = AssertionBuilder::create()->withExtensions(ExtensionsMap::of(['padding' => ExtensionsMap::text(str_repeat('a', 3800))]));

        self::assertLessThanOrEqual(self::MAX_LENGTH, mb_strlen($builder->build(self::CLIENT_DATA), '8bit'));
        self::assertSame(1, self::verifyBuilt($builder)->counter);
    }

    public function testAssertionOverTheSizeLimitIsMalformed(): void
    {
        $builder = AssertionBuilder::create()->withExtensions(ExtensionsMap::of(['padding' => ExtensionsMap::text(str_repeat('a', self::MAX_LENGTH))]));

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder));
    }

    public function testHostileDocumentIsRefusedBeforeItIsDecoded(): void
    {
        $cbor = "\xa1" . (string) TextStringObject::create('signature') . HostileInput::indefiniteListOfEmptyLists(self::HOSTILE_ITEMS);

        self::assertRefusedCheaply(static fn() => self::verifyBuilt(AssertionBuilder::create(), cbor: $cbor));
    }

    public function testHostileExtensionsAreaIsRefusedBeforeItIsDecoded(): void
    {
        $builder = AssertionBuilder::create()->withExtensions(HostileInput::indefiniteListOfEmptyLists(self::HOSTILE_ITEMS));
        $cbor = $builder->build(self::CLIENT_DATA);

        self::assertRefusedCheaply(static fn() => self::verifyBuilt($builder, cbor: $cbor));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorWithATrailingByteIsMalformed(AssertionVector $vector): void
    {
        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyVector($vector, cbor: $vector->bytes . "\x00"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTrailingData(): iterable
    {
        yield 'a break byte' => ["\xff"];
        yield 'an empty map' => [(string) MapObject::create()];
        yield 'a text string' => [(string) TextStringObject::create('signature')];
    }

    #[DataProvider('provideTrailingData')]
    public function testDocumentFollowedByMoreDataIsMalformed(string $trailing): void
    {
        $builder = AssertionBuilder::create();

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder, cbor: $builder->build(self::CLIENT_DATA) . $trailing));
    }

    public function testDocumentFollowedByItselfIsMalformed(): void
    {
        $builder = AssertionBuilder::create();
        $cbor = $builder->build(self::CLIENT_DATA);

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder, cbor: $cbor . $cbor));
    }

    /**
     * @return iterable<string, array{callable(AssertionParts): string}>
     */
    public static function provideRetypedMembers(): iterable
    {
        yield 'signature a text string' => [static fn(AssertionParts $a): string => self::assertionObject(
            TextStringObject::create($a->signature),
            ByteStringObject::create($a->authenticatorData),
        )];
        yield 'authenticatorData a text string' => [static fn(AssertionParts $a): string => self::assertionObject(
            ByteStringObject::create($a->signature),
            TextStringObject::create($a->authenticatorData),
        )];
        yield 'signature key a byte string' => [static fn(AssertionParts $a): string => (string) MapObject::create()
            ->add(ByteStringObject::create('signature'), ByteStringObject::create($a->signature))
            ->add(TextStringObject::create('authenticatorData'), ByteStringObject::create($a->authenticatorData))];
        yield 'authenticatorData key a byte string' => [static fn(AssertionParts $a): string => (string) MapObject::create()
            ->add(TextStringObject::create('signature'), ByteStringObject::create($a->signature))
            ->add(ByteStringObject::create('authenticatorData'), ByteStringObject::create($a->authenticatorData))];
    }

    /**
     * @param callable(AssertionParts): string $document
     */
    #[DataProvider('provideRetypedMembers')]
    public function testMemberOfAnotherStringTypeIsMalformed(callable $document): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder, cbor: $document($parts)));
    }

    public function testHandEncodedDocumentWithAnExtraTextKeyIsAccepted(): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));

        self::assertSame(1, self::verifyBuilt($builder, cbor: self::assertionObjectAdding($parts))->counter);
        self::assertSame(1, self::verifyBuilt($builder, cbor: self::assertionObjectAdding($parts, TextStringObject::create('extra'), ByteStringObject::create('value')))->counter);
    }

    /**
     * @return iterable<string, array{list<CBORObject>}>
     */
    public static function provideBadKeys(): iterable
    {
        yield 'a byte-string key' => [[ByteStringObject::create('extra'), ByteStringObject::create('value')]];
        yield 'a byte-string signature key besides the text one' => [[ByteStringObject::create('signature'), ByteStringObject::create('value')]];
        yield 'an integer key' => [[UnsignedIntegerObject::create(0), ByteStringObject::create('value')]];
        yield 'a negative integer key' => [[NegativeIntegerObject::create(-1), ByteStringObject::create('value')]];
        yield 'a map key' => [[MapObject::create(), ByteStringObject::create('value')]];
        yield 'signature twice' => [[TextStringObject::create('signature'), ByteStringObject::create('value')]];
        yield 'authenticatorData twice' => [[TextStringObject::create('authenticatorData'), ByteStringObject::create('value')]];
        yield 'an integer key in a nested map' => [[TextStringObject::create('extra'), MapObject::create()->add(UnsignedIntegerObject::create(1), ByteStringObject::create('value'))]];
    }

    /**
     * @param list<CBORObject> $extra
     */
    #[DataProvider('provideBadKeys')]
    public function testMapWithAKeyThatIsNotTextOrRepeatedIsMalformed(array $extra): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));

        self::assertFailure(AssertionFailureReason::Format, static fn() => self::verifyBuilt($builder, cbor: self::assertionObjectAdding($parts, ...$extra)));
    }

    public function testDamagedGenuineVectorNeverRaisesAPhpError(): void
    {
        $vector = Fixtures::assertion(self::MUTATED_VECTOR);
        $outcomes = Damage::withoutPhpErrors(static fn(): array => array_map(
            static fn(Damaged $d): string => self::outcomeOf($vector, $d->bytes),
            Damage::of($vector->bytes),
        ));

        self::assertNotContains('accepted', $outcomes);
        self::assertContains(AssertionFailureReason::Format->name, $outcomes);
        self::assertContains(AssertionFailureReason::Signature->name, $outcomes);
    }

    public function testIndefiniteLengthEncodingIsAccepted(): void
    {
        $builder = AssertionBuilder::create();
        $parts = self::partsOf($builder->build(self::CLIENT_DATA));
        $cbor = (string) IndefiniteLengthMapObject::create()
            ->add(IndefiniteLengthTextStringObject::create('sig', 'nature'), IndefiniteLengthByteStringObject::create(...mb_str_split($parts->signature, 16, '8bit')))
            ->add(TextStringObject::create('authenticatorData'), IndefiniteLengthByteStringObject::create(...mb_str_split($parts->authenticatorData, 16, '8bit')));

        self::assertSame(1, self::verifyBuilt($builder, cbor: $cbor)->counter);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidPublicKeys(): iterable
    {
        yield 'empty' => [''];
        yield 'garbage' => ['garbage'];
        yield 'a file path' => ['file:///etc/hosts'];
        yield 'not base64' => ["-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n"];
        yield 'empty body' => ["-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"];
        yield 'a certificate' => [TrustAnchor::apple()->pem];
        yield 'a private key' => [EcKey::generate()->privateKeyPem];
        yield 'an RSA key' => [Pem::generatedPublicKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048])];
        yield 'a P-384 key' => [Pem::generatedPublicKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'])];
        yield 'a point off the curve' => [self::publicKeyPem(EcKey::P256_SPKI_PREFIX . "\x04" . str_repeat("\x01", 64))];
        yield 'a hybrid point with an even y' => [EcKey::generate()->publicKeyPemWithPrefix("\x06")];
        yield 'a hybrid point with an odd y' => [EcKey::generate()->publicKeyPemWithPrefix("\x07")];
        yield 'a compressed point' => [self::publicKeyPem("\x30\x39\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x22\x00\x02" . str_repeat("\x01", 32))];
        yield 'two keys' => [EcKey::generate()->publicKeyPem . EcKey::generate()->publicKeyPem];
    }

    #[DataProvider('provideInvalidPublicKeys')]
    public function testInvalidPublicKeyIsACallerError(string $publicKeyPem): void
    {
        $builder = AssertionBuilder::create();

        $this->expectException(InvalidArgumentException::class);
        self::verifyBuilt($builder, publicKeyPem: $publicKeyPem);
    }

    public function testPublicKeyWithCrLfLineEndingsIsAccepted(): void
    {
        $builder = AssertionBuilder::create();

        self::assertSame(1, self::verifyBuilt($builder, publicKeyPem: str_replace("\n", "\r\n", $builder->publicKeyPem()))->counter);
    }

    /**
     * @return iterable<string, array{int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideInvalidPreviousCounters(): iterable
    {
        yield 'negative' => [-1];
        yield 'above 2^32 - 1' => [self::MAX_COUNTER + 1];
        yield 'the smallest integer' => [PHP_INT_MIN];
        yield 'the largest integer' => [PHP_INT_MAX];
    }

    #[DataProvider('provideInvalidPreviousCounters')]
    public function testPreviousCounterOutOfRangeIsACallerError(int $previousCounter): void
    {
        $builder = AssertionBuilder::create();

        $this->expectException(InvalidArgumentException::class);
        self::verifyBuilt($builder, previousCounter: $previousCounter);
    }

    public function testAnInvalidPublicKeyIsReportedBeforeTheAssertionIsRead(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new AssertionVerifier())->verify('garbage', self::CLIENT_DATA, 'garbage', 0, TestApp::identity());
    }

    public function testAnInvalidPreviousCounterIsReportedBeforeTheAssertionIsRead(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new AssertionVerifier())->verify('garbage', self::CLIENT_DATA, AssertionBuilder::create()->publicKeyPem(), -1, TestApp::identity());
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorWithoutLaunchValuesFailsOnlyAPolicyThatNeedsThem(AssertionVector $vector): void
    {
        self::assertSame($vector->expectedCounter, self::verifyVector($vector, launchPolicy: new LaunchPolicy())->counter);
        self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => self::verifyVector($vector, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        self::assertFailure(
            AssertionFailureReason::BundleVersion,
            static fn() => self::verifyVector($vector, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(): bool => true)),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLaunchValueEncodings(): iterable
    {
        yield 'short spellings, unsigned integer' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(2),
            ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('4.2'),
        ])];
        yield 'short spellings, four little-endian bytes' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('4.2'),
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(2),
        ])];
        yield 'Apple spellings, four little-endian bytes' => [ExtensionsMap::apple(2, '4.2')];
        yield 'Apple spellings, unsigned integer' => [ExtensionsMap::of([
            ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(2),
            ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('4.2'),
        ])];
        yield 'beside a nested map with integer keys' => [ExtensionsMap::of([
            'other' => MapObject::create()->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(2),
            ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('4.2'),
        ])];
    }

    #[DataProvider('provideLaunchValueEncodings')]
    public function testBuiltLaunchValuesAreReportedAndEnforced(string $extensions): void
    {
        $builder = AssertionBuilder::create()
            ->withCounter(3)
            ->withExtensions($extensions);
        $passing = LaunchPolicy::allowing(ValidationCategory::TestFlight)->withBundleVersion(static fn(string $version): bool => $version === '4.2');

        $reported = self::verifyBuilt($builder);
        $enforced = self::verifyBuilt($builder, launchPolicy: $passing);

        foreach ([$reported, $enforced] as $verified) {
            self::assertSame(3, $verified->counter);
            self::assertSame(2, $verified->validationCategory);
            self::assertSame(ValidationCategory::TestFlight, $verified->validationCategory());
            self::assertSame('4.2', $verified->bundleVersion);
        }

        self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => self::verifyBuilt($builder, launchPolicy: LaunchPolicy::allowing(ValidationCategory::AppStore)));
        self::assertFailure(
            AssertionFailureReason::BundleVersion,
            static fn() => self::verifyBuilt($builder, launchPolicy: LaunchPolicy::allowing(ValidationCategory::TestFlight)->withBundleVersion(static fn(string $version): bool => $version === '4.3')),
        );
    }

    public function testUnknownCategoryIsNeverAllowed(): void
    {
        foreach ([0, 7, 8, 9, 11, self::MAX_UINT32] as $category) {
            $builder = AssertionBuilder::create()->withExtensions(ExtensionsMap::of([ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger($category)]));

            $verified = self::verifyBuilt($builder);

            self::assertSame(1, $verified->counter);
            self::assertSame($category, $verified->validationCategory);
            self::assertNull($verified->validationCategory());
            self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => self::verifyBuilt($builder, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideExtensionsWithoutUsableValues(): iterable
    {
        foreach (ExtensionsMap::malformed() as $name => $bytes) {
            yield $name => [$bytes];
        }

        yield 'empty map' => [ExtensionsMap::of([])];
        yield 'values of the wrong type' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::text('2'),
            ExtensionsMap::SHORT_BUNDLE_VERSION => ByteStringObject::create('4.2'),
        ])];
        yield 'category above UInt32' => [ExtensionsMap::of([ExtensionsMap::SHORT_VALIDATION_CATEGORY => UnsignedIntegerObject::create(0x100000002)])];
        yield 'category of three bytes' => [ExtensionsMap::of([ExtensionsMap::SHORT_VALIDATION_CATEGORY => ByteStringObject::create("\x02\x00\x00")])];
        yield 'tagged values' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => Tagged::of(ExtensionsMap::categoryInteger(2)),
            ExtensionsMap::SHORT_BUNDLE_VERSION => Tagged::of(ExtensionsMap::text('4.2')),
        ])];
    }

    #[DataProvider('provideExtensionsWithoutUsableValues')]
    public function testExtensionsWithoutUsableValuesFailOnlyAPolicy(string $extensions): void
    {
        $builder = AssertionBuilder::create()->withExtensions($extensions);
        $verified = self::verifyBuilt($builder);

        self::assertSame(1, $verified->counter);
        self::assertNull($verified->validationCategory);
        self::assertNull($verified->bundleVersion);
        self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => self::verifyBuilt($builder, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        self::assertFailure(
            AssertionFailureReason::BundleVersion,
            static fn() => self::verifyBuilt($builder, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(): bool => true)),
        );
    }

    public function testMissingValueFailsOnlyThePartOfThePolicyThatNeedsIt(): void
    {
        $versionOnly = AssertionBuilder::create()->withExtensions(ExtensionsMap::of([ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('5')]));
        $categoryOnly = AssertionBuilder::create()->withExtensions(ExtensionsMap::of([ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(4)]));
        $versionFive = (new LaunchPolicy())->withBundleVersion(static fn(string $version): bool => $version === '5');

        self::assertSame(1, self::verifyBuilt($versionOnly, launchPolicy: $versionFive)->counter);
        self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => self::verifyBuilt($versionOnly, launchPolicy: LaunchPolicy::allowing(ValidationCategory::AppStore)));
        self::assertSame(1, self::verifyBuilt($categoryOnly, launchPolicy: LaunchPolicy::allowing(ValidationCategory::AppStore))->counter);
        self::assertFailure(AssertionFailureReason::BundleVersion, static fn() => self::verifyBuilt($categoryOnly, launchPolicy: $versionFive));
    }

    public function testLaunchPolicyIsCheckedAfterEveryOtherCheck(): void
    {
        $builder = AssertionBuilder::create()->withCounter(5);
        $refusing = LaunchPolicy::allowing(ValidationCategory::AppStore)->withBundleVersion(static fn(): bool => false);
        $verifier = new AssertionVerifier();
        $assertion = $builder->build(self::CLIENT_DATA);
        $otherApp = new AppIdentity(new TeamId(TestApp::TEAM_ID), new BundleId('com.example.other'));

        self::assertFailure(AssertionFailureReason::Signature, static fn() => $verifier->verify($assertion, 'other', $builder->publicKeyPem(), 0, TestApp::identity(), $refusing));
        self::assertFailure(AssertionFailureReason::RpIdHash, static fn() => $verifier->verify($assertion, self::CLIENT_DATA, $builder->publicKeyPem(), 0, $otherApp, $refusing));
        self::assertFailure(AssertionFailureReason::Counter, static fn() => $verifier->verify($assertion, self::CLIENT_DATA, $builder->publicKeyPem(), 5, TestApp::identity(), $refusing));
        self::assertFailure(AssertionFailureReason::ValidationCategory, static fn() => $verifier->verify($assertion, self::CLIENT_DATA, $builder->publicKeyPem(), 0, TestApp::identity(), $refusing));
    }

    public function testDamagedExtensionsNeverRaiseAPhpError(): void
    {
        foreach (Damage::of(ExtensionsMap::apple(2, '4.2'), [0x01, 0x80, 0xFF]) as $damaged) {
            $builder = AssertionBuilder::create()->withExtensions($damaged->bytes);

            self::assertSame(1, Damage::withoutPhpErrors(static fn(): int => self::verifyBuilt($builder)->counter), 'Damage at extensions byte ' . $damaged->offset . '.');
        }
    }

    private static function verifyVector(
        AssertionVector $vector,
        ?string $clientData = null,
        ?string $publicKeyPem = null,
        ?int $previousCounter = null,
        ?AppIdentity $app = null,
        ?string $cbor = null,
        ?LaunchPolicy $launchPolicy = null,
    ): VerifiedAssertion {
        return (new AssertionVerifier())->verify(
            $cbor ?? $vector->bytes,
            $clientData ?? $vector->clientData,
            $publicKeyPem ?? $vector->publicKeyPem,
            $previousCounter ?? $vector->previousCounter,
            $app ?? $vector->app(),
            $launchPolicy,
        );
    }

    private static function verifyBuilt(
        AssertionBuilder $builder,
        int $previousCounter = 0,
        ?string $publicKeyPem = null,
        ?string $cbor = null,
        ?LaunchPolicy $launchPolicy = null,
    ): VerifiedAssertion {
        return (new AssertionVerifier())->verify(
            $cbor ?? $builder->build(self::CLIENT_DATA),
            self::CLIENT_DATA,
            $publicKeyPem ?? $builder->publicKeyPem(),
            $previousCounter,
            TestApp::identity(),
            $launchPolicy,
        );
    }

    /**
     * @param callable(): mixed $verification
     */
    private static function assertRefusedCheaply(callable $verification): void
    {
        $growth = HostileInput::peakMemoryGrowthOf(static fn() => self::assertFailure(AssertionFailureReason::Format, $verification));

        self::assertLessThan(HostileInput::CHEAP_REFUSAL_MEMORY, $growth, 'The assertion must be refused before it is decoded.');
    }

    /**
     * @param callable(): mixed $verification
     */
    private static function assertFailure(AssertionFailureReason $reason, callable $verification): void
    {
        try {
            $verification();
        } catch (AssertionException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());

            return;
        }

        self::fail('The assertion was accepted, expected ' . $reason->name . '.');
    }

    private static function outcomeOf(AssertionVector $vector, string $cbor): string
    {
        try {
            self::verifyVector($vector, cbor: $cbor);

            return 'accepted';
        } catch (AssertionException $e) {
            return $e->reason->name;
        }
    }

    private static function partsOf(string $cbor): AssertionParts
    {
        $object = Decoder::create()->decode(StringStream::create($cbor));
        self::assertInstanceOf(Normalizable::class, $object);
        $document = $object->normalize();
        self::assertIsArray($document);
        $signature = $document['signature'] ?? null;
        $authenticatorData = $document['authenticatorData'] ?? null;
        self::assertIsString($signature);
        self::assertIsString($authenticatorData);

        return new AssertionParts($signature, $authenticatorData);
    }

    private static function assertionObject(?CBORObject $signature, ?CBORObject $authenticatorData): string
    {
        $document = MapObject::create();

        if ($signature !== null) {
            $document->add(TextStringObject::create('signature'), $signature);
        }

        if ($authenticatorData !== null) {
            $document->add(TextStringObject::create('authenticatorData'), $authenticatorData);
        }

        return (string) $document;
    }

    /**
     * The assertion encoded by hand as a definite-length map, so that any key may follow its two members,
     * one of those included.
     */
    private static function assertionObjectAdding(AssertionParts $parts, CBORObject ...$extraKeysAndValues): string
    {
        $items = [
            TextStringObject::create('signature'),
            ByteStringObject::create($parts->signature),
            TextStringObject::create('authenticatorData'),
            ByteStringObject::create($parts->authenticatorData),
            ...$extraKeysAndValues,
        ];
        self::assertSame(0, count($items) % 2);

        return chr(0xA0 + intdiv(count($items), 2)) . implode('', array_map(static fn(CBORObject $item): string => (string) $item, $items));
    }

    /**
     * @psalm-pure
     */
    private static function publicKeyPem(string $der): string
    {
        return Pem::fromDer($der, Pem::PUBLIC_KEY);
    }
}
