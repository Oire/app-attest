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
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\Tests\Support\TestApp;
use Oire\AppAttest\TrustAnchor;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
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
final class AssertionVerifierTest extends TestCase
{
    private const string CLIENT_DATA = '{"challenge":"c2luZ2xlLXVzZQ","action":"test"}';
    private const string MUTATED_VECTOR = 'veehaitch-ios-14.4';
    private const int MAX_COUNTER = 0xFFFFFFFF;

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
        self::assertSame($vector->expectedCounter, self::verifyVector($vector));
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
        self::assertSame($vector->expectedCounter, self::verifyVector($vector, publicKeyPem: $attested->expectedPublicKeyPem));
    }

    public function testBuiltAssertionIsAccepted(): void
    {
        $builder = AssertionBuilder::create()->withCounter(5);

        self::assertSame(5, self::verifyBuilt($builder, previousCounter: 0));
        self::assertSame(5, self::verifyBuilt($builder, previousCounter: 4));
    }

    public function testTheLargestCounterIsAccepted(): void
    {
        $builder = AssertionBuilder::create()->withCounter(self::MAX_COUNTER);

        self::assertSame(self::MAX_COUNTER, self::verifyBuilt($builder, previousCounter: self::MAX_COUNTER - 1));
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

        self::assertSame(1, self::verifyBuilt($builder, cbor: $cbor));
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

        self::assertSame(1, self::verifyBuilt($builder, cbor: $cbor));
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

        self::assertSame(1, self::verifyBuilt($builder, publicKeyPem: str_replace("\n", "\r\n", $builder->publicKeyPem())));
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

    private static function verifyVector(
        AssertionVector $vector,
        ?string $clientData = null,
        ?string $publicKeyPem = null,
        ?int $previousCounter = null,
        ?AppIdentity $app = null,
        ?string $cbor = null,
    ): int {
        return (new AssertionVerifier())->verify(
            $cbor ?? $vector->bytes,
            $clientData ?? $vector->clientData,
            $publicKeyPem ?? $vector->publicKeyPem,
            $previousCounter ?? $vector->previousCounter,
            $app ?? $vector->app(),
        );
    }

    private static function verifyBuilt(AssertionBuilder $builder, int $previousCounter = 0, ?string $publicKeyPem = null, ?string $cbor = null): int
    {
        return (new AssertionVerifier())->verify(
            $cbor ?? $builder->build(self::CLIENT_DATA),
            self::CLIENT_DATA,
            $publicKeyPem ?? $builder->publicKeyPem(),
            $previousCounter,
            TestApp::identity(),
        );
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
     * @psalm-pure
     */
    private static function publicKeyPem(string $der): string
    {
        return Pem::fromDer($der, Pem::PUBLIC_KEY);
    }
}
