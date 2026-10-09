<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Normalizable;
use CBOR\StringStream;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use DateTimeImmutable;
use LogicException;
use Oire\AppAttest\AttestationVerifier;
use Oire\AppAttest\Exception\AttestationException;
use Oire\AppAttest\Exception\AttestationFailureReason;
use Oire\AppAttest\Internal\NonceExtension;
use Oire\AppAttest\Tests\Support\AttestationBuilder;
use Oire\AppAttest\Tests\Support\AttestationVector;
use Oire\AppAttest\Tests\Support\BuiltAttestation;
use Oire\AppAttest\Tests\Support\Damage;
use Oire\AppAttest\Tests\Support\Damaged;
use Oire\AppAttest\Tests\Support\EcKey;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\TrustAnchor;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\AttestedKey;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;
use Override;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionProperty;
use Symfony\Component\Clock\MockClock;

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
final class AttestationVerifierTest extends TestCase
{
    private const string MUTATED_VECTOR = 'veehaitch-ios-14.4';

    /**
     * @return iterable<string, array{AttestationVector}>
     */
    public static function provideGenuineVectors(): iterable
    {
        foreach (Fixtures::attestations() as $name => $vector) {
            yield $name => [$vector];
        }
    }

    #[Override]
    protected function tearDown(): void
    {
        X509::setURLFetchCallback(null);
        X509::disableURLFetch();
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorIsAccepted(AttestationVector $vector): void
    {
        $key = self::verifyVector($vector);

        self::assertSame($vector->keyId, $key->keyId);
        self::assertSame($vector->expectedPublicKeyPem, $key->publicKeyPem);
        self::assertSame($vector->environment, $key->environment);
        self::assertSame(self::receiptOf($vector->bytes), $key->receipt);
        self::assertSame($vector->expectedCounter, $key->counter);
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherClientDataHashFailsTheNonce(AttestationVector $vector): void
    {
        self::assertFailure(AttestationFailureReason::Nonce, static fn() => self::verifyVector($vector, clientDataHash: hash('sha256', 'another challenge', true)));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherKeyIdFails(AttestationVector $vector): void
    {
        self::assertFailure(AttestationFailureReason::KeyId, static fn() => self::verifyVector($vector, keyId: hash('sha256', 'another key', true)));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherAppFailsTheRpIdHash(AttestationVector $vector): void
    {
        $app = new AppIdentity(new TeamId($vector->teamId), new BundleId($vector->bundleId . '.other'));

        self::assertFailure(AttestationFailureReason::RpIdHash, static fn() => self::verifyVector($vector, app: $app));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testEnvironmentNotAllowedFails(AttestationVector $vector): void
    {
        $other = $vector->environment === Environment::Production ? Environment::Development : Environment::Production;

        self::assertFailure(AttestationFailureReason::Environment, static fn() => self::verifyVector($vector, allowed: [$other]));
        self::assertFailure(AttestationFailureReason::Environment, static fn() => self::verifyVector($vector, allowed: []));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testChainOutsideItsValidityFails(AttestationVector $vector): void
    {
        $after = new MockClock($vector->verifyAt->modify('+1 year'));
        $before = new MockClock($vector->verifyAt->modify('-1 year'));

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyVector($vector, clock: $after));
        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyVector($vector, clock: $before));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testAnotherTrustAnchorFailsTheChain(AttestationVector $vector): void
    {
        $verifier = new AttestationVerifier(AttestationBuilder::create()->build()->trustAnchor(), $vector->clock());

        self::assertFailure(
            AttestationFailureReason::CertificateChain,
            static fn() => $verifier->verify($vector->bytes, $vector->clientDataHash, $vector->keyId, $vector->app(), Environment::cases()),
        );
    }

    public function testDefaultClockIsTheSystemClock(): void
    {
        $now = new DateTimeImmutable();
        $current = AttestationBuilder::create()
            ->withTime($now)
            ->build();

        self::assertSame($current->keyId, self::verifyWithTheDefaultClock($current)->keyId);

        foreach (['-1 week', '+1 week'] as $shift) {
            $other = AttestationBuilder::create()
                ->withTime($now->modify($shift))
                ->build();

            self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyWithTheDefaultClock($other));
        }
    }

    public function testGuideVectorWithRawChallengeAndNewerExtensionsIsAccepted(): void
    {
        $vector = Fixtures::attestation('takimoto3-apple-guide');

        self::assertSame(24, mb_strlen($vector->clientDataHash, '8bit'));
        self::assertSame(Environment::Production, self::verifyVector($vector, allowed: [Environment::Production])->environment);
    }

    public function testBuiltAttestationIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $key = self::verifyBuilt($attestation);

        self::assertSame($attestation->keyId, $key->keyId);
        self::assertSame($attestation->publicKeyPem, $key->publicKeyPem);
        self::assertSame(Environment::Development, $key->environment);
        self::assertSame(AttestationBuilder::RECEIPT, $key->receipt);
        self::assertSame(0, $key->counter);
    }

    public function testProductionIsAcceptedOnlyWhenAllowed(): void
    {
        $attestation = AttestationBuilder::create()
            ->withEnvironment(Environment::Production)
            ->build();

        self::assertSame(Environment::Production, self::verifyBuilt($attestation, [Environment::Production])->environment);
        self::assertSame(Environment::Production, self::verifyBuilt($attestation, Environment::cases())->environment);
        self::assertFailure(AttestationFailureReason::Environment, static fn() => self::verifyBuilt($attestation, [Environment::Development]));
    }

    public function testUnknownAaguidFailsTheEnvironment(): void
    {
        $attestation = AttestationBuilder::create()
            ->withAaguid(str_repeat("\xff", 16))
            ->build();

        self::assertFailure(AttestationFailureReason::Environment, static fn() => self::verifyBuilt($attestation, Environment::cases()));
    }

    public function testNonZeroCounterFails(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCounter(1)
            ->build();

        self::assertFailure(AttestationFailureReason::Counter, static fn() => self::verifyBuilt($attestation));
    }

    public function testCredentialIdOtherThanTheKeyIdFails(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialId(hash('sha256', 'not the key id', true))
            ->build();

        self::assertFailure(AttestationFailureReason::KeyId, static fn() => self::verifyBuilt($attestation));
    }

    public function testIntermediateThatIsNotACaFailsTheChain(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateNotCa()
            ->build();

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
    }

    public function testExpiredRootFailsTheChain(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExpiredRoot()
            ->build();

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
    }

    public function testCaIssuersUrlIsNeverFetched(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialFromAnUnlistedIssuer('http://192.0.2.1/ca.cer')
            ->build();
        $fetched = [];
        X509::enableURLFetch();
        X509::setURLFetchCallback(static function(string $host) use (&$fetched): bool {
            $fetched[] = $host;

            return false;
        });

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
        self::assertSame([], $fetched);
    }

    public function testAnotherNonceExtensionMapIsALogicException(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $extensions = new ReflectionProperty(X509::class, 'extensions');
        $registered = (array) $extensions->getValue();
        $extensions->setValue(null, [NonceExtension::OID => ['type' => ASN1::TYPE_OCTET_STRING]] + $registered);

        try {
            $this->expectException(LogicException::class);
            self::verifyBuilt($attestation);
        } finally {
            $extensions->setValue(null, $registered);
        }
    }

    /**
     * @return iterable<string, array{array<string, int|string>}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideCredentialKeysOtherThanP256(): iterable
    {
        yield 'P-384' => [['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']];
        yield 'RSA' => [['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]];
    }

    /**
     * @param array<string, int|string> $options
     */
    #[DataProvider('provideCredentialKeysOtherThanP256')]
    public function testCredentialKeyOtherThanP256IsMalformed(array $options): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialPublicKeyPem(Pem::generatedPublicKey($options))
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testMissingNonceExtensionFails(): void
    {
        $attestation = AttestationBuilder::create()
            ->withoutNonceExtension()
            ->build();

        self::assertFailure(AttestationFailureReason::Nonce, static fn() => self::verifyBuilt($attestation));
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideBadNonceExtensions(): iterable
    {
        yield 'empty sequence' => ["\x30\x00"];
        yield 'bare octet string' => ["\x04\x20" . str_repeat("\x01", 32)];
        yield 'short nonce' => ["\x30\x23\xa1\x21\x04\x1f" . str_repeat("\x01", 31)];
        yield 'another nonce' => [AttestationBuilder::nonceExtensionDer(hash('sha256', 'another nonce', true))];
        yield 'not DER' => ["\xff\xff\xff"];
    }

    #[DataProvider('provideBadNonceExtensions')]
    public function testBadNonceExtensionFails(string $der): void
    {
        $attestation = AttestationBuilder::create()
            ->withNonceExtensionDer($der)
            ->build();

        self::assertFailure(AttestationFailureReason::Nonce, static fn() => self::verifyBuilt($attestation));
    }

    public function testKeyWithLeadingZeroXGetsTheFullPointKeyId(): void
    {
        $attestation = AttestationBuilder::create()
            ->withLeadingZeroX()
            ->build();
        $key = self::verifyBuilt($attestation);
        $point = mb_substr(self::spkiOf($key->publicKeyPem), -EcKey::POINT_LENGTH, null, '8bit');

        self::assertSame("\x04\x00", mb_substr($point, 0, 2, '8bit'));
        self::assertSame(hash('sha256', $point, true), $key->keyId);
        self::assertSame($attestation->keyId, $key->keyId);
    }

    /**
     * @return iterable<string, array{int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideTruncatedAuthDataLengths(): iterable
    {
        yield 'empty' => [0];
        yield 'no counter' => [36];
        yield 'no credentialId length' => [54];
        yield 'short credentialId' => [86];
        yield 'no public key' => [87];
    }

    #[DataProvider('provideTruncatedAuthDataLengths')]
    public function testTruncatedAuthDataIsMalformed(int $length): void
    {
        $attestation = AttestationBuilder::create()
            ->withAuthDataTruncatedTo($length)
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testWrongFormatIsMalformed(): void
    {
        $attestation = AttestationBuilder::create()
            ->withFormat('packed')
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testMissingCertificatesAreMalformed(): void
    {
        $attestation = AttestationBuilder::create()
            ->withoutCertificates()
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testReassembledBuiltAttestationIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = self::attestationObject(self::x5c($attestation->credentialDer, $attestation->intermediateDer), $attestation->authData);

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: $cbor)->keyId);
    }

    public function testIndefiniteLengthEncodingIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $attStmt = IndefiniteLengthMapObject::create()
            ->add(TextStringObject::create('x5c'), IndefiniteLengthListObject::create(self::chunked($attestation->credentialDer), self::chunked($attestation->intermediateDer)))
            ->add(IndefiniteLengthTextStringObject::create('rec', 'eipt'), self::chunked($attestation->receipt));
        $cbor = (string) IndefiniteLengthMapObject::create()
            ->add(TextStringObject::create('fmt'), IndefiniteLengthTextStringObject::create('apple-', 'appattest'))
            ->add(TextStringObject::create('attStmt'), $attStmt)
            ->add(TextStringObject::create('authData'), self::chunked($attestation->authData));

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: $cbor)->keyId);
    }

    /**
     * @return iterable<string, array{callable(BuiltAttestation): list<string>}>
     */
    public static function provideBrokenChains(): iterable
    {
        yield 'credential only' => [static fn(BuiltAttestation $a): array => [$a->credentialDer]];
        yield 'three certificates' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, $a->intermediateDer, $a->intermediateDer]];
        yield 'swapped' => [static fn(BuiltAttestation $a): array => [$a->intermediateDer, $a->credentialDer]];
        yield 'credential twice' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, $a->credentialDer]];
        yield 'garbage credential' => [static fn(BuiltAttestation $a): array => ['garbage', $a->intermediateDer]];
        yield 'garbage intermediate' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, 'garbage']];
        yield 'no certificates' => [static fn(BuiltAttestation $a): array => array_slice([$a->credentialDer], 1)];
        yield 'foreign intermediate' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, AttestationBuilder::create()->build()->intermediateDer]];
        yield 'credential with a trailing byte' => [static fn(BuiltAttestation $a): array => [$a->credentialDer . "\x00", $a->intermediateDer]];
        yield 'intermediate with a trailing byte' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, $a->intermediateDer . "\x00"]];
        yield 'intermediate followed by its own PEM' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, $a->intermediateDer . "\n" . Pem::fromDer($a->intermediateDer, Pem::CERTIFICATE)]];
        yield 'indefinite-length credential' => [static fn(BuiltAttestation $a): array => ["\x30\x80" . mb_substr($a->credentialDer, 4, null, '8bit') . "\x00\x00", $a->intermediateDer]];
        yield '64 KiB of nested sequences as the credential' => [static fn(BuiltAttestation $a): array => [self::nestedSequences(65536), $a->intermediateDer]];
        yield '64 KiB of nested sequences as the intermediate' => [static fn(BuiltAttestation $a): array => [$a->credentialDer, self::nestedSequences(65536)]];
    }

    /**
     * @param callable(BuiltAttestation): list<string> $certificates
     */
    #[DataProvider('provideBrokenChains')]
    public function testBrokenChainFails(callable $certificates): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = self::attestationObject(self::x5c(...$certificates($attestation)), $attestation->authData);

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    public function testIntermediateWithAnotherCaInAppendedPemFailsTheChain(): void
    {
        $victim = AttestationBuilder::create()->build();
        $attacker = AttestationBuilder::create()->build();
        $intermediate = $victim->intermediateDer . "\n" . Pem::fromDer($attacker->intermediateDer, Pem::CERTIFICATE);
        $cbor = self::attestationObject(self::x5c($attacker->credentialDer, $intermediate), $attacker->authData);
        $verifier = new AttestationVerifier($victim->trustAnchor(), $attacker->clock());

        self::assertFailure(
            AttestationFailureReason::CertificateChain,
            static fn() => $verifier->verify($cbor, $attacker->clientDataHash, $attacker->keyId, $attacker->app, [Environment::Development]),
        );
    }

    public function testAppleIntermediateWithAnotherCaInAppendedPemFailsTheChain(): void
    {
        $appleIntermediate = self::certificatesOf(Fixtures::attestation('takimoto3-apple-guide')->bytes)[1];
        $attacker = AttestationBuilder::create()->build();
        $intermediate = $appleIntermediate . "\n" . Pem::fromDer($attacker->intermediateDer, Pem::CERTIFICATE);
        $cbor = self::attestationObject(self::x5c($attacker->credentialDer, $intermediate), $attacker->authData);
        $verifier = new AttestationVerifier(TrustAnchor::apple(), $attacker->clock());

        self::assertFailure(
            AttestationFailureReason::CertificateChain,
            static fn() => $verifier->verify($cbor, $attacker->clientDataHash, $attacker->keyId, $attacker->app, [Environment::Development]),
        );
    }

    /**
     * @return iterable<string, array{callable(BuiltAttestation): string}>
     */
    public static function provideMalformedDocuments(): iterable
    {
        yield 'truncated' => [static fn(BuiltAttestation $a): string => mb_substr($a->cbor, 0, 100, '8bit')];
        yield 'no fmt' => [static fn(BuiltAttestation $a): string => self::attestationObject(self::x5c($a->credentialDer, $a->intermediateDer), $a->authData, format: null)];
        yield 'no receipt' => [static fn(BuiltAttestation $a): string => self::attestationObject(self::x5c($a->credentialDer, $a->intermediateDer), $a->authData, receipt: null)];
        yield 'x5c not a list' => [static fn(BuiltAttestation $a): string => self::attestationObject(ByteStringObject::create($a->credentialDer), $a->authData)];
        yield 'x5c a map' => [static fn(BuiltAttestation $a): string => self::attestationObject(
            MapObject::create()
                ->add(TextStringObject::create('a'), ByteStringObject::create($a->credentialDer))
                ->add(TextStringObject::create('b'), ByteStringObject::create($a->intermediateDer)),
            $a->authData,
        )];
        yield 'x5c holding an integer' => [static fn(BuiltAttestation $a): string => self::attestationObject(ListObject::create([ByteStringObject::create($a->credentialDer), UnsignedIntegerObject::create(1)]), $a->authData)];
        yield 'no authData' => [static fn(BuiltAttestation $a): string => self::attestationObject(self::x5c($a->credentialDer, $a->intermediateDer), null)];
    }

    /**
     * @param callable(BuiltAttestation): string $document
     */
    #[DataProvider('provideMalformedDocuments')]
    public function testMalformedDocumentFails(callable $document): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = $document($attestation);

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGarbage(): iterable
    {
        yield 'empty' => [''];
        yield 'text' => ['garbage'];
        yield 'bytes' => [str_repeat(hash('sha512', 'garbage', true), 4)];
        yield 'a list' => [(string) ListObject::create([TextStringObject::create(AttestationBuilder::FORMAT)])];
        yield 'a text string' => [(string) TextStringObject::create(AttestationBuilder::FORMAT)];
    }

    #[DataProvider('provideGarbage')]
    public function testGarbageIsMalformed(string $cbor): void
    {
        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt(AttestationBuilder::create()->build(), cbor: $cbor));
    }

    #[DataProvider('provideGenuineVectors')]
    public function testGenuineVectorWithATrailingByteIsMalformed(AttestationVector $vector): void
    {
        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyVector($vector, cbor: $vector->bytes . "\x00"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTrailingData(): iterable
    {
        yield 'a break byte' => ["\xff"];
        yield 'an empty map' => [(string) MapObject::create()];
        yield 'a text string' => [(string) TextStringObject::create(AttestationBuilder::FORMAT)];
    }

    #[DataProvider('provideTrailingData')]
    public function testDocumentFollowedByMoreDataIsMalformed(string $trailing): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $attestation->cbor . $trailing));
    }

    public function testDocumentFollowedByItselfIsMalformed(): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $attestation->cbor . $attestation->cbor));
    }

    public function testDocumentWithEveryMemberOfItsExpectedTypeIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: self::attestationObjectRetyping($attestation, null))->keyId);
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideRetypedMembers(): iterable
    {
        yield 'fmt a byte string' => ['fmt'];
        yield 'credential certificate a text string' => ['credential'];
        yield 'intermediate certificate a text string' => ['intermediate'];
        yield 'receipt a text string' => ['receipt'];
        yield 'authData a text string' => ['authData'];
        yield 'fmt key a byte string' => ['key fmt'];
        yield 'attStmt key a byte string' => ['key attStmt'];
        yield 'x5c key a byte string' => ['key x5c'];
        yield 'receipt key a byte string' => ['key receipt'];
        yield 'authData key a byte string' => ['key authData'];
    }

    #[DataProvider('provideRetypedMembers')]
    public function testMemberOfAnotherStringTypeIsMalformed(string $member): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: self::attestationObjectRetyping($attestation, $member)));
    }

    public function testHandEncodedDocumentIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: self::attestationObjectAdding($attestation))->keyId);
    }

    public function testExtraTextKeyIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = self::attestationObjectAdding(
            $attestation,
            document: [TextStringObject::create('extra'), ByteStringObject::create('value')],
            attStmt: [TextStringObject::create('extra'), ByteStringObject::create('value')],
        );

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: $cbor)->keyId);
    }

    /**
     * @return iterable<string, array{callable(BuiltAttestation): string}>
     */
    public static function provideMapsInPlaceOfX5c(): iterable
    {
        yield 'keyed "0" and "1"' => [static fn(BuiltAttestation $a): string => self::attestationObject(
            MapObject::create()
                ->add(TextStringObject::create('0'), ByteStringObject::create($a->credentialDer))
                ->add(TextStringObject::create('1'), ByteStringObject::create($a->intermediateDer)),
            $a->authData,
        )];
        yield 'of indefinite length keyed "0" and "1"' => [static fn(BuiltAttestation $a): string => self::attestationObject(
            IndefiniteLengthMapObject::create()
                ->add(TextStringObject::create('0'), ByteStringObject::create($a->credentialDer))
                ->add(TextStringObject::create('1'), ByteStringObject::create($a->intermediateDer)),
            $a->authData,
        )];
    }

    /**
     * @param callable(BuiltAttestation): string $document
     */
    #[DataProvider('provideMapsInPlaceOfX5c')]
    public function testMapInPlaceOfX5cIsMalformed(callable $document): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $document($attestation)));
    }

    /**
     * @return iterable<string, array{list<CBORObject>, list<CBORObject>}>
     */
    public static function provideBadKeys(): iterable
    {
        yield 'a byte-string key in the document' => [[ByteStringObject::create('extra'), ByteStringObject::create('value')], []];
        yield 'a byte-string key in attStmt' => [[], [ByteStringObject::create('extra'), ByteStringObject::create('value')]];
        yield 'a byte-string fmt key besides the text one' => [[ByteStringObject::create('fmt'), TextStringObject::create(AttestationBuilder::FORMAT)], []];
        yield 'a byte-string x5c key besides the text one' => [[], [ByteStringObject::create('x5c'), ListObject::create()]];
        yield 'an integer key in the document' => [[UnsignedIntegerObject::create(0), ByteStringObject::create('value')], []];
        yield 'a negative integer key in attStmt' => [[], [NegativeIntegerObject::create(-1), ByteStringObject::create('value')]];
        yield 'a list key in the document' => [[ListObject::create(), ByteStringObject::create('value')], []];
        yield 'fmt twice' => [[TextStringObject::create('fmt'), TextStringObject::create(AttestationBuilder::FORMAT)], []];
        yield 'authData twice' => [[TextStringObject::create('authData'), ByteStringObject::create('value')], []];
        yield 'receipt twice' => [[], [TextStringObject::create('receipt'), ByteStringObject::create('value')]];
    }

    /**
     * @param list<CBORObject> $document
     * @param list<CBORObject> $attStmt
     */
    #[DataProvider('provideBadKeys')]
    public function testMapWithAKeyThatIsNotTextOrRepeatedIsMalformed(array $document, array $attStmt): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = self::attestationObjectAdding($attestation, $document, $attStmt);

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    public function testRepeatedX5cIsMalformed(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = self::attestationObjectAdding($attestation, attStmt: [TextStringObject::create('x5c'), self::x5c($attestation->credentialDer, $attestation->intermediateDer)]);

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    public function testDamagedGenuineVectorNeverRaisesAPhpError(): void
    {
        $vector = Fixtures::attestation(self::MUTATED_VECTOR);
        $damaged = Damage::of($vector->bytes, step: 11);
        $outcomes = Damage::withoutPhpErrors(static fn(): array => array_map(static fn(Damaged $d): string => self::outcomeOf($vector, $d->bytes), $damaged));

        foreach ($damaged as $index => $d) {
            if (($outcomes[$index] ?? null) === 'accepted') {
                self::assertNotNull($d->mask, 'An attestation truncated to ' . $d->offset . ' bytes was accepted.');
                self::assertTrue(self::isHarmlessDamage($vector->bytes, $d->offset), 'Damage at byte ' . $d->offset . ' was accepted.');
            }
        }

        self::assertContains('accepted', $outcomes);
        self::assertContains(AttestationFailureReason::Format->name, $outcomes);
        self::assertContains(AttestationFailureReason::CertificateChain->name, $outcomes);
    }

    public function testDamagedGenuineCertificatesNeverRaiseAPhpError(): void
    {
        $vector = Fixtures::attestation(self::MUTATED_VECTOR);
        [$credential, $intermediate] = self::certificatesOf($vector->bytes);
        $authData = self::authDataOf($vector->bytes);

        Damage::withoutPhpErrors(static function() use ($vector, $credential, $intermediate, $authData): void {
            foreach (Damage::of($credential, [0x01], truncations: false) as $d) {
                self::assertChainRefusesDamage($credential, $d, self::outcomeOf($vector, self::attestationObject(self::x5c($d->bytes, $intermediate), $authData)));
            }

            foreach (Damage::of($intermediate, [0x01], truncations: false) as $d) {
                self::assertChainRefusesDamage($intermediate, $d, self::outcomeOf($vector, self::attestationObject(self::x5c($credential, $d->bytes), $authData)));
            }
        });
    }

    /**
     * Damage that makes phpseclib raise a warning, found by damaging every byte of the certificates.
     *
     * @return iterable<string, array{bool, int, int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideCertificateDamageThatMakesPhpseclibWarn(): iterable
    {
        yield 'credential byte 9 XOR 0x01' => [false, 9, 0x01];
        yield 'credential byte 385 XOR 0x80' => [false, 385, 0x80];
        yield 'credential byte 386 XOR 0x01' => [false, 386, 0x01];
        yield 'credential byte 387 XOR 0xFF' => [false, 387, 0xFF];
        yield 'credential byte 417 XOR 0xFF' => [false, 417, 0xFF];
        yield 'intermediate byte 9 XOR 0x01' => [true, 9, 0x01];
        yield 'intermediate byte 360 XOR 0x80' => [true, 360, 0x80];
        yield 'intermediate byte 395 XOR 0x01' => [true, 395, 0x01];
        yield 'intermediate byte 460 XOR 0xFF' => [true, 460, 0xFF];
    }

    #[DataProvider('provideCertificateDamageThatMakesPhpseclibWarn')]
    public function testCertificateDamageThatMakesPhpseclibWarnFailsTheChainSilently(bool $intermediateDamaged, int $offset, int $mask): void
    {
        $vector = Fixtures::attestation(self::MUTATED_VECTOR);
        [$credential, $intermediate] = self::certificatesOf($vector->bytes);

        if ($intermediateDamaged) {
            $intermediate = Damage::flipped($intermediate, $offset, $mask);
        } else {
            $credential = Damage::flipped($credential, $offset, $mask);
        }

        $cbor = self::attestationObject(self::x5c($credential, $intermediate), self::authDataOf($vector->bytes));

        self::assertSame(
            AttestationFailureReason::CertificateChain->name,
            Damage::withoutPhpErrors(static fn(): string => self::outcomeOf($vector, $cbor)),
        );
    }

    /**
     * @param list<Environment> $allowed
     */
    private static function verifyVector(
        AttestationVector $vector,
        ?string $clientDataHash = null,
        ?string $keyId = null,
        ?AppIdentity $app = null,
        ?array $allowed = null,
        ?ClockInterface $clock = null,
        ?string $cbor = null,
    ): AttestedKey {
        return (new AttestationVerifier(null, $clock ?? $vector->clock()))->verify(
            $cbor ?? $vector->bytes,
            $clientDataHash ?? $vector->clientDataHash,
            $keyId ?? $vector->keyId,
            $app ?? $vector->app(),
            $allowed ?? [$vector->environment],
        );
    }

    /**
     * @param list<Environment> $allowed
     */
    private static function verifyBuilt(BuiltAttestation $attestation, array $allowed = [Environment::Development], ?string $cbor = null): AttestedKey
    {
        return (new AttestationVerifier($attestation->trustAnchor(), $attestation->clock()))->verify(
            $cbor ?? $attestation->cbor,
            $attestation->clientDataHash,
            $attestation->keyId,
            $attestation->app,
            $allowed,
        );
    }

    private static function verifyWithTheDefaultClock(BuiltAttestation $attestation): AttestedKey
    {
        return (new AttestationVerifier($attestation->trustAnchor()))->verify(
            $attestation->cbor,
            $attestation->clientDataHash,
            $attestation->keyId,
            $attestation->app,
            [Environment::Development],
        );
    }

    /**
     * @param callable(): mixed $verification
     */
    private static function assertFailure(AttestationFailureReason $reason, callable $verification): void
    {
        try {
            $verification();
        } catch (AttestationException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());

            return;
        }

        self::fail('The attestation was accepted, expected ' . $reason->name . '.');
    }

    private static function outcomeOf(AttestationVector $vector, string $cbor): string
    {
        try {
            self::verifyVector($vector, cbor: $cbor);

            return 'accepted';
        } catch (AttestationException $e) {
            return $e->reason->name;
        }
    }

    private static function x5c(string ...$certificates): ListObject
    {
        return ListObject::create(array_map(static fn(string $der): ByteStringObject => ByteStringObject::create($der), array_values($certificates)));
    }

    private static function attestationObject(
        CBORObject $x5c,
        ?string $authData,
        ?string $format = AttestationBuilder::FORMAT,
        ?string $receipt = AttestationBuilder::RECEIPT,
    ): string {
        $attStmt = MapObject::create()->add(TextStringObject::create('x5c'), $x5c);
        $document = MapObject::create();

        if ($receipt !== null) {
            $attStmt->add(TextStringObject::create('receipt'), ByteStringObject::create($receipt));
        }

        if ($format !== null) {
            $document->add(TextStringObject::create('fmt'), TextStringObject::create($format));
        }

        $document->add(TextStringObject::create('attStmt'), $attStmt);

        if ($authData !== null) {
            $document->add(TextStringObject::create('authData'), ByteStringObject::create($authData));
        }

        return (string) $document;
    }

    /**
     * The attestation with each string of the type Apple uses, except $retyped: a text string where a byte
     * string belongs, or the other way round.
     */
    private static function attestationObjectRetyping(BuiltAttestation $attestation, ?string $retyped): string
    {
        $string = static fn(string $member, string $value, bool $text = false): CBORObject => $text !== ($member === $retyped)
            ? TextStringObject::create($value)
            : ByteStringObject::create($value);
        $key = static fn(string $name): CBORObject => $string('key ' . $name, $name, true);
        $attStmt = MapObject::create()
            ->add($key('x5c'), ListObject::create([$string('credential', $attestation->credentialDer), $string('intermediate', $attestation->intermediateDer)]))
            ->add($key('receipt'), $string('receipt', $attestation->receipt));

        return (string) MapObject::create()
            ->add($key('fmt'), $string('fmt', AttestationBuilder::FORMAT, true))
            ->add($key('attStmt'), $attStmt)
            ->add($key('authData'), $string('authData', $attestation->authData));
    }

    /**
     * The attestation encoded by hand, so that a map may hold any key after the members Apple puts in it,
     * one of those members included.
     *
     * @param list<CBORObject> $document keys and values, alternating, added to the document
     * @param list<CBORObject> $attStmt  keys and values, alternating, added to attStmt
     */
    private static function attestationObjectAdding(BuiltAttestation $attestation, array $document = [], array $attStmt = []): string
    {
        $statement = self::handEncodedMap(
            (string) TextStringObject::create('x5c'),
            (string) self::x5c($attestation->credentialDer, $attestation->intermediateDer),
            (string) TextStringObject::create('receipt'),
            (string) ByteStringObject::create($attestation->receipt),
            ...array_map(static fn(CBORObject $item): string => (string) $item, $attStmt),
        );

        return self::handEncodedMap(
            (string) TextStringObject::create('fmt'),
            (string) TextStringObject::create(AttestationBuilder::FORMAT),
            (string) TextStringObject::create('attStmt'),
            $statement,
            (string) TextStringObject::create('authData'),
            (string) ByteStringObject::create($attestation->authData),
            ...array_map(static fn(CBORObject $item): string => (string) $item, $document),
        );
    }

    /**
     * A definite-length map of fewer than 24 entries from its keys and values, alternating and encoded.
     */
    private static function handEncodedMap(string ...$keysAndValues): string
    {
        self::assertSame(0, count($keysAndValues) % 2);

        return chr(0xA0 + intdiv(count($keysAndValues), 2)) . implode('', $keysAndValues);
    }

    private static function assertChainRefusesDamage(string $der, Damaged $damaged, string $outcome): void
    {
        if ($outcome === 'accepted') {
            self::assertTrue(self::isSignatureUnusedBitsByte($der, $damaged->offset), 'Damage at certificate byte ' . $damaged->offset . ' was accepted.');

            return;
        }

        self::assertSame(AttestationFailureReason::CertificateChain->name, $outcome, 'Damage at certificate byte ' . $damaged->offset . '.');
    }

    /**
     * Whether damage at this byte of a genuine attestation leaves it valid: inside the receipt, which is not
     * signed, or the unused-bits byte of a certificate's signature.
     */
    private static function isHarmlessDamage(string $cbor, int $offset): bool
    {
        $receipt = self::receiptOf($cbor);
        $receiptStart = mb_strpos($cbor, $receipt, 0, '8bit');

        if (is_int($receiptStart) && $offset >= $receiptStart && $offset < $receiptStart + mb_strlen($receipt, '8bit')) {
            return true;
        }

        foreach (self::certificatesOf($cbor) as $der) {
            $start = mb_strpos($cbor, $der, 0, '8bit');

            if (is_int($start) && self::isSignatureUnusedBitsByte($der, $offset - $start)) {
                return true;
            }
        }

        return false;
    }

    /**
     * phpseclib skips the unused-bits byte of the signature BIT STRING, the last element of a certificate,
     * so damage there leaves the certificate valid.
     *
     * @psalm-pure
     */
    private static function isSignatureUnusedBitsByte(string $der, int $offset): bool
    {
        $length = mb_strlen($der, '8bit');

        return $offset >= 2 && $offset < $length && $der[$offset - 2] === "\x03" && ord($der[$offset - 1]) === $length - $offset;
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function documentOf(string $cbor): array
    {
        $object = Decoder::create()->decode(StringStream::create($cbor));
        self::assertInstanceOf(Normalizable::class, $object);
        $document = $object->normalize();
        self::assertIsArray($document);

        return $document;
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function attStmtOf(string $cbor): array
    {
        $attStmt = self::documentOf($cbor)['attStmt'] ?? null;
        self::assertIsArray($attStmt);

        return $attStmt;
    }

    private static function receiptOf(string $cbor): string
    {
        $receipt = self::attStmtOf($cbor)['receipt'] ?? null;
        self::assertIsString($receipt);
        self::assertNotSame('', $receipt);

        return $receipt;
    }

    /**
     * @return array{string, string}
     */
    private static function certificatesOf(string $cbor): array
    {
        $x5c = self::attStmtOf($cbor)['x5c'] ?? null;
        self::assertIsArray($x5c);
        $credential = $x5c[0] ?? null;
        $intermediate = $x5c[1] ?? null;
        self::assertIsString($credential);
        self::assertIsString($intermediate);

        return [$credential, $intermediate];
    }

    private static function authDataOf(string $cbor): string
    {
        $authData = self::documentOf($cbor)['authData'] ?? null;
        self::assertIsString($authData);

        return $authData;
    }

    /**
     * Definite-length SEQUENCEs nested inside each other, at least this many bytes in all.
     */
    private static function nestedSequences(int $length): string
    {
        $der = '';

        while (mb_strlen($der, '8bit') < $length) {
            $der = "\x30" . ASN1::encodeLength(mb_strlen($der, '8bit')) . $der;
        }

        return $der;
    }

    private static function chunked(string $bytes): IndefiniteLengthByteStringObject
    {
        return IndefiniteLengthByteStringObject::create(...mb_str_split($bytes, 50, '8bit'));
    }

    private static function spkiOf(string $pem): string
    {
        $spki = Pem::toDer($pem);
        self::assertSame(EcKey::SPKI_LENGTH, mb_strlen($spki, '8bit'));

        return $spki;
    }
}
