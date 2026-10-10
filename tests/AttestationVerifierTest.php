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
use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use Oire\AppAttest\AttestationVerifier;
use Oire\AppAttest\Exception\AttestationException;
use Oire\AppAttest\Exception\AttestationFailureReason;
use Oire\AppAttest\Tests\Support\AttestationBuilder;
use Oire\AppAttest\Tests\Support\AttestationVector;
use Oire\AppAttest\Tests\Support\BuiltAttestation;
use Oire\AppAttest\Tests\Support\Damage;
use Oire\AppAttest\Tests\Support\Damaged;
use Oire\AppAttest\Tests\Support\EcKey;
use Oire\AppAttest\Tests\Support\ExtensionsMap;
use Oire\AppAttest\Tests\Support\HostileInput;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\Tests\Support\RsaKey;
use Oire\AppAttest\Tests\Support\SignedCertificate;
use Oire\AppAttest\Tests\Support\Tagged;
use Oire\AppAttest\Tests\Support\TestApp;
use Oire\AppAttest\TrustAnchor;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\AttestedKey;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\LaunchPolicy;
use Oire\AppAttest\Value\TeamId;
use Oire\AppAttest\Value\ValidationCategory;
use phpseclib4\Crypt\Common\Formats\Keys\PKCS;
use phpseclib4\Crypt\EC;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps\Certificate;
use phpseclib4\File\X509;
use phpseclib4\Math\BigInteger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionProperty;
use Symfony\Component\Clock\MockClock;
use Throwable;
use UnexpectedValueException;

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
    private const string GUIDE_VECTOR = 'takimoto3-apple-guide';
    private const int MAX_UINT32 = 0xFFFFFFFF;
    private const int MAX_LENGTH = 16384;
    private const int HOSTILE_ITEMS = 600_000;
    private const int NESTED_SEQUENCES_LENGTH = 14000;
    private const int MAX_CERTIFICATE_LENGTH = 4096;
    private const int LENGTH_ATTEMPTS = 20;

    /**
     * The validity's index among a built certificate's tbsCertificate fields, after the version, the serial
     * number, the signature algorithm and the issuer.
     */
    private const int VALIDITY_FIELD = 4;

    /**
     * 2.5.29.98, an extension OID no certificate the chain checks uses.
     */
    private const string UNKNOWN_EXTENSION = "\x06\x03\x55\x1d\x62";
    private const string SERIAL_NUMBER = "\x01\x02\x03\x04\x05\x06\x07\x08";

    /**
     * @var ?array<string, array{string, Closure(): string}>
     */
    private static ?array $settingIndependentCases = null;

    /**
     * @return iterable<string, array{AttestationVector}>
     */
    public static function provideGenuineVectors(): iterable
    {
        foreach (Fixtures::attestations() as $name => $vector) {
            yield $name => [$vector];
        }
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
    }

    /**
     * @return iterable<string, array{array<mixed>}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideAllowedListsNotOfEnvironments(): iterable
    {
        yield 'empty' => [[]];
        yield 'a string' => [['development']];
        yield 'an environment and a string' => [[Environment::Development, 'production']];
        yield 'an enum value' => [[Environment::Development->value]];
    }

    /**
     * @param array<mixed> $allowed
     */
    #[DataProvider('provideAllowedListsNotOfEnvironments')]
    public function testAllowedListNotOfEnvironmentsIsACallerError(array $allowed): void
    {
        $attestation = AttestationBuilder::create()->build();
        $verifier = new AttestationVerifier($attestation->trustAnchor(), $attestation->clock());

        $this->expectException(InvalidArgumentException::class);
        /** @psalm-suppress ArgumentTypeCoercion, InvalidArgument */
        $verifier->verify($attestation->cbor, $attestation->clientDataHash, $attestation->keyId, $attestation->app, $allowed);
    }

    public function testAnInvalidAllowedListIsReportedBeforeTheAttestationIsRead(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttestationVerifier())->verify('garbage', '', '', TestApp::identity(), []);
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

    public function testExpiredIntermediateFailsTheChain(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExpiredIntermediate()
            ->build();

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
    }

    public function testIntermediateNotYetValidFailsTheChain(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateNotYetValid()
            ->build();

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
    }

    public function testCredentialNamingTheSerialNumberOfItsIssuerIsAccepted(): void
    {
        $serialNumber = new BigInteger('0102030405060708', 16);
        $attestation = AttestationBuilder::create()
            ->withIntermediateSerialNumber($serialNumber)
            ->withCredentialAuthorityCertSerialNumber($serialNumber)
            ->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
    }

    /**
     * Every process-wide phpseclib setting that code the library calls, or called before it read certificates
     * with its own DER reader, could read. Each closure changes the setting and returns the closure that puts it
     * back.
     *
     * @return iterable<string, array{Closure(): Closure(): void}>
     */
    public static function provideProcessWideSettings(): iterable
    {
        yield 'ASN1::enableBlobsOnBadDecodes()' => [self::changing([[ASN1::class, 'blobsOnBadDecodes']], static fn() => ASN1::enableBlobsOnBadDecodes())];
        yield 'ASN1::setRecursionDepth(1)' => [self::changing([[ASN1::class, 'recursionDepth']], static fn() => ASN1::setRecursionDepth(1))];
        yield 'ASN1::disableCacheInvalidation()' => [self::changing([[ASN1::class, 'invalidateCache']], static fn() => ASN1::disableCacheInvalidation())];
        yield 'ASN1::ignoreEncodedCache()' => [self::changing([[ASN1::class, 'useEncodedCache']], static fn() => ASN1::ignoreEncodedCache())];
        yield 'ASN1::enable64BitOIDHandling()' => [self::changing([[ASN1::class, 'use64BitOIDHandling']], static fn() => ASN1::enable64BitOIDHandling())];
        yield 'ASN1::loadOIDs() naming every OID the chain reads' => [self::changing([[ASN1::class, 'oids'], [ASN1::class, 'reverseOIDs']], static fn() => ASN1::loadOIDs([
            'oireKeyUsage' => SignedCertificate::KEY_USAGE_OID,
            'oireSubjectKeyIdentifier' => SignedCertificate::SUBJECT_KEY_IDENTIFIER_OID,
            'oireAuthorityKeyIdentifier' => SignedCertificate::AUTHORITY_KEY_IDENTIFIER_OID,
            'oireBasicConstraints' => SignedCertificate::BASIC_CONSTRAINTS_OID,
            'oireNonce' => SignedCertificate::NONCE_OID,
            'oireEcdsaWithSha256' => '1.2.840.10045.4.3.2',
        ]))];
        yield 'X509::ignoreKeyUsage()' => [self::changing([[X509::class, 'checkKeyUsage']], static fn() => X509::ignoreKeyUsage())];
        yield 'X509::looseDNComparison()' => [self::changing([[X509::class, 'strictDNComparison']], static fn() => X509::looseDNComparison())];
        yield 'X509::ignoreBasicConstraints()' => [self::changing([[X509::class, 'checkBasicConstraints']], static fn() => X509::ignoreBasicConstraints())];
        yield 'X509::setTargetValidationDate(null)' => [self::changing([[X509::class, 'targetValidationDate']], static fn() => X509::setTargetValidationDate(null))];
        yield 'X509::setRecurLimit(0)' => [self::changing([[X509::class, 'recur_limit']], static fn() => X509::setRecurLimit(0))];
        yield 'X509::addCA() with another root' => [self::changing([[X509::class, 'CAs']], static fn() => X509::addCA(AttestationBuilder::create()->build()->rootPem))];
        yield 'X509::registerExtension() for the nonce extension' => [self::changing([[X509::class, 'extensions']], static fn() => X509::registerExtension(SignedCertificate::NONCE_OID, ['type' => ASN1::TYPE_BOOLEAN]))];
        yield 'X509::enableBinaryOutput()' => [self::changing([[X509::class, 'binary']], static fn() => X509::enableBinaryOutput())];
        yield 'PKCS::requirePEM()' => [self::changing([[PKCS::class, 'format']], static fn() => PKCS::requirePEM())];
        yield 'EC::forceEngine(\'PHP\')' => [self::changing([[EC::class, 'forcedEngine']], static fn() => EC::forceEngine('PHP'))];
        yield 'BigInteger::setEngine(\'PHP64\')' => [static function(): Closure {
            $engine = BigInteger::getEngine();
            BigInteger::setEngine('PHP64');

            return static fn() => BigInteger::setEngine($engine[0] ?? 'GMP', [$engine[1] ?? 'DefaultEngine']);
        }];
    }

    /**
     * @param Closure(): Closure(): void $change
     */
    #[DataProvider('provideProcessWideSettings')]
    public function testNoProcessWideSettingChangesAnOutcome(Closure $change): void
    {
        $cases = self::settingIndependentCases();
        $expected = array_map(static fn(array $case): string => $case[0], $cases);
        $before = array_map(static fn(array $case): string => $case[1](), $cases);
        $restore = $change();

        try {
            $during = array_map(static fn(array $case): string => $case[1](), $cases);
        } finally {
            $restore();
        }

        self::assertSame($expected, $before);
        self::assertSame($expected, $during);
    }

    /**
     * Certificates of a built chain whose structure is malformed or not DER, each signed again by its issuer,
     * so only the structure can fail the check. Several are read otherwise by phpseclib's ASN.1 mapper once
     * ASN1::enableBlobsOnBadDecodes() is on, which the library no longer uses.
     *
     * @return iterable<string, array{Closure(AttestationBuilder): AttestationBuilder, AttestationFailureReason}>
     */
    public static function provideMalformedCertificateStructures(): iterable
    {
        $chain = AttestationFailureReason::CertificateChain;
        $null = "\x05\x00";
        $unknownCritical = SignedCertificate::extension(self::UNKNOWN_EXTENSION, "\x05\x00", true);

        yield 'intermediate whose basicConstraints adds an unmappable element to cA true' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x05\x01\x01\xff\x05\x00"), $chain];
        yield 'intermediate whose basicConstraints cA is FALSE' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x03\x01\x01\x00"), $chain];
        yield 'intermediate whose basicConstraints is empty' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x00"), $chain];
        yield 'intermediate whose basicConstraints cA is 0x01' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x03\x01\x01\x01"), $chain];
        yield 'intermediate whose basicConstraints cA is two octets' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x04\x01\x02\xff\xff"), $chain];
        yield 'intermediate whose basicConstraints has a byte after it' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x03\x01\x01\xff\x00"), $chain];
        yield 'intermediate whose basicConstraints length is in long form' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x81\x03\x01\x01\xff"), $chain];
        yield 'intermediate whose basicConstraints adds an element after its path length' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x08\x01\x01\xff\x02\x01\x00" . $null), $chain];
        yield 'intermediate whose basicConstraints has a negative path length' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x06\x01\x01\xff\x02\x01\xff"), $chain];
        yield 'intermediate whose basicConstraints has its path length before cA' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x06\x02\x01\x00\x01\x01\xff"), $chain];
        yield 'intermediate with basicConstraints twice' => [self::intermediateExtensions(static fn(array $extensions): array => [...$extensions, SignedCertificate::extension(SignedCertificate::BASIC_CONSTRAINTS, "\x30\x03\x01\x01\xff")]), $chain];
        yield 'intermediate whose key usage has an element after it' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x02\x01\x06" . $null), $chain];
        yield 'intermediate whose key usage declares eight unused bits' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x03\x08\x05\x00"), $chain];
        yield 'intermediate whose key usage sets an unused bit' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x02\x01\x07"), $chain];
        yield 'intermediate whose key usage keeps a trailing zero bit' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x02\x00\x06"), $chain];
        yield 'intermediate whose key usage is a constructed bit string' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x23\x04\x03\x02\x01\x06"), $chain];
        yield 'intermediate whose key usage names a bit past decipherOnly' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x03\x06\x04\x40"), $chain];
        yield 'intermediate whose subject key identifier has an element after it' => [self::intermediateExtension(SignedCertificate::SUBJECT_KEY_IDENTIFIER, static fn(?string $value): string => ($value ?? '') . $null), $chain];
        yield 'intermediate whose subject key identifier is an integer of the same bytes' => [self::intermediateExtension(SignedCertificate::SUBJECT_KEY_IDENTIFIER, static fn(?string $value): string => "\x02" . mb_substr($value ?? '', 1, null, '8bit')), $chain];
        yield 'intermediate whose serial number has a redundant leading zero' => [self::intermediateFields(static fn(array $fields): array => [$fields[0] ?? '', SignedCertificate::encoded("\x02", "\x00" . SignedCertificate::content($fields[1] ?? '')), ...array_slice($fields, 2)]), $chain];
        yield 'intermediate with its version twice' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x06\x02\x01\x02\x02\x01\x02", ...array_slice($fields, 1)]), $chain];
        yield 'intermediate whose version holds a NULL' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x02" . $null, ...array_slice($fields, 1)]), $chain];
        yield 'intermediate without a version, as in v1' => [self::intermediateFields(static fn(array $fields): array => array_slice($fields, 1)), $chain];
        yield 'intermediate whose version is an explicit v1' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x03\x02\x01\x00", ...array_slice($fields, 1)]), $chain];
        yield 'intermediate whose version is v2' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x03\x02\x01\x01", ...array_slice($fields, 1)]), $chain];
        yield 'intermediate whose version is 99' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x03\x02\x01\x63", ...array_slice($fields, 1)]), $chain];
        yield 'intermediate whose version is negative' => [self::intermediateFields(static fn(array $fields): array => ["\xa0\x03\x02\x01\xff", ...array_slice($fields, 1)]), $chain];
        yield 'intermediate whose basicConstraints is explicitly not critical' => [self::intermediateExtensions(static fn(array $extensions): array => array_map(
            static fn(string $extension): string => str_starts_with(SignedCertificate::content($extension), SignedCertificate::BASIC_CONSTRAINTS)
                ? SignedCertificate::encoded("\x30", SignedCertificate::BASIC_CONSTRAINTS . "\x01\x01\x00" . (array_slice(SignedCertificate::elements(SignedCertificate::content($extension)), -1)[0] ?? ''))
                : $extension,
            $extensions,
        )), $chain];
        yield 'intermediate with an unknown critical extension' => [self::intermediateExtensions(static fn(array $extensions): array => [...$extensions, $unknownCritical]), $chain];
        yield 'credential whose authority key identifier adds an unknown element' => [self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => SignedCertificate::encoded("\x30", SignedCertificate::content($value ?? '') . "\x83\x00")), $chain];
        yield 'credential whose authority key identifier holds a constructed key identifier' => [self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => "\x30\x16\xa0\x14" . mb_substr($value ?? '', 4, null, '8bit')), $chain];
        yield 'credential whose authority key identifier names an issuer with a high tag number' => [self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => SignedCertificate::encoded("\x30", SignedCertificate::content($value ?? '') . "\xa1\x02\x9f\x00")), $chain];
        yield 'credential whose authority key identifier has a byte after it' => [self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => ($value ?? '') . "\x00"), $chain];
        yield 'credential whose nonce extension adds an element to its SEQUENCE' => [self::credentialExtension(SignedCertificate::NONCE, static fn(?string $value): string => SignedCertificate::encoded("\x30", SignedCertificate::content($value ?? '') . $null)), AttestationFailureReason::Nonce];
        yield 'credential whose nonce extension holds two octet strings' => [self::credentialExtension(SignedCertificate::NONCE, static fn(?string $value): string => SignedCertificate::encoded("\x30", SignedCertificate::encoded("\xa1", SignedCertificate::content(SignedCertificate::content($value ?? '')) . "\x04\x00"))), AttestationFailureReason::Nonce];
        yield 'credential with an extension of four elements' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x0c\x06\x03\x55\x1d\x62\x05\x00\x01\x01\x00\x04\x00"]), $chain];
        yield 'credential with an extension whose critical flag is 0x01' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x0a\x06\x03\x55\x1d\x62\x01\x01\x01\x04\x00"]), $chain];
        yield 'credential with an extension whose critical flag is an explicit FALSE' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x0a\x06\x03\x55\x1d\x62\x01\x01\x00\x04\x00"]), $chain];
        yield 'credential with an unknown critical extension' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x0b\x06\x03\x55\x1d\x62\x01\x01\xff\x04\x01\x00"]), $chain];
        yield 'credential whose critical key usage keeps a trailing zero bit' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x03\x02\x00\x80"]]), $chain];
        yield 'credential whose critical key usage sets no bit' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x03\x01\x00"]]), $chain];
        yield 'credential whose critical key usage is an INTEGER' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x02\x01\x05"]]), $chain];
        yield 'credential whose key usage, not critical, has an element after it' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x03\x02\x07\x80" . $null, false]]), $chain];
        yield 'credential with its key usage twice' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x03\x02\x07\x80"], [SignedCertificate::KEY_USAGE, "\x03\x02\x07\x80"]]), $chain];
        yield 'credential whose critical basicConstraints writes cA FALSE' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x03\x01\x01\x00"]]), $chain];
        yield 'credential whose critical basicConstraints is a NULL' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, $null]]), $chain];
        yield 'credential whose critical basicConstraints has a byte after it' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x00\x00"]]), $chain];
        yield 'credential whose critical basicConstraints has a path length without cA' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x03\x02\x01\x00"]]), $chain];
        yield 'credential whose critical basicConstraints says cA TRUE' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x03\x01\x01\xff"]]), $chain];
        yield 'credential whose critical basicConstraints says cA TRUE with a path length' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x06\x01\x01\xff\x02\x01\x00"]]), $chain];
        yield 'credential whose basicConstraints, not critical, says cA TRUE' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x03\x01\x01\xff", false]]), $chain];
        yield 'credential with basicConstraints twice' => [self::credentialWithExtensions([[SignedCertificate::BASIC_CONSTRAINTS, "\x30\x00"], [SignedCertificate::BASIC_CONSTRAINTS, "\x30\x00"]]), $chain];
        yield 'credential whose critical subject key identifier is an INTEGER' => [self::credentialWithExtensions([[SignedCertificate::SUBJECT_KEY_IDENTIFIER, "\x02\x01\x01"]]), $chain];
        yield 'credential whose critical subject key identifier has a byte after it' => [self::credentialWithExtensions([[SignedCertificate::SUBJECT_KEY_IDENTIFIER, "\x04\x01\x01\x00"]]), $chain];
        yield 'credential whose subject key identifier, not critical, is a NULL' => [self::credentialWithExtensions([[SignedCertificate::SUBJECT_KEY_IDENTIFIER, $null, false]]), $chain];
        yield 'credential with its subject key identifier twice' => [self::credentialWithExtensions([[SignedCertificate::SUBJECT_KEY_IDENTIFIER, "\x04\x01\x01", false], [SignedCertificate::SUBJECT_KEY_IDENTIFIER, "\x04\x01\x01", false]]), $chain];
        yield 'intermediate whose subject key identifier is an INTEGER, the credential naming no authority key' => [
            static fn(AttestationBuilder $b): AttestationBuilder => self::intermediateExtension(SignedCertificate::SUBJECT_KEY_IDENTIFIER, static fn(): string => "\x02\x01\x01")(
                $b->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withoutExtension($tbs, SignedCertificate::AUTHORITY_KEY_IDENTIFIER)),
            ),
            $chain,
        ];
        yield 'intermediate with a critical nonce extension, which the chain processes only for the credential certificate' => [
            self::intermediateExtensions(static fn(array $extensions): array => [...$extensions, SignedCertificate::extension(SignedCertificate::NONCE, AttestationBuilder::nonceExtensionDer(str_repeat("\x00", 32)), true)]),
            $chain,
        ];
        yield 'credential with an extension whose value is a BIT STRING' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x08\x06\x03\x55\x1d\x62\x03\x01\x00"]), $chain];
        yield 'credential with an empty list of extensions' => [self::credentialFields(static fn(array $fields): array => [...array_slice($fields, 0, -1), "\xa3\x02\x30\x00"]), $chain];
        yield 'credential whose extensions tag holds two lists' => [self::credentialFields(static fn(array $fields): array => [
            ...array_slice($fields, 0, -1),
            SignedCertificate::encoded("\xa3", SignedCertificate::content(array_slice($fields, -1)[0] ?? '') . "\x30\x00"),
        ]), $chain];
        yield 'credential whose issuerUniqueID sets an unused bit' => [self::credentialFields(static fn(array $fields): array => [...array_slice($fields, 0, -1), "\x81\x02\x01\x01", ...array_slice($fields, -1)]), $chain];
        yield 'credential whose validity holds three times' => [self::credentialFields(static fn(array $fields): array => [
            ...array_slice($fields, 0, self::VALIDITY_FIELD),
            SignedCertificate::encoded("\x30", SignedCertificate::content($fields[self::VALIDITY_FIELD] ?? '') . "\x17\x0d270101000000Z"),
            ...array_slice($fields, self::VALIDITY_FIELD + 1),
        ]), $chain];
        yield 'credential whose authority key identifier names only the serial number, the issuer having a key identifier' => [
            static fn(AttestationBuilder $b): AttestationBuilder => self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(): string => SignedCertificate::encoded("\x30", "\x82\x08" . self::SERIAL_NUMBER))(
                $b->withIntermediateSerialNumber(new BigInteger(bin2hex(self::SERIAL_NUMBER), 16)),
            ),
            $chain,
        ];
        yield 'credential whose authority key identifier names the serial number with a redundant leading zero' => [
            static fn(AttestationBuilder $b): AttestationBuilder => self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => SignedCertificate::encoded(
                "\x30",
                SignedCertificate::content($value ?? '') . "\x82\x09\x00" . self::SERIAL_NUMBER,
            ))($b->withIntermediateSerialNumber(new BigInteger(bin2hex(self::SERIAL_NUMBER), 16))),
            $chain,
        ];
        yield 'credential with an extension whose OID is padded with 0x80' => [self::credentialExtensions(static fn(array $extensions): array => [...$extensions, "\x30\x08\x06\x04\x55\x80\x1d\x62\x04\x00"]), $chain];
        yield 'credential with an element after its extensions' => [self::credentialFields(static fn(array $fields): array => [...$fields, $null]), $chain];
        yield 'credential with an unknown element before its extensions' => [self::credentialFields(static fn(array $fields): array => [...array_slice($fields, 0, -1), "\x84\x00", ...array_slice($fields, -1)]), $chain];
        yield 'credential whose notAfter has no seconds' => [self::credentialNotAfter("\x17\x0b2601161200Z"), $chain];
        yield 'credential whose notAfter has a time zone offset' => [self::credentialNotAfter("\x17\x11260116120000+0000"), $chain];
        yield 'credential whose notAfter is in the thirteenth month' => [self::credentialNotAfter("\x17\x0d261316120000Z"), $chain];
        yield 'credential whose notAfter is a GeneralizedTime that has passed' => [self::credentialNotAfter("\x18\x0f20260115115959Z"), $chain];
        yield 'credential whose notAfter has fractional seconds' => [self::credentialNotAfter("\x18\x1120260116120000.5Z"), $chain];
        yield 'credential whose notAfter has a line feed after it' => [self::credentialNotAfter("\x17\x0e260116120000Z\n"), $chain];
        yield 'credential whose notAfter is a PrintableString' => [self::credentialNotAfter("\x13\x0d260116120000Z"), $chain];
        yield 'credential whose notAfter is a PrintableString in GeneralizedTime form' => [self::credentialNotAfter("\x13\x0f20260116120000Z"), $chain];
        yield 'credential whose notAfter in UTCTime is in 1950' => [self::credentialNotAfter("\x17\x0d500101000000Z"), $chain];
    }

    /**
     * @param Closure(AttestationBuilder): AttestationBuilder $variant
     */
    #[DataProvider('provideMalformedCertificateStructures')]
    public function testMalformedCertificateStructureFails(Closure $variant, AttestationFailureReason $reason): void
    {
        $attestation = $variant(AttestationBuilder::create())->build();

        self::assertFailure($reason, static fn() => self::verifyBuilt($attestation));
    }

    /**
     * @return iterable<string, array{Closure(AttestationBuilder): AttestationBuilder}>
     */
    public static function provideWellFormedCertificateVariants(): iterable
    {
        yield 'intermediate whose basicConstraints carries a path length of zero, as Apple\'s does' => [self::intermediateExtension(SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => "\x30\x06\x01\x01\xff\x02\x01\x00")];
        yield 'intermediate whose key usage includes decipherOnly' => [self::intermediateExtension(SignedCertificate::KEY_USAGE, static fn(): string => "\x03\x03\x07\x86\x80")];
        yield 'credential whose notAfter is a GeneralizedTime' => [self::credentialNotAfter("\x18\x0f20260116120000Z")];
        yield 'chain issued last century, in UTCTime' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withTime(new DateTimeImmutable('1999-06-01T12:00:00Z'))];
        yield 'credential whose notAfter in UTCTime is in 2049' => [self::credentialNotAfter("\x17\x0d491231235959Z")];
        yield 'credential with issuer and subject unique identifiers' => [self::credentialFields(static fn(array $fields): array => [...array_slice($fields, 0, -1), "\x81\x02\x00\x01", "\x82\x03\x04\x02\x30", ...array_slice($fields, -1)])];
        yield 'credential whose authority key identifier names the key, the issuer\'s issuer and the serial number' => [
            static fn(AttestationBuilder $b): AttestationBuilder => self::credentialExtension(SignedCertificate::AUTHORITY_KEY_IDENTIFIER, static fn(?string $value): string => SignedCertificate::encoded(
                "\x30",
                SignedCertificate::content($value ?? '') . SignedCertificate::encoded("\xa1", SignedCertificate::encoded("\xa4", "\x30\x00")) . "\x82\x08" . self::SERIAL_NUMBER,
            ))($b->withIntermediateSerialNumber(new BigInteger(bin2hex(self::SERIAL_NUMBER), 16))),
        ];
        yield 'intermediate without a subject key identifier, the credential naming its key identifier' => [
            static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withoutExtension($tbs, SignedCertificate::SUBJECT_KEY_IDENTIFIER)),
        ];
        yield 'intermediate with an unknown extension that is not critical' => [self::intermediateExtensions(static fn(array $extensions): array => [...$extensions, SignedCertificate::extension(self::UNKNOWN_EXTENSION, "\x05\x00")])];
        yield 'intermediate with a nonce extension that is not critical' => [
            self::intermediateExtensions(static fn(array $extensions): array => [...$extensions, SignedCertificate::extension(SignedCertificate::NONCE, AttestationBuilder::nonceExtensionDer(str_repeat("\x00", 32)))]),
        ];
        yield 'credential with a critical key usage of digitalSignature' => [self::credentialWithExtensions([[SignedCertificate::KEY_USAGE, "\x03\x02\x07\x80"]])];
        yield 'credential with a critical key usage and an empty critical basicConstraints, as Apple\'s has' => [self::credentialWithExtensions([
            [SignedCertificate::BASIC_CONSTRAINTS, "\x30\x00"],
            [SignedCertificate::KEY_USAGE, "\x03\x02\x04\xf0"],
        ])];
        yield 'credential with a critical subject key identifier' => [self::credentialWithExtensions([[SignedCertificate::SUBJECT_KEY_IDENTIFIER, "\x04\x14" . str_repeat("\x5a", 20)]])];
    }

    /**
     * @param Closure(AttestationBuilder): AttestationBuilder $variant
     */
    #[DataProvider('provideWellFormedCertificateVariants')]
    public function testWellFormedCertificateVariantIsAccepted(Closure $variant): void
    {
        $attestation = $variant(AttestationBuilder::create())->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
    }

    public function testValidityLastCenturyIsReadFromUtcTime(): void
    {
        $attestation = AttestationBuilder::create()
            ->withTime(new DateTimeImmutable('1999-06-01T12:00:00Z'))
            ->build();

        self::assertStringContainsString("\x17\x0d980601120000Z", $attestation->intermediateDer);
        self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
    }

    /**
     * @return iterable<string, array{Closure(AttestationBuilder): AttestationBuilder}>
     */
    public static function provideBuiltChainsThatFail(): iterable
    {
        yield 'intermediate signed by another key than the root' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateSignedByAnotherKey()];
        yield 'credential signed by another key than the intermediate' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialSignedByAnotherKey()];
        yield 'intermediate naming another issuer' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateIssuerName('Oire Test Other Root CA')];
        yield 'credential naming another issuer' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialIssuerName('Oire Test Other CA')];
        yield 'CA intermediate without keyCertSign' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKeyUsage(['digitalSignature', 'cRLSign'])];
        yield 'credential naming another key as its authority' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialNamingAnotherKey()];
        yield 'credential naming another serial number of its issuer' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialAuthorityCertSerialNumber(new BigInteger(1))];
        yield 'intermediate with its key usage twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionTwice($tbs, SignedCertificate::KEY_USAGE))];
        yield 'intermediate with its subject key identifier twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionTwice($tbs, SignedCertificate::SUBJECT_KEY_IDENTIFIER))];
        yield 'credential with its authority key identifier twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionTwice($tbs, SignedCertificate::AUTHORITY_KEY_IDENTIFIER))];
        yield 'credential signed with ECDSA over SHA-1' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialSignatureHash('sha1')];
        yield 'intermediate with an RSA key' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKey(RsaKey::generate())];
        yield 'intermediate with an Ed25519 key' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKey(EC::createKey('Ed25519'))];
        yield 'credential signed under ecdsa-with-SHA512 inside' => [self::credentialSignedAlgorithm(SignedCertificate::ECDSA_WITH_SHA512)];
        yield 'credential signed under id-ecPublicKey inside' => [self::credentialSignedAlgorithm(SignedCertificate::ID_EC_PUBLIC_KEY)];
        yield 'credential issued by a CA the chain does not hold, named in caIssuers' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialFromAnUnlistedIssuer('http://192.0.2.1/ca.cer')];
    }

    /**
     * @param Closure(AttestationBuilder): AttestationBuilder $variant
     */
    #[DataProvider('provideBuiltChainsThatFail')]
    public function testBuiltChainFails(Closure $variant): void
    {
        $attestation = $variant(AttestationBuilder::create())->build();

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideAcceptedSignatureHashes(): iterable
    {
        yield 'SHA-384' => ['sha384'];
        yield 'SHA-512' => ['sha512'];
    }

    #[DataProvider('provideAcceptedSignatureHashes')]
    public function testCredentialSignedWithAnotherSha2HashIsAccepted(string $hash): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialSignatureHash($hash)
            ->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
    }

    public function testRootWithoutKeyUsageCannotBeATrustAnchor(): void
    {
        $attestation = AttestationBuilder::create()
            ->withRootWithoutKeyUsage()
            ->build();

        $this->expectException(InvalidArgumentException::class);
        $attestation->trustAnchor();
    }

    /**
     * @return iterable<string, array{bool, Closure(string, string, string): string}>
     */
    public static function provideReencodedCertificates(): iterable
    {
        yield 'credential with a fourth element after its signature' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::encoded("\x30", $tbs . $algorithm . SignedCertificate::encoded("\x03", $bits) . "\x05\x00")];
        yield 'credential with bytes after the ECDSA signature' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, $algorithm, $bits . "\xde\xad\xbe\xef")];
        yield 'credential with the ECDSA signature length in long form' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, $algorithm, "\x00\x30\x81" . mb_substr($bits, 2, null, '8bit'))];
        yield 'credential with a zero byte before r' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, $algorithm, self::withZeroBeforeR($bits))];
        yield 'credential declaring unused signature bits' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, $algorithm, "\x07" . mb_substr($bits, 1, null, '8bit'))];
        yield 'credential with NULL signature algorithm parameters' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, SignedCertificate::encoded("\x30", mb_substr($algorithm, 2, null, '8bit') . "\x05\x00"), $bits)];
        yield 'credential with the signature BIT STRING length in long form' => [false, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::encoded("\x30", $tbs . $algorithm . "\x03\x81" . chr(mb_strlen($bits, '8bit')) . $bits)];
        yield 'credential with its length in long form' => [false, static fn(string $tbs, string $algorithm, string $bits): string => self::inLongForm($tbs . $algorithm . SignedCertificate::encoded("\x03", $bits))];
        yield 'intermediate declaring unused signature bits' => [true, static fn(string $tbs, string $algorithm, string $bits): string => SignedCertificate::join($tbs, $algorithm, "\x07" . mb_substr($bits, 1, null, '8bit'))];
    }

    /**
     * @param Closure(string, string, string): string $reencode the certificate from its tbsCertificate,
     *                                                          signatureAlgorithm and signature BIT STRING content
     */
    #[DataProvider('provideReencodedCertificates')]
    public function testCertificateEncodedOtherwiseThanSignedFailsTheChain(bool $intermediate, Closure $reencode): void
    {
        $attestation = AttestationBuilder::create()->build();
        $original = $intermediate ? $attestation->intermediateDer : $attestation->credentialDer;
        $reencoded = $reencode(...SignedCertificate::split($original));
        $cbor = self::attestationObject(
            $intermediate ? self::x5c($attestation->credentialDer, $reencoded) : self::x5c($reencoded, $attestation->intermediateDer),
            $attestation->authData,
        );

        self::assertNotSame($original, $reencoded);
        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
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

    public function testNonceExtensionWithBytesAfterItFails(): void
    {
        $attestation = AttestationBuilder::create()
            ->withNonceExtensionSuffix("\x00")
            ->build();

        self::assertFailure(AttestationFailureReason::Nonce, static fn() => self::verifyBuilt($attestation));
    }

    /**
     * @return iterable<string, array{?string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideEarlierNonceExtensions(): iterable
    {
        yield 'the correct one twice' => [null];
        yield 'another before the correct one' => [AttestationBuilder::nonceExtensionDer(hash('sha256', 'another nonce', true))];
    }

    #[DataProvider('provideEarlierNonceExtensions')]
    public function testTwoNonceExtensionsFailTheNonce(?string $earlierDer): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionTwice($tbs, SignedCertificate::NONCE, $earlierDer))
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCredentialPublicKeysThatAreNotMaps(): iterable
    {
        yield 'not CBOR' => ["\x1f\x1f\x1f\x1f"];
        yield 'a break byte' => ["\xff"];
        yield 'a list' => [(string) ListObject::create([ByteStringObject::create(EcKey::generate()->point)])];
        yield 'a byte string' => [(string) ByteStringObject::create(EcKey::generate()->point)];
        yield 'a text string' => [(string) TextStringObject::create('cose')];
        yield 'an integer' => [(string) UnsignedIntegerObject::create(2)];
        yield 'a tagged map' => [(string) Tagged::of(MapObject::create()->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)))];
    }

    #[DataProvider('provideCredentialPublicKeysThatAreNotMaps')]
    public function testCredentialPublicKeyThatIsNotACborMapIsMalformed(string $coseKey): void
    {
        $alone = AttestationBuilder::create()
            ->withCoseKey($coseKey)
            ->build();
        $beforeExtensions = AttestationBuilder::create()
            ->withCoseKey($coseKey)
            ->withExtensions(ExtensionsMap::apple(4, '1.0'))
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($alone));
        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($beforeExtensions));
    }

    /**
     * @return iterable<string, array{int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideCoseKeyTruncations(): iterable
    {
        yield 'only the map header' => [1];
        yield 'within the x coordinate' => [20];
        yield 'one byte short' => [-1];
    }

    #[DataProvider('provideCoseKeyTruncations')]
    public function testTruncatedCredentialPublicKeyIsMalformed(int $length): void
    {
        $attestation = AttestationBuilder::create()
            ->withCoseKey(mb_substr(AttestationBuilder::coseKey(EcKey::generate()), 0, $length, '8bit'))
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testCredentialPublicKeyMapIsNotMatchedAgainstTheCertificate(): void
    {
        $otherKey = AttestationBuilder::create()
            ->withCoseKey(AttestationBuilder::coseKey(EcKey::generate()))
            ->withExtensions(ExtensionsMap::apple(4, '1.0'))
            ->build();
        $indefiniteEmptyMap = AttestationBuilder::create()
            ->withCoseKey((string) IndefiniteLengthMapObject::create())
            ->build();

        self::assertSame(4, self::verifyBuilt($otherKey)->validationCategory);
        self::assertSame($indefiniteEmptyMap->keyId, self::verifyBuilt($indefiniteEmptyMap)->keyId);
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

    /**
     * @return iterable<string, array{bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideNestedSequencePositions(): iterable
    {
        yield 'as the credential' => [false];
        yield 'as the intermediate' => [true];
    }

    #[DataProvider('provideNestedSequencePositions')]
    public function testDeeplyNestedSequencesAreRefusedCheaply(bool $asIntermediate): void
    {
        $attestation = AttestationBuilder::create()->build();
        $nested = self::nestedSequences(self::NESTED_SEQUENCES_LENGTH);
        $certificates = $asIntermediate ? [$attestation->credentialDer, $nested] : [$nested, $attestation->intermediateDer];
        $cbor = self::attestationObject(self::x5c(...$certificates), $attestation->authData);

        self::assertLessThanOrEqual(self::MAX_LENGTH, mb_strlen($cbor, '8bit'));
        self::assertRefusedCheaply(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    /**
     * @return iterable<string, array{bool, int, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideCertificateLengthsAroundTheLimit(): iterable
    {
        yield 'credential of 4096 bytes' => [false, self::MAX_CERTIFICATE_LENGTH, true];
        yield 'credential of 4097 bytes' => [false, self::MAX_CERTIFICATE_LENGTH + 1, false];
        yield 'intermediate of 4096 bytes' => [true, self::MAX_CERTIFICATE_LENGTH, true];
        yield 'intermediate of 4097 bytes' => [true, self::MAX_CERTIFICATE_LENGTH + 1, false];
    }

    #[DataProvider('provideCertificateLengthsAroundTheLimit')]
    public function testCertificateIsAtMost4096Bytes(bool $intermediate, int $length, bool $accepted): void
    {
        $attestation = self::withCertificateOfLength($intermediate, $length);

        if ($accepted) {
            self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
        } else {
            self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
        }
    }

    /**
     * @return iterable<string, array{string, bool}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideTimesAroundTheCredentialValidity(): iterable
    {
        yield 'at its notBefore' => ['-1 day', true];
        yield 'a second before its notBefore' => ['-1 day -1 second', false];
        yield 'at its notAfter' => ['+1 day', true];
        yield 'a second after its notAfter' => ['+1 day +1 second', false];
    }

    #[DataProvider('provideTimesAroundTheCredentialValidity')]
    public function testCredentialIsValidFromItsNotBeforeToItsNotAfter(string $offset, bool $accepted): void
    {
        $attestation = AttestationBuilder::create()->build();
        $verifier = new AttestationVerifier($attestation->trustAnchor(), new MockClock($attestation->clock()->now()->modify($offset)));
        $verification = static fn(): AttestedKey => $verifier->verify($attestation->cbor, $attestation->clientDataHash, $attestation->keyId, $attestation->app, [Environment::Development]);

        if ($accepted) {
            self::assertSame($attestation->keyId, $verification()->keyId);
        } else {
            self::assertFailure(AttestationFailureReason::CertificateChain, $verification);
        }
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
        yield 'fmt tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'fmt')];
        yield 'attStmt tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'attStmt')];
        yield 'x5c tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'x5c')];
        yield 'credential certificate tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'credential')];
        yield 'intermediate certificate tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'intermediate')];
        yield 'receipt tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'receipt')];
        yield 'authData tagged' => [static fn(BuiltAttestation $a): string => self::attestationObjectTagging($a, 'authData')];
    }

    public function testDocumentWithNoMemberTaggedIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertSame($attestation->keyId, self::verifyBuilt($attestation, cbor: self::attestationObjectTagging($attestation, null))->keyId);
    }

    public function testAttestationWithinTheSizeLimitIsAccepted(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of(['padding' => ExtensionsMap::text(str_repeat('a', 14000))]))
            ->build();

        self::assertLessThanOrEqual(self::MAX_LENGTH, mb_strlen($attestation->cbor, '8bit'));
        self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
    }

    public function testAttestationOverTheSizeLimitIsMalformed(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of(['padding' => ExtensionsMap::text(str_repeat('a', self::MAX_LENGTH))]))
            ->build();

        self::assertFailure(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
    }

    public function testHostileDocumentIsRefusedBeforeItIsDecoded(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $cbor = "\xa1" . (string) TextStringObject::create('fmt') . HostileInput::indefiniteListOfEmptyLists(self::HOSTILE_ITEMS);

        self::assertRefusedCheaply(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
    }

    public function testHostileExtensionsAreaIsRefusedBeforeItIsDecoded(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions(HostileInput::indefiniteListOfEmptyLists(self::HOSTILE_ITEMS))
            ->build();

        self::assertRefusedCheaply(AttestationFailureReason::Format, static fn() => self::verifyBuilt($attestation));
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
        yield 'an integer key in a map nested in the document' => [[TextStringObject::create('extra'), MapObject::create()->add(UnsignedIntegerObject::create(1), ByteStringObject::create('value'))], []];
        yield 'a byte-string key in a map nested in attStmt' => [[], [TextStringObject::create('extra'), MapObject::create()->add(ByteStringObject::create('key'), ByteStringObject::create('value'))]];
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
                self::assertChainRefusesDamage($d, self::outcomeOf($vector, self::attestationObject(self::x5c($d->bytes, $intermediate), $authData)));
            }

            foreach (Damage::of($intermediate, [0x01], truncations: false) as $d) {
                self::assertChainRefusesDamage($d, self::outcomeOf($vector, self::attestationObject(self::x5c($credential, $d->bytes), $authData)));
            }
        });
    }

    /**
     * Damage that makes phpseclib 4 raise a warning (an empty OID) in the signature AlgorithmIdentifiers, found
     * by XORing every byte of the certificates with every mask. The library reads certificates with its own DER
     * reader, which must refuse them without a warning too.
     *
     * @return iterable<string, array{bool, int, int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideCertificateDamageThatMakesPhpseclibWarn(): iterable
    {
        yield 'credential byte 24 XOR 0x08' => [false, 24, 0x08];
        yield 'credential byte 646 XOR 0x08' => [false, 646, 0x08];
        yield 'intermediate byte 34 XOR 0x08' => [true, 34, 0x08];
        yield 'intermediate byte 467 XOR 0x08' => [true, 467, 0x08];
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

        self::assertNotSame([], self::phpseclibWarningsReading($intermediateDamaged ? $intermediate : $credential), 'phpseclib no longer warns on this damage.');

        $cbor = self::attestationObject(self::x5c($credential, $intermediate), self::authDataOf($vector->bytes));

        self::assertSame(
            AttestationFailureReason::CertificateChain->name,
            Damage::withoutPhpErrors(static fn(): string => self::outcomeOf($vector, $cbor)),
        );
    }

    public function testGuideVectorReportsItsLaunchValues(): void
    {
        $key = self::verifyVector(Fixtures::attestation(self::GUIDE_VECTOR));

        self::assertSame(1, $key->validationCategory);
        self::assertSame(ValidationCategory::Platform, $key->validationCategory());
        self::assertSame('1', $key->bundleVersion);
    }

    public function testGuideVectorPassesAPolicyAllowingItsLaunchValues(): void
    {
        $vector = Fixtures::attestation(self::GUIDE_VECTOR);
        $policies = [
            LaunchPolicy::allowing(ValidationCategory::Platform),
            LaunchPolicy::allowing(ValidationCategory::AppStore, ValidationCategory::Platform)->withBundleVersion(static fn(string $version): bool => $version === '1'),
            (new LaunchPolicy())->withBundleVersion(static fn(string $version): bool => $version !== ''),
            new LaunchPolicy(),
        ];

        foreach ($policies as $policy) {
            self::assertSame($vector->keyId, self::verifyVector($vector, launchPolicy: $policy)->keyId);
        }
    }

    public function testGuideVectorFailsAnAppStoreOnlyPolicy(): void
    {
        $policy = LaunchPolicy::allowing(ValidationCategory::AppStore);

        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyVector(Fixtures::attestation(self::GUIDE_VECTOR), launchPolicy: $policy));
    }

    public function testGuideVectorFailsAPolicyWantingAnotherBundleVersion(): void
    {
        $policy = LaunchPolicy::allowing(ValidationCategory::Platform)->withBundleVersion(static fn(string $version): bool => $version === '2.0');

        self::assertFailure(AttestationFailureReason::BundleVersion, static fn() => self::verifyVector(Fixtures::attestation(self::GUIDE_VECTOR), launchPolicy: $policy));
    }

    /**
     * @return iterable<string, array{AttestationVector}>
     */
    public static function provideVectorsWithoutLaunchValues(): iterable
    {
        foreach (Fixtures::attestations() as $name => $vector) {
            if ($name !== self::GUIDE_VECTOR) {
                yield $name => [$vector];
            }
        }
    }

    #[DataProvider('provideVectorsWithoutLaunchValues')]
    public function testVectorWithoutLaunchValuesReportsNoneAndFailsAPolicy(AttestationVector $vector): void
    {
        $key = self::verifyVector($vector);

        self::assertNull($key->validationCategory);
        self::assertNull($key->validationCategory());
        self::assertNull($key->bundleVersion);
        self::assertSame($vector->keyId, self::verifyVector($vector, launchPolicy: new LaunchPolicy())->keyId);
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyVector($vector, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        self::assertFailure(
            AttestationFailureReason::BundleVersion,
            static fn() => self::verifyVector($vector, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(): bool => true)),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCategoryEncodings(): iterable
    {
        yield 'four little-endian bytes' => [ExtensionsMap::apple(4, '2.1')];
        yield 'unsigned integer' => [ExtensionsMap::of([
            ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(4),
            ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('2.1'),
        ])];
        yield 'short spellings' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(4),
            ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('2.1'),
        ])];
        yield 'short spellings, unsigned integer' => [ExtensionsMap::of([
            ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('2.1'),
            ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(4),
        ])];
        yield 'after unknown entries' => [ExtensionsMap::of([
            'apple_other_01' => ExtensionsMap::text('x'),
            ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(4),
            ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('2.1'),
        ])];
        yield 'beside a nested map with integer keys' => [ExtensionsMap::of([
            'other' => MapObject::create()->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
            ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(4),
            ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('2.1'),
        ])];
        yield 'beside a list holding a map with a byte-string key' => [ExtensionsMap::of([
            ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(4),
            'other' => ListObject::create([MapObject::create()->add(ByteStringObject::create('key'), UnsignedIntegerObject::create(2))]),
            ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('2.1'),
        ])];
    }

    #[DataProvider('provideCategoryEncodings')]
    public function testBuiltLaunchValuesAreReportedAndEnforced(string $extensions): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions($extensions)
            ->build();
        $key = self::verifyBuilt($attestation);

        self::assertSame(4, $key->validationCategory);
        self::assertSame(ValidationCategory::AppStore, $key->validationCategory());
        self::assertSame('2.1', $key->bundleVersion);
        self::assertSame(
            $attestation->keyId,
            self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(ValidationCategory::AppStore)->withBundleVersion(static fn(string $version): bool => $version === '2.1'))->keyId,
        );
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(ValidationCategory::TestFlight)));
        self::assertFailure(
            AttestationFailureReason::BundleVersion,
            static fn() => self::verifyBuilt($attestation, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(string $version): bool => $version === '2.0')),
        );
    }

    /**
     * @return iterable<string, array{int}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideUnknownCategories(): iterable
    {
        yield 'zero' => [0];
        yield 'restricted 7' => [7];
        yield 'restricted 8' => [8];
        yield 'restricted 9' => [9];
        yield 'eleven' => [11];
        yield 'largest UInt32' => [self::MAX_UINT32];
    }

    #[DataProvider('provideUnknownCategories')]
    public function testUnknownCategoryIsReportedButNeverAllowed(int $category): void
    {
        foreach ([ExtensionsMap::categoryBytes($category), ExtensionsMap::categoryInteger($category)] as $encoded) {
            $attestation = AttestationBuilder::create()
                ->withExtensions(ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => $encoded]))
                ->build();
            $key = self::verifyBuilt($attestation);

            self::assertSame($category, $key->validationCategory);
            self::assertNull($key->validationCategory());
            self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesOfTheWrongType(): iterable
    {
        yield 'three bytes' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => ByteStringObject::create("\x04\x00\x00"), ExtensionsMap::BUNDLE_VERSION => ByteStringObject::create('2.1')])];
        yield 'five bytes' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => ByteStringObject::create("\x04\x00\x00\x00\x00"), ExtensionsMap::BUNDLE_VERSION => UnsignedIntegerObject::create(2)])];
        yield 'integer above UInt32' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => UnsignedIntegerObject::create(0x100000004), ExtensionsMap::BUNDLE_VERSION => ListObject::create([ExtensionsMap::text('2.1')])])];
        yield 'negative integer' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => NegativeIntegerObject::create(-4), ExtensionsMap::BUNDLE_VERSION => MapObject::create()])];
        yield 'text' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::text('4'), ExtensionsMap::BUNDLE_VERSION => NegativeIntegerObject::create(-1)])];
        yield 'indefinite-length text' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => IndefiniteLengthTextStringObject::create()->append("\x04\x00\x00\x00")])];
        yield 'tagged' => [ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => Tagged::of(ExtensionsMap::categoryBytes(4)), ExtensionsMap::BUNDLE_VERSION => Tagged::of(ExtensionsMap::text('2.1'))])];
    }

    #[DataProvider('provideValuesOfTheWrongType')]
    public function testValueOfTheWrongTypeCountsAsAbsent(string $extensions): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions($extensions)
            ->build();
        $key = self::verifyBuilt($attestation);

        self::assertNull($key->validationCategory);
        self::assertNull($key->bundleVersion);
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(...ValidationCategory::cases())));
        self::assertFailure(
            AttestationFailureReason::BundleVersion,
            static fn() => self::verifyBuilt($attestation, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(): bool => true)),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedExtensions(): iterable
    {
        foreach (ExtensionsMap::malformed() as $name => $bytes) {
            yield $name => [$bytes];
        }
    }

    #[DataProvider('provideMalformedExtensions')]
    public function testMalformedExtensionsYieldNoValuesAndFailOnlyAPolicy(string $extensions): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions($extensions)
            ->build();
        $key = self::verifyBuilt($attestation);

        self::assertSame($attestation->keyId, $key->keyId);
        self::assertNull($key->validationCategory);
        self::assertNull($key->bundleVersion);
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(ValidationCategory::AppStore)));
        self::assertFailure(
            AttestationFailureReason::BundleVersion,
            static fn() => self::verifyBuilt($attestation, launchPolicy: (new LaunchPolicy())->withBundleVersion(static fn(): bool => true)),
        );
    }

    public function testMissingValueFailsOnlyThePartOfThePolicyThatNeedsIt(): void
    {
        $versionOnly = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of([ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('3')]))
            ->build();
        $categoryOnly = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of([ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(2)]))
            ->build();
        $anyVersion = (new LaunchPolicy())->withBundleVersion(static fn(): bool => true);

        self::assertNull(self::verifyBuilt($versionOnly)->validationCategory);
        self::assertSame('3', self::verifyBuilt($versionOnly, launchPolicy: $anyVersion)->bundleVersion);
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($versionOnly, launchPolicy: LaunchPolicy::allowing(ValidationCategory::TestFlight)));
        self::assertNull(self::verifyBuilt($categoryOnly)->bundleVersion);
        self::assertSame(ValidationCategory::TestFlight, self::verifyBuilt($categoryOnly, launchPolicy: LaunchPolicy::allowing(ValidationCategory::TestFlight))->validationCategory());
        self::assertFailure(AttestationFailureReason::BundleVersion, static fn() => self::verifyBuilt($categoryOnly, launchPolicy: $anyVersion));
    }

    public function testAppleSpellingWinsOverTheShortOne(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of([
                ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(3),
                ExtensionsMap::SHORT_BUNDLE_VERSION => ExtensionsMap::text('short'),
                ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::categoryBytes(4),
                ExtensionsMap::BUNDLE_VERSION => ExtensionsMap::text('apple'),
            ]))
            ->build();
        $key = self::verifyBuilt($attestation);

        self::assertSame(4, $key->validationCategory);
        self::assertSame('apple', $key->bundleVersion);
    }

    public function testShortSpellingIsReadWhenTheAppleOneHoldsNoUsableValue(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExtensions(ExtensionsMap::of([
                ExtensionsMap::VALIDATION_CATEGORY => ExtensionsMap::text('4'),
                ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(6),
            ]))
            ->build();

        self::assertSame(ValidationCategory::DeveloperId, self::verifyBuilt($attestation)->validationCategory());
    }

    public function testLaunchPolicyIsCheckedAfterEveryOtherCheck(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $refusing = LaunchPolicy::allowing(ValidationCategory::AppStore)->withBundleVersion(static fn(): bool => false);
        $verifier = new AttestationVerifier($attestation->trustAnchor(), $attestation->clock());
        $otherApp = new AppIdentity(new TeamId('ZYXWV98765'), new BundleId('org.example.other'));

        self::assertFailure(
            AttestationFailureReason::Nonce,
            static fn() => $verifier->verify($attestation->cbor, hash('sha256', 'other', true), $attestation->keyId, $attestation->app, [Environment::Development], $refusing),
        );
        self::assertFailure(
            AttestationFailureReason::RpIdHash,
            static fn() => $verifier->verify($attestation->cbor, $attestation->clientDataHash, $attestation->keyId, $otherApp, [Environment::Development], $refusing),
        );
        self::assertFailure(
            AttestationFailureReason::Environment,
            static fn() => $verifier->verify($attestation->cbor, $attestation->clientDataHash, $attestation->keyId, $attestation->app, [Environment::Production], $refusing),
        );
        self::assertFailure(AttestationFailureReason::ValidationCategory, static fn() => self::verifyBuilt($attestation, launchPolicy: $refusing));
    }

    public function testCredentialIdMismatchComesBeforeTheLaunchPolicy(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialId(hash('sha256', 'not the key id', true))
            ->withExtensions(ExtensionsMap::apple(4, '1.0'))
            ->build();

        self::assertFailure(AttestationFailureReason::KeyId, static fn() => self::verifyBuilt($attestation, launchPolicy: LaunchPolicy::allowing(ValidationCategory::TestFlight)));
    }

    public function testDamagedExtensionsNeverRaiseAPhpError(): void
    {
        $extensions = ExtensionsMap::apple(4, '1.0');

        foreach (Damage::of($extensions, [0x80, 0xFF]) as $damaged) {
            $attestation = AttestationBuilder::create()
                ->withExtensions($damaged->bytes)
                ->build();
            $key = Damage::withoutPhpErrors(static fn(): AttestedKey => self::verifyBuilt($attestation));

            self::assertSame($attestation->keyId, $key->keyId, 'Damage at extensions byte ' . $damaged->offset . '.');
        }
    }

    /**
     * @param list<array{class-string, string}> $properties the static properties the change sets
     * @param Closure(): mixed                  $change
     *
     * @return Closure(): Closure(): void
     */
    private static function changing(array $properties, Closure $change): Closure
    {
        return static function() use ($properties, $change): Closure {
            $saved = [];

            foreach ($properties as [$class, $name]) {
                $property = new ReflectionProperty($class, $name);
                $saved[] = [$property, $property->getValue()];
            }

            $change();

            return static function() use ($saved): void {
                foreach ($saved as $entry) {
                    $entry[0]->setValue(null, $entry[1]);
                }
            };
        };
    }

    /**
     * What each case ends in, built once: the expected outcome and the check, both 'accepted', 'refused' or a
     * failure reason's name.
     *
     * @return array<string, array{string, Closure(): string}>
     */
    private static function settingIndependentCases(): array
    {
        if (self::$settingIndependentCases !== null) {
            return self::$settingIndependentCases;
        }

        $serialNumber = new BigInteger('0102030405060708', 16);
        $built = AttestationBuilder::create()->build();
        $guide = Fixtures::attestation(self::GUIDE_VECTOR);
        $cases = [
            'built chain' => ['accepted', self::builtOutcome($built)],
            'built chain naming the serial number of the intermediate' => ['accepted', self::builtOutcome(AttestationBuilder::create()
                ->withIntermediateSerialNumber($serialNumber)
                ->withCredentialAuthorityCertSerialNumber($serialNumber)
                ->build())],
            'TrustAnchor::fromPem() of a built root' => ['accepted', self::trustAnchorOutcome($built->rootPem)],
            'TrustAnchor::fromPem() of Apple\'s root' => ['accepted', self::trustAnchorOutcome(TrustAnchor::apple()->pem)],
            'TrustAnchor::fromPem() of a root without key usage' => ['refused', self::trustAnchorOutcome(AttestationBuilder::create()
                ->withRootWithoutKeyUsage()
                ->build()
                ->rootPem)],
        ];

        foreach (Fixtures::attestations() as $name => $vector) {
            $cases['genuine ' . $name] = ['accepted', static fn(): string => self::outcomeOf($vector, $vector->bytes)];
            $cases['genuine ' . $name . ' with another clientDataHash'] = [AttestationFailureReason::Nonce->name, static fn(): string => self::failureOf(static fn() => self::verifyVector($vector, clientDataHash: hash('sha256', 'another challenge', true)))];
        }

        $cases['genuine vector under another trust anchor'] = [AttestationFailureReason::CertificateChain->name, static fn(): string => self::failureOf(static fn() => (new AttestationVerifier($built->trustAnchor(), $guide->clock()))->verify(
            $guide->bytes,
            $guide->clientDataHash,
            $guide->keyId,
            $guide->app(),
            [$guide->environment],
        ))];
        $issuerFailures = [
            'intermediate naming the root in capitals' => AttestationBuilder::create()->withIntermediateIssuerName('OIRE TEST APP ATTESTATION ROOT CA'),
            'credential naming the intermediate with doubled spaces' => AttestationBuilder::create()->withCredentialIssuerName('Oire  Test  App  Attestation  CA'),
            'intermediate that is not a CA' => AttestationBuilder::create()->withIntermediateNotCa(),
        ];

        foreach ($issuerFailures as $name => $builder) {
            $cases[$name] = [AttestationFailureReason::CertificateChain->name, self::builtOutcome($builder->build())];
        }

        foreach (self::provideWellFormedCertificateVariants() as $name => [$variant]) {
            $cases[$name] = ['accepted', self::builtOutcome($variant(AttestationBuilder::create())->build())];
        }

        foreach (self::provideMalformedCertificateStructures() as $name => [$variant, $reason]) {
            $cases[$name] = [$reason->name, self::builtOutcome($variant(AttestationBuilder::create())->build())];
        }

        foreach (self::provideBuiltChainsThatFail() as $name => [$variant]) {
            $cases[$name] = [AttestationFailureReason::CertificateChain->name, self::builtOutcome($variant(AttestationBuilder::create())->build())];
        }

        return self::$settingIndependentCases = $cases;
    }

    /**
     * @return Closure(): string
     */
    private static function builtOutcome(BuiltAttestation $attestation): Closure
    {
        return static fn(): string => self::failureOf(static fn() => self::verifyBuilt($attestation)->keyId === $attestation->keyId ? null : throw new UnexpectedValueException('Another key id was returned.'));
    }

    /**
     * @return Closure(): string
     */
    private static function trustAnchorOutcome(string $pem): Closure
    {
        return static function() use ($pem): string {
            try {
                TrustAnchor::fromPem($pem);

                return 'accepted';
            } catch (InvalidArgumentException) {
                return 'refused';
            }
        };
    }

    /**
     * 'accepted' if the verification returns, else the name of the reason it fails with.
     */
    private static function failureOf(callable $verification): string
    {
        try {
            $verification();

            return 'accepted';
        } catch (AttestationException $e) {
            return $e->reason->name;
        }
    }

    /**
     * @param Closure(?string): string $value
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function intermediateExtension(string $oid, Closure $value): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionValue($tbs, $oid, $value));
    }

    /**
     * @param Closure(list<string>): list<string> $edit
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function intermediateExtensions(Closure $edit): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensions($tbs, $edit));
    }

    /**
     * @param Closure(list<string>): list<string> $edit
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function intermediateFields(Closure $edit): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateTbsCertificate(static fn(string $tbs): string => SignedCertificate::withFields($tbs, $edit));
    }

    /**
     * @param Closure(?string): string $value
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialExtension(string $oid, Closure $value): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensionValue($tbs, $oid, $value));
    }

    /**
     * @param Closure(list<string>): list<string> $edit
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialExtensions(Closure $edit): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withExtensions($tbs, $edit));
    }

    /**
     * @param list<array{0: string, 1: string, 2?: bool}> $added each extension's OID and value as DER, critical unless it says otherwise
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialWithExtensions(array $added): Closure
    {
        return self::credentialExtensions(static fn(array $extensions): array => [
            ...$extensions,
            ...array_map(static fn(array $extension): string => SignedCertificate::extension($extension[0], $extension[1], $extension[2] ?? true), $added),
        ]);
    }

    /**
     * @param Closure(list<string>): list<string> $edit
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialFields(Closure $edit): Closure
    {
        return static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withFields($tbs, $edit));
    }

    /**
     * The credential certificate with this signature AlgorithmIdentifier (DER) inside its tbsCertificate, while
     * its signatureAlgorithm stays ecdsa-with-SHA256, signed by the intermediate with SHA-256.
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialSignedAlgorithm(string $algorithm): Closure
    {
        return self::credentialFields(static fn(array $fields): array => [
            ...array_slice($fields, 0, SignedCertificate::SIGNED_ALGORITHM_FIELD),
            $algorithm,
            ...array_slice($fields, SignedCertificate::SIGNED_ALGORITHM_FIELD + 1),
        ]);
    }

    /**
     * The credential certificate with this time element (DER) as its notAfter.
     *
     * @return Closure(AttestationBuilder): AttestationBuilder
     */
    private static function credentialNotAfter(string $time): Closure
    {
        return self::credentialFields(static fn(array $fields): array => [
            ...array_slice($fields, 0, self::VALIDITY_FIELD),
            SignedCertificate::encoded("\x30", (SignedCertificate::elements(SignedCertificate::content($fields[self::VALIDITY_FIELD] ?? ''))[0] ?? '') . $time),
            ...array_slice($fields, self::VALIDITY_FIELD + 1),
        ]);
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
        ?LaunchPolicy $launchPolicy = null,
    ): AttestedKey {
        return (new AttestationVerifier(null, $clock ?? $vector->clock()))->verify(
            $cbor ?? $vector->bytes,
            $clientDataHash ?? $vector->clientDataHash,
            $keyId ?? $vector->keyId,
            $app ?? $vector->app(),
            $allowed ?? [$vector->environment],
            $launchPolicy,
        );
    }

    /**
     * @param list<Environment> $allowed
     */
    private static function verifyBuilt(
        BuiltAttestation $attestation,
        array $allowed = [Environment::Development],
        ?string $cbor = null,
        ?LaunchPolicy $launchPolicy = null,
    ): AttestedKey {
        return (new AttestationVerifier($attestation->trustAnchor(), $attestation->clock()))->verify(
            $cbor ?? $attestation->cbor,
            $attestation->clientDataHash,
            $attestation->keyId,
            $attestation->app,
            $allowed,
            $launchPolicy,
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
    private static function assertRefusedCheaply(AttestationFailureReason $reason, callable $verification): void
    {
        $growth = HostileInput::peakMemoryGrowthOf(static fn() => self::assertFailure($reason, $verification));

        self::assertLessThan(HostileInput::CHEAP_REFUSAL_MEMORY, $growth, 'The attestation must be refused before it is parsed.');
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
     * The attestation with $tagged, a member or a certificate, wrapped in a CBOR tag.
     */
    private static function attestationObjectTagging(BuiltAttestation $attestation, ?string $tagged): string
    {
        $item = static fn(string $member, CBORObject $value): CBORObject => $member === $tagged ? Tagged::of($value) : $value;
        $x5c = ListObject::create([
            $item('credential', ByteStringObject::create($attestation->credentialDer)),
            $item('intermediate', ByteStringObject::create($attestation->intermediateDer)),
        ]);
        $attStmt = MapObject::create()
            ->add(TextStringObject::create('x5c'), $item('x5c', $x5c))
            ->add(TextStringObject::create('receipt'), $item('receipt', ByteStringObject::create($attestation->receipt)));

        return (string) MapObject::create()
            ->add(TextStringObject::create('fmt'), $item('fmt', TextStringObject::create(AttestationBuilder::FORMAT)))
            ->add(TextStringObject::create('attStmt'), $item('attStmt', $attStmt))
            ->add(TextStringObject::create('authData'), $item('authData', ByteStringObject::create($attestation->authData)));
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

    private static function assertChainRefusesDamage(Damaged $damaged, string $outcome): void
    {
        self::assertSame(AttestationFailureReason::CertificateChain->name, $outcome, 'Damage at certificate byte ' . $damaged->offset . '.');
    }

    /**
     * Whether damage at this byte of a genuine attestation leaves it valid: inside the receipt, which is not
     * signed.
     */
    private static function isHarmlessDamage(string $cbor, int $offset): bool
    {
        $receipt = self::receiptOf($cbor);
        $receiptStart = mb_strpos($cbor, $receipt, 0, '8bit');

        return is_int($receiptStart) && $offset >= $receiptStart && $offset < $receiptStart + mb_strlen($receipt, '8bit');
    }

    /**
     * The warnings phpseclib raises reading the whole certificate without ErrorGuard.
     *
     * @return list<string>
     */
    private static function phpseclibWarningsReading(string $der): array
    {
        $warnings = [];
        set_error_handler(static function(int $severity, string $message) use (&$warnings): bool {
            $warnings[] = $message;

            return true;
        }, E_WARNING);

        try {
            $certificate = ASN1::map(ASN1::decodeBER($der), Certificate::MAP);

            if ($certificate instanceof Constructed) {
                $certificate->toArray();
            }
        } catch (Throwable) {
            return $warnings;
        } finally {
            restore_error_handler();
        }

        return $warnings;
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
     * A built chain whose credential certificate, or intermediate, is exactly this many bytes long, padded with
     * a well-formed extension the chain does not read. The ECDSA signature's length varies, so it takes a few
     * attempts.
     */
    private static function withCertificateOfLength(bool $intermediate, int $length): BuiltAttestation
    {
        $padding = intdiv($length, 2);

        for ($attempt = 0; $attempt < self::LENGTH_ATTEMPTS; ++$attempt) {
            $extension = SignedCertificate::extension(self::UNKNOWN_EXTENSION, SignedCertificate::encoded("\x04", str_repeat("\x00", $padding)));
            $edit = static fn(string $tbs): string => SignedCertificate::withExtensions($tbs, static fn(array $extensions): array => [...$extensions, $extension]);
            $builder = AttestationBuilder::create();
            $attestation = ($intermediate ? $builder->withIntermediateTbsCertificate($edit) : $builder->withCredentialTbsCertificate($edit))->build();
            $built = mb_strlen($intermediate ? $attestation->intermediateDer : $attestation->credentialDer, '8bit');

            if ($built === $length) {
                return $attestation;
            }

            $padding += $length - $built;
        }

        self::fail('No certificate of ' . $length . ' bytes could be built.');
    }

    /**
     * Definite-length SEQUENCEs nested inside each other, at least this many bytes in all.
     *
     * @psalm-pure
     */
    private static function nestedSequences(int $length): string
    {
        $der = '';

        while (mb_strlen($der, '8bit') < $length) {
            $der = SignedCertificate::encoded("\x30", $der);
        }

        return $der;
    }

    private static function chunked(string $bytes): IndefiniteLengthByteStringObject
    {
        return IndefiniteLengthByteStringObject::create(...mb_str_split($bytes, 50, '8bit'));
    }

    /**
     * The signature BIT STRING content with a needless zero byte before the ECDSA signature's r.
     */
    private static function withZeroBeforeR(string $bits): string
    {
        $signature = mb_substr($bits, 1, null, '8bit');
        self::assertSame("\x30\x02", $signature[0] . $signature[2]);
        $rLength = ord($signature[3]);
        $r = mb_substr($signature, 4, $rLength, '8bit');
        $s = mb_substr($signature, 4 + $rLength, null, '8bit');

        return "\x00" . SignedCertificate::encoded("\x30", SignedCertificate::encoded("\x02", "\x00" . $r) . $s);
    }

    /**
     * A SEQUENCE with this content, its length in four bytes.
     *
     * @psalm-pure
     */
    private static function inLongForm(string $content): string
    {
        return "\x30\x84" . pack('N', mb_strlen($content, '8bit')) . $content;
    }

    private static function spkiOf(string $pem): string
    {
        $spki = Pem::toDer($pem);
        self::assertSame(EcKey::SPKI_LENGTH, mb_strlen($spki, '8bit'));

        return $spki;
    }
}
