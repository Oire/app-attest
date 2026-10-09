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
use Oire\AppAttest\Internal\NonceExtension;
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
use Override;
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
        X509::setURLFetchCallback(static fn(): bool => false);
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

    public function testCaIssuersUrlIsNeverFetched(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialFromAnUnlistedIssuer('http://192.0.2.1/ca.cer')
            ->build();
        $fetched = [];
        X509::setURLFetchCallback(static function(string $host) use (&$fetched): bool {
            $fetched[] = $host;

            return false;
        });

        self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
        self::assertSame([], $fetched);
    }

    /**
     * @return iterable<string, array{?string}>
     *
     * @psalm-capabilities read-props
     */
    public static function provideNonceMapNames(): iterable
    {
        yield 'under its OID' => [null];
        yield 'under a name given with ASN1::loadOIDs()' => ['oireAppAttestNonce'];
    }

    #[DataProvider('provideNonceMapNames')]
    public function testNonceMapRegisteredByTheProcessChangesNothing(?string $name): void
    {
        $vector = Fixtures::attestation(self::GUIDE_VECTOR);
        $oids = new ReflectionProperty(ASN1::class, 'oids');
        $reverseOids = new ReflectionProperty(ASN1::class, 'reverseOIDs');
        $extensions = new ReflectionProperty(X509::class, 'extensions');
        $savedOids = (array) $oids->getValue();
        $savedReverseOids = (array) $reverseOids->getValue();
        $registered = (array) $extensions->getValue();

        try {
            if ($name !== null) {
                ASN1::loadOIDs([$name => NonceExtension::OID]);
            }

            X509::registerExtension($name ?? NonceExtension::OID, ['type' => ASN1::TYPE_OCTET_STRING]);
            self::assertSame($vector->keyId, self::verifyVector($vector)->keyId);
            self::assertFailure(AttestationFailureReason::Nonce, static fn() => self::verifyVector($vector, clientDataHash: hash('sha256', 'another challenge', true)));
        } finally {
            $extensions->setValue(null, $registered);
            $oids->setValue(null, $savedOids);
            $reverseOids->setValue(null, $savedReverseOids);
        }
    }

    public function testSignatureAlgorithmIsMatchedWhateverNameTheProcessGivesIt(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $oids = new ReflectionProperty(ASN1::class, 'oids');
        $reverseOids = new ReflectionProperty(ASN1::class, 'reverseOIDs');
        $savedOids = (array) $oids->getValue();
        $savedReverseOids = (array) $reverseOids->getValue();

        try {
            ASN1::loadOIDs(['oireEcdsaWithSha256' => '1.2.840.10045.4.3.2']);
            self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
        } finally {
            $oids->setValue(null, $savedOids);
            $reverseOids->setValue(null, $savedReverseOids);
        }
    }

    public function testCaStoreOfTheProcessIsNeverTrusted(): void
    {
        $victim = AttestationBuilder::create()->build();
        $attacker = AttestationBuilder::create()->build();
        self::assertSame([], X509::getCAs());
        X509::addCA($attacker->rootPem);

        try {
            self::assertFailure(
                AttestationFailureReason::CertificateChain,
                static fn() => (new AttestationVerifier($victim->trustAnchor(), $attacker->clock()))->verify(
                    $attacker->cbor,
                    $attacker->clientDataHash,
                    $attacker->keyId,
                    $attacker->app,
                    [Environment::Development],
                ),
            );
        } finally {
            X509::clearCAStore();
        }
    }

    public function testValidationDateOfTheProcessNeverSwitchesTheDateCheckOff(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExpiredRoot()
            ->build();
        $date = X509::getTargetValidationDate();
        X509::setTargetValidationDate(null);

        try {
            self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
        } finally {
            X509::setTargetValidationDate($date);
        }
    }

    public function testCrlLookupCallbackIsNeverCalled(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $lookups = [];
        X509::setCRLLookupCallback(static function(string $url) use (&$lookups): bool {
            $lookups[] = $url;

            return false;
        });

        try {
            self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
            self::assertSame([], $lookups);
        } finally {
            X509::setCRLLookupCallback(static fn(): bool => false);
        }
    }

    /**
     * phpseclib's isIssuerOf() reads these X509 properties, which the switches set for the whole process.
     *
     * @return iterable<string, array{string, Closure(): void, Closure(AttestationBuilder): AttestationBuilder}>
     */
    public static function provideIssuerFailuresUnderProcessWideSwitches(): iterable
    {
        $switches = [
            'ignoreKeyUsage' => ['checkKeyUsage', X509::ignoreKeyUsage(...)],
            'looseDNComparison' => ['strictDNComparison', X509::looseDNComparison(...)],
            'ignoreBasicConstraints' => ['checkBasicConstraints', X509::ignoreBasicConstraints(...)],
        ];
        $variants = [
            'intermediate without keyCertSign' => static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKeyUsage(['digitalSignature', 'cRLSign']),
            'intermediate naming the root in capitals' => static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateIssuerName('OIRE TEST APP ATTESTATION ROOT CA'),
            'credential naming the intermediate with doubled spaces' => static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialIssuerName('Oire  Test  App  Attestation  CA'),
            'credential naming another issuer' => static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialIssuerName('Oire Test Other CA'),
            'intermediate that is not a CA' => static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateNotCa(),
        ];

        foreach ($switches as $switch => [$property, $turnOn]) {
            foreach ($variants as $name => $variant) {
                yield $switch . ', ' . $name => [$property, $turnOn, $variant];
            }
        }
    }

    /**
     * @param Closure(): void                                 $turnOn
     * @param Closure(AttestationBuilder): AttestationBuilder $variant
     */
    #[DataProvider('provideIssuerFailuresUnderProcessWideSwitches')]
    public function testProcessWideSwitchNeverLoosensTheIssuerChecks(string $property, Closure $turnOn, Closure $variant): void
    {
        $attestation = $variant(AttestationBuilder::create())->build();
        $setting = new ReflectionProperty(X509::class, $property);
        $saved = (bool) $setting->getValue();
        $turnOn();

        try {
            self::assertFailure(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation));
        } finally {
            $setting->setValue(null, $saved);
        }
    }

    public function testValidChainIsAcceptedWhateverTheProcessWideSwitches(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $vector = Fixtures::attestation(self::GUIDE_VECTOR);
        $settings = [];
        $saved = [];

        foreach (['checkKeyUsage', 'strictDNComparison', 'checkBasicConstraints'] as $property) {
            $settings[$property] = new ReflectionProperty(X509::class, $property);
            $saved[$property] = (bool) $settings[$property]->getValue();
            $settings[$property]->setValue(null, !$saved[$property]);
        }

        try {
            self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
            self::assertSame($vector->keyId, self::verifyVector($vector)->keyId);
        } finally {
            foreach ($settings as $property => $setting) {
                $setting->setValue(null, $saved[$property]);
            }
        }
    }

    public function testIssuerExtensionsAndNamesAreMatchedWhateverNamesTheProcessGivesTheirOids(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $vector = Fixtures::attestation(self::GUIDE_VECTOR);
        $oids = new ReflectionProperty(ASN1::class, 'oids');
        $reverseOids = new ReflectionProperty(ASN1::class, 'reverseOIDs');
        $savedOids = (array) $oids->getValue();
        $savedReverseOids = (array) $reverseOids->getValue();

        try {
            ASN1::loadOIDs([
                'oireKeyUsage' => '2.5.29.15',
                'oireSubjectKeyIdentifier' => '2.5.29.14',
                'oireAuthorityKeyIdentifier' => '2.5.29.35',
                'oireBasicConstraints' => '2.5.29.19',
                'oireCommonName' => '2.5.4.3',
            ]);
            self::assertSame($attestation->keyId, self::verifyBuilt($attestation)->keyId);
            self::assertSame($vector->keyId, self::verifyVector($vector)->keyId);
        } finally {
            $oids->setValue(null, $savedOids);
            $reverseOids->setValue(null, $savedReverseOids);
        }
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
        yield 'intermediate with its key usage twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateExtensionTwice(AttestationBuilder::KEY_USAGE_OID)];
        yield 'intermediate with its subject key identifier twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateExtensionTwice(AttestationBuilder::SUBJECT_KEY_IDENTIFIER_OID)];
        yield 'credential with its authority key identifier twice' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialAuthorityKeyIdentifierTwice()];
        yield 'credential signed with ECDSA over SHA-1' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialSignatureHash('sha1')];
        yield 'intermediate with an RSA key' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKey(RsaKey::generate())];
        yield 'intermediate with an Ed25519 key' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withIntermediateKey(EC::createKey('Ed25519'))];
        yield 'credential signed under ecdsa-with-SHA512 inside' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialSignedAlgorithm(SignedCertificate::ECDSA_WITH_SHA512)];
        yield 'credential signed under id-ecPublicKey inside' => [static fn(AttestationBuilder $b): AttestationBuilder => $b->withCredentialSignedAlgorithm(SignedCertificate::ID_EC_PUBLIC_KEY)];
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
            ->withNonceExtensionTwice($earlierDer)
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
    public function testNestedSequencesOverTheCertificateLimitAreRefusedBeforeTheyAreParsed(bool $asIntermediate): void
    {
        $attestation = AttestationBuilder::create()->build();
        $nested = self::nestedSequences(self::NESTED_SEQUENCES_LENGTH);
        $certificates = $asIntermediate ? [$attestation->credentialDer, $nested] : [$nested, $attestation->intermediateDer];
        $cbor = self::attestationObject(self::x5c(...$certificates), $attestation->authData);

        self::assertLessThanOrEqual(self::MAX_LENGTH, mb_strlen($cbor, '8bit'));
        self::assertRefusedCheaply(AttestationFailureReason::CertificateChain, static fn() => self::verifyBuilt($attestation, cbor: $cbor));
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
     * Damage that makes phpseclib 4 raise a warning (an empty OID) in the signature AlgorithmIdentifiers, which
     * the library reads before it checks the signature, found by XORing every byte of the certificates with
     * every mask.
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
