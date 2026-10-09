<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use DateTimeImmutable;
use DateTimeInterface;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps\Certificate;
use phpseclib4\File\ASN1\Types\BaseString;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\Boolean;
use phpseclib4\File\ASN1\Types\Choice;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\X509;
use phpseclib4\Math\BigInteger;
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
final class BuildersTest extends TestCase
{
    private const string NONCE_EXTENSION_OID_DER = "\x06\x09\x2a\x86\x48\x86\xf7\x63\x64\x08\x02";

    public function testBuiltAttestationHasTheAppleLayout(): void
    {
        $attestation = AttestationBuilder::create()->build();
        $document = self::decode($attestation->cbor);
        $attStmt = self::map($document['attStmt'] ?? null);
        $x5c = self::map($attStmt['x5c'] ?? null);

        self::assertSame(['fmt', 'attStmt', 'authData'], array_keys($document));
        self::assertSame('apple-appattest', $document['fmt']);
        self::assertSame([$attestation->credentialDer, $attestation->intermediateDer], $x5c);
        self::assertSame(AttestationBuilder::RECEIPT, $attStmt['receipt'] ?? null);
        self::assertSame($attestation->receipt, $attStmt['receipt'] ?? null);
        self::assertSame($attestation->authData, $document['authData']);

        $authData = $attestation->authData;
        self::assertSame($attestation->app->rpIdHash(), mb_substr($authData, 0, AuthDataLayout::RP_ID_HASH_LENGTH, '8bit'));
        self::assertSame(0, self::counterOf($authData));
        self::assertSame(Environment::Development->aaguid(), mb_substr($authData, AuthDataLayout::AAGUID_OFFSET, AuthDataLayout::AAGUID_LENGTH, '8bit'));
        self::assertSame($attestation->keyId, self::credentialIdOf($authData));
        self::assertSame(hash('sha256', self::pointOf($attestation->credentialDer), true), $attestation->keyId);
        self::assertSame(self::pointOf($attestation->credentialDer), self::pointOfPem($attestation->publicKeyPem));
    }

    public function testBuiltChainValidatesAgainstItsOwnRootAtItsTime(): void
    {
        $attestation = AttestationBuilder::create()->build();

        self::assertSame($attestation->rootPem, $attestation->trustAnchor()->pem);
        self::assertTrue(self::issuedBy($attestation->intermediateDer, $attestation->rootPem));
        self::assertTrue(self::issuedBy($attestation->credentialDer, $attestation->intermediateDer));
        self::assertFalse(self::issuedBy($attestation->credentialDer, AttestationBuilder::create()->build()->intermediateDer));
        self::assertTrue(self::isCa($attestation->rootPem));
        self::assertTrue(self::isCa($attestation->intermediateDer));
        self::assertFalse(self::isCa($attestation->credentialDer));

        $now = $attestation->clock()->now();
        self::assertSame((new DateTimeImmutable(AttestationBuilder::DEFAULT_TIME))->getTimestamp(), $now->getTimestamp());
        self::assertTrue(self::validAt($attestation->credentialDer, $now));
        self::assertTrue(self::validAt($attestation->intermediateDer, $now));
        self::assertTrue(self::validAt($attestation->rootPem, $now));
        self::assertFalse(self::validAt($attestation->credentialDer, $now->modify('+2 days')));
        self::assertFalse(self::validAt($attestation->credentialDer, $now->modify('-2 days')));
    }

    public function testCredentialCertificateCarriesTheNonce(): void
    {
        $clientDataHash = hash('sha256', 'another challenge', true);
        $attestation = AttestationBuilder::create()
            ->withClientDataHash($clientDataHash)
            ->build();
        $nonce = hash('sha256', $attestation->authData . $clientDataHash, true);

        self::assertSame($clientDataHash, $attestation->clientDataHash);
        self::assertSame("\x30\x24\xa1\x22\x04\x20" . $nonce, AttestationBuilder::nonceExtensionDer($nonce));
        self::assertSame(AttestationBuilder::nonceExtensionDer($nonce), self::nonceExtensionOf($attestation->credentialDer));
    }

    public function testNonceExtensionCanBeLeftOutOrMalformed(): void
    {
        $withoutNonce = AttestationBuilder::create()
            ->withoutNonceExtension()
            ->build();
        $malformed = AttestationBuilder::create()
            ->withNonceExtensionDer("\x30\x00")
            ->build();

        self::assertNull(self::nonceExtensionOf($withoutNonce->credentialDer));
        self::assertSame("\x30\x00", self::nonceExtensionOf($malformed->credentialDer));
    }

    public function testIntermediateCanBeMadeNotACa(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateNotCa()
            ->build();

        self::assertFalse(self::isCa($attestation->intermediateDer));
        self::assertTrue(self::hasKeyCertSign($attestation->intermediateDer));
        self::assertTrue(self::isIssuerOf($attestation->intermediateDer, $attestation->credentialDer));
        self::assertTrue(self::issuedBy($attestation->credentialDer, $attestation->intermediateDer));
    }

    public function testCertificatesSplitAndJoinBackUnchanged(): void
    {
        $attestation = AttestationBuilder::create()->build();

        foreach ([$attestation->credentialDer, $attestation->intermediateDer, Pem::toDer($attestation->rootPem)] as $der) {
            self::assertSame($der, SignedCertificate::join(...SignedCertificate::split($der)));
        }
    }

    public function testEachChainLinkCanFailOneIssuerCheckAlone(): void
    {
        $intermediateByAnotherKey = AttestationBuilder::create()
            ->withIntermediateSignedByAnotherKey()
            ->build();
        $credentialByAnotherKey = AttestationBuilder::create()
            ->withCredentialSignedByAnotherKey()
            ->build();
        $intermediateNamingAnotherIssuer = AttestationBuilder::create()
            ->withIntermediateIssuerName('Oire Test Other Root CA')
            ->build();
        $credentialNamingAnotherIssuer = AttestationBuilder::create()
            ->withCredentialIssuerName('Oire Test Other CA')
            ->build();

        self::assertTrue(self::isIssuerOf(Pem::toDer($intermediateByAnotherKey->rootPem), $intermediateByAnotherKey->intermediateDer));
        self::assertFalse(self::signedBy($intermediateByAnotherKey->intermediateDer, Pem::toDer($intermediateByAnotherKey->rootPem)));
        self::assertTrue(self::isIssuerOf($credentialByAnotherKey->intermediateDer, $credentialByAnotherKey->credentialDer));
        self::assertFalse(self::signedBy($credentialByAnotherKey->credentialDer, $credentialByAnotherKey->intermediateDer));
        self::assertFalse(self::isIssuerOf(Pem::toDer($intermediateNamingAnotherIssuer->rootPem), $intermediateNamingAnotherIssuer->intermediateDer));
        self::assertTrue(self::signedBy($intermediateNamingAnotherIssuer->intermediateDer, Pem::toDer($intermediateNamingAnotherIssuer->rootPem)));
        self::assertFalse(self::isIssuerOf($credentialNamingAnotherIssuer->intermediateDer, $credentialNamingAnotherIssuer->credentialDer));
        self::assertTrue(self::signedBy($credentialNamingAnotherIssuer->credentialDer, $credentialNamingAnotherIssuer->intermediateDer));
    }

    public function testIntermediateKeyUsageCanLackKeyCertSign(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateKeyUsage(['digitalSignature', 'cRLSign'])
            ->build();

        self::assertTrue(self::isCa($attestation->intermediateDer));
        self::assertFalse(self::hasKeyCertSign($attestation->intermediateDer));
        self::assertFalse(self::isIssuerOf($attestation->intermediateDer, $attestation->credentialDer));
        self::assertTrue(self::signedBy($attestation->credentialDer, $attestation->intermediateDer));
    }

    public function testIntermediateWithoutKeyCertSignPassesPhpseclibWhenKeyUsageIsIgnored(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateKeyUsage(['digitalSignature', 'cRLSign'])
            ->build();
        $enabled = X509::isCheckKeyUsageEnabled();
        X509::ignoreKeyUsage();

        try {
            self::assertTrue(self::isIssuerOf($attestation->intermediateDer, $attestation->credentialDer));
        } finally {
            if ($enabled) {
                X509::checkKeyUsage();
            }
        }
    }

    public function testIssuerNamesCanDifferOnlyInCaseOrSpacing(): void
    {
        $intermediateInCapitals = AttestationBuilder::create()
            ->withIntermediateIssuerName('OIRE TEST APP ATTESTATION ROOT CA')
            ->build();
        $credentialWithDoubledSpaces = AttestationBuilder::create()
            ->withCredentialIssuerName('Oire  Test  App  Attestation  CA')
            ->build();
        $rootDer = Pem::toDer($intermediateInCapitals->rootPem);
        $strict = X509::isStrictDNComparisonEnabled();

        self::assertFalse(self::isIssuerOf($rootDer, $intermediateInCapitals->intermediateDer));
        self::assertFalse(self::isIssuerOf($credentialWithDoubledSpaces->intermediateDer, $credentialWithDoubledSpaces->credentialDer));
        X509::looseDNComparison();

        try {
            self::assertTrue(self::isIssuerOf($rootDer, $intermediateInCapitals->intermediateDer));
            self::assertTrue(self::isIssuerOf($credentialWithDoubledSpaces->intermediateDer, $credentialWithDoubledSpaces->credentialDer));
        } finally {
            if ($strict) {
                X509::strictDNComparison();
            }
        }

        self::assertTrue(self::signedBy($intermediateInCapitals->intermediateDer, $rootDer));
        self::assertTrue(self::signedBy($credentialWithDoubledSpaces->credentialDer, $credentialWithDoubledSpaces->intermediateDer));
    }

    public function testIntermediateCanBeExpiredOrNotYetValid(): void
    {
        $expired = AttestationBuilder::create()
            ->withExpiredIntermediate()
            ->build();
        $notYetValid = AttestationBuilder::create()
            ->withIntermediateNotYetValid()
            ->build();
        $now = $expired->clock()->now();

        foreach ([$expired, $notYetValid] as $attestation) {
            self::assertFalse(self::validAt($attestation->intermediateDer, $now));
            self::assertTrue(self::validAt($attestation->rootPem, $now));
            self::assertTrue(self::validAt($attestation->credentialDer, $now));
            self::assertTrue(self::issuedBy($attestation->intermediateDer, $attestation->rootPem));
            self::assertTrue(self::issuedBy($attestation->credentialDer, $attestation->intermediateDer));
        }

        self::assertTrue(self::validAt($expired->intermediateDer, $now->modify('-2 days')));
        self::assertTrue(self::validAt($notYetValid->intermediateDer, $now->modify('+2 days')));
    }

    public function testCredentialAuthorityKeyIdentifierCanNameAnotherKeyOrSerialNumber(): void
    {
        $serialNumber = new BigInteger('0102030405060708', 16);
        $anotherKey = AttestationBuilder::create()
            ->withCredentialNamingAnotherKey()
            ->build();
        $anotherSerialNumber = AttestationBuilder::create()
            ->withCredentialAuthorityCertSerialNumber(new BigInteger(1))
            ->build();
        $issuerSerialNumber = AttestationBuilder::create()
            ->withIntermediateSerialNumber($serialNumber)
            ->withCredentialAuthorityCertSerialNumber($serialNumber)
            ->build();

        self::assertFalse(self::isIssuerOf($anotherKey->intermediateDer, $anotherKey->credentialDer));
        self::assertTrue(self::signedBy($anotherKey->credentialDer, $anotherKey->intermediateDer));
        self::assertFalse(self::isIssuerOf($anotherSerialNumber->intermediateDer, $anotherSerialNumber->credentialDer));
        self::assertTrue(self::signedBy($anotherSerialNumber->credentialDer, $anotherSerialNumber->intermediateDer));
        self::assertTrue(self::isIssuerOf($issuerSerialNumber->intermediateDer, $issuerSerialNumber->credentialDer));
    }

    public function testKeyUsageOrKeyIdentifiersCanComeTwice(): void
    {
        $keyUsageTwice = AttestationBuilder::create()
            ->withIntermediateExtensionTwice(AttestationBuilder::KEY_USAGE_OID)
            ->build();
        $subjectKeyIdentifierTwice = AttestationBuilder::create()
            ->withIntermediateExtensionTwice(AttestationBuilder::SUBJECT_KEY_IDENTIFIER_OID)
            ->build();
        $authorityKeyIdentifierTwice = AttestationBuilder::create()
            ->withCredentialAuthorityKeyIdentifierTwice()
            ->build();

        foreach ([$keyUsageTwice, $subjectKeyIdentifierTwice, $authorityKeyIdentifierTwice] as $attestation) {
            self::assertTrue(self::signedBy($attestation->intermediateDer, Pem::toDer($attestation->rootPem)));
            self::assertTrue(self::signedBy($attestation->credentialDer, $attestation->intermediateDer));
            self::assertTrue(self::isIssuerOf($attestation->intermediateDer, $attestation->credentialDer));
        }

        self::assertSame(2, self::extensionCount($keyUsageTwice->intermediateDer, AttestationBuilder::KEY_USAGE_OID));
        self::assertSame(2, self::extensionCount($subjectKeyIdentifierTwice->intermediateDer, AttestationBuilder::SUBJECT_KEY_IDENTIFIER_OID));
        self::assertSame(2, self::extensionCount($authorityKeyIdentifierTwice->credentialDer, AttestationBuilder::AUTHORITY_KEY_IDENTIFIER_OID));
        self::assertSame(1, self::extensionCount($authorityKeyIdentifierTwice->intermediateDer, AttestationBuilder::SUBJECT_KEY_IDENTIFIER_OID));
    }

    public function testCertificatesCanBeEditedAndSignedAgain(): void
    {
        $basicConstraints = "\x30\x06\x01\x01\xff\x02\x01\x00";
        $setBasicConstraints = static fn(string $tbs): string => SignedCertificate::withExtensionValue($tbs, SignedCertificate::BASIC_CONSTRAINTS, static fn(): string => $basicConstraints);
        $replaced = AttestationBuilder::create()
            ->withIntermediateTbsCertificate($setBasicConstraints)
            ->withCredentialTbsCertificate(static fn(string $tbs): string => SignedCertificate::withFields($tbs, static fn(array $fields): array => [...$fields, "\x05\x00"]))
            ->build();
        $added = AttestationBuilder::create()
            ->withIntermediateNotCa()
            ->withIntermediateTbsCertificate($setBasicConstraints)
            ->build();
        $credentialFields = SignedCertificate::elements(SignedCertificate::content(SignedCertificate::split($replaced->credentialDer)[0]));

        foreach ([$replaced, $added] as $attestation) {
            self::assertSame(1, mb_substr_count($attestation->intermediateDer, SignedCertificate::BASIC_CONSTRAINTS, '8bit'));
            self::assertStringContainsString("\x04\x08" . $basicConstraints, $attestation->intermediateDer);
            self::assertTrue(self::signedBy($attestation->intermediateDer, Pem::toDer($attestation->rootPem)));
            self::assertTrue(self::signedBy($attestation->credentialDer, $attestation->intermediateDer));
        }

        self::assertSame(["\x05\x00"], array_slice($credentialFields, -1));
        self::assertStringContainsString(SignedCertificate::extension(SignedCertificate::BASIC_CONSTRAINTS, $basicConstraints), $added->intermediateDer);
    }

    public function testRootCanLackKeyUsage(): void
    {
        $attestation = AttestationBuilder::create()
            ->withRootWithoutKeyUsage()
            ->build();
        $rootDer = Pem::toDer($attestation->rootPem);

        self::assertNull(X509::load($rootDer, ASN1::FORMAT_DER)->getExtension('id-ce-keyUsage'));
        self::assertTrue(self::isCa($attestation->rootPem));
        self::assertTrue(self::signedBy($attestation->intermediateDer, $rootDer));
    }

    public function testCredentialSignatureCanUseAnotherHashOrAlgorithm(): void
    {
        $sha512 = AttestationBuilder::create()
            ->withCredentialSignatureHash('sha512')
            ->build();
        $relabelled = AttestationBuilder::create()
            ->withCredentialSignedAlgorithm(SignedCertificate::ECDSA_WITH_SHA512)
            ->build();
        [$tbsCertificate, $algorithm] = SignedCertificate::split($relabelled->credentialDer);

        self::assertSame(SignedCertificate::ECDSA_WITH_SHA512, SignedCertificate::split($sha512->credentialDer)[1]);
        self::assertTrue(self::signedBy($sha512->credentialDer, $sha512->intermediateDer, 'sha512'));
        self::assertSame(SignedCertificate::ECDSA_WITH_SHA256, $algorithm);
        self::assertSame(SignedCertificate::ECDSA_WITH_SHA512, SignedCertificate::signedAlgorithm($tbsCertificate));
        self::assertTrue(self::signedBy($relabelled->credentialDer, $relabelled->intermediateDer));
    }

    public function testIntermediateCanHoldAnRsaKeyThatSignsUnderTheEcdsaLabel(): void
    {
        $attestation = AttestationBuilder::create()
            ->withIntermediateKey(RsaKey::generate())
            ->build();
        $intermediateKey = openssl_pkey_get_public(Pem::fromDer($attestation->intermediateDer, Pem::CERTIFICATE));
        self::assertNotFalse($intermediateKey);

        self::assertSame(OPENSSL_KEYTYPE_RSA, openssl_pkey_get_details($intermediateKey)['type'] ?? null);
        self::assertSame(SignedCertificate::ECDSA_WITH_SHA256, SignedCertificate::split($attestation->credentialDer)[1]);
        self::assertTrue(self::signedBy($attestation->credentialDer, $attestation->intermediateDer));
        self::assertTrue(self::isIssuerOf($attestation->intermediateDer, $attestation->credentialDer));
    }

    public function testNonceExtensionCanHaveBytesAfterItOrComeTwice(): void
    {
        $suffixed = AttestationBuilder::create()
            ->withNonceExtensionSuffix("\x00")
            ->build();
        $twice = AttestationBuilder::create()
            ->withNonceExtensionTwice()
            ->build();
        $nonce = hash('sha256', $suffixed->authData . $suffixed->clientDataHash, true);

        self::assertSame(AttestationBuilder::nonceExtensionDer($nonce) . "\x00", self::nonceExtensionOf($suffixed->credentialDer));
        self::assertSame(2, mb_substr_count($twice->credentialDer, self::NONCE_EXTENSION_OID_DER, '8bit'));
    }

    public function testAuthDataFieldsCanBeChosen(): void
    {
        $app = new AppIdentity(new TeamId('ZYXWV98765'), new BundleId('org.example.other'));
        $credentialId = hash('sha256', 'not the key id', true);
        $attestation = AttestationBuilder::create()
            ->withApp($app)
            ->withCounter(7)
            ->withEnvironment(Environment::Production)
            ->withCredentialId($credentialId)
            ->build();
        $authData = $attestation->authData;

        self::assertSame($app, $attestation->app);
        self::assertSame($app->rpIdHash(), mb_substr($authData, 0, AuthDataLayout::RP_ID_HASH_LENGTH, '8bit'));
        self::assertSame(7, self::counterOf($authData));
        self::assertSame(Environment::Production->aaguid(), mb_substr($authData, AuthDataLayout::AAGUID_OFFSET, AuthDataLayout::AAGUID_LENGTH, '8bit'));
        self::assertSame($credentialId, self::credentialIdOf($authData));
        self::assertNotSame($credentialId, $attestation->keyId);
        self::assertSame(
            AttestationBuilder::nonceExtensionDer(hash('sha256', $authData . $attestation->clientDataHash, true)),
            self::nonceExtensionOf($attestation->credentialDer),
        );

        $unknown = AttestationBuilder::create()
            ->withAaguid(str_repeat("\xff", 16))
            ->build();
        self::assertSame(str_repeat("\xff", 16), mb_substr($unknown->authData, AuthDataLayout::AAGUID_OFFSET, AuthDataLayout::AAGUID_LENGTH, '8bit'));
    }

    public function testCoseKeyFollowsTheCredentialIdAndCanBeReplaced(): void
    {
        $plain = AttestationBuilder::create()->build();
        $coseKeyOffset = AuthDataLayout::CREDENTIAL_ID_OFFSET + mb_strlen($plain->keyId, '8bit');
        $coseKey = self::decode(mb_substr($plain->authData, $coseKeyOffset, null, '8bit'));
        $point = self::pointOfPem($plain->publicKeyPem);
        $replaced = AttestationBuilder::create()
            ->withCoseKey('not a key')
            ->build();

        self::assertSame([1 => '2', 3 => '-7', -1 => '1', -2 => mb_substr($point, 1, 32, '8bit'), -3 => mb_substr($point, 33, 32, '8bit')], $coseKey);
        self::assertSame('not a key', mb_substr($replaced->authData, $coseKeyOffset, null, '8bit'));
        self::assertSame(
            AttestationBuilder::nonceExtensionDer(hash('sha256', $replaced->authData . $replaced->clientDataHash, true)),
            self::nonceExtensionOf($replaced->credentialDer),
        );
    }

    public function testExtensionsFollowTheCredentialPublicKey(): void
    {
        $extensions = ExtensionsMap::apple(4, '2.1');
        $plain = AttestationBuilder::create()->build();
        $extended = AttestationBuilder::create()
            ->withExtensions($extensions)
            ->build();

        self::assertSame($extensions, mb_substr($extended->authData, -mb_strlen($extensions, '8bit'), null, '8bit'));
        self::assertSame(mb_strlen($plain->authData, '8bit') + mb_strlen($extensions, '8bit'), mb_strlen($extended->authData, '8bit'));
        self::assertSame(
            AttestationBuilder::nonceExtensionDer(hash('sha256', $extended->authData . $extended->clientDataHash, true)),
            self::nonceExtensionOf($extended->credentialDer),
        );
        self::assertSame(
            [ExtensionsMap::BUNDLE_VERSION => '2.1', ExtensionsMap::VALIDATION_CATEGORY => "\x04\x00\x00\x00"],
            self::decode($extensions),
        );
    }

    public function testCredentialKeyCanStartWithAZeroByte(): void
    {
        $attestation = AttestationBuilder::create()
            ->withLeadingZeroX()
            ->build();
        $point = self::pointOf($attestation->credentialDer);

        self::assertSame("\x04\x00", mb_substr($point, 0, 2, '8bit'));
        self::assertSame(hash('sha256', $point, true), $attestation->keyId);
        self::assertSame($attestation->keyId, self::credentialIdOf($attestation->authData));
    }

    public function testDocumentCanBeMalformed(): void
    {
        $wrongFormat = self::decode(AttestationBuilder::create()->withFormat('packed')->build()->cbor);
        $withoutCertificates = self::decode(AttestationBuilder::create()->withoutCertificates()->build()->cbor);
        $truncated = AttestationBuilder::create()
            ->withAuthDataTruncatedTo(36)
            ->build();

        self::assertSame('packed', $wrongFormat['fmt']);
        self::assertSame(['receipt'], array_keys(self::map($withoutCertificates['attStmt'] ?? null)));
        self::assertSame(36, mb_strlen($truncated->authData, '8bit'));
        self::assertSame($truncated->authData, self::decode($truncated->cbor)['authData']);
    }

    public function testCertificatesAreValidAtTheChosenTime(): void
    {
        $time = new DateTimeImmutable('2031-06-01T08:00:00Z');
        $attestation = AttestationBuilder::create()
            ->withTime($time)
            ->build();

        self::assertSame($time->getTimestamp(), $attestation->clock()->now()->getTimestamp());
        self::assertTrue(self::validAt($attestation->credentialDer, $time));
        self::assertFalse(self::validAt($attestation->credentialDer, new DateTimeImmutable(AttestationBuilder::DEFAULT_TIME)));
    }

    public function testCredentialCertificateCanHoldAnotherKey(): void
    {
        $p384 = Pem::generatedPublicKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        $attestation = AttestationBuilder::create()
            ->withCredentialPublicKeyPem($p384)
            ->build();
        $credentialKey = openssl_pkey_get_public(Pem::fromDer($attestation->credentialDer, Pem::CERTIFICATE));
        self::assertNotFalse($credentialKey);

        self::assertSame($p384, openssl_pkey_get_details($credentialKey)['key'] ?? null);
        self::assertTrue(self::issuedBy($attestation->credentialDer, $attestation->intermediateDer));
        self::assertSame($attestation->keyId, self::credentialIdOf($attestation->authData));
    }

    public function testRootCanBeExpired(): void
    {
        $attestation = AttestationBuilder::create()
            ->withExpiredRoot()
            ->build();
        $now = $attestation->clock()->now();

        self::assertFalse(self::validAt($attestation->rootPem, $now));
        self::assertTrue(self::validAt($attestation->rootPem, $now->modify('-2 days')));
        self::assertTrue(self::validAt($attestation->intermediateDer, $now));
        self::assertTrue(self::validAt($attestation->credentialDer, $now));
        self::assertTrue(self::issuedBy($attestation->intermediateDer, $attestation->rootPem));
    }

    public function testCredentialCanComeFromAnUnlistedIssuer(): void
    {
        $attestation = AttestationBuilder::create()
            ->withCredentialFromAnUnlistedIssuer('http://192.0.2.1/ca.cer')
            ->build();
        $credential = X509::load($attestation->credentialDer);
        $authorityInfoAccess = $credential->getExtension('id-pe-authorityInfoAccess')['extnValue'] ?? null;
        self::assertInstanceOf(Constructed::class, $authorityInfoAccess);

        self::assertSame(['Oire Test Unlisted CA'], array_map(static fn(BaseString $name): string => $name->value, $credential->getIssuerDNProps('id-at-commonName')));
        self::assertSame(
            [['accessMethod' => 'id-ad-caIssuers', 'accessLocation' => ['uniformResourceIdentifier' => 'http://192.0.2.1/ca.cer']]],
            $authorityInfoAccess->toArray(true),
        );
        self::assertNotNull(self::nonceExtensionOf($attestation->credentialDer));
    }

    public function testBuiltAssertionIsSignedLikeADevice(): void
    {
        $builder = AssertionBuilder::create();
        $document = self::decode($builder->build('client data'));
        $signature = $document['signature'] ?? null;
        $authenticatorData = $document['authenticatorData'] ?? null;
        self::assertIsString($signature);
        self::assertIsString($authenticatorData);

        self::assertSame(['signature', 'authenticatorData'], array_keys($document));
        self::assertSame(AuthDataLayout::ASSERTION_LENGTH, mb_strlen($authenticatorData, '8bit'));
        self::assertSame(TestApp::identity()->rpIdHash(), mb_substr($authenticatorData, 0, AuthDataLayout::RP_ID_HASH_LENGTH, '8bit'));
        self::assertSame(1, self::counterOf($authenticatorData));
        self::assertSame(1, openssl_verify(hash('sha256', $authenticatorData . hash('sha256', 'client data', true), true), $signature, $builder->publicKeyPem(), OPENSSL_ALGO_SHA256));
        self::assertSame(0, openssl_verify(hash('sha256', $authenticatorData . hash('sha256', 'other data', true), true), $signature, $builder->publicKeyPem(), OPENSSL_ALGO_SHA256));
    }

    public function testAssertionFieldsCanBeChosen(): void
    {
        $app = new AppIdentity(new TeamId('ZYXWV98765'), new BundleId('org.example.other'));
        $builder = AssertionBuilder::create();
        $document = self::decode($builder
            ->withApp($app)
            ->withCounter(5)
            ->build('client data'));
        $authenticatorData = $document['authenticatorData'] ?? null;
        $signature = $document['signature'] ?? null;
        self::assertIsString($authenticatorData);
        self::assertIsString($signature);

        self::assertSame($app->rpIdHash(), mb_substr($authenticatorData, 0, AuthDataLayout::RP_ID_HASH_LENGTH, '8bit'));
        self::assertSame(5, self::counterOf($authenticatorData));
        self::assertSame(1, openssl_verify(hash('sha256', $authenticatorData . hash('sha256', 'client data', true), true), $signature, $builder->publicKeyPem(), OPENSSL_ALGO_SHA256));
    }

    public function testAssertionExtensionsFollowTheCounterAndAreSigned(): void
    {
        $extensions = ExtensionsMap::of([ExtensionsMap::SHORT_VALIDATION_CATEGORY => ExtensionsMap::categoryInteger(2)]);
        $builder = AssertionBuilder::create()->withExtensions($extensions);
        $document = self::decode($builder->build('client data'));
        $authenticatorData = $document['authenticatorData'] ?? null;
        $signature = $document['signature'] ?? null;
        self::assertIsString($authenticatorData);
        self::assertIsString($signature);

        self::assertSame($extensions, mb_substr($authenticatorData, AuthDataLayout::ASSERTION_LENGTH, null, '8bit'));
        self::assertSame(1, openssl_verify(hash('sha256', $authenticatorData . hash('sha256', 'client data', true), true), $signature, $builder->publicKeyPem(), OPENSSL_ALGO_SHA256));
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function decode(string $cbor): array
    {
        $object = Decoder::create()->decode(StringStream::create($cbor));
        self::assertInstanceOf(Normalizable::class, $object);

        return self::map($object->normalize());
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function map(mixed $value): array
    {
        self::assertIsArray($value);

        return $value;
    }

    private static function counterOf(string $authData): int
    {
        $counter = unpack('N', mb_substr($authData, AuthDataLayout::COUNTER_OFFSET, AuthDataLayout::COUNTER_LENGTH, '8bit'));

        if ($counter === false || !isset($counter[1]) || !is_int($counter[1])) {
            self::fail('The counter cannot be read.');
        }

        return $counter[1];
    }

    private static function credentialIdOf(string $authData): string
    {
        $length = unpack('n', mb_substr($authData, AuthDataLayout::CREDENTIAL_ID_LENGTH_OFFSET, 2, '8bit'));

        if ($length === false || !isset($length[1]) || !is_int($length[1])) {
            self::fail('The credentialId length cannot be read.');
        }

        return mb_substr($authData, AuthDataLayout::CREDENTIAL_ID_OFFSET, $length[1], '8bit');
    }

    private static function pointOf(string $certificateDer): string
    {
        $offset = mb_strpos($certificateDer, EcKey::P256_SPKI_PREFIX, 0, '8bit');
        self::assertIsInt($offset);

        return mb_substr($certificateDer, $offset + mb_strlen(EcKey::P256_SPKI_PREFIX, '8bit'), EcKey::POINT_LENGTH, '8bit');
    }

    private static function pointOfPem(string $pem): string
    {
        $spki = Pem::toDer($pem);
        self::assertSame(EcKey::SPKI_LENGTH, mb_strlen($spki, '8bit'));

        return mb_substr($spki, -EcKey::POINT_LENGTH, null, '8bit');
    }

    private static function nonceExtensionOf(string $certificateDer): ?string
    {
        $offset = mb_strpos($certificateDer, self::NONCE_EXTENSION_OID_DER, 0, '8bit');

        if ($offset === false) {
            return null;
        }

        $octetString = mb_substr($certificateDer, $offset + mb_strlen(self::NONCE_EXTENSION_OID_DER, '8bit'), 2, '8bit');
        self::assertSame("\x04", $octetString[0]);

        return mb_substr($certificateDer, $offset + mb_strlen(self::NONCE_EXTENSION_OID_DER, '8bit') + 2, ord($octetString[1]), '8bit');
    }

    private static function issuedBy(string $certificate, string $issuer): bool
    {
        X509::addCA($issuer);
        X509::setTargetValidationDate(null);

        try {
            return X509::load($certificate)->validateSignature();
        } finally {
            X509::clearCAStore();
            X509::setTargetValidationDate('now');
        }
    }

    private static function signedBy(string $certificate, string $issuer, string $hash = 'sha256'): bool
    {
        [$tbsCertificate, , $bits] = SignedCertificate::split($certificate);
        $key = openssl_pkey_get_public(Pem::fromDer($issuer, Pem::CERTIFICATE));
        self::assertNotFalse($key);

        return openssl_verify($tbsCertificate, mb_substr($bits, 1, null, '8bit'), $key, $hash) === 1;
    }

    /**
     * How many extensions with the OID the certificate holds, and all of them with the same value.
     */
    private static function extensionCount(string $der, string $oid): int
    {
        $certificate = ASN1::map(ASN1::decodeBER($der), Certificate::MAP);
        self::assertInstanceOf(Constructed::class, $certificate);
        $tbsCertificate = $certificate['tbsCertificate'];
        self::assertInstanceOf(Constructed::class, $tbsCertificate);
        $extensions = $tbsCertificate['extensions'];
        self::assertInstanceOf(Constructed::class, $extensions);
        $values = [];

        foreach ($extensions as $extension) {
            self::assertInstanceOf(Constructed::class, $extension);

            if (ASN1::getOIDFromName((string) $extension['extnId']) === $oid) {
                $value = $extension['extnValue'];
                self::assertInstanceOf(OctetString::class, $value);
                $values[] = $value->value;
            }
        }

        self::assertLessThanOrEqual(1, count(array_unique($values)));

        return count($values);
    }

    private static function isIssuerOf(string $issuer, string $certificate): bool
    {
        return X509::load($issuer, ASN1::FORMAT_DER)->isIssuerOf(X509::load($certificate, ASN1::FORMAT_DER));
    }

    private static function hasKeyCertSign(string $certificate): bool
    {
        $keyUsage = X509::load($certificate, ASN1::FORMAT_DER)->getExtension('id-ce-keyUsage')['extnValue'] ?? null;
        self::assertInstanceOf(BitString::class, $keyUsage);

        return $keyUsage->contains('keyCertSign');
    }

    private static function isCa(string $certificate): bool
    {
        $basicConstraints = X509::load($certificate)->getExtension('id-ce-basicConstraints')['extnValue'] ?? null;

        if ($basicConstraints === null) {
            return false;
        }

        self::assertInstanceOf(Constructed::class, $basicConstraints);
        $cA = $basicConstraints['cA'];
        self::assertInstanceOf(Boolean::class, $cA);

        return $cA->value;
    }

    private static function validAt(string $certificate, DateTimeImmutable $time): bool
    {
        $tbsCertificate = X509::load($certificate)['tbsCertificate'];
        self::assertInstanceOf(Constructed::class, $tbsCertificate);
        $validity = $tbsCertificate['validity'];
        self::assertInstanceOf(Constructed::class, $validity);

        return $time >= self::timeOf($validity['notBefore']) && $time <= self::timeOf($validity['notAfter']);
    }

    private static function timeOf(mixed $choice): DateTimeInterface
    {
        self::assertInstanceOf(Choice::class, $choice);
        self::assertInstanceOf(DateTimeInterface::class, $choice->value);

        return $choice->value;
    }
}
