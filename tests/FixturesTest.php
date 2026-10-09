<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use Oire\AppAttest\Tests\Support\AssertionVector;
use Oire\AppAttest\Tests\Support\AttestationVector;
use Oire\AppAttest\Tests\Support\ClientDataHashFormation;
use Oire\AppAttest\Tests\Support\Pem;
use Oire\AppAttest\Tests\Support\VectorOrigin;
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
final class FixturesTest extends TestCase
{
    public function testEveryReferenceVectorIsCollected(): void
    {
        self::assertCount(8, Fixtures::attestations());
        self::assertCount(7, Fixtures::assertions());
    }

    #[DataProvider('provideAttestations')]
    public function testAttestationSidecarIsComplete(AttestationVector $vector): void
    {
        self::assertSame(32, mb_strlen($vector->keyId, '8bit'));
        self::assertSame($vector->clientDataHashFormation->form($vector->challenge), $vector->clientDataHash);
        self::assertSame(hash('sha256', $vector->app()->appId(), true), $vector->app()->rpIdHash());
        self::assertNotFalse(openssl_pkey_get_public($vector->expectedPublicKeyPem));
        self::assertSame(0, $vector->expectedCounter);
        self::assertSame($vector->verifyAt->format(DATE_RFC3339_EXTENDED), $vector->clock()->now()->format(DATE_RFC3339_EXTENDED));
        self::assertOriginHolds($vector->origin, $vector->bytes);
    }

    #[DataProvider('provideAttestations')]
    public function testAttestationIsVerifiedWithinItsCredentialCertificateValidity(AttestationVector $vector): void
    {
        $object = Decoder::create()->decode(StringStream::create($vector->bytes));
        self::assertInstanceOf(Normalizable::class, $object);
        $document = $object->normalize();
        self::assertIsArray($document);
        self::assertIsArray($document['attStmt'] ?? null);
        self::assertIsArray($document['attStmt']['x5c'] ?? null);
        $credentialDer = $document['attStmt']['x5c'][0] ?? null;
        self::assertIsString($credentialDer);

        $certificate = openssl_x509_parse(Pem::fromDer($credentialDer, Pem::CERTIFICATE));
        self::assertIsArray($certificate);
        self::assertIsInt($certificate['validFrom_time_t'] ?? null);
        self::assertIsInt($certificate['validTo_time_t'] ?? null);

        self::assertGreaterThanOrEqual($certificate['validFrom_time_t'], $vector->verifyAt->getTimestamp());
        self::assertLessThanOrEqual($certificate['validTo_time_t'], $vector->verifyAt->getTimestamp());
    }

    #[DataProvider('provideAssertions')]
    public function testAssertionSidecarIsComplete(AssertionVector $vector): void
    {
        $attestation = Fixtures::attestation($vector->attestation);

        self::assertSame($attestation->keyId, $vector->keyId);
        self::assertSame($attestation->expectedPublicKeyPem, $vector->publicKeyPem);
        self::assertSame($attestation->app()->rpIdHash(), $vector->app()->rpIdHash());
        self::assertSame($attestation->environment, $vector->environment);
        self::assertGreaterThan($attestation->verifyAt, $vector->verifyAt);
        self::assertStringContainsString($vector->challenge, $vector->clientData);
        self::assertGreaterThan($vector->previousCounter, $vector->expectedCounter);
        self::assertOriginHolds($vector->origin, $vector->bytes);
    }

    #[DataProvider('provideAttestationsFromYaml')]
    public function testAttestationSidecarMatchesItsSourceDocument(AttestationVector $vector): void
    {
        $document = self::sourceDocumentOf($vector->origin);

        self::assertSame(ClientDataHashFormation::Sha256, $vector->clientDataHashFormation);
        self::assertStringContainsString("\nclientDataBase64: " . base64_encode($vector->challenge) . "\n", $document);
        self::assertStringContainsString("\nclientDataHashSha256Base64: " . base64_encode($vector->clientDataHash) . "\n", $document);
        self::assertStringContainsString("\ntimestamp: '" . $vector->verifyAt->format('Y-m-d\\TH:i:s.v\\Z') . "'\n", $document);
        self::assertSourceDocumentNamesTheKey($document, $vector->teamId, $vector->bundleId, $vector->keyId, $vector->expectedPublicKeyPem, $vector->environment->value);
    }

    #[DataProvider('provideAssertionsFromYaml')]
    public function testAssertionSidecarMatchesItsSourceDocument(AssertionVector $vector): void
    {
        $document = self::sourceDocumentOf($vector->origin);

        self::assertStringContainsString("\nclientDataBase64: " . base64_encode($vector->clientData) . "\n", $document);
        self::assertStringContainsString("\nchallengeBase64: " . base64_encode($vector->challenge) . "\n", $document);
        self::assertStringContainsString("\ncounter: " . $vector->expectedCounter . "\n", $document);
        self::assertStringContainsString("\ntimestamp: '" . $vector->verifyAt->format('Y-m-d\\TH:i:s.v\\Z') . "'\n", $document);
        self::assertSourceDocumentNamesTheKey($document, $vector->teamId, $vector->bundleId, $vector->keyId, $vector->publicKeyPem, $vector->environment->value);
    }

    public function testEveryVectorIsListedInTheReadme(): void
    {
        $readme = file_get_contents(Fixtures::DIRECTORY . '/README.md');
        self::assertIsString($readme);

        foreach ([...Fixtures::attestations(), ...Fixtures::assertions()] as $vector) {
            self::assertStringContainsString('`' . $vector->name . '`', $readme);
        }
    }

    /**
     * @return iterable<string, array{AttestationVector}>
     */
    public static function provideAttestations(): iterable
    {
        foreach (Fixtures::attestations() as $name => $vector) {
            yield $name => [$vector];
        }
    }

    /**
     * @return iterable<string, array{AssertionVector}>
     */
    public static function provideAssertions(): iterable
    {
        foreach (Fixtures::assertions() as $name => $vector) {
            yield $name => [$vector];
        }
    }

    /**
     * @return iterable<string, array{AttestationVector}>
     */
    public static function provideAttestationsFromYaml(): iterable
    {
        foreach (Fixtures::attestations() as $name => $vector) {
            if ($vector->origin->documentId !== null) {
                yield $name => [$vector];
            }
        }
    }

    /**
     * @return iterable<string, array{AssertionVector}>
     */
    public static function provideAssertionsFromYaml(): iterable
    {
        foreach (Fixtures::assertions() as $name => $vector) {
            if ($vector->origin->documentId !== null) {
                yield $name => [$vector];
            }
        }
    }

    /**
     * The document of the copied multi-document YAML file whose id the sidecar names, with a leading
     * newline so that every key can be matched at the start of a line.
     */
    private static function sourceDocumentOf(VectorOrigin $origin): string
    {
        $source = file_get_contents($origin->copyPath);
        self::assertIsString($source);
        $documentId = $origin->documentId;
        self::assertIsString($documentId);

        $matching = array_values(array_filter(
            explode("\n---\n", "\n" . $source . "\n"),
            static fn(string $document): bool => str_contains("\n" . $document . "\n", "\nid: " . $documentId . "\n"),
        ));
        self::assertCount(1, $matching);
        $document = $matching[0] ?? null;
        self::assertIsString($document);

        return "\n" . $document . "\n";
    }

    private static function assertSourceDocumentNamesTheKey(string $document, string $teamId, string $bundleId, string $keyId, string $publicKeyPem, string $environment): void
    {
        self::assertStringContainsString("\nteamIdentifier: " . $teamId . "\n", $document);
        self::assertStringContainsString("\nbundleIdentifier: " . $bundleId . "\n", $document);
        self::assertStringContainsString("\nenvironment: " . $environment . "\n", $document);
        self::assertStringContainsString("\nkeyIdBase64: " . base64_encode($keyId) . "\n", $document);

        foreach (array_filter(explode("\n", $publicKeyPem), static fn(string $line): bool => $line !== '') as $line) {
            self::assertStringContainsString("\n  " . $line . "\n", $document);
        }
    }

    /**
     * The vector file holds exactly the bytes the reference ships base64-encoded in the copied source file.
     */
    private static function assertOriginHolds(VectorOrigin $origin, string $bytes): void
    {
        self::assertMatchesRegularExpression('/^https:\\/\\/github\\.com\\/[A-Za-z0-9-]+\\/[A-Za-z0-9-]+$/D', $origin->repository);
        self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/D', $origin->commit);
        self::assertStringEndsWith('/' . basename($origin->path), $origin->copyPath);
        self::assertFileExists($origin->licensePath);

        $source = file_get_contents($origin->copyPath);
        self::assertIsString($source);
        self::assertStringContainsString(base64_encode($bytes), $source);
    }
}
