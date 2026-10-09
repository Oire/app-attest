<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use DateTimeImmutable;
use Oire\AppAttest\Tests\Support\AssertionVector;
use Oire\AppAttest\Tests\Support\AttestationVector;
use Oire\AppAttest\Tests\Support\ClientDataHashFormation;
use Oire\AppAttest\Tests\Support\VectorOrigin;
use Oire\AppAttest\Value\Environment;
use SodiumException;
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

/**
 * Loads the golden vectors in tests/fixtures from their JSON sidecars.
 */
final class Fixtures
{
    public const string DIRECTORY = __DIR__ . '/fixtures';

    /**
     * @return array<string, AttestationVector> keyed by vector name
     */
    public static function attestations(): array
    {
        $vectors = [];

        foreach (self::sidecars('attestation') as $name => $sidecar) {
            $vectors[$name] = self::attestationFrom($name, $sidecar);
        }

        return $vectors;
    }

    /**
     * @return array<string, AssertionVector> keyed by vector name
     */
    public static function assertions(): array
    {
        $vectors = [];

        foreach (self::sidecars('assertion') as $name => $sidecar) {
            $vectors[$name] = self::assertionFrom($name, $sidecar);
        }

        return $vectors;
    }

    public static function attestation(string $name): AttestationVector
    {
        return self::attestations()[$name] ?? throw new UnexpectedValueException('No attestation vector named ' . $name . '.');
    }

    public static function assertion(string $name): AssertionVector
    {
        return self::assertions()[$name] ?? throw new UnexpectedValueException('No assertion vector named ' . $name . '.');
    }

    /**
     * @return array<string, array<array-key, mixed>>
     */
    private static function sidecars(string $kind): array
    {
        $paths = glob(self::DIRECTORY . '/' . $kind . '/*.json');

        if ($paths === false || $paths === []) {
            throw new UnexpectedValueException('No ' . $kind . ' sidecars found.');
        }

        $sidecars = [];

        foreach ($paths as $path) {
            $json = file_get_contents($path);

            if ($json === false) {
                throw new UnexpectedValueException('Cannot read ' . $path . '.');
            }

            $sidecar = json_decode($json, true, 16, JSON_THROW_ON_ERROR);

            if (!is_array($sidecar)) {
                throw new UnexpectedValueException($path . ' does not hold a JSON object.');
            }

            $sidecars[basename($path, '.json')] = $sidecar;
        }

        return $sidecars;
    }

    /**
     * @param array<array-key, mixed> $sidecar
     */
    private static function attestationFrom(string $name, array $sidecar): AttestationVector
    {
        $clientDataHash = self::object($sidecar, 'clientDataHash');
        $expected = self::object($sidecar, 'expected');
        self::expectAccepted($expected);

        return new AttestationVector(
            $name,
            self::vectorBytes('attestation', $sidecar),
            self::origin($sidecar),
            self::string($sidecar, 'teamId'),
            self::string($sidecar, 'bundleId'),
            self::base64Url($sidecar, 'keyId'),
            self::string($clientDataHash, 'challenge'),
            ClientDataHashFormation::from(self::string($clientDataHash, 'formedAs')),
            self::base64Url($clientDataHash, 'value'),
            Environment::from(self::string($sidecar, 'environment')),
            self::time($sidecar, 'verifyAt'),
            self::string($expected, 'publicKeyPem'),
            self::int($expected, 'counter'),
        );
    }

    /**
     * @param array<array-key, mixed> $sidecar
     */
    private static function assertionFrom(string $name, array $sidecar): AssertionVector
    {
        $expected = self::object($sidecar, 'expected');
        self::expectAccepted($expected);

        return new AssertionVector(
            $name,
            self::vectorBytes('assertion', $sidecar),
            self::origin($sidecar),
            self::string($sidecar, 'attestation'),
            self::string($sidecar, 'teamId'),
            self::string($sidecar, 'bundleId'),
            self::base64Url($sidecar, 'keyId'),
            self::base64Url($sidecar, 'clientData'),
            self::base64Url($sidecar, 'challenge'),
            self::string($sidecar, 'publicKeyPem'),
            self::int($sidecar, 'previousCounter'),
            Environment::from(self::string($sidecar, 'environment')),
            self::time($sidecar, 'verifyAt'),
            self::int($expected, 'counter'),
        );
    }

    /**
     * @param array<array-key, mixed> $sidecar
     */
    private static function vectorBytes(string $kind, array $sidecar): string
    {
        $path = self::DIRECTORY . '/' . $kind . '/' . self::string($sidecar, 'vector');
        $bytes = is_file($path) ? file_get_contents($path) : false;

        if ($bytes === false || $bytes === '') {
            throw new UnexpectedValueException('The vector file ' . $path . ' is missing or empty.');
        }

        return $bytes;
    }

    /**
     * @param array<array-key, mixed> $sidecar
     *
     * @psalm-pure
     */
    private static function origin(array $sidecar): VectorOrigin
    {
        $origin = self::object($sidecar, 'origin');

        return new VectorOrigin(
            self::string($origin, 'repository'),
            self::string($origin, 'commit'),
            self::string($origin, 'path'),
            self::DIRECTORY . '/' . self::string($origin, 'copy'),
            self::DIRECTORY . '/' . self::string($origin, 'license'),
            isset($origin['documentId']) ? self::string($origin, 'documentId') : null,
        );
    }

    /**
     * @param array<array-key, mixed> $expected
     *
     * @psalm-pure
     */
    private static function expectAccepted(array $expected): void
    {
        if (self::string($expected, 'result') !== 'accepted') {
            throw new UnexpectedValueException('Genuine vectors are only ever expected to be accepted.');
        }
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @return array<array-key, mixed>
     *
     * @psalm-pure
     */
    private static function object(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        if (!is_array($value)) {
            throw new UnexpectedValueException('The sidecar member ' . $key . ' must be an object.');
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @psalm-pure
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (!is_string($value) || $value === '') {
            throw new UnexpectedValueException('The sidecar member ' . $key . ' must be a non-empty string.');
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @psalm-pure
     */
    private static function int(array $data, string $key): int
    {
        $value = $data[$key] ?? null;

        if (!is_int($value)) {
            throw new UnexpectedValueException('The sidecar member ' . $key . ' must be an integer.');
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @psalm-pure
     */
    private static function base64Url(array $data, string $key): string
    {
        try {
            return sodium_base642bin(self::string($data, $key), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (SodiumException $e) {
            throw new UnexpectedValueException('The sidecar member ' . $key . ' must be unpadded base64url.', 0, $e);
        }
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @psalm-capabilities read-props
     */
    private static function time(array $data, string $key): DateTimeImmutable
    {
        $time = DateTimeImmutable::createFromFormat('!Y-m-d\\TH:i:s.vp', self::string($data, $key));

        if ($time === false) {
            throw new UnexpectedValueException('The sidecar member ' . $key . ' must be an ISO 8601 UTC time with milliseconds.');
        }

        return $time;
    }
}
