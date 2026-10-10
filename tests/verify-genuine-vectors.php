<?php

declare(strict_types=1);

use Oire\AppAttest\AssertionVerifier;
use Oire\AppAttest\AttestationVerifier;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;
use Psr\Clock\ClockInterface;

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

/*
 * Verifies every genuine vector in tests/fixtures with no autoloader but the one PHP prepends, CI's install of
 * the Composer package made with `composer install --no-dev`:
 *
 *     php -d auto_prepend_file=<package>/vendor/autoload.php tests/verify-genuine-vectors.php
 *
 * so that code in src/ cannot come to need a development dependency without CI failing.
 */

/**
 * @return array<array-key, mixed>
 */
function sidecar(string $path): array
{
    $sidecar = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);

    if (!is_array($sidecar)) {
        throw new UnexpectedValueException($path . ' does not hold a JSON object.');
    }

    return $sidecar;
}

/**
 * @param array<array-key, mixed> $data
 *
 * @return array<array-key, mixed>
 *
 * @psalm-pure
 */
function objectMember(array $data, string $key): array
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
function member(array $data, string $key): string
{
    $value = $data[$key] ?? null;

    if (!is_string($value)) {
        throw new UnexpectedValueException('The sidecar member ' . $key . ' must be a string.');
    }

    return $value;
}

/**
 * @param array<array-key, mixed> $data
 *
 * @psalm-pure
 */
function bytes(array $data, string $key): string
{
    return sodium_base642bin(member($data, $key), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

/**
 * @return list<string>
 */
function sidecarPaths(string $directory): array
{
    $paths = glob($directory . '/*.json');

    return $paths === false ? [] : $paths;
}

/**
 * @param array<array-key, mixed> $sidecar
 *
 * @psalm-pure
 */
function appOf(array $sidecar): AppIdentity
{
    return new AppIdentity(new TeamId(member($sidecar, 'teamId')), new BundleId(member($sidecar, 'bundleId')));
}

$fixtures = __DIR__ . '/fixtures';
$verified = 0;

foreach (sidecarPaths($fixtures . '/attestation') as $path) {
    $sidecar = sidecar($path);
    $clock = new class(new DateTimeImmutable(member($sidecar, 'verifyAt'))) implements ClockInterface {
        /**
         * @psalm-capabilities read-props
         */
        public function __construct(private readonly DateTimeImmutable $now) {}

        #[Override]
        public function now(): DateTimeImmutable
        {
            return $this->now;
        }
    };
    $key = (new AttestationVerifier(null, $clock))->verify(
        (string) file_get_contents($fixtures . '/attestation/' . member($sidecar, 'vector')),
        bytes(objectMember($sidecar, 'clientDataHash'), 'value'),
        bytes($sidecar, 'keyId'),
        appOf($sidecar),
        [Environment::from(member($sidecar, 'environment'))],
    );

    if ($key->publicKeyPem !== member(objectMember($sidecar, 'expected'), 'publicKeyPem')) {
        throw new UnexpectedValueException(basename($path) . ' returned another public key.');
    }

    ++$verified;
}

foreach (sidecarPaths($fixtures . '/assertion') as $path) {
    $sidecar = sidecar($path);
    $previousCounter = $sidecar['previousCounter'] ?? null;

    if (!is_int($previousCounter)) {
        throw new UnexpectedValueException(basename($path) . ' has no previousCounter.');
    }

    (new AssertionVerifier())->verify(
        (string) file_get_contents($fixtures . '/assertion/' . member($sidecar, 'vector')),
        bytes($sidecar, 'clientData'),
        member($sidecar, 'publicKeyPem'),
        $previousCounter,
        appOf($sidecar),
    );
    ++$verified;
}

if ($verified === 0) {
    throw new UnexpectedValueException('No genuine vector was found.');
}

echo 'Verified ' . $verified . " genuine vectors.\n";
