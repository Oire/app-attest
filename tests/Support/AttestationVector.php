<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use DateTimeImmutable;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\Environment;
use Oire\AppAttest\Value\TeamId;
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

/**
 * A genuine attestation from a reference implementation, with the inputs it verifies with.
 */
final readonly class AttestationVector
{
    /**
     * @param string $bytes          the attestation object, byte-for-byte as the reference ships it
     * @param string $keyId          raw bytes
     * @param string $clientDataHash raw bytes, as passed to the verifier
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        public string $name,
        public string $bytes,
        public VectorOrigin $origin,
        public string $teamId,
        public string $bundleId,
        public string $keyId,
        public string $challenge,
        public ClientDataHashFormation $clientDataHashFormation,
        public string $clientDataHash,
        public Environment $environment,
        public DateTimeImmutable $verifyAt,
        public string $expectedPublicKeyPem,
        public int $expectedCounter,
    ) {}

    /**
     * @psalm-capabilities read-props
     */
    public function app(): AppIdentity
    {
        return new AppIdentity(new TeamId($this->teamId), new BundleId($this->bundleId));
    }

    /**
     * The clock to verify the vector with: its certificates have long expired.
     */
    public function clock(): MockClock
    {
        return new MockClock($this->verifyAt);
    }
}
