<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use DateTimeImmutable;
use Oire\AppAttest\TrustAnchor;
use Oire\AppAttest\Value\AppIdentity;
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
 * An attestation made by AttestationBuilder, with everything needed to verify it.
 */
final readonly class BuiltAttestation
{
    /**
     * @param string $cbor           the attestation object
     * @param string $keyId          raw bytes: the SHA-256 of the credential key's uncompressed EC point
     * @param string $clientDataHash raw bytes
     * @param string $authData       raw bytes, as inside the attestation object
     * @param string $receipt        raw bytes, as inside the attestation object
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        public string $cbor,
        public string $keyId,
        public string $publicKeyPem,
        public string $clientDataHash,
        public AppIdentity $app,
        public string $authData,
        public string $receipt,
        public string $rootPem,
        public string $intermediateDer,
        public string $credentialDer,
        public DateTimeImmutable $time,
    ) {}

    public function trustAnchor(): TrustAnchor
    {
        return TrustAnchor::fromPem($this->rootPem);
    }

    /**
     * A clock at the time the builder's certificates are valid at.
     */
    public function clock(): MockClock
    {
        return new MockClock($this->time);
    }
}
