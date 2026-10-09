<?php

declare(strict_types=1);

namespace Oire\AppAttest\Value;

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
 * A key that passed attestation: what the caller stores to verify the app's later assertions.
 *
 * @psalm-api
 * @psalm-immutable
 */
final readonly class AttestedKey
{
    /**
     * The sign counter of a freshly attested key, which is always 0.
     */
    public int $counter;

    /**
     * @param string $keyId   the key id as raw bytes: the SHA-256 of the public key's uncompressed EC point
     * @param string $receipt Apple's App Attest receipt as raw bytes
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        public string $keyId,
        public string $publicKeyPem,
        public Environment $environment,
        public string $receipt,
    ) {
        $this->counter = 0;
    }

    /**
     * The key id as unpadded base64url, for storing or indexing it as text.
     *
     * @psalm-capabilities read-props
     */
    public function keyIdBase64Url(): string
    {
        return sodium_bin2base64($this->keyId, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
