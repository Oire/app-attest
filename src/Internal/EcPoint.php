<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

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
 * A P-256 public key as its raw 65-byte uncompressed point, read from the bytes of a SubjectPublicKeyInfo:
 * the key id is the SHA-256 of exactly these bytes, leading zeros included.
 *
 * @internal
 *
 * @psalm-immutable
 */
final readonly class EcPoint
{
    /**
     * SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (66 bytes, no unused bits) }.
     */
    private const string P256_SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";
    private const int POINT_LENGTH = 65;
    private const string UNCOMPRESSED = "\x04";

    /**
     * @psalm-capabilities read-props
     */
    private function __construct(private string $subjectPublicKeyInfo, public string $point) {}

    /**
     * The point, or null if the DER is not an uncompressed P-256 key on the curve.
     *
     * @psalm-capabilities read-props
     */
    public static function tryFromSubjectPublicKeyInfo(string $der): ?self
    {
        $prefixLength = mb_strlen(self::P256_SPKI_PREFIX, '8bit');

        if (
            mb_strlen($der, '8bit') !== $prefixLength + self::POINT_LENGTH
            || !hash_equals(self::P256_SPKI_PREFIX, mb_substr($der, 0, $prefixLength, '8bit'))
        ) {
            return null;
        }

        $point = new self($der, mb_substr($der, $prefixLength, null, '8bit'));

        if (mb_substr($point->point, 0, 1, '8bit') !== self::UNCOMPRESSED || !$point->isOnP256()) {
            return null;
        }

        return $point;
    }

    /**
     * The key id: the SHA-256 of the point, as raw bytes.
     *
     * @psalm-capabilities read-props
     */
    public function keyId(): string
    {
        return hash('sha256', $this->point, true);
    }

    /**
     * @psalm-capabilities read-props
     */
    public function publicKeyPem(): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($this->subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * @psalm-capabilities read-props
     */
    private function isOnP256(): bool
    {
        $key = openssl_pkey_get_public($this->publicKeyPem());
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if (!is_array($details) || !isset($details['ec']) || !is_array($details['ec'])) {
            return false;
        }

        return ($details['ec']['curve_name'] ?? null) === 'prime256v1';
    }
}
