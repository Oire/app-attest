<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use RuntimeException;

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
 * A freshly generated P-256 key pair for the test builders.
 *
 * @psalm-immutable
 */
final readonly class EcKey
{
    /**
     * SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (66 bytes, no unused bits) }.
     */
    public const string P256_SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";
    public const int SPKI_LENGTH = 91;
    public const int POINT_LENGTH = 65;

    /**
     * @param string $point the uncompressed EC point: 0x04, then x and y, 32 bytes each
     *
     * @psalm-capabilities read-props
     */
    private function __construct(
        public string $privateKeyPem,
        public string $publicKeyPem,
        public string $point,
    ) {}

    /**
     * @psalm-pure
     */
    public static function generate(): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        if ($key === false || !openssl_pkey_export($key, $privateKeyPem)) {
            throw new RuntimeException('Cannot generate a P-256 key.');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || !isset($details['key']) || !is_string($details['key'])) {
            throw new RuntimeException('Cannot export the generated P-256 key.');
        }

        $publicKeyPem = $details['key'];
        $spki = Pem::toDer($publicKeyPem);

        if (mb_strlen($spki, '8bit') !== self::SPKI_LENGTH) {
            throw new RuntimeException('The generated key is not an uncompressed P-256 key.');
        }

        return new self($privateKeyPem, $publicKeyPem, mb_substr($spki, -self::POINT_LENGTH, null, '8bit'));
    }

    /**
     * A key whose x coordinate starts with a zero byte, which a naive key id computation would drop.
     *
     * @psalm-pure
     */
    public static function generateWithLeadingZeroX(): self
    {
        do {
            $key = self::generate();
        } while ($key->point[1] !== "\x00");

        return $key;
    }

    /**
     * The public key as a SubjectPublicKeyInfo whose point starts with another prefix byte than 0x04.
     *
     * @psalm-capabilities read-props
     */
    public function publicKeyPemWithPrefix(string $prefix): string
    {
        return Pem::fromDer(self::P256_SPKI_PREFIX . $prefix . mb_substr($this->point, 1, null, '8bit'), Pem::PUBLIC_KEY);
    }

    /**
     * @psalm-capabilities read-props
     */
    public function keyId(): string
    {
        return hash('sha256', $this->point, true);
    }

    /**
     * @psalm-capabilities read-props
     */
    public function x(): string
    {
        return mb_substr($this->point, 1, 32, '8bit');
    }

    /**
     * @psalm-capabilities read-props
     */
    public function y(): string
    {
        return mb_substr($this->point, 33, 32, '8bit');
    }
}
