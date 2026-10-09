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
    private const int SPKI_LENGTH = 91;
    private const int POINT_LENGTH = 65;

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
        $spki = base64_decode(preg_replace('/-----[A-Z ]+-----|\\s+/', '', $publicKeyPem) ?? '', true);

        if (!is_string($spki) || mb_strlen($spki, '8bit') !== self::SPKI_LENGTH) {
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
