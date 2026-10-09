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
 * The authenticatorData of an attestation: rpIdHash (32 bytes), flags (1), signCount (4, big-endian),
 * aaguid (16), credentialId length (2, big-endian), credentialId, then the credential public key.
 * Bytes after the credentialId are not interpreted: the public key, and any extensions Apple appends.
 *
 * @internal
 *
 * @psalm-immutable
 */
final readonly class AuthenticatorData
{
    private const int RP_ID_HASH_LENGTH = 32;
    private const int COUNTER_OFFSET = 33;
    private const int AAGUID_OFFSET = 37;
    private const int AAGUID_LENGTH = 16;
    private const int CREDENTIAL_ID_LENGTH_OFFSET = 53;
    private const int CREDENTIAL_ID_OFFSET = 55;

    /**
     * @param string $rpIdHash     raw bytes
     * @param string $aaguid       raw bytes
     * @param string $credentialId raw bytes
     *
     * @psalm-capabilities read-props
     */
    private function __construct(
        public string $rpIdHash,
        public int $counter,
        public string $aaguid,
        public string $credentialId,
    ) {}

    /**
     * The parsed data, or null if the bytes are shorter than the layout requires.
     *
     * @psalm-pure
     */
    public static function tryFromAttestation(string $bytes): ?self
    {
        $length = mb_strlen($bytes, '8bit');

        if ($length < self::CREDENTIAL_ID_OFFSET) {
            return null;
        }

        $credentialIdLength = self::unsigned('n', mb_substr($bytes, self::CREDENTIAL_ID_LENGTH_OFFSET, 2, '8bit'));

        if ($length <= self::CREDENTIAL_ID_OFFSET + $credentialIdLength) {
            return null;
        }

        return new self(
            mb_substr($bytes, 0, self::RP_ID_HASH_LENGTH, '8bit'),
            self::unsigned('N', mb_substr($bytes, self::COUNTER_OFFSET, 4, '8bit')),
            mb_substr($bytes, self::AAGUID_OFFSET, self::AAGUID_LENGTH, '8bit'),
            mb_substr($bytes, self::CREDENTIAL_ID_OFFSET, $credentialIdLength, '8bit'),
        );
    }

    /**
     * @param 'n'|'N' $format
     *
     * @psalm-pure
     */
    private static function unsigned(string $format, string $bytes): int
    {
        $unpacked = unpack($format, $bytes);

        return $unpacked === false || !isset($unpacked[1]) || !is_int($unpacked[1]) ? 0 : $unpacked[1];
    }
}
