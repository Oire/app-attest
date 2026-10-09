<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use LogicException;

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
 * Authenticator data: rpIdHash (32 bytes), flags (1), signCount (4, big-endian), then, in an attestation
 * only, aaguid (16), credentialId length (2, big-endian), credentialId and the credential public key as one
 * CBOR item. What follows, after the public key in an attestation and after the counter in an assertion, is
 * read as the extensions map whatever the flags say; bytes that are not one well-formed map are ignored.
 *
 * @internal
 */
final readonly class AuthenticatorData
{
    public const int MAX_UINT32 = 0xFFFFFFFF;
    private const int RP_ID_HASH_LENGTH = 32;
    private const int COUNTER_OFFSET = 33;
    private const int COUNTER_LENGTH = 4;
    public const int ASSERTION_LENGTH = self::COUNTER_OFFSET + self::COUNTER_LENGTH;
    private const int AAGUID_OFFSET = 37;
    private const int AAGUID_LENGTH = 16;
    private const int CREDENTIAL_ID_LENGTH_OFFSET = 53;
    private const int CREDENTIAL_ID_LENGTH_SIZE = 2;
    private const int CREDENTIAL_ID_OFFSET = 55;

    /**
     * @param string $rpIdHash     raw bytes
     * @param string $aaguid       raw bytes, empty in an assertion
     * @param string $credentialId raw bytes, empty in an assertion
     *
     * @psalm-capabilities read-props
     */
    private function __construct(
        public string $rpIdHash,
        public int $counter,
        public string $aaguid,
        public string $credentialId,
        public Extensions $extensions,
    ) {}

    /**
     * The parsed data, or null if the bytes are shorter than the layout requires.
     */
    public static function tryFromAttestation(string $bytes): ?self
    {
        $length = mb_strlen($bytes, '8bit');

        if ($length < self::CREDENTIAL_ID_OFFSET) {
            return null;
        }

        $credentialIdLength = self::unsigned('n', mb_substr($bytes, self::CREDENTIAL_ID_LENGTH_OFFSET, self::CREDENTIAL_ID_LENGTH_SIZE, '8bit'));

        if ($length <= self::CREDENTIAL_ID_OFFSET + $credentialIdLength) {
            return null;
        }

        $publicKeyAndExtensions = mb_substr($bytes, self::CREDENTIAL_ID_OFFSET + $credentialIdLength, null, '8bit');
        $publicKeyLength = Cbor::tryItemLength($publicKeyAndExtensions);

        return new self(
            self::rpIdHashOf($bytes),
            self::counterOf($bytes),
            mb_substr($bytes, self::AAGUID_OFFSET, self::AAGUID_LENGTH, '8bit'),
            mb_substr($bytes, self::CREDENTIAL_ID_OFFSET, $credentialIdLength, '8bit'),
            $publicKeyLength === null
                ? Extensions::none()
                : Extensions::fromArea(mb_substr($publicKeyAndExtensions, $publicKeyLength, null, '8bit')),
        );
    }

    /**
     * The rpIdHash, counter and extensions of an assertion, or null if the bytes are shorter than
     * ASSERTION_LENGTH.
     */
    public static function tryFromAssertion(string $bytes): ?self
    {
        if (mb_strlen($bytes, '8bit') < self::ASSERTION_LENGTH) {
            return null;
        }

        return new self(
            self::rpIdHashOf($bytes),
            self::counterOf($bytes),
            '',
            '',
            Extensions::fromArea(mb_substr($bytes, self::ASSERTION_LENGTH, null, '8bit')),
        );
    }

    /**
     * @psalm-pure
     */
    private static function rpIdHashOf(string $bytes): string
    {
        return mb_substr($bytes, 0, self::RP_ID_HASH_LENGTH, '8bit');
    }

    /**
     * @psalm-pure
     */
    private static function counterOf(string $bytes): int
    {
        return self::unsigned('N', mb_substr($bytes, self::COUNTER_OFFSET, self::COUNTER_LENGTH, '8bit'));
    }

    /**
     * @param 'n'|'N' $format
     *
     * @throws LogicException if the bytes are too short, which every caller has checked
     *
     * @psalm-pure
     */
    private static function unsigned(string $format, string $bytes): int
    {
        $unpacked = unpack($format, $bytes);

        if ($unpacked === false || !isset($unpacked[1]) || !is_int($unpacked[1])) {
            throw new LogicException('A length-checked authenticator data field could not be read.');
        }

        return $unpacked[1];
    }
}
