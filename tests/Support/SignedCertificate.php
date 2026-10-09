<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps\Certificate;
use phpseclib4\File\ASN1\Maps\TBSCertificate;
use phpseclib4\File\ASN1\Types\BitString;
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
 * Takes a DER certificate apart into its tbsCertificate, signatureAlgorithm and signature BIT STRING, and puts
 * one together again, signed or not: test code only, never shipped.
 */
final class SignedCertificate
{
    public const string ECDSA_WITH_SHA256 = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
    public const string ECDSA_WITH_SHA512 = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04";
    public const string ID_EC_PUBLIC_KEY = "\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";

    /**
     * @return array{string, string, string} the tbsCertificate, the signatureAlgorithm and the content of the
     *                                       signature BIT STRING, its unused-bits octet first, all as DER
     */
    public static function split(string $der): array
    {
        $certificate = ASN1::map(ASN1::decodeBER($der), Certificate::MAP);

        if (!$certificate instanceof Constructed) {
            throw new RuntimeException('The bytes are not a certificate.');
        }

        $tbsCertificate = $certificate['tbsCertificate'];
        $algorithm = $certificate['signatureAlgorithm'];
        $signature = $certificate['signature'];

        if (!$tbsCertificate instanceof Constructed || !$algorithm instanceof Constructed || !$signature instanceof BitString) {
            throw new RuntimeException('The certificate does not have the three parts of one.');
        }

        return [$tbsCertificate->getEncoded(), $algorithm->getEncoded(), $signature->value];
    }

    public static function join(string $tbsCertificate, string $algorithm, string $bitStringContent): string
    {
        return self::encoded("\x30", $tbsCertificate . $algorithm . self::encoded("\x03", $bitStringContent));
    }

    /**
     * The certificate with its tbsCertificate signed by the key, labelled with this signatureAlgorithm.
     */
    public static function signed(string $tbsCertificate, string $algorithm, PrivateKey $key): string
    {
        $signature = $key->sign($tbsCertificate);

        if (!is_string($signature)) {
            throw new RuntimeException('The key did not return a signature.');
        }

        return self::join($tbsCertificate, $algorithm, "\x00" . $signature);
    }

    /**
     * The signature AlgorithmIdentifier inside the tbsCertificate, as DER.
     */
    public static function signedAlgorithm(string $tbsCertificate): string
    {
        $algorithm = self::mappedTbsCertificate($tbsCertificate)['signature'];

        if (!$algorithm instanceof Constructed) {
            throw new RuntimeException('The tbsCertificate has no signature AlgorithmIdentifier.');
        }

        return $algorithm->getEncoded();
    }

    /**
     * The tbsCertificate with another signature AlgorithmIdentifier inside it.
     */
    public static function withSignedAlgorithm(string $tbsCertificate, string $algorithm): string
    {
        $signed = self::signedAlgorithm($tbsCertificate);
        $content = self::mappedTbsCertificate($tbsCertificate)->getEncodedWithoutHeader();
        $offset = mb_strpos($content, $signed, 0, '8bit');

        if ($offset === false) {
            throw new RuntimeException('The signature AlgorithmIdentifier is not in the tbsCertificate.');
        }

        return self::encoded("\x30", mb_substr($content, 0, $offset, '8bit') . $algorithm . mb_substr($content, $offset + mb_strlen($signed, '8bit'), null, '8bit'));
    }

    public static function encoded(string $tag, string $content): string
    {
        return $tag . ASN1::encodeLength(mb_strlen($content, '8bit')) . $content;
    }

    private static function mappedTbsCertificate(string $tbsCertificate): Constructed
    {
        $mapped = ASN1::map(ASN1::decodeBER($tbsCertificate), TBSCertificate::MAP);

        if (!$mapped instanceof Constructed) {
            throw new RuntimeException('The bytes are not a tbsCertificate.');
        }

        return $mapped;
    }
}
