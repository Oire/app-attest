<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use Closure;
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
    public const string BASIC_CONSTRAINTS = "\x06\x03\x55\x1d\x13";
    public const string KEY_USAGE = "\x06\x03\x55\x1d\x0f";
    public const string SUBJECT_KEY_IDENTIFIER = "\x06\x03\x55\x1d\x0e";
    public const string AUTHORITY_KEY_IDENTIFIER = "\x06\x03\x55\x1d\x23";
    public const string NONCE = "\x06\x09\x2a\x86\x48\x86\xf7\x63\x64\x08\x02";
    private const string EXTENSIONS_TAG = "\xa3";

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

    /**
     * The elements the bytes hold one after another, each as DER; definite lengths only.
     *
     * @return list<string>
     *
     * @psalm-pure
     */
    public static function elements(string $bytes): array
    {
        $elements = [];
        $offset = 0;
        $length = mb_strlen($bytes, '8bit');

        while ($offset < $length) {
            $first = ord($bytes[$offset + 1] ?? throw new RuntimeException('The DER is truncated.'));
            $lengthBytes = $first < 0x80 ? 0 : $first & 0x7F;
            $contentLength = $first < 0x80 ? $first : (int) hexdec(bin2hex(mb_substr($bytes, $offset + 2, $lengthBytes, '8bit')));
            $elementLength = 2 + $lengthBytes + $contentLength;

            if ($first === 0x80 || $offset + $elementLength > $length) {
                throw new RuntimeException('The DER is truncated or has an indefinite length.');
            }

            $elements[] = mb_substr($bytes, $offset, $elementLength, '8bit');
            $offset += $elementLength;
        }

        return $elements;
    }

    /**
     * The content of one DER element.
     *
     * @psalm-pure
     */
    public static function content(string $der): string
    {
        $first = ord($der[1] ?? throw new RuntimeException('The DER is truncated.'));

        return mb_substr($der, 2 + ($first < 0x80 ? 0 : $first & 0x7F), null, '8bit');
    }

    /**
     * The tbsCertificate with its fields, each as DER, edited.
     *
     * @param Closure(list<string>): list<string> $edit
     */
    public static function withFields(string $tbsCertificate, Closure $edit): string
    {
        return self::encoded("\x30", implode('', $edit(self::elements(self::content($tbsCertificate)))));
    }

    /**
     * The tbsCertificate with its list of extensions, each Extension as DER, edited.
     *
     * @param Closure(list<string>): list<string> $edit
     */
    public static function withExtensions(string $tbsCertificate, Closure $edit): string
    {
        return self::withFields($tbsCertificate, static function(array $fields) use ($edit): array {
            $extensions = array_pop($fields) ?? '';

            if (mb_substr($extensions, 0, 1, '8bit') !== self::EXTENSIONS_TAG) {
                throw new RuntimeException('The tbsCertificate ends without extensions.');
            }

            return [...$fields, self::encoded(self::EXTENSIONS_TAG, self::encoded("\x30", implode('', $edit(self::elements(self::content(self::content($extensions)))))))];
        });
    }

    /**
     * The tbsCertificate with the value of each extension with this OID replaced, or with one such extension
     * added if it has none.
     *
     * @param string                   $oid   the OBJECT IDENTIFIER as DER
     * @param Closure(?string): string $value the new value from the current one, as DER
     */
    public static function withExtensionValue(string $tbsCertificate, string $oid, Closure $value): string
    {
        return self::withExtensions($tbsCertificate, static function(array $extensions) use ($oid, $value): array {
            $found = false;

            foreach ($extensions as $index => $extension) {
                $fields = self::elements(self::content($extension));

                if (($fields[0] ?? null) === $oid) {
                    $extnValue = array_pop($fields) ?? '';
                    $extensions[$index] = self::encoded("\x30", implode('', $fields) . self::encoded("\x04", $value(self::content($extnValue))));
                    $found = true;
                }
            }

            return $found ? $extensions : [...$extensions, self::extension($oid, $value(null))];
        });
    }

    /**
     * An Extension, not critical, with this OID (DER) and value (DER).
     */
    public static function extension(string $oid, string $value): string
    {
        return self::encoded("\x30", $oid . self::encoded("\x04", $value));
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
