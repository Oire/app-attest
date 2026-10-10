<?php

declare(strict_types=1);

namespace Oire\AppAttest\Internal;

use DateTimeImmutable;
use DateTimeZone;

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
 * An X.509 certificate taken apart by the library's own DER reader: the parts the chain checks read, each as
 * the bytes the certificate holds. Every structure it reads is checked as DER and in RFC 5280's layout, so a
 * certificate decodes to the same parts, or fails, whatever any ASN.1 parser of the process is set to. It must
 * be a v3 certificate, its signature must declare no unused bits, and an extension's critical flag, when
 * present, must be TRUE, since DER leaves out a DEFAULT value. Names and the SubjectPublicKeyInfo are checked
 * only as SEQUENCEs, and a GeneralizedTime is accepted for any year.
 *
 * @internal
 *
 * @psalm-immutable
 */
final readonly class Certificate
{
    private const int VERSION_TAG = 0xA0;
    private const string V3 = "\x02\x01\x02";
    private const string NO_UNUSED_BITS = "\x00";
    private const int ISSUER_UNIQUE_ID_TAG = 0x81;
    private const int SUBJECT_UNIQUE_ID_TAG = 0x82;
    private const int EXTENSIONS_TAG = 0xA3;
    private const int CENTURY_PIVOT = 50;

    /**
     * @param string                            $tbsCertificate       the signed part, as DER
     * @param string                            $signedAlgorithm      the signature AlgorithmIdentifier inside tbsCertificate, as DER
     * @param string                            $signatureAlgorithm   the signatureAlgorithm after tbsCertificate, as DER
     * @param string                            $signature            the signature BIT STRING's bits
     * @param string                            $serialNumber         the serialNumber INTEGER's content
     * @param string                            $issuer               the issuer Name, as DER
     * @param string                            $subject              the subject Name, as DER
     * @param string                            $subjectPublicKeyInfo as DER
     * @param list<array{string, bool, string}> $extensions           each extension's OBJECT IDENTIFIER content, critical flag and value
     *
     * @psalm-pure
     */
    private function __construct(
        public string $tbsCertificate,
        public string $signedAlgorithm,
        public string $signatureAlgorithm,
        public string $signature,
        public string $serialNumber,
        public string $issuer,
        public DateTimeImmutable $notBefore,
        public DateTimeImmutable $notAfter,
        public string $subject,
        public string $subjectPublicKeyInfo,
        private array $extensions,
    ) {}

    /**
     * The certificate, or null unless the bytes are exactly one.
     */
    public static function tryParse(string $der): ?self
    {
        $parts = Der::tryOne($der)?->children(Der::SEQUENCE) ?? [];

        if (count($parts) !== 3 || !isset($parts[0], $parts[1], $parts[2])) {
            return null;
        }

        [$tbsCertificate, $signatureAlgorithm, $signature] = $parts;
        $fields = $tbsCertificate->children(Der::SEQUENCE);

        if (
            $fields === null
            || $signatureAlgorithm->tag !== Der::SEQUENCE
            || $signature->tag !== Der::BIT_STRING
            || mb_substr($signature->content, 0, 1, '8bit') !== self::NO_UNUSED_BITS
        ) {
            return null;
        }

        $version = Der::hasTag($fields[0] ?? null, self::VERSION_TAG) ? array_shift($fields)?->children(self::VERSION_TAG) ?? [] : [];

        if (count($version) !== 1 || ($version[0] ?? null)?->encoded !== self::V3) {
            return null;
        }

        $serialNumber = array_shift($fields);
        $signedAlgorithm = array_shift($fields);
        $issuer = array_shift($fields);
        $validity = array_shift($fields)?->children(Der::SEQUENCE) ?? [];
        $subject = array_shift($fields);
        $subjectPublicKeyInfo = array_shift($fields);

        if (Der::isBitString($fields[0] ?? null, self::ISSUER_UNIQUE_ID_TAG)) {
            array_shift($fields);
        }

        if (Der::isBitString($fields[0] ?? null, self::SUBJECT_UNIQUE_ID_TAG)) {
            array_shift($fields);
        }

        $extensions = [];
        $extensionsField = $fields[0] ?? null;

        if (Der::hasTag($extensionsField, self::EXTENSIONS_TAG)) {
            $extensions = self::tryExtensions($extensionsField);
            array_shift($fields);
        }

        $notBefore = count($validity) === 2 ? self::timeOf($validity[0] ?? null) : null;
        $notAfter = count($validity) === 2 ? self::timeOf($validity[1] ?? null) : null;

        if (
            $fields !== []
            || !Der::isInteger($serialNumber)
            || !Der::hasTag($signedAlgorithm, Der::SEQUENCE)
            || !Der::hasTag($issuer, Der::SEQUENCE)
            || $notBefore === null
            || $notAfter === null
            || !Der::hasTag($subject, Der::SEQUENCE)
            || !Der::hasTag($subjectPublicKeyInfo, Der::SEQUENCE)
            || $extensions === null
        ) {
            return null;
        }

        return new self(
            $tbsCertificate->encoded,
            $signedAlgorithm->encoded,
            $signatureAlgorithm->encoded,
            mb_substr($signature->content, 1, null, '8bit'),
            $serialNumber->content,
            $issuer->encoded,
            $notBefore,
            $notAfter,
            $subject->encoded,
            $subjectPublicKeyInfo->encoded,
            $extensions,
        );
    }

    /**
     * The value of every extension with this OBJECT IDENTIFIER, given as its content octets.
     *
     * @return list<string>
     *
     * @psalm-capabilities read-props
     */
    public function extensionValues(string $objectIdentifier): array
    {
        $values = [];

        foreach ($this->extensions as [$id, , $value]) {
            if ($id === $objectIdentifier) {
                $values[] = $value;
            }
        }

        return $values;
    }

    /**
     * The OBJECT IDENTIFIER, given as its content octets, of every extension marked critical.
     *
     * @return list<string>
     *
     * @psalm-capabilities read-props
     */
    public function criticalExtensionIdentifiers(): array
    {
        $identifiers = [];

        foreach ($this->extensions as [$id, $critical]) {
            if ($critical) {
                $identifiers[] = $id;
            }
        }

        return $identifiers;
    }

    /**
     * Extensions ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT
     * FALSE, extnValue OCTET STRING }, inside the explicit [3] tag.
     *
     * @return ?list<array{string, bool, string}>
     *
     * @psalm-pure
     */
    private static function tryExtensions(DerElement $explicit): ?array
    {
        $wrapped = $explicit->children(self::EXTENSIONS_TAG);
        $list = $wrapped !== null && count($wrapped) === 1 ? ($wrapped[0] ?? null)?->children(Der::SEQUENCE) : null;

        if ($list === null || $list === []) {
            return null;
        }

        $extensions = [];

        foreach ($list as $extension) {
            $fields = $extension->children(Der::SEQUENCE) ?? [];
            $id = array_shift($fields);
            $value = array_pop($fields);
            $critical = array_pop($fields);

            if ($fields !== [] || !Der::isObjectIdentifier($id) || !Der::hasTag($value, Der::OCTET_STRING) || ($critical !== null && !Der::isTrue($critical))) {
                return null;
            }

            $extensions[] = [$id->content, $critical !== null, $value->content];
        }

        return $extensions;
    }

    /**
     * A UTCTime or GeneralizedTime in the forms RFC 5280 requires: UTC, with seconds, without fractions.
     */
    private static function timeOf(?DerElement $time): ?DateTimeImmutable
    {
        $digits = $time === null ? null : match ($time->tag) {
            Der::UTC_TIME => self::digitsBeforeZ($time->content, 12),
            Der::GENERALIZED_TIME => self::digitsBeforeZ($time->content, 14),
            default => null,
        };

        if ($digits !== null && $time?->tag === Der::UTC_TIME) {
            $digits = ((int) mb_substr($digits, 0, 2, '8bit') >= self::CENTURY_PIVOT ? '19' : '20') . $digits;
        }

        if ($digits === null) {
            return null;
        }

        $parsed = DateTimeImmutable::createFromFormat('!YmdHis', $digits, new DateTimeZone('UTC'));

        return $parsed !== false && $parsed->format('YmdHis') === $digits ? $parsed : null;
    }

    /**
     * @psalm-pure
     */
    private static function digitsBeforeZ(string $content, int $count): ?string
    {
        return preg_match('/^[0-9]{' . $count . '}Z$/D', $content) === 1 ? mb_substr($content, 0, $count, '8bit') : null;
    }
}
