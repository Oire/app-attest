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
 * PEM armor for the tests, written independently of the library's own.
 *
 * @psalm-pure
 */
final class Pem
{
    public const string CERTIFICATE = 'CERTIFICATE';
    public const string PUBLIC_KEY = 'PUBLIC KEY';

    /**
     * @psalm-pure
     */
    public static function fromDer(string $der, string $label): string
    {
        return '-----BEGIN ' . $label . "-----\n" . chunk_split(base64_encode($der), 64, "\n") . '-----END ' . $label . "-----\n";
    }

    /**
     * The DER of the only block in the PEM, whatever its label.
     *
     * @psalm-pure
     */
    public static function toDer(string $pem): string
    {
        $der = base64_decode(preg_replace('/-----[A-Z ]+-----|\\s+/', '', $pem) ?? '', true);

        if ($der === false || $der === '') {
            throw new RuntimeException('The text is not a PEM block.');
        }

        return $der;
    }

    /**
     * The public key of a key pair OpenSSL generates with these options, such as an RSA or a P-384 key.
     *
     * @param array<string, int|string> $options
     *
     * @psalm-pure
     */
    public static function generatedPublicKey(array $options): string
    {
        $key = openssl_pkey_new($options);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        $pem = is_array($details) ? $details['key'] ?? null : null;

        if (!is_string($pem)) {
            throw new RuntimeException('Cannot generate the test key.');
        }

        return $pem;
    }
}
