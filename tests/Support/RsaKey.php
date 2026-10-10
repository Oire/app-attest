<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PrivateKey;
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
 * A freshly generated 2048-bit RSA key that signs with PKCS #1 v1.5 over SHA-256, as openssl_verify() expects
 * of an RSA key.
 */
final class RsaKey
{
    public static function generate(): PrivateKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new RuntimeException('Cannot generate an RSA key.');
        }

        $rsa = PublicKeyLoader::loadPrivateKey($pem);

        if (!$rsa instanceof PrivateKey) {
            throw new RuntimeException('The generated key is not an RSA key.');
        }

        return $rsa
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha256');
    }
}
