<?php

declare(strict_types=1);

namespace Oire\AppAttest;

use InvalidArgumentException;
use LogicException;
use Oire\AppAttest\Internal\Der;
use Oire\AppAttest\Internal\ErrorGuard;
use Oire\AppAttest\Internal\Pem;
use phpseclib3\File\X509;
use Throwable;

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
 * The root certificate an attestation's chain must lead to.
 *
 * @psalm-api
 */
final readonly class TrustAnchor
{
    /**
     * SHA-256 of the DER certificate in resources/Apple_App_Attestation_Root_CA.pem, fetched on 2026-10-09
     * from https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem and cross-checked
     * against the roots bundled in veehaitch/devicecheck-appattest and takimoto3/app-attest.
     */
    public const string APPLE_ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932';
    private const string APPLE_ROOT_PATH = __DIR__ . '/../resources/Apple_App_Attestation_Root_CA.pem';

    /**
     * @psalm-capabilities read-props
     */
    private function __construct(public string $pem) {}

    /**
     * Apple's App Attest root, bundled with the library and checked against its pinned fingerprint.
     *
     * @throws LogicException if the bundled file is missing or is not the pinned certificate
     */
    public static function apple(): self
    {
        $pem = is_readable(self::APPLE_ROOT_PATH) ? file_get_contents(self::APPLE_ROOT_PATH) : false;

        if ($pem === false) {
            throw new LogicException('The bundled Apple App Attest root certificate cannot be read.');
        }

        return self::fromPinnedPem($pem, self::APPLE_ROOT_SHA256);
    }

    /**
     * Any root certificate, such as the one a test signs its own chains with.
     *
     * @throws InvalidArgumentException if the PEM does not hold exactly one parsable certificate
     */
    public static function fromPem(string $pem): self
    {
        $der = Pem::tryDecode($pem, Pem::CERTIFICATE);

        if ($der === null || !Der::isOneSequence($der) || !self::isParsable($der)) {
            throw new InvalidArgumentException('The trust anchor must be exactly one PEM-encoded X.509 certificate.');
        }

        return new self($pem);
    }

    /**
     * @internal
     *
     * @param string $sha256Fingerprint lowercase hexadecimal SHA-256 of the DER certificate
     *
     * @throws LogicException if the PEM is not the certificate with this fingerprint
     *
     * @psalm-pure
     */
    public static function fromPinnedPem(string $pem, string $sha256Fingerprint): self
    {
        $der = Pem::tryDecode($pem, Pem::CERTIFICATE);

        if ($der === null || !hash_equals($sha256Fingerprint, hash('sha256', $der))) {
            throw new LogicException('The root certificate does not match its pinned SHA-256 fingerprint.');
        }

        return new self($pem);
    }

    private static function isParsable(string $der): bool
    {
        try {
            return ErrorGuard::call(static fn(): bool => is_array((new X509())->loadX509($der, X509::FORMAT_DER)));
        } catch (Throwable) {
            return false;
        }
    }
}
