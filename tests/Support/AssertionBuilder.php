<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\TextStringObject;
use Oire\AppAttest\Value\AppIdentity;
use Oire\AppAttest\Value\BundleId;
use Oire\AppAttest\Value\TeamId;
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
 * Makes assertions the way a device does: signs the nonce SHA-256(authenticatorData ‖ SHA-256(clientData)) with
 * ECDSA P-256 over SHA-256 and CBOR-encodes {signature, authenticatorData}. Test code only, never shipped.
 */
final class AssertionBuilder
{
    private const int FLAGS = 0x40;
    private AppIdentity $app;
    private int $counter = 1;

    /**
     * @psalm-capabilities read-props
     */
    private function __construct(private readonly EcKey $key)
    {
        $this->app = new AppIdentity(new TeamId('ABCDE12345'), new BundleId('com.example.app'));
    }

    /**
     * A builder with a freshly generated key.
     *
     * @psalm-pure
     */
    public static function create(): self
    {
        return new self(EcKey::generate());
    }

    /**
     * The public key to verify this builder's assertions with.
     *
     * @psalm-capabilities read-props
     */
    public function publicKeyPem(): string
    {
        return $this->key->publicKeyPem;
    }

    public function withApp(AppIdentity $app): self
    {
        $builder = clone $this;
        $builder->app = $app;

        return $builder;
    }

    public function withCounter(int $counter): self
    {
        $builder = clone $this;
        $builder->counter = $counter;

        return $builder;
    }

    /**
     * The assertion object for this client data.
     */
    public function build(string $clientData): string
    {
        $authenticatorData = $this->app->rpIdHash() . chr(self::FLAGS) . pack('N', $this->counter);

        $nonce = hash('sha256', $authenticatorData . hash('sha256', $clientData, true), true);

        if (!openssl_sign($nonce, $signature, $this->key->privateKeyPem, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Cannot sign the test assertion.');
        }

        return (string) MapObject::create()
            ->add(TextStringObject::create('signature'), ByteStringObject::create($signature))
            ->add(TextStringObject::create('authenticatorData'), ByteStringObject::create($authenticatorData));
    }
}
