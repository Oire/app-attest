<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests\Support;

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
 * Where a golden vector was taken from.
 *
 * @psalm-immutable
 */
final readonly class VectorOrigin
{
    /**
     * @param string $copyPath    absolute path of the byte-for-byte copy of the reference file
     * @param string $licensePath absolute path of the reference's license beside the vectors
     *
     * @psalm-capabilities read-props
     */
    public function __construct(
        public string $repository,
        public string $commit,
        public string $path,
        public string $copyPath,
        public string $licensePath,
    ) {}
}
