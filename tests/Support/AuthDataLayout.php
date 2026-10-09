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
 * Byte offsets of the authenticator data, restated for the tests independently of the library.
 *
 * @psalm-pure
 */
final class AuthDataLayout
{
    public const int RP_ID_HASH_LENGTH = 32;
    public const int FLAGS_OFFSET = 32;
    public const int COUNTER_OFFSET = 33;
    public const int COUNTER_LENGTH = 4;
    public const int ASSERTION_LENGTH = 37;
    public const int AAGUID_OFFSET = 37;
    public const int AAGUID_LENGTH = 16;
    public const int CREDENTIAL_ID_LENGTH_OFFSET = 53;
    public const int CREDENTIAL_ID_OFFSET = 55;
}
