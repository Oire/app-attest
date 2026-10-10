<?php

declare(strict_types=1);

namespace Oire\AppAttest\Tests;

use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

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
final class RuntimeDependencyTest extends TestCase
{
    private const string SOURCE_DIRECTORY = __DIR__ . '/../src';

    /**
     * phpseclib is a development dependency, so code in src/ that names it would fail where the package is
     * installed without it. Comments may mention it.
     */
    public function testSourceCodeNeverNamesPhpseclib(): void
    {
        $offenders = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::SOURCE_DIRECTORY, FilesystemIterator::SKIP_DOTS));

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
                if (is_array($token) && !in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) && mb_stripos($token[1], 'phpseclib') !== false) {
                    $offenders[] = $file->getPathname() . ':' . $token[2];
                }
            }
        }

        self::assertSame([], $offenders);
    }
}
