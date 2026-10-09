<?php

declare(strict_types=1);

use Oire\Helpers\CsFixerRules;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests'])
    ->append([__FILE__]);

return CsFixerRules::style($finder);
