<?php
use Oire\Helpers\CsFixerRules;

$finder = PhpCsFixer\Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests']);

return CsFixerRules::style($finder);
