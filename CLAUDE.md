# CLAUDE.md - Oire App Attest

## Project Overview

`oire/app-attest` verifies Apple App Attest attestations and assertions in PHP. It verifies and nothing
else: no state, no key storage, no challenges, no network, no logging. Namespace `Oire\AppAttest\`
(PSR-4 mapped to `src/`); tests `Oire\AppAttest\Tests\`. The implementation plan is
`docs/plans/001-app-attest-library.md`.

## Quick Reference

```bash
composer install
composer test    # phpunit
composer lint    # php-cs-fixer fix --dry-run --diff, then psalm --no-cache
```

Without a local PHP: `docker compose run --rm php composer test` (PHP 8.5 CLI with gmp).

## Conventions

- PHP 8.3+, extensions gmp, mbstring, openssl, sodium. `declare(strict_types=1);` everywhere.
- Final classes (abstract exception base excepted), readonly value objects.
- Binary data is sliced and measured with `mb_substr`/`mb_strlen` and the `'8bit'` encoding: the code
  style's `mb_str_functions` rule rewrites `substr`/`strlen`, which would corrupt byte offsets.
- Every class is imported with `use` and written unqualified; native functions are called unqualified.
- LF line endings, American English.
