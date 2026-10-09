# Oire App Attest

Verify Apple App Attest attestations and assertions in PHP: certificate chain, nonce, key id, counter.
Stateless, no I/O.

This library is under development; installation and usage will be documented with the first release.

## Development

```bash
composer install
composer test
composer lint
```

Without a local PHP, the repository's container gives PHP 8.5 with every required extension:
`docker compose run --rm php composer test`.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
