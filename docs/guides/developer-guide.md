# Developer Guide

This document covers everything needed to contribute to or extend `acme/security-kit`.

---

## Table of Contents

1. [Local Setup](#1-local-setup)
2. [Project Structure](#2-project-structure)
3. [Coding Standards](#3-coding-standards)
4. [Writing Tests](#4-writing-tests)
5. [Running the Full Quality Pipeline](#5-running-the-full-quality-pipeline)
6. [Adding a New Module](#6-adding-a-new-module)
7. [Extending Key Management](#7-extending-key-management)
8. [Implementing Custom Auditors](#8-implementing-custom-auditors)
9. [Debugging & Tracing](#9-debugging--tracing)
10. [Release Process](#10-release-process)

---

## 1. Local Setup

### Requirements

| Tool | Minimum version |
|------|----------------|
| PHP | 8.2 |
| Composer | 2.x |
| Xdebug | 3.x (for coverage) |
| Extensions | `openssl`, `mbstring` |

### Clone and install

```bash
git clone https://github.com/acme/security-kit.git
cd security-kit
composer install
```

### Verify the setup

```bash
vendor/bin/phpunit --testdox        # all tests green
vendor/bin/phpstan analyse          # zero errors at level 8
vendor/bin/php-cs-fixer check       # zero style violations
```

---

## 2. Project Structure

```
acme/security-kit/
├── src/
│   ├── Audit/           # Auditor interface, SecurityEvent, implementations
│   ├── Authz/           # RBAC: Authorizer, Role, Repositories, RbacAuthorizer
│   ├── Crypto/          # Keys, KeySet, KeyProvider, SecureRandom, HashEquals
│   ├── Csrf/            # HmacCsrfManager, CsrfPolicy, CsrfToken
│   ├── Jwt/             # FirebaseJwtManager, JwtConfig, VerifiedToken, JwtException
│   ├── OAuth2/          # PkceValidator, TokenTtlPolicy, DTOs, Repository interfaces
│   ├── Password/        # Argon2idHasher, PasswordPolicy, PolicyAwareHasher
│   ├── Support/         # PSR-15 CsrfMiddleware, SignedUrlMiddleware
│   ├── Totp/            # RfcTotp, TotpConfig
│   └── UrlSigner/       # HmacUrlSigner, UrlSignerPolicy, SignedUrl
├── tests/
│   ├── Audit/
│   ├── Authz/
│   ├── Crypto/
│   ├── Csrf/
│   ├── Jwt/
│   ├── OAuth2/
│   ├── Password/
│   ├── Totp/
│   └── UrlSigner/
├── examples/
│   ├── laravel/         # Laravel ServiceProvider
│   └── psr15-middleware/ # Plain PSR-15 stack example
├── diagrams/            # PlantUML (.puml) + PNG diagram exports
├── docs/
│   ├── decisions/       # Architecture Decision Records (ADRs)
│   ├── guides/          # Usage guide, dev guide, security guide
│   └── threat-model.md
├── phpunit.xml
├── phpstan.neon
├── infection.json
└── rector.php
```

---

## 3. Coding Standards

The project enforces PHP-CS-Fixer with `@PER-CS2.0` rules (a superset of PSR-12):

```bash
vendor/bin/php-cs-fixer check       # show violations
vendor/bin/php-cs-fixer fix         # auto-fix
```

Key style rules:

- `declare(strict_types=1)` at the top of every file
- `final` on all concrete classes unless inheritance is intentional
- `readonly` constructor promotion for value objects
- No magic `__get` / `__set`
- All methods have return type declarations
- `@var` docblocks only where PHPStan cannot infer the type

---

## 4. Writing Tests

### Test class conventions

```php
<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Csrf;

use PHPUnit\Framework\TestCase;

final class HmacCsrfManagerTest extends TestCase
{
    private HmacCsrfManager $manager;

    protected function setUp(): void
    {
        $this->manager = new HmacCsrfManager(
            secret: str_repeat('a', 32),
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: 3600),
        );
    }

    public function testIssuedTokenValidatesSuccessfully(): void
    {
        $token = $this->manager->issue('session-1', 'form-a');
        self::assertTrue($this->manager->validate('session-1', 'form-a', $token->value));
    }
}
```

### NullAuditor in tests

Always inject `NullAuditor` when the class under test accepts an `Auditor`:

```php
$authorizer = new RbacAuthorizer($roles, $assignments, new NullAuditor());
```

### Time-sensitive tests

Use `DateTimeImmutable` with explicit timestamps to avoid flaky TTL tests:

```php
// Simulate an expired token
$clock = new \DateTimeImmutable('2020-01-01T00:00:00Z');
$expiredToken = $manager->issue('sess', 'ctx', issuedAt: $clock);
// advance time by 2h
$laterClock = $clock->modify('+2 hours');
self::assertFalse($manager->validate('sess', 'ctx', $expiredToken->value, now: $laterClock));
```

---

## 5. Running the Full Quality Pipeline

```bash
# 1. Unit tests
vendor/bin/phpunit

# 2. Static analysis
vendor/bin/phpstan analyse

# 3. Code style
vendor/bin/php-cs-fixer check

# 4. Automated upgrade suggestions
vendor/bin/rector process --dry-run

# 5. Mutation testing (slow — run before PR)
vendor/bin/infection

# 6. Code coverage (requires Xdebug)
vendor/bin/phpunit --coverage-html coverage/html
open coverage/html/index.html
```

The CI pipeline (`.github/workflows/ci.yml`) runs steps 1–4 on every push.

---

## 6. Adding a New Module

1. **Create the namespace** under `src/YourModule/`.
2. **Define interfaces first.** Any class that has multiple implementations or
   needs to be mocked should be an interface.
3. **Depend on `Crypto` primitives** — never call `random_bytes()` directly;
   inject `SecureRandom`. Never compare secrets with `===`; inject `ConstantTime`.
4. **Accept `?Auditor`** for any security-significant failure path. Record events
   using the standard event type string conventions (e.g., `yourmodule.event_name`).
5. **Write tests** in `tests/YourModule/` mirroring the src structure.
6. **Add an ADR** in `docs/decisions/` if the module introduces a non-obvious
   design decision.
7. **Update `diagrams/`** — add or update the relevant PlantUML diagram.

---

## 7. Extending Key Management

`InMemoryKeyProvider` is suitable for single-server deployments. For
production multi-server setups, implement `KeyProvider`:

```php
use Acme\SecurityKit\Crypto\KeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\KeySet;

final class AwsSecretsManagerKeyProvider implements KeyProvider
{
    public function __construct(
        private readonly SecretsManagerClient $client,
        private readonly string $secretArn,
    ) {}

    public function current(): KeySet
    {
        $secret = $this->client->getSecretValue(['SecretId' => $this->secretArn]);
        $data   = json_decode($secret['SecretString'], true);

        return new KeySet(
            new Key($data['kid'], $data['algorithm'], $data['material'], isSymmetric: true),
        );
    }

    public function byKid(string $kid): ?Key
    {
        // Load all versions and find the matching kid
        // This supports key rotation — old tokens still verify
        foreach ($this->loadAllVersions() as $key) {
            if ($key->kid === $kid) {
                return $key;
            }
        }
        return null;
    }
}
```

---

## 8. Implementing Custom Auditors

```php
use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\SecurityEvent;

final class DatadogAuditor implements Auditor
{
    public function __construct(private readonly DatadogClient $dd) {}

    public function record(SecurityEvent $event): void
    {
        $this->dd->event(
            title: $event->type,
            text: json_encode($event->context),
            alertType: match($event->severity) {
                'critical', 'error' => 'error',
                'warning' => 'warning',
                default => 'info',
            },
            tags: ["severity:{$event->severity}", "channel:security"],
        );
    }
}
```

---

## 9. Debugging & Tracing

To trace security events during development, use a simple `ClosureAuditor`:

```php
$auditor = new class implements Auditor {
    public function record(SecurityEvent $event): void {
        fwrite(STDERR, sprintf(
            "[%s] %s %s\n",
            $event->severity,
            $event->type,
            json_encode($event->context)
        ));
    }
};
```

For JWT debugging, decode a token's payload without verification:

```php
$parts   = explode('.', $jwt);
$payload = json_decode(base64_decode(str_pad(strtr($parts[1], '-_', '+/'), strlen($parts[1]) % 4, '=', STR_PAD_RIGHT)), true);
var_dump($payload);
```

---

## 10. Release Process

1. Update `CHANGELOG.md` with the new version entry.
2. Bump version in `composer.json`.
3. Ensure all quality checks pass (see §5).
4. Run mutation testing: `vendor/bin/infection` — confirm minMsi ≥ 70%.
5. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. GitHub Actions publishes to Packagist automatically via the webhook.

Semantic versioning rules:
- **Patch** — bug fixes, no interface changes.
- **Minor** — new features, backward-compatible.
- **Major** — breaking changes to public interfaces or security guarantees.
