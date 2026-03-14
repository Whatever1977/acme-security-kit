# acme/security-kit


<img src = "https://github.com/PanagiotisKotsorgios/acme-php/blob/main/assets/logo-01.png">

> A modular PHP security toolkit with PSR compatibility, strong typing, immutable value objects, and enterprise-grade defaults.

[![PHP](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg)](https://phpstan.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/acme/security-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/acme/security-kit/actions)

---

## Modules

| Module | Description |
|--------|-------------|
| **Crypto** | Secure randomness, constant-time comparison, key sets + JWKS export |
| **CSRF** | Stateless HMAC tokens with per-form context, TTL, and rotation |
| **UrlSigner** | HMAC-SHA256 signed URLs with key rotation and canonical query ordering |
| **JWT** | RS256/ES256/HS256 token issuance and validation with strict claim checking |
| **OAuth2** | Storage interfaces, PKCE validation, token TTL policies, refresh rotation |
| **Password** | Argon2id hashing, policy enforcement, rehash-on-login helper |
| **TOTP** | RFC 6238 compliant, Base32, configurable step/digits/algorithm |
| **Authz** | RBAC with role inheritance + ABAC-lite attribute callbacks |
| **Audit** | PSR-3 structured security event logging |

---

## Requirements

- PHP 8.2+
- Extensions: `openssl`, `mbstring`

---

## Installation

```bash
composer require acme/security-kit
```

---

## Quick Start

### CSRF Protection

```php
use Acme\SecurityKit\Crypto\{HashEquals, SecureRandom};
use Acme\SecurityKit\Csrf\{HmacCsrfManager, CsrfPolicy};

$manager = new HmacCsrfManager(
    secret: 'your-32-byte-secret-here!!!!!!!!!',
    random: new SecureRandom(),
    constantTime: new HashEquals(),
    policy: new CsrfPolicy(ttlSeconds: 3600),
);

$token = $manager->issue($sessionId, 'transfer_funds');

if (!$manager->validate($sessionId, 'transfer_funds', $submitted)) {
    throw new \RuntimeException('CSRF validation failed');
}
```

### Signed URLs

```php
use Acme\SecurityKit\Crypto\{InMemoryKeyProvider, Key, HashEquals};
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;

$key    = new Key('k1', 'HS256', 'your-signing-secret', isSymmetric: true);
$signer = new HmacUrlSigner(new InMemoryKeyProvider($key), new HashEquals());

$signed = $signer->sign('https://app.example.com/download/file.pdf', new \DateTimeImmutable('+1 hour'));

if (!$signer->verify($request->getUri())) {
    // 403 Forbidden
}
```

### JWT

```php
use Acme\SecurityKit\Jwt\{FirebaseJwtManager, JwtConfig};

$manager = new FirebaseJwtManager(
    config: new JwtConfig(issuer: 'https://auth.example.com', audience: 'api'),
    keyProvider: $keyProvider,
    random: new SecureRandom(),
);

$jwt      = $manager->mint(['sub' => 'user-42', 'roles' => ['editor']], new \DateTimeImmutable('+1 hour'));
$verified = $manager->parseAndValidate($jwt);

echo $verified->claim('sub'); // "user-42"
```

### Password Hashing

```php
use Acme\SecurityKit\Password\{Argon2idHasher, PolicyAwareHasher, PasswordPolicy};

$hasher = new PolicyAwareHasher(new Argon2idHasher(), new PasswordPolicy(minLength: 12));

$hash = $hasher->hash($plaintext);

if ($hasher->needsRehash($hash)) {
    $hash = $hasher->hash($plaintext); // upgrade on next login
}
```

### TOTP (Two-Factor Auth)

```php
use Acme\SecurityKit\Totp\{RfcTotp, TotpConfig};

$totp   = new RfcTotp(new SecureRandom(), new TotpConfig(digits: 6, step: 30));
$secret = $totp->generateSecret();
$uri    = $totp->provisioningUri('user@example.com', 'MyApp', $secret);

if (!$totp->verify($secret, $submittedCode)) {
    // 401 Unauthorized
}
```

### RBAC Authorization

```php
use Acme\SecurityKit\Authz\{RbacAuthorizer, Role, InMemoryRoleRepository, InMemoryAssignmentRepository};

$roles   = new InMemoryRoleRepository();
$assigns = new InMemoryAssignmentRepository();

$roles->add(new Role('viewer', permissions: ['read:posts']));
$roles->add(new Role('editor', parents: ['viewer'], permissions: ['edit:posts']));
$assigns->assign('user-42', ['editor']);

$authz    = new RbacAuthorizer($roles, $assigns);
$decision = $authz->can('user-42', 'read', 'posts');

if (!$decision->allowed) {
    // 403 Forbidden — $decision->reason explains why
}
```

---

## PSR-15 Middleware

Drop these into any PSR-15-compatible middleware stack (Slim, Mezzio, Laravel Pipeline, etc.):

```php
$app->pipe(new CsrfMiddleware($csrfManager, $responseFactory, $auditor));
$app->pipe(new SignedUrlMiddleware($urlSigner, $responseFactory, $auditor));
```

Full framework integration examples are in [`examples/`](examples/).

---

## Security Guarantees

- All random values use `random_bytes()` (CSPRNG).
- All secret/token comparisons use `hash_equals()` (constant-time).
- Argon2id is the default password hashing algorithm (memory-hard, GPU-resistant).
- JWTs: algorithm is configured server-side in `JwtConfig` — never read from the token header.
- PKCE: only `S256` is accepted; `plain` method is rejected.
- CSRF tokens are scoped to `(sessionId, context)` pairs to prevent cross-form replay.

---

## Non-Goals

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

- TLS / transport security
- Rate limiting / DDoS protection
- Full OAuth2 authorization server (use [`league/oauth2-server`](https://oauth2.thephpleague.com))
- Hardware Security Module (HSM) key management

---

## Development

```bash
composer install
vendor/bin/phpunit                        # tests
vendor/bin/phpstan analyse                # static analysis (level 8)
vendor/bin/php-cs-fixer check --diff      # code style check
vendor/bin/rector process --dry-run       # upgrade suggestions
vendor/bin/infection --min-msi=70         # mutation testing
```

CI runs PHPUnit on PHP 8.2, 8.3, and 8.4, PHPStan at level 8, CS Fixer, and mutation testing on every push to `main`.

---

## Contributing

We welcome pull requests! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

---

## Security

**Do not open a public GitHub issue to report a security vulnerability.**

Please follow the responsible disclosure process in [SECURITY.md](SECURITY.md).

---

## License

MIT. See [LICENSE](LICENSE).

