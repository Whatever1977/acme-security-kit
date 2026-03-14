# Test Suite

Comprehensive PHPUnit test suite for `acme/security-kit`.

---

## Running Tests

```bash
# All tests
vendor/bin/phpunit

# Single module
vendor/bin/phpunit tests/Audit
vendor/bin/phpunit tests/Authz
vendor/bin/phpunit tests/Crypto
vendor/bin/phpunit tests/Csrf
vendor/bin/phpunit tests/Jwt
vendor/bin/phpunit tests/OAuth2
vendor/bin/phpunit tests/Password
vendor/bin/phpunit tests/Totp
vendor/bin/phpunit tests/UrlSigner

# Verbose output (shows each test name)
vendor/bin/phpunit --testdox

# With coverage (requires Xdebug or PCOV)
vendor/bin/phpunit --coverage-html coverage/html
vendor/bin/phpunit --coverage-text

# Run a specific test class
vendor/bin/phpunit tests/Authz/AuthzTest.php

# Run a specific test method
vendor/bin/phpunit --filter testWildcardPermissionGrantsEverything
```

---

## Test Coverage Map

| Module | Test File | Tests |
|--------|-----------|-------|
| Audit | `Audit/AuditTest.php` | SecurityEvent fields, NullAuditor no-op, PsrLoggerAuditor severity mapping, context embedding |
| Authz | `Authz/AuthzTest.php` | Decision factory, direct permissions, role inheritance, wildcard, multi-role, ABAC checks, circular inheritance guard |
| Crypto | `Crypto/CryptoTest.php` | HashEquals constant-time, Key expiry, KeySet get/all, InMemoryKeyProvider |
| CSRF | `Csrf/CsrfTest.php` | Token issuance uniqueness, validate happy path, wrong session, wrong context, tamper, expiry, cross-context replay, secret isolation |
| JWT | `Jwt/JwtTest.php` | Mint format, unique JTI, parse & validate, claims, expiry, tamper, wrong key, key rotation |
| OAuth2 | `OAuth2/OAuth2Test.php` | PKCE challenge computation, S256 validate, plain rejected, unknown method, token TTL policy |
| Password | `Password/PasswordTest.php` | Argon2id hash format, verify, unique salts, needsRehash, policy violations, PolicyAwareHasher, WeakPasswordException |
| TOTP | `Totp/TotpTest.php` | Secret generation (Base32, uniqueness), provisioning URI, currentCode verify, wrong code, 8-digit mode |
| UrlSigner | `UrlSigner/UrlSignerTest.php` | Signed URL structure, verify, tampered path/sig/expiry, expired URL, key rotation, canonical query ordering |

---

## Test Design Principles

**Use `NullAuditor` everywhere** — inject `NullAuditor` when the class under
test accepts an `Auditor`. This prevents test output pollution and removes the
audit subsystem as a potential failure cause.

**No mocking of security primitives** — `SecureRandom` and `HashEquals` are
used as real implementations in tests. Mocking them would defeat the purpose
of testing the security properties.

**Deterministic time** — where tests depend on TTL or expiry, use explicit
`DateTimeImmutable` values rather than `new \DateTimeImmutable()` inline.
For already-expired scenarios, use `new \DateTimeImmutable('-1 second')`.

**Test the negative path** — every security feature has tests for failure:
wrong inputs, tampered values, expired tokens, cross-context replays.

**Mutation testing** — run `vendor/bin/infection` to verify test quality.
Target: minMsi ≥ 70%, minCoveredMsi ≥ 80%.

---

## Adding Tests for a New Module

1. Create `tests/YourModule/YourModuleTest.php`
2. Use `final class YourModuleTest extends TestCase`
3. Group tests with comment blocks: `// ─── Feature name ────`
4. Cover: happy path, all failure paths, edge cases (empty strings, nulls, expiry boundaries)
5. Run `vendor/bin/phpunit tests/YourModule` before opening a PR
