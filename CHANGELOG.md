
# Changelog

All notable changes to `acme/security-kit` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Full PlantUML diagram suite (13 diagrams: architecture, class, sequence, state)
- `docs/guides/developer-guide.md` — contributor and extension guide
- `docs/guides/security-hardening.md` — production hardening recommendations
- `docs/decisions/ADR-003` through `ADR-005` — constant-time comparisons, PSR interfaces, immutable value objects
- Comprehensive test suite with 80+ test cases across all 9 modules
- Standalone all-modules example (`examples/standalone/all-modules.php`)
- Slim 4 integration example (`examples/slim/slim-app.php`)
- Improved PSR-15 middleware example with key rotation demonstration

---

## [1.0.0] — 2024-01-31

### Added
- **Crypto module**: `SecureRandom`, `HashEquals` (`ConstantTime`), `Key`, `KeySet`, `KeyProvider`, `InMemoryKeyProvider`
- **CSRF module**: `HmacCsrfManager`, `CsrfPolicy`, `CsrfToken` — stateless HMAC tokens scoped to `(sessionId, context)`
- **UrlSigner module**: `HmacUrlSigner`, `UrlSignerPolicy`, `SignedUrl` — HMAC-SHA256 signed URLs with TTL and key rotation
- **JWT module**: `FirebaseJwtManager`, `JwtConfig`, `VerifiedToken`, `JwtException` — wraps `firebase/php-jwt` with strict claim validation
- **OAuth2 module**: `PkceValidator`, `TokenTtlPolicy`, `Client` DTO, repository interfaces — PKCE S256 enforcement, refresh token rotation policy
- **Password module**: `Argon2idHasher`, `PasswordPolicy`, `PolicyAwareHasher`, `WeakPasswordException` — Argon2id hashing with policy enforcement and rehash-on-login
- **TOTP module**: `RfcTotp`, `TotpConfig` — RFC 6238 TOTP with Base32, configurable digits/step/window
- **Authz module**: `RbacAuthorizer`, `Role`, `Decision`, `InMemoryRoleRepository`, `InMemoryAssignmentRepository` — RBAC with role inheritance and ABAC-lite attribute callbacks
- **Audit module**: `Auditor`, `SecurityEvent`, `PsrLoggerAuditor`, `NullAuditor` — PSR-3 structured security event logging
- **Support module**: `CsrfMiddleware`, `SignedUrlMiddleware` — PSR-15 plug-and-play middleware
- Laravel `SecurityKitServiceProvider` example
- PSR-15 middleware pipeline example
- Architecture Decision Records: ADR-001 (firebase/php-jwt), ADR-002 (Argon2id default)
- Threat model documentation
- GitHub Actions CI pipeline (PHPUnit, PHPStan level 8, PHP-CS-Fixer, Rector)
- Infection mutation testing configuration (minMsi=70%, minCoveredMsi=80%)

### Security
- All random values use `random_bytes()` (CSPRNG) exclusively
- All secret comparisons use `hash_equals()` (constant time) via `ConstantTime` interface
- JWT algorithm fixed server-side in `JwtConfig` — never read from token header
- PKCE enforces S256 only; `plain` method unconditionally rejected
- Argon2id is the default password hashing algorithm (not bcrypt)
- CSRF tokens scoped to `(sessionId, context)` — cross-form replay impossible
