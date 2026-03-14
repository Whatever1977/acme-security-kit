# Security Hardening Guide

This guide describes production hardening recommendations for deployments using `acme/security-kit`.

---

## 1. Secret Management

### Never hardcode secrets

All secrets — CSRF secret, JWT signing key, URL signing key — must come from environment variables or a secrets manager, never from source code.

```php
// Bad
$manager = new HmacCsrfManager(secret: 'hardcoded-secret-bad!!!!!!!!!!', ...);

// Good
$manager = new HmacCsrfManager(secret: (string) getenv('CSRF_SECRET'), ...);
```

### Minimum secret lengths

| Secret | Minimum entropy |
|--------|----------------|
| CSRF secret | 32 bytes (256 bits) |
| URL signing key | 32 bytes (256 bits) |
| JWT HS256 secret | 32 bytes (256 bits) |
| JWT RS256 private key | 2048-bit RSA (recommended: 4096) |
| JWT ES256 private key | P-256 curve |

Generate safe secrets:

```bash
# 32-byte hex secret
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

# Or base64
php -r "echo base64_encode(random_bytes(32)) . PHP_EOL;"
```

---

## 2. Key Rotation

### Rotate keys on a schedule

Rotate signing keys at least quarterly. The `kid` (Key ID) system enables zero-downtime rotation:

```php
// Step 1: Add new key first, keep old key second
$provider = new InMemoryKeyProvider(
    new Key('jwt-key-2025-q2', 'HS256', getenv('JWT_SECRET_NEW'), isSymmetric: true),  // signs new tokens
    new Key('jwt-key-2025-q1', 'HS256', getenv('JWT_SECRET_OLD'), isSymmetric: true),  // verifies old tokens
);

// Step 2: After all old tokens have expired, remove the old key
```

### Immediate rotation after compromise

If a key is suspected compromised:

1. Generate a new key immediately and set it as current.
2. Remove the compromised key from `byKid()` lookup — all tokens signed with it will fail validation.
3. Force re-authentication for all active sessions.
4. Record a `crypto.key_compromised` audit event at severity `critical`.

---

## 3. JWT Hardening

### Use asymmetric keys for distributed systems

When the token issuer and verifier are separate services (e.g., dedicated auth server + microservices):

```php
// Auth server — signs with private key
$issuerProvider = new InMemoryKeyProvider(
    new Key('rsa-v1', 'RS256', file_get_contents('/secrets/jwt-private.pem'), isSymmetric: false)
);

// Resource servers — verify with public key ONLY
$verifierProvider = new InMemoryKeyProvider(
    new Key('rsa-v1', 'RS256', file_get_contents('/secrets/jwt-public.pem'), isSymmetric: false)
);
```

This means a compromised resource server cannot forge tokens.

### Always require JTI

```php
$config = new JwtConfig(
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    requireJti: true,   // prevents replay attacks
    clockSkewSeconds: 30, // keep small
);
```

### Short expiry for access tokens

Access tokens should expire in 15–60 minutes. Use refresh tokens for longer sessions.

---

## 4. CSRF Hardening

### Use per-form contexts

Always pass a unique `$context` string per form. This prevents a CSRF token from one form being replayed on another:

```php
// Different context for different forms
$transferToken  = $manager->issue($sessionId, 'transfer_funds');
$profileToken   = $manager->issue($sessionId, 'update_profile');
$passwordToken  = $manager->issue($sessionId, 'change_password');
```

### Use one-time tokens for high-value actions

```php
$policy = new CsrfPolicy(
    ttlSeconds: 300,      // 5 minutes
    oneTimeTokens: true,  // token invalid after first use
);
```

### Reduce TTL for sensitive operations

Default TTL is 1 hour. For sensitive forms (fund transfers, password changes), reduce to 15–30 minutes.

---

## 5. Password Security

### Tune Argon2id parameters for your hardware

The defaults are conservative. Test on your production hardware and increase memory/time costs:

```php
$hasher = new Argon2idHasher(
    memoryCost: 131072,  // 128 MB (default: 65536 / 64 MB)
    timeCost: 6,          // iterations (default: 4)
    threads: 2,
);
```

Run benchmarks: aim for 200–1000ms per hash on your login servers.

### Enable breach checking in production

```php
$policy = new PasswordPolicy(
    minLength: 12,
    requireUpper: true,
    requireLower: true,
    requireDigit: true,
    requireSymbol: true,
    checkPwned: true,    // rejects passwords in HIBP database
);
```

The HIBP check uses k-anonymity — only the first 5 characters of the SHA1 hash are sent to the API.

---

## 6. TOTP Security

### Encrypt stored TOTP secrets

TOTP secrets in the database should be encrypted at rest. Use a KMS or application-level encryption:

```php
// Store encrypted
$encrypted = openssl_encrypt($secret, 'aes-256-gcm', $appKey, iv: $iv);
$db->saveTotpSecret($userId, base64_encode($iv . $encrypted));

// Load and decrypt
[$iv, $ciphertext] = splitIvAndCiphertext(base64_decode($stored));
$secret = openssl_decrypt($ciphertext, 'aes-256-gcm', $appKey, iv: $iv);
```

### Rate-limit TOTP verification attempts

The library does not implement rate limiting — apply this at the application or infrastructure layer:

```php
$attempts = $cache->get("totp_attempts:{$userId}");
if ($attempts >= 5) {
    throw new TooManyAttemptsException('Account locked for 15 minutes.');
}

if (!$totp->verify($secret, $submittedCode)) {
    $cache->increment("totp_attempts:{$userId}", ttl: 900); // 15 min
    // ...
}

$cache->delete("totp_attempts:{$userId}");
```

---

## 7. Audit Log Protection

### Treat audit logs as append-only

Route audit events to an immutable log store (e.g., AWS CloudWatch, Datadog, Splunk). Avoid writing to writable files on the application server.

### Alert on critical events

Set up real-time alerts for these event types:

| Event | Alert threshold |
|-------|----------------|
| `oauth.refresh_reuse_detected` | Every occurrence |
| `jwt.invalid_signature` | > 10/min per IP |
| `csrf.invalid` | > 50/min |
| `authz.denied` | Spike detection |
| `totp.failed` | > 5 consecutive per user |

---

## 8. Transport Security

`acme/security-kit` assumes TLS is handled at the infrastructure level. You must:

- Terminate TLS at your load balancer or reverse proxy (nginx, Caddy, AWS ALB).
- Use TLS 1.2 or higher; disable TLS 1.0/1.1.
- Set `Strict-Transport-Security` (HSTS) headers.
- Set secure cookie flags: `Secure`, `HttpOnly`, `SameSite=Strict` (or `Lax`).

---

## 9. Content Security Policy

When using the CSRF middleware, ensure your CSP allows the form submission to your own domain and disallows arbitrary form actions:

```
Content-Security-Policy: form-action 'self'; default-src 'self'
```

---

## 10. Dependency Management

Pin exact versions of `firebase/php-jwt` in `composer.lock`. Subscribe to security advisories for your dependencies:

```bash
composer audit          # check for known vulnerabilities
composer outdated       # show available updates
```

Review the [Firebase PHP JWT release notes](https://github.com/firebase/php-jwt/releases) before upgrading.
