# acme/security-kit — Complete Usage Guide

> From first clone to production-ready security primitives.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Crypto — Randomness, Keys & Constant-Time](#2-crypto)
3. [CSRF — Cross-Site Request Forgery Protection](#3-csrf)
4. [UrlSigner — Signed URLs](#4-urlsigner)
5. [JWT — JSON Web Tokens](#5-jwt)
6. [OAuth2 — Token Policies & PKCE](#6-oauth2)
7. [Password — Hashing & Policy](#7-password)
8. [TOTP — Two-Factor Authentication](#8-totp)
9. [Authz — Role-Based Access Control](#9-authz)
10. [Audit — Security Event Logging](#10-audit)
11. [PSR-15 Middleware](#11-psr-15-middleware)
12. [Running the Test Suite](#12-running-the-test-suite)
13. [Tooling Reference](#13-tooling-reference)

---

## 1. Getting Started

### Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| PHP | 8.2 |
| Composer | 2.x |
| Extensions | `openssl`, `mbstring` |

### Clone from GitHub

```bash
git clone https://github.com/acme/security-kit.git
cd acme-security-kit
```

### Install dependencies

```bash
composer install
```

For **production** (no dev tools):

```bash
composer install --no-dev --optimize-autoloader
```

### Use as a library in your own project

Add to your project's `composer.json`:

```json
{
    "require": {
        "acme/security-kit": "^1.0"
    }
}
```

Then run:

```bash
composer require acme/security-kit
```

### Autoloading

Everything is PSR-4 autoloaded. As long as you include Composer's autoloader you are ready to go:

```php
<?php
require __DIR__ . '/vendor/autoload.php';
```

---

## 2. Crypto

**Namespace:** `Acme\SecurityKit\Crypto`

The foundation of the entire toolkit. All other modules depend on these primitives.

### 2.1 Secure Random Bytes

```php
use Acme\SecurityKit\Crypto\SecureRandom;

$random = new SecureRandom();

// Raw binary — 32 cryptographically secure bytes
$bytes = $random->bytes(32);

// URL-safe base64 string — safe for tokens, nonces, IDs
$token = $random->base64Url(32);
// e.g. "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

### 2.2 Constant-Time Comparison

Always use this instead of `===` when comparing secrets, tokens or MACs.

```php
use Acme\SecurityKit\Crypto\HashEquals;

$ct = new HashEquals();

$valid = $ct->equals($trustedToken, $submittedToken); // true or false
```

> **Why?** Regular string comparison (`===`) short-circuits on the first differing byte, leaking timing information that attackers can exploit.

### 2.3 Keys and KeySets

```php
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\KeySet;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;

// Symmetric key (HMAC / HS256)
$hmacKey = new Key(
    kid: 'hmac-2024-q4',
    algorithm: 'HS256',
    material: 'your-secret-at-least-32-bytes-long!!',
    isSymmetric: true,
);

// Asymmetric key — load PEM from file
$rsaKey = new Key(
    kid: 'rsa-2025-q1',
    algorithm: 'RS256',
    material: file_get_contents('/path/to/private.pem'),
    isSymmetric: false,
);

// Bundle into a KeySet
$keySet = new KeySet($hmacKey, $rsaKey);

// Retrieve by kid
$key = $keySet->get('hmac-2024-q4');

// Export public keys as JWKS JSON (RS256/ES256 only)
$jwks = $keySet->toJwks();
// {"keys":[{"kid":"rsa-2025-q1","use":"sig","alg":"RS256","kty":"RSA","n":"...","e":"..."}]}
```

### 2.4 KeyProvider

```php
// InMemoryKeyProvider is great for single-server setups.
// For distributed systems, implement KeyProvider to load from a secrets manager.
$provider = new InMemoryKeyProvider($hmacKey, $rsaKey);

$currentKeySet = $provider->current();       // KeySet with all keys
$specificKey   = $provider->byKid('hmac-2024-q4'); // ?Key
```

---

## 3. CSRF

**Namespace:** `Acme\SecurityKit\Csrf`

Stateless HMAC-based CSRF tokens scoped to a session and a form context.

### 3.1 Setup

```php
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;

$manager = new HmacCsrfManager(
    secret: 'your-32-byte-csrf-secret-here!!!!',
    random: new SecureRandom(),
    constantTime: new HashEquals(),
    policy: new CsrfPolicy(
        ttlSeconds: 3600,    // token lifetime — 1 hour
        leewaySeconds: 60,   // grace period for clock drift
        oneTimeTokens: false // set true for high-security forms
    ),
);
```

### 3.2 Issue a token

Call this when rendering a form. Store the token value in the HTML.

```php
$sessionId = session_id(); // or any stable session identifier
$context   = 'transfer_funds'; // unique per form

$token = $manager->issue($sessionId, $context);

echo $token->value;     // embed in a hidden <input>
echo $token->expiresAt->format('c'); // optional — show user when it expires
```

### 3.3 Validate on form submission

```php
$submitted = $_POST['_csrf_token'] ?? '';

if (!$manager->validate($sessionId, $context, $submitted)) {
    http_response_code(419);
    exit('CSRF validation failed.');
}

// Safe to process the form
```

### 3.4 Double-submit cookie pattern

```php
// On page render — also set a cookie
$token = $manager->issue($sessionId, 'checkout');
setcookie('csrf_token', $token->value, [
    'httponly' => false, // JS must read it
    'samesite' => 'Strict',
    'secure'   => true,
]);

// On submission — compare header (set by JS) to session-bound token
$headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
$valid = $manager->validate($sessionId, 'checkout', $headerToken);
```

---

## 4. UrlSigner

**Namespace:** `Acme\SecurityKit\UrlSigner`

HMAC-SHA256 signed URLs for email verification links, password reset links, and time-limited download links.

### 4.1 Setup

```php
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;
use Acme\SecurityKit\UrlSigner\UrlSignerPolicy;

$key    = new Key('url-key-v1', 'HS256', 'your-url-signing-secret-32bytes!!', isSymmetric: true);
$signer = new HmacUrlSigner(
    keyProvider: new InMemoryKeyProvider($key),
    constantTime: new HashEquals(),
    policy: new UrlSignerPolicy(
        expiresParam:  '_expires',
        kidParam:      '_kid',
        signatureParam: '_sig',
    ),
);
```

### 4.2 Sign a URL

```php
$signedUrl = $signer->sign(
    url: 'https://app.example.com/verify-email',
    expiresAt: new \DateTimeImmutable('+24 hours'),
    claims: ['user_id' => 'usr-42', 'email' => 'alice@example.com'],
);

echo $signedUrl->url;       // full signed URL — send this in the email
echo $signedUrl->signature; // HMAC value
echo $signedUrl->expiresAt->format('c');
```

### 4.3 Verify a URL

```php
// In your controller / route handler:
$incomingUrl = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

if (!$signer->verify($incomingUrl)) {
    http_response_code(403);
    exit('Link is invalid or has expired.');
}

// Parse back to get claims
$parsed = $signer->parse($incomingUrl);
parse_str(parse_url($parsed->url, PHP_URL_QUERY), $params);
$userId = $params['user_id']; // "usr-42"
```

### 4.4 Key rotation

```php
// Add a new key — new URLs will be signed with it (it goes first in the set).
// Old URLs signed with the previous key still verify because byKid() finds historical keys.
$newKey = new Key('url-key-v2', 'HS256', 'new-secret-after-rotation!!!!!!!!', isSymmetric: true);
$oldKey = new Key('url-key-v1', 'HS256', 'your-url-signing-secret-32bytes!!', isSymmetric: true);

$provider = new InMemoryKeyProvider($newKey, $oldKey); // first = current signing key
$signer   = new HmacUrlSigner($provider, new HashEquals());
```

---

## 5. JWT

**Namespace:** `Acme\SecurityKit\Jwt`

Wraps `firebase/php-jwt` with strict claim validation, key rotation, and audit logging.

### 5.1 Setup

```php
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Jwt\FirebaseJwtManager;
use Acme\SecurityKit\Jwt\JwtConfig;

$config = new JwtConfig(
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    clockSkewSeconds: 60,
    requireJti: true,      // recommended — prevents replay attacks
    algorithm: 'HS256',    // or 'RS256' / 'ES256' for asymmetric
);

$key     = new Key('jwt-key-v1', 'HS256', 'your-jwt-secret-at-least-32-bytes!', isSymmetric: true);
$manager = new FirebaseJwtManager(
    config: $config,
    keyProvider: new InMemoryKeyProvider($key),
    random: new SecureRandom(),
);
```

### 5.2 Mint a token

```php
$jwt = $manager->mint(
    claims: [
        'sub'   => 'user-42',
        'roles' => ['editor', 'viewer'],
        'email' => 'alice@example.com',
    ],
    expiresAt: new \DateTimeImmutable('+1 hour'),
);

// $jwt is a compact JWT string — send in Authorization: Bearer header
```

### 5.3 Validate a token

```php
use Acme\SecurityKit\Jwt\JwtException;

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$jwt = str_replace('Bearer ', '', $authHeader);

try {
    $verified = $manager->parseAndValidate($jwt);

    echo $verified->claim('sub');   // "user-42"
    echo $verified->claim('email'); // "alice@example.com"
    echo $verified->kid;            // "jwt-key-v1"
    echo $verified->expiresAt->format('c');

} catch (JwtException $e) {
    http_response_code(401);
    exit('Unauthorized: ' . $e->getMessage());
}
```

### 5.4 RS256 asymmetric keys

```php
// Generate keys (do this once, store securely):
// openssl genrsa -out private.pem 2048
// openssl rsa -in private.pem -pubout -out public.pem

$privateKey = new Key('rsa-v1', 'RS256', file_get_contents('private.pem'), isSymmetric: false);
$publicKey  = new Key('rsa-v1', 'RS256', file_get_contents('public.pem'),  isSymmetric: false);

// Auth server mints with private key:
$mintManager = new FirebaseJwtManager($config, new InMemoryKeyProvider($privateKey), $random);

// Resource server validates with public key:
$verifyManager = new FirebaseJwtManager($config, new InMemoryKeyProvider($publicKey), $random);
```

### 5.5 JWKS export (for public key discovery)

```php
$keySet = $provider->current();
$jwks   = $keySet->toJwks();
// Serve as JSON at /.well-known/jwks.json
header('Content-Type: application/json');
echo json_encode($jwks);
```

---

## 6. OAuth2

**Namespace:** `Acme\SecurityKit\OAuth2`

Storage interfaces, PKCE validation, and token TTL policies. Wire these into your own OAuth2 flow or an existing server like `league/oauth2-server`.

### 6.1 Storage interfaces

Implement these three interfaces backed by your database:

```php
use Acme\SecurityKit\OAuth2\Repository\ClientRepository;
use Acme\SecurityKit\OAuth2\Repository\TokenRepository;
use Acme\SecurityKit\OAuth2\Repository\ScopeRepository;

class MyClientRepository implements ClientRepository
{
    public function findById(string $clientId): ?Client
    {
        // Load from DB, return Client DTO or null
    }

    public function verifySecret(string $clientId, string $secret): bool
    {
        // Constant-time comparison of hashed secret
    }
}
```

### 6.2 Client DTO

```php
use Acme\SecurityKit\OAuth2\DTO\Client;

$client = new Client(
    clientId: 'my-spa',
    isPublic: true,                          // SPA / mobile = public client
    redirectUris: ['https://app.example.com/callback'],
    grantTypes: ['authorization_code'],
    scopes: ['read', 'write'],
    requirePkce: true,                       // always true for public clients
);

$client->hasRedirectUri('https://app.example.com/callback'); // true
```

### 6.3 PKCE validation

Always enforce PKCE for public clients (SPAs, mobile apps). Only S256 is accepted — `plain` is rejected.

```php
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\OAuth2\PkceValidator;

$pkce = new PkceValidator(new HashEquals());

// --- Authorization request (client side, for illustration) ---
$codeVerifier  = base64_encode(random_bytes(32)); // store this securely
$codeChallenge = $pkce->challenge($codeVerifier); // send in auth request

// --- Token request (server side) ---
$isValid = $pkce->validate(
    codeVerifier:  $_POST['code_verifier'],
    codeChallenge: $storedChallenge,  // retrieved from your auth code store
    method: 'S256',
);

if (!$isValid) {
    http_response_code(400);
    exit('invalid_grant: PKCE verification failed');
}
```

### 6.4 Token TTL policy

```php
use Acme\SecurityKit\OAuth2\TokenTtlPolicy;

$policy = new TokenTtlPolicy(
    accessTokenTtlSeconds: 3600,        // 1 hour
    refreshTokenTtlSeconds: 2592000,    // 30 days
    rotateRefreshTokens: true,          // issue new refresh token on every use
    detectRefreshTokenReuse: true,      // revoke entire family if old token reused
);
```

### 6.5 Refresh token rotation + reuse detection

```php
// When a refresh token is presented:
$refreshToken = $tokenRepo->findRefreshToken($_POST['refresh_token']);

if ($refreshToken === null || $refreshToken->revoked) {
    if ($policy->detectRefreshTokenReuse && $refreshToken?->revoked) {
        // SUSPICIOUS — revoke all tokens for this client/user
        $auditor->record(new SecurityEvent(
            'oauth.refresh_reuse_detected',
            new \DateTimeImmutable(),
            ['clientId' => $clientId, 'userId' => $userId],
            'critical'
        ));
        // revoke entire token family here
    }
    http_response_code(401);
    exit('invalid_grant');
}

// Revoke old, issue new
$tokenRepo->revokeRefreshToken($refreshToken->token);
// ... mint new access + refresh tokens
```

---

## 7. Password

**Namespace:** `Acme\SecurityKit\Password`

Password hashing with Argon2id (bcrypt fallback), policy enforcement, and rehash-on-login.

### 7.1 Basic hashing

```php
use Acme\SecurityKit\Password\Argon2idHasher;

$hasher = new Argon2idHasher();

$hash = $hasher->hash('correct-horse-Battery-staple!9');
// "$argon2id$v=19$m=65536,t=4,p=1$..."

$valid = $hasher->verify('correct-horse-Battery-staple!9', $hash); // true
$valid = $hasher->verify('wrongpassword', $hash);                   // false
```

### 7.2 Password policy

```php
use Acme\SecurityKit\Password\PasswordPolicy;

$policy = new PasswordPolicy(
    minLength: 12,
    requireUpper: true,
    requireLower: true,
    requireDigit: true,
    requireSymbol: true,
    checkPwned: false, // set true + inject PwnedPasswordChecker for breach checks
);

$violations = $policy->validate('weakpass');
// ["Password must be at least 12 characters.",
//  "Password must contain at least one uppercase letter.", ...]

if (!$policy->satisfies($password)) {
    // reject registration
}
```

### 7.3 Policy-aware hasher (recommended for registration)

```php
use Acme\SecurityKit\Password\PolicyAwareHasher;
use Acme\SecurityKit\Password\WeakPasswordException;

$hasher = new PolicyAwareHasher(
    inner: new Argon2idHasher(),
    policy: $policy,
);

try {
    $hash = $hasher->hash($submittedPassword);
    // Store $hash in database
} catch (WeakPasswordException $e) {
    foreach ($e->getViolations() as $violation) {
        echo $violation . "\n";
    }
}
```

### 7.4 Rehash on login

Call this after every successful login to silently upgrade hashes when your parameters change.

```php
$storedHash = $db->getPasswordHash($userId);

if (!$hasher->verify($password, $storedHash)) {
    // wrong password
    exit;
}

// Upgrade hash if needed (new algorithm / cost parameters)
if ($hasher->needsRehash($storedHash)) {
    $newHash = $hasher->hash($password);
    $db->updatePasswordHash($userId, $newHash);
}
```

### 7.5 Pluggable breach checker

```php
use Acme\SecurityKit\Password\PwnedPasswordChecker;

class HibpChecker implements PwnedPasswordChecker
{
    public function isBreached(string $password): bool
    {
        // Use k-anonymity: only send first 5 chars of SHA1
        $sha1   = strtoupper(sha1($password));
        $prefix = substr($sha1, 0, 5);
        $suffix = substr($sha1, 5);

        $response = file_get_contents("https://api.pwnedpasswords.com/range/{$prefix}");
        return str_contains($response, $suffix);
    }
}

$policy  = new PasswordPolicy(checkPwned: true);
$hasher  = new PolicyAwareHasher(new Argon2idHasher(), $policy, new HibpChecker());
```

---

## 8. TOTP

**Namespace:** `Acme\SecurityKit\Totp`

RFC 6238 Time-based One-Time Passwords — compatible with Google Authenticator, Authy, and any standard TOTP app.

### 8.1 Setup

```php
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Totp\RfcTotp;
use Acme\SecurityKit\Totp\TotpConfig;

$totp = new RfcTotp(
    random: new SecureRandom(),
    config: new TotpConfig(
        digits: 6,        // 6 or 8
        step: 30,         // seconds per window
        window: 1,        // accept ±1 step for clock drift
        algorithm: 'sha1' // sha1 (most compatible) or sha256
    ),
);
```

### 8.2 Enrolment flow

```php
// 1. Generate and store a secret for the user
$secret = $totp->generateSecret(); // e.g. "JBSWY3DPEHPK3PXP..."
$db->saveTotpSecret($userId, $secret); // store encrypted at rest

// 2. Generate the provisioning URI
$uri = $totp->provisioningUri(
    accountName: 'alice@example.com',
    issuer: 'MyApp',
    secret: $secret,
);
// otpauth://totp/MyApp:alice%40example.com?secret=JBSWY...&issuer=MyApp&...

// 3. Display as QR code (use any QR library)
// e.g. endroid/qr-code: QrCode::create($uri)
echo "<img src='https://api.qrserver.com/v1/create-qr-code/?data=" . urlencode($uri) . "'>";
```

### 8.3 Verification on login

```php
$secret = $db->getTotpSecret($userId); // load stored secret

$submittedCode = $_POST['totp_code'] ?? '';

if (!$totp->verify($secret, $submittedCode)) {
    $auditor->record(new SecurityEvent('totp.failed', new \DateTimeImmutable(),
        ['userId' => $userId], 'warning'));

    http_response_code(401);
    exit('Invalid authenticator code.');
}

// 2FA passed — complete login
```

---

## 9. Authz

**Namespace:** `Acme\SecurityKit\Authz`

Role-Based Access Control (RBAC) with role inheritance and optional attribute-based (ABAC-lite) callbacks.

### 9.1 Define roles

```php
use Acme\SecurityKit\Authz\InMemoryRoleRepository;
use Acme\SecurityKit\Authz\Role;

$roles = new InMemoryRoleRepository();

// Base role
$roles->add(new Role('viewer', permissions: ['read:posts', 'read:comments']));

// Editor inherits viewer's permissions
$roles->add(new Role('editor',
    parents: ['viewer'],
    permissions: ['create:posts', 'edit:posts', 'delete:comments']
));

// Admin has a wildcard — can do everything
$roles->add(new Role('admin', permissions: ['*']));
```

### 9.2 Assign roles to users

```php
use Acme\SecurityKit\Authz\InMemoryAssignmentRepository;

$assignments = new InMemoryAssignmentRepository();
$assignments->assign('user-42', ['editor']);
$assignments->assign('user-99', ['admin']);
```

### 9.3 Check permissions

```php
use Acme\SecurityKit\Authz\RbacAuthorizer;

$authz    = new RbacAuthorizer($roles, $assignments);
$decision = $authz->can('user-42', 'edit', 'posts');

if (!$decision->allowed) {
    http_response_code(403);
    exit('Forbidden: ' . $decision->reason);
}

// $decision->reason explains why access was granted or denied
echo $decision->reason; // "Granted via role: editor"
```

### 9.4 ABAC-lite attribute checks

Pass additional context (IP, time of day, resource owner, etc.) for fine-grained control.

```php
use Acme\SecurityKit\Authz\RbacAuthorizer;

$authz = new RbacAuthorizer(
    roleRepository: $roles,
    assignmentRepository: $assignments,
    attributeChecks: [
        // Block requests from suspicious IPs regardless of role
        function (string $subjectId, string $action, string $resource, array $context): ?bool {
            if (in_array($context['ip'] ?? '', $blocklist, true)) {
                return false; // deny
            }
            return null; // abstain — let RBAC decide
        },

        // Only allow "delete" between 09:00-17:00
        function (string $subjectId, string $action, string $resource, array $context): ?bool {
            if ($action === 'delete') {
                $hour = (int) date('G');
                if ($hour < 9 || $hour >= 17) {
                    return false; // deny outside business hours
                }
            }
            return null; // abstain
        },
    ]
);

$decision = $authz->can('user-42', 'delete', 'posts', [
    'ip' => $_SERVER['REMOTE_ADDR'],
]);
```

### 9.5 Decision object

```php
$decision->allowed; // bool
$decision->reason;  // human-readable explanation

// Convenience factory methods
Decision::allow('Explicitly permitted.');
Decision::deny('Outside allowed hours.');
```

---

## 10. Audit

**Namespace:** `Acme\SecurityKit\Audit`

Structured security event logging via PSR-3.

### 10.1 Setup with PSR-3 logger

```php
use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$monolog = new Logger('app');
$monolog->pushHandler(new StreamHandler('/var/log/security.log'));

$auditor = new PsrLoggerAuditor($monolog, channel: 'security');
```

### 10.2 Record a security event

```php
use Acme\SecurityKit\Audit\SecurityEvent;

$auditor->record(new SecurityEvent(
    type: 'auth.login.failed',
    at: new \DateTimeImmutable(),
    context: [
        'ip'        => $_SERVER['REMOTE_ADDR'],
        'userAgent' => $_SERVER['HTTP_USER_AGENT'],
        'userId'    => $attemptedUserId,
    ],
    severity: 'warning', // info | warning | error | critical
));
```

### 10.3 Severity levels

| Severity | PSR-3 level | When to use |
|----------|------------|-------------|
| `info` | INFO | Normal security events (login, token issued) |
| `warning` | WARNING | Suspicious activity (invalid token, CSRF failure) |
| `error` | ERROR | Definite attack indicators |
| `critical` | CRITICAL | Refresh token reuse, key compromise suspected |

### 10.4 Standard event types

All modules emit these event type strings — set up log alerts on them:

| Event type | Emitted by | Severity |
|---|---|---|
| `csrf.invalid` | CsrfMiddleware | warning |
| `urlsig.invalid` | SignedUrlMiddleware | warning |
| `jwt.expired` | FirebaseJwtManager | warning |
| `jwt.invalid_signature` | FirebaseJwtManager | warning |
| `jwt.kid_unknown` | FirebaseJwtManager | warning |
| `oauth.refresh_reuse_detected` | Your token handler | critical |
| `totp.failed` | Your login handler | warning |
| `authz.denied` | RbacAuthorizer | warning |

### 10.5 NullAuditor for testing

```php
use Acme\SecurityKit\Audit\NullAuditor;

// Silently discards all events — use in unit tests
$auditor = new NullAuditor();
```

---

## 11. PSR-15 Middleware

**Namespace:** `Acme\SecurityKit\Support`

Plug-and-play middleware for any PSR-15 compatible framework (Slim, Mezzio, Laravel via bridge, etc.).

### 11.1 CSRF Middleware

```php
use Acme\SecurityKit\Support\CsrfMiddleware;

// Add to your middleware pipeline
$app->add(new CsrfMiddleware(
    csrfManager: $csrfManager,
    responseFactory: $responseFactory, // PSR-17 ResponseFactoryInterface
    auditor: $auditor,
    headerName: 'X-CSRF-Token',      // JS frameworks send token here
    formFieldName: '_csrf_token',     // HTML form hidden field
    sessionIdAttribute: 'session_id', // request attribute name
    contextAttribute: 'csrf_context', // request attribute name
));
```

The middleware:
- Skips `GET`, `HEAD`, `OPTIONS` requests automatically
- Checks the `X-CSRF-Token` header first, then falls back to `_csrf_token` in POST body
- Returns `419` on failure and records a `csrf.invalid` audit event

### 11.2 Signed URL Middleware

```php
use Acme\SecurityKit\Support\SignedUrlMiddleware;

// Protect an entire route group with signed URL verification
$app->group('/download', function () { ... })
    ->add(new SignedUrlMiddleware(
        signer: $urlSigner,
        responseFactory: $responseFactory,
        auditor: $auditor,
    ));
```

Returns `403` on invalid/expired URLs and records a `urlsig.invalid` audit event.

---

## 12. Running the Test Suite

```bash
# Run all tests
vendor/bin/phpunit

# Run a single module's tests
vendor/bin/phpunit tests/Csrf
vendor/bin/phpunit tests/Jwt

# Run with verbose output
vendor/bin/phpunit --testdox

# With code coverage (requires Xdebug)
vendor/bin/phpunit --coverage-html coverage/html
# Open coverage/html/index.html in your browser
```

---

## 13. Tooling Reference

### Static analysis (PHPStan level 8)

```bash
vendor/bin/phpstan analyse
vendor/bin/phpstan analyse --level=max  # strictest possible
```

### Code style (PHP-CS-Fixer)

```bash
vendor/bin/php-cs-fixer check          # check without modifying
vendor/bin/php-cs-fixer fix            # auto-fix all issues
```

### Automated upgrades (Rector)

```bash
vendor/bin/rector process --dry-run    # preview changes
vendor/bin/rector process              # apply changes
```

### Mutation testing (Infection)

```bash
vendor/bin/infection
# Targets: minMsi=70%, minCoveredMsi=80%
# Results in infection.log
```

### Benchmarks (PHPBench)

```bash
vendor/bin/phpbench run benchmarks/ --report=default
```

---

## Security Guarantees Summary

| Guarantee | Mechanism |
|-----------|-----------|
| Secure randomness | `random_bytes()` only — no `mt_rand()` or `uniqid()` |
| Constant-time comparisons | `hash_equals()` on all secret/token comparisons |
| No algorithm confusion | JWT algorithm set server-side, never from token header |
| Memory-hard password hashing | Argon2id (bcrypt fallback) |
| PKCE enforced | S256 only — `plain` rejected |
| Short-lived tokens | Explicit `expiresAt` required on all tokens |
| Key rotation support | `kid` in all signed artifacts, `KeyProvider` interface |
| Structured audit trail | All failures emit typed `SecurityEvent` records |

---

*For threat model details and architectural decisions see [`docs/threat-model.md`](docs/threat-model.md) and [`docs/decisions/`](docs/decisions/).*