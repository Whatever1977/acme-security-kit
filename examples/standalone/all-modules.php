<?php

/**
 * acme/security-kit — Standalone "kitchen sink" example.
 *
 * Demonstrates all nine modules wired together without a framework.
 * Run with: php examples/standalone/all-modules.php
 */

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use Acme\SecurityKit\Authz\InMemoryAssignmentRepository;
use Acme\SecurityKit\Authz\InMemoryRoleRepository;
use Acme\SecurityKit\Authz\RbacAuthorizer;
use Acme\SecurityKit\Authz\Role;
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use Acme\SecurityKit\Jwt\FirebaseJwtManager;
use Acme\SecurityKit\Jwt\JwtConfig;
use Acme\SecurityKit\Password\Argon2idHasher;
use Acme\SecurityKit\Password\PasswordPolicy;
use Acme\SecurityKit\Password\PolicyAwareHasher;
use Acme\SecurityKit\Totp\RfcTotp;
use Acme\SecurityKit\Totp\TotpConfig;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;

// ─────────────────────────────────────────────
// Shared primitives
// ─────────────────────────────────────────────
$random = new SecureRandom();
$ct     = new HashEquals();

// Simple stderr logger for the example
$logger = new class extends \Psr\Log\AbstractLogger {
    public function log($level, $message, array $context = []): void
    {
        $ctx = $context ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES) : '';
        fwrite(STDERR, strtoupper((string) $level) . " $message$ctx\n");
    }
};
$auditor = new PsrLoggerAuditor($logger, channel: 'security');

echo "=== acme/security-kit — All Modules Demo ===" . PHP_EOL . PHP_EOL;

// ─────────────────────────────────────────────
// 1. Crypto — Keys
// ─────────────────────────────────────────────
echo "--- 1. Crypto ---" . PHP_EOL;

$symmetricKey = new Key('hmac-v1', 'HS256', str_repeat('x', 32), isSymmetric: true);
$keyProvider  = new InMemoryKeyProvider($symmetricKey);

$nonce = $random->base64Url(16);
echo "Random nonce (base64url, 16 bytes): $nonce" . PHP_EOL;

$a = 'expected-mac-value';
$b = 'expected-mac-value';
echo "Constant-time equals: " . ($ct->equals($a, $b) ? 'true' : 'false') . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 2. CSRF
// ─────────────────────────────────────────────
echo "--- 2. CSRF ---" . PHP_EOL;

$csrfManager = new HmacCsrfManager(
    secret: str_repeat('c', 32),
    random: $random,
    constantTime: $ct,
    policy: new CsrfPolicy(ttlSeconds: 3600),
);

$csrfToken = $csrfManager->issue('session-abc', 'transfer_funds');
echo "Issued token: {$csrfToken->value}" . PHP_EOL;
echo "Expires at: {$csrfToken->expiresAt->format('c')}" . PHP_EOL;

$valid = $csrfManager->validate('session-abc', 'transfer_funds', $csrfToken->value);
echo "Valid: " . ($valid ? 'yes' : 'no') . PHP_EOL;

$invalid = $csrfManager->validate('session-abc', 'other_form', $csrfToken->value);
echo "Cross-form replay blocked: " . ($invalid ? 'FAIL' : 'yes') . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 3. URL Signer
// ─────────────────────────────────────────────
echo "--- 3. URL Signer ---" . PHP_EOL;

$urlSigner = new HmacUrlSigner(
    keyProvider: new InMemoryKeyProvider(
        new Key('url-v1', 'HS256', str_repeat('u', 32), isSymmetric: true)
    ),
    constantTime: $ct,
);

$signedUrl = $urlSigner->sign(
    'https://app.example.com/download/report.pdf',
    new \DateTimeImmutable('+1 hour'),
    ['user_id' => 'usr-42'],
);

echo "Signed URL: {$signedUrl->url}" . PHP_EOL;
echo "Verifies: " . ($urlSigner->verify($signedUrl->url) ? 'yes' : 'no') . PHP_EOL;
echo "Tampered URL verifies: " . ($urlSigner->verify($signedUrl->url . 'tampered') ? 'FAIL' : 'no') . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 4. JWT
// ─────────────────────────────────────────────
echo "--- 4. JWT ---" . PHP_EOL;

$jwtManager = new FirebaseJwtManager(
    config: new JwtConfig(
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        requireJti: true,
        algorithm: 'HS256',
    ),
    keyProvider: $keyProvider,
    random: $random,
    auditor: $auditor,
);

$jwt = $jwtManager->mint(
    ['sub' => 'user-42', 'roles' => ['editor']],
    new \DateTimeImmutable('+1 hour'),
);
echo "JWT (first 60 chars): " . substr($jwt, 0, 60) . "..." . PHP_EOL;

$verified = $jwtManager->parseAndValidate($jwt);
echo "Subject: " . $verified->claim('sub') . PHP_EOL;
echo "KID: " . $verified->kid . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 5. Password
// ─────────────────────────────────────────────
echo "--- 5. Password ---" . PHP_EOL;

$hasher = new PolicyAwareHasher(
    inner: new Argon2idHasher(),
    policy: new PasswordPolicy(minLength: 12, requireUpper: true, requireDigit: true),
);

$password = 'Correct-Horse-Battery-9';
$hash     = $hasher->hash($password);
echo "Hash algorithm: " . (str_starts_with($hash, '$argon2id') ? 'argon2id ✓' : $hash) . PHP_EOL;
echo "Verify correct: " . ($hasher->verify($password, $hash) ? 'yes' : 'no') . PHP_EOL;
echo "Verify wrong:   " . ($hasher->verify('wrongpassword', $hash) ? 'FAIL' : 'no') . PHP_EOL;
echo "Needs rehash:   " . ($hasher->needsRehash($hash) ? 'yes' : 'no') . PHP_EOL;

$weakViolations = (new PasswordPolicy(minLength: 12, requireUpper: true))->validate('weak');
echo "Weak password violations: " . implode(', ', $weakViolations) . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 6. TOTP
// ─────────────────────────────────────────────
echo "--- 6. TOTP ---" . PHP_EOL;

$totp   = new RfcTotp($random, new TotpConfig(digits: 6, step: 30));
$secret = $totp->generateSecret();
echo "TOTP secret (Base32): $secret" . PHP_EOL;

$uri = $totp->provisioningUri('alice@example.com', 'MyApp', $secret);
echo "Provisioning URI: " . substr($uri, 0, 60) . "..." . PHP_EOL;

// Generate a current valid code and verify it
$currentCode = $totp->currentCode($secret);
echo "Current code: $currentCode" . PHP_EOL;
echo "Verifies: " . ($totp->verify($secret, $currentCode) ? 'yes' : 'no') . PHP_EOL;
echo "Wrong code: " . ($totp->verify($secret, '000000') ? 'FAIL' : 'no') . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 7. RBAC / Authz
// ─────────────────────────────────────────────
echo "--- 7. RBAC ---" . PHP_EOL;

$roles = new InMemoryRoleRepository();
$roles->add(new Role('viewer', permissions: ['read:posts']));
$roles->add(new Role('editor', parents: ['viewer'], permissions: ['edit:posts', 'create:posts']));
$roles->add(new Role('admin',  permissions: ['*']));

$assignments = new InMemoryAssignmentRepository();
$assignments->assign('user-42', ['editor']);
$assignments->assign('user-99', ['admin']);

$authz = new RbacAuthorizer($roles, $assignments, $auditor);

$d1 = $authz->can('user-42', 'edit', 'posts');
echo "editor can edit:posts — {$d1->reason}" . PHP_EOL;

$d2 = $authz->can('user-42', 'read', 'posts');  // inherited from viewer
echo "editor can read:posts (inherited) — {$d2->reason}" . PHP_EOL;

$d3 = $authz->can('user-42', 'delete', 'posts'); // not allowed
echo "editor can delete:posts — allowed: " . ($d3->allowed ? 'FAIL' : 'no') . PHP_EOL;

$d4 = $authz->can('user-99', 'delete', 'posts'); // admin wildcard
echo "admin can delete:posts — {$d4->reason}" . PHP_EOL;
echo PHP_EOL;

// ─────────────────────────────────────────────
// 8. Audit
// ─────────────────────────────────────────────
echo "--- 8. Audit (see STDERR) ---" . PHP_EOL;

$auditor->record(new SecurityEvent(
    type: 'demo.all_modules_completed',
    at: new \DateTimeImmutable(),
    context: ['modules' => 8],
    severity: 'info',
));

echo PHP_EOL . "All modules demonstrated successfully." . PHP_EOL;
