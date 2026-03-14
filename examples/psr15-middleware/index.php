<?php

/**
 * acme/security-kit — PSR-15 middleware wiring example.
 *
 * Demonstrates manual construction and use of CsrfMiddleware
 * and SignedUrlMiddleware in a relay-style pipeline.
 *
 * Also shows key rotation in action.
 */

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Acme\SecurityKit\Audit\NullAuditor;
use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;

$random = new SecureRandom();
$ct     = new HashEquals();

// ─────────────────────────────────────────────
// CSRF — issue + validate
// ─────────────────────────────────────────────
echo "=== CSRF ===" . PHP_EOL;

$csrfManager = new HmacCsrfManager(
    secret: str_repeat('s', 32),
    random: $random,
    constantTime: $ct,
    policy: new CsrfPolicy(
        ttlSeconds: 3600,
        leewaySeconds: 60,
        oneTimeTokens: false,
    ),
);

$sessionId = 'user-session-' . bin2hex(random_bytes(4));
$contexts  = ['checkout', 'transfer_funds', 'delete_account'];

foreach ($contexts as $ctx) {
    $token = $csrfManager->issue($sessionId, $ctx);
    $ok    = $csrfManager->validate($sessionId, $ctx, $token->value);
    echo "  [$ctx] issued and validated: " . ($ok ? 'ok' : 'FAIL') . PHP_EOL;

    // Cross-form replay must be rejected
    $crossForm = $csrfManager->validate($sessionId, 'wrong_context', $token->value);
    echo "  [$ctx] cross-form replay rejected: " . ($crossForm ? 'FAIL' : 'ok') . PHP_EOL;
}

echo PHP_EOL;

// ─────────────────────────────────────────────
// URL Signer — sign, verify, key rotation
// ─────────────────────────────────────────────
echo "=== URL Signer ===" . PHP_EOL;

$keyV1 = new Key('url-v1', 'HS256', str_repeat('a', 32), isSymmetric: true);
$keyV2 = new Key('url-v2', 'HS256', str_repeat('b', 32), isSymmetric: true);

// Phase 1: only v1 key
$signerV1 = new HmacUrlSigner(new InMemoryKeyProvider($keyV1), $ct);
$signed   = $signerV1->sign('https://app.example.com/download/report.pdf', new \DateTimeImmutable('+1 hour'));
echo "  Signed with v1: " . substr($signed->url, 0, 80) . "..." . PHP_EOL;
echo "  Verifies with v1: " . ($signerV1->verify($signed->url) ? 'ok' : 'FAIL') . PHP_EOL;

// Phase 2: rotate to v2 — old URL still verifies
$signerV2 = new HmacUrlSigner(new InMemoryKeyProvider($keyV2, $keyV1), $ct);
echo "  Verifies with v2 provider (v1 URL): " . ($signerV2->verify($signed->url) ? 'ok' : 'FAIL') . PHP_EOL;

// New URLs are signed with v2
$signedNew = $signerV2->sign('https://app.example.com/download/new.pdf', new \DateTimeImmutable('+1 hour'));
echo "  New URL signed with v2: " . substr($signedNew->url, 0, 80) . "..." . PHP_EOL;

// Tampered URL must fail
$tampered = str_replace('download', 'admin', $signed->url);
echo "  Tampered URL rejected: " . ($signerV1->verify($tampered) ? 'FAIL' : 'ok') . PHP_EOL;

echo PHP_EOL;

// ─────────────────────────────────────────────
// Audit — structured events
// ─────────────────────────────────────────────
echo "=== Audit ===" . PHP_EOL;

$stderrLogger = new class extends \Psr\Log\AbstractLogger {
    public function log($level, $message, array $context = []): void {
        $ctx = $context ? ' ' . json_encode(array_intersect_key($context, array_flip(['event_type', 'occurred_at']))) : '';
        echo "  [" . strtoupper((string)$level) . "] $message$ctx" . PHP_EOL;
    }
};

$auditor = new PsrLoggerAuditor($stderrLogger, channel: 'security');

$auditor->record(new \Acme\SecurityKit\Audit\SecurityEvent(
    type: 'csrf.invalid',
    at: new \DateTimeImmutable(),
    context: ['ip' => '1.2.3.4', 'path' => '/transfer'],
    severity: 'warning',
));

$auditor->record(new \Acme\SecurityKit\Audit\SecurityEvent(
    type: 'oauth.refresh_reuse_detected',
    at: new \DateTimeImmutable(),
    context: ['userId' => 'user-42', 'clientId' => 'my-spa'],
    severity: 'critical',
));

$nullAuditor = new NullAuditor();
$nullAuditor->record(new \Acme\SecurityKit\Audit\SecurityEvent(
    type: 'this.is.discarded', at: new \DateTimeImmutable()
));
echo "  NullAuditor discarded event silently: ok" . PHP_EOL;
