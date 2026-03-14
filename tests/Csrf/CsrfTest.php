<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Csrf;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use PHPUnit\Framework\TestCase;

final class CsrfTest extends TestCase
{
    private HmacCsrfManager $manager;

    protected function setUp(): void
    {
        $this->manager = new HmacCsrfManager(
            secret: str_repeat('s', 32),
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: 3600),
        );
    }

    // ─── Token issuance ───────────────────────────────────────────────

    public function testIssuedTokenHasNonEmptyValue(): void
    {
        $token = $this->manager->issue('sess-1', 'form-a');
        self::assertNotEmpty($token->value);
    }

    public function testIssuedTokenHasFutureExpiry(): void
    {
        $token = $this->manager->issue('sess-1', 'form-a');
        self::assertGreaterThan(new \DateTimeImmutable(), $token->expiresAt);
    }

    public function testTwoIssuedTokensForSameContextAreDifferent(): void
    {
        // Nonce randomness ensures each token is unique
        $t1 = $this->manager->issue('sess-1', 'form-a');
        $t2 = $this->manager->issue('sess-1', 'form-a');
        self::assertNotSame($t1->value, $t2->value);
    }

    // ─── Validation — happy path ──────────────────────────────────────

    public function testValidTokenValidatesSuccessfully(): void
    {
        $token = $this->manager->issue('sess-1', 'checkout');
        self::assertTrue($this->manager->validate('sess-1', 'checkout', $token->value));
    }

    // ─── Validation — failure cases ───────────────────────────────────

    public function testValidationFailsWithWrongSessionId(): void
    {
        $token = $this->manager->issue('sess-1', 'checkout');
        self::assertFalse($this->manager->validate('sess-WRONG', 'checkout', $token->value));
    }

    public function testValidationFailsWithWrongContext(): void
    {
        $token = $this->manager->issue('sess-1', 'checkout');
        self::assertFalse($this->manager->validate('sess-1', 'transfer_funds', $token->value));
    }

    public function testValidationFailsWithTamperedToken(): void
    {
        $token    = $this->manager->issue('sess-1', 'form');
        $tampered = base64_encode('totally-fake-value');
        self::assertFalse($this->manager->validate('sess-1', 'form', $tampered));
    }

    public function testValidationFailsWithEmptyToken(): void
    {
        self::assertFalse($this->manager->validate('sess-1', 'form', ''));
    }

    public function testValidationFailsWithTruncatedToken(): void
    {
        $token = $this->manager->issue('sess-1', 'form');
        self::assertFalse($this->manager->validate('sess-1', 'form', substr($token->value, 0, 10)));
    }

    // ─── Token expiry ─────────────────────────────────────────────────

    public function testExpiredTokenFailsValidation(): void
    {
        $expiredManager = new HmacCsrfManager(
            secret: str_repeat('s', 32),
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: -1), // already expired
        );

        $token = $expiredManager->issue('sess-1', 'form');
        self::assertFalse($expiredManager->validate('sess-1', 'form', $token->value));
    }

    // ─── Cross-context replay ─────────────────────────────────────────

    public function testTokenFromOneContextCannotBeUsedInAnother(): void
    {
        $t = $this->manager->issue('sess-1', 'form-a');
        self::assertFalse($this->manager->validate('sess-1', 'form-b', $t->value));
    }

    // ─── Different secrets isolate tokens ─────────────────────────────

    public function testTokenFromDifferentSecretIsInvalid(): void
    {
        $otherManager = new HmacCsrfManager(
            secret: str_repeat('z', 32),
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: 3600),
        );

        $token = $this->manager->issue('sess-1', 'form');
        self::assertFalse($otherManager->validate('sess-1', 'form', $token->value));
    }

    // ─── CsrfPolicy ───────────────────────────────────────────────────

    public function testCsrfPolicyDefaultTtl(): void
    {
        $policy = new CsrfPolicy(ttlSeconds: 1800);
        self::assertSame(1800, $policy->ttlSeconds);
    }
}
