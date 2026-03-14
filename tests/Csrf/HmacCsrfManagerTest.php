<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Csrf;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use PHPUnit\Framework\TestCase;

final class HmacCsrfManagerTest extends TestCase
{
    private HmacCsrfManager $manager;

    protected function setUp(): void
    {
        $this->manager = new HmacCsrfManager(
            secret: 'test-secret-key-at-least-32-bytes!!',
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: 3600),
        );
    }

    public function testIssueReturnsToken(): void
    {
        $token = $this->manager->issue('session1', 'login_form');
        self::assertNotEmpty($token->value);
        self::assertFalse($token->isExpired());
    }

    public function testValidateReturnsTrueForValidToken(): void
    {
        $token = $this->manager->issue('session1', 'login_form');
        self::assertTrue($this->manager->validate('session1', 'login_form', $token->value));
    }

    public function testValidateReturnsFalseForWrongSession(): void
    {
        $token = $this->manager->issue('session1', 'login_form');
        self::assertFalse($this->manager->validate('session_other', 'login_form', $token->value));
    }

    public function testValidateReturnsFalseForWrongContext(): void
    {
        $token = $this->manager->issue('session1', 'login_form');
        self::assertFalse($this->manager->validate('session1', 'other_form', $token->value));
    }

    public function testValidateReturnsFalseForTamperedToken(): void
    {
        $token = $this->manager->issue('session1', 'login_form');
        self::assertFalse($this->manager->validate('session1', 'login_form', $token->value . 'tampered'));
    }

    public function testValidateReturnsFalseForEmptyToken(): void
    {
        self::assertFalse($this->manager->validate('session1', 'login_form', ''));
    }

    public function testTokensAreUnique(): void
    {
        $a = $this->manager->issue('s', 'ctx');
        $b = $this->manager->issue('s', 'ctx');
        self::assertNotSame($a->value, $b->value);
    }

    public function testExpiredTokenIsInvalid(): void
    {
        $manager = new HmacCsrfManager(
            secret: 'test-secret-key-at-least-32-bytes!!',
            random: new SecureRandom(),
            constantTime: new HashEquals(),
            policy: new CsrfPolicy(ttlSeconds: -1, leewaySeconds: 0),
        );
        $token = $manager->issue('s', 'ctx');
        self::assertFalse($manager->validate('s', 'ctx', $token->value));
    }
}
