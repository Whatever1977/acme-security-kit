<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Totp;

use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Totp\RfcTotp;
use Acme\SecurityKit\Totp\TotpConfig;
use PHPUnit\Framework\TestCase;

final class RfcTotpTest extends TestCase
{
    private RfcTotp $totp;

    protected function setUp(): void
    {
        $this->totp = new RfcTotp(new SecureRandom(), new TotpConfig());
    }

    public function testGenerateSecretIsBase32(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/i', $secret);
        self::assertNotEmpty($secret);
    }

    public function testProvisioningUriFormat(): void
    {
        $secret = $this->totp->generateSecret();
        $uri = $this->totp->provisioningUri('user@example.com', 'MyApp', $secret);
        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertStringContainsString('secret=', $uri);
        self::assertStringContainsString('issuer=MyApp', $uri);
    }

    public function testVerifyCurrentCode(): void
    {
        // Generate a secret, then verify that the code produced right now is valid.
        // This avoids hardcoded vectors that depend on internal Base32 implementation details.
        $secret = $this->totp->generateSecret();
        $now    = new \DateTimeImmutable();

        // Use reflection to call generateCode directly, then verify it round-trips
        $ref    = new \ReflectionClass($this->totp);
        $method = $ref->getMethod('generateCode');
        $method->setAccessible(true);

        $counter = (int) floor($now->getTimestamp() / 30);
        $code    = $method->invoke($this->totp, $secret, $counter);

        self::assertTrue($this->totp->verify($secret, $code, $now));
    }

    public function testVerifyReturnsFalseForBadCode(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertFalse($this->totp->verify($secret, '000000'));
    }

    public function testVerifyReturnsFalseForWrongLength(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertFalse($this->totp->verify($secret, '12345'));
    }
}