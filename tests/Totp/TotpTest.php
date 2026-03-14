<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Totp;

use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Totp\RfcTotp;
use Acme\SecurityKit\Totp\TotpConfig;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    private RfcTotp $totp;

    protected function setUp(): void
    {
        $this->totp = new RfcTotp(
            random: new SecureRandom(),
            config: new TotpConfig(digits: 6, step: 30, window: 1, algorithm: 'sha1'),
        );
    }

    // ─── Secret generation ────────────────────────────────────────────

    public function testGenerateSecretReturnsNonEmptyString(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertNotEmpty($secret);
    }

    public function testGenerateSecretIsValidBase32(): void
    {
        $secret = $this->totp->generateSecret();
        // Base32 alphabet: A-Z and 2-7
        self::assertMatchesRegularExpression('/^[A-Z2-7]+=*$/', $secret);
    }

    public function testTwoGeneratedSecretsAreDifferent(): void
    {
        self::assertNotSame(
            $this->totp->generateSecret(),
            $this->totp->generateSecret(),
        );
    }

    public function testGenerateSecretDefaultLengthIs20Bytes(): void
    {
        $secret = $this->totp->generateSecret();
        // 20 raw bytes → 32 base32 chars (padded to multiple of 8)
        self::assertGreaterThanOrEqual(32, strlen($secret));
    }

    // ─── Provisioning URI ─────────────────────────────────────────────

    public function testProvisioningUriStartsWithOtpauth(): void
    {
        $secret = $this->totp->generateSecret();
        $uri    = $this->totp->provisioningUri('alice@example.com', 'MyApp', $secret);
        self::assertStringStartsWith('otpauth://totp/', $uri);
    }

    public function testProvisioningUriContainsIssuer(): void
    {
        $secret = $this->totp->generateSecret();
        $uri    = $this->totp->provisioningUri('alice@example.com', 'Acme Corp', $secret);
        self::assertStringContainsString('issuer=Acme+Corp', $uri);
    }

    public function testProvisioningUriContainsAccountName(): void
    {
        $secret = $this->totp->generateSecret();
        $uri    = $this->totp->provisioningUri('alice@example.com', 'MyApp', $secret);
        self::assertStringContainsString('alice', $uri);
    }

    public function testProvisioningUriContainsSecret(): void
    {
        $secret = $this->totp->generateSecret();
        $uri    = $this->totp->provisioningUri('alice@example.com', 'MyApp', $secret);
        self::assertStringContainsString('secret=' . $secret, $uri);
    }

    public function testProvisioningUriContainsDigitsAndStep(): void
    {
        $secret = $this->totp->generateSecret();
        $uri    = $this->totp->provisioningUri('alice@example.com', 'MyApp', $secret);
        self::assertStringContainsString('digits=6', $uri);
        self::assertStringContainsString('period=30', $uri);
    }

    // ─── Verification ─────────────────────────────────────────────────

    public function testCurrentCodeVerifiesSuccessfully(): void
    {
        $secret = $this->totp->generateSecret();
        $code   = $this->totp->currentCode($secret);
        self::assertTrue($this->totp->verify($secret, $code));
    }

    public function testWrongCodeFailsVerification(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertFalse($this->totp->verify($secret, '000000'));
    }

    public function testEmptyCodeFailsVerification(): void
    {
        $secret = $this->totp->generateSecret();
        self::assertFalse($this->totp->verify($secret, ''));
    }

    public function testCodeForDifferentSecretFailsVerification(): void
    {
        $secret1 = $this->totp->generateSecret();
        $secret2 = $this->totp->generateSecret();
        $code    = $this->totp->currentCode($secret1);
        // Extremely unlikely to match, but not impossible — accept statistical reality
        if ($code !== $this->totp->currentCode($secret2)) {
            self::assertFalse($this->totp->verify($secret2, $code));
        } else {
            $this->markTestSkipped('Astronomically unlikely collision occurred');
        }
    }

    public function testCurrentCodeHasCorrectLength(): void
    {
        $secret = $this->totp->generateSecret();
        $code   = $this->totp->currentCode($secret);
        self::assertSame(6, strlen($code));
    }

    public function testCurrentCodeIsNumericString(): void
    {
        $secret = $this->totp->generateSecret();
        $code   = $this->totp->currentCode($secret);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
    }

    // ─── TotpConfig ───────────────────────────────────────────────────

    public function testTotpConfigStoresValues(): void
    {
        $config = new TotpConfig(digits: 8, step: 60, window: 2, algorithm: 'sha256');
        self::assertSame(8, $config->digits);
        self::assertSame(60, $config->step);
        self::assertSame(2, $config->window);
        self::assertSame('sha256', $config->algorithm);
    }

    public function testEightDigitTotpProducesEightDigitCode(): void
    {
        $totp   = new RfcTotp(new SecureRandom(), new TotpConfig(digits: 8, step: 30));
        $secret = $totp->generateSecret();
        $code   = $totp->currentCode($secret);
        self::assertSame(8, strlen($code));
    }
}
