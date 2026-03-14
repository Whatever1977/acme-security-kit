<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\OAuth2;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\OAuth2\PkceValidator;
use Acme\SecurityKit\OAuth2\TokenTtlPolicy;
use PHPUnit\Framework\TestCase;

final class OAuth2Test extends TestCase
{
    // ─── PkceValidator ────────────────────────────────────────────────

    private PkceValidator $pkce;

    protected function setUp(): void
    {
        $this->pkce = new PkceValidator(new HashEquals());
    }

    public function testChallengeFromVerifierIsBase64UrlSha256(): void
    {
        $verifier   = base64_encode(random_bytes(32));
        $challenge  = $this->pkce->challenge($verifier);

        // Manually compute expected challenge
        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        self::assertSame($expected, $challenge);
    }

    public function testValidateReturnsTrueForMatchingVerifierAndChallenge(): void
    {
        $verifier  = base64_encode(random_bytes(32));
        $challenge = $this->pkce->challenge($verifier);

        self::assertTrue($this->pkce->validate($verifier, $challenge, 'S256'));
    }

    public function testValidateReturnsFalseForWrongVerifier(): void
    {
        $verifier  = base64_encode(random_bytes(32));
        $challenge = $this->pkce->challenge($verifier);

        self::assertFalse($this->pkce->validate('wrong-verifier', $challenge, 'S256'));
    }

    public function testValidateReturnsFalseForTamperedChallenge(): void
    {
        $verifier  = base64_encode(random_bytes(32));
        $challenge = $this->pkce->challenge($verifier);

        self::assertFalse($this->pkce->validate($verifier, $challenge . 'X', 'S256'));
    }

    public function testValidateRejectsPLainMethod(): void
    {
        $verifier  = 'some-verifier';
        $challenge = $verifier; // plain: challenge = verifier

        self::assertFalse($this->pkce->validate($verifier, $challenge, 'plain'));
    }

    public function testValidateRejectsUnknownMethod(): void
    {
        $verifier  = base64_encode(random_bytes(32));
        $challenge = $this->pkce->challenge($verifier);

        self::assertFalse($this->pkce->validate($verifier, $challenge, 'S512'));
    }

    public function testValidateRejectsEmptyVerifier(): void
    {
        $challenge = $this->pkce->challenge('real-verifier');
        self::assertFalse($this->pkce->validate('', $challenge, 'S256'));
    }

    public function testValidateRejectsEmptyChallenge(): void
    {
        $verifier = base64_encode(random_bytes(32));
        self::assertFalse($this->pkce->validate($verifier, '', 'S256'));
    }

    public function testTwoDifferentVerifiersProduceDifferentChallenges(): void
    {
        $v1 = base64_encode(random_bytes(32));
        $v2 = base64_encode(random_bytes(32));
        self::assertNotSame($this->pkce->challenge($v1), $this->pkce->challenge($v2));
    }

    // ─── TokenTtlPolicy ───────────────────────────────────────────────

    public function testTokenTtlPolicyStoresValues(): void
    {
        $policy = new TokenTtlPolicy(
            accessTokenTtlSeconds: 3600,
            refreshTokenTtlSeconds: 2592000,
            rotateRefreshTokens: true,
            detectRefreshTokenReuse: true,
        );

        self::assertSame(3600, $policy->accessTokenTtlSeconds);
        self::assertSame(2592000, $policy->refreshTokenTtlSeconds);
        self::assertTrue($policy->rotateRefreshTokens);
        self::assertTrue($policy->detectRefreshTokenReuse);
    }

    public function testTokenTtlPolicyDefaultRotateFalse(): void
    {
        $policy = new TokenTtlPolicy(
            accessTokenTtlSeconds: 3600,
            refreshTokenTtlSeconds: 86400,
        );
        self::assertFalse($policy->rotateRefreshTokens);
        self::assertFalse($policy->detectRefreshTokenReuse);
    }

    public function testAccessTokenExpiryComputation(): void
    {
        $policy    = new TokenTtlPolicy(accessTokenTtlSeconds: 900, refreshTokenTtlSeconds: 86400);
        $issuedAt  = new \DateTimeImmutable('2025-01-01T00:00:00Z');
        $expiresAt = $issuedAt->modify("+{$policy->accessTokenTtlSeconds} seconds");

        self::assertSame('2025-01-01T00:15:00+00:00', $expiresAt->format(\DateTimeInterface::ATOM));
    }

    public function testRefreshTokenExpiryComputation(): void
    {
        $policy    = new TokenTtlPolicy(accessTokenTtlSeconds: 3600, refreshTokenTtlSeconds: 2592000);
        $issuedAt  = new \DateTimeImmutable('2025-01-01T00:00:00Z');
        $expiresAt = $issuedAt->modify("+{$policy->refreshTokenTtlSeconds} seconds");

        // 2592000 seconds = 30 days
        self::assertSame('2025-01-31T00:00:00+00:00', $expiresAt->format(\DateTimeInterface::ATOM));
    }
}
