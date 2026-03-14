<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Jwt;

use Acme\SecurityKit\Audit\NullAuditor;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Jwt\FirebaseJwtManager;
use Acme\SecurityKit\Jwt\JwtConfig;
use Acme\SecurityKit\Jwt\JwtException;
use PHPUnit\Framework\TestCase;

final class JwtTest extends TestCase
{
    private FirebaseJwtManager $manager;
    private Key $key;

    protected function setUp(): void
    {
        $this->key = new Key('test-key-v1', 'HS256', str_repeat('k', 32), isSymmetric: true);

        $this->manager = new FirebaseJwtManager(
            config: new JwtConfig(
                issuer: 'https://auth.example.com',
                audience: 'https://api.example.com',
                requireJti: true,
                algorithm: 'HS256',
                clockSkewSeconds: 0,
            ),
            keyProvider: new InMemoryKeyProvider($this->key),
            random: new SecureRandom(),
            auditor: new NullAuditor(),
        );
    }

    // ─── Minting ──────────────────────────────────────────────────────

    public function testMintReturnsNonEmptyString(): void
    {
        $jwt = $this->manager->mint(['sub' => 'u-1'], new \DateTimeImmutable('+1 hour'));
        self::assertNotEmpty($jwt);
    }

    public function testMintedTokenHasThreeParts(): void
    {
        $jwt = $this->manager->mint(['sub' => 'u-1'], new \DateTimeImmutable('+1 hour'));
        self::assertCount(3, explode('.', $jwt));
    }

    public function testTwoMintsProduceDifferentJtiValues(): void
    {
        $j1 = $this->manager->mint(['sub' => 'u-1'], new \DateTimeImmutable('+1 hour'));
        $j2 = $this->manager->mint(['sub' => 'u-1'], new \DateTimeImmutable('+1 hour'));
        self::assertNotSame($j1, $j2);
    }

    // ─── Validation — happy path ──────────────────────────────────────

    public function testValidTokenParsesAndValidates(): void
    {
        $jwt      = $this->manager->mint(['sub' => 'user-42'], new \DateTimeImmutable('+1 hour'));
        $verified = $this->manager->parseAndValidate($jwt);

        self::assertSame('user-42', $verified->claim('sub'));
    }

    public function testVerifiedTokenExposesKid(): void
    {
        $jwt      = $this->manager->mint(['sub' => 'u'], new \DateTimeImmutable('+1 hour'));
        $verified = $this->manager->parseAndValidate($jwt);

        self::assertSame('test-key-v1', $verified->kid);
    }

    public function testVerifiedTokenExposesExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable('+1 hour');
        $jwt       = $this->manager->mint(['sub' => 'u'], $expiresAt);
        $verified  = $this->manager->parseAndValidate($jwt);

        // Allow 2-second tolerance for test execution time
        self::assertEqualsWithDelta(
            $expiresAt->getTimestamp(),
            $verified->expiresAt->getTimestamp(),
            2,
        );
    }

    public function testVerifiedTokenExposesCustomClaims(): void
    {
        $jwt      = $this->manager->mint(
            ['sub' => 'u', 'roles' => ['editor', 'viewer'], 'tenantId' => 'acme'],
            new \DateTimeImmutable('+1 hour'),
        );
        $verified = $this->manager->parseAndValidate($jwt);

        self::assertSame(['editor', 'viewer'], $verified->claim('roles'));
        self::assertSame('acme', $verified->claim('tenantId'));
    }

    public function testVerifiedTokenClaimReturnsNullForMissingClaim(): void
    {
        $jwt      = $this->manager->mint(['sub' => 'u'], new \DateTimeImmutable('+1 hour'));
        $verified = $this->manager->parseAndValidate($jwt);

        self::assertNull($verified->claim('nonexistent'));
    }

    // ─── Validation failures ──────────────────────────────────────────

    public function testExpiredTokenThrowsJwtException(): void
    {
        $this->expectException(JwtException::class);

        $jwt = $this->manager->mint(['sub' => 'u'], new \DateTimeImmutable('-1 second'));
        $this->manager->parseAndValidate($jwt);
    }

    public function testTamperedTokenThrowsJwtException(): void
    {
        $this->expectException(JwtException::class);

        $jwt      = $this->manager->mint(['sub' => 'u'], new \DateTimeImmutable('+1 hour'));
        $parts    = explode('.', $jwt);
        $parts[1] = base64_encode('{"sub":"hacker","iss":"https://auth.example.com"}');
        $tampered = implode('.', $parts);

        $this->manager->parseAndValidate($tampered);
    }

    public function testRandomStringThrowsJwtException(): void
    {
        $this->expectException(JwtException::class);
        $this->manager->parseAndValidate('not.a.jwt');
    }

    public function testEmptyStringThrowsJwtException(): void
    {
        $this->expectException(JwtException::class);
        $this->manager->parseAndValidate('');
    }

    public function testTokenSignedWithWrongKeyThrowsJwtException(): void
    {
        $this->expectException(JwtException::class);

        $otherKey     = new Key('other-key', 'HS256', str_repeat('z', 32), isSymmetric: true);
        $otherManager = new FirebaseJwtManager(
            config: new JwtConfig('https://auth.example.com', 'https://api.example.com'),
            keyProvider: new InMemoryKeyProvider($otherKey),
            random: new SecureRandom(),
        );

        $jwt = $otherManager->mint(['sub' => 'u'], new \DateTimeImmutable('+1 hour'));
        $this->manager->parseAndValidate($jwt);
    }

    // ─── Key rotation ─────────────────────────────────────────────────

    public function testKeyRotationOldTokenStillVerifies(): void
    {
        // Mint with old key
        $oldJwt = $this->manager->mint(['sub' => 'u'], new \DateTimeImmutable('+1 hour'));

        // Rotate: new key is current, old key still in provider
        $newKey      = new Key('test-key-v2', 'HS256', str_repeat('n', 32), isSymmetric: true);
        $rotated     = new FirebaseJwtManager(
            config: new JwtConfig('https://auth.example.com', 'https://api.example.com'),
            keyProvider: new InMemoryKeyProvider($newKey, $this->key),
            random: new SecureRandom(),
        );

        // Old token must still verify
        $verified = $rotated->parseAndValidate($oldJwt);
        self::assertSame('u', $verified->claim('sub'));
    }

    // ─── JwtConfig ────────────────────────────────────────────────────

    public function testJwtConfigDefaults(): void
    {
        $config = new JwtConfig('https://iss.example.com', 'aud');
        self::assertSame('https://iss.example.com', $config->issuer);
        self::assertSame('aud', $config->audience);
    }
}
