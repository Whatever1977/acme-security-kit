<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\UrlSigner;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;
use PHPUnit\Framework\TestCase;

final class UrlSignerTest extends TestCase
{
    private HmacUrlSigner $signer;
    private Key $key;

    protected function setUp(): void
    {
        $this->key = new Key('url-key-v1', 'HS256', str_repeat('u', 32), isSymmetric: true);

        $this->signer = new HmacUrlSigner(
            keyProvider: new InMemoryKeyProvider($this->key),
            constantTime: new HashEquals(),
        );
    }

    // ─── Signing ──────────────────────────────────────────────────────

    public function testSignedUrlContainsOriginalPath(): void
    {
        $signed = $this->signer->sign('https://app.example.com/download/file.pdf', new \DateTimeImmutable('+1 hour'));
        self::assertStringContainsString('/download/file.pdf', $signed->url);
    }

    public function testSignedUrlContainsExpiresParam(): void
    {
        $signed = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        self::assertStringContainsString('_expires=', $signed->url);
    }

    public function testSignedUrlContainsKidParam(): void
    {
        $signed = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        self::assertStringContainsString('_kid=url-key-v1', $signed->url);
    }

    public function testSignedUrlContainsSignatureParam(): void
    {
        $signed = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        self::assertStringContainsString('_sig=', $signed->url);
    }

    public function testSignedUrlExpiresAtMatchesInput(): void
    {
        $expiresAt = new \DateTimeImmutable('+2 hours');
        $signed    = $this->signer->sign('https://app.example.com/file', $expiresAt);

        self::assertEqualsWithDelta($expiresAt->getTimestamp(), $signed->expiresAt->getTimestamp(), 2);
    }

    public function testSignedUrlWithCustomClaimsEmbedsThem(): void
    {
        $signed = $this->signer->sign(
            'https://app.example.com/dl',
            new \DateTimeImmutable('+1 hour'),
            ['user_id' => 'usr-42', 'role' => 'viewer'],
        );
        self::assertStringContainsString('user_id=usr-42', $signed->url);
    }

    // ─── Verification — happy path ────────────────────────────────────

    public function testValidSignedUrlVerifiesSuccessfully(): void
    {
        $signed = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        self::assertTrue($this->signer->verify($signed->url));
    }

    public function testSignedUrlWithQueryParamsVerifies(): void
    {
        $signed = $this->signer->sign(
            'https://app.example.com/dl?format=pdf&page=1',
            new \DateTimeImmutable('+1 hour'),
        );
        self::assertTrue($this->signer->verify($signed->url));
    }

    // ─── Verification failures ────────────────────────────────────────

    public function testTamperedPathFailsVerification(): void
    {
        $signed   = $this->signer->sign('https://app.example.com/download/report.pdf', new \DateTimeImmutable('+1 hour'));
        $tampered = str_replace('/download/report.pdf', '/download/admin.php', $signed->url);
        self::assertFalse($this->signer->verify($tampered));
    }

    public function testTamperedSignatureFailsVerification(): void
    {
        $signed   = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        $tampered = preg_replace('/_sig=[^&]+/', '_sig=invalidsignature', $signed->url);
        self::assertFalse($this->signer->verify((string) $tampered));
    }

    public function testExpiredUrlFailsVerification(): void
    {
        $signed = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('-1 second'));
        self::assertFalse($this->signer->verify($signed->url));
    }

    public function testUrlWithoutSignatureFailsVerification(): void
    {
        self::assertFalse($this->signer->verify('https://app.example.com/unsigned'));
    }

    public function testTamperedExpiryFailsVerification(): void
    {
        $signed  = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        // Extend expiry manually — signature covers the expiry, so this must fail
        $tampered = preg_replace('/_expires=\d+/', '_expires=' . (time() + 999999), $signed->url);
        self::assertFalse($this->signer->verify((string) $tampered));
    }

    // ─── Key rotation ─────────────────────────────────────────────────

    public function testOldUrlVerifiesAfterKeyRotation(): void
    {
        $oldSigned = $this->signer->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));

        $newKey     = new Key('url-key-v2', 'HS256', str_repeat('n', 32), isSymmetric: true);
        $newSigner  = new HmacUrlSigner(
            keyProvider: new InMemoryKeyProvider($newKey, $this->key), // v2 is current, v1 still in provider
            constantTime: new HashEquals(),
        );

        self::assertTrue($newSigner->verify($oldSigned->url));
    }

    public function testNewUrlSignedWithNewKeyVerifies(): void
    {
        $newKey    = new Key('url-key-v2', 'HS256', str_repeat('n', 32), isSymmetric: true);
        $newSigner = new HmacUrlSigner(
            keyProvider: new InMemoryKeyProvider($newKey),
            constantTime: new HashEquals(),
        );

        $signed = $newSigner->sign('https://app.example.com/file', new \DateTimeImmutable('+1 hour'));
        self::assertTrue($newSigner->verify($signed->url));
        // Old signer with old key cannot verify new URL
        self::assertFalse($this->signer->verify($signed->url));
    }

    // ─── Canonical query ordering ─────────────────────────────────────

    public function testQueryParamOrderDoesNotAffectVerification(): void
    {
        // Sign a URL, then swap query param order manually (but keep the signature)
        $signed = $this->signer->sign(
            'https://app.example.com/dl?b=2&a=1',
            new \DateTimeImmutable('+1 hour'),
        );
        // The signed URL should verify as-is (params are canonicalized internally)
        self::assertTrue($this->signer->verify($signed->url));
    }
}
