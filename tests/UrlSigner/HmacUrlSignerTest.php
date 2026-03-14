<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\UrlSigner;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;
use PHPUnit\Framework\TestCase;

final class HmacUrlSignerTest extends TestCase
{
    private HmacUrlSigner $signer;

    protected function setUp(): void
    {
        $key    = new Key('key-1', 'HS256', 'a-very-secret-key-for-url-signing', true);
        $this->signer = new HmacUrlSigner(
            keyProvider: new InMemoryKeyProvider($key),
            constantTime: new HashEquals(),
        );
    }

    public function testSignReturnsSignedUrl(): void
    {
        $expires = new \DateTimeImmutable('+1 hour');
        $signed  = $this->signer->sign('https://example.com/download', $expires);
        self::assertStringContainsString('_sig=', $signed->url);
        self::assertStringContainsString('_kid=key-1', $signed->url);
    }

    public function testVerifyReturnsTrueForValidUrl(): void
    {
        $expires = new \DateTimeImmutable('+1 hour');
        $signed  = $this->signer->sign('https://example.com/download', $expires);
        self::assertTrue($this->signer->verify($signed->url));
    }

    public function testVerifyReturnsFalseForTamperedUrl(): void
    {
        $expires = new \DateTimeImmutable('+1 hour');
        $signed  = $this->signer->sign('https://example.com/download', $expires);
        self::assertFalse($this->signer->verify($signed->url . '&extra=tampered'));
    }

    public function testVerifyReturnsFalseForExpiredUrl(): void
    {
        $expires = new \DateTimeImmutable('-1 second');
        $signed  = $this->signer->sign('https://example.com/download', $expires);
        self::assertFalse($this->signer->verify($signed->url));
    }

    public function testCanonicalOrdering(): void
    {
        $expires = new \DateTimeImmutable('+1 hour');
        $signed1 = $this->signer->sign('https://example.com/?b=2&a=1', $expires);
        $signed2 = $this->signer->sign('https://example.com/?a=1&b=2', $expires);
        // Both should be verifiable (canonical form strips order differences)
        self::assertTrue($this->signer->verify($signed1->url));
        self::assertTrue($this->signer->verify($signed2->url));
    }
}
