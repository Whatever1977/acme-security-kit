<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Crypto;

use Acme\SecurityKit\Crypto\SecureRandom;
use PHPUnit\Framework\TestCase;

final class SecureRandomTest extends TestCase
{
    private SecureRandom $random;

    protected function setUp(): void
    {
        $this->random = new SecureRandom();
    }

    public function testBytesReturnsCorrectLength(): void
    {
        $bytes = $this->random->bytes(32);
        self::assertSame(32, strlen($bytes));
    }

    public function testBytesAreDifferentEachCall(): void
    {
        $a = $this->random->bytes(32);
        $b = $this->random->bytes(32);
        self::assertNotSame($a, $b);
    }

    public function testBase64UrlReturnsUrlSafeString(): void
    {
        $result = $this->random->base64Url(32);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $result);
    }

    public function testThrowsOnZeroLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->random->bytes(0);
    }

    public function testThrowsOnNegativeLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->random->bytes(-1);
    }
}
