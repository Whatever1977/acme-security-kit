<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Crypto;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\KeySet;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    // ─── HashEquals ───────────────────────────────────────────────────

    public function testHashEqualsReturnsTrueForEqualStrings(): void
    {
        $ct = new HashEquals();
        self::assertTrue($ct->equals('abc', 'abc'));
    }

    public function testHashEqualsReturnsFalseForDifferentStrings(): void
    {
        $ct = new HashEquals();
        self::assertFalse($ct->equals('abc', 'xyz'));
    }

    public function testHashEqualsReturnsFalseForDifferentLengths(): void
    {
        $ct = new HashEquals();
        self::assertFalse($ct->equals('abc', 'abcd'));
    }

    public function testHashEqualsHandlesEmptyStrings(): void
    {
        $ct = new HashEquals();
        self::assertTrue($ct->equals('', ''));
        self::assertFalse($ct->equals('', 'a'));
    }

    public function testHashEqualsHandlesBinaryStrings(): void
    {
        $ct  = new HashEquals();
        $bin = random_bytes(32);
        self::assertTrue($ct->equals($bin, $bin));
        self::assertFalse($ct->equals($bin, random_bytes(32)));
    }

    // ─── Key ──────────────────────────────────────────────────────────

    public function testKeyStoresAllProperties(): void
    {
        $notAfter = new \DateTimeImmutable('+1 year');
        $key = new Key('kid-1', 'HS256', 'secret', isSymmetric: true, notAfter: $notAfter);

        self::assertSame('kid-1', $key->kid);
        self::assertSame('HS256', $key->algorithm);
        self::assertSame('secret', $key->material);
        self::assertTrue($key->isSymmetric);
        self::assertSame($notAfter, $key->notAfter);
    }

    public function testKeyIsNotExpiredByDefault(): void
    {
        $key = new Key('k', 'HS256', 's', isSymmetric: true);
        self::assertFalse($key->isExpired());
    }

    public function testKeyWithNullNotAfterIsNeverExpired(): void
    {
        $key = new Key('k', 'HS256', 's', isSymmetric: true, notAfter: null);
        self::assertFalse($key->isExpired(new \DateTimeImmutable('+100 years')));
    }

    public function testKeyIsExpiredWhenPastNotAfter(): void
    {
        $pastDate = new \DateTimeImmutable('-1 day');
        $key      = new Key('k', 'HS256', 's', isSymmetric: true, notAfter: $pastDate);
        self::assertTrue($key->isExpired());
    }

    public function testKeyIsNotExpiredBeforeNotAfter(): void
    {
        $futureDate = new \DateTimeImmutable('+1 day');
        $key        = new Key('k', 'HS256', 's', isSymmetric: true, notAfter: $futureDate);
        self::assertFalse($key->isExpired());
    }

    public function testKeyExpiryCheckedAtSpecificTime(): void
    {
        $notAfter = new \DateTimeImmutable('2025-01-01T00:00:00Z');
        $key      = new Key('k', 'HS256', 's', isSymmetric: true, notAfter: $notAfter);

        $before = new \DateTimeImmutable('2024-12-31T23:59:59Z');
        $after  = new \DateTimeImmutable('2025-01-01T00:00:01Z');

        self::assertFalse($key->isExpired($before));
        self::assertTrue($key->isExpired($after));
    }

    // ─── KeySet ───────────────────────────────────────────────────────

    public function testKeySetGetReturnsKeyByKid(): void
    {
        $key1 = new Key('k1', 'HS256', 's1', isSymmetric: true);
        $key2 = new Key('k2', 'HS256', 's2', isSymmetric: true);
        $ks   = new KeySet($key1, $key2);

        self::assertSame($key1, $ks->get('k1'));
        self::assertSame($key2, $ks->get('k2'));
    }

    public function testKeySetGetReturnsNullForUnknownKid(): void
    {
        $ks = new KeySet(new Key('k1', 'HS256', 's', isSymmetric: true));
        self::assertNull($ks->get('unknown'));
    }

    public function testKeySetAllReturnsAllKeys(): void
    {
        $k1 = new Key('k1', 'HS256', 's1', isSymmetric: true);
        $k2 = new Key('k2', 'HS256', 's2', isSymmetric: true);
        $ks = new KeySet($k1, $k2);

        self::assertCount(2, $ks->all());
    }

    // ─── InMemoryKeyProvider ──────────────────────────────────────────

    public function testInMemoryKeyProviderCurrentReturnsKeySet(): void
    {
        $key      = new Key('k1', 'HS256', 's', isSymmetric: true);
        $provider = new InMemoryKeyProvider($key);

        $ks = $provider->current();
        self::assertInstanceOf(KeySet::class, $ks);
        self::assertSame($key, $ks->get('k1'));
    }

    public function testInMemoryKeyProviderByKidFindsKey(): void
    {
        $key      = new Key('my-kid', 'HS256', 'material', isSymmetric: true);
        $provider = new InMemoryKeyProvider($key);

        self::assertSame($key, $provider->byKid('my-kid'));
    }

    public function testInMemoryKeyProviderByKidReturnsNullForMissing(): void
    {
        $provider = new InMemoryKeyProvider(new Key('k1', 'HS256', 's', isSymmetric: true));
        self::assertNull($provider->byKid('nonexistent'));
    }

    public function testInMemoryKeyProviderWithMultipleKeys(): void
    {
        $k1 = new Key('k1', 'HS256', 'a', isSymmetric: true);
        $k2 = new Key('k2', 'HS256', 'b', isSymmetric: true);
        $k3 = new Key('k3', 'HS256', 'c', isSymmetric: true);

        $provider = new InMemoryKeyProvider($k1, $k2, $k3);

        self::assertSame($k1, $provider->byKid('k1'));
        self::assertSame($k2, $provider->byKid('k2'));
        self::assertSame($k3, $provider->byKid('k3'));
        self::assertNull($provider->byKid('k4'));
    }
}
