<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Crypto;

use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\KeySet;
use PHPUnit\Framework\TestCase;

final class KeySetTest extends TestCase
{
    public function testGetReturnsKeyByKid(): void
    {
        $key    = new Key('kid1', 'HS256', 'secret', true);
        $keySet = new KeySet($key);

        self::assertSame($key, $keySet->get('kid1'));
    }

    public function testGetReturnsNullForUnknownKid(): void
    {
        $keySet = new KeySet();
        self::assertNull($keySet->get('nonexistent'));
    }

    public function testFirstReturnsFirstKey(): void
    {
        $key1 = new Key('k1', 'HS256', 's1', true);
        $key2 = new Key('k2', 'HS256', 's2', true);
        $keySet = new KeySet($key1, $key2);

        self::assertSame($key1, $keySet->first());
    }

    public function testAllReturnsAllKeys(): void
    {
        $key1 = new Key('k1', 'HS256', 's1', true);
        $key2 = new Key('k2', 'HS256', 's2', true);
        $keySet = new KeySet($key1, $key2);

        self::assertCount(2, $keySet->all());
    }
}
