<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Crypto;

use Acme\SecurityKit\Crypto\HashEquals;
use PHPUnit\Framework\TestCase;

final class HashEqualsTest extends TestCase
{
    private HashEquals $ct;

    protected function setUp(): void
    {
        $this->ct = new HashEquals();
    }

    public function testEqualStrings(): void
    {
        self::assertTrue($this->ct->equals('abc', 'abc'));
    }

    public function testDifferentStrings(): void
    {
        self::assertFalse($this->ct->equals('abc', 'xyz'));
    }

    public function testDifferentLengths(): void
    {
        self::assertFalse($this->ct->equals('abc', 'abcd'));
    }

    public function testEmptyStrings(): void
    {
        self::assertTrue($this->ct->equals('', ''));
    }
}
