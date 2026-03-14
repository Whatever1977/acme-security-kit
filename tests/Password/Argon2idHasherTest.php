<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Password;

use Acme\SecurityKit\Password\Argon2idHasher;
use PHPUnit\Framework\TestCase;

final class Argon2idHasherTest extends TestCase
{
    private Argon2idHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new Argon2idHasher();
    }

    public function testHashAndVerify(): void
    {
        $hash = $this->hasher->hash('correct-horse-battery-staple!1A');
        self::assertTrue($this->hasher->verify('correct-horse-battery-staple!1A', $hash));
    }

    public function testVerifyReturnsFalseForWrongPassword(): void
    {
        $hash = $this->hasher->hash('correct-horse-battery-staple!1A');
        self::assertFalse($this->hasher->verify('wrong-password', $hash));
    }

    public function testHashesAreDifferentForSamePassword(): void
    {
        $a = $this->hasher->hash('password1A!');
        $b = $this->hasher->hash('password1A!');
        self::assertNotSame($a, $b); // different salts
    }
}
