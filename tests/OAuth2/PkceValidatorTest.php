<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\OAuth2;

use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\OAuth2\PkceValidator;
use PHPUnit\Framework\TestCase;

final class PkceValidatorTest extends TestCase
{
    private PkceValidator $pkce;

    protected function setUp(): void
    {
        $this->pkce = new PkceValidator(new HashEquals());
    }

    public function testValidVerifier(): void
    {
        $verifier   = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $challenge  = $this->pkce->challenge($verifier);
        self::assertTrue($this->pkce->validate($verifier, $challenge, 'S256'));
    }

    public function testInvalidVerifier(): void
    {
        $challenge = $this->pkce->challenge('correct-verifier');
        self::assertFalse($this->pkce->validate('wrong-verifier', $challenge, 'S256'));
    }

    public function testPlainMethodRejected(): void
    {
        self::assertFalse($this->pkce->validate('anything', 'anything', 'plain'));
    }
}
