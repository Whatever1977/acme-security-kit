<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Password;

use Acme\SecurityKit\Password\PasswordPolicy;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function testSatisfiesStrongPassword(): void
    {
        $policy = new PasswordPolicy();
        self::assertTrue($policy->satisfies('StrongP@ssword1'));
    }

    public function testFailsShortPassword(): void
    {
        $policy = new PasswordPolicy(minLength: 12);
        $violations = $policy->validate('Short1!');
        self::assertNotEmpty($violations);
    }

    public function testFailsMissingSymbol(): void
    {
        $policy = new PasswordPolicy();
        $violations = $policy->validate('StrongPassword1');
        self::assertNotEmpty($violations);
    }

    public function testFailsMissingDigit(): void
    {
        $policy = new PasswordPolicy();
        $violations = $policy->validate('StrongPassword!');
        self::assertNotEmpty($violations);
    }

    public function testCustomPolicyRelaxed(): void
    {
        $policy = new PasswordPolicy(
            minLength: 6,
            requireUpper: false,
            requireLower: false,
            requireDigit: false,
            requireSymbol: false,
        );
        self::assertTrue($policy->satisfies('simple'));
    }
}
