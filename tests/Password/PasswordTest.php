<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Password;

use Acme\SecurityKit\Password\Argon2idHasher;
use Acme\SecurityKit\Password\PasswordPolicy;
use Acme\SecurityKit\Password\PolicyAwareHasher;
use Acme\SecurityKit\Password\WeakPasswordException;
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    // ─── Argon2idHasher ───────────────────────────────────────────────

    public function testHashProducesArgon2idHash(): void
    {
        $hasher = new Argon2idHasher();
        $hash   = $hasher->hash('correct-Horse-Battery-9');
        self::assertStringStartsWith('$argon2id$', $hash);
    }

    public function testVerifyReturnsTrueForCorrectPassword(): void
    {
        $hasher = new Argon2idHasher();
        $hash   = $hasher->hash('my-secret-pass!1');
        self::assertTrue($hasher->verify('my-secret-pass!1', $hash));
    }

    public function testVerifyReturnsFalseForWrongPassword(): void
    {
        $hasher = new Argon2idHasher();
        $hash   = $hasher->hash('correct-password');
        self::assertFalse($hasher->verify('wrong-password', $hash));
    }

    public function testVerifyReturnsFalseForEmptyPassword(): void
    {
        $hasher = new Argon2idHasher();
        $hash   = $hasher->hash('correct-password');
        self::assertFalse($hasher->verify('', $hash));
    }

    public function testTwoHashesOfSamePasswordAreDifferent(): void
    {
        $hasher = new Argon2idHasher();
        $h1     = $hasher->hash('password123!A');
        $h2     = $hasher->hash('password123!A');
        // Argon2id uses a random salt each time
        self::assertNotSame($h1, $h2);
        // Both must still verify correctly
        self::assertTrue($hasher->verify('password123!A', $h1));
        self::assertTrue($hasher->verify('password123!A', $h2));
    }

    public function testNeedsRehashReturnsFalseForFreshHash(): void
    {
        $hasher = new Argon2idHasher();
        $hash   = $hasher->hash('passWord!9');
        self::assertFalse($hasher->needsRehash($hash));
    }

    public function testNeedsRehashReturnsTrueForBcryptHash(): void
    {
        $hasher     = new Argon2idHasher();
        $bcryptHash = password_hash('test', PASSWORD_BCRYPT);
        self::assertTrue($hasher->needsRehash($bcryptHash));
    }

    // ─── PasswordPolicy ───────────────────────────────────────────────

    public function testPolicyAcceptsStrongPassword(): void
    {
        $policy     = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true);
        $violations = $policy->validate('Correct-Horse-Battery-9!');
        self::assertEmpty($violations);
    }

    public function testPolicySatisfiesReturnsTrueForStrongPassword(): void
    {
        $policy = new PasswordPolicy(minLength: 8, requireUpper: true, requireDigit: true);
        self::assertTrue($policy->satisfies('StrongPass9'));
    }

    public function testPolicyRejectsTooShortPassword(): void
    {
        $policy     = new PasswordPolicy(minLength: 12);
        $violations = $policy->validate('short');
        self::assertNotEmpty($violations);
        self::assertStringContainsString('12', implode('', $violations));
    }

    public function testPolicyRequiresUppercase(): void
    {
        $policy     = new PasswordPolicy(requireUpper: true);
        $violations = $policy->validate('alllowercase123!');
        self::assertNotEmpty($violations);
    }

    public function testPolicyRequiresLowercase(): void
    {
        $policy     = new PasswordPolicy(requireLower: true);
        $violations = $policy->validate('ALLUPPERCASE123!');
        self::assertNotEmpty($violations);
    }

    public function testPolicyRequiresDigit(): void
    {
        $policy     = new PasswordPolicy(requireDigit: true);
        $violations = $policy->validate('NoDigitsHere!');
        self::assertNotEmpty($violations);
    }

    public function testPolicyRequiresSymbol(): void
    {
        $policy     = new PasswordPolicy(requireSymbol: true);
        $violations = $policy->validate('NoSymbolsHere1A');
        self::assertNotEmpty($violations);
    }

    public function testPolicySatisfiesReturnsFalseForWeakPassword(): void
    {
        $policy = new PasswordPolicy(minLength: 12);
        self::assertFalse($policy->satisfies('weak'));
    }

    public function testPolicyAcceptsPasswordExactlyAtMinLength(): void
    {
        $policy     = new PasswordPolicy(minLength: 8);
        $violations = $policy->validate('Exact8!A');
        // Length check should pass; other checks may apply depending on settings
        $lengthViolations = array_filter($violations, fn($v) => str_contains($v, '8'));
        self::assertEmpty($lengthViolations);
    }

    // ─── PolicyAwareHasher ────────────────────────────────────────────

    public function testPolicyAwareHasherHashesStrongPassword(): void
    {
        $hasher = new PolicyAwareHasher(
            inner: new Argon2idHasher(),
            policy: new PasswordPolicy(minLength: 8, requireUpper: true),
        );
        $hash = $hasher->hash('StrongPass9');
        self::assertStringStartsWith('$argon2id$', $hash);
    }

    public function testPolicyAwareHasherThrowsForWeakPassword(): void
    {
        $this->expectException(WeakPasswordException::class);

        $hasher = new PolicyAwareHasher(
            inner: new Argon2idHasher(),
            policy: new PasswordPolicy(minLength: 20),
        );
        $hasher->hash('tooshort');
    }

    public function testWeakPasswordExceptionContainsViolations(): void
    {
        $hasher = new PolicyAwareHasher(
            inner: new Argon2idHasher(),
            policy: new PasswordPolicy(minLength: 20, requireUpper: true, requireDigit: true),
        );

        try {
            $hasher->hash('weak');
            self::fail('Expected WeakPasswordException');
        } catch (WeakPasswordException $e) {
            self::assertNotEmpty($e->getViolations());
        }
    }

    public function testPolicyAwareHasherVerifyDelegatesToInner(): void
    {
        $inner  = new Argon2idHasher();
        $hasher = new PolicyAwareHasher($inner, new PasswordPolicy());
        $hash   = $inner->hash('CorrectPass9!');
        self::assertTrue($hasher->verify('CorrectPass9!', $hash));
        self::assertFalse($hasher->verify('WrongPass9!', $hash));
    }

    public function testPolicyAwareHasherNeedsRehashDelegatesToInner(): void
    {
        $inner      = new Argon2idHasher();
        $hasher     = new PolicyAwareHasher($inner, new PasswordPolicy());
        $bcryptHash = password_hash('x', PASSWORD_BCRYPT);
        self::assertTrue($hasher->needsRehash($bcryptHash));
    }
}
