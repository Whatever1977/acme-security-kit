<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

/**
 * Decorator that enforces PasswordPolicy before hashing,
 * and optionally checks breach databases.
 */
final class PolicyAwareHasher implements PasswordHasher
{
    public function __construct(
        private readonly PasswordHasher $inner,
        private readonly PasswordPolicy $policy,
        private readonly ?PwnedPasswordChecker $pwnedChecker = null,
    ) {}

    public function hash(string $password): string
    {
        $violations = $this->policy->validate($password);
        if ($violations !== []) {
            throw new WeakPasswordException($violations);
        }

        if ($this->policy->checkPwned && $this->pwnedChecker?->isBreached($password)) {
            throw new WeakPasswordException(['Password has appeared in a data breach. Choose a different password.']);
        }

        return $this->inner->hash($password);
    }

    public function verify(string $password, string $hash): bool
    {
        return $this->inner->verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return $this->inner->needsRehash($hash);
    }
}
