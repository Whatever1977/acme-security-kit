<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

final class PasswordPolicy
{
    public function __construct(
        public readonly int $minLength = 12,
        public readonly bool $requireUpper = true,
        public readonly bool $requireLower = true,
        public readonly bool $requireDigit = true,
        public readonly bool $requireSymbol = true,
        public readonly bool $checkPwned = false,
    ) {}

    /** @return list<string> A list of violation messages, empty if policy is satisfied */
    public function validate(string $password): array
    {
        $violations = [];

        if (mb_strlen($password) < $this->minLength) {
            $violations[] = "Password must be at least {$this->minLength} characters.";
        }
        if ($this->requireUpper && !preg_match('/[A-Z]/', $password)) {
            $violations[] = 'Password must contain at least one uppercase letter.';
        }
        if ($this->requireLower && !preg_match('/[a-z]/', $password)) {
            $violations[] = 'Password must contain at least one lowercase letter.';
        }
        if ($this->requireDigit && !preg_match('/[0-9]/', $password)) {
            $violations[] = 'Password must contain at least one digit.';
        }
        if ($this->requireSymbol && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $violations[] = 'Password must contain at least one symbol.';
        }

        return $violations;
    }

    public function satisfies(string $password): bool
    {
        return $this->validate($password) === [];
    }
}
