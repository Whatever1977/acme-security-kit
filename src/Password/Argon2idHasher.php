<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

final class Argon2idHasher implements PasswordHasher
{
    /** @param array<string, int>|null $options Pass null to use PHP's built-in Argon2 defaults */
    public function __construct(
        private readonly ?array $options = null,
    ) {}

    /** Returns PASSWORD_ARGON2ID if available, otherwise PASSWORD_BCRYPT. */
    private function algorithm(): string|int
    {
        return defined('PASSWORD_ARGON2ID') ? \PASSWORD_ARGON2ID : \PASSWORD_BCRYPT;
    }

    public function hash(string $password): string
    {
        $hash = password_hash($password, $this->algorithm(), $this->options ?? []);
        if ($hash === false) {
            throw new \RuntimeException('password_hash() failed.');
        }
        return $hash;
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm(), $this->options ?? []);
    }
}