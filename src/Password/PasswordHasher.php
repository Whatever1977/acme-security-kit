<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

interface PasswordHasher
{
    public function hash(string $password): string;
    public function verify(string $password, string $hash): bool;
    public function needsRehash(string $hash): bool;
}
