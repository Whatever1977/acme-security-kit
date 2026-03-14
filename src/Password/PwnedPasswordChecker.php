<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

/**
 * Pluggable interface for checking passwords against breach databases.
 * Implementations should use k-anonymity (HaveIBeenPwned range API) to avoid sending full hashes.
 */
interface PwnedPasswordChecker
{
    /**
     * Returns true if the password appears in a known breach database.
     */
    public function isBreached(string $password): bool;
}
