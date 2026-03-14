<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

interface ConstantTime
{
    /**
     * Compare two strings in constant time to prevent timing attacks.
     */
    public function equals(string $a, string $b): bool;
}
