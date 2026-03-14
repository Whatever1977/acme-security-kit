<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

final class HashEquals implements ConstantTime
{
    public function equals(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
