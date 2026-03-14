<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

use function random_bytes;

final class SecureRandom implements Random
{
    public function bytes(int $length): string
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException("Length must be > 0, got {$length}.");
        }
        return random_bytes($length);
    }

    public function base64Url(int $length): string
    {
        $raw = $this->bytes($length);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
