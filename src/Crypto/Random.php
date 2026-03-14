<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

interface Random
{
    /**
     * Generate cryptographically secure random bytes.
     */
    public function bytes(int $length): string;

    /**
     * Generate a URL-safe base64-encoded random string.
     */
    public function base64Url(int $length): string;
}
