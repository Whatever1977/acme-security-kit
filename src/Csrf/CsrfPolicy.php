<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Csrf;

final class CsrfPolicy
{
    public function __construct(
        public readonly int $ttlSeconds = 3600,
        public readonly int $leewaySeconds = 60,
        public readonly bool $oneTimeTokens = false,
    ) {}
}
