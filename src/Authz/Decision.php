<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

final class Decision
{
    public function __construct(
        public readonly bool $allowed,
        public readonly string $reason = '',
    ) {}

    public static function allow(string $reason = 'Permission granted.'): self
    {
        return new self(true, $reason);
    }

    public static function deny(string $reason = 'Permission denied.'): self
    {
        return new self(false, $reason);
    }
}
