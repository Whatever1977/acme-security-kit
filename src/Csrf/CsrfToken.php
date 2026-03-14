<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Csrf;

final class CsrfToken
{
    public function __construct(
        public readonly string $value,
        public readonly \DateTimeImmutable $expiresAt,
    ) {}

    public function isExpired(?\DateTimeImmutable $at = null): bool
    {
        return ($at ?? new \DateTimeImmutable()) > $this->expiresAt;
    }
}
