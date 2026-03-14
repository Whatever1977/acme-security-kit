<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Jwt;

final class VerifiedToken
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly array $claims,
        public readonly string $kid,
        public readonly \DateTimeImmutable $expiresAt,
    ) {}

    public function claim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    public function isExpired(?\DateTimeImmutable $at = null): bool
    {
        return ($at ?? new \DateTimeImmutable()) > $this->expiresAt;
    }
}
