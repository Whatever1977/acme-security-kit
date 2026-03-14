<?php

declare(strict_types=1);

namespace Acme\SecurityKit\UrlSigner;

final class SignedUrl
{
    public function __construct(
        public readonly string $url,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly string $signature,
    ) {}

    public function isExpired(?\DateTimeImmutable $at = null): bool
    {
        return ($at ?? new \DateTimeImmutable()) > $this->expiresAt;
    }
}
