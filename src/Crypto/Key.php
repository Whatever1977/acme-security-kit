<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

final class Key
{
    public function __construct(
        public readonly string $kid,
        public readonly string $algorithm,
        /** PEM string or raw symmetric key */
        public readonly string $material,
        public readonly bool $isSymmetric = false,
        public readonly ?\DateTimeImmutable $notAfter = null,
    ) {}

    public function isExpired(?\DateTimeImmutable $at = null): bool
    {
        if ($this->notAfter === null) {
            return false;
        }
        return ($at ?? new \DateTimeImmutable()) > $this->notAfter;
    }
}
