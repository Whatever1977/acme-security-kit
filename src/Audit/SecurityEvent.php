<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Audit;

final class SecurityEvent
{
    public function __construct(
        /** e.g. "auth.jwt.invalid", "csrf.invalid", "oauth.refresh_reuse_detected" */
        public readonly string $type,
        public readonly \DateTimeImmutable $at,
        /** @var array<string, mixed> */
        public readonly array $context = [],
        public readonly string $severity = 'info',
    ) {}
}
