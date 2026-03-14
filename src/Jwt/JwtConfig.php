<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Jwt;

final class JwtConfig
{
    public function __construct(
        public readonly string $issuer,
        public readonly string $audience,
        public readonly int $clockSkewSeconds = 60,
        public readonly bool $requireJti = true,
        /** Supported algorithms: RS256, ES256, HS256 */
        public readonly string $algorithm = 'RS256',
    ) {}
}
