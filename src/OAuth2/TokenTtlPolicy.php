<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2;
final class TokenTtlPolicy
{
    public function __construct(
        public readonly int $accessTokenTtlSeconds = 3600,
        public readonly int $refreshTokenTtlSeconds = 2592000,
        public readonly bool $rotateRefreshTokens = true,
        public readonly bool $detectRefreshTokenReuse = true,
    ) {}
}
