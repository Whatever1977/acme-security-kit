<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\DTO;
final class RefreshToken
{
    public function __construct(
        public readonly string $token,
        public readonly string $accessTokenJti,
        public readonly string $clientId,
        public readonly ?string $userId,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly bool $revoked = false,
    ) {}
    public function isExpired(): bool { return new \DateTimeImmutable() > $this->expiresAt; }
}
