<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\DTO;
final class AccessToken
{
    public function __construct(
        public readonly string $jti,
        public readonly string $clientId,
        public readonly ?string $userId,
        public readonly array $scopes,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly bool $revoked = false,
    ) {}
    public function isExpired(): bool { return new \DateTimeImmutable() > $this->expiresAt; }
}
