<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\DTO;
final class Client
{
    public function __construct(
        public readonly string $clientId,
        public readonly bool $isPublic,
        public readonly array $redirectUris = [],
        public readonly array $grantTypes = ['authorization_code'],
        public readonly array $scopes = [],
        public readonly bool $requirePkce = true,
    ) {}
    public function hasRedirectUri(string $uri): bool
    {
        return in_array($uri, $this->redirectUris, true);
    }
}
