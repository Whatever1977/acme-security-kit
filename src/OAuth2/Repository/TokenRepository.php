<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\Repository;
use Acme\SecurityKit\OAuth2\DTO\AccessToken;
use Acme\SecurityKit\OAuth2\DTO\RefreshToken;
interface TokenRepository
{
    public function persistAccessToken(AccessToken $token): void;
    public function findAccessToken(string $jti): ?AccessToken;
    public function revokeAccessToken(string $jti): void;
    public function persistRefreshToken(RefreshToken $token): void;
    public function findRefreshToken(string $token): ?RefreshToken;
    public function revokeRefreshToken(string $token): void;
    public function isAccessTokenRevoked(string $jti): bool;
    public function isRefreshTokenRevoked(string $token): bool;
}
