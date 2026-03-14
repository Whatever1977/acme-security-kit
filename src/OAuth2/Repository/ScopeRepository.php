<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\Repository;
interface ScopeRepository
{
    public function finalizeScopes(array $requested, string $clientId, string $userId): array;
    public function scopeExists(string $scope): bool;
}
