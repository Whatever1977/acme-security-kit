<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2\Repository;
use Acme\SecurityKit\OAuth2\DTO\Client;
interface ClientRepository
{
    public function findById(string $clientId): ?Client;
    public function verifySecret(string $clientId, string $secret): bool;
}
