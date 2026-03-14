<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

interface RoleRepository
{
    public function findByName(string $name): ?Role;
}
