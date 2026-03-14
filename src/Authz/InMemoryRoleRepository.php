<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

final class InMemoryRoleRepository implements RoleRepository
{
    /** @var array<string, Role> */
    private array $roles = [];

    public function add(Role $role): void
    {
        $this->roles[$role->name] = $role;
    }

    public function findByName(string $name): ?Role
    {
        return $this->roles[$name] ?? null;
    }
}
