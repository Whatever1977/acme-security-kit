<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

final class Role
{
    /**
     * @param list<string> $parents Parent role names for inheritance
     * @param list<string> $permissions Granted permissions
     */
    public function __construct(
        public readonly string $name,
        public readonly array $parents = [],
        public readonly array $permissions = [],
    ) {}
}
