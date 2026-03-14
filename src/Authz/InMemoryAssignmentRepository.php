<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

final class InMemoryAssignmentRepository implements AssignmentRepository
{
    /** @var array<string, list<string>> */
    private array $assignments = [];

    /** @param list<string> $roles */
    public function assign(string $subjectId, array $roles): void
    {
        $this->assignments[$subjectId] = array_merge(
            $this->assignments[$subjectId] ?? [],
            $roles
        );
    }

    public function getRolesForSubject(string $subjectId): array
    {
        return $this->assignments[$subjectId] ?? [];
    }
}
