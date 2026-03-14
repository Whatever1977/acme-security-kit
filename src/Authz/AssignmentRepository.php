<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

interface AssignmentRepository
{
    /** @return list<string> role names assigned to the subject */
    public function getRolesForSubject(string $subjectId): array;
}
