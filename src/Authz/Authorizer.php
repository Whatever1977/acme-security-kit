<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

interface Authorizer
{
    /**
     * Check whether the subject can perform the action on the resource.
     *
     * @param array<string, mixed> $context Attribute context for ABAC-style checks
     */
    public function can(string $subjectId, string $action, string $resource, array $context = []): Decision;
}
