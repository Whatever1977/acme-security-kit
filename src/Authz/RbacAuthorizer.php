<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Authz;

use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\SecurityEvent;

/**
 * RBAC authorizer with role inheritance and optional ABAC attribute checks.
 */
final class RbacAuthorizer implements Authorizer
{
    /**
     * @param list<callable(string $subjectId, string $action, string $resource, array $context): bool|null> $attributeChecks
     *        Callables return true (allow), false (deny), or null (abstain)
     */
    public function __construct(
        private readonly RoleRepository $roleRepository,
        private readonly AssignmentRepository $assignmentRepository,
        private readonly ?Auditor $auditor = null,
        private readonly array $attributeChecks = [],
    ) {}

    public function can(string $subjectId, string $action, string $resource, array $context = []): Decision
    {
        // First pass: attribute checks (ABAC-lite)
        foreach ($this->attributeChecks as $check) {
            $result = $check($subjectId, $action, $resource, $context);
            if ($result === true) {
                return Decision::allow("Attribute check granted access.");
            }
            if ($result === false) {
                $this->audit($subjectId, $action, $resource, 'denied by attribute check');
                return Decision::deny("Attribute check denied access.");
            }
        }

        // Second pass: RBAC
        $permission = "{$action}:{$resource}";
        $roles      = $this->assignmentRepository->getRolesForSubject($subjectId);

        foreach ($roles as $roleName) {
            if ($this->roleHasPermission($roleName, $permission, [])) {
                return Decision::allow("Granted via role: {$roleName}");
            }
        }

        $this->audit($subjectId, $action, $resource, 'no matching role or permission');
        return Decision::deny("Subject '{$subjectId}' lacks permission '{$permission}'.");
    }

    /** @param list<string> $visited Guard against circular role inheritance */
    private function roleHasPermission(string $roleName, string $permission, array $visited): bool
    {
        if (in_array($roleName, $visited, true)) {
            return false; // circular reference guard
        }
        $visited[] = $roleName;

        $role = $this->roleRepository->findByName($roleName);
        if ($role === null) {
            return false;
        }

        if (in_array($permission, $role->permissions, true) || in_array('*', $role->permissions, true)) {
            return true;
        }

        foreach ($role->parents as $parent) {
            if ($this->roleHasPermission($parent, $permission, $visited)) {
                return true;
            }
        }

        return false;
    }

    private function audit(string $subjectId, string $action, string $resource, string $reason): void
    {
        $this->auditor?->record(new SecurityEvent(
            'authz.denied',
            new \DateTimeImmutable(),
            ['subjectId' => $subjectId, 'action' => $action, 'resource' => $resource, 'reason' => $reason],
            'warning',
        ));
    }
}
