<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Authz;

use Acme\SecurityKit\Audit\NullAuditor;
use Acme\SecurityKit\Authz\Decision;
use Acme\SecurityKit\Authz\InMemoryAssignmentRepository;
use Acme\SecurityKit\Authz\InMemoryRoleRepository;
use Acme\SecurityKit\Authz\RbacAuthorizer;
use Acme\SecurityKit\Authz\Role;
use PHPUnit\Framework\TestCase;

final class AuthzTest extends TestCase
{
    private InMemoryRoleRepository $roles;
    private InMemoryAssignmentRepository $assignments;
    private RbacAuthorizer $authz;

    protected function setUp(): void
    {
        $this->roles = new InMemoryRoleRepository();
        $this->roles->add(new Role('viewer', permissions: ['read:posts', 'read:comments']));
        $this->roles->add(new Role('editor', parents: ['viewer'], permissions: ['create:posts', 'edit:posts']));
        $this->roles->add(new Role('moderator', parents: ['viewer'], permissions: ['delete:comments']));
        $this->roles->add(new Role('admin', permissions: ['*']));

        $this->assignments = new InMemoryAssignmentRepository();
        $this->assignments->assign('user-viewer', ['viewer']);
        $this->assignments->assign('user-editor', ['editor']);
        $this->assignments->assign('user-admin', ['admin']);
        $this->assignments->assign('user-multi', ['editor', 'moderator']);

        $this->authz = new RbacAuthorizer($this->roles, $this->assignments, new NullAuditor());
    }

    // ─── Decision value object ────────────────────────────────────────

    public function testDecisionAllowFactory(): void
    {
        $d = Decision::allow('reason');
        self::assertTrue($d->allowed);
        self::assertSame('reason', $d->reason);
    }

    public function testDecisionDenyFactory(): void
    {
        $d = Decision::deny('reason');
        self::assertFalse($d->allowed);
    }

    public function testDecisionDefaultReason(): void
    {
        $d = Decision::allow();
        self::assertNotEmpty($d->reason);
    }

    // ─── Direct permissions ───────────────────────────────────────────

    public function testDirectPermissionGranted(): void
    {
        $d = $this->authz->can('user-viewer', 'read', 'posts');
        self::assertTrue($d->allowed);
    }

    public function testDirectPermissionDenied(): void
    {
        $d = $this->authz->can('user-viewer', 'edit', 'posts');
        self::assertFalse($d->allowed);
    }

    // ─── Role inheritance ─────────────────────────────────────────────

    public function testInheritedPermissionFromParentRole(): void
    {
        // editor inherits viewer's read:posts
        $d = $this->authz->can('user-editor', 'read', 'posts');
        self::assertTrue($d->allowed);
    }

    public function testChildPermissionNotGrantedToParent(): void
    {
        // viewer cannot edit:posts — that belongs to editor
        $d = $this->authz->can('user-viewer', 'edit', 'posts');
        self::assertFalse($d->allowed);
    }

    // ─── Wildcard permission ──────────────────────────────────────────

    public function testWildcardPermissionGrantsEverything(): void
    {
        foreach (['read', 'edit', 'delete', 'create', 'anything'] as $action) {
            $d = $this->authz->can('user-admin', $action, 'posts');
            self::assertTrue($d->allowed, "Admin should be allowed to $action posts");
        }
    }

    // ─── Multiple roles ───────────────────────────────────────────────

    public function testMultipleRolesUnionPermissions(): void
    {
        // user-multi has editor + moderator
        self::assertTrue($this->authz->can('user-multi', 'edit', 'posts')->allowed);
        self::assertTrue($this->authz->can('user-multi', 'delete', 'comments')->allowed);
        self::assertTrue($this->authz->can('user-multi', 'read', 'posts')->allowed); // inherited
    }

    // ─── Unknown subject ─────────────────────────────────────────────

    public function testUnknownSubjectDenied(): void
    {
        $d = $this->authz->can('ghost-user', 'read', 'posts');
        self::assertFalse($d->allowed);
    }

    // ─── Unknown role ─────────────────────────────────────────────────

    public function testUnknownRoleAssignedIsDenied(): void
    {
        $this->assignments->assign('user-bad', ['nonexistent-role']);
        $d = $this->authz->can('user-bad', 'read', 'posts');
        self::assertFalse($d->allowed);
    }

    // ─── ABAC attribute checks ────────────────────────────────────────

    public function testAttributeCheckCanDenyBeforeRbac(): void
    {
        $authz = new RbacAuthorizer(
            $this->roles,
            $this->assignments,
            new NullAuditor(),
            attributeChecks: [
                static fn(string $subject, string $action, string $resource, array $context): ?bool
                    => $context['blocked'] ?? false ? false : null,
            ]
        );

        // admin is blocked by attribute check
        $d = $authz->can('user-admin', 'read', 'posts', ['blocked' => true]);
        self::assertFalse($d->allowed);
    }

    public function testAttributeCheckAbstainFallsBackToRbac(): void
    {
        $authz = new RbacAuthorizer(
            $this->roles,
            $this->assignments,
            new NullAuditor(),
            attributeChecks: [
                static fn(): ?bool => null, // always abstain
            ]
        );

        $d = $authz->can('user-admin', 'read', 'posts');
        self::assertTrue($d->allowed);
    }

    public function testAttributeCheckCanExplicitlyAllow(): void
    {
        $authz = new RbacAuthorizer(
            $this->roles,
            $this->assignments,
            new NullAuditor(),
            attributeChecks: [
                static fn(): ?bool => true, // always allow
            ]
        );

        // user-viewer normally can't edit, but attribute check allows it
        $d = $authz->can('user-viewer', 'edit', 'posts');
        self::assertTrue($d->allowed);
    }

    // ─── Circular role inheritance guard ──────────────────────────────

    public function testCircularRoleInheritanceDoesNotInfiniteLoop(): void
    {
        // role-a → role-b → role-a (circular)
        $roles = new InMemoryRoleRepository();
        $roles->add(new Role('role-a', parents: ['role-b'], permissions: ['read:x']));
        $roles->add(new Role('role-b', parents: ['role-a'], permissions: []));

        $assignments = new InMemoryAssignmentRepository();
        $assignments->assign('u', ['role-a']);

        $authz = new RbacAuthorizer($roles, $assignments);

        // Should not throw or loop forever
        $d = $authz->can('u', 'write', 'x');
        self::assertFalse($d->allowed);
    }

    // ─── InMemoryRepositories ─────────────────────────────────────────

    public function testInMemoryRoleRepositoryFindByNameReturnsNull(): void
    {
        self::assertNull($this->roles->findByName('nonexistent'));
    }

    public function testInMemoryAssignmentRepositoryReturnsEmptyArrayForUnknown(): void
    {
        self::assertSame([], $this->assignments->getRolesForSubject('no-one'));
    }

    public function testInMemoryAssignmentRepositoryAccumulatesRoles(): void
    {
        $repo = new InMemoryAssignmentRepository();
        $repo->assign('u', ['role-a']);
        $repo->assign('u', ['role-b']);
        self::assertEqualsCanonicalizing(['role-a', 'role-b'], $repo->getRolesForSubject('u'));
    }
}
