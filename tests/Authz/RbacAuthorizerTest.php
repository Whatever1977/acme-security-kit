<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Authz;

use Acme\SecurityKit\Authz\InMemoryAssignmentRepository;
use Acme\SecurityKit\Authz\InMemoryRoleRepository;
use Acme\SecurityKit\Authz\RbacAuthorizer;
use Acme\SecurityKit\Authz\Role;
use PHPUnit\Framework\TestCase;

final class RbacAuthorizerTest extends TestCase
{
    private InMemoryRoleRepository $roleRepo;
    private InMemoryAssignmentRepository $assignmentRepo;
    private RbacAuthorizer $authorizer;

    protected function setUp(): void
    {
        $this->roleRepo       = new InMemoryRoleRepository();
        $this->assignmentRepo = new InMemoryAssignmentRepository();
        $this->authorizer     = new RbacAuthorizer($this->roleRepo, $this->assignmentRepo);
    }

    public function testAdminCanDoEverything(): void
    {
        $this->roleRepo->add(new Role('admin', permissions: ['*']));
        $this->assignmentRepo->assign('user1', ['admin']);

        $decision = $this->authorizer->can('user1', 'delete', 'posts');
        self::assertTrue($decision->allowed);
    }

    public function testEditorCanEdit(): void
    {
        $this->roleRepo->add(new Role('editor', permissions: ['edit:posts', 'read:posts']));
        $this->assignmentRepo->assign('user2', ['editor']);

        self::assertTrue($this->authorizer->can('user2', 'edit', 'posts')->allowed);
        self::assertFalse($this->authorizer->can('user2', 'delete', 'posts')->allowed);
    }

    public function testRoleInheritance(): void
    {
        $this->roleRepo->add(new Role('viewer', permissions: ['read:posts']));
        $this->roleRepo->add(new Role('editor', parents: ['viewer'], permissions: ['edit:posts']));
        $this->assignmentRepo->assign('user3', ['editor']);

        // Should inherit viewer's read permission
        self::assertTrue($this->authorizer->can('user3', 'read', 'posts')->allowed);
        self::assertTrue($this->authorizer->can('user3', 'edit', 'posts')->allowed);
        self::assertFalse($this->authorizer->can('user3', 'delete', 'posts')->allowed);
    }

    public function testUnassignedUserIsDenied(): void
    {
        $decision = $this->authorizer->can('nobody', 'read', 'posts');
        self::assertFalse($decision->allowed);
    }

    public function testAttributeCheckCanOverride(): void
    {
        $this->roleRepo->add(new Role('viewer', permissions: ['read:posts']));
        $this->assignmentRepo->assign('user4', ['viewer']);

        $authorizer = new RbacAuthorizer(
            $this->roleRepo,
            $this->assignmentRepo,
            attributeChecks: [
                function (string $subjectId, string $action, string $resource, array $context): ?bool {
                    if ($context['ip'] === '1.2.3.4') {
                        return false; // block suspicious IP
                    }
                    return null; // abstain
                }
            ]
        );

        self::assertFalse($authorizer->can('user4', 'read', 'posts', ['ip' => '1.2.3.4'])->allowed);
        self::assertTrue($authorizer->can('user4', 'read', 'posts', ['ip' => '5.6.7.8'])->allowed);
    }
}
