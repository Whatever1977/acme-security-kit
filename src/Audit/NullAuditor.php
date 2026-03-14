<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Audit;

/**
 * No-op auditor for testing or disabled audit contexts.
 */
final class NullAuditor implements Auditor
{
    public function record(SecurityEvent $event): void
    {
        // intentionally empty
    }
}
