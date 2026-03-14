<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Audit;

interface Auditor
{
    public function record(SecurityEvent $event): void;
}
