<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Password;

final class WeakPasswordException extends \InvalidArgumentException
{
    /** @param list<string> $violations */
    public function __construct(
        private readonly array $violations,
    ) {
        parent::__construct(implode(' ', $violations));
    }

    /** @return list<string> */
    public function getViolations(): array
    {
        return $this->violations;
    }
}
