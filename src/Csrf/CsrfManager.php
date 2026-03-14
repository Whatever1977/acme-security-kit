<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Csrf;

interface CsrfManager
{
    /**
     * Issue a new CSRF token for the given session + context combination.
     * Context should be a meaningful string like "transfer_funds" or "delete_account".
     */
    public function issue(string $sessionId, string $context): CsrfToken;

    /**
     * Validate a submitted token against session + context.
     */
    public function validate(string $sessionId, string $context, string $token): bool;
}
