<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

interface KeyProvider
{
    /**
     * Return the current (signing) key set.
     */
    public function current(): KeySet;

    /**
     * Find a key by key ID (kid). Returns null if not found.
     */
    public function byKid(string $kid): ?Key;
}
