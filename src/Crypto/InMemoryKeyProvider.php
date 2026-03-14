<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

final class InMemoryKeyProvider implements KeyProvider
{
    private KeySet $keySet;

    public function __construct(Key ...$keys)
    {
        $this->keySet = new KeySet(...$keys);
    }

    public function current(): KeySet
    {
        return $this->keySet;
    }

    public function byKid(string $kid): ?Key
    {
        return $this->keySet->get($kid);
    }
}
