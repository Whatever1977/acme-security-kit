<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Crypto;

final class KeySet
{
    /** @var array<string, Key> keyed by kid */
    private array $keys;

    public function __construct(Key ...$keys)
    {
        $this->keys = [];
        foreach ($keys as $key) {
            $this->keys[$key->kid] = $key;
        }
    }

    public function get(string $kid): ?Key
    {
        return $this->keys[$kid] ?? null;
    }

    /** @return array<string, Key> */
    public function all(): array
    {
        return $this->keys;
    }

    public function first(): ?Key
    {
        $values = array_values($this->keys);
        return $values[0] ?? null;
    }

    /**
     * Export public keys as a JWKS array (for RS256/ES256 keys).
     * @return array{keys: array<int, array<string, mixed>>}
     */
    public function toJwks(): array
    {
        $jwkKeys = [];
        foreach ($this->keys as $key) {
            if ($key->isSymmetric) {
                continue; // never export symmetric keys in JWKS
            }
            $pubKey = openssl_pkey_get_public($key->material);
            if ($pubKey === false) {
                continue;
            }
            $details = openssl_pkey_get_details($pubKey);
            if ($details === false) {
                continue;
            }
            $jwk = ['kid' => $key->kid, 'use' => 'sig', 'alg' => $key->algorithm];
            if (($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
                $jwk['kty'] = 'RSA';
                $jwk['n']   = rtrim(base64_encode($details['rsa']['n']), '=');
                $jwk['e']   = rtrim(base64_encode($details['rsa']['e']), '=');
            } elseif (($details['type'] ?? null) === OPENSSL_KEYTYPE_EC) {
                $jwk['kty'] = 'EC';
                $jwk['crv'] = 'P-256';
                $jwk['x']   = rtrim(base64_encode($details['ec']['x']), '=');
                $jwk['y']   = rtrim(base64_encode($details['ec']['y']), '=');
            }
            $jwkKeys[] = $jwk;
        }
        return ['keys' => $jwkKeys];
    }
}
