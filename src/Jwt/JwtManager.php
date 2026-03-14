<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Jwt;

interface JwtManager
{
    /**
     * Mint a new signed JWT with the given additional claims.
     *
     * @param array<string, mixed> $claims
     */
    public function mint(array $claims, \DateTimeImmutable $expiresAt): string;

    /**
     * Parse and validate a JWT. Throws on failure.
     *
     * @throws JwtException
     */
    public function parseAndValidate(string $jwt): VerifiedToken;
}
