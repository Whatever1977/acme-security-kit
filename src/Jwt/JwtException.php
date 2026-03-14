<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Jwt;

final class JwtException extends \RuntimeException
{
    public static function invalidSignature(string $detail = ''): self
    {
        return new self("JWT has an invalid signature. {$detail}");
    }

    public static function expired(string $detail = ''): self
    {
        return new self("JWT is expired. {$detail}");
    }

    public static function unknownKid(string $kid): self
    {
        return new self("Unknown key ID: {$kid}");
    }

    public static function missingClaim(string $claim): self
    {
        return new self("Required claim missing: {$claim}");
    }

    public static function invalidClaim(string $claim, string $reason): self
    {
        return new self("Invalid claim '{$claim}': {$reason}");
    }
}
