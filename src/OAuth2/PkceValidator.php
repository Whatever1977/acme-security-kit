<?php
declare(strict_types=1);
namespace Acme\SecurityKit\OAuth2;
use Acme\SecurityKit\Crypto\ConstantTime;
/**
 * PKCE (RFC 7636) code_verifier / code_challenge validation.
 * Only S256 method is accepted; 'plain' is rejected as insecure.
 */
final class PkceValidator
{
    public function __construct(private readonly ConstantTime $constantTime) {}

    public function validate(string $codeVerifier, string $codeChallenge, string $method = 'S256'): bool
    {
        if ($method !== 'S256') {
            return false;
        }
        $derived = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        return $this->constantTime->equals($derived, $codeChallenge);
    }

    public function challenge(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }
}
