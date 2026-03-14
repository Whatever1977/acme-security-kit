<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Totp;

interface Totp
{
    /**
     * Generate a new random Base32-encoded TOTP secret.
     */
    public function generateSecret(int $bytes = 20): string;

    /**
     * Generate the otpauth:// URI for QR code generation.
     */
    public function provisioningUri(string $accountName, string $issuer, string $secret): string;

    /**
     * Verify a TOTP code. Accepts ±window steps for clock drift.
     */
    public function verify(string $secret, string $code, ?\DateTimeImmutable $now = null): bool;
}
