<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Totp;

use Acme\SecurityKit\Crypto\Random;

/**
 * RFC 6238 TOTP implementation.
 *
 * Uses Base32 encoding for secrets (Google Authenticator compatible).
 */
final class RfcTotp implements Totp
{
    private const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function __construct(
        private readonly Random $random,
        private readonly TotpConfig $config = new TotpConfig(),
    ) {}

    public function generateSecret(int $bytes = 20): string
    {
        return $this->base32Encode($this->random->bytes($bytes));
    }

    public function provisioningUri(string $accountName, string $issuer, string $secret): string
    {
        $params = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => strtoupper($this->config->algorithm),
            'digits'    => $this->config->digits,
            'period'    => $this->config->step,
        ]);

        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);
        return "otpauth://totp/{$label}?{$params}";
    }

    public function verify(string $secret, string $code, ?\DateTimeImmutable $now = null): bool
    {
        $timestamp = ($now ?? new \DateTimeImmutable())->getTimestamp();
        $counter   = (int) floor($timestamp / $this->config->step);

        for ($i = -$this->config->window; $i <= $this->config->window; $i++) {
            $expected = $this->generateCode($secret, $counter + $i);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }
        return false;
    }

    private function generateCode(string $secret, int $counter): string
    {
        $key = $this->base32Decode($secret);

        // Pack counter as big-endian 64-bit integer
        $message = pack('J', $counter);
        $hash = hash_hmac($this->config->algorithm, $message, $key, true);

        // Dynamic truncation (RFC 4226)
        $offset = ord($hash[-1]) & 0x0F;
        $code   = (
            (ord($hash[$offset])     & 0x7F) << 24 |
            (ord($hash[$offset + 1]) & 0xFF) << 16 |
            (ord($hash[$offset + 2]) & 0xFF) << 8  |
            (ord($hash[$offset + 3]) & 0xFF)
        );
        $code = $code % (10 ** $this->config->digits);

        return str_pad((string) $code, $this->config->digits, '0', STR_PAD_LEFT);
    }

    private function base32Encode(string $data): string
    {
        $encoded = '';
        $length  = strlen($data);

        for ($i = 0; $i < $length; $i += 5) {
            $chunk = substr($data, $i, 5);
            $pad   = 5 - strlen($chunk);
            $chunk .= str_repeat("\x00", $pad);

            $b = array_values(unpack('C5', $chunk) ?: []);
            $encoded .= self::BASE32_CHARS[($b[0] >> 3) & 0x1F];
            $encoded .= self::BASE32_CHARS[(($b[0] & 0x07) << 2) | (($b[1] >> 6) & 0x03)];
            $encoded .= self::BASE32_CHARS[($b[1] >> 1) & 0x1F];
            $encoded .= self::BASE32_CHARS[(($b[1] & 0x01) << 4) | (($b[2] >> 4) & 0x0F)];
            $encoded .= self::BASE32_CHARS[(($b[2] & 0x0F) << 1) | (($b[3] >> 7) & 0x01)];
            $encoded .= self::BASE32_CHARS[($b[3] >> 2) & 0x1F];
            $encoded .= self::BASE32_CHARS[(($b[3] & 0x03) << 3) | (($b[4] >> 5) & 0x07)];
            $encoded .= self::BASE32_CHARS[$b[4] & 0x1F];

            if ($pad > 0) {
                $encoded = substr($encoded, 0, -($pad * 8 / 5));
            }
        }

        return $encoded;
    }

    private function base32Decode(string $input): string
    {
        $input  = strtoupper($input);
        $lookup = array_flip(str_split(self::BASE32_CHARS));
        $bits   = '';

        foreach (str_split($input) as $char) {
            if (!isset($lookup[$char])) {
                continue;
            }
            $bits .= str_pad(decbin($lookup[$char]), 5, '0', STR_PAD_LEFT);
        }

        $decoded = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $decoded .= chr(bindec($byte));
            }
        }

        return $decoded;
    }
}
