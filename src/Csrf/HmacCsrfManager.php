<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Csrf;

use Acme\SecurityKit\Crypto\ConstantTime;
use Acme\SecurityKit\Crypto\Random;

/**
 * Stateless HMAC-based CSRF manager.
 *
 * Token format: base64url(json({session, context, issuedAt, nonce})).HMAC
 */
final class HmacCsrfManager implements CsrfManager
{
    public function __construct(
        private readonly string $secret,
        private readonly Random $random,
        private readonly ConstantTime $constantTime,
        private readonly CsrfPolicy $policy = new CsrfPolicy(),
    ) {}

    public function issue(string $sessionId, string $context): CsrfToken
    {
        $issuedAt  = new \DateTimeImmutable();
        $expiresAt = $issuedAt->modify("+{$this->policy->ttlSeconds} seconds");
        $nonce     = $this->random->base64Url(16);

        $payload = $this->buildPayload($sessionId, $context, $issuedAt->getTimestamp(), $nonce);
        $hmac    = $this->sign($payload);
        $value   = $payload . '.' . $hmac;

        return new CsrfToken($value, $expiresAt);
    }

    public function validate(string $sessionId, string $context, string $token): bool
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$payload, $providedHmac] = $parts;

        // Constant-time signature check first
        $expectedHmac = $this->sign($payload);
        if (!$this->constantTime->equals($expectedHmac, $providedHmac)) {
            return false;
        }

        $data = $this->decodePayload($payload);
        if ($data === null) {
            return false;
        }

        if ($data['session'] !== $sessionId || $data['context'] !== $context) {
            return false;
        }

        $issuedAt  = \DateTimeImmutable::createFromFormat('U', (string)$data['issued_at']);
        $expiresAt = $issuedAt->modify("+{$this->policy->ttlSeconds} seconds")
                              ->modify("+{$this->policy->leewaySeconds} seconds");

        return new \DateTimeImmutable() <= $expiresAt;
    }

    private function buildPayload(string $sessionId, string $context, int $issuedAt, string $nonce): string
    {
        $json = json_encode([
            'session'   => $sessionId,
            'context'   => $context,
            'issued_at' => $issuedAt,
            'nonce'     => $nonce,
        ], JSON_THROW_ON_ERROR);

        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    }

    /** @return array<string, mixed>|null */
    private function decodePayload(string $payload): ?array
    {
        $json = base64_decode(strtr($payload, '-_', '+/'));
        if ($json === false) {
            return null;
        }
        try {
            /** @var array<string, mixed> $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            return $data;
        } catch (\JsonException) {
            return null;
        }
    }

    private function sign(string $payload): string
    {
        return hash_hmac('sha256', $payload, $this->secret);
    }
}
