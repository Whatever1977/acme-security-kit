<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Jwt;

use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use Acme\SecurityKit\Crypto\KeyProvider;
use Acme\SecurityKit\Crypto\Random;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * JWT manager that wraps firebase/php-jwt and adds:
 *   - key rotation via KeyProvider
 *   - strict claim validation
 *   - audit logging
 */
final class FirebaseJwtManager implements JwtManager
{
    public function __construct(
        private readonly JwtConfig $config,
        private readonly KeyProvider $keyProvider,
        private readonly Random $random,
        private readonly ?Auditor $auditor = null,
    ) {}

    public function mint(array $claims, \DateTimeImmutable $expiresAt): string
    {
        $signingKey = $this->keyProvider->current()->first();
        if ($signingKey === null) {
            throw new JwtException('No signing key available.');
        }

        $now = new \DateTimeImmutable();

        $payload = array_merge($claims, [
            'iss' => $this->config->issuer,
            'aud' => $this->config->audience,
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $expiresAt->getTimestamp(),
        ]);

        if ($this->config->requireJti) {
            $payload['jti'] = $this->random->base64Url(16);
        }

        return JWT::encode(
            $payload,
            $signingKey->material,
            $this->config->algorithm,
            $signingKey->kid,
        );
    }

    public function parseAndValidate(string $jwt): VerifiedToken
    {
        // Decode header to get kid without full validation first
        $kid = $this->extractKid($jwt);

        $key = $kid !== null ? $this->keyProvider->byKid($kid) : $this->keyProvider->current()->first();
        if ($key === null) {
            $this->audit('jwt.kid_unknown', ['kid' => $kid ?? 'none'], 'warning');
            throw JwtException::unknownKid($kid ?? 'none');
        }

        try {
            JWT::$leeway = $this->config->clockSkewSeconds;

            $decoded = JWT::decode($jwt, new Key($key->material, $this->config->algorithm));
            /** @var array<string, mixed> $claims */
            $claims = (array) $decoded;

            $this->validateClaims($claims);

            $expiresAt = \DateTimeImmutable::createFromFormat('U', (string) $claims['exp']);
            if ($expiresAt === false) {
                throw JwtException::missingClaim('exp');
            }

            return new VerifiedToken($claims, $kid ?? $key->kid, $expiresAt);
        } catch (JwtException $e) {
            $this->audit('jwt.invalid', ['error' => $e->getMessage()], 'warning');
            throw $e;
        } catch (\Firebase\JWT\ExpiredException $e) {
            $this->audit('jwt.expired', ['error' => $e->getMessage()], 'warning');
            throw JwtException::expired($e->getMessage());
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            $this->audit('jwt.invalid_signature', ['error' => $e->getMessage()], 'warning');
            throw JwtException::invalidSignature($e->getMessage());
        } catch (\Throwable $e) {
            $this->audit('jwt.invalid', ['error' => $e->getMessage()], 'warning');
            throw new JwtException("JWT validation failed: {$e->getMessage()}", 0, $e);
        }
    }

    /** @param array<string, mixed> $claims */
    private function validateClaims(array $claims): void
    {
        if (($claims['iss'] ?? null) !== $this->config->issuer) {
            throw JwtException::invalidClaim('iss', 'Issuer mismatch.');
        }
        if (($claims['aud'] ?? null) !== $this->config->audience) {
            throw JwtException::invalidClaim('aud', 'Audience mismatch.');
        }
        if ($this->config->requireJti && empty($claims['jti'])) {
            throw JwtException::missingClaim('jti');
        }
    }

    private function extractKid(string $jwt): ?string
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        $headerJson = base64_decode(strtr($parts[0], '-_', '+/'));
        if ($headerJson === false) {
            return null;
        }
        try {
            /** @var array<string, mixed> $header */
            $header = json_decode($headerJson, true, 512, JSON_THROW_ON_ERROR);
            return isset($header['kid']) ? (string) $header['kid'] : null;
        } catch (\JsonException) {
            return null;
        }
    }

    private function audit(string $type, array $context, string $severity): void
    {
        $this->auditor?->record(new SecurityEvent($type, new \DateTimeImmutable(), $context, $severity));
    }
}
