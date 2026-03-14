<?php

declare(strict_types=1);

namespace Acme\SecurityKit\UrlSigner;

use Acme\SecurityKit\Crypto\ConstantTime;
use Acme\SecurityKit\Crypto\KeyProvider;

/**
 * HMAC-SHA256 URL signer with key rotation support.
 *
 * Signing process:
 *   1. Add _expires, _kid to URL query params
 *   2. Canonicalize all query params (ksort)
 *   3. HMAC-SHA256 over the canonical URL string
 *   4. Append _sig to URL
 */
final class HmacUrlSigner implements UrlSigner
{
    public function __construct(
        private readonly KeyProvider $keyProvider,
        private readonly ConstantTime $constantTime,
        private readonly UrlSignerPolicy $policy = new UrlSignerPolicy(),
    ) {}

    public function sign(string $url, \DateTimeImmutable $expiresAt, array $claims = []): SignedUrl
    {
        $currentKey = $this->keyProvider->current()->first();
        if ($currentKey === null) {
            throw new \RuntimeException('No signing key available.');
        }

        $parsed = parse_url($url);
        if ($parsed === false) {
            throw new \InvalidArgumentException("Cannot parse URL: {$url}");
        }

        parse_str($parsed['query'] ?? '', $queryParams);

        $queryParams = array_merge($queryParams, $claims, [
            $this->policy->expiresParam => (string) $expiresAt->getTimestamp(),
            $this->policy->kidParam      => $currentKey->kid,
        ]);

        ksort($queryParams);

        $canonical = $this->buildCanonicalUrl($parsed, $queryParams);
        $signature = hash_hmac('sha256', $canonical, $currentKey->material);

        $queryParams[$this->policy->signatureParam] = $signature;
        ksort($queryParams);

        $signedUrl = $this->buildUrl($parsed, $queryParams);

        return new SignedUrl($signedUrl, $expiresAt, $signature);
    }

    public function verify(string $url): bool
    {
        try {
            $parsed = parse_url($url);
            if ($parsed === false) {
                return false;
            }

            parse_str($parsed['query'] ?? '', $queryParams);

            $providedSig = $queryParams[$this->policy->signatureParam] ?? null;
            $kid         = $queryParams[$this->policy->kidParam] ?? null;
            $expires     = $queryParams[$this->policy->expiresParam] ?? null;

            if ($providedSig === null || $kid === null || $expires === null) {
                return false;
            }

            $key = $this->keyProvider->byKid((string) $kid);
            if ($key === null) {
                return false;
            }

            // Check expiration before verifying signature (fail fast, still constant-time on sig)
            $expiresAt = \DateTimeImmutable::createFromFormat('U', (string) $expires);
            if ($expiresAt === false || new \DateTimeImmutable() > $expiresAt) {
                return false;
            }

            // Rebuild canonical URL without signature param
            unset($queryParams[$this->policy->signatureParam]);
            ksort($queryParams);
            $canonical = $this->buildCanonicalUrl($parsed, $queryParams);
            $expected  = hash_hmac('sha256', $canonical, $key->material);

            return $this->constantTime->equals($expected, (string) $providedSig);
        } catch (\Throwable) {
            return false;
        }
    }

    public function parse(string $url): SignedUrl
    {
        $parsed = parse_url($url);
        if ($parsed === false) {
            throw new \InvalidArgumentException("Cannot parse URL: {$url}");
        }

        parse_str($parsed['query'] ?? '', $queryParams);

        $sig     = $queryParams[$this->policy->signatureParam] ?? null;
        $expires = $queryParams[$this->policy->expiresParam] ?? null;

        if ($sig === null || $expires === null) {
            throw new \InvalidArgumentException('URL is missing signature or expiration parameters.');
        }

        $expiresAt = \DateTimeImmutable::createFromFormat('U', (string) $expires);
        if ($expiresAt === false) {
            throw new \InvalidArgumentException('Invalid expiration timestamp in URL.');
        }

        return new SignedUrl($url, $expiresAt, (string) $sig);
    }

    /** @param array<string, string> $parsed */
    /** @param array<string, mixed> $queryParams */
    private function buildCanonicalUrl(array $parsed, array $queryParams): string
    {
        $url  = '';
        $url .= isset($parsed['scheme']) ? $parsed['scheme'] . '://' : '';
        $url .= $parsed['host'] ?? '';
        $url .= isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $url .= $parsed['path'] ?? '/';
        $url .= '?' . http_build_query($queryParams);
        return $url;
    }

    /** @param array<string, mixed> $parsed
     *  @param array<string, mixed> $queryParams */
    private function buildUrl(array $parsed, array $queryParams): string
    {
        return $this->buildCanonicalUrl($parsed, $queryParams);
    }
}
