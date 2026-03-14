<?php

declare(strict_types=1);

namespace Acme\SecurityKit\UrlSigner;

interface UrlSigner
{
    /**
     * Sign a URL and return a SignedUrl value object.
     *
     * @param array<string, string> $claims Additional claims embedded in the URL
     */
    public function sign(string $url, \DateTimeImmutable $expiresAt, array $claims = []): SignedUrl;

    /**
     * Verify a signed URL: checks signature + expiration.
     */
    public function verify(string $url): bool;

    /**
     * Parse a signed URL into a value object without verifying.
     *
     * @throws \InvalidArgumentException if URL is not a valid signed URL
     */
    public function parse(string $url): SignedUrl;
}
