<?php

declare(strict_types=1);

namespace Acme\SecurityKit\UrlSigner;

final class UrlSignerPolicy
{
    public function __construct(
        /** Query parameter name for the expiration timestamp */
        public readonly string $expiresParam = '_expires',
        /** Query parameter name for the key ID */
        public readonly string $kidParam = '_kid',
        /** Query parameter name for the signature */
        public readonly string $signatureParam = '_sig',
    ) {}
}
