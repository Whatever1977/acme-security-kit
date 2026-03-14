<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Totp;

final class TotpConfig
{
    public function __construct(
        public readonly int $digits = 6,
        public readonly int $step = 30,
        public readonly int $window = 1,
        /** Supported: sha1, sha256 */
        public readonly string $algorithm = 'sha1',
    ) {}
}
