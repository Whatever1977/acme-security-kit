<?php
/**
 * Example Laravel service provider for acme/security-kit.
 *
 * Drop this into app/Providers/ and register it in config/app.php.
 */

declare(strict_types=1);

namespace App\Providers;

use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Crypto\ConstantTime;
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\KeyProvider;
use Acme\SecurityKit\Crypto\Random;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfManager;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use Acme\SecurityKit\Jwt\FirebaseJwtManager;
use Acme\SecurityKit\Jwt\JwtConfig;
use Acme\SecurityKit\Jwt\JwtManager;
use Acme\SecurityKit\Password\Argon2idHasher;
use Acme\SecurityKit\Password\PasswordHasher;
use Acme\SecurityKit\Password\PasswordPolicy;
use Acme\SecurityKit\Totp\RfcTotp;
use Acme\SecurityKit\Totp\Totp;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;
use Acme\SecurityKit\UrlSigner\UrlSigner;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;

class SecurityKitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Core crypto
        $this->app->singleton(Random::class, SecureRandom::class);
        $this->app->singleton(ConstantTime::class, HashEquals::class);

        // Audit
        $this->app->singleton(Auditor::class, static function ($app) {
            return new PsrLoggerAuditor($app->make(LoggerInterface::class), channel: 'security');
        });

        // Key provider — in production, load from config / secrets manager
        $this->app->singleton(KeyProvider::class, static function () {
            $key = new Key(
                kid: config('security.jwt.kid', 'default'),
                algorithm: 'HS256',
                material: config('security.jwt.secret'),
                isSymmetric: true,
            );
            return new InMemoryKeyProvider($key);
        });

        // CSRF
        $this->app->singleton(CsrfManager::class, static function ($app) {
            return new HmacCsrfManager(
                secret: config('security.csrf.secret'),
                random: $app->make(Random::class),
                constantTime: $app->make(ConstantTime::class),
                policy: new CsrfPolicy(ttlSeconds: (int) config('security.csrf.ttl', 3600)),
            );
        });

        // JWT
        $this->app->singleton(JwtManager::class, static function ($app) {
            return new FirebaseJwtManager(
                config: new JwtConfig(
                    issuer: config('app.url'),
                    audience: config('app.url'),
                ),
                keyProvider: $app->make(KeyProvider::class),
                random: $app->make(Random::class),
                auditor: $app->make(Auditor::class),
            );
        });

        // URL Signer
        $this->app->singleton(UrlSigner::class, static function ($app) {
            return new HmacUrlSigner(
                keyProvider: $app->make(KeyProvider::class),
                constantTime: $app->make(ConstantTime::class),
            );
        });

        // Password
        $this->app->singleton(PasswordHasher::class, Argon2idHasher::class);
        $this->app->singleton(PasswordPolicy::class, static fn() => new PasswordPolicy(
            minLength: (int) config('security.password.min_length', 12),
            checkPwned: (bool) config('security.password.check_pwned', false),
        ));

        // TOTP
        $this->app->singleton(Totp::class, static function ($app) {
            return new RfcTotp($app->make(Random::class));
        });
    }
}
