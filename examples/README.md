# Examples

Ready-to-run examples showing how to integrate `acme/security-kit` into real applications.

---

## Directory Structure

```
examples/
├── laravel/
│   └── SecurityKitServiceProvider.php   # Laravel service provider (DI wiring)
├── psr15-middleware/
│   └── index.php                        # PSR-15 CSRF + URL Signer middleware demo
├── slim/
│   └── slim-app.php                     # Full Slim 4 application with all middleware
└── standalone/
    └── all-modules.php                  # Framework-free demo of all 9 modules
```

---

## Running the Standalone Example

```bash
composer install
php examples/standalone/all-modules.php
```

Expected output:
```
=== acme/security-kit — All Modules Demo ===

--- 1. Crypto ---
Random nonce (base64url, 16 bytes): dBjftJeZ4CVP-mB92K27uh
Constant-time equals: true

--- 2. CSRF ---
Issued token: eyJub25jZSI6...
Expires at: 2025-01-15T13:00:00+00:00
Valid: yes
Cross-form replay blocked: yes
...
```

---

## Running the PSR-15 Middleware Example

```bash
php examples/psr15-middleware/index.php
```

---

## Laravel Integration

Copy `examples/laravel/SecurityKitServiceProvider.php` into your Laravel
project's `app/Providers/` directory, then register it:

```php
// config/app.php
'providers' => [
    // ...
    App\Providers\SecurityKitServiceProvider::class,
],
```

Add the required config entries to `config/security.php`:

```php
return [
    'csrf' => [
        'secret' => env('CSRF_SECRET'),
        'ttl'    => env('CSRF_TTL', 3600),
    ],
    'jwt' => [
        'kid'    => env('JWT_KID', 'default'),
        'secret' => env('JWT_SECRET'),
    ],
    'password' => [
        'min_length'  => env('PASSWORD_MIN_LENGTH', 12),
        'check_pwned' => env('PASSWORD_CHECK_PWNED', false),
    ],
];
```

---

## Slim 4 Integration

```bash
composer require slim/slim slim/psr7
php -S localhost:8080 examples/slim/slim-app.php
```

Available routes:
- `GET /transfer` — render form with CSRF token
- `POST /transfer` — submit form (CSRF validated by middleware)
- `GET /api/me` — JWT-protected endpoint
- `GET /sign/{file}` — generate a signed download URL
- `GET /download/{file}` — signed-URL-protected download endpoint
