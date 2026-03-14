<?php

/**
 * acme/security-kit — Slim 4 integration example.
 *
 * Shows how to wire up the PSR-15 middleware in a Slim 4 application.
 * Requires: slim/slim, slim/psr7
 *
 * composer require slim/slim slim/psr7
 */

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Crypto\HashEquals;
use Acme\SecurityKit\Crypto\InMemoryKeyProvider;
use Acme\SecurityKit\Crypto\Key;
use Acme\SecurityKit\Crypto\SecureRandom;
use Acme\SecurityKit\Csrf\CsrfPolicy;
use Acme\SecurityKit\Csrf\HmacCsrfManager;
use Acme\SecurityKit\Jwt\FirebaseJwtManager;
use Acme\SecurityKit\Jwt\JwtConfig;
use Acme\SecurityKit\Jwt\JwtException;
use Acme\SecurityKit\Support\CsrfMiddleware;
use Acme\SecurityKit\Support\SignedUrlMiddleware;
use Acme\SecurityKit\UrlSigner\HmacUrlSigner;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

// ─────────────────────────────────────────────
// Bootstrap security services
// ─────────────────────────────────────────────
$random      = new SecureRandom();
$ct          = new HashEquals();
$keyProvider = new InMemoryKeyProvider(
    new Key('app-key-v1', 'HS256', (string) getenv('APP_SECRET'), isSymmetric: true)
);

$logger  = /* your PSR-3 logger, e.g. Monolog */ new \Psr\Log\NullLogger();
$auditor = new PsrLoggerAuditor($logger, channel: 'security');

$csrfManager = new HmacCsrfManager(
    secret: (string) getenv('CSRF_SECRET'),
    random: $random,
    constantTime: $ct,
    policy: new CsrfPolicy(ttlSeconds: 3600),
);

$urlSigner = new HmacUrlSigner($keyProvider, $ct);

$jwtManager = new FirebaseJwtManager(
    config: new JwtConfig(
        issuer: (string) getenv('APP_URL'),
        audience: (string) getenv('APP_URL'),
        requireJti: true,
    ),
    keyProvider: $keyProvider,
    random: $random,
    auditor: $auditor,
);

// ─────────────────────────────────────────────
// Global CSRF middleware (applied to all state-changing routes)
// ─────────────────────────────────────────────
$app->add(new CsrfMiddleware(
    csrfManager: $csrfManager,
    responseFactory: $app->getResponseFactory(),
    auditor: $auditor,
));

// ─────────────────────────────────────────────
// Routes
// ─────────────────────────────────────────────

// Public: render a form with a CSRF token
$app->get('/transfer', function (Request $request, Response $response): Response {
    global $csrfManager;

    $sessionId = session_id() ?: 'anon';
    $token     = $csrfManager->issue($sessionId, 'transfer_funds');

    $html = <<<HTML
    <form method="POST" action="/transfer">
        <input type="hidden" name="_csrf_token" value="{$token->value}">
        <input type="number" name="amount" placeholder="Amount">
        <button type="submit">Transfer</button>
    </form>
    HTML;

    $response->getBody()->write($html);
    return $response->withHeader('Content-Type', 'text/html');
});

// Protected: process the form (CSRF middleware validates automatically)
$app->post('/transfer', function (Request $request, Response $response): Response {
    $body   = (array) $request->getParsedBody();
    $amount = (float) ($body['amount'] ?? 0);

    $response->getBody()->write(json_encode(['status' => 'ok', 'amount' => $amount]));
    return $response->withHeader('Content-Type', 'application/json');
});

// JWT-protected API route
$app->get('/api/me', function (Request $request, Response $response) use ($jwtManager): Response {
    $auth = $request->getHeaderLine('Authorization');
    $jwt  = str_replace('Bearer ', '', $auth);

    try {
        $verified = $jwtManager->parseAndValidate($jwt);
        $data     = ['sub' => $verified->claim('sub'), 'roles' => $verified->claim('roles')];
    } catch (JwtException $e) {
        $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }

    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json');
});

// Signed-URL protected download route
$app->get('/download/{file}', function (Request $request, Response $response, array $args): Response {
    $response->getBody()->write("Serving file: " . htmlspecialchars($args['file']));
    return $response;
})->add(new SignedUrlMiddleware(
    signer: $urlSigner,
    responseFactory: $app->getResponseFactory(),
    auditor: $auditor,
));

// Helper: generate a signed download URL (protected by JWT auth in production)
$app->get('/sign/{file}', function (Request $request, Response $response, array $args) use ($urlSigner): Response {
    $signed = $urlSigner->sign(
        "https://app.example.com/download/{$args['file']}",
        new \DateTimeImmutable('+1 hour'),
    );

    $response->getBody()->write(json_encode(['url' => $signed->url]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();
