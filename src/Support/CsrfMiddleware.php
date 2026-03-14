<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Support;

use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use Acme\SecurityKit\Csrf\CsrfManager;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware that validates CSRF tokens on mutating HTTP methods.
 */
final class CsrfMiddleware implements MiddlewareInterface
{
    private const MUTATING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function __construct(
        private readonly CsrfManager $csrfManager,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly ?Auditor $auditor = null,
        private readonly string $headerName = 'X-CSRF-Token',
        private readonly string $formFieldName = '_csrf_token',
        private readonly string $sessionIdAttribute = 'session_id',
        private readonly string $contextAttribute = 'csrf_context',
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array($request->getMethod(), self::MUTATING_METHODS, true)) {
            return $handler->handle($request);
        }

        $sessionId = (string) ($request->getAttribute($this->sessionIdAttribute) ?? '');
        $context   = (string) ($request->getAttribute($this->contextAttribute) ?? 'default');
        $token     = $request->getHeaderLine($this->headerName);

        if ($token === '') {
            /** @var array<string, mixed> $body */
            $body  = (array) ($request->getParsedBody() ?? []);
            $token = (string) ($body[$this->formFieldName] ?? '');
        }

        if (!$this->csrfManager->validate($sessionId, $context, $token)) {
            $this->auditor?->record(new SecurityEvent(
                'csrf.invalid',
                new \DateTimeImmutable(),
                ['method' => $request->getMethod(), 'path' => $request->getUri()->getPath()],
                'warning',
            ));
            return $this->responseFactory->createResponse(419, 'CSRF token invalid or expired.');
        }

        return $handler->handle($request);
    }
}
