<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Support;

use Acme\SecurityKit\Audit\Auditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use Acme\SecurityKit\UrlSigner\UrlSigner;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware that verifies signed URLs before passing to the handler.
 */
final class SignedUrlMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly UrlSigner $signer,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly ?Auditor $auditor = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $url = (string) $request->getUri();

        if (!$this->signer->verify($url)) {
            $this->auditor?->record(new SecurityEvent(
                'urlsig.invalid',
                new \DateTimeImmutable(),
                ['url' => $url],
                'warning',
            ));
            return $this->responseFactory->createResponse(403, 'Invalid or expired signed URL.');
        }

        return $handler->handle($request);
    }
}
