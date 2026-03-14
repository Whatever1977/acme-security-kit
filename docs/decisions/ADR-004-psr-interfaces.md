# ADR-004: Target PSR-3, PSR-7, and PSR-15 Interfaces Throughout

**Date:** 2024-01  
**Status:** Accepted

## Context

PHP has several well-established interoperability standards (PSR) from the
PHP-FIG. By depending on PSR interfaces rather than concrete implementations,
`acme/security-kit` can be consumed by any framework that implements those
standards — Laravel, Symfony, Slim, Mezzio, and others — without binding users
to any particular HTTP layer.

The relevant standards are:

| PSR | What it defines | Used by |
|-----|-----------------|---------|
| PSR-3 | `LoggerInterface` | `Audit` module |
| PSR-7 | HTTP message interfaces (`RequestInterface`, `ResponseInterface`) | `Support` middleware |
| PSR-15 | `MiddlewareInterface`, `RequestHandlerInterface` | `CsrfMiddleware`, `SignedUrlMiddleware` |
| PSR-17 | HTTP factory interfaces (`ResponseFactoryInterface`) | `Support` middleware |

## Decision

- The `Audit` module accepts `Psr\Log\LoggerInterface` — any Monolog, Laravel
  Log, or Symfony logger works without adapters.
- The PSR-15 middleware in `Support\` depends only on PSR-7 and PSR-15
  interfaces, making them usable in any compliant stack.
- The library ships **no** concrete HTTP implementation. Users bring their own
  PSR-17 factory (e.g., `nyholm/psr7`, `guzzlehttp/psr7`).

## Consequences

**Positive:**
- Zero framework lock-in.
- Middleware tests can use lightweight PSR-7 implementations (e.g., `nyholm/psr7`).
- Clear boundaries: the library never pulls in a full HTTP framework.

**Negative:**
- Users must provide a PSR-17 `ResponseFactoryInterface` when wiring up
  middleware — a one-time DI configuration step.
- PSR-7 is immutable by design; middleware must use `withAttribute()` to pass
  data through the pipeline rather than mutating the request.

## Alternatives Considered

- **Bundle a PSR-7 implementation** — rejected; forces a specific implementation
  on consumers.
- **Symfony HttpFoundation / Laravel Request** — rejected; ties the library to
  specific frameworks.
