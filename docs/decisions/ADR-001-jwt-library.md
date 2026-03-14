# ADR-001: Use firebase/php-jwt instead of hand-rolled JWT

## Status

Accepted

## Context

Implementing JWT signing and verification correctly requires careful handling of:
- Algorithm confusion attacks (`alg: none`, RS256→HS256 downgrade)
- Timing attacks during signature comparison
- Edge cases in base64url encoding and JSON serialisation

## Decision

Wrap `firebase/php-jwt` (widely audited, ~20M downloads/week) rather than
hand-rolling JWT logic. Our `FirebaseJwtManager` adds:

- Key management via `KeyProvider` / `KeySet`
- Strict claim validation (`iss`, `aud`, `jti`)
- Audit logging on validation failures
- Policy objects (`JwtConfig`) for all security parameters

## Consequences

- Less code to audit in this library for JWT internals.
- Dependency on an external library; pinned via Composer.
- Algorithm is locked in `JwtConfig` server-side — never read from the token header.
