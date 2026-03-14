# ADR-001: Wrap firebase/php-jwt Rather Than Hand-Rolling JWT

**Date:** 2024-01  
**Status:** Accepted

## Context

JWTs require careful implementation of signature verification, claim validation, and algorithm handling. Common vulnerabilities include the `alg:none` attack, algorithm confusion (RS256 public key used as HS256 secret), and improper claim validation.

## Decision

We wrap `firebase/php-jwt` (the most widely-used, battle-tested PHP JWT library) rather than implementing JWT encode/decode from scratch.

Our `FirebaseJwtManager`:
- Supplies the allowed algorithm explicitly (not read from the JWT header)
- Uses `firebase/php-jwt`'s `Key` class to enforce key-algorithm binding
- Adds our own `iss`/`aud`/`jti` validation layer on top

## Consequences

**Positive:**
- Benefits from upstream security fixes automatically.
- Eliminates entire classes of hand-rolled JWT bugs.
- Reduces library surface area.

**Negative:**
- One additional dependency.
- Must track `firebase/php-jwt` deprecations.

## Alternatives Considered

- `lcobucci/jwt` — well-respected, but more verbose API; `firebase/php-jwt` is more approachable for contributors.
- Hand-rolled — rejected; no justification for the risk.
