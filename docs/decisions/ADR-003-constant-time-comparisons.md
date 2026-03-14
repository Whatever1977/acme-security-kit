# ADR-003: Always Use `hash_equals()` for Secret Comparison

**Date:** 2024-01  
**Status:** Accepted

## Context

Comparing cryptographic secrets, tokens, MACs, and signatures with the `===`
operator (or `strcmp()`) causes the PHP engine to short-circuit on the first
differing byte. An attacker who can measure response times can exploit this
timing differential to reconstruct a valid token byte-by-byte — a
*timing side-channel attack*.

This vulnerability affects all of the following in `acme/security-kit`:

- CSRF token validation
- Signed URL signature comparison
- PKCE `code_challenge` verification
- Any HMAC digest comparison

## Decision

All comparisons involving secrets, MACs, signatures, or any value derived from
cryptographic material **must** go through the `ConstantTime` interface, backed
by `HashEquals` which delegates to PHP's built-in `hash_equals()`.

```php
// WRONG — vulnerable to timing attacks
if ($submittedToken === $expectedToken) { ... }

// CORRECT — constant-time
if ($this->constantTime->equals($expectedToken, $submittedToken)) { ... }
```

The `ConstantTime` interface is injected wherever secret comparison is needed,
making it easy to swap implementations in tests and making the security contract
visible at the type level.

## Consequences

**Positive:**
- Eliminates timing oracle vulnerabilities across the entire toolkit.
- The explicit interface makes auditing easy — grep for `ConstantTime` usages.
- Behaviour is trivially testable with `NullAuditor` and mock comparators.

**Negative:**
- Slight verbosity vs. a plain `===` comparison.
- Developers must remember to use the interface; PHPStan cannot enforce this
  automatically (though a custom rule could be added).

## Alternatives Considered

- **`sodium_memcmp()`** — equally correct, but requires the `sodium` extension
  which is not universally available. `hash_equals()` is available in all
  PHP 8.x installations without extra extensions.
- **Inline `hash_equals()` calls** — rejected in favour of the injectable
  interface, which improves testability.
