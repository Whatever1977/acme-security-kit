# ADR-005: Use Immutable Value Objects for All Tokens and Keys

**Date:** 2024-01  
**Status:** Accepted

## Context

Security-sensitive objects — tokens, keys, decisions — must not be mutated
after creation. Mutable state in security primitives creates subtle bugs:
a partially-constructed token could be passed to validation code; a key's
material could be overwritten after signing; a decision object's `allowed`
field could be flipped after the RBAC check.

PHP 8.2 introduced `readonly` properties, which provides first-class language
support for immutable objects.

## Decision

All value objects in `acme/security-kit` use `readonly` constructor-promoted
properties, making them fully immutable after construction:

```php
final class SecurityEvent
{
    public function __construct(
        public readonly string $type,
        public readonly \DateTimeImmutable $at,
        public readonly array $context = [],
        public readonly string $severity = 'info',
    ) {}
}
```

All token and key objects (`Key`, `SecurityEvent`, `Decision`, `Role`) are
`final` to prevent subclass mutation.

`DateTimeImmutable` is used exclusively (never `DateTime`) for timestamps.

## Consequences

**Positive:**
- No defensive copying required — consumers can safely store references.
- PHP 8.2+ `readonly` prevents accidental mutation at compile/runtime.
- `final` classes prevent inheritance-based mutation tricks.
- `DateTimeImmutable` operations always return new instances.

**Negative:**
- PHP 8.2 minimum is required (matches the library's stated requirement).
- Readonly arrays in PHP still allow mutating nested objects — documented
  as a known limitation.

## Alternatives Considered

- **Mutable objects with clone-on-write** — rejected; too easy to forget.
- **PHP 8.1 `readonly` on individual properties** — considered, but PHP 8.2
  full constructor promotion is cleaner.
