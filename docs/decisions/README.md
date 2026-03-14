# Architecture Decision Records

This directory records significant architectural decisions made during the development of `acme/security-kit`.

Each ADR follows the format:

- **Status** – Proposed / Accepted / Deprecated / Superseded
- **Context** – Why the decision was needed
- **Decision** – What was decided
- **Consequences** – Trade-offs and implications

## Index

| ID | Title | Status |
|----|-------|--------|
| [ADR-001](ADR-001-jwt-library.md) | Use `firebase/php-jwt` instead of hand-rolled JWT | Accepted |
| [ADR-002](ADR-002-argon2id-default.md) | Default to Argon2id for password hashing | Accepted |
| [ADR-003](ADR-003-constant-time-comparisons.md) | Always use `hash_equals()` for secret comparison | Accepted |
| [ADR-004](ADR-004-psr-interfaces.md) | Target PSR-3, PSR-7, PSR-15 interfaces throughout | Accepted |
| [ADR-005](ADR-005-immutable-value-objects.md) | Use immutable value objects for all tokens and keys | Accepted |
