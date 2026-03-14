# ADR-002: Default to Argon2id for password hashing

## Status

Accepted

## Context

PHP supports `bcrypt`, `Argon2i`, and `Argon2id`. bcrypt has a 72-byte password
limit and is susceptible to GPU acceleration relative to Argon2. Argon2id is the
OWASP-recommended default as of 2023.

## Decision

`Argon2idHasher` uses `PASSWORD_ARGON2ID` as the default algorithm.
A `bcrypt` hasher can be added if legacy support is needed, but it is not the
default in this library.

## Consequences

- PHP 7.3+ / 8.x all support Argon2id.
- `password_needs_rehash()` ensures a smooth migration path if parameters change.
- Higher memory / time cost vs bcrypt — users can tune via constructor options.
