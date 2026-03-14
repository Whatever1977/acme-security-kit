
# Contributing to acme/security-kit

Thank you for your interest in improving **acme/security-kit**! This document explains how to contribute code, documentation, and bug reports.

---

## Before You Start

- Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.
- For large or API-breaking changes, open an issue first to discuss the approach before writing code.

---

## Development Setup

```bash
git clone https://github.com/PanagiotisKotsorgios/acme-security-kit.git
cd security-kit
composer install
```

Required PHP extensions: `openssl`, `mbstring` (plus `sodium` for the test suite).

---

## Running the Quality Suite

All of the following must pass before a pull request is merged:

```bash
# Unit tests
vendor/bin/phpunit

# Static analysis (PHPStan level 8)
vendor/bin/phpstan analyse

# Code style (PSR-12 + project rules)
vendor/bin/php-cs-fixer fix --dry-run --diff

# Rector upgrade suggestions (new code must pass with no changes)
vendor/bin/rector process --dry-run

# Mutation testing (run locally before pushing to main)
vendor/bin/infection --min-msi=70 --min-covered-msi=80
```

CI runs all of the above automatically on every pull request.

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```

2. **Write tests first** — this is a security library and every public method must have test coverage. Prefer unit tests; integration tests live in `tests/` subdirectories named after the module.

3. **Follow the coding style** enforced by PHP CS Fixer. Run `vendor/bin/php-cs-fixer fix` to auto-correct formatting before committing.

4. **Update documentation** if you change public interfaces or add new features. Update the relevant section in `README.md` and, if appropriate, `docs/threat-model.md`.

5. **Add a changelog entry** in the `Unreleased` section of `CHANGELOG.md` (if one exists), or note the change in your PR description.

6. **Keep commits focused** — one logical change per commit. Prefer squashing before opening the PR.

7. Open a pull request against `main`. Fill in the PR template (bug fix, feature, docs, etc.) and link any related issues.

8. At least one maintainer review is required before merging.

---

## Contribution Scope

This library provides **security primitives**, not application logic. When proposing new modules, ask:

- Does this belong in a security-primitives library, or is it better served by a dedicated package?
- Does it follow the existing design principles (PSR interfaces, immutable value objects, explicit error types)?
- Is it documented in the threat model?

Contributions that introduce new dependencies need a strong justification. The current production dependency surface is intentionally small (`psr/*`, `firebase/php-jwt`, `paragonie/constant_time_encoding`).

---

## Security-Sensitive Changes

Changes to cryptographic code, token validation logic, or any module listed in `docs/threat-model.md` require extra care:

- Include a short explanation of the security impact in the PR description.
- Reference the relevant threat(s) from the threat model.
- Maintainers will take additional time to review these PRs — please be patient.

---

## Reporting Bugs

Open a new issue.

- PHP version and OS
- The minimal code that reproduces the problem
- Expected vs. actual behavior
- Any relevant error messages or stack traces

**Do not include sensitive data** (real secrets, tokens, user data) in issue reports.

---

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
