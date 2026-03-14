# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | ✅ Active          |
| < 1.0   | ❌ Not supported   |

Security fixes are backported to the latest patch release of the current stable minor version.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

If you believe you have found a security vulnerability in `acme/security-kit`, please disclose it responsibly using one of the methods below.

### Option A — GitHub Private Security Advisory (preferred)

Use [GitHub's private vulnerability reporting](https://github.com/acme/security-kit/security/advisories/new) to submit a report confidentially. This keeps the disclosure private until a fix is released.

### Option B — Email

Send a PGP-encrypted email to **security-kit@acme.example**. Include the following in your report:

- A description of the vulnerability and the affected component
- The version(s) affected
- Step-by-step reproduction instructions or a minimal proof-of-concept
- Your assessment of the potential impact (CVSS score if possible)
- Any suggested mitigations or patches (optional but appreciated)

We will acknowledge receipt within **2 business days** and aim to provide a full response — including a remediation timeline — within **7 business days**.

---

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. You report the vulnerability privately.
2. We confirm receipt and begin investigation.
3. We develop and test a fix (typically within 14–30 days, depending on severity).
4. We release the fix and publish a GitHub Security Advisory.
5. You are credited in the advisory unless you prefer to remain anonymous.

We ask that you do not publish details of the vulnerability until a fix has been released, or until 90 days have elapsed from the initial report — whichever comes first.

---

## Scope

The following are **in scope** for this policy:

- All modules in `src/` (`Crypto`, `Csrf`, `UrlSigner`, `Jwt`, `OAuth2`, `Password`, `Totp`, `Authz`, `Audit`)
- The PSR-15 middleware helpers in `src/Support/`

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report those to the upstream project)
- Issues that require a compromised server or host-level access to exploit
- Denial-of-service via unbounded computation if the caller controls input size (document this as expected behavior instead)

---

## Security Design

For our threat model, security guarantees, and known non-goals, see [`docs/threat-model.md`](docs/threat-model.md).

Key guarantees at a glance:

- All random values use `random_bytes()` (CSPRNG).
- All secret/token comparisons use `hash_equals()` (constant-time).
- JWT algorithm is configured server-side — never read from the token header.
- PKCE: only `S256` is accepted.
- Argon2id is the default password hashing algorithm.

---

## Bug Bounty

This project does not currently operate a paid bug bounty program. We do credit reporters in security advisories and are happy to provide a letter of acknowledgement upon request.
