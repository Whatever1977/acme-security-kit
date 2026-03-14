# Threat Model

## Scope

`acme/security-kit` provides security building blocks for PHP web applications.
This document describes the threats we defend against, our mitigations, and
explicit non-goals.

---

## Assets

| Asset | Sensitivity | Module |
|-------|-------------|--------|
| CSRF tokens | High | `Csrf` |
| Signed URLs | High | `UrlSigner` |
| JWT access tokens | Critical | `Jwt` |
| Refresh tokens | Critical | `OAuth2` |
| Password hashes | Critical | `Password` |
| TOTP secrets | Critical | `Totp` |
| Signing keys | Critical | `Crypto` |
| Audit logs | High | `Audit` |

---

## Threat Actors

- **Passive network attacker**: reads traffic, cannot modify it.
- **Active network attacker (MITM)**: can read and modify traffic (mitigated by TLS at the application layer).
- **Compromised client / XSS attacker**: can read cookies/local storage accessible to JS.
- **Insider**: has read access to the database but not application code.
- **Brute-force attacker**: attempts dictionary/rainbow-table attacks on credentials.

---

## Threats and Mitigations

### T1 – CSRF Replay

**Threat**: Attacker tricks browser into replaying an old CSRF token.

**Mitigations**:
- Tokens are time-limited (default 1 hour) with `issuedAt` embedded.
- Per-form `$context` prevents cross-form replay.
- Optional one-time tokens add replay resistance for high-value forms.

---

### T2 – Signed URL Forgery

**Threat**: Attacker crafts a valid-looking signed URL for a different resource/expiry.

**Mitigations**:
- HMAC-SHA256 over the canonical URL (all query params, sorted).
- Expiration timestamp is part of the signed payload.
- Constant-time comparison on the signature.
- Key rotation with `kid` allows revocation of compromised keys.

---

### T3 – JWT Forgery / Algorithm Confusion

**Threat**: Attacker forges JWTs or exploits `alg: none` / RS256→HS256 confusion.

**Mitigations**:
- Algorithm is configured server-side in `JwtConfig`, never read from the token header.
- RS256 and ES256 use asymmetric keys; verification uses public key only.
- `iss` + `aud` claims validated strictly.
- `jti` required by default for replay prevention.

---

### T4 – OAuth2 Refresh Token Theft

**Threat**: Stolen refresh token used multiple times.

**Mitigations**:
- Refresh token rotation: each use issues a new token and revokes the old one.
- Reuse detection: if a revoked refresh token is presented, the entire family is revoked.
- PKCE required for public clients (prevents authorization code interception).

---

### T5 – Password Database Compromise

**Threat**: Attacker dumps password hashes and runs offline cracking.

**Mitigations**:
- Argon2id by default (memory-hard, GPU-resistant).
- `needsRehash()` enables in-place upgrades when parameters change.
- Optional HaveIBeenPwned check rejects known-compromised passwords at registration.

---

### T6 – TOTP Phishing / Brute Force

**Threat**: Real-time phishing or brute-force of TOTP codes.

**Mitigations**:
- Constant-time code comparison (no timing oracle).
- ±1 window (configurable) minimises brute-force surface while tolerating clock drift.
- Application layer should enforce rate limiting and lockout after N failures.

---

### T7 – Privilege Escalation via RBAC

**Threat**: Attacker manipulates role assignments to gain higher privileges.

**Mitigations**:
- Roles are resolved from a server-side repository (never from client tokens directly).
- Circular role inheritance is guarded against.
- ABAC attribute checks can further restrict access beyond roles.

---

## Non-Goals

- **Transport security (TLS)**: This library does not handle HTTPS termination.
- **DDoS / rate limiting**: Not implemented here; use a reverse proxy or a dedicated library.
- **SQL injection / XSS sanitisation**: Out of scope for a security-primitives library.
- **Hardware Security Modules (HSM)**: Key management is software-only.
- **Full OAuth2 server**: We provide components; see `league/oauth2-server` for a complete server.
