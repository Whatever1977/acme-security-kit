# Diagrams

All architecture and flow diagrams for `acme/security-kit`. Source files are in `.puml` (PlantUML) format; rendered exports are in `.png`.

To regenerate PNGs after editing a `.puml` file:

```bash
plantuml -tpng diagrams/*.puml
```

Or using the Docker-based renderer (no local Java required):

```bash
docker run --rm -v "$(pwd)/diagrams:/work" plantuml/plantuml -tpng /work/*.puml
```

---

## Diagram Index

| File | Type | Description |
|------|------|-------------|
| [01-architecture-overview](01-architecture-overview.puml) | Component | High-level module map with dependency arrows |
| [02-class-diagram-crypto](02-class-diagram-crypto.puml) | Class | Crypto module: Key, KeySet, KeyProvider, HashEquals, SecureRandom |
| [03-class-diagram-authz](03-class-diagram-authz.puml) | Class | Authz module: RBAC roles, repositories, RbacAuthorizer |
| [04-class-diagram-audit](04-class-diagram-audit.puml) | Class | Audit module: Auditor interface, SecurityEvent, implementations |
| [05-sequence-csrf-flow](05-sequence-csrf-flow.puml) | Sequence | CSRF token issue and validate lifecycle |
| [06-sequence-jwt-flow](06-sequence-jwt-flow.puml) | Sequence | JWT mint (auth server) and validate (resource server) |
| [07-sequence-rbac-flow](07-sequence-rbac-flow.puml) | Sequence | RbacAuthorizer ABAC + RBAC decision logic |
| [08-sequence-oauth2-pkce-flow](08-sequence-oauth2-pkce-flow.puml) | Sequence | OAuth2 PKCE authorization code + refresh token rotation |
| [09-sequence-totp-flow](09-sequence-totp-flow.puml) | Sequence | TOTP enrolment (QR) and verification on login |
| [10-component-module-dependencies](10-component-module-dependencies.puml) | Component | Full module dependency map including external PSR libs |
| [11-state-key-rotation](11-state-key-rotation.puml) | State | Key lifecycle: Active → Retired → Revoked |
| [12-state-password-flow](12-state-password-flow.puml) | State | Password hashing, login verification, and rehash-on-login flow |
| [13-sequence-psr15-pipeline](13-sequence-psr15-pipeline.puml) | Sequence | PSR-15 middleware pipeline with CSRF and SignedUrl guards |
