# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/) (before 1.0, a minor release
may break the API).

## [Unreleased]

The first release. Everything below is new.

### Schemes

- `JwtScheme` and `SessionScheme`: one `CredentialScheme` over a
  `TokenStrategy` (signed JWTs, or opaque server-side sessions).
- `ApiKeyScheme` for machine-to-machine calls, with scopes.
- Compose several schemes on an enum of your own (`examples/composed_scheme.rs`).

### Capabilities (`supports_*`, routes auto-wired by `auth_service`)

- Registration, login and logout.
- Two-factor authentication: mailed codes, authenticator apps (TOTP) and
  recovery codes.
- Elevation ("sudo" mode) for password change, account deletion and other
  credential changes.
- Password reset; email verification; email change; passwordless login by
  mailed code or link.
- OAuth2 / OpenID Connect with PKCE, ID-token verification, discovery and
  provider presets (Google, Microsoft, GitHub); linking and unlinking
  providers.
- Passkeys (WebAuthn) with `WebAuthnRsVerifier`; listing, renaming and
  removing them.
- JWT refresh tokens with rotation and reuse detection; bearer tokens.
- Sessions: an absolute lifetime, a device list, ending one device.
- API-key self-service: issue, list, revoke, expiry and last use.

### Security

- Rate limits per account and per client on logins, 2FA, elevation, reset,
  verification mail and email change.
- Cross-site writes refused; `__Host-` cookies; `aud`/`iss` binding.
- Token epochs and ban lists, so revocation reaches every token.
- Password policy, with an optional breached-password check (HIBP).
- Argon2 hashing behind a semaphore, with rehash on login.
- Fuzz targets for client input (`fuzz/`).

### Stores and integration

- Every account has a stable id (`UserId`), carried by tokens (`uid`,
  `IdentityClaims::user_id`). Passkeys, provider links, authenticator
  apps and API keys belong to it, so an email change moves nothing; key
  your own tables on it.

- Postgres and Redis backends for every port, in-memory ones for tests.
- Public store contract tests (`testing` feature) for stores of your own.
- Typed mail (`Mail`, `EmailClient::send_mail`), audit events
  (`AuthEventSink`), a deferred-work runner, custom JWT claims.
- Store errors keep their source error (`Failure`).
- A `tempered.route` tracing span per request; counters behind `metrics`.
- A framework-neutral route table; the axum adapter mounts it.

Minimum supported Rust version: 1.91.

[Unreleased]: https://github.com/aleanon/Tempered/commits/main
