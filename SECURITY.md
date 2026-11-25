# Security policy

`tempered` is an authentication library, so a flaw in it is a flaw in every
service that uses it. Reports are welcome and taken seriously.

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/aleanon/Tempered/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). Please do not
open a public issue for a security problem.

Include what you can of:

- the affected version or commit, and the features and capabilities enabled;
- what an attacker can do, and what they need first (an account, a stolen
  token, a position on the network);
- steps or a test that shows it.

You can expect an acknowledgement within a week. Once a fix is ready it is
released and published as a GitHub security advisory, crediting you unless
you ask otherwise.

## Supported versions

Before 1.0, only the latest release gets fixes. Breaking changes may come
with any 0.x release; the [CHANGELOG](CHANGELOG.md) lists them.

## Scope

In scope: the crates in this repository (`tempered`, `tempered_core`,
`tempered_adapters`, `tempered_axum`) and the behaviour their docs promise.
For example: tokens, sessions and API keys; 2FA, elevation, password reset
and email flows; passkeys and OAuth; rate limits; the store backends and
their contracts.

Out of scope: the examples' demo configuration (in-memory stores, the
`.env.example` secrets); misconfiguration the docs warn against (sharing a
code store between 2FA and email login, a reverse proxy without
`client_address`); and vulnerabilities in dependencies, which belong
upstream (tell us too if `tempered` makes one reachable).

## Hardening already in place

The design notes in [`ARCHITECTURE.md`](ARCHITECTURE.md) and the review
history in [`docs/`](docs/) record the threat model. The parsers that read
what a client sends are fuzzed (`fuzz/`).
