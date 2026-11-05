# OAuth PTY plugin and local Skill

Base: Komari 1.6.1. The existing agent and its PTY protocol remain in use.

## Delivery

1. A native plugin terminal bridge uses the existing terminal forwarding path with an in-memory peer instead of a browser WebSocket. Sessions belong to a plugin and an OAuth grant; they expire with the grant. Output is consumed as base64 bytes. Closed sessions remain readable until explicitly closed or expired. Buffer exhaustion is an explicit error.
2. `plugins/ai-terminal` implements OAuth authorization-code + PKCE S256, explicit administrator consent, host selection, expiring bearer tokens, revocation, and JSON PTY APIs. Deployment values live in its root `config.json`. No client secret or Komari administrator credential is distributed to the AI.
3. `skills/komari-terminal` contains SKILL.md and a dependency-free Node CLI. Login uses a loopback callback; open/read/write/resize/list/close use HTTP. The CLI configuration is at the Skill root. Credentials are local and ignored by Git.
4. Build a candidate image and check its binary in a temporary network-disabled container. Back up the data and deployment configuration, replace only Komari, install the plugin with the current host allowlist, and verify OAuth and persistent PTY interaction against the existing agent.

## HTTP contract

Prefix `/api/ai-terminal`. Admin domain: GET/POST `/oauth/authorize`, GET `/oauth/grants`, POST `/oauth/revoke-grant`. Public API domain: POST `/oauth/token`, POST `/oauth/revoke`, GET `/pty/sessions`, POST `/pty/open`, `/pty/read`, `/pty/write`, `/pty/resize`, `/pty/close`.

OAuth clients are pre-registered in configuration with exact redirect URIs. Scopes: `pty:read`, `pty:write`. Scope and host checks apply to every operation. Unknown inputs produce errors. No refresh flow in v1; log in again after expiration. Only sessions created by this grant can be read or changed. Existing browser terminals are not attached or intercepted.

## Verification

No new tests, test scaffolding or file checksums. Build and syntax checks plus real-host operational verification: consent, token exchange, open/read/write, shell state across requests, Ctrl-C, resize, list, close; unauthorized host/scope/token rejection and revocation. Capture concise sanitized evidence. Preserve theme, monitoring, Dokploy, ntfy and SSH configuration.
