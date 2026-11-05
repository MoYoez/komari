# AI Terminal

This plugin requires this fork's native `server.terminal` bridge. It does not run on an unmodified Komari server. Existing Komari agents and browser terminals use their original protocol.

Copy `config.example.json` to `config.json` in the plugin root. Register each client's exact callback URI, host UUIDs and allowed scopes. Configure the administrator origin, `query_token_ttl_seconds` (query access, example: 30 days) and `access_token_ttl_seconds` (PTY access, example: 60 minutes) there. Package `komari-plugin.json`, `script.js`, `styles.css` and `config.json` at the ZIP root, install the plugin and approve its HTTP-route and system-RPC permissions. No shell-exec, arbitrary filesystem or listener permission is needed.

## Query first, then request terminal access

1. The human grants long-lived `access:read` through the existing authorization-code + PKCE flow. It cannot be combined with PTY scopes in one grant.
2. The AI calls `GET /api/ai-terminal/access` with that bearer token. The response contains `client_id`, `hosts` (`uuid` and current Komari `name`), `requestable_scopes`, `pty_token_ttl_seconds`, `query_expires_at` and active `grants` (`id`, `hosts`, `scopes`, `purpose`, `created_at`, `expires_at`). Grant metadata is restricted to the same user/client and hosts fully visible to this query token. No token, agent credential or terminal output is returned.
3. The AI creates a new short-term authorization URL with the ordinary OAuth parameters plus `hosts` (comma-separated UUIDs), `scope` (space-separated PTY scopes), and `purpose` (required human-readable text). The MD3 consent page shows those prefilled values. The human can deselect hosts/scopes or deny the request; the page cannot expand the requested scope or host list.
4. The separately issued short-lived token operates the PTY APIs. The query token cannot execute commands, read PTYs, approve requests or revoke other grants. It can revoke itself through the existing logout endpoint.

Host access is limited by the registered client and selected grant. Add a host to the plugin configuration and obtain new consent before including it in an existing client's query grant. Names are resolved from Komari rather than the example configuration's label.

Authorization uses the existing Komari administrator session and its configured 2FA policy. The approval page displays the client, selected hosts, scopes, callback and expiry. Codes are one-use, valid for 60 seconds, and bound to the client, redirect URI and PKCE S256 challenge. Access tokens expire at the configured time and can be revoked through the plugin's administrator page or the client's logout command. Revocation closes the grant's PTYs. Persisted grants live in Komari's `data/plugin-data/ai-terminal/grants.json`; tokens themselves are not stored there. Restarting Komari closes all PTYs; tokens keep their original expiry. Pending authorization codes/consent forms are in memory and must be restarted after a server restart.

The authorization and grant-management endpoints stay on the Cloudflare Access-protected administrator domain. Route only `/api/ai-terminal/access`, `/api/ai-terminal/oauth/token`, `/api/ai-terminal/oauth/revoke` and `/api/ai-terminal/pty/` to the API origin, preserving `Authorization` for these paths. Keep the existing public dashboard's cookie/header stripping and protected admin routing. The query API is OAuth-protected; it is not a public machine directory. Administrator cookies and API keys do not substitute for OAuth grants.

The local client and complete HTTP request contract are in [`skills/komari-terminal`](../../skills/komari-terminal/SKILL.md). PTY output is consumed by reads, not retained as a terminal recording. Only sessions created by the same grant are accessible; existing browser sessions are not attachable. Buffer exhaustion and unexpected disconnection are reported explicitly.

## Build

`Dockerfile.ai-terminal` builds the Go changes and replaces only `/app/komari` in the supplied existing Komari image. Supply `KOMARI_RUNTIME_IMAGE` as a build argument. It needs the normal upstream frontend inputs at `web/public/defaultTheme/komari-theme.json` and `dist.tar.zst`. For an existing deployment, pack that container's `/app/cache/dist` as `dist.tar.zst` to preserve the served frontend exactly, or build the frontend using the upstream composite action. Keep these generated inputs outside source control.

Back up the data directory and current image/configuration before replacing the Komari container. Keep the old image for rollback. No changes to SSH, monitoring agent configuration, or unrelated services are required.
