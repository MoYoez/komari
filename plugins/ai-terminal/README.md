# AI Terminal

This plugin requires this fork's native `server.terminal` bridge. It does not run on an unmodified Komari server. Existing Komari agents and browser terminals use their original protocol.

Copy `config.example.json` to `config.json` in the plugin root. Register each client's exact callback URI, host UUIDs and allowed scopes. Configure the administrator origin and `query_token_ttl_seconds` (query access, example: 30 days) there. PTY duration is selected for each request from three fixed choices: `60m` (60 minutes), `12h` (12 hours), or `24h` (24 hours). Package `komari-plugin.json`, `script.js`, `styles.css` and `config.json` at the ZIP root, install the plugin and approve its HTTP-route and system-RPC permissions. No shell-exec, arbitrary filesystem or listener permission is needed.

## Query first, then request terminal access

1. The human grants long-lived `access:read` through the existing authorization-code + PKCE flow. It cannot be combined with PTY scopes in one grant.
2. The AI calls `GET /api/ai-terminal/access` with that bearer token. The response contains `client_id`, `hosts` (`uuid` and current Komari `name`), `requestable_scopes`, `pty_durations` (`value`, `label`, `seconds`), `query_expires_at` and active `grants` (`id`, `hosts`, `scopes`, `purpose`, `created_at`, `expires_at`). Grant metadata is restricted to the same user/client and hosts fully visible to this query token. No token, agent credential or terminal output is returned.
3. The AI creates a new short-term authorization URL with the ordinary OAuth parameters plus `hosts` (comma-separated UUIDs), `scope` (space-separated PTY scopes), `duration` (`60m`, `12h` or `24h`), and `purpose` (required human-readable text). The MD3 consent page shows those prefilled values. The human can change the duration among the three choices, deselect hosts/scopes or deny the request; the page cannot expand the requested scope or host list. Missing or unsupported PTY durations are rejected. The final duration selected on the form is bound to the authorization code and determines `expires_in` and `expires_at` at token exchange.
4. The separately issued short-lived token operates the PTY APIs. The query token cannot execute commands, read PTYs, approve requests or revoke other grants. It can revoke itself through the existing logout endpoint.

Host access is limited by the registered client and selected grant. Add a host to the plugin configuration and obtain new consent before including it in an existing client's query grant. Names are resolved from Komari rather than the example configuration's label.

Authorization uses the existing Komari administrator session and its configured 2FA policy. The approval page displays the client, selected hosts, scopes, callback and duration. Codes are one-use, valid for 60 seconds, and bound to the client, redirect URI and PKCE S256 challenge. Tokens expire at the confirmed time and can be revoked through the plugin's administrator page or the client's logout command. Revocation closes the grant's PTYs. Persisted grants live in Komari's `data/plugin-data/ai-terminal/grants.json`; tokens themselves are not stored there. Restarting Komari closes all PTYs; tokens keep their original expiry. Pending authorization codes/consent forms are in memory and must be restarted after a server restart.

The authorization and grant-management endpoints stay on the Cloudflare Access-protected administrator domain. Route only `/api/ai-terminal/access`, `/api/ai-terminal/oauth/token`, `/api/ai-terminal/oauth/revoke` and `/api/ai-terminal/pty/` to the API origin, preserving `Authorization` for these paths. Keep the existing public dashboard's cookie/header stripping and protected admin routing. The query API is OAuth-protected; it is not a public machine directory. Administrator cookies and API keys do not substitute for OAuth grants.

The local client and complete HTTP request contract are in [`skills/komari-terminal`](../../skills/komari-terminal/SKILL.md). PTY output is consumed by reads, not retained as a terminal recording. Only sessions created by the same grant are accessible; existing browser sessions are not attachable. Buffer exhaustion and unexpected disconnection are reported explicitly.

## Build

`Dockerfile.ai-terminal` builds the Go changes and replaces only `/app/komari` in the supplied existing Komari image. Supply `KOMARI_RUNTIME_IMAGE` as a build argument. It needs the normal upstream frontend inputs at `web/public/defaultTheme/komari-theme.json` and `dist.tar.zst`. For an existing deployment, pack that container's `/app/cache/dist` as `dist.tar.zst` to preserve the served frontend exactly, or build the frontend using the upstream composite action. Keep these generated inputs outside source control.

Back up the data directory and current image/configuration before replacing the Komari container. Keep the old image for rollback. No changes to SSH, monitoring agent configuration, or unrelated services are required.
