# AI Terminal

This plugin requires this fork's native `server.terminal` bridge. It does not run on an unmodified Komari server. Existing Komari agents and browser terminals use their original protocol.

Copy `config.example.json` to `config.json` in the plugin root. Register each client's exact callback URI, host UUIDs and allowed scopes. Configure the administrator origin and grant lifetime there. Package `komari-plugin.json`, `script.js`, `styles.css` and `config.json` at the ZIP root, install the plugin and approve its HTTP-route and system-RPC permissions. No shell-exec, arbitrary filesystem or listener permission is needed.

Authorization uses the existing Komari administrator session and its configured 2FA policy. The approval page displays the client, selected hosts, scopes, callback and expiry. Codes are one-use, valid for 60 seconds, and bound to the client, redirect URI and PKCE S256 challenge. Access tokens expire at the configured time and can be revoked through the plugin's administrator page or the client's logout command. Revocation closes the grant's PTYs. Persisted grants live in Komari's `data/plugin-data/ai-terminal/grants.json`; tokens themselves are not stored there. Restarting Komari closes all PTYs; tokens keep their original expiry. Pending authorization codes/consent forms are in memory and must be restarted after a server restart.

The authorization and grant-management endpoints stay on the Cloudflare Access-protected administrator domain. Route only `/api/ai-terminal/oauth/token`, `/api/ai-terminal/oauth/revoke` and `/api/ai-terminal/pty/` to the public API origin, preserving `Authorization` for these paths. Keep the existing public dashboard's cookie/header stripping and protected admin routing. The plugin uses OAuth tokens on API routes; administrator cookies and API keys do not substitute for OAuth grants.

The local client and complete HTTP request contract are in [`skills/komari-terminal`](../../skills/komari-terminal/SKILL.md). PTY output is consumed by reads, not retained as a terminal recording. Only sessions created by the same grant are accessible; existing browser sessions are not attachable. Buffer exhaustion and unexpected disconnection are reported explicitly.

## Build

`Dockerfile.ai-terminal` builds the Go changes and replaces only `/app/komari` in the supplied existing Komari image. Supply `KOMARI_RUNTIME_IMAGE` as a build argument. It needs the normal upstream frontend inputs at `web/public/defaultTheme/komari-theme.json` and `dist.tar.zst`. For an existing deployment, pack that container's `/app/cache/dist` as `dist.tar.zst` to preserve the served frontend exactly, or build the frontend using the upstream composite action. Keep these generated inputs outside source control.

Back up the data directory and current image/configuration before replacing the Komari container. Keep the old image for rollback. No changes to SSH, monitoring agent configuration, or unrelated services are required.
