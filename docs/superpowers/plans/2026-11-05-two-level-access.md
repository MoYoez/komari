# Two-level AI Terminal authorization

The user approved long-lived access only for querying machines and existing permissions. PTY access still requires a separate short-lived human-approved OAuth grant.

1. Add `access:read`, issued by the existing authorization-code + PKCE flow. Configure its lifetime as `query_token_ttl_seconds` (this deployment: 30 days), separately from the existing 60-minute PTY lifetime. A grant cannot mix query and PTY scopes.
2. Add `GET /api/ai-terminal/access`. A query token returns only its allowed host UUIDs/current Komari names, requestable PTY scopes, lifetime and the same user's/client's active grant metadata within those hosts. It returns no tokens, agent credentials, terminal output or execution capability.
3. Short-lived OAuth requests must specify `hosts` (comma-separated UUIDs), `scope` and `purpose`. Show the prefilled choices and purpose on the existing MD3 consent page. Human consent and the existing administrator/2FA flow remain necessary. Bind the selected grant lifetime and purpose through the one-use code into the token.
4. Extend the local CLI: `login` obtains query access; `access` queries it; `authorize HOSTS_CSV SCOPES_CSV PURPOSE` checks the query result and opens a prefilled PKCE consent flow. Store query and PTY credentials separately. Existing PTY commands use the short-lived file. Add query logout, with no refresh, retries or automatic approvals.
5. Back up the plugin and current Traefik route. Replace/reload only the plugin, adding only the exact `/access` path to its existing Bearer-preserving API route. No Go binary or agent change is needed.
6. Verify syntax and inspect the changes without adding tests/scaffolding/checksums. Check real rendered consent, unauthorized API rejection, and—only after user consent—query metadata, separation from PTY, prefilled short-term approval and actual persistent PTY operations. Capture sanitized results.

## Confirmed duration revision

The user requested PTY choices of 60 minutes, 12 hours and 24 hours. Replace the fixed PTY configuration value with named choices (`60m`, `12h`, `24h`), expose them as `pty_durations` through `/access`, and require the AI to supply `duration`. Add MD3 radio controls so the human may change the prefilled duration. Validate the final selection on POST and bind that duration through code exchange to token expiry. The CLI becomes `authorize HOSTS_CSV SCOPES_CSV DURATION PURPOSE`; no missing-duration default is supported. Query access remains separately configured at 30 days. Back up and reload only the plugin and update the installed Skill; no binary, route or permission changes. Verify syntax and the real rendered choices without submitting human consent.
