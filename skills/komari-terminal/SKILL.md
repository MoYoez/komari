---
name: komari-terminal
description: Query Komari hosts and existing grants with long-lived OAuth access, then obtain separate human-approved short-lived PTY access for a specific task through the local Node CLI.
---

# Komari terminal

Use Node.js 22 or newer; no packages are required. This calls the generic Komari AI terminal API, with no OpenAI integration or SSH secrets.

Copy `config.example.json` to `config.json` in this Skill's root and set all four deployment values. `authorization_url` is the administrator consent endpoint; `api_base` is the public API prefix with no trailing slash, query, or fragment. Register `client_id` and the exact `redirect_uri` with the server. This version requires `http://127.0.0.1:PORT/callback`, with one fixed port from 1 to 65535. The browser must reach the CLI's own loopback listener.

Run commands from this Skill's directory (or use the script's absolute path):

```sh
node scripts/komari-pty.mjs [--config CONFIG_PATH] COMMAND [ARGS...]
```

`--config` must precede the command. Without it, the script reads this Skill's root `config.json`, independent of the working directory. An explicit relative path is relative to the working directory. Long-lived query credentials use `access-credentials.json`; short-lived PTY credentials use `credentials.json`, both beside the selected config. Keep the config and both credential files local and untracked, including in custom directories.

## Authorization and use

1. Run `access` to query allowed machines and existing grant metadata. Run `login` only when query credentials are missing or expired: it requests only `access:read` and never grants terminal access. Present the returned authorization URL and wait for the human to approve it.
2. Use `/access` results and the actual task to prefill host UUIDs, PTY scopes, and a concrete purpose. If the local PTY grant already covers the task and is valid, reuse it. Otherwise run `authorize HOSTS_CSV SCOPES_CSV PURPOSE`; all three arguments are required. The CLI queries `/access` again and rejects hosts or scopes outside its permissions before generating a consent URL.
3. Present the generated URL as a clickable link, with the selected hosts, scopes, and purpose for the human to review. A browser tool may open the link; the human must personally confirm the grant. Never automatically click approval, submit consent, use hidden administrator credentials, or expose either token or the PKCE verifier. The CLI does not launch a browser.
4. After approval, use the short-lived PTY credential to operate the authorized hosts. Retain each returned session ID and repeat `read` and `write`/`command` with it to preserve shell state, working directory, and running processes. Use `interrupt` for Ctrl-C, then read the output. Close sessions when finished.

The server config controls both lifetimes: the agreed query grant is 30 days and the PTY grant is 60 minutes; the CLI uses the returned expiry rather than hardcoding either duration. Each interactive OAuth flow times out after five minutes. There is no refresh or retry. Missing, invalid, expired, or rejected query credentials point to `login`; PTY credentials point to `authorize HOSTS_CSV SCOPES_CSV PURPOSE`. Do not silently switch between credentials. Existing browser terminals cannot be attached to or intercepted in v1; only PTYs created under the current PTY grant are accessible.

| Command | Behavior |
| --- | --- |
| `login` | Authorization Code + PKCE S256 for `access:read`; saves only `access-credentials.json`. |
| `access` | `GET /access` with the long-lived bearer token; outputs host and grant metadata, without tokens. |
| `authorize HOSTS_CSV SCOPES_CSV PURPOSE` | Query `/access`, validate selected permissions, then obtain separate PKCE consent and save only `credentials.json`. |
| `list` | `GET /pty/sessions`. |
| `open CLIENT_UUID` | `POST /pty/open` with `{client_uuid, cols:120, rows:30}`. |
| `read ID [WAIT_MS]` | `POST /pty/read` with `{id, wait_ms}`; omitted wait is 0 ms. |
| `write ID TEXT` | `POST /pty/write` with `{id, data_base64}`; sends exactly the UTF-8 bytes of the single TEXT argument, without a newline. |
| `command ID TEXT` | Same as `write`, with exactly one LF byte appended. |
| `interrupt ID` | Same write endpoint, sending only Ctrl-C (`0x03`). |
| `resize ID COLS ROWS` | `POST /pty/resize` with `{id, cols, rows}`; positive integers. |
| `close ID` | `POST /pty/close` with `{id}`. |
| `logout` | Revoke the short-lived PTY token, then delete only `credentials.json` on success. |
| `logout-access` | Revoke the long-lived query token, then delete only `access-credentials.json` on success. |

Quote TEXT and PURPOSE for the invoking shell so each arrives as one argument. CSV arguments require distinct values with no surrounding whitespace; scopes are selected from `pty:read,pty:write`. WAIT_MS must be a nonnegative integer. Unsupported input and failed requests exit nonzero with a concise JSON error on stderr. Successful output is JSON on stdout; `login` and `authorize` first emit the authorization URL, then a separate result without tokens. Neither flow overwrites the other credential file. Revocation uses form-encoded `POST /oauth/revoke` with `token`; failures preserve the local file and never silently skip revocation.

## API response contract

All paths above are relative to `api_base`. `GET /access` uses the query bearer token and returns `{client_id, hosts:[{uuid,name}], requestable_scopes:["pty:read","pty:write"], pty_token_ttl_seconds, query_expires_at, grants:[{id,hosts,scopes,created_at,expires_at,purpose}]}`. This is metadata, never a token source.

Both OAuth flows use random state and PKCE S256. `login` sets `scope=access:read`. `authorize` converts SCOPES_CSV to a space-separated `scope` and adds `hosts` as comma-separated UUIDs and `purpose` to the authorization URL. Token exchange uses form-encoded `POST /oauth/token` with `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, and `code_verifier`, without a client secret. Its JSON response must include `access_token`, `token_type` (`Bearer`, case-insensitive), `expires_at` (Unix seconds), `scope` (space-separated string), `allowed_hosts` (UUID array), and `grant_id` (string). Store exactly those fields in the appropriate credential file, preserving the server's expiry. All PTY commands use only the short-lived bearer token. API errors use `error` and `error_description`.

PTY success responses are JSON; `list` returns an array. `read` requires a top-level `data_base64` string with standard padded base64; the CLI preserves it and adds `output` decoded as UTF-8. ANSI controls are JSON-escaped. Preserve base64 bytes when exact reconstruction matters, including UTF-8 characters split between reads. Other PTY responses pass through unchanged. Revocation accepts any successful HTTP response, including an empty body.
