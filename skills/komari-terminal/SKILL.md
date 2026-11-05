---
name: komari-terminal
description: Use the local Node CLI to authorize Komari OAuth access and operate persistent PTY sessions on explicitly selected hosts.
---

# Komari terminal

Use Node.js 22 or newer; no packages are required. This calls the generic Komari AI terminal API, with no OpenAI integration or SSH secrets.

Copy `config.example.json` to `config.json` in this Skill's root and set all four deployment values. `authorization_url` is the administrator consent endpoint; `api_base` is the public API prefix with no trailing slash, query, or fragment. Register `client_id` and the exact `redirect_uri` with the server. This version requires `http://127.0.0.1:PORT/callback`, with one fixed port from 1 to 65535. The browser must reach the CLI's own loopback listener.

Run commands from this Skill's directory (or use the script's absolute path):

```sh
node scripts/komari-pty.mjs [--config CONFIG_PATH] COMMAND [ARGS...]
```

`--config` must precede the command. Without it, the script reads this Skill's root `config.json`, independent of the working directory. An explicit relative path is relative to the working directory. Credentials are always stored as `credentials.json` beside the selected config; keep both files local and untracked, including when using a custom directory.

## Authorization and use

Run `login` only when there is no valid local token: the requested operation reports missing or expired credentials explicitly. Login prints a JSON `authorization_url`; present it as a clickable link for the human or open it with an available browser tool. The CLI does not launch a browser. Wait for the user to explicitly consent and select hosts. Never automatically approve the OAuth grant, use hidden administrator credentials, or print the token or PKCE verifier. Login expires after five minutes. There is no refresh flow; an expired token requires `login` again.

Use `open` for an allowed host and retain its returned session ID. Repeat `read` and `write`/`command` with that same ID to preserve shell state, working directory, and running processes. Use `interrupt` for Ctrl-C and keep reading for the resulting output. Close sessions when finished, and use `logout` to revoke the grant and remove local credentials. Existing browser terminals cannot be attached to or intercepted in v1; only PTYs created under this grant are accessible.

| Command | Behavior |
| --- | --- |
| `login` | Authorization Code + PKCE S256, requesting `pty:read pty:write`; saves credentials locally. |
| `list` | `GET /pty/sessions`. |
| `open CLIENT_UUID` | `POST /pty/open` with `{client_uuid, cols:120, rows:30}`. |
| `read ID [WAIT_MS]` | `POST /pty/read` with `{id, wait_ms}`; omitted wait is 0 ms. |
| `write ID TEXT` | `POST /pty/write` with `{id, data_base64}`; sends exactly the UTF-8 bytes of the single TEXT argument, without a newline. |
| `command ID TEXT` | Same as `write`, with exactly one LF byte appended. |
| `interrupt ID` | Same write endpoint, sending only Ctrl-C (`0x03`). |
| `resize ID COLS ROWS` | `POST /pty/resize` with `{id, cols, rows}`; positive integers. |
| `close ID` | `POST /pty/close` with `{id}`. |
| `logout` | Form-encoded `POST /oauth/revoke` with `token`, then deletes local credentials on success. |

Quote TEXT for the invoking shell so it arrives as one argument. WAIT_MS must be a nonnegative integer. Unsupported commands, arguments, configuration, and failed requests exit nonzero with a concise JSON error on stderr. Successful output is JSON on stdout; login first emits the authorization URL and then a separate result without the access token. No command retries automatically.

## API response contract

All paths above are relative to `api_base`. Token exchange uses form-encoded `POST /oauth/token` with `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, and `code_verifier`, without a client secret. Its JSON response must include `access_token`, `token_type` (`Bearer`, case-insensitive), `expires_at` (Unix seconds), `scope` (space-separated string), `allowed_hosts` (UUID array), and `grant_id` (string). The CLI stores exactly those fields, preserving the server's expiry. PTY calls use the stored bearer token. API errors use `error` and `error_description`.

PTY success responses are JSON; `list` returns an array. `read` requires a top-level `data_base64` string with standard padded base64; the CLI preserves it and adds `output` decoded as UTF-8. ANSI controls are JSON-escaped. Preserve base64 bytes when exact reconstruction matters, including UTF-8 characters split between reads. Other PTY responses pass through unchanged. Revocation accepts any successful HTTP response, including an empty body.
