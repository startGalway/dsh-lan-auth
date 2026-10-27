# `@dsh-lan-auth/server`

Single-file, dependency-free password gate + reverse proxy for a loopback-only
DeepSeek Harness Web GUI.

```bash
node server.js --set-password 'your-password'
node server.js            # listens on every non-loopback IPv4, port 3080
```

## How it authenticates

1. Unauthenticated request → `303` to `/__unlock` (password form).
2. Correct password → signed `HttpOnly` cookie (HMAC-SHA256, default 365 days) → `303` back to the requested path.
3. Authenticated request → proxied to the loopback GUI with `Host`/`Origin`
   rewritten and the harness's own session cookie injected server-side.

The harness cookie is read from `$DSH_LAN_AUTH_STATE_DIR/harness-cookie` when
possible; otherwise it is minted by redeeming the launch token that `dsh web`
prints into its systemd journal (`journalctl --user -u $DSH_LAN_AUTH_UNIT`).
A `401` from upstream triggers one refresh-and-retry.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/__unlock` | GET | password page |
| `/__unlock` | POST | verify password, set cookie |
| `/__lock` | GET | clear the cookie |
| everything else | any | proxied to the harness (requires the cookie) |

## Environment

See the table in the repository README. Notable defaults:

- `DSH_LAN_AUTH_UPSTREAM=127.0.0.1:3080`
- `DSH_LAN_AUTH_PORT=3080`
- `DSH_LAN_AUTH_UNIT=dsh-web`
- `DSH_LAN_AUTH_STATE_DIR=~/.config/dsh-lan-auth`

## Security notes

- Passwords are stored as scrypt (N=16384, r=8, p=1) with a per-install salt, `0600`.
- The device cookie is signed with `$DSH_LAN_AUTH_STATE_DIR/secret` (32 random bytes).
- Failed logins are limited to 8 per 10 minutes per source IP.
- Rotate the secret to force every device to sign in again.
