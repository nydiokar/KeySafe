# FastAPI server: direction, current state, remaining work

Decision record and history: `docs/PROJECT_HISTORY.md`.
File: `secure_credentials/src/api/server.py` (entry point: `secure-credentials-api`).

## 1. Goal

Reach the KeePass vault from other devices (phone, laptop) over a **private network**, without
exposing it to the public internet. Read/retrieve only: list entries, view one entry.
Write operations from the network are out of scope unless a concrete need appears.

## 2. Network binding must be network-agnostic

Yggdrasil was a trial. The server must work on any private network: Tailscale, WireGuard,
ZeroTier, Yggdrasil, a plain LAN, or loopback behind a reverse proxy.

Current code: `YGGDRASIL_IP` is the only way to set the bind address and it is mandatory.

Required change:
- Replace with a generic `BIND_HOST` (IPv4, IPv6 or hostname). Keep `YGGDRASIL_IP` as a deprecated alias for one release.
- Default `127.0.0.1` when unset (safe: unreachable from other machines).
- Refuse `0.0.0.0` / `::` unless `ALLOW_PUBLIC_BIND=1` is set, with a warning.
- Keep `API_PORT`.
- Do not hard-code any network name in messages or docs; docs show one example per network.

How each network is used:

| Network | Bind to | Notes |
|---|---|---|
| Tailscale | the node's `100.x` / `fd7a:...` address, **or** `127.0.0.1` + `tailscale serve` | `tailscale serve` adds HTTPS with an automatic certificate |
| WireGuard / ZeroTier | the interface address | transport is encrypted by the tunnel |
| Yggdrasil | the `2xx:` / `3xx:` address | transport is end-to-end encrypted |
| LAN only | the LAN address | plain HTTP on the LAN; add TLS (section 4.3) |

Preferred pattern: bind to loopback and let a proxy or overlay-provided TLS front it, so the
app never listens on an interface it did not choose.

## 3. Already in place

- Dependencies at current patched versions; `pip-audit` runs in CI on every PR and weekly; Dependabot PRs weekly.
- Tag-triggered release (exe, wheel, sdist, `SHA256SUMS.txt`).
- Vault auto-lock after idle timeout (`AUTO_LOCK_TIMEOUT`, default 300 s); vault handle dropped on lock.
- Per-credential password required to read a value, on top of the master password.
- Swagger/ReDoc UI disabled; generic `500` errors without internals.
- Master password not accepted via URL; prompted with `getpass` at startup.
- Smoke tests for lock/unlock flow, crypto and backend round-trip.

## 4. Remaining work, in priority order

### P0: close real weaknesses in the current code

1. **Online brute-force protection on `POST /api/unlock`.** There is no rate limit or lockout, so anyone who reaches the port can guess the master password at network speed. Add per-client exponential backoff and a temporary lockout; log failed attempts (time and client address only, never the guess).
2. **Per-client sessions instead of global unlock.** Today unlocking is global state: once unlocked, any client that reaches the port can list entry names. Issue a random session token at unlock (`HttpOnly`, `Secure`, `SameSite=Strict` cookie or bearer token), require it on every `/api/*` call except health, and expire it with the idle timer.
3. **Stop keeping the master password in process memory.** `server.py` stores `vault.master_password` at startup and `lock()` does not clear it, which defeats auto-lock. Verify it is unused, then remove it.
4. **Credential names in URLs.** `POST /api/credentials/{name}` puts entry names into access logs. Move the name into the request body or disable uvicorn access logging.
5. **`start-api.bat` / `start-api.sh` require `MASTER_PASSWORD` in `.env`.** This contradicts the "never stored on disk" model that `server.py` documents. Remove that requirement from the scripts and `.env.example`.
6. **Quote handling in the web UI.** Entry names pass through `escapeHtml`, which does not escape quotes, and are then placed inside an inline `onclick='...'`. A name containing `'` breaks out of the string. Use `data-` attributes plus event listeners.

### P1: standard hardening

7. **Security headers** on all responses: `Content-Security-Policy` (move inline script/style to a nonce or static files), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`.
8. **`Cache-Control: no-store`** on every `/api/*` response so credential values are never cached by the browser or a proxy.
9. **TLS.** On an encrypted overlay the transport is already protected. For plain LAN or loopback-proxy setups, support uvicorn `--ssl-certfile/--ssl-keyfile` via env vars (`TLS_CERT`, `TLS_KEY`) and document `tailscale serve` as the zero-config option.
10. **Concurrency.** The backend does blocking KeePass work (key derivation) inside `async def` handlers, which stalls the event loop. Declare the handlers `def` (FastAPI runs them in a threadpool) and guard `VaultState` with a lock. Run a **single** uvicorn worker, because state is in-process.
11. **Input limits.** Add `max_length` to `master_password`, `credential_password` and the `name` path parameter, and cap request body size.
12. **Single source for the version.** `FastAPI(version="2.0.0")` disagrees with the package version; read it from `importlib.metadata`.

### P2: operations and quality

13. **Run as a service**: Task Scheduler or NSSM on Windows, a systemd unit on Linux. The unlock prompt currently needs a console, so decide whether unlock stays interactive or moves entirely to the web UI.
14. **Make the API installable without a checkout**: done for imports and the console script; add a smoke test that runs it from an installed wheel in CI.
15. **More tests**: auto-lock timeout, wrong credential password, rate-limit and lockout, session expiry, bind-address validation.
16. **Static checks in CI**: ruff and mypy at a level the codebase passes today, then tighten.
17. **Docs**: rewrite `docs/QUICKSTART.md` and `docs/FINAL_SIMPLE_PLAN.md` to be network-agnostic; fix the clone URL and install section in `README.md`.

## 5. Best practices for this kind of app

General, for any self-hosted secret-serving service:
- **Never expose it to the public internet.** Reachability comes from a private overlay or VPN, not a port-forward.
- **Least privilege in the API.** Read-only unless a write is needed; every added endpoint is more surface.
- **Defence in depth.** Network boundary, then master password, then per-credential password, then idle auto-lock.
- **Secrets in memory only as long as needed.** Clear on lock; do not log or echo them; do not put them in URLs, env files or shell history.
- **Limit and log authentication attempts.** Throttle, back off, and record failures without recording guesses.
- **Responses that carry secrets are never cacheable.**
- **Transport encryption end to end.** Overlay encryption or TLS; no plain HTTP across untrusted segments.
- **Keep it patched automatically.** Dependabot plus `pip-audit` in CI, and a release pipeline so the fix actually ships.
- **Small, boring surface.** One server, one worker, one vault, no extra framework.

Specific to this app:
- The server holds a decrypted vault in a long-lived process; **idle timeout and lock-clears-memory are the main control**, so keep the timeout short and make locking drop every secret.
- The vault file is the crown jewel: keep it outside the repo, back it up encrypted, and restrict file permissions to the service account.
- Phones are the likely client; require the session to expire on tab close/idle and clear the clipboard after copy (already done in the UI timers).
- Any future write endpoint must require the credential password, be rate-limited, and be off by default behind a config flag.
