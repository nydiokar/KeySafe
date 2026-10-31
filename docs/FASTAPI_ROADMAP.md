# FastAPI server: roadmap and burndown

Decision record and history: `docs/PROJECT_HISTORY.md`.
Code: `secure_credentials/src/api/` (`server.py`, `config.py`, `auth.py`, `vault.py`, `static/`).
Entry point: `secure-credentials-api` or `python -m secure_credentials.src.api.server`.

Goal: reach the KeePass vault from other devices over a **private network** (Tailscale,
WireGuard, ZeroTier, Yggdrasil, LAN, or loopback behind a proxy), read/retrieve only,
simple and secure. Never exposed to the public internet.

---

## 1. Agent protocol (read this first, then work without asking)

1. Read this file, then `docs/PROJECT_HISTORY.md` section 5 (decision) if context is needed.
2. Pick the **first item in the Burndown with status `TODO`** whose dependencies are `DONE`. Items marked `BLOCKED` or `NEEDS-USER` are skipped. Do not ask which item to take.
3. Implement it to its **Acceptance** criteria, with the tests it lists. Keep the change minimal; no unrelated refactors.
4. Verify (PowerShell, from the repo root):
   - `.\.venv\Scripts\python.exe -m pytest -q tests` must pass.
   - `.\.venv\Scripts\python.exe -m pip_audit --skip-editable` must report no vulnerabilities (if `pip_audit` is missing: `.\.venv\Scripts\python.exe -m pip install pip-audit`).
5. Update this file in the same commit: set the item to `DONE`, add one line to the **Done log** (date, item ID, commit subject). Add newly discovered work as new `TODO` items at the right priority.
6. Commit locally with a message `<ID>: <summary>`. Local commits do not need approval.
7. Repeat from step 2 until no `TODO` remains or an item needs the user.
8. **Never without the user's explicit say-so:** `git push`, creating or pushing tags, deleting remote branches, force-anything, changing repo settings.
9. When stopping, report in 5 lines or fewer: items completed, items remaining, anything blocked and what exactly the user must do.

Environment facts: Windows, PowerShell for anything handed to the user, venv at `.venv\`, Python 3.12, `pyproject.toml` is the only dependency source (no ad-hoc installs; add to `pyproject.toml` then `pip install -e ".[dev]"`). Code style: strict type annotations, pydantic models for data, functions over classes where practical, no `@staticmethod`, minimal logging.

### Decisions already made (do not reopen)

- FastAPI is the only network server. The Flask app is not coming back (see history doc).
- The server is **read-only** (list names, retrieve one credential). Remote write endpoints are out of scope unless the user asks; if ever added they must be off by default behind a config flag.
- One process, one uvicorn worker (state is in-process).
- Master password is entered only in the web UI and is never stored (not in env, `.env`, scripts, or memory beyond opening the database).
- Network-agnostic: configuration is `BIND_HOST`; no network name is hard-coded in code. `YGGDRASIL_IP` is a deprecated alias.
- Default bind is loopback; wildcard binds require `ALLOW_PUBLIC_BIND=1`.
- Frontend stays dependency-free static files (`static/index.html`, `app.js`, `style.css`) under a strict CSP: no inline script/style, no inline handlers.

---

## 2. Current state (2026-10-31, release 1.3.0)

Implemented and tested (35 tests, ruff and mypy clean):

- Dependencies at current patched versions; CI runs pytest + `pip-audit`; Dependabot weekly; tag-triggered releases.
- Per-client sessions: random token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` when TLS/`COOKIE_SECURE`). All `/api/*` except health and status require it. Status polling does not extend the session.
- Idle auto-lock per session; vault handle dropped when the last session expires (background reaper every 2 s, plus a check on every request). `POST /api/lock` revokes all sessions.
- Throttling with exponential backoff: unlock (per client and global) and credential retrieval (per client); `429` with `Retry-After`; bounded memory.
- Master password is never stored. Interactive startup prompt removed; unlock is through the web UI.
- Credential name moved out of the URL: `POST /api/credentials/retrieve` with `{name, credential_password}`; access log disabled.
- Strict CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on every response; OpenAPI/docs endpoints removed.
- UI renders entry names with DOM APIs only (fixes the quote-injection bug).
- `BIND_HOST` (any private-network address), loopback default, wildcard refusal, optional `TLS_CERT`/`TLS_KEY`, input length limits, version read from package metadata.
- Handlers run in the threadpool; vault access serialised by a lock; session and throttle stores are thread-safe.
- Retrieval is truly read-only (`persist=False`); the vault file is unchanged after a read (test). Backend logs no longer contain entry names or notes.
- Cross-origin `POST`s rejected, bodies over 16 KB rejected, rotating audit log, `TRUSTED_PROXY` for proxies.
- CI: pytest, ruff, mypy (strict on `api/`), `pip-audit`, installed-wheel smoke test (real process, health, CSP, static assets).

Config reference (env vars or `.env`): `BIND_HOST`, `ALLOW_PUBLIC_BIND`, `API_PORT` (8080), `AUTO_LOCK_TIMEOUT` (300, range 10-86400), `VAULT_PATH`, `TLS_CERT`, `TLS_KEY`, `COOKIE_SECURE`.

Breaking changes vs v1.2.0: endpoint `/api/credentials/{name}` -> `/api/credentials/retrieve`; `YGGDRASIL_IP` -> `BIND_HOST`; default bind is loopback; no startup password prompt; `.env` `MASTER_PASSWORD` is no longer used (remove it from your `.env`).

---

## 3. Burndown

Status values: `TODO`, `DONE`, `WONTDO`, `BLOCKED`, `NEEDS-USER`. Priority: P0 must-have, P1 should-have, P2 nice-to-have.

### P0

| ID | Status | Item |
|---|---|---|
| A1 | DONE | Online brute-force protection on unlock and retrieve (backoff + 429) |
| A2 | DONE | Per-client sessions instead of global unlock |
| A3 | DONE | Stop keeping the master password in memory; remove startup prompt |
| A4 | DONE | Credential names out of URLs; access log off |
| A5 | DONE | Remove `MASTER_PASSWORD` requirement from start scripts |
| A6 | DONE | Quote-safe UI rendering |
| A7 | DONE | Generic `BIND_HOST`, loopback default, wildcard refusal |
| A8 | NEEDS-USER | Replace `.env.example` with the new template (agents are denied access to `.env*` files). The template is in section 4. Also remove `MASTER_PASSWORD` / `YGGDRASIL_IP` lines from your real `.env`. |
| A9 | DONE | **Vault location and sync design.** The server reads a `.kdbx` on its own disk; edits made in the desktop GUI on another machine do not reach it. Write `docs/VAULT_SYNC.md` choosing one model and documenting setup: (a) vault lives only on the server host (GUI used there), (b) one-way sync PC -> server (e.g. Syncthing or scheduled copy; server picks up changes on next unlock), (c) other. Include a **backup** procedure (encrypted copy, restore test). Acceptance: doc exists, linked from README; if (b) is chosen, the server reopens the file on each unlock (already true: `VaultGuard.open` builds a fresh handler) and a test proves a replaced vault file is seen after re-unlock. Default recommendation if no preference is known: (b). |

### P1

| ID | Status | Item |
|---|---|---|
| B1 | DONE | Security headers, CSP, no-store |
| B2 | DONE | Optional TLS via `TLS_CERT`/`TLS_KEY` |
| B3 | DONE | Threadpool handlers + vault lock; single worker |
| B4 | DONE | Input length limits |
| B5 | DONE | Version from package metadata |
| B6 | DONE | **Network docs.** Rewrite `docs/QUICKSTART.md` to be network-agnostic with one short, tested-by-reading section each for Tailscale (bind to tailnet IP, or loopback + `tailscale serve` with `COOKIE_SECURE=1`), WireGuard/ZeroTier, Yggdrasil, LAN. Mark `docs/FINAL_SIMPLE_PLAN.md` as historical (top banner) or delete it if everything in it is covered. Fix `README.md` clone URL (`https://github.com/nydiokar/KeySafe.git`), Python version, and add an "API" section pointing here. Acceptance: no doc tells the user to put the master password in `.env`; grep for `MASTER_PASSWORD` and `YGGDRASIL_IP` in docs finds only deprecation notes. |
| B7 | DONE | **Reverse-proxy / client address handling.** Behind `tailscale serve` or any proxy every request arrives from `127.0.0.1`, so per-client throttling collapses into one bucket (still safe, but one attacker locks out the owner). Add optional `TRUSTED_PROXY=1` that makes uvicorn honour `X-Forwarded-For` only from loopback (`proxy_headers=True, forwarded_allow_ips="127.0.0.1"`). Acceptance: setting documented in B6, test for `load_settings`. |
| B8 | DONE | **CSRF defence in depth.** Cookie is already `SameSite=Strict` and endpoints need JSON. Add a check that rejects state-changing requests (`POST`) whose `Origin` header is present and does not match the request host. Acceptance: tests for matching, mismatching and absent `Origin`. |
| B9 | DONE | **Audit log.** Configure the `secure_credentials.api` logger to a rotating file (`~/.secure_credentials/logs/api.log`, 1 MB x 3): failed unlocks (time + client address), throttle lockouts, lock/unlock events. Never log secrets, credential names, or request bodies. Acceptance: test that a failed unlock writes a line and that no password text appears in the log. |
| B10 | DONE | **Backend: names containing quotes cannot be stored.** `KeePassHandler.add_credential` returns `False` for a name like `it's "x"` (pykeepass entry lookup builds an XPath from the title). Reproduce, find the cause in `pykeepass` source (`pip show pykeepass`), and either sanitise/escape in the backend or reject such names with a clear error in the GUI. Acceptance: test covering the chosen behaviour. |

### P2

| ID | Status | Item |
|---|---|---|
| C1 | DONE | **Run as a service.** Provide `docs/SERVICE.md` with Windows (NSSM or Task Scheduler at logon) and Linux (systemd unit) recipes. Acceptance: units/commands included, mention that unlock is via the web UI after every restart. |
| C2 | DONE | **Installed-wheel smoke test in CI.** New job: build wheel, install into a clean venv, run `python -m secure_credentials.src.api.server` against a temp vault with `API_PORT` set, poll `/api/health`, then stop it (no orphaned process). |
| C3 | DONE | **Static checks in CI.** Add `ruff` and `mypy` (dev extras in `pyproject.toml`), configured at a level the current code passes, scoped to `secure_credentials/src/api` and `tests` first. |
| C4 | WONTDO | Optional TOTP second factor. Dropped for 1.3.0: the private network, master password, per-credential password, throttling and idle lock are already four layers, and a second factor adds lockout risk and secret handling (TOTP seed) for one user. Reopen only if the server is ever exposed beyond a private overlay. |
| C5 | DONE | Phone UI: `autocomplete` attributes on secret inputs, revealed values auto-hide after 30 s and on lock, lock clears list and modal. PWA/offline intentionally not done. |
| C6 | TODO | **Triage Dependabot PRs** left from the old `main` workflow (#3 codecov, #4 checkout-6): close if superseded, merge if CI is green. Needs the user's GitHub permissions if done via `gh`. |
| C7 | DONE | Release v1.3.0 (version bumped, CHANGELOG.md added, release notes taken from the changelog). |
| C8 | TODO | **Remove `httpx` test deprecation warning** when FastAPI/Starlette's `TestClient` supports the new client package; check on each Dependabot bump. |

| C9 | TODO | **ttkbootstrap legacy theme.** The GUI uses theme `darkly`, which ttkbootstrap 2 reports as a legacy name planned for removal in 3.0. Pick an equivalent 2.0 theme from `Style.theme_names()` in `secure_credentials/src/ui/gui.py` and `run_app.py`, check the GUI visually, run tests. |
| C10 | TODO | **Repo clutter.** `run_pass_manager.bat` option 5 references a missing notebook; `create_notebook.py`, `installer.nsi` (git-ignored, v1.0.0) and `build.bat` pauses are stale. Remove or fix what is unused (confirm `create_blank_db.py` is still needed first). |
| C11 | TODO | **Triage global-lockout trade-off.** 12 failed unlocks from anywhere lock *everyone*, including the owner, for up to 5 minutes (denial of service by design: it caps guessing). If that proves annoying on a private network, make the global limit configurable (`GLOBAL_LOCKOUT=0` to disable) and keep the per-client limit. |

### Done log

- 2026-10-30  A1-A7, B1-B5: server rewrite (config, sessions, throttling, CSP, static UI), 26 tests.
- 2026-10-31  A9, B6-B10, C1-C3, C5, C7: vault sync/backup/service/quickstart docs, `TRUSTED_PROXY`, cross-origin check, body cap, audit log, thread-safe stores, read-only retrieval (backend previously wrote the vault on every read), log scrub, quote-name rejection, launcher/direct_gui crash fix, ruff + mypy + wheel-smoke CI, v1.3.0.
- 2026-10-31  C4 dropped (see table).
- 2026-10-31  v1.3.1: GUI fixes found in user testing (global `master.hash` check wrongly rejecting a valid vault password, lock bypass via Escape/tray, dead clipboard auto-clear, settings wiped on close, shortcuts firing in the search box, cancelled prompt leaving an empty window).

---

## 4. `.env.example` template (for A8)

```
# API server configuration (environment variables or a .env file in the working directory).
# Never put MASTER_PASSWORD here: unlock happens in the web UI and is never stored.

# Address of the private-network interface to listen on (Tailscale 100.x / fd7a:..., WireGuard,
# ZeroTier, Yggdrasil, LAN IP). Default: 127.0.0.1 (this machine only).
# BIND_HOST=100.101.102.103
# Wildcard binds (0.0.0.0, ::) are refused unless ALLOW_PUBLIC_BIND=1.
# ALLOW_PUBLIC_BIND=0

# API_PORT=8080
# Idle seconds before sessions expire and the vault locks (10-86400).
# AUTO_LOCK_TIMEOUT=300
# Vault file (default: ~/.secure_credentials/vault.kdbx).
# VAULT_PATH=C:\path\to\vault.kdbx

# HTTPS directly from the server (sets Secure cookies), or COOKIE_SECURE=1 when a proxy
# such as `tailscale serve` terminates TLS.
# TLS_CERT=
# TLS_KEY=
# COOKIE_SECURE=0
```

---

## 5. Best practices this server follows (keep them true)

- Never reachable from the public internet; reachability comes from a private overlay or VPN.
- Least privilege: read-only API; every new endpoint needs a stated reason.
- Defence in depth: network boundary, master password, per-credential password, idle auto-lock, throttling.
- Secrets live in memory only while needed; never in URLs, logs, env files or error messages.
- Every response that can carry a secret is `no-store`.
- Transport protection end to end: encrypted overlay or TLS; no plain HTTP across untrusted segments.
- Automatic patching: Dependabot + `pip-audit` in CI + a release pipeline so fixes ship.
- Small surface: one server, one worker, one vault, static dependency-free UI under a strict CSP.
- The vault file is the crown jewel: keep it outside the repo, back it up (A9), restrict file permissions to the service account.
