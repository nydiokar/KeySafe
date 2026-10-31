# Changelog

## Unreleased

- GUI theme moved from the legacy `darkly` to `bootstrap-dark` (a saved `darkly` setting is migrated).

## 1.3.1

GUI fixes:
- Opening an existing vault no longer fails with "Invalid master password" and an empty list. The GUI also checked the password against a global `~/.secure_credentials/master.hash` that has nothing to do with the vault; the vault password is now the only check.
- Cancelling the master-password prompt now exits instead of leaving an empty window.
- The lock screen can no longer be dismissed with Escape or the close button, and tray "Show" no longer bypasses the lock. Ctrl+L now locks (it was shown in the menu but not bound).
- Delete, Ctrl+C and Ctrl+E typed in the search box no longer trigger credential actions.
- Clipboard auto-clear never fired (it compared against values that are never loaded); it now clears the copied secret after 30 s, also for copies from the details dialog.
- Saved auto-lock timeout is applied at startup (it was reset to 5 minutes), and closing the window no longer wipes saved settings (theme, timeout, clipboard) from `gui_config.json`.

## 1.3.0

API server (breaking changes for API users):
- Per-client sessions (`HttpOnly`, `SameSite=Strict` cookie) instead of one global unlock; sessions and the vault auto-lock after the idle timeout.
- Exponential backoff with `429` + `Retry-After` on unlock and credential retrieval.
- Master password is no longer stored anywhere and no longer prompted at startup: unlock in the web UI. Remove `MASTER_PASSWORD` from `.env`.
- `POST /api/credentials/{name}` is now `POST /api/credentials/retrieve` with `{name, credential_password}`; access log disabled.
- `BIND_HOST` replaces `YGGDRASIL_IP` (alias kept). Works with any private network. Default is `127.0.0.1`; wildcard binds need `ALLOW_PUBLIC_BIND=1`.
- Optional HTTPS (`TLS_CERT`/`TLS_KEY`), `COOKIE_SECURE`, `TRUSTED_PROXY`.
- Strict CSP and other security headers, `no-store` on all responses, cross-origin write rejection, request size and input limits, OpenAPI endpoints removed.
- Rotating audit log (`~/.secure_credentials/logs/api.log`) with no secrets or credential names.
- Retrieval never writes to the vault file (the backend previously updated "Last Accessed" on every read).
- UI: names rendered safely, revealed values hide after 30 s and on lock.

Backend and GUI:
- Credential names containing a double quote are rejected (they could be stored but never found again).
- Backend logs no longer contain credential names or entry notes.
- `launcher.py` and `run_app.py direct_gui` no longer crash for a missing `SecurityManager`.
- Replaced `pkg_resources` (removed from recent setuptools).

Dependencies and build:
- All dependencies moved to current patched versions (Pillow 13, ttkbootstrap 2, cryptography 50, FastAPI 0.162 / Starlette 1.x, requests, urllib3, ...). Python 3.10+ required.
- CI: pytest, ruff, mypy, `pip-audit`, installed-wheel smoke test. Dependabot weekly. Tag-triggered release builds exe, wheel, sdist and checksums.

## 1.2.0

Previous release line (see git history).
