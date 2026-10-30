# Quick start: API server over a private network

The server exposes your KeePass vault to a browser (phone, laptop) over a private network. It is
read-only: list entry names and retrieve one credential. Reference and roadmap:
`docs/FASTAPI_ROADMAP.md`. How the vault file gets onto the server: `docs/VAULT_SYNC.md`.

## 1. Install

From a release (no checkout): download the wheel from the
[latest release](https://github.com/nydiokar/KeySafe/releases/latest) and install it into a venv:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install .\secure_credentials-<version>-py3-none-any.whl
```

From source: `pip install -e ".[dev]"` in a venv inside the clone.

## 2. Configure

Environment variables or a `.env` file in the working directory (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `BIND_HOST` | `127.0.0.1` | Address of the private-network interface to listen on |
| `API_PORT` | `8080` | Port |
| `VAULT_PATH` | `~/.secure_credentials/vault.kdbx` | Vault file |
| `AUTO_LOCK_TIMEOUT` | `300` | Idle seconds before auto-lock (10-86400) |
| `TLS_CERT`, `TLS_KEY` | unset | Serve HTTPS directly (both required) |
| `COOKIE_SECURE` | `0` | Set `1` when a proxy terminates HTTPS in front of the server |
| `TRUSTED_PROXY` | `0` | Set `1` to trust `X-Forwarded-For` from a loopback proxy |
| `ALLOW_PUBLIC_BIND` | `0` | Required to bind `0.0.0.0` / `::` (not recommended) |

Never put the master password anywhere: you type it in the web UI.

## 3. Run

```powershell
secure-credentials-api
```

or `python -m secure_credentials.src.api.server`. The server refuses to start if the vault file does
not exist; create it with the desktop GUI first. Open the printed URL, enter the master password,
then the per-credential password to reveal a value. After the idle timeout the vault locks again.

Events (unlock, failed attempts, lockouts) go to `~/.secure_credentials/logs/api.log`. No secrets
or credential names are logged.

## 4. Pick your network

The server needs only an address to bind. Use the address of the private interface, or `127.0.0.1`
behind a proxy that provides the private reachability.

**Tailscale**
- Direct: `BIND_HOST=<this machine's tailnet IP>` (`tailscale ip -4`). Reach it at `http://<tailnet-ip>:8080/`. Tailscale encrypts the transport.
- With HTTPS: keep `BIND_HOST=127.0.0.1`, run `tailscale serve` to publish the local port on your tailnet (check `tailscale serve --help` for the syntax of your version), and set `COOKIE_SECURE=1`, `TRUSTED_PROXY=1`.

**WireGuard / ZeroTier**: `BIND_HOST=<the interface address of the tunnel>`. The tunnel encrypts traffic.

**Yggdrasil**: `BIND_HOST=<your Yggdrasil address>` (`yggdrasilctl getSelf`). Traffic is end-to-end encrypted. IPv6 addresses need no brackets in `BIND_HOST`.

**Plain LAN**: `BIND_HOST=<LAN address>` and add TLS (`TLS_CERT`/`TLS_KEY`), because the LAN segment is not encrypted. Do not forward this port from your router.

If the machine has no private-network interface, stay on the default loopback and use the server only locally.

## 5. Troubleshooting

- `Refusing to bind to wildcard address`: set `BIND_HOST` to a specific interface address.
- `vault not found`: set `VAULT_PATH` or create the vault with the GUI.
- Login keeps failing with "Too many attempts": wait for the shown seconds; lockouts grow with repeated failures and reset on success or after an hour.
- Unlock works but the list is empty/stale: the vault file was replaced; lock and unlock again (`docs/VAULT_SYNC.md`).
- Cookie not stored over HTTPS proxy: set `COOKIE_SECURE=1`. Over plain HTTP leave it at `0`.
