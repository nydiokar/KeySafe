# Vaultroom rollout and recovery

## What changes

Vaultroom replaces the web interface at the existing service URL. It reads the same encrypted KeePass file configured by `VAULT_PATH`. Existing entry passwords continue to protect each secret. The rollout uses read-only mode, so it needs no import, database conversion, or credential reset. Read-only mode supports listing, retrieval, and encrypted backup download. Web editing and import require an explicitly server-owned vault.

The source checkpoint is `126e256`. The previous live UI was at `0d2f6f9`. The rollout review added format validation to prevent invalid metadata from making the workspace unreadable, guarded retrieval of an entry without a stored value, and expanded repository ignores for KeePass files. Regression coverage includes reading a legacy-format entry without rewriting the vault and rejecting invalid metadata before saving.

## Run under PM2

Install the application in a virtual environment at `.venv`, then copy `.env.example` to `.env` and set `VAULT_PATH` if your vault is outside the default location. Keep `.env` private and out of Git. Run one PM2 process because the vault session and throttling state live in that process.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
pm2 start ecosystem.config.cjs --only keysafe
pm2 status keysafe
curl -fsS http://127.0.0.1:8080/api/health
```

The checked-in PM2 configuration binds to localhost and sets `WEB_VAULT_WRITES=0`. Access it from the host browser or an authenticated private tunnel. For a TLS reverse proxy, follow the trusted loopback proxy and secure cookie guidance in [Quick start](QUICKSTART.md). To apply a code or environment update, run `pm2 restart ecosystem.config.cjs --only keysafe --update-env` from the checkout. All sessions reset on restart. For automatic restart at boot, configure PM2 startup for the service account and save its intended process list.

## Verify a rollout

1. Make an encrypted copy with owner-only permissions and compare its bytes with the original. Keep both files outside the checkout.
2. Test unlock, selection, and retrieval on a disposable vault with legacy entries. Confirm rejected writes and compare the original test file bytes after reading.
3. Restart the `keysafe` process. Confirm the health response, locked status, and Vaultroom HTML at its existing address. Compare the live file bytes with the encrypted checkpoint.
4. In your own browser, unlock with your existing master password and verify an entry with its existing credential password. Never put either password in the shell or release notes.

For a UI rollback, stop `keysafe`, switch the deployment checkout to the previously deployed revision, and restart the existing process using `pm2 restart keysafe`. Restore the vault only if you independently establish that the file itself needs recovery. Follow [vault restore instructions](VAULT_SYNC.md).

## Follow-up review

An independent defensive security review is planned. The [review handoff](VAULTROOM_SECURITY_REVIEW.md) defines the scope and reporting requirements.
