# Vault location, sync and backup

The API server reads one `.kdbx` file from its own disk (`VAULT_PATH`, default
`~/.secure_credentials/vault.kdbx`). The server **never writes** to it: retrieving a credential
leaves the file byte-for-byte unchanged (covered by a test). Every unlock opens the file fresh,
so a replaced file is picked up on the next unlock.

## Recommended model: one-way sync, PC -> server

You edit the vault with the desktop GUI on your PC. A sync tool copies the file to the server.
The server only reads it.

1. Install Syncthing on both machines (or any file sync you trust; the vault is already encrypted).
2. On the PC share the folder that holds the vault as **Send Only**.
3. On the server accept it as **Receive Only** into a folder outside the repo, for example `C:\SecureCredentials\vault\`.
4. Point the server at it: `VAULT_PATH=C:\SecureCredentials\vault\vault.kdbx`.
5. After editing credentials on the PC, wait for the sync to finish, then lock and unlock in the web UI to load the new copy.

Why one-way: with two writers, a sync conflict can silently drop a credential. Receive Only on the
server means a change made there can never overwrite the PC's copy.

Alternatives:
- **Vault lives only on the server.** Run the GUI on the server host and nowhere else. Simplest, no sync, but you lose the local copy on your PC.
- **Manual copy.** `Copy-Item` the file to the server after each change. Fine if you change credentials rarely.

Do not put the vault in the git repository (`*.kdbx` is git-ignored), in a public cloud folder, or in a
folder served by any web server.

## Backup

The vault is the only copy of your credentials and cannot be regenerated.

- Keep at least **three copies**, one on a different device or offline medium.
- Copy the file, do not export it: it is already encrypted with your master password.
  PowerShell: `Copy-Item $env:USERPROFILE\.secure_credentials\vault.kdbx "D:\backup\vault-$(Get-Date -Format yyyyMMdd).kdbx"`
- **Test a restore** at least once per quarter: open the backup copy with
  `python -m secure_credentials.run_app --vault=D:\backup\vault-YYYYMMDD.kdbx` and open one credential.
- The master password and per-credential passwords are not recoverable. Store the master password in a
  place that survives losing your devices (for example on paper in a safe).

## Permissions

Restrict the vault folder to the account that runs the server (Windows: remove inherited access and
grant only that user; Linux: `chmod 600` the file and `chmod 700` the folder).
