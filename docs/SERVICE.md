# Running the API server as a service

The server needs no console: the master password is entered in the web UI after every restart,
so a service can start unattended and simply stays locked until you unlock it.

Prerequisites: a venv with the package installed, a `.env` (or system environment) with `BIND_HOST`
and `VAULT_PATH`, and a dedicated low-privilege account that owns the vault folder.

## Windows (Task Scheduler, no extra tools)

Run once in an elevated PowerShell, adjusting paths:

```powershell
$a = New-ScheduledTaskAction -Execute "C:\SecureCredentials\.venv\Scripts\secure-credentials-api.exe" -WorkingDirectory "C:\SecureCredentials"
$t = New-ScheduledTaskTrigger -AtStartup
$s = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SecureCredentialsApi" -Action $a -Trigger $t -Settings $s -User "svc_credentials" -Password "<account password>" -RunLevel Limited
```

Start / stop / remove:

```powershell
Start-ScheduledTask SecureCredentialsApi
Stop-ScheduledTask SecureCredentialsApi
Unregister-ScheduledTask SecureCredentialsApi -Confirm:$false
```

NSSM is an alternative if you prefer a real Windows service.

## Linux (systemd)

`/etc/systemd/system/secure-credentials-api.service`:

```ini
[Unit]
Description=Secure Credentials API
After=network-online.target

[Service]
User=svc-credentials
WorkingDirectory=/opt/secure_credentials
EnvironmentFile=/opt/secure_credentials/.env
ExecStart=/opt/secure_credentials/.venv/bin/secure-credentials-api
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/secure_credentials /var/lib/secure_credentials

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now secure-credentials-api
```

If you bind to a Tailscale or WireGuard address, make the unit start after that interface exists
(for example `After=tailscaled.service`), otherwise the bind fails at boot.

## Notes

- Run exactly one instance: sessions and throttling are held in memory.
- The audit log is `~/.secure_credentials/logs/api.log` of the service account.
- Updating: stop the service, `pip install --upgrade` the new wheel, start it.
