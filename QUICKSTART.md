# Quick Start Guide - Secure Password Manager API v2.0

## What's New in v2.0 🔒

✅ **Real vault locking** - Vault actually closes after 5 minutes (not just hidden!)
✅ **Master password prompt** - Never stored on disk, only in memory
✅ **Auto-lock timer** - Shows countdown until auto-lock
✅ **Manual lock button** - Lock vault when done
✅ **More secure than GUI!** - Vault truly locks, not just window hiding

---

## Setup (3 Steps)

### 1. Install Dependencies

```bash
pip install fastapi uvicorn[standard]
```

### 2. Create .env File

```bash
# Copy the example
cp .env.example .env

# Edit .env and fill in ONLY your Yggdrasil IP
# (Master password will be prompted, NOT in file!)
```

**Your .env should look like:**
```bash
YGGDRASIL_IP=your-ip-here
API_PORT=8080
AUTO_LOCK_TIMEOUT=300
```

### 3. Start the Server

**Windows:**
```bash
start-api.bat
```

**Linux/Mac:**
```bash
./start-api.sh
```

**You'll see:**
```
============================================================
🚀 Password Manager Starting
============================================================
📍 Binding to: [200:1234:...]:8080
⏱️  Auto-lock timeout: 5 minutes

🔐 Master Password Setup
============================================================

The master password will be used to unlock your vault.
It will NOT be stored anywhere - only kept in memory.

You'll need to enter it again:
  - When starting the server
  - After vault auto-locks (5 min inactivity)
  - After manually locking the vault

Enter master password: ▌
```

**Type your master password** (characters won't show - that's normal!)

**Then:**
```
🔓 Verifying master password...
✅ Vault unlocked at 14:23:15
🔒 Vault locked at 14:23:15
✅ Password verified successfully
🔒 Vault is now locked - unlock it via web UI

🌐 Access from phone:
   http://[200:1234:...]:8080/

============================================================
```

---

## Using the Web UI

### From Your Phone:

1. **Connect to Yggdrasil**
   - Open Yggdrasil app
   - Verify connected

2. **Open Browser**
   - Navigate to: `http://[your-ygg-ip]:8080/`

3. **You'll See:**
   ```
   ┌─────────────────────────┐
   │ 🔐 Password Manager     │
   ├─────────────────────────┤
   │ 🔒 Locked | ⏱️          │
   ├─────────────────────────┤
   │         🔒              │
   │  Vault is Locked        │
   │                         │
   │  Enter your master      │
   │  password to unlock     │
   │                         │
   │  [••••••••••••]        │
   │  [Unlock Vault]         │
   └─────────────────────────┘
   ```

4. **Enter Master Password**
   - Type your master password
   - Click "Unlock Vault"

5. **Now You See:**
   ```
   ┌─────────────────────────┐
   │ 🔐 Password Manager     │
   ├─────────────────────────┤
   │ 🔓 Unlocked | 4:58 ⏱️   │
   ├─────────────────────────┤
   │ [Search...]             │
   │ [🔒 Lock Vault]         │
   ├─────────────────────────┤
   │ github                  │
   │ PASSWORD               │
   ├─────────────────────────┤
   │ gmail                   │
   │ PASSWORD               │
   └─────────────────────────┘
   ```

6. **To Get a Password:**
   - Click credential (e.g., "github")
   - Enter credential password
   - Click "Unlock"
   - Password appears
   - Click "Copy to Clipboard"
   - Auto-clears after 30 seconds

7. **Security Features:**
   - ⏱️ **Auto-lock timer** shows time remaining
   - 🔒 **Lock button** to manually lock when done
   - After 5 min inactivity → vault locks automatically
   - Next access requires master password again

---

## How It Works (Security Model)

### Two-Tier Protection:

```
1️⃣ Master Password (unlocks vault)
    ↓
   Vault unlocked in server memory
    ↓
2️⃣ Credential Password (unlocks each entry)
    ↓
   Get specific password
```

### Auto-Lock Mechanism:

```
Vault Unlocked
  ↓
5 minutes of inactivity
  ↓
Vault ACTUALLY CLOSES (cleared from memory!)
  ↓
Next request → 423 "Vault Locked"
  ↓
Web UI shows lock screen
  ↓
User must re-enter master password
```

### Better Than GUI:

| Feature | GUI | API v2.0 |
|---------|-----|----------|
| **Auto-lock** | Hides window | ✅ **Closes vault!** |
| **Network access** | No | Yes (Yggdrasil only) |
| **Master password** | Dialog prompt | ✅ Terminal prompt |
| **Password on disk** | No | ✅ No (more secure!) |
| **Per-credential** | ✅ Yes | ✅ Yes |

---

## Troubleshooting

### "ERROR: Set YGGDRASIL_IP environment variable"
- Create `.env` file from `.env.example`
- Fill in your Yggdrasil IP

### "ERROR: Invalid master password"
- Double-check your master password
- Make sure vault exists (create with GUI first if needed)

### Can't access from phone
- Verify Yggdrasil connected on phone
- Try `ping6 [yggdrasil-ip]` from phone
- Check server is running

### Vault keeps locking
- That's normal! It's secure
- Adjust timeout in `.env`: `AUTO_LOCK_TIMEOUT=600` (10 minutes)
- Or just unlock when needed

### Password field empty when typing
- Normal! It's hidden for security
- Just type and press Enter

---

## API Endpoints (for developers)

```
GET    /api/health           # Health check
GET    /api/status           # Vault lock status
POST   /api/unlock           # Unlock vault
POST   /api/lock             # Lock vault
GET    /api/credentials      # List credentials (requires unlocked vault)
POST   /api/credentials/{id} # Get credential (requires credential password)
```

**Example: Unlock vault from terminal**
```bash
curl -X POST http://[ygg-ip]:8080/api/unlock \
  -H "Content-Type: application/json" \
  -d '{"master_password": "your-master-password"}'
```

**Example: Get credential**
```bash
curl -X POST http://[ygg-ip]:8080/api/credentials/github \
  -H "Content-Type: application/json" \
  -d '{"credential_password": "cred-password"}'
```

---

## Optional: Run as Service

### Linux (systemd)

Create `/etc/systemd/system/passmanager.service`:
```ini
[Unit]
Description=Password Manager API
After=yggdrasil.service
Requires=yggdrasil.service

[Service]
Type=simple
User=yourusername
WorkingDirectory=/path/to/pass_manager
EnvironmentFile=/path/to/pass_manager/.env
ExecStart=/path/to/pass_manager/.venv/bin/python /path/to/pass_manager/secure_credentials/src/api/server.py
Restart=on-failure

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Note:** For systemd, you'll need to handle master password differently:
- Use systemd credential storage
- Or use a key file (less secure)
- Or start manually when needed

---

## Security Summary

### What Protects Your Passwords:

1. ✅ **Yggdrasil network** - Only accessible from your private mesh
2. ✅ **Master password** - Required to unlock vault (never stored!)
3. ✅ **Auto-lock** - Vault closes after 5 min inactivity
4. ✅ **Credential passwords** - Each entry has its own password
5. ✅ **KeePass encryption** - Vault encrypted at rest (AES-256)
6. ✅ **Clipboard auto-clear** - Passwords cleared after 30 sec

### Attack Scenarios:

**"Someone gets my Yggdrasil IP"**
- ✅ They still need master password
- ✅ AND credential passwords for each entry
- ✅ Vault locks after 5 min anyway

**"Someone hacks my workstation"**
- ⚠️ If vault is unlocked: passwords accessible
- ✅ If vault is locked: need master password
- ✅ Master password not on disk anywhere

**"I forget to lock vault"**
- ✅ Auto-locks after 5 minutes
- ✅ Next phone access requires master password

---

## Files Created

```
pass_manager/
├── .env.example          ✅ Config template (updated)
├── .env                  📝 Your config (YGGDRASIL_IP only!)
├── start-api.bat         ✅ Windows startup
├── start-api.sh          ✅ Linux/Mac startup
├── QUICKSTART.md         ✅ This file (updated)
└── secure_credentials/
    └── src/
        └── api/
            └── server.py ✅ v2.0 with vault locking!
```

---

## Comparison: v1.0 vs v2.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| **Vault locking** | ❌ Never | ✅ Auto after 5 min |
| **Master password** | .env file | ✅ Prompted (secure!) |
| **Lock UI** | No | ✅ Shows timer |
| **Manual lock** | No | ✅ Lock button |
| **Network safe** | ⚠️ Risky | ✅ Safe |
| **Status bar** | No | ✅ Shows lock status |

---

## That's It! 🎉

**You now have:**
- 🔒 Secure vault with real locking
- 📱 Mobile web UI
- ⏱️ Auto-lock after inactivity
- 🔐 Master password never stored
- 🚀 Same credential password model as GUI

**Enjoy your secure password manager!**
