# Simple Password Manager API with Web UI

## What Changed from Original Plan?

**ORIGINAL PLAN:** Complex, full-featured API with CRUD, JWT, logging, etc. (weeks of work)

**THIS PLAN:** Simple read-only API + basic web UI (can implement in a day)

---

## Goals (Simple & Focused)

1. ✅ Thin API layer over existing KeePassHandler
2. ✅ Read-only access to credentials
3. ✅ Simple web UI for phone browser
4. ✅ Bind to Yggdrasil IPv6 only
5. ✅ Use existing vault (no changes)
6. ❌ No complex authentication (master password at startup)
7. ❌ No write operations (safe, can't break anything)
8. ❌ No logging, rate limiting, etc. (KISS principle)

---

## Architecture

```
[Phone Browser]
    ↓ Opens http://[ygg-ip]:8080/
[Simple Web UI] (static HTML/JS)
    ↓ Calls API
[Thin FastAPI Layer] (~200 lines)
    ↓ Delegates to
[Existing KeePassHandler] (no changes)
    ↓ Reads
[vault.kdbx] (no changes)
```

---

## Implementation (2 Files Only!)

### File 1: `secure_credentials/src/api/server.py`

```python
#!/usr/bin/env python3
"""
Simple read-only password manager API with web UI.
Thin layer over existing KeePassHandler.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import os
from pathlib import Path
import sys

# Import existing KeePass handler
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.keepass_backend import KeePassHandler

# ==================== CONFIGURATION ====================

YGGDRASIL_HOST = os.getenv("YGGDRASIL_IP", "")
PORT = int(os.getenv("API_PORT", "8080"))
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "")

if not YGGDRASIL_HOST:
    print("❌ ERROR: Set YGGDRASIL_IP environment variable")
    print("   Get it with: yggdrasilctl getSelf")
    sys.exit(1)

if not MASTER_PASSWORD:
    print("❌ ERROR: Set MASTER_PASSWORD environment variable")
    sys.exit(1)

# ==================== FASTAPI APP ====================

app = FastAPI(
    title="Password Manager",
    version="1.0.0",
    docs_url=None,  # Disable Swagger UI (not needed)
    redoc_url=None  # Disable ReDoc (not needed)
)

# ==================== VAULT INITIALIZATION ====================

keepass = KeePassHandler()

print("🔓 Unlocking vault...")
if not keepass.open_database(MASTER_PASSWORD):
    print("❌ ERROR: Failed to unlock vault with provided master password")
    sys.exit(1)

print("✅ Vault unlocked successfully")

# ==================== MODELS ====================

class CredentialMetadata(BaseModel):
    """Entry metadata without password"""
    name: str
    type: str
    created_at: Optional[str]
    last_accessed: Optional[str]


class Credential(BaseModel):
    """Full credential with password"""
    name: str
    value: str
    type: str


class RetrieveRequest(BaseModel):
    """Request to retrieve credential"""
    credential_password: str


# ==================== STATIC WEB UI ====================

# Serve web UI at root
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve web UI"""
    return WEB_UI_HTML


# ==================== API ENDPOINTS ====================

@app.get("/api/health")
async def health():
    """Health check"""
    return {
        "status": "ok",
        "vault": str(keepass.db_path),
        "unlocked": keepass.kp is not None
    }


@app.get("/api/credentials", response_model=List[CredentialMetadata])
async def list_credentials():
    """List all credentials (metadata only, no passwords)"""
    try:
        creds = keepass.get_all_credentials()

        result = []
        for name, data in creds.items():
            result.append(CredentialMetadata(
                name=name,
                type=data.get("type", "other"),
                created_at=data.get("created_at"),
                last_accessed=data.get("last_accessed")
            ))

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/credentials/{name}", response_model=Credential)
async def get_credential(name: str, request: RetrieveRequest):
    """
    Retrieve credential by name.
    Requires credential password.
    """
    try:
        cred = keepass.get_credential(name, request.credential_password)

        if not cred:
            raise HTTPException(
                status_code=403,
                detail="Credential not found or incorrect password"
            )

        return Credential(
            name=cred["name"],
            value=cred["value"],
            type=cred["type"]
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== WEB UI (INLINE HTML) ====================

WEB_UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
            max-width: 600px;
            margin: 0 auto;
        }

        h1 {
            margin-bottom: 20px;
            color: #4CAF50;
            font-size: 24px;
        }

        .search-box {
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 8px;
            color: #e0e0e0;
            font-size: 16px;
        }

        .credential-list {
            list-style: none;
        }

        .credential-item {
            background: #2a2a2a;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.2s;
            border: 1px solid #444;
        }

        .credential-item:hover {
            background: #333;
        }

        .credential-item:active {
            background: #3a3a3a;
        }

        .credential-name {
            font-weight: 600;
            font-size: 18px;
            margin-bottom: 5px;
            color: #4CAF50;
        }

        .credential-type {
            font-size: 12px;
            color: #999;
            text-transform: uppercase;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
        }

        .modal.show {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: #2a2a2a;
            padding: 30px;
            border-radius: 12px;
            max-width: 400px;
            width: 90%;
            border: 1px solid #444;
        }

        .modal h2 {
            margin-bottom: 20px;
            color: #4CAF50;
        }

        .form-group {
            margin-bottom: 15px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            color: #999;
            font-size: 14px;
        }

        input[type="password"],
        input[type="text"] {
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            border: 1px solid #444;
            border-radius: 8px;
            color: #e0e0e0;
            font-size: 16px;
        }

        .password-display {
            background: #1a1a1a;
            padding: 12px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            margin-bottom: 15px;
            border: 1px solid #444;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.2s;
            min-width: 44px;
            min-height: 44px;
        }

        .btn-primary {
            background: #4CAF50;
            color: white;
            margin-right: 10px;
        }

        .btn-primary:active {
            background: #45a049;
        }

        .btn-secondary {
            background: #666;
            color: white;
        }

        .btn-secondary:active {
            background: #555;
        }

        .btn-copy {
            background: #2196F3;
            color: white;
            width: 100%;
            margin-bottom: 10px;
        }

        .btn-copy:active {
            background: #1976D2;
        }

        .error {
            color: #f44336;
            margin-top: 10px;
            font-size: 14px;
        }

        .success {
            color: #4CAF50;
            margin-top: 10px;
            font-size: 14px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #999;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #999;
        }
    </style>
</head>
<body>
    <h1>🔐 Password Manager</h1>

    <input type="text"
           id="searchBox"
           class="search-box"
           placeholder="Search credentials...">

    <ul id="credentialList" class="credential-list">
        <li class="loading">Loading credentials...</li>
    </ul>

    <!-- Modal for password entry -->
    <div id="modal" class="modal">
        <div class="modal-content">
            <h2 id="modalTitle"></h2>

            <div id="passwordPrompt">
                <div class="form-group">
                    <label for="credPassword">Credential Password:</label>
                    <input type="password"
                           id="credPassword"
                           placeholder="Enter password to unlock">
                </div>
                <button class="btn btn-primary" onclick="retrievePassword()">
                    Unlock
                </button>
                <button class="btn btn-secondary" onclick="closeModal()">
                    Cancel
                </button>
                <div id="error" class="error"></div>
            </div>

            <div id="passwordDisplay" style="display: none;">
                <div class="password-display" id="passwordValue"></div>
                <button class="btn btn-copy" onclick="copyPassword()">
                    📋 Copy to Clipboard
                </button>
                <button class="btn btn-secondary" onclick="closeModal()" style="width: 100%;">
                    Close
                </button>
                <div id="copySuccess" class="success"></div>
            </div>
        </div>
    </div>

    <script>
        let credentials = [];
        let currentCredential = null;
        let currentPassword = null;

        // Load credentials on page load
        async function loadCredentials() {
            try {
                const response = await fetch('/api/credentials');
                credentials = await response.json();
                renderCredentials(credentials);
            } catch (error) {
                document.getElementById('credentialList').innerHTML =
                    '<li class="error">Failed to load credentials</li>';
            }
        }

        // Render credential list
        function renderCredentials(creds) {
            const list = document.getElementById('credentialList');

            if (creds.length === 0) {
                list.innerHTML = '<li class="empty-state">No credentials found</li>';
                return;
            }

            list.innerHTML = creds.map(cred => `
                <li class="credential-item" onclick="openModal('${cred.name}', '${cred.type}')">
                    <div class="credential-name">${cred.name}</div>
                    <div class="credential-type">${cred.type}</div>
                </li>
            `).join('');
        }

        // Search filter
        document.getElementById('searchBox').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = credentials.filter(cred =>
                cred.name.toLowerCase().includes(query)
            );
            renderCredentials(filtered);
        });

        // Open modal
        function openModal(name, type) {
            currentCredential = name;
            currentPassword = null;

            document.getElementById('modalTitle').textContent = name;
            document.getElementById('credPassword').value = '';
            document.getElementById('error').textContent = '';
            document.getElementById('copySuccess').textContent = '';
            document.getElementById('passwordPrompt').style.display = 'block';
            document.getElementById('passwordDisplay').style.display = 'none';
            document.getElementById('modal').classList.add('show');

            // Focus password input
            setTimeout(() => {
                document.getElementById('credPassword').focus();
            }, 100);
        }

        // Close modal
        function closeModal() {
            document.getElementById('modal').classList.remove('show');
            currentPassword = null;
        }

        // Retrieve password
        async function retrievePassword() {
            const credPassword = document.getElementById('credPassword').value;
            const errorEl = document.getElementById('error');

            if (!credPassword) {
                errorEl.textContent = 'Please enter credential password';
                return;
            }

            try {
                const response = await fetch(`/api/credentials/${currentCredential}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        credential_password: credPassword
                    })
                });

                if (!response.ok) {
                    errorEl.textContent = 'Incorrect password';
                    return;
                }

                const data = await response.json();
                currentPassword = data.value;

                // Show password
                document.getElementById('passwordValue').textContent = currentPassword;
                document.getElementById('passwordPrompt').style.display = 'none';
                document.getElementById('passwordDisplay').style.display = 'block';

            } catch (error) {
                errorEl.textContent = 'Failed to retrieve password';
            }
        }

        // Copy to clipboard
        async function copyPassword() {
            try {
                await navigator.clipboard.writeText(currentPassword);
                document.getElementById('copySuccess').textContent = '✓ Copied to clipboard!';

                // Auto-clear after 30 seconds
                setTimeout(() => {
                    navigator.clipboard.writeText('');
                }, 30000);

                // Clear success message after 2 seconds
                setTimeout(() => {
                    document.getElementById('copySuccess').textContent = '';
                }, 2000);
            } catch (error) {
                alert('Failed to copy to clipboard');
            }
        }

        // Allow Enter key to submit
        document.getElementById('credPassword').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                retrievePassword();
            }
        });

        // Close modal on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeModal();
            }
        });

        // Load credentials on page load
        loadCredentials();
    </script>
</body>
</html>
"""


# ==================== STARTUP ====================

if __name__ == "__main__":
    import uvicorn

    print(f"\n{'='*60}")
    print(f"🚀 Password Manager Starting")
    print(f"{'='*60}")
    print(f"📍 Binding to: [{YGGDRASIL_HOST}]:{PORT}")
    print(f"🔐 Vault: {keepass.db_path}")
    print(f"📊 Credentials: {len(keepass.get_all_credentials())}")
    print(f"\n🌐 Access from phone:")
    print(f"   http://[{YGGDRASIL_HOST}]:{PORT}/")
    print(f"\n{'='*60}\n")

    uvicorn.run(
        app,
        host=YGGDRASIL_HOST,
        port=PORT,
        log_level="info"
    )
```

**That's it! One file, ~350 lines total (including the HTML/CSS/JS).**

---

### File 2: `.env`

```bash
# Get with: yggdrasilctl getSelf
YGGDRASIL_IP=200:1234:5678:90ab:cdef:1234:5678:90ab

# Your vault's master password
MASTER_PASSWORD=your-master-password-here

# Port (default: 8080)
API_PORT=8080
```

---

## How to Use

### 1. Install FastAPI

```bash
pip install fastapi uvicorn[standard]
```

### 2. Set up environment

```bash
# Get your Yggdrasil IP
yggdrasilctl getSelf

# Create .env file
cat > .env << 'EOF'
YGGDRASIL_IP=<your-yggdrasil-ipv6-here>
MASTER_PASSWORD=<your-master-password-here>
API_PORT=8080
EOF
```

### 3. Run the server

```bash
# Load environment and run
source .env
python secure_credentials/src/api/server.py
```

**Or create a startup script:**

```bash
#!/bin/bash
# start-passmanager.sh
cd ~/Projects/pass_manager
source .env
python secure_credentials/src/api/server.py
```

```bash
chmod +x start-passmanager.sh
./start-passmanager.sh
```

---

## Using the Web UI

### On your phone:

1. **Connect to Yggdrasil** (open Yggdrasil app)

2. **Open browser** (Chrome, Firefox, Safari, etc.)

3. **Navigate to:**
   ```
   http://[<workstation-yggdrasil-ip>]:8080/
   ```

4. **You'll see:**
   - List of all your credentials
   - Search box to filter
   - Click any credential to unlock it

5. **To view password:**
   - Click credential name
   - Enter credential password (the one specific to that entry)
   - Click "Unlock"
   - Password appears
   - Click "Copy to Clipboard"
   - Automatically clears after 30 seconds

**Screenshot mockup:**
```
┌─────────────────────────────┐
│  🔐 Password Manager        │
├─────────────────────────────┤
│  [Search credentials...]    │
├─────────────────────────────┤
│  github                     │
│  PASSWORD                   │
├─────────────────────────────┤
│  gmail                      │
│  PASSWORD                   │
├─────────────────────────────┤
│  aws-api-key                │
│  API_KEY                    │
└─────────────────────────────┘
```

**Click "github":**
```
┌─────────────────────────────┐
│  github                     │
├─────────────────────────────┤
│  Credential Password:       │
│  [•••••••••••••]           │
│                             │
│  [Unlock]  [Cancel]         │
└─────────────────────────────┘
```

**After unlocking:**
```
┌─────────────────────────────┐
│  github                     │
├─────────────────────────────┤
│  my-secret-password-123     │
│                             │
│  [📋 Copy to Clipboard]     │
│  [Close]                    │
│                             │
│  ✓ Copied to clipboard!     │
└─────────────────────────────┘
```

---

## Features

✅ **Mobile-friendly UI** - Works on any phone browser
✅ **Search** - Filter credentials by name
✅ **Dark mode** - Easy on the eyes
✅ **Touch-friendly** - Large tap targets (44px minimum)
✅ **Clipboard copy** - One tap to copy
✅ **Auto-clear** - Clipboard cleared after 30 seconds
✅ **Keyboard shortcuts** - Enter to unlock, Escape to close
✅ **No installation** - Just open browser

---

## What This Doesn't Do (Intentionally Simple)

❌ No write operations (read-only)
❌ No user management (single user)
❌ No session tokens (master password in env at startup)
❌ No rate limiting (Yggdrasil is private)
❌ No audit logging (use server logs if needed)
❌ No TLS (Yggdrasil encrypts everything)

**Why?** KISS principle - this is for personal use over a private network.

---

## Security

**What protects your passwords:**
1. ✅ Yggdrasil-only binding (not accessible from internet)
2. ✅ Master password required to start server
3. ✅ Credential password required for each entry
4. ✅ KeePass vault encrypted at rest
5. ✅ Clipboard auto-clear after 30 seconds

**Attack scenarios:**
- **Someone finds your Yggdrasil IP?** They still need credential passwords
- **Server crashes?** Vault auto-locks, need master password to restart
- **Phone stolen?** No passwords stored on phone, just the web UI

---

## Optional Improvements

**Add firewall (recommended):**

```bash
# Linux
sudo ip6tables -A INPUT -i tun0 -p tcp --dport 8080 -j ACCEPT
sudo ip6tables -A INPUT -p tcp --dport 8080 -j DROP
```

**Run as systemd service:**

Create `/etc/systemd/system/passmanager.service`:
```ini
[Unit]
Description=Password Manager API
After=yggdrasil.service

[Service]
Type=simple
User=<your-username>
WorkingDirectory=/home/<your-username>/Projects/pass_manager
ExecStart=/home/<your-username>/Projects/pass_manager/start-passmanager.sh
Restart=on-failure
Environment="YGGDRASIL_IP=<your-ip>"
Environment="MASTER_PASSWORD=<your-password>"

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable passmanager
sudo systemctl start passmanager
```

---

## Comparison with Original Plan

| Feature | Original Plan | This Plan |
|---------|--------------|-----------|
| **Lines of code** | ~3000+ | ~350 |
| **Files to create** | 20+ | 1 |
| **Implementation time** | 4-6 weeks | Few hours |
| **Web UI** | Full SPA | Simple HTML page |
| **Auth** | JWT sessions | Master password at startup |
| **Operations** | Full CRUD | Read-only |
| **Logging** | Audit logs | Basic server logs |
| **Rate limiting** | Yes | No (not needed) |
| **Testing** | Unit/Integration/E2E | Manual testing |

**Both achieve the goal:** Access passwords from phone over Yggdrasil.

**This plan:** Simple, secure, sufficient.

---

## FAQ

**Q: Can I still use the GUI?**
A: Yes! Just don't run both at the same time (KeePass file locking).

**Q: What if I want to add/edit passwords?**
A: Use the GUI for that. This API is read-only.

**Q: Is the web UI secure?**
A: Yes - it's served only over Yggdrasil, requires credential passwords, and runs only when you start the server.

**Q: Can I add HTTPS?**
A: Don't need it - Yggdrasil encrypts all traffic end-to-end.

**Q: What happens if I close the terminal?**
A: Server stops. Run with systemd or screen/tmux for persistence.

**Q: Can I access from multiple devices?**
A: Yes! Any device on Yggdrasil can access it.

---

## Summary

**What you get:**
- 📱 Phone web UI to browse passwords
- 🔍 Search functionality
- 📋 One-tap copy to clipboard
- 🔒 Same security as desktop GUI
- 🚀 350 lines of code in 1 file
- ⚡ Thin API layer (no bloat)
- 💾 Uses existing vault (no migration)

**Total implementation:**
- 1 Python file (~350 lines)
- 1 .env file (3 lines)
- Done!

**Ready to implement?** I can generate the actual `server.py` file now if you want!
