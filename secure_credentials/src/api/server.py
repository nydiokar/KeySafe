#!/usr/bin/env python3
"""
Secure password manager API with vault auto-locking.
Thin layer over existing KeePassHandler.

Security model:
- Master password prompted on startup (never stored on disk)
- Vault auto-locks after 5 minutes of inactivity
- Requires master password to unlock vault
- Requires credential password per entry
- Only accessible over Yggdrasil network

Usage:
    Set YGGDRASIL_IP environment variable
    Run: python server.py
    Enter master password when prompted
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import os
from pathlib import Path
import sys
import getpass
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

# Import existing KeePass handler
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.keepass_backend import KeePassHandler

# ==================== CONFIGURATION ====================

YGGDRASIL_HOST = os.getenv("YGGDRASIL_IP", "")
PORT = int(os.getenv("API_PORT", "8080"))
AUTO_LOCK_TIMEOUT = int(os.getenv("AUTO_LOCK_TIMEOUT", "300"))  # 5 minutes default

if not YGGDRASIL_HOST:
    print("❌ ERROR: Set YGGDRASIL_IP environment variable")
    print("   Get it with: yggdrasilctl getSelf")
    sys.exit(1)

# ==================== VAULT STATE MANAGER ====================

class VaultState:
    """Manages vault state with auto-locking."""

    def __init__(self):
        self.kp: Optional[KeePassHandler] = None
        self.master_password: Optional[str] = None
        self.last_activity: Optional[datetime] = None
        self.timeout_seconds = AUTO_LOCK_TIMEOUT
        self.is_locked = True

    def unlock(self, master_password: str) -> bool:
        """Unlock vault with master password."""
        try:
            # Create new KeePassHandler
            temp_kp = KeePassHandler()

            # Try to open database
            if not temp_kp.open_database(master_password):
                return False

            # Success - store the handler and password
            self.kp = temp_kp
            self.master_password = master_password
            self.last_activity = datetime.now()
            self.is_locked = False

            print(f"✅ Vault unlocked at {self.last_activity.strftime('%H:%M:%S')}")
            return True

        except Exception as e:
            # Don't print exception details that might contain sensitive info
            print(f"❌ Failed to unlock vault")
            return False

    def lock(self):
        """Lock vault and clear from memory."""
        if self.kp:
            self.kp = None
        self.is_locked = True
        self.last_activity = None
        print(f"🔒 Vault locked at {datetime.now().strftime('%H:%M:%S')}")

    def check_and_lock_if_needed(self) -> bool:
        """Check if vault should be locked due to inactivity. Returns True if locked."""
        if self.is_locked or not self.last_activity:
            return True

        idle_time = datetime.now() - self.last_activity
        if idle_time.total_seconds() > self.timeout_seconds:
            self.lock()
            return True

        return False

    def update_activity(self):
        """Update last activity timestamp."""
        if not self.is_locked:
            self.last_activity = datetime.now()

    def get_status(self) -> dict:
        """Get current vault status."""
        if self.is_locked:
            return {
                "locked": True,
                "timeout_seconds": self.timeout_seconds
            }

        idle_time = datetime.now() - self.last_activity
        remaining = self.timeout_seconds - int(idle_time.total_seconds())

        return {
            "locked": False,
            "timeout_seconds": self.timeout_seconds,
            "seconds_until_lock": max(0, remaining),
            "last_activity": self.last_activity.isoformat()
        }

# Global vault state
vault = VaultState()

# ==================== FASTAPI APP ====================

app = FastAPI(
    title="Password Manager",
    version="2.0.0",
    docs_url=None,
    redoc_url=None
)

# ==================== MODELS ====================

class CredentialMetadata(BaseModel):
    """Entry metadata without password"""
    name: str
    type: str
    created_at: Optional[str] = None
    last_accessed: Optional[str] = None


class Credential(BaseModel):
    """Full credential with password"""
    name: str
    value: str
    type: str


class UnlockRequest(BaseModel):
    """Request to unlock vault"""
    master_password: str


class RetrieveRequest(BaseModel):
    """Request to retrieve credential"""
    credential_password: str


class VaultStatus(BaseModel):
    """Vault status response"""
    locked: bool
    timeout_seconds: int
    seconds_until_lock: Optional[int] = None
    last_activity: Optional[str] = None


# ==================== HELPER FUNCTIONS ====================

def require_unlocked_vault():
    """Check if vault is unlocked, raise exception if not."""
    if vault.check_and_lock_if_needed():
        raise HTTPException(
            status_code=423,
            detail="Vault is locked. Please unlock it first by calling POST /api/unlock"
        )
    vault.update_activity()


# ==================== STATIC WEB UI ====================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve web UI"""
    return WEB_UI_HTML


# ==================== API ENDPOINTS ====================

@app.get("/api/health")
async def health():
    """Health check (doesn't require unlocked vault)"""
    return {
        "status": "ok",
        "vault_locked": vault.is_locked,
        "timeout_seconds": vault.timeout_seconds
    }


@app.get("/api/status", response_model=VaultStatus)
async def get_status():
    """Get vault lock status"""
    return vault.get_status()


@app.post("/api/unlock")
async def unlock_vault(request: UnlockRequest):
    """Unlock vault with master password"""
    if vault.unlock(request.master_password):
        return {
            "status": "unlocked",
            "timeout_seconds": vault.timeout_seconds,
            "message": f"Vault will auto-lock after {vault.timeout_seconds // 60} minutes of inactivity"
        }

    raise HTTPException(status_code=403, detail="Invalid master password")


@app.post("/api/lock")
async def lock_vault():
    """Manually lock the vault"""
    vault.lock()
    return {"status": "locked"}


@app.get("/api/credentials", response_model=List[CredentialMetadata])
async def list_credentials():
    """List all credentials (metadata only, no passwords)"""
    require_unlocked_vault()

    try:
        creds = vault.kp.get_all_credentials()

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
        # Don't expose internal error details that might contain sensitive info
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/credentials/{name}", response_model=Credential)
async def get_credential(name: str, request: RetrieveRequest):
    """
    Retrieve credential by name.
    Requires vault to be unlocked AND credential password.
    """
    require_unlocked_vault()

    try:
        cred = vault.kp.get_credential(name, request.credential_password)

        if not cred:
            raise HTTPException(
                status_code=403,
                detail="Credential not found or incorrect credential password"
            )

        return Credential(
            name=cred["name"],
            value=cred["value"],
            type=cred["type"]
        )

    except HTTPException:
        raise
    except Exception as e:
        # Don't expose internal error details that might contain sensitive info
        raise HTTPException(status_code=500, detail="Internal server error")


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

        .status-bar {
            background: #2a2a2a;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            border: 1px solid #444;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .status-locked {
            color: #f44336;
        }

        .status-unlocked {
            color: #4CAF50;
        }

        .timer {
            font-size: 12px;
            color: #999;
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

        .btn-danger {
            background: #f44336;
            color: white;
        }

        .btn-danger:active {
            background: #da190b;
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

        .locked-screen {
            text-align: center;
            padding: 60px 20px;
        }

        .locked-screen h2 {
            color: #f44336;
            margin-bottom: 20px;
        }

        .lock-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>🔐 Password Manager</h1>

    <!-- Status Bar -->
    <div class="status-bar">
        <div id="lockStatus" class="status-locked">🔒 Locked</div>
        <div id="timer" class="timer"></div>
    </div>

    <!-- Locked Screen -->
    <div id="lockedScreen" class="locked-screen">
        <div class="lock-icon">🔒</div>
        <h2>Vault is Locked</h2>
        <p style="margin-bottom: 20px; color: #999;">Enter your master password to unlock</p>
        <div class="form-group">
            <input type="password"
                   id="masterPassword"
                   placeholder="Master password"
                   style="max-width: 300px; margin: 0 auto;">
        </div>
        <button class="btn btn-primary" onclick="unlockVault()">
            Unlock Vault
        </button>
        <div id="unlockError" class="error"></div>
    </div>

    <!-- Main Content (hidden when locked) -->
    <div id="mainContent" style="display: none;">
        <input type="text"
               id="searchBox"
               class="search-box"
               placeholder="Search credentials...">

        <button class="btn btn-danger" onclick="lockVault()" style="margin-bottom: 20px;">
            🔒 Lock Vault
        </button>

        <ul id="credentialList" class="credential-list">
            <li class="loading">Loading credentials...</li>
        </ul>
    </div>

    <!-- Modal for credential password entry -->
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
        let statusCheckInterval = null;
        let currentSearchQuery = '';

        // Check vault status on load
        async function checkVaultStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();

                if (status.locked) {
                    showLockedScreen();
                } else {
                    showMainContent();
                    updateStatusBar(status);
                }
            } catch (error) {
                console.error('Failed to check vault status:', error);
            }
        }

        // Update status bar
        function updateStatusBar(status) {
            const statusEl = document.getElementById('lockStatus');
            const timerEl = document.getElementById('timer');

            if (status.locked) {
                statusEl.className = 'status-locked';
                statusEl.textContent = '🔒 Locked';
                timerEl.textContent = '';
            } else {
                statusEl.className = 'status-unlocked';
                statusEl.textContent = '🔓 Unlocked';

                const minutes = Math.floor(status.seconds_until_lock / 60);
                const seconds = status.seconds_until_lock % 60;
                timerEl.textContent = `Auto-lock in ${minutes}:${seconds.toString().padStart(2, '0')}`;
            }
        }

        // Show locked screen
        function showLockedScreen() {
            document.getElementById('lockedScreen').style.display = 'block';
            document.getElementById('mainContent').style.display = 'none';

            if (statusCheckInterval) {
                clearInterval(statusCheckInterval);
                statusCheckInterval = null;
            }
        }

        // Show main content
        function showMainContent() {
            document.getElementById('lockedScreen').style.display = 'none';
            document.getElementById('mainContent').style.display = 'block';

            loadCredentials();

            // Start status checking
            if (!statusCheckInterval) {
                statusCheckInterval = setInterval(checkVaultStatus, 5000);
            }
        }

        // Unlock vault
        async function unlockVault() {
            const masterPassword = document.getElementById('masterPassword').value;
            const errorEl = document.getElementById('unlockError');

            if (!masterPassword) {
                errorEl.textContent = 'Please enter master password';
                return;
            }

            try {
                const response = await fetch('/api/unlock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ master_password: masterPassword })
                });

                if (!response.ok) {
                    errorEl.textContent = 'Invalid master password';
                    return;
                }

                // Clear password field
                document.getElementById('masterPassword').value = '';
                errorEl.textContent = '';

                // Show main content
                showMainContent();

            } catch (error) {
                errorEl.textContent = 'Failed to unlock vault';
            }
        }

        // Lock vault manually
        async function lockVault() {
            try {
                await fetch('/api/lock', { method: 'POST' });
                showLockedScreen();
            } catch (error) {
                console.error('Failed to lock vault:', error);
            }
        }

        // Apply search filter
        function applySearchFilter() {
            if (!currentSearchQuery) {
                renderCredentials(credentials);
            } else {
                const filtered = credentials.filter(cred =>
                    cred.name.toLowerCase().includes(currentSearchQuery.toLowerCase())
                );
                renderCredentials(filtered);
            }
        }

        // Load credentials
        async function loadCredentials() {
            try {
                const response = await fetch('/api/credentials');

                if (response.status === 423) {
                    // Vault locked
                    showLockedScreen();
                    return;
                }

                credentials = await response.json();
                // Reapply search filter if active
                applySearchFilter();
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
                <li class="credential-item" onclick="openModal('${escapeHtml(cred.name)}', '${escapeHtml(cred.type)}')">
                    <div class="credential-name">${escapeHtml(cred.name)}</div>
                    <div class="credential-type">${escapeHtml(cred.type)}</div>
                </li>
            `).join('');
        }

        // Escape HTML
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Search filter
        document.getElementById('searchBox').addEventListener('input', (e) => {
            currentSearchQuery = e.target.value;
            applySearchFilter();
        });

        // Open modal for credential
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
                const response = await fetch(`/api/credentials/${encodeURIComponent(currentCredential)}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ credential_password: credPassword })
                });

                if (response.status === 423) {
                    // Vault locked
                    closeModal();
                    showLockedScreen();
                    return;
                }

                if (!response.ok) {
                    errorEl.textContent = 'Incorrect credential password';
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

                setTimeout(() => {
                    document.getElementById('copySuccess').textContent = '';
                }, 2000);
            } catch (error) {
                alert('Failed to copy to clipboard');
            }
        }

        // Enter key handlers
        document.getElementById('masterPassword').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') unlockVault();
        });

        document.getElementById('credPassword').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') retrievePassword();
        });

        // Escape key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        // Initialize
        checkVaultStatus();
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
    print(f"⏱️  Auto-lock timeout: {AUTO_LOCK_TIMEOUT // 60} minutes")
    print(f"\n🔐 Master Password Setup")
    print(f"{'='*60}")

    # Prompt for master password
    print("\nThe master password will be used to unlock your vault.")
    print("It will NOT be stored anywhere - only kept in memory.")
    print("\nYou'll need to enter it again:")
    print("  - When starting the server")
    print("  - After vault auto-locks (5 min inactivity)")
    print("  - After manually locking the vault\n")

    master_password = getpass.getpass("Enter master password: ")

    if not master_password:
        print("❌ ERROR: Master password cannot be empty")
        sys.exit(1)

    # Try to unlock vault with provided password
    print("\n🔓 Verifying master password...")
    if not vault.unlock(master_password):
        print("❌ ERROR: Invalid master password or vault doesn't exist")
        print("\nIf this is your first time, please create a vault using the GUI first:")
        print("  python secure_credentials/run_app.py")
        sys.exit(1)

    # Lock it immediately - user will unlock via web UI
    vault.lock()

    print(f"\n✅ Password verified successfully")
    print(f"🔒 Vault is now locked - unlock it via web UI")
    print(f"\n🌐 Access from phone:")
    print(f"   http://[{YGGDRASIL_HOST}]:{PORT}/")
    print(f"\n{'='*60}\n")

    # Store master password for unlock API
    vault.master_password = master_password

    uvicorn.run(
        app,
        host=YGGDRASIL_HOST,
        port=PORT,
        log_level="info"
    )
