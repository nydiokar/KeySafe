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
            errorEl.textContent = response.status === 429
                ? `Too many attempts. Try again in ${response.headers.get('Retry-After') || 'a few'} seconds.`
                : 'Invalid master password';
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

        if (response.status === 423 || response.status === 401) {
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

// Render credential list (DOM APIs only: entry names are never parsed as HTML or JS)
function renderCredentials(creds) {
    const list = document.getElementById('credentialList');
    list.replaceChildren();

    if (creds.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-state';
        empty.textContent = 'No credentials found';
        list.appendChild(empty);
        return;
    }

    for (const cred of creds) {
        const item = document.createElement('li');
        item.className = 'credential-item';
        item.addEventListener('click', () => openModal(cred.name, cred.type));

        const name = document.createElement('div');
        name.className = 'credential-name';
        name.textContent = cred.name;

        const type = document.createElement('div');
        type.className = 'credential-type';
        type.textContent = cred.type;

        item.append(name, type);
        list.appendChild(item);
    }
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
        const response = await fetch('/api/credentials/retrieve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: currentCredential, credential_password: credPassword })
        });

        if (response.status === 423 || response.status === 401) {
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
        document.getElementById('copySuccess').textContent = 'Failed to copy to clipboard';
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

document.getElementById('unlockBtn').addEventListener('click', unlockVault);
document.getElementById('lockBtn').addEventListener('click', lockVault);
document.getElementById('retrieveBtn').addEventListener('click', retrievePassword);
document.getElementById('cancelBtn').addEventListener('click', closeModal);
document.getElementById('closeBtn').addEventListener('click', closeModal);
document.getElementById('copyBtn').addEventListener('click', copyPassword);

// Initialize
checkVaultStatus();
