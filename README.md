# Secure Credential Manager

A secure and user-friendly credential manager with GUI interface, built with Python and KeePass.

## Features

- Secure credential storage using KeePass database
- Modern GUI interface with dark mode support
- Support for passwords, API keys, and other credentials
- Individual passwords for each credential
- Auto-lock functionality
- System tray integration
- Search and filter capabilities
- Automatic clipboard clearing
- Backup and restore functionality

## Installation

### Option 1: Using the Executable (Windows)

1. Download `SecureCredentialManager.exe` from the [latest release](https://github.com/nydiokar/KeySafe/releases/latest)
2. Run it (portable, no installer). Verify against `SHA256SUMS.txt` if desired.

### Option 1b: GUI + API via pip (any release)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install https://github.com/nydiokar/KeySafe/releases/latest/download/<wheel-filename>.whl
```

- GUI: `python -m secure_credentials.run_app`
- API: set `YGGDRASIL_IP` (and optionally `API_PORT`, `VAULT_PATH`) in the environment or a `.env`, then run `secure-credentials-api`

### Option 2: From Source

1. Ensure you have Python 3.10 or newer installed
2. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/secure_credentials.git
   cd secure_credentials
   ```
3. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/Mac:
   source venv/bin/activate
   ```
4. Install the package:
   ```bash
   pip install -e .
   ```

## Usage

### First Time Setup

1. Launch the application:
   ```bash
   python -m secure_credentials.run_app 
   ```
2. Create a strong master password when prompted - # THERE IS NO RECOVERY 
3. The application will create a new vault file in your home directory

### Daily Use

1. Launch the application
2. Enter your master password
3. Use the interface to:
   - Add new credentials (Ctrl+N)
   - View existing credentials (double-click)
   - Edit credentials
   - Search for credentials (Ctrl+F)
   - Copy credential values to clipboard

### Security Features

- Each credential has its own password
- Auto-lock after inactivity
- Automatic clipboard clearing
- Encrypted storage using KeePass

### Backup and Restore

1. Go to File → Backup Database to create a backup
2. Use File → Restore Database to restore from a backup
3. Keep backups in a secure location

## Building from Source

To create a standalone executable:

1. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

2. Build the executable:
   ```bash
   pyinstaller --name SecureCredentialManager --onefile --noconsole --icon secure_credentials/assets/icon.ico --clean secure_credentials/run_app.py
   ```

The executable will be created in the `dist` directory.

## Releases and dependency updates

- Dependabot opens weekly PRs for Python dependencies and GitHub Actions; CI (tests + `pip-audit`) runs on every PR and weekly.
- To release: bump `version` in `pyproject.toml` and `__version__` in `secure_credentials/__init__.py`, commit, then `git tag vX.Y.Z; git push origin vX.Y.Z`. The Release workflow verifies the tag matches both, runs tests, builds the exe, wheel and sdist, and publishes them with `SHA256SUMS.txt`.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

- The master password is never stored
- Credentials are stored in an encrypted KeePass database
- Each credential has its own password
- The application auto-locks after inactivity

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 