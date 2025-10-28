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

1. Download the latest release from the releases page
2. Run the installer
3. Launch "Secure Credential Manager" from the Start Menu

### Option 2: From Source

1. Ensure you have Python 3.8 or newer installed
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
   pyinstaller secure_credentials.spec
   ```

The executable will be created in the `dist` directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

- The master password is never stored
- Credentials are stored in an encrypted KeePass database
- Each credential has its own password
- The application auto-locks after inactivity

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 