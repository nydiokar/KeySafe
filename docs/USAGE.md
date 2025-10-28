# Usage Guide

## Quick Reference - How to Run

| Method | Platform | Command | Description |
|--------|----------|---------|-------------|
| **Desktop GUI** | All | `secure-credentials` | Full GUI application |
| **Desktop GUI** | All | `python -m secure_credentials.src.run_app` | Direct Python execution |
| **Desktop Debug** | All | `python -m secure_credentials.src.run_app debug` | GUI with debug logging |
| **Web Server** | All | `secure-credentials-web` | Web interface at http://localhost:5000/app |
| **Web Server** | All | `python -m secure_credentials.src.web_app` | Direct web app execution |
| **Compiled Executable** | Windows | `.\dist\SecureCredentialManager.exe` | Standalone Windows app |
| **Compiled Executable** | Linux | `./dist/SecureCredentialManager` | Standalone Linux app |

## First Time Setup

### Desktop Application

1. **Launch the application:**
   ```bash
   secure-credentials
   ```

2. **Create a master password:**
   - Choose a strong master password (12+ characters recommended)
   - **⚠️ WARNING: There is NO password recovery - keep it safe!**

3. **Database creation:**
   - The application will create a new KeePass database automatically
   - Default location: `~/.secure_credentials/vault.kdbx`

### Web Interface

1. **Launch the web server:**
   ```bash
   secure-credentials-web
   ```

2. **Access the interface:**
   - Open browser to: `http://localhost:5000/app`
   - Create master password (same as desktop app)

3. **Database sharing:**
   - Both desktop and web interfaces use the same database
   - Changes sync automatically between interfaces

## Desktop Application Usage

### Main Interface

- **Credential List:** Shows all stored credentials
- **Search Bar:** Filter credentials by name (Ctrl+F)
- **Add Button:** Create new credentials (Ctrl+N)
- **Tabs:** Organized by credential type (Passwords, API Keys, Other)

### Basic Operations

#### Adding Credentials
1. Click "Add New Credential" or press Ctrl+N
2. Select credential type
3. Enter credential details:
   - Name (required)
   - Username/Email
   - Password (will be encrypted)
   - URL/Notes
4. Set individual password for this credential
5. Click "Save"

#### Viewing Credentials
1. Double-click a credential in the list
2. Enter the individual credential password
3. View/edit all credential details

#### Editing Credentials
1. Select credential and click "Edit"
2. Modify any fields
3. Save changes

#### Deleting Credentials
1. Select credential
2. Click "Delete" and confirm

### Keyboard Shortcuts

- `Ctrl+N`: Add new credential
- `Ctrl+F`: Focus search bar
- `F5`: Refresh credential list
- `Esc`: Close dialogs
- `Ctrl+S`: Save changes (in edit mode)

### Security Features

#### Auto-lock
- Application locks automatically after inactivity
- Configurable timeout (default: 5 minutes)

#### Clipboard Security
- Passwords auto-clear from clipboard after 30 seconds
- Manual clear option available

#### Session Management
- Secure session handling
- Automatic logout on application close

## Web Interface Usage

### Browser Access

#### Local Access
```bash
# Start web server
secure-credentials-web

# Access at: http://localhost:5000/app
```

#### Network Access
```bash
# Allow external access
HOST=0.0.0.0 secure-credentials-web

# Access from other devices: http://YOUR_SERVER_IP:5000/app
```

### Web Interface Features

#### Dashboard
- **Tabbed Organization:** Passwords, API Keys, Other credentials
- **Real-time Search:** Instant filtering as you type
- **Responsive Design:** Works on desktop and mobile

#### Adding Credentials
1. Click "Add New Credential"
2. Fill in the form
3. Set individual password
4. Save

#### Viewing Credentials
1. Click "View" button on any credential
2. Enter individual credential password
3. View details in modal popup
4. Copy to clipboard or edit directly

#### Modal Features
- **Secure Viewing:** Credentials displayed in popup, not new page
- **Copy to Clipboard:** One-click copying
- **Edit in Place:** Modify credentials without navigation
- **Password Protection:** Each credential requires its own password

### Session Management

#### Login/Logout
- Automatic login session management
- Secure logout clears all session data
- Browser close automatically logs out

#### Security
- Session timeout after inactivity
- Secure cookie handling
- HTTPS recommended for network access

## Backup and Restore

### Creating Backups

#### Desktop Application
1. Go to File → Backup Database
2. Choose backup location
3. Backup includes all credentials and settings

#### Manual Backup
```bash
# Copy the database file
cp ~/.secure_credentials/vault.kdbx ~/vault_backup.kdbx
```

### Restoring from Backup

#### Desktop Application
1. Go to File → Restore Database
2. Select backup file
3. Confirm restore operation

#### Manual Restore
```bash
# Replace the database file
cp ~/vault_backup.kdbx ~/.secure_credentials/vault.kdbx
```

## Configuration

### Database Location

Default location: `~/.secure_credentials/vault.kdbx`

To change location:
```bash
# Set environment variable before running
export SECURE_CREDENTIALS_DB=/path/to/your/database.kdbx
```

### Application Settings

Currently, most settings are configured through the interface:
- Auto-lock timeout
- Clipboard clear time
- UI preferences

## Troubleshooting

### Common Issues

#### "Database not found" Error
- First run: Database is created automatically
- Check file permissions on database directory
- Restore from backup if file is corrupted

#### "Invalid password" Error
- Verify master password is correct
- Check for caps lock
- Try resetting if password is forgotten (⚠️ destructive operation)

#### Web interface not loading
- Check if port 5000 is available
- Verify firewall allows local connections
- Try different port: `PORT=8080 secure-credentials-web`

#### Slow performance
- Large database: Consider archiving old credentials
- Many concurrent users: Use production deployment
- Network latency: Optimize database location

### Logs and Debugging

#### Desktop Application Logs
```bash
# Enable debug logging
python -m secure_credentials.src.run_app debug
```

#### Web Application Logs
```bash
# Enable debug mode
FLASK_ENV=development secure-credentials-web
```

#### Log Locations
- Desktop: Console output
- Web: Console output and `run_app_debug.log`

### Getting Help

1. Check this documentation first
2. Review [Security Guide](SECURITY.md) for security-related issues
3. Check existing GitHub issues
4. Create detailed bug report with:
   - Operating system and version
   - Python version
   - Application version
   - Steps to reproduce
   - Error messages and logs
