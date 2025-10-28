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

### Option 1: Using Pre-built Executables

#### Windows
1. Download the latest release from the releases page
2. Run the installer
3. Launch "Secure Credential Manager" from the Start Menu

#### Linux
1. Download the latest Linux executable from the releases page
2. Make it executable: `chmod +x SecureCredentialManager`
3. Run: `./SecureCredentialManager`

### Option 2: From Source (Cross-platform)

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
   # Option 1: Using the installed script (GUI mode)
   secure-credentials

   # Option 2: Direct module execution
   python -m secure_credentials.run_app

   # Option 3: Debug mode (with extra logging)
   python -m secure_credentials.run_app debug
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

### Windows (Recommended)

Run the automated build script:

```bash
build.bat
```

This script will:
- Create/activate a virtual environment
- Install all dependencies
- Clean previous builds
- Build the executable using PyInstaller
- Optionally create an installer if NSIS is installed

The executable will be created in the `dist` directory.

### Linux (Recommended)

Run the automated build script:

```bash
# Make the script executable (first time only)
chmod +x build.sh

# Run the build script
./build.sh
```

This script will:
- Create/activate a virtual environment
- Install all dependencies
- Clean previous builds
- Build the executable using PyInstaller

The executable will be created in the `dist` directory.

### Linux Manual Build

1. Install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install python3-dev python3-tk

   # Fedora/CentOS/RHEL
   sudo dnf install python3-devel tkinter

   # Arch Linux
   sudo pacman -S python tk
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Generate and run PyInstaller:
   ```bash
   pyinstaller secure_credentials.spec
   ```

The executable will be created in the `dist` directory.

## Web Server Mode (Network Access)

Run the application as a web server to access it from any device on your network via browser.

### Quick Start

```bash
# Install dependencies
pip install -e .

# Run web server (accessible at http://localhost:5000/app)
secure-credentials-web

# Or run directly
python -m secure_credentials.src.web_app
```

### Advanced Configuration

#### Environment Variables
```bash
# Set server port
export FLASK_PORT=8080

# Allow external access (use with caution!)
export HOST=0.0.0.0

# Enable debug mode
export FLASK_ENV=development

# Set custom secret key (important for production!)
export SECRET_KEY="your-secure-random-key-here"
```

#### Access from Network
```bash
# Run on all interfaces (accessible from other devices)
HOST=0.0.0.0 secure-credentials-web

# Then access from another device at: http://YOUR_SERVER_IP:5000
```

### Security Considerations

⚠️ **Important Security Notes:**

1. **Network Access**: By default, the web server only listens on `127.0.0.1` (localhost)
2. **HTTPS**: The built-in server doesn't provide HTTPS - use a reverse proxy (nginx/apache) for production
3. **Firewall**: Configure your firewall to restrict access to trusted networks only
4. **VPN**: Consider running through a VPN for remote access
5. **Session Security**: The web interface maintains sessions but doesn't implement advanced security features

#### Security Setup Script

Use the automated security setup script for basic network security:

```bash
# Make executable and run interactive setup
chmod +x setup_security.sh
./setup_security.sh

# Or run specific components
./setup_security.sh firewall    # Setup firewall rules
./setup_security.sh ssl         # Generate SSL certificate
./setup_security.sh service     # Create systemd service
./setup_security.sh config      # Generate secure config
./setup_security.sh all         # Run complete setup
```

### Development vs Production Server

#### ⚠️ Development Server Warning

When you run the web server, you'll see this message:
```
WARNING: This is a development server. Do not use it in a production deployment.
Use a production WSGI server instead.
```

**What this means:**
- Flask's built-in server (Werkzeug) is designed for **development and testing only**
- It lacks security features, performance optimizations, and production reliability
- It's single-threaded and can't handle multiple concurrent users well
- **Never use it for production deployments**

**Why you see this:** Flask shows this warning to prevent accidental production use of the development server.

#### Production Deployment

For production use, deploy behind a proper web server:

```bash
# Using Gunicorn (recommended for production)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 "secure_credentials.src.web_app:app"

# Using nginx as reverse proxy (example)
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/ssl/server.crt;
    ssl_certificate_key /path/to/ssl/server.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Production Benefits:**
- **Security:** Proper request handling, headers, and SSL termination
- **Performance:** Multi-worker, async processing
- **Reliability:** Process monitoring, automatic restarts
- **Load Balancing:** Handle multiple concurrent users
- **Logging:** Production-grade logging and monitoring

**Documentation Reference:**
- [Flask Deployment Options](https://flask.palletsprojects.com/en/3.0.x/deploying/)
- [Gunicorn Documentation](https://docs.gunicorn.org/en/stable/)
- [nginx Reverse Proxy](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)

### Web Interface Features

- **Browser-based GUI**: Full credential management through web interface
- **Tabbed Organization**: Separate views for Passwords, API Keys, and Other credentials
- **Real-time Search**: Filter credentials instantly
- **Secure Access**: Master password required, individual passwords for each credential
- **Responsive Design**: Works on desktop and mobile browsers
- **Session Management**: Automatic logout on browser close

### Manual Build (Cross-platform)

1. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

2. Generate and run PyInstaller:
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