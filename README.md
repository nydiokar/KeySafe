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
- Web interface for browser access

## Quick Start

### Desktop Application
```bash
# Install dependencies
pip install -e .

# Run GUI application
secure-credentials
```

### Web Interface
```bash
# Run web server
secure-credentials-web

# Access at: http://localhost:5000/app
```

## 📚 Documentation

- **[Installation Guide](docs/INSTALL.md)** - Pre-built executables and source installation
- **[Usage Guide](docs/USAGE.md)** - Desktop and web interface usage
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Network deployment and production setup
- **[Development Guide](docs/DEVELOPMENT.md)** - Development environment and contributing
- **[Security Guide](docs/SECURITY.md)** - Security features and best practices

## Deployment Options

| Type | Use Case | Setup | Security |
|------|----------|-------|----------|
| **Desktop GUI** | Personal use | ⭐ Low | ⭐⭐⭐⭐⭐ |
| **Web (Local)** | Browser access | ⭐⭐ Medium | ⭐⭐⭐⭐ High |
| **Web (Network)** | Shared access | ⭐⭐⭐ High | ⭐⭐⭐ Medium |
| **Production** | Enterprise | ⭐⭐⭐⭐⭐ Very High | ⭐⭐⭐⭐⭐ Production |

## Requirements

- Python 3.8+
- KeePass database support
- GUI libraries (Tkinter/ttkbootstrap)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please see [Development Guide](docs/DEVELOPMENT.md) for setup instructions.
