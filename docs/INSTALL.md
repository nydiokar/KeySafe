# Installation Guide

## Option 1: Pre-built Executables (Recommended for End Users)

### Windows
1. Download the latest release from the releases page
2. Run the installer (`SecureCredentialManager-Setup.exe`)
3. Launch "Secure Credential Manager" from the Start Menu

### Linux
1. Download the latest Linux executable from the releases page
2. Make it executable: `chmod +x SecureCredentialManager`
3. Run: `./SecureCredentialManager`

## Option 2: From Source (Cross-platform)

### System Requirements

#### Windows
- Python 3.8 or newer
- No additional system dependencies required

#### Linux
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev python3-tk

# Fedora/CentOS/RHEL
sudo dnf install python3-devel tkinter

# Arch Linux
sudo pacman -S python tk
```

#### macOS
```bash
# Install Python 3.8+ (using Homebrew recommended)
brew install python@3.9 tk
```

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nydiokar/KeySafe.git
   cd secure_credentials
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/macOS
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install the package:**
   ```bash
   pip install -e .
   ```

## Building from Source

### Windows (Recommended)
```bash
# Run the automated build script
.\build.bat
```

### Linux (Recommended)
```bash
# Make the script executable (first time only)
chmod +x build.sh

# Run the build script
./build.sh
```

### Manual Build (Cross-platform)
```bash
# Install development dependencies
pip install -e ".[dev]"

# Generate executable
pyinstaller secure_credentials.spec
```

The executable will be created in the `dist` directory.

## Verification

After installation, verify the installation:

```bash
# Check if scripts are available
secure-credentials --help
secure-credentials-web --help

# Check version
python -c "import secure_credentials; print('Installation successful')"
```

## Troubleshooting

### Common Issues

**"Python not found" error:**
- Ensure Python 3.8+ is installed and in PATH
- On Windows, use `py` instead of `python`

**"tkinter not found" error (Linux):**
- Install tkinter: `sudo apt-get install python3-tk`
- Restart your terminal session

**"Permission denied" error:**
- Make sure scripts have execute permissions: `chmod +x build.sh`
- On Windows, run PowerShell as Administrator

**Build fails:**
- Ensure all development dependencies are installed: `pip install -e ".[dev]"`
- Check that PyInstaller version is compatible

### Getting Help

If you encounter issues:
1. Check the [Usage Guide](USAGE.md) for common usage patterns
2. Review the [Development Guide](DEVELOPMENT.md) for development setup
3. Check existing GitHub issues for similar problems
4. Create a new issue with your system information and error logs
