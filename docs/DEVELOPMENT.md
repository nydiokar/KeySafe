# Development Guide

## Getting Started

### Prerequisites

- Python 3.8 or newer
- Git
- Virtual environment support

### Initial Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nydiokar/KeySafe.git
   cd secure_credentials
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv

   # Windows
   .\venv\Scripts\activate

   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   # Install main package
   pip install -e .

   # Install development dependencies
   pip install -e ".[dev]"
   ```

4. **Verify installation:**
   ```bash
   # Test imports
   python -c "import secure_credentials; print('Import successful')"

   # Test CLI commands
   secure-credentials --help
   secure-credentials-web --help
   ```

## Project Structure

```
secure_credentials/
├── src/                    # Main source code
│   ├── __init__.py
│   ├── run_app.py         # GUI application entry point
│   ├── web_app.py         # Web application entry point
│   ├── hash_utility.py    # Password hashing utilities
│   ├── keepass_backend.py # KeePass database operations
│   ├── pass_manager.py    # Core credential management
│   ├── security.py        # Security utilities
│   └── ui/                # User interface components
│       ├── __init__.py
│       ├── gui.py         # Main GUI application
│       └── gui_components.py  # GUI helper components
├── templates/             # Jinja2 templates for web interface
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── add.html
│   ├── edit.html
│   ├── view.html
│   └── error.html
├── static/               # Static assets (CSS, JS, images)
├── tests/               # Test suite
├── docs/                # Documentation
├── assets/              # Application icons and resources
└── __init__.py
```

## Development Workflow

### Running the Application

#### GUI Application
```bash
# Normal mode
python -m secure_credentials.src.run_app

# Debug mode (with logging)
python -m secure_credentials.src.run_app debug

# Test window mode
python -m secure_credentials.src.run_app test_window

# Direct GUI mode (skip launcher)
python -m secure_credentials.src.run_app direct_gui
```

#### Web Application
```bash
# Normal mode
python -m secure_credentials.src.web_app

# With debug mode
FLASK_ENV=development python -m secure_credentials.src.web_app

# Custom host/port
HOST=0.0.0.0 PORT=8080 python -m secure_credentials.src.web_app
```

### Testing

#### Run Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_keepass_backend.py

# Run with coverage
pytest --cov=secure_credentials --cov-report=html

# Run with verbose output
pytest -v
```

#### Test Structure
```
tests/
├── __init__.py
├── test_keepass_backend.py    # KeePass operations
├── test_pass_manager.py       # Credential management
├── test_security.py          # Security functions
├── test_web_app.py           # Web interface
├── test_gui.py              # GUI components
└── fixtures/                # Test data and fixtures
```

### Code Quality

#### Linting
```bash
# Run flake8
flake8 secure_credentials

# Run black (code formatting)
black secure_credentials

# Run isort (import sorting)
isort secure_credentials
```

#### Type Checking
```bash
# Run mypy
mypy secure_credentials
```

#### Pre-commit Hooks
```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run manually
pre-commit run --all-files
```

## Building and Packaging

### Creating Executables

#### Windows
```bash
# Run build script
.\build.bat

# Or manual build
pyinstaller secure_credentials.spec
```

#### Linux
```bash
# Run build script
chmod +x build.sh
./build.sh

# Or manual build
pyinstaller secure_credentials.spec
```

#### macOS
```bash
# Manual build
pyinstaller secure_credentials.spec
```

### PyInstaller Configuration

The `secure_credentials.spec` file contains:
- Entry points for GUI and web applications
- Hidden imports for dependencies
- Data files and templates
- Icon and metadata

### Creating Distributions

```bash
# Build wheel
python -m build --wheel

# Build source distribution
python -m build --sdist

# Upload to PyPI (requires API token)
twine upload dist/*
```

## Contributing

### Development Process

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Run tests and linting:**
   ```bash
   pytest
   flake8 secure_credentials
   black secure_credentials
   ```
5. **Commit your changes:**
   ```bash
   git commit -m "Add your feature description"
   ```
6. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request**

### Code Standards

#### Python Style Guide
- Follow PEP 8
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep line length under 88 characters (Black default)

#### Naming Conventions
```python
# Classes
class CredentialManager:
    pass

# Functions and methods
def get_credentials(self) -> list:
    pass

# Variables
user_credentials = []
max_attempts = 3

# Constants
MAX_PASSWORD_LENGTH = 128
DEFAULT_TIMEOUT = 300
```

#### Error Handling
```python
try:
    result = risky_operation()
except SpecificError as e:
    logger.error(f"Operation failed: {e}")
    raise CustomError("User-friendly message") from e
except Exception as e:
    logger.exception("Unexpected error")
    raise
```

### Testing Guidelines

#### Unit Tests
```python
import pytest
from secure_credentials.src.pass_manager import CredentialManager

class TestCredentialManager:
    def test_add_credential(self):
        manager = CredentialManager()
        credential = {"name": "test", "password": "secret"}

        result = manager.add_credential(credential)

        assert result is True
        assert len(manager.get_credentials()) == 1

    def test_invalid_credential(self):
        manager = CredentialManager()

        with pytest.raises(ValueError):
            manager.add_credential({})
```

#### Integration Tests
```python
def test_full_workflow():
    # Test complete user workflows
    # Setup database, add credentials, retrieve, etc.
    pass
```

#### Test Coverage
- Aim for 80%+ code coverage
- Test error conditions and edge cases
- Mock external dependencies
- Use fixtures for test data

### Documentation

#### Code Documentation
```python
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user with username and password.

    Args:
        username: User's login name
        password: User's password

    Returns:
        True if authentication successful, False otherwise

    Raises:
        ConnectionError: If database is unreachable
        ValueError: If username or password is invalid

    Example:
        >>> authenticate_user("admin", "password")
        True
    """
    pass
```

#### API Documentation
```python
# For web endpoints
@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    """
    Retrieve all user credentials.

    Returns:
        JSON response with credential list

    Query Parameters:
        type (str): Filter by credential type
        limit (int): Maximum number of results

    Response:
        {
            "credentials": [...],
            "total": 42
        }
    """
    pass
```

## Debugging

### Logging

#### Configure Logging
```python
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
```

#### Log Levels
- `DEBUG`: Detailed information for debugging
- `INFO`: General information about application operation
- `WARNING`: Warning messages for potential issues
- `ERROR`: Error messages for failures
- `CRITICAL`: Critical errors that may cause application failure

### Debug Mode

#### GUI Application
```bash
python -m secure_credentials.src.run_app debug
```

#### Web Application
```python
# In code
app.run(debug=True)

# Or via environment
export FLASK_ENV=development
```

### Profiling

#### Memory Profiling
```python
from memory_profiler import profile

@profile
def memory_intensive_function():
    # Code to profile
    pass
```

#### Performance Profiling
```python
import cProfile

cProfile.run('main_function()', 'profile_output.prof')

# Analyze results
import pstats
p = pstats.Stats('profile_output.prof')
p.sort_stats('cumulative').print_stats(10)
```

## Environment Configuration

### Environment Variables

```bash
# Database configuration
export SECURE_CREDENTIALS_DB=/path/to/database.kdbx

# Web server configuration
export HOST=0.0.0.0
export PORT=5000
export FLASK_ENV=development
export SECRET_KEY=your-secret-key

# Logging
export LOG_LEVEL=DEBUG
export LOG_FILE=/var/log/secure_credentials.log

# Security
export SSL_CERT=/path/to/cert.pem
export SSL_KEY=/path/to/key.pem
```

### Configuration Files

#### config.py
```python
import os

class Config:
    # Database
    DATABASE_PATH = os.getenv('SECURE_CREDENTIALS_DB', '~/.secure_credentials/vault.kdbx')

    # Web server
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5000))
    DEBUG = os.getenv('FLASK_ENV') == 'development'

    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SSL_CERT = os.getenv('SSL_CERT')
    SSL_KEY = os.getenv('SSL_KEY')

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE')

    # Application
    AUTO_LOCK_TIMEOUT = int(os.getenv('AUTO_LOCK_TIMEOUT', 300))
    CLIPBOARD_CLEAR_TIME = int(os.getenv('CLIPBOARD_CLEAR_TIME', 30))
```

## Security Considerations

### Development Security

#### Never Commit Secrets
```bash
# .gitignore should include
.env
*.key
*.pem
secrets.json
config/local_config.py
```

#### Use Environment Variables
```python
# Good
api_key = os.getenv('API_KEY')

# Bad - hardcoded
api_key = "sk-1234567890abcdef"
```

#### Secure Development Practices
- Use HTTPS in development when possible
- Implement proper input validation
- Use parameterized queries
- Sanitize user inputs
- Implement proper error handling

### Code Review Checklist

- [ ] No hardcoded secrets or credentials
- [ ] Input validation on all user inputs
- [ ] Proper error handling and logging
- [ ] SQL injection prevention
- [ ] XSS prevention in templates
- [ ] CSRF protection on forms
- [ ] Secure session handling
- [ ] Proper permission checks
- [ ] Tests cover new functionality
- [ ] Documentation updated

## Release Process

### Version Management

1. **Update version in `pyproject.toml`:**
   ```toml
   [project]
   version = "1.1.0"
   ```

2. **Update CHANGELOG.md:**
   ```
   ## [1.1.0] - 2024-01-15

   ### Added
   - New feature description

   ### Fixed
   - Bug fix description

   ### Changed
   - Breaking change description
   ```

3. **Create git tag:**
   ```bash
   git tag -a v1.1.0 -m "Release version 1.1.0"
   git push origin v1.1.0
   ```

### Building Releases

#### Automated Release
```bash
# Run full build pipeline
./build_release.sh

# Or manually
python -m build
pyinstaller secure_credentials.spec
```

#### Release Checklist
- [ ] Version updated in pyproject.toml
- [ ] CHANGELOG.md updated
- [ ] All tests pass
- [ ] Code linted and formatted
- [ ] Documentation updated
- [ ] Executables tested on target platforms
- [ ] Release notes written
- [ ] Git tag created and pushed

### Distribution

#### PyPI Release
```bash
# Build distributions
python -m build

# Upload to test PyPI first
twine upload --repository testpypi dist/*

# Upload to production PyPI
twine upload dist/*
```

#### GitHub Release
1. Go to GitHub releases
2. Create new release
3. Upload executables and distributions
4. Write release notes

## Troubleshooting Development Issues

### Import Errors
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Install in development mode
pip install -e .

# Check for circular imports
python -c "import secure_credentials.src.run_app"
```

### Template Issues
```bash
# Check template paths
export FLASK_ENV=development

# Enable template debugging
app.jinja_env.undefined = jinja2.StrictUndefined
```

### Database Issues
```bash
# Check database file permissions
ls -la ~/.secure_credentials/

# Test database operations manually
python -c "from secure_credentials.src.keepass_backend import KeePassHandler; h = KeePassHandler(); print('DB loaded')"
```

### Performance Issues
```bash
# Profile application startup
python -m cProfile -o profile.prof secure_credentials/src/run_app.py

# Analyze profile
import pstats
p = pstats.Stats('profile.prof')
p.sort_stats('cumulative').print_stats(20)
```

### Getting Help

1. **Check existing issues** on GitHub
2. **Review documentation** in this guide
3. **Ask in discussions** for general questions
4. **Create detailed bug reports** with:
   - Python version and OS
   - Full error traceback
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant code snippets
