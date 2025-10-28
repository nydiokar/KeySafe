# Security Guide

## Overview

The Secure Credential Manager implements multiple layers of security to protect your sensitive data. This guide explains the security features and best practices.

## Security Architecture

### Core Security Principles

1. **Defense in Depth**: Multiple security layers protect credentials
2. **Least Privilege**: Minimal permissions required for operations
3. **Fail-Safe Defaults**: Secure defaults that require explicit opt-in for less secure options
4. **Audit Trail**: Comprehensive logging of security events

### Data Protection Layers

```
User Input → Input Validation → Encryption → Access Control → Audit Logging
```

## Encryption and Storage

### KeePass Database

- **AES-256 encryption** for all stored data
- **PBKDF2 key derivation** with configurable rounds
- **Master password protection** with no recovery mechanism
- **Individual credential passwords** for additional protection

### Database Security

```python
# Key derivation parameters (configurable)
PBKDF2_ROUNDS = 1000000  # High iteration count
AES_KEY_SIZE = 256       # AES-256 encryption
CIPHER_MODE = "CBC"      # Cipher block chaining
```

### File System Security

#### Database Location
- Default: `~/.secure_credentials/vault.kdbx`
- Custom location via environment variable
- File permissions: `600` (owner read/write only)

#### Permission Setup
```bash
# Secure database directory
mkdir -p ~/.secure_credentials
chmod 700 ~/.secure_credentials

# Secure database file
touch ~/.secure_credentials/vault.kdbx
chmod 600 ~/.secure_credentials/vault.kdbx
```

## Authentication and Authorization

### Master Password

#### Requirements
- Minimum 12 characters (recommended)
- No maximum length limit
- **No password recovery** - lost password = lost data
- **No password hints** stored

#### Best Practices
```python
# Strong password requirements
MIN_PASSWORD_LENGTH = 12
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True
```

### Individual Credential Passwords

#### Purpose
- Additional protection layer beyond master password
- Each credential can have its own access password
- Protects against master password compromise

#### Implementation
```python
# Per-credential encryption
credential_key = PBKDF2(master_password + credential_password)
encrypted_data = AES256(credential_key, credential_data)
```

### Session Management

#### Web Interface Sessions
```python
# Flask session configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # Prevent XSS
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800, # 30 minutes
)
```

#### Session Security
- **Secure cookies** (HTTPS only in production)
- **HttpOnly cookies** (prevent XSS access)
- **SameSite protection** (CSRF mitigation)
- **Session timeout** (automatic logout)

## Network Security

### Web Server Security

#### Development Server Warnings
```
WARNING: This is a development server. Do not use it in a production deployment.
Use a production WSGI server instead.
```

**Why development servers are insecure:**
- Single-threaded (one request at a time)
- No request size limits
- No timeout controls
- Debug information leakage
- No security headers

#### Production Deployment Security

##### HTTPS Configuration
```nginx
# Nginx SSL configuration
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates
    ssl_certificate /etc/ssl/certs/secure_credentials.crt;
    ssl_certificate_key /etc/ssl/private/secure_credentials.key;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

##### Gunicorn Security
```python
# gunicorn.conf.py
bind = "127.0.0.1:8000"  # Internal only
workers = 4
worker_class = "sync"
timeout = 30
keepalive = 10
max_requests = 1000
max_requests_jitter = 50
user = "secureuser"
group = "secureuser"
```

### Firewall Configuration

#### Local Network Access
```bash
# Allow specific subnet only
sudo ufw allow from 192.168.1.0/24 to any port 5000 proto tcp

# Deny all other access to port 5000
sudo ufw deny 5000

# Enable firewall
sudo ufw --force enable
```

#### iptables Alternative
```bash
# Allow local network
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 5000 -j ACCEPT

# Drop everything else on port 5000
iptables -A INPUT -p tcp --dport 5000 -j DROP
```

## Application Security

### Input Validation

#### Client-Side Validation
```javascript
// Form validation
function validateCredentialForm() {
    const name = document.getElementById('name').value;
    const password = document.getElementById('password').value;

    if (name.length < 1 || name.length > 100) {
        showError('Name must be 1-100 characters');
        return false;
    }

    if (password.length < 8) {
        showError('Password must be at least 8 characters');
        return false;
    }

    return true;
}
```

#### Server-Side Validation
```python
def validate_credential_data(data):
    """Validate credential input data."""
    required_fields = ['name', 'password']
    max_lengths = {
        'name': 100,
        'username': 100,
        'url': 500,
        'notes': 1000
    }

    # Check required fields
    for field in required_fields:
        if not data.get(field):
            raise ValueError(f"{field} is required")

    # Check field lengths
    for field, max_length in max_lengths.items():
        value = data.get(field, '')
        if len(value) > max_length:
            raise ValueError(f"{field} exceeds maximum length of {max_length}")

    # Sanitize inputs
    for field in data:
        if isinstance(data[field], str):
            data[field] = data[field].strip()

    return data
```

### SQL Injection Protection

#### Parameterized Queries
```python
# Safe KeePass operations
def get_credential(self, name: str) -> dict:
    """Safely retrieve credential by name."""
    # KeePass library handles SQL injection prevention
    try:
        entry = self.kp.find_entries(title=name, first=True)
        return self._entry_to_dict(entry) if entry else None
    except Exception as e:
        logger.error(f"Error retrieving credential {name}: {e}")
        raise
```

### XSS Protection

#### Template Escaping
```html
<!-- Jinja2 auto-escapes by default -->
<h1>{{ user_input }}</h1>

<!-- Explicit escaping if needed -->
<p>{{ user_input | e }}</p>
```

#### Content Security Policy
```python
# Flask CSP headers
@app.after_request
def add_csp_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    return response
```

### CSRF Protection

#### Flask-WTF CSRF
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# Automatic CSRF protection on all forms
# Tokens automatically included in templates
```

#### Manual CSRF Protection
```python
def generate_csrf_token():
    """Generate CSRF token for forms."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token."""
    session_token = session.get('csrf_token')
    if not session_token or not secrets.compare_digest(token, session_token):
        raise ValueError("Invalid CSRF token")
```

## Operational Security

### Logging and Monitoring

#### Security Event Logging
```python
import logging

# Security logger
security_logger = logging.getLogger('security')

def log_security_event(event_type, user, details):
    """Log security-related events."""
    security_logger.info(
        f"SECURITY_EVENT: {event_type} | "
        f"USER: {user} | "
        f"DETAILS: {details} | "
        f"IP: {request.remote_addr} | "
        f"USER_AGENT: {request.headers.get('User-Agent')}"
    )

# Log authentication events
@login_manager.user_logged_in.connect
def log_login(sender, user):
    log_security_event('LOGIN_SUCCESS', user.get_id(), 'User logged in')

@login_manager.user_logged_out.connect
def log_logout(sender, user):
    log_security_event('LOGOUT', user.get_id(), 'User logged out')
```

#### Audit Trail
```python
def audit_credential_access(credential_name, action):
    """Audit credential access events."""
    log_security_event(
        'CREDENTIAL_ACCESS',
        current_user.get_id(),
        f"ACTION: {action} | CREDENTIAL: {credential_name}"
    )

# Track credential operations
def add_credential(name, data):
    # ... add logic ...
    audit_credential_access(name, 'CREATE')

def view_credential(name):
    # ... view logic ...
    audit_credential_access(name, 'VIEW')

def update_credential(name, data):
    # ... update logic ...
    audit_credential_access(name, 'UPDATE')

def delete_credential(name):
    # ... delete logic ...
    audit_credential_access(name, 'DELETE')
```

### Backup Security

#### Encrypted Backups
```python
def create_secure_backup(backup_path):
    """Create encrypted backup of database."""
    import shutil
    from cryptography.fernet import Fernet

    # Generate encryption key for backup
    backup_key = Fernet.generate_key()
    cipher = Fernet(backup_key)

    # Encrypt database file
    with open(self.db_path, 'rb') as f:
        data = f.read()

    encrypted_data = cipher.encrypt(data)

    # Save encrypted backup
    with open(backup_path, 'wb') as f:
        f.write(encrypted_data)

    # Save decryption key separately (user must secure this)
    key_path = backup_path + '.key'
    with open(key_path, 'wb') as f:
        f.write(backup_key)

    return backup_path, key_path
```

#### Backup Verification
```bash
#!/bin/bash
# Backup verification script

BACKUP_FILE="$1"
KEY_FILE="$1.key"

# Verify backup integrity
if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: Key file not found"
    exit 1
fi

# Test decryption
python3 -c "
import sys
from cryptography.fernet import Fernet

try:
    with open('$KEY_FILE', 'rb') as f:
        key = f.read()
    with open('$BACKUP_FILE', 'rb') as f:
        encrypted_data = f.read()

    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)

    print('SUCCESS: Backup integrity verified')
except Exception as e:
    print(f'ERROR: Backup verification failed: {e}')
    sys.exit(1)
"
```

## Security Best Practices

### Development Security

#### Code Review Checklist
- [ ] No hardcoded secrets or API keys
- [ ] Input validation on all user inputs
- [ ] Proper error handling (no sensitive data in errors)
- [ ] SQL injection prevention
- [ ] XSS prevention in templates
- [ ] CSRF protection on forms
- [ ] Secure session handling
- [ ] Proper permission checks
- [ ] Security headers implemented
- [ ] Dependencies scanned for vulnerabilities

#### Dependency Security
```bash
# Check for vulnerable dependencies
pip install safety
safety check

# Update dependencies securely
pip install --upgrade --upgrade-strategy eager -r requirements.txt

# Use specific versions in production
Flask==2.3.0  # Exact version pinning
```

### Production Security

#### Server Hardening
```bash
# Disable root login
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Use key-based authentication only
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart sshd
```

#### Regular Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python packages
pip install --upgrade pip
pip install --upgrade -e .

# Restart services
sudo systemctl restart secure-credentials
```

### Incident Response

#### Breach Detection
```bash
# Monitor for suspicious activity
tail -f /var/log/secure_credentials.log | grep -i "failed\|error\|security"

# Check for unauthorized access
sudo last | grep -v "system boot\|runlevel\|still logged in"
```

#### Incident Response Plan
1. **Isolate**: Disconnect affected systems from network
2. **Assess**: Determine scope and impact of breach
3. **Contain**: Change all passwords and revoke access
4. **Recover**: Restore from clean backups
5. **Learn**: Update security measures based on lessons learned

#### Emergency Contacts
- Keep emergency contact information separate from the application
- Have backup communication methods
- Document incident response procedures

## Compliance Considerations

### Data Protection Regulations

#### GDPR Compliance (Europe)
- **Data minimization**: Only collect necessary data
- **Purpose limitation**: Clear purpose for data collection
- **Storage limitation**: Delete data when no longer needed
- **Integrity and confidentiality**: Strong encryption and access controls
- **Accountability**: Document all security measures

#### CCPA Compliance (California)
- **Right to know**: Users can request what data is stored
- **Right to delete**: Users can request data deletion
- **Right to opt-out**: No selling of personal data (not applicable)
- **Security safeguards**: Implement appropriate security measures

### Security Standards

#### OWASP Top 10 Mitigation
- **Injection**: Parameterized queries, input validation
- **Broken Authentication**: Strong passwords, session management
- **Sensitive Data Exposure**: Encryption, HTTPS
- **XML External Entities**: Not applicable (no XML processing)
- **Broken Access Control**: Proper authorization checks
- **Security Misconfiguration**: Secure defaults, configuration management
- **Cross-Site Scripting**: Template escaping, CSP headers
- **Insecure Deserialization**: Not applicable (no object deserialization)
- **Vulnerable Components**: Dependency scanning, regular updates
- **Insufficient Logging**: Comprehensive security logging

## Security Testing

### Automated Security Testing

#### Dependency Scanning
```bash
# Check for vulnerabilities
pip install safety
safety check

# Alternative: pip-audit
pip install pip-audit
pip-audit
```

#### Code Security Analysis
```bash
# Bandit - Python security linter
pip install bandit
bandit -r secure_credentials/

# Find secrets in code
pip install detect-secrets
detect-secrets scan secure_credentials/
```

### Manual Security Testing

#### Penetration Testing Checklist
- [ ] SQL injection attempts
- [ ] XSS payload testing
- [ ] CSRF token validation
- [ ] Session cookie security
- [ ] Password brute force protection
- [ ] File upload restrictions
- [ ] Directory traversal attempts
- [ ] HTTP method testing
- [ ] Header injection testing

#### Authentication Testing
```bash
# Test password policies
# Test session timeout
# Test concurrent session limits
# Test password reset functionality
# Test account lockout mechanisms
```

### Security Monitoring

#### Log Analysis
```bash
# Monitor for security events
tail -f /var/log/secure_credentials.log | grep -E "(SECURITY_EVENT|FAILED_LOGIN|ACCESS_DENIED)"

# Alert on suspicious patterns
# Implement log aggregation and alerting
# Regular log review and analysis
```

#### Intrusion Detection
```bash
# Install fail2ban for SSH protection
sudo apt install fail2ban

# Configure fail2ban for application
sudo tee /etc/fail2ban/jail.d/secure-credentials.conf << EOF
[secure-credentials]
enabled = true
port = 5000
filter = secure-credentials
logpath = /var/log/secure_credentials.log
maxretry = 3
bantime = 3600
EOF
```

## Security Resources

### Documentation and Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO 27001 Information Security](https://www.iso.org/standard/54534.html)

### Tools and Services
- [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - Web app security scanner
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanner
- [SQLMap](https://sqlmap.org/) - SQL injection testing
- [Nikto](https://cirt.net/Nikto2) - Web server scanner

### Security Mailing Lists and Communities
- [OWASP Mailing Lists](https://owasp.org/mailing-list/)
- [NIST Security Announcements](https://www.nist.gov/itl/applied-cybersecurity/nice/resources/nice-cybersecurity-workforce-framework)
- [CERT Coordination Center](https://www.sei.cmu.edu/about/divisions/cert/)

## Reporting Security Issues

### Responsible Disclosure

If you discover a security vulnerability, please:

1. **Do not publicly disclose** the vulnerability
2. **Email security details** to: nydiokar@gmail.com
3. **Provide sufficient information** to reproduce the issue
4. **Allow reasonable time** for the issue to be fixed
5. **Do not access or modify** other users' data

### Security Issue Template

When reporting security issues, include:

```
**Summary:** Brief description of the vulnerability
**Severity:** Critical/High/Medium/Low
**Affected Versions:** Version numbers affected
**Steps to Reproduce:**
1. Step 1
2. Step 2
3. Step 3
**Expected Behavior:** What should happen
**Actual Behavior:** What actually happens
**Impact:** Potential consequences
**Mitigation:** Suggested fix (optional)
```

### Security Updates

Security updates will be:
- Released as soon as possible
- Documented in release notes
- Communicated through security advisories
- Applied to all supported versions

## Conclusion

Security is an ongoing process, not a destination. Regular updates, monitoring, and adherence to best practices are essential for maintaining the security of your credential data.

**Remember: The security of your data ultimately depends on your master password and operational security practices.**
