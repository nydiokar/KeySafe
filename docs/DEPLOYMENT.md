# Deployment Guide

## Overview

This guide covers deploying the Secure Credential Manager in various environments, from personal use to enterprise production deployments.

## Deployment Options

| Deployment Type | Use Case | Setup Complexity | Security Level | Performance |
|-----------------|----------|------------------|----------------|-------------|
| **Local Desktop** | Personal use | ⭐ Low | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Local Web** | Browser access | ⭐⭐ Medium | ⭐⭐⭐⭐ High | ⭐⭐⭐ Good |
| **Network Web** | Shared access | ⭐⭐⭐ Medium | ⭐⭐⭐ Medium | ⭐⭐ Good |
| **Network + SSL** | Secure sharing | ⭐⭐⭐⭐ High | ⭐⭐⭐⭐⭐ Very High | ⭐⭐ Good |
| **Production** | Enterprise | ⭐⭐⭐⭐⭐ Very High | ⭐⭐⭐⭐⭐ Production | ⭐⭐⭐⭐⭐ Excellent |

## Local Desktop Deployment

### Windows
```bash
# Use pre-built executable
# Download and run SecureCredentialManager-Setup.exe

# Or build from source
git clone <repository>
cd secure_credentials
pip install -e .
secure-credentials
```

### Linux
```bash
# Use pre-built executable
chmod +x SecureCredentialManager
./SecureCredentialManager

# Or build from source
git clone <repository>
cd secure_credentials
pip install -e .
secure-credentials
```

## Web Server Deployment

### Local Web Access

#### Basic Setup
```bash
# Install and run
pip install -e .
secure-credentials-web

# Access at: http://localhost:5000/app
```

#### Custom Configuration
```bash
# Set custom port
export PORT=8080
secure-credentials-web

# Enable debug mode
export FLASK_ENV=development
secure-credentials-web
```

### Network Deployment

#### Basic Network Access
```bash
# Allow external connections
export HOST=0.0.0.0
secure-credentials-web

# Access from other devices: http://YOUR_SERVER_IP:5000/app
```

#### Secure Network Setup

1. **Firewall Configuration:**
   ```bash
   # UFW (Ubuntu/Debian)
   sudo ufw allow from 192.168.1.0/24 to any port 5000
   sudo ufw --force enable

   # iptables
   sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 5000 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 5000 -j DROP
   ```

2. **SSL/TLS Setup:**
   ```bash
   # Generate self-signed certificate
   sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/private/secure_credentials.key \
     -out /etc/ssl/certs/secure_credentials.crt -days 365 -nodes

   # Set proper permissions
   sudo chmod 600 /etc/ssl/private/secure_credentials.key
   sudo chmod 644 /etc/ssl/certs/secure_credentials.crt
   ```

3. **Run with SSL:**
   ```bash
   export SSL_CERT=/etc/ssl/certs/secure_credentials.crt
   export SSL_KEY=/etc/ssl/private/secure_credentials.key
   python -m secure_credentials.src.web_app
   ```

### Systemd Service (Auto-start)

#### Create Service
```bash
sudo tee /etc/systemd/system/secure-credentials.service > /dev/null <<EOF
[Unit]
Description=Secure Credential Manager Web Service
After=network.target

[Service]
Type=simple
User=secureuser
WorkingDirectory=/home/secureuser/secure_credentials
ExecStart=/home/secureuser/secure_credentials/venv/bin/python -m secure_credentials.src.web_app
Restart=always
Environment=HOST=0.0.0.0
Environment=PORT=5000

[Install]
WantedBy=multi-user.target
EOF
```

#### Manage Service
```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable secure-credentials
sudo systemctl start secure-credentials

# Check status
sudo systemctl status secure-credentials

# View logs
sudo journalctl -u secure-credentials -f
```

## Production Deployment

### Development vs Production Server

#### ⚠️ Development Server Warning

When you run the web server, you'll see:
```
WARNING: This is a development server. Do not use it in a production deployment.
Use a production WSGI server instead.
```

**Why this matters:**
- Flask's development server is single-threaded
- Cannot handle multiple concurrent users
- Lacks security hardening
- Not designed for production traffic

**Never use the development server for production!**

### Production Setup with Gunicorn

#### Basic Gunicorn Setup
```bash
# Install Gunicorn
pip install gunicorn

# Run with multiple workers
gunicorn -w 4 -b 0.0.0.0:8000 "secure_credentials.src.web_app:app"
```

#### Advanced Configuration
```bash
# Create gunicorn.conf.py
bind = "0.0.0.0:8000"
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
user = "secureuser"
group = "secureuser"
tmp_upload_dir = "/tmp"
```

### Nginx Reverse Proxy

#### Install and Configure
```bash
# Install nginx
sudo apt install nginx

# Create site configuration
sudo tee /etc/nginx/sites-available/secure-credentials > /dev/null <<EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/secure-credentials /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL with Let's Encrypt

#### Certbot Setup
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com

# Automatic renewal
sudo certbot renew --dry-run
```

### Complete Production Stack

```
Internet → Nginx (SSL) → Gunicorn → Flask App → KeePass DB
```

#### Full Setup Script
```bash
#!/bin/bash
# Production deployment script

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y nginx certbot python3-certbot-nginx postgresql redis-server

# Create user
sudo useradd -m -s /bin/bash secureuser

# Setup application
sudo -u secureuser bash << EOF
cd /home/secureuser
git clone <repository> secure_credentials
cd secure_credentials
python -m venv venv
source venv/bin/activate
pip install -e .
pip install gunicorn psycopg2-binary redis
EOF

# Configure nginx
sudo tee /etc/nginx/sites-available/secure-credentials << EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/secure-credentials /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Create systemd service
sudo tee /etc/systemd/system/secure-credentials.service << EOF
[Unit]
Description=Secure Credential Manager
After=network.target postgresql.service redis-server.service

[Service]
Type=exec
User=secureuser
WorkingDirectory=/home/secureuser/secure_credentials
ExecStart=/home/secureuser/secure_credentials/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 "secure_credentials.src.web_app:app"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start services
sudo systemctl daemon-reload
sudo systemctl enable secure-credentials nginx
sudo systemctl start secure-credentials nginx
```

## Docker Deployment

### Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

EXPOSE 5000

CMD ["python", "-m", "secure_credentials.src.web_app"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - HOST=0.0.0.0
      - PORT=5000
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - app
    restart: unless-stopped
```

## Cloud Deployment

### Heroku
```yaml
# requirements.txt
Flask==2.3.0
flask-login==0.6.0
pykeepass==4.0.3
# ... other dependencies

# Procfile
web: gunicorn secure_credentials.src.web_app:app
```

### AWS EC2
```bash
# Launch EC2 instance
# Ubuntu Server recommended

# Security group: Allow SSH (22), HTTP (80), HTTPS (443)

# User data script for automatic setup
#!/bin/bash
apt update
apt install -y nginx certbot python3-pip
# ... rest of setup
```

### DigitalOcean App Platform
```yaml
# .do/app.yaml
name: secure-credentials
services:
- name: web
  source_dir: /
  github:
    repo: yourusername/secure_credentials
    branch: main
  run_command: gunicorn secure_credentials.src.web_app:app
  environment_slug: python
  instance_count: 1
  instance_size_slug: basic-xxs
  health_check:
    http_path: /app
```

## Monitoring and Maintenance

### Health Checks
```bash
# Application health check
curl http://localhost:5000/app

# Gunicorn status
ps aux | grep gunicorn

# Nginx status
sudo systemctl status nginx
```

### Log Management
```bash
# Application logs
tail -f /var/log/secure-credentials.log

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# System logs
sudo journalctl -u secure-credentials -f
```

### Backup Strategy
```bash
#!/bin/bash
# Daily backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/secure_credentials"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
cp /home/secureuser/.secure_credentials/vault.kdbx $BACKUP_DIR/vault_$DATE.kdbx

# Backup configuration
cp /etc/systemd/system/secure-credentials.service $BACKUP_DIR/

# Compress and cleanup old backups
find $BACKUP_DIR -name "*.kdbx" -mtime +30 -delete
```

### Performance Tuning

#### Gunicorn Optimization
```python
# gunicorn.conf.py
import multiprocessing

bind = "127.0.0.1:8000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 10
```

#### Database Optimization
```bash
# For PostgreSQL (if using external DB)
# Adjust connection pooling
# Enable query optimization
```

## Security Checklist

### Pre-deployment
- [ ] Change default SSH keys
- [ ] Update all packages
- [ ] Configure firewall
- [ ] Disable root login
- [ ] Setup SSL/TLS certificates
- [ ] Configure backups

### Production Checks
- [ ] HTTPS enabled
- [ ] Security headers configured
- [ ] Database encrypted
- [ ] Regular backups tested
- [ ] Monitoring alerts configured
- [ ] Log rotation enabled

### Maintenance
- [ ] Security updates applied monthly
- [ ] Certificate renewal automated
- [ ] Backups verified weekly
- [ ] Performance monitoring active
- [ ] Incident response plan documented

## Troubleshooting

### Common Deployment Issues

#### Port Already in Use
```bash
# Find process using port
sudo lsof -i :5000

# Kill process
sudo kill -9 <PID>
```

#### Permission Denied
```bash
# Fix database permissions
sudo chown -R secureuser:secureuser /home/secureuser/.secure_credentials

# Fix SSL certificate permissions
sudo chmod 600 /etc/ssl/private/*.key
```

#### Service Won't Start
```bash
# Check service status
sudo systemctl status secure-credentials

# View detailed logs
sudo journalctl -u secure-credentials -n 50

# Test manual execution
sudo -u secureuser bash -c "cd /home/secureuser/secure_credentials && source venv/bin/activate && python -m secure_credentials.src.web_app"
```

#### SSL Certificate Issues
```bash
# Test certificate
openssl s_client -connect localhost:443 -servername yourdomain.com

# Check certificate validity
openssl x509 -in /etc/ssl/certs/secure_credentials.crt -text -noout
```

### Performance Issues

#### High CPU Usage
- Reduce Gunicorn workers
- Enable connection pooling
- Optimize database queries

#### High Memory Usage
- Monitor for memory leaks
- Restart services periodically
- Use smaller worker pools

#### Slow Response Times
- Check network latency
- Optimize database queries
- Enable caching where appropriate
- Scale horizontally if needed

### Getting Help

1. Check application logs first
2. Review [Security Guide](SECURITY.md) for security issues
3. Test with minimal configuration
4. Check GitHub issues for similar problems
5. Create detailed issue with:
   - Deployment method
   - System specifications
   - Configuration files
   - Error logs
   - Steps to reproduce
