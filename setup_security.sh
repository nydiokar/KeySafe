#!/bin/bash

# Secure Credential Manager - Security Setup Script
# This script helps configure basic network security for the web interface

echo "🔒 Secure Credential Manager - Security Setup"
echo "============================================"
echo

# Check if running as root for firewall setup
if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "ubuntu"
        elif command -v dnf >/dev/null 2>&1; then
            echo "fedora"
        elif command -v pacman >/dev/null 2>&1; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)

# Setup firewall rules
setup_firewall() {
    echo "🔥 Setting up firewall rules..."

    case $OS in
        "ubuntu")
            echo "Detected Ubuntu/Debian"
            $SUDO ufw --version >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo "Configuring UFW firewall..."
                $SUDO ufw allow ssh
                $SUDO ufw --force enable
                echo "✅ UFW firewall configured"
            else
                echo "⚠️  UFW not installed. Install with: sudo apt install ufw"
            fi
            ;;
        "fedora")
            echo "Detected Fedora/RHEL"
            $SUDO firewall-cmd --version >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo "Configuring firewalld..."
                $SUDO firewall-cmd --permanent --add-service=ssh
                $SUDO firewall-cmd --reload
                echo "✅ Firewalld configured"
            else
                echo "⚠️  firewalld not installed. Install with: sudo dnf install firewalld"
            fi
            ;;
        "arch")
            echo "Detected Arch Linux"
            $SUDO ufw --version >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo "Configuring UFW firewall..."
                $SUDO ufw allow ssh
                $SUDO ufw --force enable
                echo "✅ UFW firewall configured"
            else
                echo "⚠️  UFW not installed. Install with: sudo pacman -S ufw"
            fi
            ;;
        *)
            echo "⚠️  Automatic firewall setup not supported for this OS"
            echo "   Please manually configure your firewall to only allow SSH access"
            ;;
    esac
}

# Generate self-signed SSL certificate
generate_ssl_cert() {
    echo "🔐 Generating self-signed SSL certificate..."

    if ! command -v openssl >/dev/null 2>&1; then
        echo "❌ OpenSSL not found. Please install OpenSSL first."
        return 1
    fi

    CERT_DIR="ssl"
    mkdir -p "$CERT_DIR"

    # Generate private key
    openssl genrsa -out "$CERT_DIR/server.key" 2048

    # Generate certificate signing request
    cat > "$CERT_DIR/cert.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
OU = Unit
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

    # Generate self-signed certificate
    openssl req -new -x509 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365 -config "$CERT_DIR/cert.conf"

    # Clean up config file
    rm "$CERT_DIR/cert.conf"

    echo "✅ SSL certificate generated in ssl/ directory"
    echo "   Certificate: ssl/server.crt"
    echo "   Private key: ssl/server.key"
}

# Create systemd service file
create_service() {
    echo "⚙️  Creating systemd service file..."

    if [[ "$OS" != "ubuntu" && "$OS" != "fedora" && "$OS" != "arch" ]]; then
        echo "⚠️  Systemd service creation not supported for this OS"
        return 1
    fi

    SERVICE_FILE="/etc/systemd/system/secure-credentials.service"

    cat > /tmp/secure-credentials.service << EOF
[Unit]
Description=Secure Credential Manager Web Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(which python3) -m secure_credentials.src.web_app
Restart=always
RestartSec=5
Environment=FLASK_ENV=production

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$(pwd)
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

    $SUDO mv /tmp/secure-credentials.service "$SERVICE_FILE"
    $SUDO systemctl daemon-reload

    echo "✅ Systemd service created: $SERVICE_FILE"
    echo "   Start service: sudo systemctl start secure-credentials"
    echo "   Enable on boot: sudo systemctl enable secure-credentials"
    echo "   Check status: sudo systemctl status secure-credentials"
}

# Generate secure configuration
generate_config() {
    echo "🔧 Generating secure configuration..."

    # Generate a random secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    cat > .env << EOF
# Secure Credential Manager Configuration
# Copy this file and customize as needed

# Flask Configuration
FLASK_ENV=production
SECRET_KEY=$SECRET_KEY

# Server Configuration
HOST=127.0.0.1
FLASK_PORT=5000

# Security (uncomment and configure for HTTPS)
# SSL_CERT=ssl/server.crt
# SSL_KEY=ssl/server.key

# Database Configuration (if using external database)
# DATABASE_URL=

# Logging
# LOG_LEVEL=INFO
# LOG_FILE=logs/web_app.log
EOF

    echo "✅ Configuration file created: .env"
    echo "   Edit this file to customize your setup"
}

# Main menu
show_menu() {
    echo "Select security setup options:"
    echo "1) Setup firewall (recommended)"
    echo "2) Generate SSL certificate for HTTPS"
    echo "3) Create systemd service"
    echo "4) Generate secure configuration"
    echo "5) Run all security setup (recommended)"
    echo "6) Exit"
    echo
    read -p "Enter your choice (1-6): " choice
}

# Main logic
case "${1:-}" in
    "firewall")
        setup_firewall
        ;;
    "ssl")
        generate_ssl_cert
        ;;
    "service")
        create_service
        ;;
    "config")
        generate_config
        ;;
    "all")
        echo "Running complete security setup..."
        setup_firewall
        generate_ssl_cert
        create_service
        generate_config
        echo
        echo "🎉 Security setup complete!"
        echo
        echo "Next steps:"
        echo "1. Edit .env file with your configuration"
        echo "2. Test the service: sudo systemctl start secure-credentials"
        echo "3. Enable on boot: sudo systemctl enable secure-credentials"
        echo "4. Access at: https://localhost:5000 (if SSL enabled)"
        ;;
    *)
        echo "Interactive security setup:"
        echo
        while true; do
            show_menu
            case $choice in
                1) setup_firewall ;;
                2) generate_ssl_cert ;;
                3) create_service ;;
                4) generate_config ;;
                5)
                    echo "Running complete security setup..."
                    setup_firewall
                    generate_ssl_cert
                    create_service
                    generate_config
                    echo
                    echo "🎉 Security setup complete!"
                    break
                    ;;
                6) break ;;
                *) echo "Invalid option. Please choose 1-6." ;;
            esac
            echo
        done
        ;;
esac
