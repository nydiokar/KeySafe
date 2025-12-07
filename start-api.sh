#!/bin/bash
# Password Manager API Startup Script for Linux/Mac

echo "========================================"
echo "Password Manager API Startup"
echo "========================================"
echo

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ ERROR: .env file not found!"
    echo
    echo "Please create .env file from .env.example:"
    echo "  1. Copy .env.example to .env"
    echo "  2. Fill in your YGGDRASIL_IP and MASTER_PASSWORD"
    echo
    exit 1
fi

# Load environment variables
set -a
source .env
set +a

# Check if required variables are set
if [ -z "$YGGDRASIL_IP" ]; then
    echo "❌ ERROR: YGGDRASIL_IP not set in .env file"
    exit 1
fi

if [ -z "$MASTER_PASSWORD" ]; then
    echo "❌ ERROR: MASTER_PASSWORD not set in .env file"
    exit 1
fi

# Activate virtual environment if it exists
if [ -f .venv/bin/activate ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
else
    echo "⚠️  Warning: Virtual environment not found at .venv/"
    echo "Using system Python..."
fi

# Check if FastAPI is installed
if ! python -c "import fastapi" 2>/dev/null; then
    echo "❌ ERROR: FastAPI not installed!"
    echo
    echo "Please install required dependencies:"
    echo "  pip install fastapi uvicorn[standard]"
    echo
    exit 1
fi

# Start the server
echo "Starting API server..."
echo
python secure_credentials/src/api/server.py
