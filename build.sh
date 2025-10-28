#!/bin/bash

echo "Building Secure Credential Manager for Linux..."
echo

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "Using existing virtual environment: $VIRTUAL_ENV"
else
    echo "Creating new virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "Virtual environment created and activated"
fi

# Install/update dependencies
echo "Installing dependencies..."
python -m pip install --upgrade pip
pip install -e ".[dev]"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -f *.spec

# Create assets directory if it doesn't exist
if [ ! -d "secure_credentials/assets" ]; then
    mkdir -p secure_credentials/assets
fi

# Build the executable
echo "Building executable..."
pyinstaller secure_credentials.spec

echo
if [ -f "dist/SecureCredentialManager" ]; then
    echo "Build successful! Executable is in dist/SecureCredentialManager"
    echo "You can run it with: ./dist/SecureCredentialManager"
else
    echo "Build failed! Check the error messages above."
    exit 1
fi

echo
echo "Build completed."
