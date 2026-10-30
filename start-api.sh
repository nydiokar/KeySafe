#!/bin/bash
# Password Manager API startup (Linux/Mac). Configuration: environment or .env (see docs/FASTAPI_ROADMAP.md).
set -e
cd "$(dirname "$0")"

if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi

exec python -m secure_credentials.src.api.server
