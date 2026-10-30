@echo off
REM Password Manager API startup (Windows). Configuration: environment or .env (see docs\FASTAPI_ROADMAP.md).
cd /d "%~dp0"

if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat

python -m secure_credentials.src.api.server
if errorlevel 1 pause
