@echo off
REM Password Manager API Startup Script for Windows

echo ========================================
echo Password Manager API Startup
echo ========================================
echo.

REM Check if .env exists
if not exist .env (
    echo ERROR: .env file not found!
    echo.
    echo Please create .env file from .env.example:
    echo   1. Copy .env.example to .env
    echo   2. Fill in your YGGDRASIL_IP and MASTER_PASSWORD
    echo.
    pause
    exit /b 1
)

REM Load environment variables from .env
for /f "tokens=1,2 delims==" %%a in (.env) do (
    if not "%%a"=="" if not "%%a:~0,1%"=="#" (
        set %%a=%%b
    )
)

REM Check if required variables are set
if "%YGGDRASIL_IP%"=="" (
    echo ERROR: YGGDRASIL_IP not set in .env file
    pause
    exit /b 1
)

if "%MASTER_PASSWORD%"=="" (
    echo ERROR: MASTER_PASSWORD not set in .env file
    pause
    exit /b 1
)

REM Activate virtual environment if it exists
if exist .venv\Scripts\activate.bat (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo Warning: Virtual environment not found at .venv\
    echo Using system Python...
)

REM Check if FastAPI is installed
python -c "import fastapi" 2>nul
if errorlevel 1 (
    echo ERROR: FastAPI not installed!
    echo.
    echo Please install required dependencies:
    echo   pip install fastapi uvicorn[standard]
    echo.
    pause
    exit /b 1
)

REM Start the server
echo Starting API server...
echo.
python secure_credentials\src\api\server.py

pause
