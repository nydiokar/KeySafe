@echo off
echo Building Secure Credential Manager...
echo.

:: Activate virtual environment if it exists, create if it doesn't
if exist .venv (
    echo Using existing virtual environment...
    call .venv\Scripts\activate
) else (
    echo Creating new virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate
)

:: Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -e ".[dev]"

:: Clean previous builds
echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del *.spec

:: Create assets directory if it doesn't exist
if not exist secure_credentials\assets mkdir secure_credentials\assets

:: Build the executable
echo Building executable...
pyinstaller secure_credentials.spec

echo.
if exist dist\SecureCredentialManager.exe (
    echo Build successful! Executable is in dist\SecureCredentialManager.exe
) else (
    echo Build failed! Check the error messages above.
)

:: Build installer if NSIS is installed
where makensis >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Building installer...
    makensis installer.nsi
    if exist SecureCredentialManager-Setup.exe (
        echo Installer created successfully!
    ) else (
        echo Failed to create installer!
    )
) else (
    echo NSIS not found. Skipping installer creation.
    echo To create an installer, please install NSIS from https://nsis.sourceforge.io/Download
)

echo.
pause 