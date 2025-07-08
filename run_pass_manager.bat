 @echo off
cls
echo Secure Credential Manager - Testing Launcher
echo =============================================
echo.
echo Select an option:
echo 1. Run normally (through launcher)
echo 2. Run directly (bypass launcher)
echo 3. Debug mode (aggressive window visibility)
echo 4. Test window only (verify basic window works)
echo 5. Run with Jupyter notebook (for interactive debugging)
echo 6. View logs (check for errors)
echo 7. Exit
echo.

set /p option="Enter option number: "

if "%option%"=="1" (
    echo Running in normal mode...
    python -m secure_credentials.launcher
) else if "%option%"=="2" (
    echo Running directly (bypassing launcher)...
    python -m secure_credentials.run_app direct_gui
) else if "%option%"=="3" (
    echo Running in debug mode with enhanced visibility...
    python -m secure_credentials.run_app debug
) else if "%option%"=="4" (
    echo Testing basic window functionality...
    python -m secure_credentials.run_app test_window
) else if "%option%"=="5" (
    echo Launching Jupyter notebook for interactive debugging...
    jupyter notebook secure_credentials\debug_gui.ipynb
) else if "%option%"=="6" (
    echo Log files:
    echo.
    if exist "secure_credentials_debug.log" (
        echo secure_credentials_debug.log (Last 10 lines):
        echo ---------------------------------------
        powershell -Command "Get-Content secure_credentials_debug.log -Tail 10"
        echo.
    )
    if exist "run_app_debug.log" (
        echo run_app_debug.log (Last 10 lines):
        echo ---------------------------------
        powershell -Command "Get-Content run_app_debug.log -Tail 10"
        echo.
    )
    if exist "gui_test_debug.log" (
        echo gui_test_debug.log (Last 10 lines):
        echo ----------------------------------
        powershell -Command "Get-Content gui_test_debug.log -Tail 10"
        echo.
    )
    set log_path=%USERPROFILE%\.secure_credentials\logs\credential_manager.log
    if exist "%log_path%" (
        echo %log_path% (Last 10 lines):
        echo ----------------------------------
        powershell -Command "Get-Content '%log_path%' -Tail 10"
        echo.
    )
    echo.
    pause
) else if "%option%"=="7" (
    exit
) else (
    echo Invalid option selected
    timeout /t 2 >nul
)

echo.
echo Press any key to return to menu...
pause >nul
%0