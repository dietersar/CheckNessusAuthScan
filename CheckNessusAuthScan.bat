@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

set "SCRIPT_DIR=%~dp0"
set "PS1_FILE=%SCRIPT_DIR%CheckNessusAuthScan.ps1"

cls
echo.
echo ===============================================================
echo Running Admin shell to Check Nessus Authenticated Scan settings
echo ===============================================================
echo.

if not exist "%PS1_FILE%" (
    echo ERROR: Cannot find "%PS1_FILE%"
    echo.
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrative privileges...
    "%PS%" -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%PS%' -Verb RunAs -WorkingDirectory '%SCRIPT_DIR%' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%PS1_FILE%""'"
    exit /b
)

cd /d "%SCRIPT_DIR%"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%PS1_FILE%"
set "EXITCODE=%ERRORLEVEL%"

echo.
pause
exit /b %EXITCODE%