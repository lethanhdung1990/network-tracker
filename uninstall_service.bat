@echo off
chcp 65001 >nul
:: Request Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting Administrator privileges to remove Windows Service...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ======================================================================
echo    UNINSTALL WINDOWS SERVICE: Network Tracker Monitoring Service
echo ======================================================================
echo.
echo [*] Stopping service...
network-tracker.exe service stop
echo.
echo [*] Removing service from Windows...
network-tracker.exe service uninstall
echo.
echo [+] Service removed successfully from services.msc!
echo.
pause
