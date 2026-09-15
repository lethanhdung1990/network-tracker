@echo off
chcp 65001 >nul
:: Request Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting Administrator privileges to install Windows Service...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ======================================================================
echo    INSTALL WINDOWS SERVICE: Network Tracker Monitoring Service
echo ======================================================================
echo.
echo [*] Registering service into Windows Service Control Manager...
network-tracker.exe service install
echo.
echo [*] Starting service...
network-tracker.exe service start
echo.
network-tracker.exe service status
echo.
echo [+] Service installed successfully and will start automatically with Windows!
echo     You can manage this service in services.msc.
echo.
pause
