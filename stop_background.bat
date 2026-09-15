@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [*] Stopping network-tracker...
network-tracker.exe stop
echo.
network-tracker.exe status
echo.
pause
