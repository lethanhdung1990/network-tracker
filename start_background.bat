@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [*] Starting network-tracker...
network-tracker.exe start
echo.
network-tracker.exe status
echo.
pause
