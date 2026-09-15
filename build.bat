@echo off
chcp 65001 >nul
echo [*] Building network-tracker.exe (Optimized binary)...
go build -ldflags="-s -w" -o dist/network-tracker.exe ./cmd/tracker
if %ERRORLEVEL% equ 0 (
    echo [+] Build successful: dist\network-tracker.exe
) else (
    echo [X] Build failed!
)
pause
