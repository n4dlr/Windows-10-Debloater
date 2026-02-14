@echo off
:: God Debloater - Launcher (Requests Administrator)
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit
)
powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0God-Debloater.ps1" %*
if errorlevel 1 pause
