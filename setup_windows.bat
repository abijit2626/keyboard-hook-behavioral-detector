@echo off
rem Double-click wrapper for setup_windows.ps1 (bypasses the default
rem PowerShell execution policy for this one invocation only).
rem Pass -Demo to also seed sample dashboard data:  setup_windows.bat -Demo
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_windows.ps1" %*
if errorlevel 1 (
    echo.
    echo Setup failed -- see the messages above.
)
pause
