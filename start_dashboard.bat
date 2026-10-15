@echo off
rem Serve the web dashboard at http://127.0.0.1:5000 using the project venv.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo .venv not found -- run setup_windows.bat first.
    pause
    exit /b 1
)
start "" http://127.0.0.1:5000
".venv\Scripts\python.exe" -m scanner.dashboard %*
pause
