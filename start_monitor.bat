@echo off
rem Run the live scan / analyze / risk-score loop using the project venv.
rem Leave this window open; press Ctrl+C to stop.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo .venv not found -- run setup_windows.bat first.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" main_controller.py
pause
