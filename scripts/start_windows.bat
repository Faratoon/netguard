@echo off
REM Start NetGuard on Windows: http://localhost:8080
setlocal
cd /d "%~dp0.."

if not exist .venv\Scripts\activate.bat (
    echo No virtual environment found - run scripts\setup_windows.bat first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
start "" http://localhost:8080
python -m uvicorn netguard.main:app --host 0.0.0.0 --port 8080
endlocal
