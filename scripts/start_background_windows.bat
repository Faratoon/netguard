@echo off
REM Start NetGuard in the background on Windows (used for a "always on" instance).
cd /d "%~dp0.."
start "" /B .venv\Scripts\python.exe -m uvicorn netguard.main:app --host 0.0.0.0 --port 8765 > netguard.log 2>&1
echo NetGuard started in the background - log: netguard.log
