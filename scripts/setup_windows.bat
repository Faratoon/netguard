@echo off
REM Create the Python environment and install NetGuard dependencies (Windows).
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Done. Now run scripts\start_windows.bat
endlocal
