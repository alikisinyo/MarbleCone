@echo off
echo ========================================
echo MarbleCone Threat Emulator - APT-33 Replica
echo ========================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting MarbleCone Threat Emulator...
echo.
echo Access the web interface at: http://localhost:5000
echo Login credentials: admin / admin123
echo.
echo Press Ctrl+C to stop the server
echo.

python app.py

pause 