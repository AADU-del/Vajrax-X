@echo off
REM ============================================
REM VAJRA-X Windows Development Runner
REM ============================================

echo.
echo ========================================
echo   VAJRA-X - Starting Development Server
echo ========================================
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    echo Please run setup_windows.bat first
    pause
    exit /b 1
)

echo Starting Flask development server...
echo.
echo Open your browser: http://127.0.0.1:5000
echo Seed Login: admin / ChangeMe@2024!
echo.
echo Press Ctrl+C to stop the server
echo.

python run.py
