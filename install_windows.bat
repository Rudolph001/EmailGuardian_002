
@echo off
echo Email Guardian - Windows Installation
echo ====================================

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detected

:: Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

:: Install requirements
echo Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies
    pause
    exit /b 1
)

:: Run setup script
echo Running setup script...
python setup.py
if errorlevel 1 (
    echo Setup failed
    pause
    exit /b 1
)

echo.
echo ====================================
echo Installation completed successfully!
echo.
echo To start the application:
echo   python app.py
echo.
echo Then open your browser to: http://localhost:5000
echo ====================================
pause
