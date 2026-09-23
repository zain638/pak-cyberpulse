@echo off
REM =====================================================================
REM Pak-CyberPulse - Windows build script (does EVERYTHING on a fresh PC)
REM  1. Checks for Python 3.10+ (tries winget install if missing)
REM  2. Installs project requirements + PyInstaller
REM  3. Builds dist\Pak-CyberPulse.exe (onefile)
REM Run by double-clicking this file from the "desktop" folder.
REM =====================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================================
echo  Pak-CyberPulse - Windows build
echo ============================================================

REM ---- Step 1: Python -------------------------------------------------
echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found. Trying to install Python 3.11 via winget...
    winget install -e --id Python.Python.3.11 --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo.
        echo ERROR: Could not install Python automatically.
        echo Please install Python 3.11+ manually from https://www.python.org/downloads/
        echo IMPORTANT: tick "Add python.exe to PATH" during setup, then re-run this file.
        pause
        exit /b 1
    )
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python311;%LOCALAPPDATA%\Programs\Python\Python311\Scripts;%PATH%"
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Found Python %PYVER%
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3.10 or newer is required (found %PYVER%).
    pause
    exit /b 1
)

REM ---- Step 2: requirements -------------------------------------------
echo [2/4] Installing project requirements (takes a few minutes)...
python -m pip install --upgrade pip
if errorlevel 1 ( echo ERROR: pip upgrade failed. & pause & exit /b 1 )
python -m pip install -r "..\requirements.txt"
if errorlevel 1 ( echo ERROR: requirements install failed. & pause & exit /b 1 )

REM ---- Step 3: PyInstaller ---------------------------------------------
echo [3/4] Installing PyInstaller...
python -m pip install pyinstaller
if errorlevel 1 ( echo ERROR: PyInstaller install failed. & pause & exit /b 1 )

REM ---- Step 4: build ----------------------------------------------------
echo [4/4] Building Pak-CyberPulse.exe (takes several minutes)...
python -m PyInstaller --clean --noconfirm pak_cyberpulse.spec
if errorlevel 1 ( echo ERROR: build failed. & pause & exit /b 1 )

echo.
echo ============================================================
echo  BUILD OK: %cd%\dist\Pak-CyberPulse.exe
echo  Next: run install-windows.bat to install it.
echo ============================================================
pause
