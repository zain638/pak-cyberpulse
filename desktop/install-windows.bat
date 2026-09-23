@echo off
REM =====================================================================
REM Pak-CyberPulse - Windows installer
REM  Copies Pak-CyberPulse.exe to %LOCALAPPDATA%\PakCyberPulse\,
REM  creates a Start Menu shortcut, optionally enables "run at startup",
REM  then launches the app.
REM  Build the exe first with build-windows.bat.
REM =====================================================================
setlocal
cd /d "%~dp0"

set "SRC=%~dp0dist\Pak-CyberPulse.exe"
set "DEST=%LOCALAPPDATA%\PakCyberPulse"

if not exist "%SRC%" (
    echo ERROR: "%SRC%" not found.
    echo Run build-windows.bat first to build the exe.
    pause
    exit /b 1
)

echo Installing Pak-CyberPulse to %DEST% ...
if not exist "%DEST%" mkdir "%DEST%"
copy /y "%SRC%" "%DEST%\" >nul
if errorlevel 1 ( echo ERROR: copy failed. & pause & exit /b 1 )

REM ---- Start Menu shortcut ---------------------------------------------
echo Creating Start Menu shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ws = New-Object -ComObject WScript.Shell; " ^
  "$sc = $ws.CreateShortcut($env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Pak-CyberPulse.lnk'); " ^
  "$sc.TargetPath = $env:LOCALAPPDATA + '\PakCyberPulse\Pak-CyberPulse.exe'; " ^
  "$sc.WorkingDirectory = $env:LOCALAPPDATA + '\PakCyberPulse'; " ^
  "$sc.Description = 'Pak-CyberPulse SIEM / SOAR / GRC desktop app'; " ^
  "$sc.Save()"
if errorlevel 1 ( echo WARNING: Start Menu shortcut could not be created. )

REM ---- Optional: run at Windows startup ---------------------------------
choice /M "Start Pak-CyberPulse automatically when Windows starts"
if not errorlevel 2 (
    echo Enabling run-at-startup...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$ws = New-Object -ComObject WScript.Shell; " ^
      "$sc = $ws.CreateShortcut($env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Startup\Pak-CyberPulse.lnk'); " ^
      "$sc.TargetPath = $env:LOCALAPPDATA + '\PakCyberPulse\Pak-CyberPulse.exe'; " ^
      "$sc.WorkingDirectory = $env:LOCALAPPDATA + '\PakCyberPulse'; " ^
      "$sc.Save()"
    echo Run-at-startup enabled.
) else (
    echo Run-at-startup skipped.
)

REM ---- Launch ------------------------------------------------------------
echo.
echo Installed. Launching Pak-CyberPulse...
echo Your browser will open to http://localhost:8501
start "" "%DEST%\Pak-CyberPulse.exe"
echo Done.
pause
