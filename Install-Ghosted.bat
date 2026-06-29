@echo off
REM One-click launcher for the Ghosted installer. Double-click this file.
REM It runs the PowerShell installer (bypassing the script-execution policy for
REM this one run only) which installs every Ghosted bundle found beside it
REM (Ghosted-FULL / Ghosted-LEAN) and drops a Desktop icon for each.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Ghosted.ps1" %*
echo.
pause
