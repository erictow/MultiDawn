@echo off
setlocal
set "launcher=%~dp0MultiDawn.Launcher.exe"
if exist "%launcher%" goto launch
set "launcher=%~dp0build\launcher\MultiDawn.Launcher.exe"
if exist "%launcher%" goto launch
if not exist "%~dp0tools\launcher\Build-Launcher.ps1" (
    echo MultiDawn.Launcher.exe is missing. Extract the complete launcher ZIP first.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\launcher\Build-Launcher.ps1"
if errorlevel 1 (
    echo The launcher build failed. Read the error above.
    pause
    exit /b 1
)
:launch
start "" /d "%~dp0." "%launcher%" %*
