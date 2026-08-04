@echo off
:: Talos Control Panel - Windows entry point (monorepo).
::
:: Delegates to run-control-panel.ps1 which:
::   - cleans up stale backend/frontend from prior runs
::   - starts frontend + backend bound to a Job Object (dies with the terminal)
::   - handles Ctrl+C without the flaky "Terminate batch job (Y/N)?" hang
::
:: Prefer from PowerShell:
::   .\scripts\run-control-panel.ps1
::
:: Optional env overrides (set before launch):
::   TALOS_ROOT, CP_ROOT, TALOS_HOME, CP_BACKEND_PORT, CP_FRONTEND_PORT

setlocal
set "SCRIPT_DIR=%~dp0"

where powershell >nul 2>&1
if errorlevel 1 (
    echo [error] powershell not found. Open PowerShell and run:
    echo         powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run-control-panel.ps1"
    exit /b 1
)

:: -NoLogo reduces noise; Bypass avoids ExecutionPolicy blocks for this repo script.
:: Use call-style so ERRORLEVEL propagates; do not leave a long-lived cmd wait
:: loop that prompts "Terminate batch job".
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run-control-panel.ps1" %*
set "EC=%ERRORLEVEL%"
endlocal & exit /b %EC%
