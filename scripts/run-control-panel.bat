@echo off
setlocal EnableDelayedExpansion

:: Talos Control Panel - Windows launcher (monorepo).
::
:: Auto-detects the Talos repo root and the integrated control panel tree.
:: On first run (or whenever pieces are missing) it:
::   1. Creates TALOS_ROOT\.venv and installs Talos editable
::   2. Creates talos-control-panel\backend\.venv and installs backend deps
::   3. Runs npm install in the frontend when node_modules is missing
:: Then starts backend (foreground) + frontend (hidden background), opens the
:: browser, and cleans up the frontend when the backend stops (Ctrl+C / close).
::
:: Usage (from repo root, or double-click / call by full path):
::   scripts\run-control-panel.bat
::
:: Optional overrides (env vars set before launch):
::   TALOS_ROOT, CP_ROOT, TALOS_HOME, CP_BACKEND_PORT, CP_FRONTEND_PORT

if /I "%~1"=="openWhenReady" goto :openWhenReady

set "SCRIPT_DIR=%~dp0"
:: scripts\ lives at <repo>\scripts → repo root is parent
for %%I in ("%SCRIPT_DIR%..") do set "DEFAULT_TALOS_ROOT=%%~fI"

if not defined TALOS_ROOT set "TALOS_ROOT=%DEFAULT_TALOS_ROOT%"
if not defined CP_ROOT set "CP_ROOT=%TALOS_ROOT%\talos-control-panel"
if not defined CP_BACKEND_PORT set "CP_BACKEND_PORT=8420"
if not defined CP_FRONTEND_PORT set "CP_FRONTEND_PORT=5173"
if not defined TALOS_HOME set "TALOS_HOME=%USERPROFILE%\.talos"
if not defined TALOS_VENV set "TALOS_VENV=%TALOS_ROOT%\.venv"

set "CP_BACKEND_DIR=%CP_ROOT%\backend"
set "CP_FRONTEND_DIR=%CP_ROOT%\frontend"
set "CP_BACKEND_VENV=%CP_BACKEND_DIR%\.venv"
set "TALOS_PY=%TALOS_VENV%\Scripts\python.exe"
set "CP_PY=%CP_BACKEND_VENV%\Scripts\python.exe"
set "FRONTEND_LOG=%CP_ROOT%\frontend.log"
set "FRONTEND_ERR_LOG=%CP_ROOT%\frontend-error.log"
set "PID_FILE=%CP_ROOT%\.frontend.pid"

if not exist "%TALOS_ROOT%\pyproject.toml" (
    echo [error] TALOS_ROOT does not look like the Talos repo: %TALOS_ROOT%
    echo         Expected pyproject.toml at that path.
    exit /b 1
)
if not exist "%CP_BACKEND_DIR%\" (
    echo [error] Control panel backend not found: %CP_BACKEND_DIR%
    exit /b 1
)
if not exist "%CP_FRONTEND_DIR%\" (
    echo [error] Control panel frontend not found: %CP_FRONTEND_DIR%
    exit /b 1
)

echo == Talos Control Panel launcher ==
echo     TALOS_ROOT=%TALOS_ROOT%
echo     CP_ROOT=%CP_ROOT%
echo     TALOS_HOME=%TALOS_HOME%
echo     backend=http://127.0.0.1:%CP_BACKEND_PORT%
echo     frontend=http://127.0.0.1:%CP_FRONTEND_PORT%

where python >nul 2>&1
if errorlevel 1 (
    echo [error] python not found in PATH. Install Python 3.11+ and try again.
    exit /b 1
)
where node >nul 2>&1
if errorlevel 1 (
    echo [error] node not found in PATH. Install Node.js and try again.
    exit /b 1
)
where npm >nul 2>&1
if errorlevel 1 (
    echo [error] npm not found in PATH.
    exit /b 1
)
where curl >nul 2>&1
if errorlevel 1 (
    echo [warn] curl not found - browser will not auto-open.
)

:: ---- 1. Talos core venv + editable install ----
:: Do not use bare `import talos` as readiness — starting from the repo root
:: puts cwd on sys.path so the source tree imports without pip (deps missing).
if not exist "%TALOS_PY%" (
    echo [setup] Creating Talos venv at %TALOS_VENV%
    python -m venv "%TALOS_VENV%"
    "%TALOS_PY%" -m pip install --upgrade pip
)
set "NEED_TALOS_INSTALL=0"
if not exist "%TALOS_VENV%\Scripts\talos.exe" set "NEED_TALOS_INSTALL=1"
"%TALOS_PY%" -c "import httpx" >nul 2>&1
if errorlevel 1 set "NEED_TALOS_INSTALL=1"
if "%NEED_TALOS_INSTALL%"=="1" (
    echo [setup] Installing talos package ^(editable^) from %TALOS_ROOT%
    "%TALOS_PY%" -m pip install -e "%TALOS_ROOT%"
) else (
    echo [setup] Talos venv OK
)

:: ---- 2. Control panel backend venv + deps ----
if not exist "%CP_PY%" (
    echo [setup] Creating control panel backend venv
    python -m venv "%CP_BACKEND_VENV%"
    "%CP_PY%" -m pip install --upgrade pip
)
"%CP_PY%" -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [setup] Installing control panel backend dependencies
    "%CP_PY%" -m pip install -r "%CP_BACKEND_DIR%\requirements.txt"
) else (
    echo [setup] Control panel backend venv OK
)

:: ---- 3. Frontend deps ----
if not exist "%CP_FRONTEND_DIR%\node_modules\" (
    echo [setup] Installing frontend dependencies ^(npm install^)
    pushd "%CP_FRONTEND_DIR%"
    call npm install
    if errorlevel 1 (
        popd
        echo [error] npm install failed
        exit /b 1
    )
    popd
) else (
    echo [setup] Frontend node_modules OK
)

set "TALOS_PYTHON=%TALOS_PY%"
set "CP_PORT=%CP_BACKEND_PORT%"
set "VITE_API_BASE=http://127.0.0.1:%CP_BACKEND_PORT%"

:: ---- 4. Frontend hidden in background ----
echo [run] Starting frontend in background (logs -^> %FRONTEND_LOG%)
if exist "%PID_FILE%" del "%PID_FILE%"
if exist "%FRONTEND_LOG%" del "%FRONTEND_LOG%"
if exist "%FRONTEND_ERR_LOG%" del "%FRONTEND_ERR_LOG%"
powershell -NoProfile -Command ^
  "$p = Start-Process -FilePath 'npm.cmd' -ArgumentList 'run','dev','--','--port','%CP_FRONTEND_PORT%','--strictPort' -WorkingDirectory '%CP_FRONTEND_DIR%' -WindowStyle Hidden -RedirectStandardOutput '%FRONTEND_LOG%' -RedirectStandardError '%FRONTEND_ERR_LOG%' -PassThru; $p.Id | Out-File -Encoding ascii '%PID_FILE%'"
if errorlevel 1 (
    echo [error] Failed to start frontend
    exit /b 1
)

:: ---- 5. Open browser once frontend responds (detached watcher) ----
start "" /min cmd /c "%~f0" openWhenReady %CP_FRONTEND_PORT%

:: ---- 6. Backend in the foreground ----
echo [run] Starting backend on port %CP_BACKEND_PORT% - press Ctrl+C to stop everything
cd /d "%CP_BACKEND_DIR%"
"%CP_PY%" -m uvicorn talos_ui.main:app --reload --host 127.0.0.1 --port %CP_BACKEND_PORT%

:: ---- 7. Cleanup frontend once backend stops ----
echo [run] Backend stopped, cleaning up frontend...
if exist "%PID_FILE%" (
    set /p FRONTEND_PID=<"%PID_FILE%"
    powershell -NoProfile -Command ^
      "$frontendPid = %FRONTEND_PID%; if ($frontendPid) { Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $frontendPid -or $_.ParentProcessId -eq $frontendPid } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }"
    del "%PID_FILE%" 2>nul
)
goto :eof

:openWhenReady
set "PORT=%~2"
if not defined PORT set "PORT=5173"
set "FRONTEND_URL=http://127.0.0.1:%PORT%"
for /L %%i in (1,1,60) do (
    curl -s -o nul --connect-timeout 1 "%FRONTEND_URL%" 2>nul
    if not errorlevel 1 (
        start "" "%FRONTEND_URL%"
        exit /b 0
    )
    timeout /t 1 >nul
)
echo [warn] Frontend did not become ready in time - open %FRONTEND_URL% manually
exit /b 0
