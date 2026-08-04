#Requires -Version 5.1
<#
.SYNOPSIS
  Talos Control Panel launcher for Windows (monorepo).

.DESCRIPTION
  Sets up missing venvs/deps, frees stale Control Panel ports from prior runs,
  starts frontend + backend, opens the browser, and tears everything down on
  Ctrl+C or normal exit. Child processes are bound to a Windows Job Object with
  KILL_ON_JOB_CLOSE so closing the terminal does not leave orphans.

  Prefer invoking this script directly from PowerShell:
    .\scripts\run-control-panel.ps1

  The .bat wrapper is a thin entry point for double-click / cmd.exe.

  Optional env overrides (set before launch):
    TALOS_ROOT, CP_ROOT, TALOS_HOME, TALOS_VENV, CP_BACKEND_PORT, CP_FRONTEND_PORT
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DefaultTalosRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

if (-not $env:TALOS_ROOT) { $env:TALOS_ROOT = $DefaultTalosRoot }
if (-not $env:CP_ROOT) { $env:CP_ROOT = Join-Path $env:TALOS_ROOT "talos-control-panel" }
if (-not $env:CP_BACKEND_PORT) { $env:CP_BACKEND_PORT = "8420" }
if (-not $env:CP_FRONTEND_PORT) { $env:CP_FRONTEND_PORT = "5173" }
if (-not $env:TALOS_HOME) { $env:TALOS_HOME = Join-Path $env:USERPROFILE ".talos" }
if (-not $env:TALOS_VENV) { $env:TALOS_VENV = Join-Path $env:TALOS_ROOT ".venv" }

$TalosRoot = $env:TALOS_ROOT
$CpRoot = $env:CP_ROOT
$CpBackendPort = [int]$env:CP_BACKEND_PORT
$CpFrontendPort = [int]$env:CP_FRONTEND_PORT
$TalosHome = $env:TALOS_HOME
$TalosVenv = $env:TALOS_VENV

$CpBackendDir = Join-Path $CpRoot "backend"
$CpFrontendDir = Join-Path $CpRoot "frontend"
$CpBackendVenv = Join-Path $CpBackendDir ".venv"
$TalosPy = Join-Path $TalosVenv "Scripts\python.exe"
$CpPy = Join-Path $CpBackendVenv "Scripts\python.exe"
$FrontendLog = Join-Path $CpRoot "frontend.log"
$FrontendErrLog = Join-Path $CpRoot "frontend-error.log"
$PidFile = Join-Path $CpRoot ".frontend.pid"
$BackendPidFile = Join-Path $CpRoot ".backend.pid"

# ---------------------------------------------------------------------------
# Job Object: kill all assigned children when this process exits (incl. close)
# ---------------------------------------------------------------------------
$JobHelperType = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class TalosJobObject {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(
        IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public UInt32 LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public UIntPtr Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    const UInt32 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const int JobObjectExtendedLimitInformation = 9;

    public static IntPtr CreateKillOnCloseJob() {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(length);
        try {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ptr, (uint)length)) {
                int err = Marshal.GetLastWin32Error();
                CloseHandle(job);
                throw new System.ComponentModel.Win32Exception(err);
            }
        } finally {
            Marshal.FreeHGlobal(ptr);
        }
        return job;
    }

    public static void Assign(IntPtr job, Process process) {
        if (job == IntPtr.Zero || process == null) return;
        if (!AssignProcessToJobObject(job, process.Handle)) {
            // ACCESS_DENIED can happen for elevated children; non-fatal.
            int err = Marshal.GetLastWin32Error();
            if (err != 5) {
                throw new System.ComponentModel.Win32Exception(err);
            }
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $JobHelperType -ErrorAction Stop | Out-Null
} catch {
    # Type already loaded in this session
    if ($_.Exception.Message -notmatch "already exists") { throw }
}

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------
function Get-ListeningPids {
    param([Parameter(Mandatory = $true)][int]$Port)
    $pids = New-Object System.Collections.Generic.HashSet[int]
    try {
        Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($_.OwningProcess -gt 0) { [void]$pids.Add([int]$_.OwningProcess) }
            }
    } catch {
        # Fallback: netstat parsing (works without Get-NetTCPConnection)
        # Example: TCP    127.0.0.1:8420    0.0.0.0:0    LISTENING    12345
        $pattern = ":$Port\s+\S+\s+LISTENING\s+(\d+)"
        netstat -ano -p tcp 2>$null | ForEach-Object {
            if ($_ -match $pattern) {
                $pidVal = [int]$Matches[1]
                if ($pidVal -gt 0) { [void]$pids.Add($pidVal) }
            }
        }
    }
    return @($pids)
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    if ($ProcessId -le 0) { return }
    # /T kills the whole tree; ignore errors if already gone
    & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
}

function Stop-PortListeners {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [string]$Label = "port"
    )
    $owners = Get-ListeningPids -Port $Port
    if (-not $owners -or $owners.Count -eq 0) { return }
    Write-Host "[cleanup] Freeing $Label $Port (pids: $($owners -join ', '))"
    foreach ($pidVal in $owners) {
        Stop-ProcessTree -ProcessId $pidVal
    }
    Start-Sleep -Milliseconds 300
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Setup {
    if (-not (Test-Path (Join-Path $TalosRoot "pyproject.toml"))) {
        throw "TALOS_ROOT does not look like the Talos repo: $TalosRoot (expected pyproject.toml)"
    }
    if (-not (Test-Path $CpBackendDir)) {
        throw "Control panel backend not found: $CpBackendDir"
    }
    if (-not (Test-Path $CpFrontendDir)) {
        throw "Control panel frontend not found: $CpFrontendDir"
    }

    foreach ($bin in @("python", "node", "npm")) {
        if (-not (Test-CommandExists $bin)) {
            throw "'$bin' not found in PATH"
        }
    }

    # ---- 1. Talos core venv ----
    if (-not (Test-Path $TalosPy)) {
        Write-Host "[setup] Creating Talos venv at $TalosVenv"
        & python -m venv $TalosVenv
        & $TalosPy -m pip install --upgrade pip
    }
    $needTalos = $false
    if (-not (Test-Path (Join-Path $TalosVenv "Scripts\talos.exe"))) { $needTalos = $true }
    & $TalosPy -c "import httpx" 2>$null
    if ($LASTEXITCODE -ne 0) { $needTalos = $true }
    if ($needTalos) {
        Write-Host "[setup] Installing talos package (editable) from $TalosRoot"
        & $TalosPy -m pip install -e $TalosRoot
        if ($LASTEXITCODE -ne 0) { throw "pip install -e talos failed" }
    } else {
        Write-Host "[setup] Talos venv OK"
    }

    # ---- 2. Control panel backend venv ----
    if (-not (Test-Path $CpPy)) {
        Write-Host "[setup] Creating control panel backend venv"
        & python -m venv $CpBackendVenv
        & $CpPy -m pip install --upgrade pip
    }
    & $CpPy -c "import fastapi, uvicorn" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[setup] Installing control panel backend dependencies"
        & $CpPy -m pip install -r (Join-Path $CpBackendDir "requirements.txt")
        if ($LASTEXITCODE -ne 0) { throw "backend pip install failed" }
    } else {
        Write-Host "[setup] Control panel backend venv OK"
    }

    # ---- 3. Frontend deps ----
    if (-not (Test-Path (Join-Path $CpFrontendDir "node_modules"))) {
        Write-Host "[setup] Installing frontend dependencies (npm install)"
        Push-Location $CpFrontendDir
        try {
            & npm install
            if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "[setup] Frontend node_modules OK"
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$script:JobHandle = [IntPtr]::Zero
$script:FrontendProc = $null
$script:BackendProc = $null
$script:CleaningUp = $false

function Invoke-Shutdown {
    if ($script:CleaningUp) { return }
    $script:CleaningUp = $true
    Write-Host ""
    Write-Host "[run] Shutting down Control Panel..."

    if ($script:FrontendProc -and -not $script:FrontendProc.HasExited) {
        Stop-ProcessTree -ProcessId $script:FrontendProc.Id
    } elseif (Test-Path $PidFile) {
        try {
            $oldPid = [int]((Get-Content $PidFile -Raw).Trim())
            if ($oldPid -gt 0) { Stop-ProcessTree -ProcessId $oldPid }
        } catch { }
    }

    if ($script:BackendProc -and -not $script:BackendProc.HasExited) {
        Stop-ProcessTree -ProcessId $script:BackendProc.Id
    } elseif (Test-Path $BackendPidFile) {
        try {
            $oldPid = [int]((Get-Content $BackendPidFile -Raw).Trim())
            if ($oldPid -gt 0) { Stop-ProcessTree -ProcessId $oldPid }
        } catch { }
    }

    # Belt-and-suspenders: free CP ports (never touches proxy :8080).
    Stop-PortListeners -Port $CpBackendPort -Label "backend"
    Stop-PortListeners -Port $CpFrontendPort -Label "frontend"

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Remove-Item $BackendPidFile -Force -ErrorAction SilentlyContinue

    if ($script:JobHandle -ne [IntPtr]::Zero) {
        [void][TalosJobObject]::CloseHandle($script:JobHandle)
        $script:JobHandle = [IntPtr]::Zero
    }
    Write-Host "[run] Cleanup complete."
}

try {
    Write-Host "== Talos Control Panel launcher =="
    Write-Host "    TALOS_ROOT=$TalosRoot"
    Write-Host "    CP_ROOT=$CpRoot"
    Write-Host "    TALOS_HOME=$TalosHome"
    Write-Host "    backend=http://127.0.0.1:$CpBackendPort"
    Write-Host "    frontend=http://127.0.0.1:$CpFrontendPort"

    Invoke-Setup

    # Pre-start cleanup: prior Ctrl+C / closed terminals often leave orphans.
    Write-Host "[cleanup] Checking for stale Control Panel processes..."
    if (Test-Path $PidFile) {
        try {
            $staleFe = [int]((Get-Content $PidFile -Raw).Trim())
            if ($staleFe -gt 0) {
                Write-Host "[cleanup] Stopping stale frontend pid $staleFe"
                Stop-ProcessTree -ProcessId $staleFe
            }
        } catch { }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $BackendPidFile) {
        try {
            $staleBe = [int]((Get-Content $BackendPidFile -Raw).Trim())
            if ($staleBe -gt 0) {
                Write-Host "[cleanup] Stopping stale backend pid $staleBe"
                Stop-ProcessTree -ProcessId $staleBe
            }
        } catch { }
        Remove-Item $BackendPidFile -Force -ErrorAction SilentlyContinue
    }
    Stop-PortListeners -Port $CpBackendPort -Label "backend"
    Stop-PortListeners -Port $CpFrontendPort -Label "frontend"

    $env:TALOS_PYTHON = $TalosPy
    $env:CP_PORT = "$CpBackendPort"
    $env:VITE_API_BASE = "http://127.0.0.1:$CpBackendPort"
    $env:TALOS_HOME = $TalosHome
    $env:TALOS_ROOT = $TalosRoot

    try {
        $script:JobHandle = [TalosJobObject]::CreateKillOnCloseJob()
    } catch {
        Write-Host "[warn] Could not create Job Object (orphans on terminal close still possible): $_"
        $script:JobHandle = [IntPtr]::Zero
    }

    if (Test-Path $FrontendLog) { Remove-Item $FrontendLog -Force -ErrorAction SilentlyContinue }
    if (Test-Path $FrontendErrLog) { Remove-Item $FrontendErrLog -Force -ErrorAction SilentlyContinue }

    Write-Host "[run] Starting frontend in background (logs -> $FrontendLog)"
    $npmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue)
    if (-not $npmCmd) { $npmCmd = Get-Command npm }
    $feArgs = @(
        "run", "dev", "--",
        "--port", "$CpFrontendPort",
        "--strictPort"
    )
    $script:FrontendProc = Start-Process -FilePath $npmCmd.Source `
        -ArgumentList $feArgs `
        -WorkingDirectory $CpFrontendDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $FrontendLog `
        -RedirectStandardError $FrontendErrLog `
        -PassThru
    $script:FrontendProc.Id | Out-File -Encoding ascii -FilePath $PidFile
    if ($script:JobHandle -ne [IntPtr]::Zero) {
        try { [TalosJobObject]::Assign($script:JobHandle, $script:FrontendProc) } catch {
            Write-Host "[warn] Could not assign frontend to job: $_"
        }
    }

    Write-Host "[run] Starting backend on port $CpBackendPort — press Ctrl+C to stop everything"
    $beArgs = @(
        "-m", "uvicorn", "talos_ui.main:app",
        "--reload",
        "--host", "127.0.0.1",
        "--port", "$CpBackendPort"
    )
    $script:BackendProc = Start-Process -FilePath $CpPy `
        -ArgumentList $beArgs `
        -WorkingDirectory $CpBackendDir `
        -NoNewWindow `
        -PassThru
    $script:BackendProc.Id | Out-File -Encoding ascii -FilePath $BackendPidFile
    if ($script:JobHandle -ne [IntPtr]::Zero) {
        try { [TalosJobObject]::Assign($script:JobHandle, $script:BackendProc) } catch {
            Write-Host "[warn] Could not assign backend to job: $_"
        }
    }

    # Open browser once frontend responds (background)
    $frontendUrl = "http://127.0.0.1:$CpFrontendPort"
    $opener = Start-Job -ScriptBlock {
        param($Url)
        for ($i = 0; $i -lt 60; $i++) {
            try {
                $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
                if ($resp.StatusCode -ge 200) {
                    Start-Process $Url
                    return
                }
            } catch { }
            Start-Sleep -Seconds 1
        }
        Write-Host "[warn] Frontend did not become ready in time — open $Url manually"
    } -ArgumentList $frontendUrl

    # Wait for backend; Ctrl+C aborts the wait and runs finally cleanup.
    # Polling avoids Start-Process -Wait quirks with console signals.
    while ($script:BackendProc -and -not $script:BackendProc.HasExited) {
        Start-Sleep -Milliseconds 400
        # Refresh process state
        try { $script:BackendProc.Refresh() } catch { break }
    }

    if ($opener) {
        Stop-Job $opener -ErrorAction SilentlyContinue
        Remove-Job $opener -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[error] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Invoke-Shutdown
}
