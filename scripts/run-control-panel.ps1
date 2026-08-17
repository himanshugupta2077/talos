#Requires -Version 5.1
<#
.SYNOPSIS
  Talos Control Panel launcher for Windows (monorepo) — the only Windows script.

.DESCRIPTION
  Sets up missing venvs/deps, frees stale Control Panel ports from prior runs,
  starts frontend + backend, opens the browser, and tears everything down on
  Ctrl+C or normal exit. Child processes are bound to a Windows Job Object with
  KILL_ON_JOB_CLOSE so closing the terminal does not leave orphans.

  Run from PowerShell (repo root or any cwd — paths resolve from this file):
    .\scripts\run-control-panel.ps1

  From cmd.exe:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-control-panel.ps1

  Optional env overrides (set before launch):
    TALOS_ROOT, CP_ROOT, TALOS_HOME, TALOS_VENV, CP_BACKEND_PORT, CP_FRONTEND_PORT,
    TALOS_CP_CLI_TIMEOUT (seconds for CP-invoked CLI; default 600 / 10 min for slow VDI)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# PS7+: do not treat native-command stderr as terminating errors.
if (Test-Path Variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DefaultTalosRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

function Test-TalosRepoRoot {
    param([string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    return Test-Path -LiteralPath (Join-Path $Candidate "pyproject.toml")
}

function Test-ControlPanelRoot {
    param([string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    return (Test-Path -LiteralPath (Join-Path $Candidate "backend")) -and
           (Test-Path -LiteralPath (Join-Path $Candidate "frontend"))
}

function Test-IsUnderPath {
    param([string]$Child, [string]$Parent)
    if ([string]::IsNullOrWhiteSpace($Child) -or [string]::IsNullOrWhiteSpace($Parent)) { return $false }
    try {
        $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\', '/')
        $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    } catch {
        return $false
    }
    $sep = [System.IO.Path]::DirectorySeparatorChar
    return $childFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase) -or
           $childFull.StartsWith(($parentFull + $sep), [System.StringComparison]::OrdinalIgnoreCase)
}

# Honor TALOS_ROOT only when it actually looks like this repo. A leftover
# User/System env var (common after a GitHub zip extract named talos-main)
# used to win over the clone that contains this script.
$envTalosRoot = $env:TALOS_ROOT
if (Test-TalosRepoRoot $envTalosRoot) {
    $env:TALOS_ROOT = $envTalosRoot
} elseif (Test-TalosRepoRoot $DefaultTalosRoot) {
    if ($envTalosRoot) {
        Write-Host "[warn] TALOS_ROOT=$envTalosRoot is not a Talos repo (missing pyproject.toml)."
        Write-Host "[warn] Ignoring stale TALOS_ROOT and using $DefaultTalosRoot"
    }
    $env:TALOS_ROOT = $DefaultTalosRoot
} elseif ($envTalosRoot) {
    $env:TALOS_ROOT = $envTalosRoot
} else {
    $env:TALOS_ROOT = $DefaultTalosRoot
}

$defaultCpRoot = Join-Path $env:TALOS_ROOT "talos-control-panel"
$envCpRoot = $env:CP_ROOT
$remappedTalosRoot = $envTalosRoot -and ($env:TALOS_ROOT -ne $envTalosRoot)
if ((Test-ControlPanelRoot $envCpRoot) -and -not ($remappedTalosRoot -and (Test-IsUnderPath $envCpRoot $envTalosRoot) -and (Test-ControlPanelRoot $defaultCpRoot))) {
    $env:CP_ROOT = $envCpRoot
} elseif (Test-ControlPanelRoot $defaultCpRoot) {
    if ($envCpRoot) {
        Write-Host "[warn] CP_ROOT=$envCpRoot is not a Control Panel tree (missing backend/ or frontend/), or it sits under a stale TALOS_ROOT."
        Write-Host "[warn] Ignoring stale CP_ROOT and using $defaultCpRoot"
    }
    $env:CP_ROOT = $defaultCpRoot
} elseif ($envCpRoot) {
    $env:CP_ROOT = $envCpRoot
} else {
    $env:CP_ROOT = $defaultCpRoot
}

if (-not $env:CP_BACKEND_PORT) { $env:CP_BACKEND_PORT = "8420" }
if (-not $env:CP_FRONTEND_PORT) { $env:CP_FRONTEND_PORT = "5173" }
if (-not $env:TALOS_HOME) { $env:TALOS_HOME = Join-Path $env:USERPROFILE ".talos" }

$defaultTalosVenv = Join-Path $env:TALOS_ROOT ".venv"
$envTalosVenv = $env:TALOS_VENV
if ($remappedTalosRoot -and $envTalosVenv -and (Test-IsUnderPath $envTalosVenv $envTalosRoot)) {
    Write-Host "[warn] TALOS_VENV=$envTalosVenv is under stale TALOS_ROOT."
    Write-Host "[warn] Ignoring stale TALOS_VENV and using $defaultTalosVenv"
    $env:TALOS_VENV = $defaultTalosVenv
} elseif (-not $env:TALOS_VENV) {
    $env:TALOS_VENV = $defaultTalosVenv
}
# Slow Windows/VDI: CLI cold-start + large IV/attack enqueue need a long budget.
if (-not $env:TALOS_CP_CLI_TIMEOUT) { $env:TALOS_CP_CLI_TIMEOUT = "600" }

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
# Helpers
# ---------------------------------------------------------------------------

function Get-LastExitCodeSafe {
    # StrictMode: $LASTEXITCODE may be unset until a native command runs.
    if (Test-Path Variable:LASTEXITCODE) {
        return [int]$LASTEXITCODE
    }
    return 0
}

function Invoke-Native {
    <#
      Run an external executable. Never treats stderr as a terminating error.
      Throws only on non-zero exit code (with a clear message).

      Always pass args via -ArgumentList @(...). Do NOT use remaining-args
      style like: Invoke-Native $py -m pip ...
      PowerShell binds -m as a parameter name and fails before the process starts.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [object[]]$ArgumentList = @()
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($null -eq $ArgumentList) { $ArgumentList = @() }
        if ($ArgumentList.Count -eq 0) {
            & $FilePath
        } else {
            & $FilePath @ArgumentList
        }
        $code = Get-LastExitCodeSafe
        if ($code -ne 0) {
            $joined = ($ArgumentList | ForEach-Object { "$_" }) -join " "
            throw "Command failed (exit $code): $FilePath $joined".Trim()
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

function Test-PythonImport {
    <#
      Probe imports without ever throwing or polluting the PowerShell error stream.

      Why not bare & $py -c ... ?
        PowerShell ErrorAction Stop turns Python stderr (tracebacks) into
        terminating errors whose Message is only the first line.

      Why not Start-Process -WindowStyle Hidden -NoNewWindow ?
        Those two parameters are mutually exclusive on Windows PowerShell —
        Start-Process throws InvalidOperationException and the probe always
        "fails", even when the package is installed. That was the root cause
        of:  talos install finished but 'import httpx' still fails

      Use ProcessStartInfo with redirected stdio + CreateNoWindow instead.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PythonExe,
        [Parameter(Mandatory = $true)][string]$Code
    )
    if (-not (Test-Path -LiteralPath $PythonExe)) { return $false }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $PythonExe
        # ProcessStartInfo.Arguments is a single string (PS 5.1 / .NET Framework).
        # Quote the -c payload so commas/spaces in import lists are preserved.
        $escaped = $Code.Replace('\', '\\').Replace('"', '\"')
        $psi.Arguments = "-c `"$escaped`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = [System.IO.Path]::GetTempPath()

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        # Drain both streams before WaitForExit to avoid pipe deadlocks.
        $null = $proc.StandardOutput.ReadToEnd()
        $null = $proc.StandardError.ReadToEnd()
        if (-not $proc.WaitForExit(120000)) {
            try { $proc.Kill() } catch { }
            return $false
        }
        return ($proc.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Get-ListeningPids {
    param([Parameter(Mandatory = $true)][int]$Port)
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($conns) {
            foreach ($c in @($conns)) {
                if ($c.OwningProcess -gt 0) { [void]$set.Add([int]$c.OwningProcess) }
            }
        }
    } catch {
        # Fallback: netstat parsing (works without Get-NetTCPConnection)
        # Example: TCP    127.0.0.1:8420    0.0.0.0:0    LISTENING    12345
        $pattern = ":$Port\s+\S+\s+LISTENING\s+(\d+)"
        $ErrorActionPreference = "Continue"
        $lines = & netstat.exe -ano -p tcp 2>$null
        foreach ($line in @($lines)) {
            if ($line -match $pattern) {
                $pidVal = [int]$Matches[1]
                if ($pidVal -gt 0) { [void]$set.Add($pidVal) }
            }
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
    return @($set)
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    if ($ProcessId -le 0) { return }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # /T kills the whole tree; ignore errors if already gone
        & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

function Stop-PortListeners {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [string]$Label = "port"
    )
    $owners = @(Get-ListeningPids -Port $Port)
    if ($owners.Count -eq 0) { return }
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
        throw "TALOS_ROOT does not look like the Talos repo: $TalosRoot (expected pyproject.toml). Unset TALOS_ROOT if a stale User/System env var is pointing at an old extract (often ...\talos-main), or set it to the clone that contains this script."
    }
    if (-not (Test-Path $CpBackendDir)) {
        throw "Control panel backend not found: $CpBackendDir. Unset CP_ROOT if a stale User/System env var is pointing at an old extract (often ...\talos-main\talos-control-panel)."
    }
    if (-not (Test-Path $CpFrontendDir)) {
        throw "Control panel frontend not found: $CpFrontendDir. Unset CP_ROOT if a stale User/System env var is pointing at an old extract."
    }

    foreach ($bin in @("python", "node", "npm")) {
        if (-not (Test-CommandExists $bin)) {
            throw "'$bin' not found in PATH. Install it and re-open this terminal."
        }
    }

    # Resolve python launcher once (Windows often has py/python/python3).
    $pythonCmd = $null
    foreach ($cand in @("python", "py", "python3")) {
        if (Test-CommandExists $cand) {
            $pythonCmd = $cand
            break
        }
    }
    if (-not $pythonCmd) {
        throw "'python' not found in PATH"
    }

    # ---- 1. Talos core venv ----
    # Do NOT use bare `import talos` as readiness: started from the repo root,
    # cwd is on sys.path and the source tree imports without pip (deps missing).
    if (-not (Test-Path -LiteralPath $TalosPy)) {
        Write-Host "[setup] Creating Talos venv at $TalosVenv"
        Invoke-Native -FilePath $pythonCmd -ArgumentList @("-m", "venv", $TalosVenv)
        if (-not (Test-Path -LiteralPath $TalosPy)) {
            throw "venv created but python not found at $TalosPy"
        }
        Write-Host "[setup] Upgrading pip in Talos venv"
        Invoke-Native -FilePath $TalosPy -ArgumentList @("-m", "pip", "install", "--upgrade", "pip")
    }

    $talosExe = Join-Path $TalosVenv "Scripts\talos.exe"
    $needTalos = $false
    if (-not (Test-Path -LiteralPath $talosExe)) { $needTalos = $true }
    if (-not (Test-PythonImport -PythonExe $TalosPy -Code "import httpx")) { $needTalos = $true }

    if ($needTalos) {
        Write-Host "[setup] Installing talos package (editable) from $TalosRoot"
        Write-Host "[setup]   This can take a few minutes on first run..."
        Invoke-Native -FilePath $TalosPy -ArgumentList @("-m", "pip", "install", "-e", $TalosRoot)
        if (-not (Test-PythonImport -PythonExe $TalosPy -Code "import httpx")) {
            throw "talos install finished but 'import httpx' still fails in $TalosPy"
        }
        Write-Host "[setup] Talos package installed"
    } else {
        Write-Host "[setup] Talos venv OK"
    }

    # ---- 2. Control panel backend venv ----
    if (-not (Test-Path -LiteralPath $CpPy)) {
        Write-Host "[setup] Creating control panel backend venv"
        Invoke-Native -FilePath $pythonCmd -ArgumentList @("-m", "venv", $CpBackendVenv)
        if (-not (Test-Path -LiteralPath $CpPy)) {
            throw "backend venv created but python not found at $CpPy"
        }
        Write-Host "[setup] Upgrading pip in backend venv"
        Invoke-Native -FilePath $CpPy -ArgumentList @("-m", "pip", "install", "--upgrade", "pip")
    }

    if (-not (Test-PythonImport -PythonExe $CpPy -Code "import fastapi, uvicorn, httpx")) {
        $req = Join-Path $CpBackendDir "requirements.txt"
        if (-not (Test-Path -LiteralPath $req)) {
            throw "backend requirements.txt not found: $req"
        }
        Write-Host "[setup] Installing control panel backend dependencies"
        Invoke-Native -FilePath $CpPy -ArgumentList @("-m", "pip", "install", "-r", $req)
        if (-not (Test-PythonImport -PythonExe $CpPy -Code "import fastapi, uvicorn, httpx")) {
            throw "backend install finished but 'import fastapi, uvicorn, httpx' still fails in $CpPy"
        }
        Write-Host "[setup] Backend dependencies installed"
    } else {
        Write-Host "[setup] Control panel backend venv OK"
    }

    # ---- 3. Frontend deps ----
    if (-not (Test-Path (Join-Path $CpFrontendDir "node_modules"))) {
        Write-Host "[setup] Installing frontend dependencies (npm install)"
        $npmExe = $null
        $npmCmdInfo = Get-Command npm.cmd -ErrorAction SilentlyContinue
        if ($npmCmdInfo) { $npmExe = $npmCmdInfo.Source }
        if (-not $npmExe) {
            $npmCmdInfo = Get-Command npm -ErrorAction Stop
            $npmExe = $npmCmdInfo.Source
        }
        Push-Location $CpFrontendDir
        try {
            Invoke-Native -FilePath $npmExe -ArgumentList @("install")
        } finally {
            Pop-Location
        }
        Write-Host "[setup] Frontend dependencies installed"
    } else {
        Write-Host "[setup] Frontend node_modules OK"
    }
}

function Format-ErrorRecord {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return "(unknown error)" }
    $lines = New-Object System.Collections.Generic.List[string]
    $msg = $ErrorRecord.Exception.Message
    if ($msg) { [void]$lines.Add($msg) }
    if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.PositionMessage) {
        [void]$lines.Add($ErrorRecord.InvocationInfo.PositionMessage)
    }
    if ($ErrorRecord.ScriptStackTrace) {
        [void]$lines.Add("Script stack:")
        [void]$lines.Add($ErrorRecord.ScriptStackTrace)
    }
    # If the exception wrapped a multi-line native/python failure, surface it.
    $inner = $ErrorRecord.Exception.InnerException
    while ($inner) {
        [void]$lines.Add("Inner: $($inner.Message)")
        $inner = $inner.InnerException
    }
    return ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$script:JobHandle = [IntPtr]::Zero
$script:FrontendProc = $null
$script:BackendProc = $null
$script:CleaningUp = $false
$script:ExitCode = 0

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
        try { [void][TalosJobObject]::CloseHandle($script:JobHandle) } catch { }
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
        Write-Host "[warn] Could not create Job Object (orphans on terminal close still possible): $($_.Exception.Message)"
        $script:JobHandle = [IntPtr]::Zero
    }

    if (Test-Path $FrontendLog) { Remove-Item $FrontendLog -Force -ErrorAction SilentlyContinue }
    if (Test-Path $FrontendErrLog) { Remove-Item $FrontendErrLog -Force -ErrorAction SilentlyContinue }

    Write-Host "[run] Starting frontend in background (logs -> $FrontendLog)"
    $npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npmCmd) { $npmCmd = Get-Command npm -ErrorAction Stop }
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
            Write-Host "[warn] Could not assign frontend to job: $($_.Exception.Message)"
        }
    }

    Write-Host "[run] Starting backend on port $CpBackendPort - press Ctrl+C to stop everything"
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
            Write-Host "[warn] Could not assign backend to job: $($_.Exception.Message)"
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
        Write-Host "[warn] Frontend did not become ready in time - open $Url manually"
    } -ArgumentList $frontendUrl

    # Wait for backend; Ctrl+C aborts the wait and runs finally cleanup.
    # Polling avoids Start-Process -Wait quirks with console signals.
    while ($script:BackendProc -and -not $script:BackendProc.HasExited) {
        Start-Sleep -Milliseconds 400
        try { $script:BackendProc.Refresh() } catch { break }
    }

    if ($script:BackendProc -and $script:BackendProc.HasExited -and $script:BackendProc.ExitCode -ne 0) {
        $script:ExitCode = [int]$script:BackendProc.ExitCode
        Write-Host "[error] Backend exited with code $script:ExitCode" -ForegroundColor Red
        if (Test-Path $FrontendErrLog) {
            Write-Host "[error] Frontend stderr (last 30 lines):" -ForegroundColor Red
            Get-Content $FrontendErrLog -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        }
    }

    if ($opener) {
        Stop-Job $opener -ErrorAction SilentlyContinue
        Remove-Job $opener -Force -ErrorAction SilentlyContinue
    }
} catch {
    $script:ExitCode = 1
    Write-Host "[error] $(Format-ErrorRecord $_)" -ForegroundColor Red
} finally {
    Invoke-Shutdown
}

exit $script:ExitCode
