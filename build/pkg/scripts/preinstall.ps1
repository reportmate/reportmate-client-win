# ReportMate Pre-Installation Script (cimipkg)
#
# Runs before cimipkg's payload copy. Its job is to leave the install location
# free of any process holding handles on managedreportsrunner.exe or
# usagetracker.exe. osqueryi.exe is also killed (in case the runner spawned
# it as a child) but is not lock-verified -- it lives under
# C:\Program Files\osquery\, not under our install dir, so it cannot block
# payload replacement here.
#
# If a binary stays locked, the MSI engine defers replacement to the next
# reboot via MoveFileEx. ARP and the registry get updated, but the on-disk
# .exe is still the previous build -- and the scheduled task keeps firing
# the old binary indefinitely. That mismatch is the failure mode this
# script exists to prevent.

$ErrorActionPreference = 'Continue'

Write-Host "ReportMate Pre-Installation Script (cimipkg)"
Write-Host "============================================"

$InstallDir = 'C:\Program Files\ReportMate'

# ----------------------------------------------------------------------------
# 1. Disable scheduled tasks first.
#    Stopping a running task does not prevent Task Scheduler from launching
#    it again seconds later, so disable each task before killing processes.
#
#    Every call here is bounded, and that is not defensive padding.
#    Get-ScheduledTask talks to the Task Scheduler service, and on a machine
#    whose scheduler has degraded it never returns. -ErrorAction
#    SilentlyContinue suppresses errors and does nothing whatsoever about a
#    hang. Unbounded, this line stops the whole install: cimipkg has already
#    removed the previous payload by the time a preinstall runs, so the MSI
#    never completes and the machine is left with no managedreportsrunner.exe
#    at all. Observed on a workstation whose scheduler was wedged -- the
#    install sat here for thirty minutes with the binary gone.
#
#    A skipped disable is survivable: the process kill below still frees the
#    file handles, which is what the payload replacement actually needs.
# ----------------------------------------------------------------------------
$taskQueryTimeout = [TimeSpan]::FromSeconds(20)

function Invoke-Bounded {
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string]      $What
    )

    $job = Start-Job -ScriptBlock $Action
    try {
        if (Wait-Job -Job $job -Timeout $taskQueryTimeout.TotalSeconds) {
            return Receive-Job -Job $job -ErrorAction SilentlyContinue
        }

        Write-Host "  Task Scheduler did not answer within $([int]$taskQueryTimeout.TotalSeconds)s; skipping $What and continuing."
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        return $null
    }
    finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

$reportMateTasks = @(Invoke-Bounded -What 'the ReportMate scheduled-task lookup' -Action {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like '*ReportMate*' -or
        $_.Description -like '*ReportMate*' -or
        $_.TaskName -like '*Report*Mate*'
    } | Select-Object TaskName, TaskPath, State
})

foreach ($task in $reportMateTasks) {
    if (-not $task) { continue }

    $state = $task.State
    Invoke-Bounded -What "disabling task '$($task.TaskName)'" -Action {
        Disable-ScheduledTask -TaskName $using:task.TaskName -TaskPath $using:task.TaskPath -ErrorAction SilentlyContinue | Out-Null
        if ($using:state -eq 'Running') {
            Stop-ScheduledTask -TaskName $using:task.TaskName -TaskPath $using:task.TaskPath -ErrorAction SilentlyContinue
        }
    } | Out-Null

    Write-Host "  Disabled task: $($task.TaskName)"
}

# ----------------------------------------------------------------------------
# 2. Kill all ReportMate processes.
#    Stop-Process first (clean). Then taskkill /F /T as the hard fallback:
#    it reaches across user sessions (usagetracker.exe runs in the logged-in
#    user's session, not session 0) and kills child processes such as
#    osqueryi.exe spawned by the runner.
# ----------------------------------------------------------------------------
$processNames = @('managedreportsrunner', 'usagetracker', 'runner', 'Managed Reports Runner')
$exeNames     = @(
    'managedreportsrunner.exe'
    'usagetracker.exe'
    'runner.exe'
    'osqueryi.exe'
    'Managed Reports Runner.exe'
)

foreach ($name in $processNames) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "  Stop-Process: $($procs.Count) $name process(es)"
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2

foreach ($exe in $exeNames) {
    try { & taskkill.exe /F /IM $exe /T 2>$null | Out-Null } catch { }
}
Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# 3. Verify install-dir binaries are unlocked. If anything is still locked
#    after the kill attempts, warn loudly -- the install will succeed but
#    the new binary will not land until reboot.
# ----------------------------------------------------------------------------
function Test-FileUnlocked {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $true }
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $true
    } catch {
        return $false
    }
}

$binariesToVerify = @(
    Join-Path $InstallDir 'managedreportsrunner.exe'
    Join-Path $InstallDir 'usagetracker.exe'
)

foreach ($bin in $binariesToVerify) {
    if (-not (Test-Path $bin)) { continue }
    $name = Split-Path $bin -Leaf
    $waited = 0
    while (-not (Test-FileUnlocked $bin) -and $waited -lt 10) {
        Write-Host "  Waiting for $name to be released ($($waited + 1)/10)..."
        Start-Sleep -Seconds 1
        $waited++
    }
    if (Test-FileUnlocked $bin) {
        Write-Host "  Unlocked: $name"
    } else {
        Write-Warning "  Still locked after 10s: $bin -- MSI may defer file replacement to reboot"
    }
}

# ----------------------------------------------------------------------------
# 4. Legacy migration: remove the old runner.exe (predecessor of
#    managedreportsrunner.exe) so it cannot be invoked again by anything
#    referencing the old path.
# ----------------------------------------------------------------------------
$legacyRunner = Join-Path $InstallDir 'runner.exe'
if (Test-Path $legacyRunner) {
    try {
        Remove-Item $legacyRunner -Force -ErrorAction Stop
        Write-Host "Removed legacy runner.exe"
    } catch {
        Write-Warning "Could not remove legacy runner.exe: $_"
        try { & cmd.exe /c "del /f /q `"$legacyRunner`"" 2>$null } catch { }
    }
}

# ----------------------------------------------------------------------------
# 5. Clean ephemeral cache/lock files
# ----------------------------------------------------------------------------
$tempPatterns = @(
    'C:\ProgramData\ManagedReports\cache\*.lock'
    'C:\ProgramData\ManagedReports\logs\*.tmp'
)
foreach ($pattern in $tempPatterns) {
    Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "Pre-installation cleanup completed"
exit 0
