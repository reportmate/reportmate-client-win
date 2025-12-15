# ═══════════════════════════════════════════════════════════════════════════════
# ReportMate Pre-Installation Script - PKG Format
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script runs before ReportMate files are installed. It handles cleanup
# of any existing installation and prepares the system for the new installation.
#
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "ReportMate Pre-Installation Script (PKG Format)"
Write-Host "==============================================="

$ErrorActionPreference = "Continue"

# ═══════════════════════════════════════════════════════════════════════════════
# STOP ALL REPORTMATE PROCESSES - Must complete before file copy
# ═══════════════════════════════════════════════════════════════════════════════

# Function to forcefully stop a process and wait for file release
function Stop-ReportMateProcess {
    param([string]$ProcessName, [string]$BinaryPath)
    
    $maxAttempts = 5
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if (-not $processes) { break }
        
        $attempt++
        Write-Host "Stopping $ProcessName processes (attempt $attempt/$maxAttempts)..."
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    
    # Verify file is not locked
    if ($BinaryPath -and (Test-Path $BinaryPath)) {
        $maxWait = 10
        $waited = 0
        while ($waited -lt $maxWait) {
            try {
                $stream = [System.IO.File]::Open($BinaryPath, 'Open', 'ReadWrite', 'None')
                $stream.Close()
                Write-Host "File $ProcessName.exe is now unlocked"
                return $true
            } catch {
                $waited++
                Write-Host "Waiting for $ProcessName.exe to be released ($waited/$maxWait)..."
                Start-Sleep -Seconds 1
            }
        }
        Write-Warning "File may still be locked after $maxWait seconds"
    }
    return $true
}

# Stop old runner.exe processes
Stop-ReportMateProcess -ProcessName "runner" -BinaryPath "C:\Program Files\ReportMate\runner.exe"

# Stop new managedreportsrunner.exe processes  
Stop-ReportMateProcess -ProcessName "managedreportsrunner" -BinaryPath "C:\Program Files\ReportMate\managedreportsrunner.exe"

# ═══════════════════════════════════════════════════════════════════════════════
# MIGRATION: Forcefully remove old runner.exe binary (renamed to managedreportsrunner.exe)
# ═══════════════════════════════════════════════════════════════════════════════
$OldBinaryPath = "C:\Program Files\ReportMate\runner.exe"

# Forcefully delete the old binary
if (Test-Path $OldBinaryPath) {
    Write-Host "Migration: Forcefully removing old runner.exe binary..."
    try {
        # Try normal deletion first
        Remove-Item $OldBinaryPath -Force -ErrorAction Stop
        Write-Host "Old runner.exe binary removed successfully"
    } catch {
        # If that fails, try taking ownership and removing
        Write-Host "Standard removal failed, attempting forceful removal..."
        try {
            $acl = Get-Acl $OldBinaryPath
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl $OldBinaryPath $acl -ErrorAction SilentlyContinue
            Remove-Item $OldBinaryPath -Force -ErrorAction Stop
            Write-Host "Old runner.exe binary removed with elevated permissions"
        } catch {
            Write-Warning "Could not remove old runner.exe: $_ - Will be cleaned up on next reboot"
            # Schedule deletion on reboot as last resort
            cmd /c "del /f /q `"$OldBinaryPath`"" 2>$null
        }
    }
}

# Stop any running ReportMate scheduled tasks
Write-Host "Stopping any running ReportMate tasks..."
Get-ScheduledTask | Where-Object { 
    $_.TaskName -like "*ReportMate*" -or 
    $_.Description -like "*ReportMate*" -or
    $_.TaskName -like "*Report*Mate*"
} | ForEach-Object {
    if ($_.State -eq "Running") {
        Write-Host "  Stopping task: $($_.TaskName)"
        Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue
    }
}

# Clean up any temporary files or locks
$tempPaths = @(
    "C:\ProgramData\ManagedReports\cache\*.lock",
    "C:\ProgramData\ManagedReports\logs\*.tmp"
)

foreach ($pattern in $tempPaths) {
    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
    if ($files) {
        $files | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "Cleaned temporary files: $pattern"
    }
}

Write-Host "Pre-installation cleanup completed"