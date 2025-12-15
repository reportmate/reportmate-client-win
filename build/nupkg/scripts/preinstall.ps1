# ReportMate Pre-Installation Script
# Prepares the system for ReportMate installation

$ErrorActionPreference = "Continue"

Write-Host "ReportMate Pre-Installation Script"
Write-Host "================================================="

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warning "Installation should be run as Administrator for full functionality"
}

# Check Windows version
$WindowsVersion = [System.Environment]::OSVersion.Version
if ($WindowsVersion.Major -lt 6 -or ($WindowsVersion.Major -eq 6 -and $WindowsVersion.Minor -lt 1)) {
    Write-Error "Windows 7 or later is required"
    exit 1
}

Write-Host "Windows version check passed: $($WindowsVersion.ToString())"

# Check .NET runtime (this should be included in self-contained build)
try {
    $DotNetVersion = & dotnet --version 2>$null
    if ($DotNetVersion) {
        Write-Host ".NET runtime detected: $DotNetVersion"
    }
} catch {
    Write-Host ".NET runtime not detected (using self-contained executable)"
}

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

# Check available disk space
$SystemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
$FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
$RequiredSpaceGB = 0.5  # 500MB minimum

if ($FreeSpaceGB -lt $RequiredSpaceGB) {
    Write-Error "Insufficient disk space. Required: ${RequiredSpaceGB}GB, Available: ${FreeSpaceGB}GB"
    exit 1
}

Write-Host "Disk space check passed: ${FreeSpaceGB}GB available"

# Check network connectivity (if API URL is provided)
$ApiUrl = $env:REPORTMATE_API_URL
if (-not [string]::IsNullOrEmpty($ApiUrl)) {
    try {
        $Uri = [System.Uri]::new($ApiUrl)
        $TestConnection = Test-NetConnection -ComputerName $Uri.Host -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
        if ($TestConnection) {
            Write-Host "Network connectivity test passed for: $($Uri.Host)"
        } else {
            Write-Warning "Unable to connect to API endpoint: $($Uri.Host)"
        }
    } catch {
        Write-Warning "Unable to test API connectivity: $_"
    }
}

# Remove old installation if it exists
$OldInstallPath = "C:\Program Files\ReportMate"
if (Test-Path $OldInstallPath) {
    Write-Host "Removing existing installation..."
    try {
        # Stop services if any
        Get-Service -Name "*ReportMate*" -ErrorAction SilentlyContinue | Stop-Service -Force
        
        # Remove files (but preserve data)
        Remove-Item -Path $OldInstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed existing installation"
    } catch {
        Write-Warning "Failed to completely remove existing installation: $_"
    }
}

Write-Host "Pre-installation script completed successfully"
