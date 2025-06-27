# ReportMate Windows Client Pre-Installation Script
# Prepares the system for ReportMate installation

$ErrorActionPreference = "Continue"

Write-Host "ReportMate Windows Client Pre-Installation Script"
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

# Stop any existing ReportMate processes
$ReportMateProcesses = Get-Process -Name "runner" -ErrorAction SilentlyContinue
if ($ReportMateProcesses) {
    Write-Host "Stopping existing ReportMate processes..."
    $ReportMateProcesses | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Check for conflicting software (optional)
$ConflictingProcesses = @("munki", "jamf")
foreach ($ProcessName in $ConflictingProcesses) {
    $Process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if ($Process) {
        Write-Warning "Detected potentially conflicting software: $ProcessName"
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
