# ReportMate Manual Installation Script
# Run this script as Administrator
#
# This script is for manual/development installation only.
# For production deployment, use the MSI or Chocolatey package from build.ps1

#Requires -RunAsAdministrator

param(
    [string]$ApiUrl = "https://reportmate.ecuad.ca",
    [string]$SourcePath = ".\dist",
    [switch]$SkipOsquery
)

$ErrorActionPreference = "Stop"

Write-Host "Installing ReportMate Windows Client..." -ForegroundColor Green
Write-Host "API URL: $ApiUrl" -ForegroundColor Cyan

# Verify source files exist
$runnerPath = Join-Path $SourcePath "runner.exe"
$configPath = Join-Path $SourcePath "appsettings.yaml"

if (-not (Test-Path $runnerPath)) {
    # Try alternate locations
    $altPaths = @(
        ".\.publish\runner.exe",
        ".\build\publish\runner.exe",
        ".\src\bin\Release\net8.0-windows\win-x64\publish\runner.exe"
    )
    foreach ($alt in $altPaths) {
        if (Test-Path $alt) {
            $runnerPath = $alt
            break
        }
    }
}

if (-not (Test-Path $runnerPath)) {
    Write-Error "runner.exe not found. Build the project first with: .\build.ps1 -Sign"
    exit 1
}

# Create Program Files directory
Write-Host "Creating installation directory..." -ForegroundColor Yellow
try {
    New-Item -ItemType Directory -Path "C:\Program Files\ReportMate" -Force | Out-Null
    Copy-Item $runnerPath "C:\Program Files\ReportMate\" -Force
    Write-Host "[OK] Executable installed to C:\Program Files\ReportMate\runner.exe" -ForegroundColor Green
} catch {
    Write-Error "Failed to install executable: $_"
    exit 1
}

# Create ProgramData directories
Write-Host "Creating data directories..." -ForegroundColor Yellow
$dirs = @(
    "C:\ProgramData\ManagedReports",
    "C:\ProgramData\ManagedReports\logs",
    "C:\ProgramData\ManagedReports\cache",
    "C:\ProgramData\ManagedReports\config"
)
foreach ($dir in $dirs) {
    try {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[OK] Created: $dir" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create directory ${dir}: $_"
    }
}

# Copy or create configuration file
Write-Host "Installing configuration..." -ForegroundColor Yellow
$destConfig = "C:\ProgramData\ManagedReports\appsettings.yaml"

if (Test-Path $configPath) {
    Copy-Item $configPath $destConfig -Force
} elseif (Test-Path ".\src\appsettings.yaml") {
    Copy-Item ".\src\appsettings.yaml" $destConfig -Force
} else {
    # Create minimal configuration
    @"
ReportMate:
  ApiUrl: "$ApiUrl"
  Passphrase: ""
  CollectionIntervalSeconds: 3600
  OsQueryPath: "C:\\Program Files\\osquery\\osqueryi.exe"
  DataDirectory: "C:\\ProgramData\\ManagedReports"
  LogDirectory: "C:\\ProgramData\\ManagedReports\\logs"
  CacheDirectory: "C:\\ProgramData\\ManagedReports\\cache"
"@ | Set-Content $destConfig
}

# Update API URL in configuration
try {
    $config = Get-Content $destConfig -Raw
    $config = $config -replace 'ApiUrl:\s*"[^"]*"', "ApiUrl: `"$ApiUrl`""
    Set-Content $destConfig $config
    Write-Host "[OK] Configuration installed with API URL: $ApiUrl" -ForegroundColor Green
} catch {
    Write-Warning "Failed to update configuration: $_"
}

# Install osquery
if (-not $SkipOsquery) {
    Write-Host "Installing osquery..." -ForegroundColor Yellow
    try {
        $null = winget install osquery.osquery --silent --accept-package-agreements --accept-source-agreements 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] osquery installed successfully" -ForegroundColor Green
        } else {
            Write-Warning "winget install returned non-zero exit code"
            Write-Host "[INFO] Install osquery manually from: https://osquery.io/downloads/official" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "Failed to install osquery: $_"
        Write-Host "[INFO] Install osquery manually from: https://osquery.io/downloads/official" -ForegroundColor Cyan
    }
}

# Create scheduled task
Write-Host "Creating scheduled task..." -ForegroundColor Yellow
try {
    $existingTask = Get-ScheduledTask -TaskName "ReportMate Data Collection" -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName "ReportMate Data Collection" -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "C:\Program Files\ReportMate\runner.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "ReportMate Data Collection" -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    Write-Host "[OK] Scheduled task created" -ForegroundColor Green
} catch {
    Write-Warning "Failed to create scheduled task: $_"
}

# Test the installation
Write-Host "Testing installation..." -ForegroundColor Yellow
try {
    $testResult = & "C:\Program Files\ReportMate\runner.exe" version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Installation test successful" -ForegroundColor Green
        Write-Host $testResult -ForegroundColor Cyan
    } else {
        Write-Warning "Installation test returned non-zero exit code"
    }
} catch {
    Write-Warning "Failed to test installation: $_"
}

Write-Host ""
Write-Host "ReportMate installation completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. View system info:"
Write-Host "   & 'C:\Program Files\ReportMate\runner.exe' info" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Test data collection:"
Write-Host "   sudo pwsh -c `"& 'C:\Program Files\ReportMate\runner.exe' -vv --collect-only`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Transmit data:"
Write-Host "   sudo pwsh -c `"& 'C:\Program Files\ReportMate\runner.exe' -vv --transmit-only`"" -ForegroundColor Cyan
