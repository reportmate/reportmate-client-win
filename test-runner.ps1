# Test ReportMate Windows Client Configuration
# This script tests the configuration and runs the client

param(
    [string]$ApiUrl = "",
    [switch]$Force = $false
)

Write-Host "=== ReportMate Windows Client Test ===" -ForegroundColor Green

# Get API URL from environment or registry if not provided
if (-not $ApiUrl) {
    # Try to get from registry first
    try {
        $regKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\ReportMate" -Name "ServerUrl" -ErrorAction SilentlyContinue
        if ($regKey) {
            $ApiUrl = $regKey.ServerUrl
            Write-Host "Using API URL from registry: $ApiUrl" -ForegroundColor Green
        }
    } catch {
        # Registry lookup failed, continue
    }
    
    # If still not found, try environment variable
    if (-not $ApiUrl) {
        $ApiUrl = $env:REPORTMATE_API_URL
        if ($ApiUrl) {
            Write-Host "Using API URL from environment: $ApiUrl" -ForegroundColor Green
        }
    }
    
    # If still not found, fail
    if (-not $ApiUrl) {
        Write-Host "❌ No API URL configured. Please either:" -ForegroundColor Red
        Write-Host "  1. Set REPORTMATE_API_URL environment variable" -ForegroundColor Yellow
        Write-Host "  2. Configure via registry (HKLM:\SOFTWARE\Policies\ReportMate\ServerUrl)" -ForegroundColor Yellow
        Write-Host "  3. Pass -ApiUrl parameter" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host "API URL: $ApiUrl" -ForegroundColor Yellow

# Set environment variable for API URL
$env:REPORTMATE_API_URL = $ApiUrl
Write-Host "Set REPORTMATE_API_URL = $($env:REPORTMATE_API_URL)" -ForegroundColor Cyan

# Check if runner.exe exists
$runnerPath = "C:\Program Files\ReportMate\runner.exe"
if (Test-Path $runnerPath) {
    Write-Host "✅ Found runner.exe at $runnerPath" -ForegroundColor Green
} else {
    Write-Host "❌ runner.exe not found at $runnerPath" -ForegroundColor Red
    Write-Host "Please build and copy the signed runner.exe first:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1 -Sign" -ForegroundColor White
    Write-Host "  sudo powershell -Command `"Copy-Item '.\.publish\runner.exe' 'C:\Program Files\ReportMate\runner.exe' -Force`"" -ForegroundColor White
    exit 1
}

# Test configuration
Write-Host "`n=== Testing Configuration ===" -ForegroundColor Green
try {
    if ($Force) {
        Write-Host "Running with --force flag to override recent run check" -ForegroundColor Yellow
        & $runnerPath --force
    } else {
        Write-Host "Running normal collection" -ForegroundColor Yellow
        & $runnerPath
    }
} catch {
    Write-Host "❌ Error running runner.exe: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Green
Write-Host "Check logs in C:\ProgramData\ManagedReports\logs for details" -ForegroundColor Cyan
