# ReportMate Cimian Postflight Script
# This script runs after Cimian installation to execute ReportMate

param(
    [string]$ApiUrl = $env:REPORTMATE_API_URL
)

Write-Host "ReportMate Cimian postflight script starting..."

try {
    $reportMateExe = "C:\Program Files\ReportMate\runner.exe"
    
    if (Test-Path $reportMateExe) {
        Write-Host "Found ReportMate executable: $reportMateExe"
        
        # Configure API URL if provided
        if ($ApiUrl) {
            Write-Host "Configuring API URL: $ApiUrl"
            & $reportMateExe install --api-url $ApiUrl
        }
        
        # Test the installation
        Write-Host "Testing ReportMate installation..."
        & $reportMateExe test
        
        Write-Host "ReportMate postflight completed successfully"
    } else {
        Write-Error "ReportMate executable not found at: $reportMateExe"
        exit 1
    }
} catch {
    Write-Error "ReportMate postflight failed: $_"
    exit 1
}
