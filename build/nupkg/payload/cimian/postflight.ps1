# ReportMate Cimian Postflight Script

Write-Host "ReportMate Cimian postflight starting..."

try {
    $reportMateExe = "C:\Program Files\ReportMate\runner.exe"

    if (Test-Path $reportMateExe) {
        Write-Host "Running ReportMate installs module..."
        
        # Use PowerShell invoke operator with proper quoting format - suppress verbose output
        & 'C:\Program Files\ReportMate\runner.exe' --run-module installs | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "ReportMate execution completed successfully" -ForegroundColor Green
        } else {
            Write-Warning "ReportMate execution failed with exit code: $LASTEXITCODE"
        }
    } else {
        Write-Error "ReportMate executable not found at: $reportMateExe"
        exit 1
    }
} catch {
    Write-Error "ReportMate postflight failed: $_"
    exit 1
}

Write-Host "ReportMate postflight completed"