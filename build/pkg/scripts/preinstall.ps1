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