# ReportMate MSI - Uninstall Scheduled Tasks
# This script removes Windows scheduled tasks for ReportMate

Write-Host "Removing ReportMate scheduled tasks..."

try {
    $taskNames = @(
        "ReportMate Hourly Collection",
        "ReportMate 4-Hourly Collection", 
        "ReportMate Daily Collection",
        "ReportMate All Modules Collection"
    )
    
    foreach ($taskName in $taskNames) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Host "✅ Removed scheduled task: $taskName"
            } else {
                Write-Host "ℹ️  Task not found (already removed): $taskName"
            }
        } catch {
            Write-Warning "Failed to remove task '$taskName': $_"
        }
    }
    
    Write-Host "✅ ReportMate scheduled tasks cleanup completed"
    
} catch {
    Write-Error "Failed to remove scheduled tasks: $_"
    # Don't exit with error during uninstall to avoid blocking removal
}
