# ReportMate MSI - Uninstall Scheduled Tasks
# This script removes Windows scheduled tasks for ReportMate

Write-Host "Removing ReportMate scheduled tasks..."

# Tasks are deleted by exact name through the Task Scheduler COM API.
# Get-ScheduledTask -TaskName and Unregister-ScheduledTask enumerate the whole
# store underneath, and one broken entry anywhere in it (another product's
# task whose definition file is gone) makes them throw. Keep the name list in
# step with install-tasks.ps1.
$taskNames = @(
    "ReportMate Hourly Collection",
    "ReportMate 4-Hourly Collection",
    "ReportMate Daily Collection",
    "ReportMate All Modules Collection",
    "ReportMate User Session Tracker",
    # Retired names an older build may have left behind
    "ReportMate Data Collection",
    "ReportMate Data Transmission",
    "ReportMate Usage Tracker"
)

try {
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    $folder = $service.GetFolder('\')

    foreach ($taskName in $taskNames) {
        try {
            $folder.DeleteTask($taskName, 0)
            Write-Host "Removed scheduled task: $taskName"
        } catch {
            # 0x80070002 is "no task by that name".
            if ($_.Exception.HResult -eq -2147024894) {
                Write-Host "Task not found (already removed): $taskName"
            } else {
                Write-Warning "Failed to remove task '$taskName': $_"
            }
        }
    }

    Write-Host "ReportMate scheduled tasks cleanup completed"

} catch {
    Write-Error "Failed to remove scheduled tasks: $_"
    # Don't exit with error during uninstall to avoid blocking removal
}
