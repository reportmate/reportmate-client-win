# ReportMate MSI - Install Scheduled Tasks
# This script creates Windows scheduled tasks for ReportMate data collection

param(
    [string]$InstallPath = "C:\Program Files\ReportMate"
)

Write-Host "Installing ReportMate scheduled tasks..."

try {
    # Load module schedules configuration
    $scheduleConfigPath = Join-Path $InstallPath "module-schedules.json"
    if (Test-Path $scheduleConfigPath) {
        $scheduleConfig = Get-Content $scheduleConfigPath | ConvertFrom-Json
        Write-Host "Loaded module schedules configuration"
    } else {
        Write-Warning "Module schedules configuration not found, using defaults"
        # Default configuration
        $scheduleConfig = @{
            schedules = @{
                hourly = @{
                    interval = "PT1H"
                    modules = @("security", "installs", "profiles", "system", "network")
                }
                every4hours = @{
                    interval = "PT4H" 
                    modules = @("applications", "inventory")
                }
                daily = @{
                    interval = "P1D"
                    modules = @("hardware", "management", "printers", "displays")
                }
            }
        }
    }

    $runnerExe = Join-Path $InstallPath "runner.exe"
    
    # Create hourly collection task
    Write-Host "Creating hourly collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--collect-only --run-modules $($scheduleConfig.schedules.hourly.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -RunOnlyIfNetworkAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName "ReportMate Hourly Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects security-critical device data every hour" -Force
    
    # Create 4-hourly collection task  
    Write-Host "Creating 4-hourly collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--collect-only --run-modules $($scheduleConfig.schedules.every4hours.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours 4)
    
    Register-ScheduledTask -TaskName "ReportMate 4-Hourly Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects moderately changing device data every 4 hours" -Force
    
    # Create daily collection task
    Write-Host "Creating daily collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--collect-only --run-modules $($scheduleConfig.schedules.daily.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
    
    Register-ScheduledTask -TaskName "ReportMate Daily Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects static device data once daily" -Force
    
    # Create transmission task (runs 15 minutes after collections)
    Write-Host "Creating data transmission task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--transmit-only" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At "09:15" -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2) -RunOnlyIfNetworkAvailable
    
    Register-ScheduledTask -TaskName "ReportMate Data Transmission" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Transmits collected data to ReportMate API" -Force
    
    Write-Host "✅ All ReportMate scheduled tasks created successfully"
    
} catch {
    Write-Error "Failed to create scheduled tasks: $_"
    exit 1
}
