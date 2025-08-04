# ReportMate Task Scheduler Setup Script
# Creates Windows scheduled tasks based on module schedules
# Supports differentiated scheduling for different module types

param(
    [string]$ExecutablePath = "C:\Program Files\ReportMate\runner.exe",
    [string]$ScheduleConfigPath = "",
    [switch]$RemoveExisting = $false,
    [switch]$Silent = $false
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if (-not $Silent) {
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

Write-Log "ReportMate Task Scheduler Setup Started"

# Load schedule configuration
if ($ScheduleConfigPath -and (Test-Path $ScheduleConfigPath)) {
    try {
        $scheduleConfig = Get-Content $ScheduleConfigPath -Raw | ConvertFrom-Json
        Write-Log "Loaded schedule configuration from: $ScheduleConfigPath"
    } catch {
        Write-Log "Error loading schedule configuration: $($_.Exception.Message)" "ERROR"
        return
    }
} else {
    # Default configuration if file not found
    $scheduleConfig = @{
        schedules = @{
            hourly = @{
                modules = @("security", "installs", "profiles", "system", "network")
                interval_minutes = 60
                description = "Modules that need frequent updates for security and configuration monitoring"
            }
            every_4_hours = @{
                modules = @("applications", "inventory")
                interval_minutes = 240
                description = "Modules that change moderately - software installs and basic device info"
            }
            daily = @{
                modules = @("hardware", "management", "printers", "displays")
                interval_minutes = 1440
                description = "Modules that rarely change - physical hardware and peripheral devices"
            }
        }
        task_settings = @{
            start_boundary = "2025-01-01T09:00:00"
            execution_time_limit = "PT30M"
            restart_count = 3
            restart_interval = "PT5M"
            run_only_if_network_available = $true
            wake_to_run = $false
            allow_start_on_demand = $true
            stop_if_going_on_batteries = $false
            disallow_start_if_on_batteries = $false
        }
    }
    Write-Log "Using default schedule configuration"
}

# Remove existing tasks if requested
if ($RemoveExisting) {
    $taskNames = @(
        "ReportMate Hourly Collection",
        "ReportMate 4-Hourly Collection", 
        "ReportMate Daily Collection",
        "ReportMate Data Transmission"
    )
    
    foreach ($taskName in $taskNames) {
        try {
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Log "Removed existing task: $taskName"
            }
        } catch {
            Write-Log "Warning: Could not remove task $taskName - $($_.Exception.Message)" "WARN"
        }
    }
}

# Create tasks for each schedule type
foreach ($scheduleType in $scheduleConfig.schedules.PSObject.Properties) {
    $schedule = $scheduleType.Value
    $modulesString = $schedule.modules -join ","
    
    $taskName = switch ($scheduleType.Name) {
        "hourly" { "ReportMate Hourly Collection" }
        "every_4_hours" { "ReportMate 4-Hourly Collection" }
        "daily" { "ReportMate Daily Collection" }
        default { "ReportMate $($scheduleType.Name) Collection" }
    }
    
    Write-Log "Creating task: $taskName"
    Write-Log "  Modules: $modulesString"
    Write-Log "  Interval: $($schedule.interval_minutes) minutes"
    
    # Create trigger based on interval
    $triggerParams = @{
        Once = $true
        At = [DateTime]::Parse($scheduleConfig.task_settings.start_boundary)
    }
    
    if ($schedule.interval_minutes -eq 60) {
        $triggerParams.RepetitionInterval = New-TimeSpan -Hours 1
        $triggerParams.RepetitionDuration = [TimeSpan]::MaxValue
    } elseif ($schedule.interval_minutes -eq 240) {
        $triggerParams.RepetitionInterval = New-TimeSpan -Hours 4
        $triggerParams.RepetitionDuration = [TimeSpan]::MaxValue
    } elseif ($schedule.interval_minutes -eq 1440) {
        $triggerParams.Daily = $true
        $triggerParams.DaysInterval = 1
        $triggerParams.Remove("Once")
        $triggerParams.Remove("RepetitionInterval") 
        $triggerParams.Remove("RepetitionDuration")
    }
    
    $trigger = New-ScheduledTaskTrigger @triggerParams
    
    # Create action
    $arguments = "--collect-only --run-modules $modulesString"
    $action = New-ScheduledTaskAction -Execute $ExecutablePath -Argument $arguments -WorkingDirectory (Split-Path $ExecutablePath)
    
    # Create settings
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::Parse($scheduleConfig.task_settings.execution_time_limit)) `
        -RestartCount $scheduleConfig.task_settings.restart_count `
        -RestartInterval ([TimeSpan]::Parse($scheduleConfig.task_settings.restart_interval)) `
        -RunOnlyIfNetworkAvailable:$scheduleConfig.task_settings.run_only_if_network_available `
        -WakeToRun:$scheduleConfig.task_settings.wake_to_run `
        -AllowStartIfOnDemand:$scheduleConfig.task_settings.allow_start_on_demand `
        -DontStopIfGoingOnBatteries:(-not $scheduleConfig.task_settings.stop_if_going_on_batteries) `
        -DontStopOnIdleEnd
    
    # Create principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Register the task
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $schedule.description -Force
        Write-Log "Successfully created task: $taskName"
    } catch {
        Write-Log "Error creating task $taskName - $($_.Exception.Message)" "ERROR"
    }
}

# Create transmission task (runs 15 minutes after collections)
Write-Log "Creating transmission task"

$transmissionTrigger = New-ScheduledTaskTrigger -Once -At ([DateTime]::Parse($scheduleConfig.task_settings.start_boundary).AddMinutes(15)) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
$transmissionAction = New-ScheduledTaskAction -Execute $ExecutablePath -Argument "--transmit-only" -WorkingDirectory (Split-Path $ExecutablePath)

$transmissionSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2) `
    -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnDemand `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd

$transmissionPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName "ReportMate Data Transmission" -Action $transmissionAction -Trigger $transmissionTrigger -Settings $transmissionSettings -Principal $transmissionPrincipal -Description "Transmits collected data to ReportMate API" -Force
    Write-Log "Successfully created transmission task"
} catch {
    Write-Log "Error creating transmission task - $($_.Exception.Message)" "ERROR"
}

Write-Log "ReportMate Task Scheduler Setup Completed"
