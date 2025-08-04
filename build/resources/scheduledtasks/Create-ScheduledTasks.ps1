#Requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    Creates scheduled tasks for ReportMate module collection
    
.DESCRIPTION
    Sets up Windows scheduled tasks for different ReportMate modules with optimized schedules:
    - Hourly: security, installs, profiles (frequently changing data)
    - Daily: hardware, management, system, network, applications, inventory, displays, printers
    
.PARAMETER ExecutablePath
    Path to the ReportMate runner.exe executable
    
.PARAMETER Remove
    Remove all ReportMate scheduled tasks instead of creating them
    
.PARAMETER DryRun
    Show what tasks would be created without actually creating them
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExecutablePath = "C:\Program Files\ReportMate\runner.exe",
    
    [switch]$Remove = $false,
    [switch]$DryRun = $false
)

$ErrorActionPreference = "Stop"

# Task definitions based on module-schedules.json
$HourlyModules = @(
    @{ Name = "security"; Description = "Security status and threat monitoring"; Offset = 0 }
    @{ Name = "installs"; Description = "Software installation tracking"; Offset = 5 }
    @{ Name = "profiles"; Description = "Configuration and policy changes"; Offset = 10 }
)

$DailyModules = @(
    @{ Name = "hardware"; Description = "Physical hardware inventory"; Offset = 0 }
    @{ Name = "management"; Description = "Device management and enrollment status"; Offset = 15 }
    @{ Name = "system"; Description = "Operating system and configuration"; Offset = 30 }
    @{ Name = "network"; Description = "Network interfaces and connectivity"; Offset = 45 }
    @{ Name = "applications"; Description = "Installed applications and processes"; Offset = 60 }
    @{ Name = "inventory"; Description = "Device identification and assets"; Offset = 75 }
    @{ Name = "displays"; Description = "Display hardware and configuration"; Offset = 90 }
    @{ Name = "printers"; Description = "Printer hardware and configuration"; Offset = 105 }
)

function Write-Status {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Remove-ReportMateTasks {
    Write-Status "Removing all ReportMate scheduled tasks..."
    
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "ReportMate*" }
    
    if ($tasks.Count -eq 0) {
        Write-Status "No ReportMate tasks found to remove" -Level "Warning"
        return
    }
    
    foreach ($task in $tasks) {
        if ($DryRun) {
            Write-Status "[DRY RUN] Would remove task: $($task.TaskName)"
        } else {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
                Write-Status "Removed task: $($task.TaskName)" -Level "Success"
            } catch {
                Write-Status "Failed to remove task $($task.TaskName): $($_.Exception.Message)" -Level "Error"
            }
        }
    }
}

function New-ModuleTask {
    param(
        [string]$ModuleName,
        [string]$Description,
        [string]$Schedule,
        [DateTime]$StartTime,
        [TimeSpan]$RepetitionInterval = $null
    )
    
    $taskName = "ReportMate $($ModuleName.Substring(0,1).ToUpper())$($ModuleName.Substring(1)) Collection"
    $arguments = "--run-module $ModuleName --transmit-only"
    
    if ($DryRun) {
        Write-Status "[DRY RUN] Would create task: $taskName"
        Write-Status "[DRY RUN]   Schedule: $Schedule at $($StartTime.ToString('HH:mm:ss'))"
        Write-Status "[DRY RUN]   Command: `"$ExecutablePath`" $arguments"
        if ($RepetitionInterval) {
            Write-Status "[DRY RUN]   Repeat: Every $($RepetitionInterval.TotalHours) hours"
        }
        return
    }
    
    try {
        # Create the scheduled task action
        $action = New-ScheduledTaskAction -Execute $ExecutablePath -Argument $arguments -WorkingDirectory (Split-Path $ExecutablePath)
        
        # Create the trigger
        if ($RepetitionInterval) {
            # Hourly tasks
            $trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
            $trigger.Repetition = New-ScheduledTaskTrigger -Once -At $StartTime -RepetitionInterval $RepetitionInterval -RepetitionDuration ([TimeSpan]::FromDays(1))
        } else {
            # Daily tasks
            $trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
        }
        
        # Create task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        
        # Create the principal (run as SYSTEM)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "ReportMate: $Description" -Force
        
        Write-Status "Created task: $taskName" -Level "Success"
        
    } catch {
        Write-Status "Failed to create task $taskName`: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function New-ReportMateTasks {
    Write-Status "Creating ReportMate scheduled tasks..."
    
    # Verify executable exists
    if (-not (Test-Path $ExecutablePath)) {
        throw "ReportMate executable not found at: $ExecutablePath"
    }
    
    Write-Status "Using ReportMate executable: $ExecutablePath"
    
    # Create hourly tasks (security, installs, profiles)
    Write-Status "Creating hourly collection tasks..."
    $hourlyInterval = [TimeSpan]::FromHours(1)
    
    foreach ($module in $HourlyModules) {
        $startTime = [DateTime]::Today.AddMinutes($module.Offset)
        New-ModuleTask -ModuleName $module.Name -Description $module.Description -Schedule "Hourly" -StartTime $startTime -RepetitionInterval $hourlyInterval
    }
    
    # Create daily tasks
    Write-Status "Creating daily collection tasks..."
    $baseTime = [DateTime]::Today.AddHours(8) # 8:00 AM
    
    foreach ($module in $DailyModules) {
        $startTime = $baseTime.AddMinutes($module.Offset)
        New-ModuleTask -ModuleName $module.Name -Description $module.Description -Schedule "Daily" -StartTime $startTime
    }
}

# Main execution
try {
    Write-Status "ReportMate Scheduled Task Manager"
    Write-Status "================================="
    
    if ($Remove) {
        Remove-ReportMateTasks
    } else {
        New-ReportMateTasks
    }
    
    if (-not $DryRun) {
        Write-Status "Operation completed successfully!" -Level "Success"
        Write-Status "Use 'Get-ScheduledTask | Where-Object { `$_.TaskName -like `"ReportMate*`" }' to view created tasks"
    }
    
} catch {
    Write-Status "Operation failed: $($_.Exception.Message)" -Level "Error"
    exit 1
}
