# ReportMate MSI - Install Scheduled Tasks
# This script creates Windows scheduled tasks for ReportMate data collection

param(
    [string]$InstallPath = "C:\Program Files\ReportMate"
)

Write-Host "Installing ReportMate scheduled tasks..."

function Enable-ReportMateKernelProcessLog {
    param(
        [string[]]$LogNames = @(
            "Microsoft-Windows-Kernel-Process/Analytic",
            "Microsoft-Windows-Kernel-Process/Operational"
        )
    )

    foreach ($logName in $LogNames) {
        Write-Host "Configuring kernel process telemetry log: $logName"

        try {
            & wevtutil gl $logName > $null 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Verbose "Telemetry log not available: $logName"
                continue
            }

            & wevtutil sl $logName /q:true /e:true > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Kernel process telemetry log enabled: $logName"
                return $true
            }

            Write-Warning "Telemetry log command returned exit code $LASTEXITCODE for $logName"
        } catch {
            Write-Warning ("Failed to configure telemetry log {0}: {1}" -f $logName, $_.Exception.Message)
        }
    }

    Write-Warning "Unable to enable kernel process telemetry logs. Application usage tracking may be unavailable."
    return $false
}

$ProcessLogEnabled = Enable-ReportMateKernelProcessLog

try {
    # First, remove any existing ReportMate tasks to prevent duplicates
    Write-Host "Removing any existing ReportMate tasks..."
    Get-ScheduledTask | Where-Object { 
        $_.TaskName -like "*ReportMate*" -or 
        $_.Description -like "*ReportMate*" -or
        $_.TaskName -like "*Report*Mate*"
    } | ForEach-Object {
        Write-Host "  Removing existing task: $($_.TaskName)"
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    
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
                    modules = @("security", "profiles", "network")
                }
                every4hours = @{
                    interval = "PT4H" 
                    modules = @("applications", "inventory", "system")
                }
                daily = @{
                    interval = "P1D"
                    modules = @("hardware", "management", "printers", "displays")
                }
                all = @{
                    interval_minutes = 720
                    modules = @("security", "profiles", "network", "applications", "inventory", "system", "hardware", "management", "printers", "displays")
                }
            }
        }
    }

    $runnerExe = Join-Path $InstallPath "runner.exe"
    
    # Create hourly collection task
    Write-Host "Creating hourly collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--run-modules $($scheduleConfig.schedules.hourly.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -RunOnlyIfNetworkAvailable -Hidden -AllowStartIfOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName "ReportMate Hourly Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits security-critical device data every hour" -Force
    
    # Create 4-hourly collection task  
    Write-Host "Creating 4-hourly collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--run-modules $($scheduleConfig.schedules.every4hours.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours 4)
    
    Register-ScheduledTask -TaskName "ReportMate 4-Hourly Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits moderately changing device data every 4 hours" -Force
    
    # Create daily collection task
    Write-Host "Creating daily collection task..."
    $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--run-modules $($scheduleConfig.schedules.daily.modules -join ',')" -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
    
    Register-ScheduledTask -TaskName "ReportMate Daily Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits static device data once daily" -Force
    
    # Create all modules collection task (if configured)
    if ($scheduleConfig.schedules.all) {
        Write-Host "Creating all modules collection task..."
        
        $allModules = $scheduleConfig.schedules.all.modules
        if ($allModules -eq "all") {
            # For 'all' modules, don't use --run-modules flag to run everything
            $action = New-ScheduledTaskAction -Execute $runnerExe -WorkingDirectory $InstallPath
        } else {
            # If explicit list, use --run-modules
            $modulesArg = $allModules -join ','
            $action = New-ScheduledTaskAction -Execute $runnerExe -Argument "--run-modules $modulesArg" -WorkingDirectory $InstallPath
        }

        $intervalMinutes = $scheduleConfig.schedules.all.interval_minutes
        $intervalHours = [math]::Floor($intervalMinutes / 60)
        $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours $intervalHours)
        
        Register-ScheduledTask -TaskName "ReportMate All Modules Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits data from all available modules" -Force
    }
    
    Write-Host "✅ All ReportMate scheduled tasks created successfully"
    if ($ProcessLogEnabled) {
        Write-Host "✅ Kernel process telemetry log enabled"
    } else {
        Write-Warning "Kernel process telemetry log could not be enabled automatically. Usage tracking may be limited."
    }
    
} catch {
    Write-Error "Failed to create scheduled tasks: $_"
    exit 1
}
