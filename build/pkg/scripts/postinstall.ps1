# ReportMate Post-Installation Script (cimipkg)
#
# Runs after cimipkg's payload copy. Configures registry, scheduled tasks,
# data directories, and Cimian integration.
#
# Hard-fails (exit 1) on errors so broken installs are visible in install
# logs and ARP rather than discoverable weeks later via stale dashboard
# data. Nice-to-have operations (PATH addition, Start Menu, winget-based
# osquery install) keep their own try/catch + Write-Warning so they can
# soft-fail without breaking the install. Must-have operations (scheduled
# task registration, payload presence) throw and bubble to the master
# catch.

$ErrorActionPreference = "Stop"

Write-Host "ReportMate Post-Installation Script (cimipkg)"
Write-Host "============================================="

$InstallDir = "C:\Program Files\ReportMate"

try {

# ----------------------------------------------------------------------------
# Verify expected files from the payload.
# A missing file means cimipkg's CAB extraction or our build produced an
# incomplete package -- fail loud here rather than register scheduled tasks
# against missing binaries (which would fail silently at run time and only
# surface when the dashboard goes dark).
# ----------------------------------------------------------------------------
$expectedPayload = @(
    'managedreportsrunner.exe'
    'usagetracker.exe'
    'appsettings.yaml'
    'module-schedules.json'
)
# appsettings.json is not required: build.ps1 copies it with
# -ErrorAction SilentlyContinue, so the source may legitimately not ship one.
# appsettings.yaml is the canonical config and is always copied.
$missing = @()
foreach ($name in $expectedPayload) {
    if (-not (Test-Path (Join-Path $InstallDir $name))) { $missing += $name }
}
if ($missing.Count -gt 0) {
    throw "Missing expected files from payload: $($missing -join ', ')"
}

# ----------------------------------------------------------------------------
# ADD TO SYSTEM PATH: make managedreportsrunner.exe accessible from anywhere
# ----------------------------------------------------------------------------
Write-Host "Adding ReportMate to system PATH..."

try {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$InstallDir*") {
        $newPath = $currentPath.TrimEnd(';') + ";$InstallDir"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
        Write-Host "Added '$InstallDir' to system PATH"
        Write-Host "  NOTE: New terminal sessions will have access to managedreportsrunner.exe"
    } else {
        Write-Host "ReportMate already in system PATH"
    }
} catch {
    Write-Warning "Could not add to PATH: $_"
    Write-Host "  You can manually add '$InstallDir' to your system PATH"
}

function Enable-ReportMateKernelProcessLog {
    param(
        [string[]]$LogNames = @(
            "Microsoft-Windows-Kernel-Process/Analytic",
            "Microsoft-Windows-Kernel-Process/Operational"
        )
    )

    # Security Log (Event 4688/4689) is the preferred source for process telemetry on
    # Windows 10/11. Check for it first before attempting kernel log setup.
    try {
        $auditResult = & auditpol.exe /get /subcategory:"Process Creation" 2>&1
        if ($LASTEXITCODE -eq 0 -and ($auditResult -join "" -match "Success|Failure")) {
            Write-Host "Process telemetry: Security Log (Event 4688) audit is active"
            return $true
        }
        # Attempt to enable Security Log process creation auditing
        & auditpol.exe /set /subcategory:"Process Creation" /success:enable > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Process telemetry: Enabled Security Log (Event 4688) process creation audit"
            return $true
        }
    } catch {
        Write-Verbose "Security Log audit check failed: $_"
    }

    # Fall back to kernel process event logs (older Windows versions)
    foreach ($logName in $LogNames) {
        Write-Verbose "Attempting kernel process telemetry log: $logName"

        try {
            & wevtutil gl $logName > $null 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Verbose "Telemetry log not available: $logName"
                continue
            }

            # Analytic/Debug logs must be disabled before changing settings
            if ($logName -like '*Analytic*' -or $logName -like '*Debug*') {
                & wevtutil sl $logName /e:false > $null 2>&1
            }
            & wevtutil sl $logName /e:true > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Process telemetry: Kernel log enabled ($logName)"
                return $true
            }
        } catch {
            Write-Verbose ("Failed to configure kernel log {0}: {1}" -f $logName, $_.Exception.Message)
        }
    }

    Write-Warning "Process telemetry unavailable: Security Log audit and kernel logs could not be configured. Application usage tracking will be limited."
    return $false
}

# =================================================================
# CONFIGURATION VARIABLES
# =================================================================
# Configuration is sourced from:
# 1. Environment variables (highest precedence)
# 2. Bundled .env file in install directory
# 3. CSP/OMA-URI registry settings
# 4. Production defaults (Container Apps API endpoint)

# Load bundled .env file if environment variables aren't already set
$envFile = Join-Path "C:\Program Files\ReportMate" ".env"
if (-not (Test-Path $envFile)) {
    # During PKG install, .env may be alongside the scripts directory
    $envFile = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
}
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
        $parts = $_ -split '=', 2
        $key = $parts[0].Trim()
        $val = $parts[1].Trim()
        if (-not [Environment]::GetEnvironmentVariable($key, 'Process')) {
            [Environment]::SetEnvironmentVariable($key, $val, 'Process')
        }
    }
    Write-Host "Loaded configuration from bundled .env file"
}

$PROD_API_URL = if ($env:REPORTMATE_API_URL) { $env:REPORTMATE_API_URL } else { $env:PROD_API_URL }
$PROD_PASSPHRASE = if ($env:REPORTMATE_PASSPHRASE) { $env:REPORTMATE_PASSPHRASE } else { $env:PROD_PASSPHRASE }
$AUTO_CONFIGURE = if (-not [string]::IsNullOrEmpty($env:REPORTMATE_AUTO_CONFIGURE)) { [bool]::Parse($env:REPORTMATE_AUTO_CONFIGURE) } else { $true }

if ([string]::IsNullOrEmpty($env:PROD_API_URL) -and [string]::IsNullOrEmpty($PROD_API_URL)) {
    Write-Warning "PROD_API_URL environment variable not provided. ReportMate will rely on existing registry or manual configuration."
}

if ([string]::IsNullOrEmpty($env:PROD_PASSPHRASE) -and [string]::IsNullOrEmpty($PROD_PASSPHRASE)) {
    Write-Warning "PROD_PASSPHRASE environment variable not provided. Authentication must be configured separately."
}

# Initialize configuration variables
$ApiUrl = ""
$Passphrase = ""

$ProcessLogEnabled = Enable-ReportMateKernelProcessLog

# REGISTRY CONFIGURATION
# Check for CSP OMA-URI first (management configs)
$CSPRegistryPath = "HKLM\SOFTWARE\Config\ReportMate"
if (Test-Path $CSPRegistryPath) {
    Write-Host "Found CSP OMA-URI configuration"
    $CSPApiUrl = Get-ItemProperty -Path $CSPRegistryPath -Name "ApiUrl" -ErrorAction SilentlyContinue
    if ($CSPApiUrl -and -not [string]::IsNullOrEmpty($CSPApiUrl.ApiUrl)) {
        $ApiUrl = $CSPApiUrl.ApiUrl
        Write-Host "Using CSP-configured API URL"
    }
    
    $CSPPassphrase = Get-ItemProperty -Path $CSPRegistryPath -Name "Passphrase" -ErrorAction SilentlyContinue
    if ($CSPPassphrase -and -not [string]::IsNullOrEmpty($CSPPassphrase.Passphrase)) {
        $Passphrase = $CSPPassphrase.Passphrase
        Write-Host "Using CSP-configured Passphrase"
    }
}

# Create registry key if it doesn't exist
$RegistryPath = "HKLM\SOFTWARE\ReportMate"
if (-not (Test-Path $RegistryPath)) {
    try {
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Host "Created registry key: $RegistryPath"
    } catch {
        Write-Warning "Failed to create registry key: $_"
    }
}

# Set default configuration values
try {
    Set-ItemProperty -Path $RegistryPath -Name "CollectionInterval" -Value 3600 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegistryPath -Name "LogLevel" -Value "Information" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegistryPath -Name "OsQueryPath" -Value "C:\Program Files\osquery\osqueryi.exe" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegistryPath -Name "OsQueryConfigPath" -Value "C:\ProgramData\ManagedReports\osquery" -ErrorAction SilentlyContinue
    Write-Host "Set default configuration values"
} catch {
    Write-Warning "Failed to set default configuration: $_"
}

# Set API URL
if (-not [string]::IsNullOrEmpty($PROD_API_URL)) {
    $ApiUrl = $PROD_API_URL
}
if (-not [string]::IsNullOrEmpty($ApiUrl)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl
        Write-Host "Set API URL: $ApiUrl"
    } catch {
        Write-Warning "Failed to set API URL: $_"
    }
}

# Set Passphrase
if (-not [string]::IsNullOrEmpty($PROD_PASSPHRASE)) {
    $Passphrase = $PROD_PASSPHRASE
}
if (-not [string]::IsNullOrEmpty($Passphrase)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "Passphrase" -Value $Passphrase
        Write-Host "Set Client Passphrase: [CONFIGURED]"
    } catch {
        Write-Warning "Failed to set Client Passphrase: $_"
    }
}

# DIRECTORY STRUCTURE & FILE MANAGEMENT
$DataDirectories = @(
    "C:\ProgramData\ManagedReports",
    "C:\ProgramData\ManagedReports\config",
    "C:\ProgramData\ManagedReports\logs",
    "C:\ProgramData\ManagedReports\cache",
    "C:\ProgramData\ManagedReports\data"
)

foreach ($Directory in $DataDirectories) {
    if (-not (Test-Path $Directory)) {
        try {
            New-Item -ItemType Directory -Path $Directory -Force | Out-Null
            Write-Host "Created directory: $Directory"
        } catch {
            Write-Warning "Failed to create directory $Directory`: $_"
        }
    }
}

# Set permissions on data directory
try {
    $Acl = Get-Acl "C:\ProgramData\ManagedReports"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.SetAccessRule($AccessRule)
    Set-Acl -Path "C:\ProgramData\ManagedReports" -AclObject $Acl
    Write-Host "Set permissions on data directory"
} catch {
    Write-Warning "Failed to set permissions on data directory: $_"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADD REPORTMATE TO SYSTEM PATH (handled at top of script - this is legacy/duplicate)
# ═══════════════════════════════════════════════════════════════════════════════
# PATH addition already handled above - skip duplicate section
if ($false) {  # Disabled - duplicate of earlier PATH addition
    try {
        $NewPath = "$CurrentPath;$ReportMatePath"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
        Write-Host "Added ReportMate to system PATH"
        
        # Broadcast WM_SETTINGCHANGE so new terminals pick up the PATH change
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class Win32 {
                [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
                public static extern IntPtr SendMessageTimeout(
                    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
                    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
            }
"@
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1a
        $result = [UIntPtr]::Zero
        [Win32]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result) | Out-Null
        Write-Host "Environment change broadcast sent"
        
        # Also update current session PATH
        $env:Path = "$env:Path;$ReportMatePath"
    } catch {
        Write-Warning "Failed to add ReportMate to PATH: $_"
    }
} else {
    Write-Host "ReportMate already in system PATH"
}

# Copy configuration files to ProgramData (they should be in payload root since PKG uses install_location)
$configFiles = @(
    @{ Source = "C:\Program Files\ReportMate\appsettings.yaml"; Destination = "C:\ProgramData\ManagedReports\appsettings.yaml" },
    @{ Source = "C:\Program Files\ReportMate\appsettings.template.yaml"; Destination = "C:\ProgramData\ManagedReports\appsettings.template.yaml" }
)

foreach ($configFile in $configFiles) {
    if (Test-Path $configFile.Source) {
        try {
            Copy-Item $configFile.Source $configFile.Destination -Force
            Write-Host "Copied config file: $(Split-Path $configFile.Destination -Leaf)"
        } catch {
            Write-Warning "Failed to copy config file: $_"
        }
    }
}

# Copy osquery modules to ProgramData (file-by-file with verification)
$osquerySource = "C:\Program Files\ReportMate\osquery"
$osqueryDestination = "C:\ProgramData\ManagedReports\osquery"

if (Test-Path $osquerySource) {
    Write-Host "Deploying osquery module configs to ProgramData..."
    try {
        # Ensure destination directories exist
        $modulesDestDir = Join-Path $osqueryDestination "modules"
        New-Item -Path $modulesDestDir -ItemType Directory -Force | Out-Null

        # Copy enabled-modules.json
        $enabledSrc = Join-Path $osquerySource "enabled-modules.json"
        if (Test-Path $enabledSrc) {
            Copy-Item $enabledSrc (Join-Path $osqueryDestination "enabled-modules.json") -Force
            Write-Host "  Copied enabled-modules.json"
        }

        # Copy each module config individually
        $modulesSrcDir = Join-Path $osquerySource "modules"
        if (Test-Path $modulesSrcDir) {
            $copied = 0
            foreach ($file in Get-ChildItem $modulesSrcDir -Filter "*.json") {
                Copy-Item $file.FullName (Join-Path $modulesDestDir $file.Name) -Force
                $copied++
            }
            Write-Host "  Copied $copied module config files"
        }

        # Verify deployment
        $deployed = (Get-ChildItem $modulesDestDir -Filter "*.json" -ErrorAction SilentlyContinue).Count
        Write-Host "  Verification: $deployed module configs deployed to $modulesDestDir"
        if ($deployed -eq 0) {
            Write-Warning "No module configs deployed - data collection will be degraded"
        }
    } catch {
        Write-Warning "Failed to copy osquery modules: $_"
    }
}

# SCHEDULED TASKS INSTALLATION
Write-Host "Installing ReportMate scheduled tasks..."
try {
    $InstallPath = "C:\Program Files\ReportMate"
    
    # Remove any existing ReportMate tasks
    Get-ScheduledTask | Where-Object { 
        $_.TaskName -like "*ReportMate*" -or 
        $_.Description -like "*ReportMate*" -or
        $_.TaskName -like "*Report*Mate*"
    } | ForEach-Object {
        Write-Host "  Removing existing task: $($_.TaskName)"
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    
    # Load module schedules configuration. Guaranteed present by the
    # payload presence check at the top of this script.
    $scheduleConfigPath = Join-Path $InstallPath "module-schedules.json"
    $scheduleConfig = Get-Content $scheduleConfigPath | ConvertFrom-Json
    Write-Host "Loaded module schedules configuration"

    $runnerExe = Join-Path $InstallPath "managedreportsrunner.exe"
    
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
        $action = New-ScheduledTaskAction -Execute $runnerExe -WorkingDirectory $InstallPath
        $intervalMinutes = $scheduleConfig.schedules.all.interval_minutes
        $intervalHours = [math]::Floor($intervalMinutes / 60)
        $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours $intervalHours)

        Register-ScheduledTask -TaskName "ReportMate All Modules Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits data from all available modules" -Force
    }

    # Per-user usagetracker companion. usagetracker.exe captures foreground
    # and active-input time per executable, written to
    # %ProgramData%\ManagedReports\usagetracker\{username}.json. It MUST run
    # in the interactive user's session (not as SYSTEM in session 0) to see
    # foreground window / GetLastInputInfo data. BUILTIN\Users + RunLevel
    # Limited fires the task for whichever user is logging in, with their
    # own token. The exe enforces single-instance per user via the
    # Global\ReportMate.UsageTracker.{username} mutex, so MultipleInstances
    # IgnoreNew is a belt-and-braces guard.
    $utExe = Join-Path $InstallPath "usagetracker.exe"
    if (Test-Path $utExe) {
        Write-Host "Creating per-user usagetracker logon task..."
        $utAction    = New-ScheduledTaskAction -Execute $utExe -WorkingDirectory $InstallPath
        $utTrigger   = New-ScheduledTaskTrigger -AtLogOn
        $utPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
        $utSettings  = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 24) `
            -MultipleInstances IgnoreNew `
            -Hidden
        Register-ScheduledTask `
            -TaskName "ReportMate Usage Tracker" `
            -Action $utAction -Trigger $utTrigger `
            -Settings $utSettings -Principal $utPrincipal `
            -Description "Per-user logon-triggered companion that records application foreground and active-input time. Writes %ProgramData%\ManagedReports\usagetracker\{username}.json for managedreportsrunner.exe to read during scheduled collections." `
            -Force | Out-Null
        Write-Host "Registered per-user logon task: ReportMate Usage Tracker"
        Write-Host "  NOTE: Existing user sessions will start tracking on their next logon."
    } else {
        Write-Warning "usagetracker.exe not found at $utExe -- skipping logon task registration"
    }

    Write-Host "Scheduled tasks installed successfully"

} catch {
    # Task registration is must-have -- without it, the client never runs.
    # Bare `throw` re-raises the original ErrorRecord so the master catch
    # gets the full stack trace and exception type, not a wrapped string.
    Write-Host "Failed to create scheduled tasks: $_" -ForegroundColor Red
    throw
}

# CIMIAN INTEGRATION
$cimianReportMateDir = "C:\Program Files\ReportMate\cimian"
$cimianDestination = "C:\Program Files\Cimian"

if (Test-Path $cimianReportMateDir) {
    Write-Host "Setting up Cimian integration..."
    
    # Create Cimian destination directory
    New-Item -ItemType Directory -Path $cimianDestination -Force | Out-Null
    
    # Copy files from ReportMate\cimian to C:\Program Files\Cimian
    Get-ChildItem $cimianReportMateDir -File | ForEach-Object {
        $destPath = Join-Path $cimianDestination $_.Name
        Copy-Item $_.FullName $destPath -Force
        Write-Host "Copied $($_.Name) from ReportMate\cimian to C:\Program Files\Cimian"
    }
    
    Write-Host "Cimian integration files installed successfully"
    Write-Host "   Final location: C:\Program Files\Cimian (single copy only)"
} else {
    Write-Verbose "No Cimian integration directory found at: $cimianReportMateDir"
}

# OSQUERY DEPENDENCY CHECK & INSTALLATION
$osqueryPath = "C:\Program Files\osquery\osqueryi.exe"
if (-not (Test-Path $osqueryPath)) {
    Write-Host "WARNING: osquery not found at expected location: $osqueryPath"
    Write-Host "Attempting automatic installation via Windows Package Manager (winget)..."
    
    # Check if winget is available (built-in to Windows 11 and modern Windows 10)
    $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
    
    # If winget not found, try to register it (required after fresh Windows install/OOBE)
    if (-not $wingetCommand) {
        Write-Host "winget not immediately available - attempting to register App Installer..."
        try {
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Could not register App Installer: $_"
        }
    }
    
    if ($wingetCommand) {
        Write-Host "Installing osquery via winget..."
        try {
            # Install osquery silently with automatic acceptance
            $installProcess = Start-Process winget -ArgumentList "install --id osquery.osquery --silent --accept-package-agreements --accept-source-agreements" -Wait -PassThru -NoNewWindow
            
            if ($installProcess.ExitCode -eq 0) {
                Write-Host "osquery installed successfully via winget"
                
                # Verify installation
                if (Test-Path $osqueryPath) {
                    Write-Host "osquery verified at: $osqueryPath"
                    
                    # Get and display osquery version
                    try {
                        $osqueryVersion = & $osqueryPath --version 2>&1 | Select-Object -First 1
                        Write-Host "osquery version: $osqueryVersion"
                    } catch {
                        Write-Verbose "Could not retrieve osquery version: $_"
                    }
                } else {
                    Write-Warning "osquery installation completed but not found at expected location"
                    Write-Host "INFO: You may need to restart your session for PATH changes to take effect"
                }
            } else {
                Write-Warning "Failed to install osquery via winget (exit code: $($installProcess.ExitCode))"
                Write-Host "INFO: You can manually install osquery from: https://osquery.io/downloads/"
            }
        } catch {
            Write-Warning "Error installing osquery via winget: $_"
            Write-Host "INFO: You can manually install osquery from: https://osquery.io/downloads/"
        }
    } else {
        Write-Warning "Windows Package Manager (winget) not available for automatic osquery installation"
        Write-Host "INFO: Please install osquery manually from: https://osquery.io/downloads/"
        Write-Host "INFO: Or use winget if available: winget install osquery.osquery"
    }
} else {
    Write-Host "osquery found at: $osqueryPath"
    
    # Get osquery version
    try {
        $osqueryVersion = & $osqueryPath --version 2>&1 | Select-Object -First 1
        Write-Host "osquery version: $osqueryVersion"
    } catch {
        Write-Verbose "Could not retrieve osquery version: $_"
    }
}

# VALIDATION & TESTING
$TestResult = & "C:\Program Files\ReportMate\managedreportsrunner.exe" info 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Installation test successful"
} else {
    Write-Warning "Installation test failed: $TestResult"
}

# Run initial collection immediately so the device appears in ReportMate right away
Write-Host "Running initial inventory and system collection..."
$logDir = "C:\ProgramData\ManagedReports\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Start-Process -FilePath "C:\Program Files\ReportMate\managedreportsrunner.exe" `
    -ArgumentList "--run-modules", "inventory,system" `
    -WindowStyle Hidden `
    -PassThru | Out-Null

Write-Host "Post-installation script completed"
Write-Host ""
Write-Host "Configuration Summary:"
Write-Host "  API URL: $(if ($ApiUrl) { $ApiUrl } else { 'Not configured' })"
Write-Host "  Passphrase: $(if ($Passphrase) { '[CONFIGURED]' } else { 'Not set' })"
Write-Host "  Auto-Configure: $AUTO_CONFIGURE"
Write-Host "  osquery: $(if (Test-Path 'C:\Program Files\osquery\osqueryi.exe') { 'Installed' } else { 'Missing' })"
Write-Host "  Kernel Process Telemetry Log: $(if ($ProcessLogEnabled) { 'Enabled' } else { 'Unavailable' })"
Write-Host ""
Write-Host "Registry Locations:"
Write-Host "  CSP/Policy: HKLM\SOFTWARE\Config\ReportMate (highest precedence)"
Write-Host "  Standard: HKLM\SOFTWARE\ReportMate"
Write-Host ""
Write-Host "Environment Variables (override defaults):"
Write-Host "  REPORTMATE_API_URL - Override production API URL"
Write-Host "  REPORTMATE_PASSPHRASE - Override production passphrase"
Write-Host "  REPORTMATE_AUTO_CONFIGURE - Override auto-configuration setting"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Configuration is ready - ReportMate will use registry settings automatically"
Write-Host "2. Test connectivity: & 'C:\Program Files\ReportMate\managedreportsrunner.exe' test"
Write-Host "3. Run data collection: & 'C:\Program Files\ReportMate\managedreportsrunner.exe' run"

}
catch {
    Write-Host "ReportMate postinstall failed: $_" -ForegroundColor Red
    exit 1
}

exit 0