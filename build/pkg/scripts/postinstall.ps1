# ═══════════════════════════════════════════════════════════════════════════════
# ReportMate Post-Installation Script - PKG Format
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script handles the complete installation of ReportMate after files are copied
# to their target location by cimipkg. It configures registry settings, creates
# scheduled tasks, sets up data directories, and ensures proper integration.
#
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "ReportMate Post-Installation Script (PKG Format)"
Write-Host "=================================================="

$ErrorActionPreference = "Continue"

# =================================================================
# CONFIGURATION VARIABLES
# =================================================================
# Configuration is sourced from:
# 1. Environment variables (highest precedence)
# 2. CSP/OMA-URI registry settings
# 3. Production defaults (Container Apps API endpoint)
$PROD_API_URL = if ($env:REPORTMATE_API_URL) { $env:REPORTMATE_API_URL } else { $env:PROD_API_URL }
$PROD_PASSPHRASE = if ($env:REPORTMATE_PASSPHRASE) { $env:REPORTMATE_PASSPHRASE } else { $env:PROD_PASSPHRASE }
$AUTO_CONFIGURE = if (-not [string]::IsNullOrEmpty($env:REPORTMATE_AUTO_CONFIGURE)) { [bool]::Parse($env:REPORTMATE_AUTO_CONFIGURE) } else { $true }

# Validate required environment variables are available
if ([string]::IsNullOrEmpty($env:PROD_API_URL)) {
    Write-Error "CRITICAL: PROD_API_URL environment variable is required but not found"
    Write-Host "Please ensure .env file is properly configured with PROD_API_URL"
    exit 1
}

if ([string]::IsNullOrEmpty($env:PROD_PASSPHRASE)) {
    Write-Error "CRITICAL: PROD_PASSPHRASE environment variable is required but not found" 
    Write-Host "Please ensure .env file is properly configured with PROD_PASSPHRASE"
    exit 1
}

# Initialize configuration variables
$ApiUrl = ""
$Passphrase = ""

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

# Copy osquery modules to ProgramData
$osquerySource = "C:\Program Files\ReportMate\osquery"
$osqueryDestination = "C:\ProgramData\ManagedReports\osquery"

if (Test-Path $osquerySource) {
    Write-Host "Copying osquery modules to ProgramData..."
    try {
        if (Test-Path $osqueryDestination) {
            Remove-Item $osqueryDestination -Recurse -Force
        }
        Copy-Item $osquerySource $osqueryDestination -Recurse -Force
        Write-Host "osquery modules copied successfully"
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
    
    # Load module schedules configuration
    $scheduleConfigPath = Join-Path $InstallPath "module-schedules.json"
    if (Test-Path $scheduleConfigPath) {
        $scheduleConfig = Get-Content $scheduleConfigPath | ConvertFrom-Json
        Write-Host "Loaded module schedules configuration"
    } else {
        Write-Warning "Module schedules configuration not found, using defaults"
        $scheduleConfig = @{
            schedules = @{
                hourly = @{ interval = "PT1H"; modules = @("security", "installs", "profiles", "system", "network") }
                every4hours = @{ interval = "PT4H"; modules = @("applications", "inventory") }
                daily = @{ interval = "P1D"; modules = @("hardware", "management", "printers", "displays") }
                all = @{ interval_minutes = 720; modules = "all" }
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
        $action = New-ScheduledTaskAction -Execute $runnerExe -WorkingDirectory $InstallPath
        $intervalMinutes = $scheduleConfig.schedules.all.interval_minutes
        $intervalHours = [math]::Floor($intervalMinutes / 60)
        $trigger = New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionInterval (New-TimeSpan -Hours $intervalHours)
        
        Register-ScheduledTask -TaskName "ReportMate All Modules Collection" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Collects and transmits data from all available modules" -Force
    }
    
    Write-Host "Scheduled tasks installed successfully"
    
} catch {
    Write-Warning "Failed to create scheduled tasks: $_"
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
$TestResult = & "C:\Program Files\ReportMate\runner.exe" info 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Installation test successful"
} else {
    Write-Warning "Installation test failed: $TestResult"
}

Write-Host "Post-installation script completed"
Write-Host ""
Write-Host "Configuration Summary:"
Write-Host "  API URL: $(if ($ApiUrl) { $ApiUrl } else { 'Not configured' })"
Write-Host "  Passphrase: $(if ($Passphrase) { '[CONFIGURED]' } else { 'Not set' })"
Write-Host "  Auto-Configure: $AUTO_CONFIGURE"
Write-Host "  osquery: $(if (Test-Path 'C:\Program Files\osquery\osqueryi.exe') { 'Installed' } else { 'Missing' })"
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
Write-Host "2. Test connectivity: & 'C:\Program Files\ReportMate\runner.exe' test"
Write-Host "3. Run data collection: & 'C:\Program Files\ReportMate\runner.exe' run"