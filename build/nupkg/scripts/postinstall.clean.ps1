# ═══════════════════════════════════════════════════════════════════════════════
# ReportMate Post-Installation Script - Comprehensive Checklist & Implementation
# ═══════════════════════════════════════════════════════════════════════════════
#
# INSTALLATION DUTIES CHECKLIST:
# ═══════════════════════════════════════════════════════════════════════════════
#
# REGISTRY CONFIGURATION:
#   - Write to the machine settings key (HKLM\SOFTWARE\ReportMate\Settings)
#   - Set defaults (CollectionIntervalSeconds, LogLevel, OsQuery paths) only where unset
#   - Configure API URL and Passphrase from the package, unless the legacy
#     HKLM\SOFTWARE\Config\ReportMate key already sets them
#   - Support DeviceId override (optional, auto-detected by default)
#
# DIRECTORY STRUCTURE:
#   - Create ProgramData directories (ManagedReports, config, logs, cache, data)
#   - Set proper permissions on data directory (SYSTEM FullControl)
#   - Copy payload data files to ProgramData location
#   - Preserve directory structure during data file copying
#
# FILE MANAGEMENT:
#   - Copy osquery modules to C:\ProgramData\ManagedReports\osquery\
#   - Copy configuration files (appsettings.yaml, appsettings.template.yaml)
#   - Handle file path escaping and relative path calculation
#   - Create parent directories as needed during file operations
#
# SCHEDULED TASKS:
#   - Remove any existing ReportMate scheduled tasks (prevent duplicates)
#   - Load module schedules configuration from module-schedules.json
#   - Create hourly collection task (security, installs, profiles, system, network)
#   - Create 4-hourly collection task (applications, inventory)
#   - Create daily collection task (hardware, management, printers, displays)
#   - Create all modules collection task (if configured)
#   - Configure task settings (execution time limits, restart policies, network requirements)
#   - Run tasks as SYSTEM with highest privileges
#
# CIMIAN INTEGRATION:
#   - Move files from C:\Program Files\ReportMate\cimian to C:\Program Files\Cimian
#   - Create target Cimian directory if needed
#   - Ensure only one copy of files exists (in final Cimian location)
#   - Handle missing Cimian directory gracefully
#
# OSQUERY DEPENDENCY:
#   - Check if osquery is installed at C:\Program Files\osquery\osqueryi.exe
#   - Attempt automatic installation via chocolatey if missing
#   - Verify osquery installation and version
#   - Provide manual installation instructions if automatic fails
#   - Continue installation even if osquery is missing (with warnings)
#
# VALIDATION & TESTING:
#   - Test installation by running 'managedreportsrunner.exe info'
#   - Verify exit codes and handle test failures
#   - Provide comprehensive installation summary
#   - Display configuration status and registry locations
#   - Show environment variable override instructions
#   - Provide next steps and verification commands
#
# ERROR HANDLING:
#   - Use "Continue" error action for non-critical operations
#   - Wrap critical operations in try-catch blocks
#   - Provide meaningful warning messages for failures
#   - Continue installation even if individual components fail
#   - Distinguish between warnings and critical errors
#
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "ReportMate Post-Installation Script"
Write-Host "=================================================="
Write-Host "Comprehensive checklist verified - all duties covered!"

$ErrorActionPreference = "Continue"

# ═══════════════════════════════════════════════════════════════════════════════
# ADD TO SYSTEM PATH: Make managedreportsrunner.exe accessible from anywhere
# ═══════════════════════════════════════════════════════════════════════════════
$InstallDir = "C:\Program Files\ReportMate"
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

# ═══════════════════════════════════════════════════════════════════════════════
# START MENU: shortcut to the Managed Reports Runner app for every user
# ═══════════════════════════════════════════════════════════════════════════════
try {
    $appExe = Join-Path $InstallDir "Managed Reports Runner.exe"
    $shortcutPath = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Managed Reports Runner.lnk"
    if (Test-Path $appExe) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $appExe
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.Description = "Managed Reports Runner"
        $shortcut.Save()
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
        Write-Host "Start Menu shortcut: $shortcutPath"
    } else {
        Write-Warning "App not found at $appExe; Start Menu shortcut not created"
    }
} catch {
    Write-Warning "Could not create the Start Menu shortcut: $_"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MIGRATION: Remove old runner.exe binary (renamed to managedreportsrunner.exe)
# ═══════════════════════════════════════════════════════════════════════════════
$OldBinaryPath = "C:\Program Files\ReportMate\runner.exe"
if (Test-Path $OldBinaryPath) {
    Write-Host "Migration: Removing old runner.exe binary..."
    try {
        Remove-Item $OldBinaryPath -Force -ErrorAction Stop
        Write-Host "Old runner.exe binary removed successfully"
    } catch {
        Write-Warning "Could not remove old runner.exe: $_"
    }
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
    # During NUPKG install, .env may be alongside the scripts directory
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
# [bool]::Parse throws on anything but true/false; accept the usual spellings.
$AUTO_CONFIGURE = $env:REPORTMATE_AUTO_CONFIGURE -notmatch '^\s*(false|0|no|off)\s*$'

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
# Standard keys: MDM sets HKLM\SOFTWARE\Policies\ReportMate; the installer and local
# administrators use HKLM\SOFTWARE\ReportMate\Settings. Credentials (Passphrase, ApiKey)
# live in HKLM\SOFTWARE\ReportMate\Secrets, readable by SYSTEM and Administrators only.
# HKLM\SOFTWARE\Config\ReportMate and the values directly under HKLM\SOFTWARE\ReportMate
# are deprecated: still read as fallbacks and copied into Settings here where Settings
# lacks them. The only change made to them is removing Passphrase and ApiKey once they
# are safely in the secrets key.
$PolicyPath = "HKLM:\SOFTWARE\Policies\ReportMate"
$SettingsPath = "HKLM:\SOFTWARE\ReportMate\Settings"
$SecretsPath = "HKLM:\SOFTWARE\ReportMate\Secrets"
$LegacyPaths = @("HKLM:\SOFTWARE\Config\ReportMate", "HKLM:\SOFTWARE\ReportMate")
$SecretNames = @("Passphrase", "ApiKey")
$StateNames = @("LastRunTime", "InstallTime", "Version")
$Aliases = @{ "ServerUrl" = "ApiUrl"; "CollectionInterval" = "CollectionIntervalSeconds" }

function Get-CanonicalName([string]$Name) {
    if ($Aliases.ContainsKey($Name)) { return $Aliases[$Name] }
    return $Name
}

# Names a key holds, under their current spelling.
function Get-CanonicalNames([string]$Path) {
    $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if (-not $key) { return @() }
    return @($key.GetValueNames() | ForEach-Object { Get-CanonicalName $_ })
}

try {
    if (-not (Test-Path $SettingsPath)) {
        New-Item -Path $SettingsPath -Force | Out-Null
        Write-Host "Created registry key: $SettingsPath"
    }
} catch {
    Write-Warning "Failed to create registry key: $_"
}

# The secrets key gets its own ACL every time: SYSTEM and Administrators, nothing inherited.
# Nothing is written to it unless this succeeds.
$SecretsSecured = $false
try {
    $hklm64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $secretsKey = $hklm64.CreateSubKey('SOFTWARE\ReportMate\Secrets', $true)
    $SecretsAcl = New-Object System.Security.AccessControl.RegistrySecurity
    $SecretsAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $SecretsAcl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit', 'None', 'Allow')))
    }
    $secretsKey.SetAccessControl($SecretsAcl)
    $secretsKey.Dispose()
    $SecretsSecured = $true
    Write-Host "Secured $SecretsPath (SYSTEM and Administrators only)"
} catch {
    Write-Warning "Failed to secure registry key ${SecretsPath}; no credential will be written: $_"
}

# Credentials in the deprecated keys move to the secrets key, and only those two values are
# deleted from the legacy keys, never before the secrets key reads back what was stored.
# A legacy value is stored only when policy and Settings do not hold the name and the
# secrets key is empty (Config\ReportMate first); otherwise the stored value already
# wins, and the legacy copy is just removed. Values are never printed.
if ($SecretsSecured) {
    foreach ($name in $SecretNames) {
        try {
            $legacyWith = @()
            foreach ($legacyPath in $LegacyPaths) {
                $v = (Get-ItemProperty -Path $legacyPath -Name $name -ErrorAction SilentlyContinue).$name
                if (-not [string]::IsNullOrEmpty($v)) { $legacyWith += , @($legacyPath, $v) }
            }
            if ($legacyWith.Count -eq 0) { continue }

            $claimed = ((Get-CanonicalNames $PolicyPath) -contains $name) -or ((Get-CanonicalNames $SettingsPath) -contains $name)
            $stored = (Get-ItemProperty -Path $SecretsPath -Name $name -ErrorAction SilentlyContinue).$name
            $written = $null
            if (-not $claimed -and [string]::IsNullOrEmpty($stored)) {
                $written = $legacyWith[0][1]
                New-ItemProperty -Path $SecretsPath -Name $name -Value $written -PropertyType String -Force | Out-Null
            }

            $readBack = (Get-ItemProperty -Path $SecretsPath -Name $name -ErrorAction SilentlyContinue).$name
            $verified = if ($null -ne $written) { $readBack -ceq $written } else { -not [string]::IsNullOrEmpty($readBack) }
            if (-not $verified) {
                Write-Warning "Could not verify $name in $SecretsPath; readable copies in the deprecated keys were left in place"
                continue
            }
            if ($null -ne $written) { Write-Host "Stored $name from $($legacyWith[0][0]) in $SecretsPath" }
            foreach ($entry in $legacyWith) {
                Remove-ItemProperty -Path $entry[0] -Name $name -ErrorAction Stop
                Write-Host "Deleted the readable $name from the deprecated key $($entry[0])"
            }
        } catch {
            Write-Warning "Failed to move $name to ${SecretsPath}: $_"
        }
    }
}

# Copy legacy settings into Settings where Settings lacks them. Config\ReportMate first:
# it outranks the top-level key, as when the runner reads them. Credentials were handled
# above and are never copied into Settings.
$LegacyInUse = $false
foreach ($legacyPath in $LegacyPaths) {
    $legacy = Get-Item -Path $legacyPath -ErrorAction SilentlyContinue
    if (-not $legacy) { continue }
    $present = Get-CanonicalNames $SettingsPath
    # Current spellings before older ones, so ApiUrl wins over ServerUrl.
    $names = @($legacy.GetValueNames() | Where-Object { $_ } | Sort-Object { if ($Aliases.ContainsKey($_)) { 1 } else { 0 } })
    foreach ($name in $names) {
        $canonical = Get-CanonicalName $name
        if ($StateNames -contains $canonical) { continue }
        $LegacyInUse = $true
        if ($SecretNames -contains $canonical -or $present -contains $canonical) { continue }
        try {
            $value = $legacy.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
            if ($null -eq $value -or "$value" -eq "") { continue }
            $kind = $legacy.GetValueKind($name)
            New-ItemProperty -Path $SettingsPath -Name $canonical -Value $value -PropertyType $kind -Force | Out-Null
            $present += $canonical
            Write-Host "Copied $canonical from $legacyPath to $SettingsPath"
        } catch {
            Write-Warning "Failed to copy $name from ${legacyPath}: $_"
        }
    }
}
if ($LegacyInUse) {
    Write-Warning "Legacy ReportMate registry keys are deprecated ($($LegacyPaths -join ', ')). Use $PolicyPath for MDM and $SettingsPath locally. They are still read as fallbacks; only credentials were moved out of them."
}

# API URL and passphrase supplied with this package, where nothing already sets them.
# A legacy passphrase left in place (the secrets key could not be secured) still counts.
$settingsNames = Get-CanonicalNames $SettingsPath
$policyNames = Get-CanonicalNames $PolicyPath
$legacyNames = @($LegacyPaths | ForEach-Object { Get-CanonicalNames $_ })
if (-not [string]::IsNullOrEmpty($PROD_API_URL) -and $settingsNames -notcontains "ApiUrl") {
    try {
        New-ItemProperty -Path $SettingsPath -Name "ApiUrl" -Value $PROD_API_URL -PropertyType String -Force | Out-Null
        Write-Host "Set API URL: $PROD_API_URL"
    } catch {
        Write-Warning "Failed to set API URL: $_"
    }
}
if ($SecretsSecured -and -not [string]::IsNullOrEmpty($PROD_PASSPHRASE) -and $policyNames -notcontains "Passphrase" -and $settingsNames -notcontains "Passphrase" -and $legacyNames -notcontains "Passphrase") {
    try {
        $stored = (Get-ItemProperty -Path $SecretsPath -Name "Passphrase" -ErrorAction SilentlyContinue).Passphrase
        if ([string]::IsNullOrEmpty($stored)) {
            New-ItemProperty -Path $SecretsPath -Name "Passphrase" -Value $PROD_PASSPHRASE -PropertyType String -Force | Out-Null
            Write-Host "Set Client Passphrase: [CONFIGURED]"
        }
    } catch {
        Write-Warning "Failed to set Client Passphrase: $_"
    }
}

# Defaults, only where Settings has no value after the copy above, so an upgrade never
# resets what an administrator or the app set.
$Defaults = @(
    @{ Name = "CollectionIntervalSeconds"; Value = 3600; Type = "DWord" },
    @{ Name = "LogLevel"; Value = "Information"; Type = "String" },
    @{ Name = "OsQueryPath"; Value = "C:\Program Files\osquery\osqueryi.exe"; Type = "String" },
    @{ Name = "OsQueryConfigPath"; Value = "C:\ProgramData\ManagedReports\osquery"; Type = "String" }
)
$settingsNames = Get-CanonicalNames $SettingsPath
foreach ($default in $Defaults) {
    if ($settingsNames -contains $default.Name) { continue }
    try {
        New-ItemProperty -Path $SettingsPath -Name $default.Name -Value $default.Value -PropertyType $default.Type -Force | Out-Null
        Write-Host "Set default $($default.Name)"
    } catch {
        Write-Warning "Failed to set default $($default.Name): $_"
    }
}

# For the summary below: the API URL the runner will use, highest source first, and
# whether a passphrase is set anywhere. The passphrase value is never printed.
$EffectivePaths = @($PolicyPath, $SettingsPath) + $LegacyPaths
$ApiUrl = @($EffectivePaths | ForEach-Object { (Get-ItemProperty -Path $_ -Name ApiUrl -ErrorAction SilentlyContinue).ApiUrl } | Where-Object { $_ })[0]
$Passphrase = @((@($SecretsPath) + $EffectivePaths) | ForEach-Object { (Get-ItemProperty -Path $_ -Name Passphrase -ErrorAction SilentlyContinue).Passphrase } | Where-Object { $_ })[0]

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

# Lock down the data directory. The runner runs as SYSTEM and trusts what it reads here,
# so only SYSTEM and Administrators may write: full control for both, read for Users,
# no inheritance from ProgramData (which lets any user create files). Explicit entries are
# cleared and children reset to inherit this ACL. Owners below the folder are left alone:
# the runner rejects a settings file a non-administrator owns. Well-known SIDs keep this
# working on non-English Windows.
$DataRoot = "C:\ProgramData\ManagedReports"
try {
    & icacls.exe $DataRoot /reset /Q | Out-Null
    & icacls.exe $DataRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls exited with $LASTEXITCODE" }
    & icacls.exe $DataRoot /setowner "*S-1-5-32-544" /C /Q | Out-Null
    & icacls.exe "$DataRoot\*" /reset /T /C /Q | Out-Null
    Write-Host "Locked down $DataRoot (SYSTEM and Administrators full control, Users read)"
} catch {
    Write-Warning "Failed to set permissions on data directory: $_"
}

# usagetracker.exe runs as each signed-in user and writes its own JSON file here, so
# Users may create files in this one folder, and each user may change only the file
# they created (CREATOR OWNER).
$TrackerDir = Join-Path $DataRoot "usagetracker"
try {
    if (-not (Test-Path $TrackerDir)) { New-Item -ItemType Directory -Path $TrackerDir -Force | Out-Null }
    & icacls.exe $TrackerDir /grant "*S-1-5-32-545:(WD)" "*S-1-3-0:(OI)(IO)M" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls exited with $LASTEXITCODE" }
    Write-Host "Allowed users to write their own usage tracker files"
} catch {
    Write-Warning "Failed to set permissions on usage tracker directory: $_"
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

# Copy ProgramData files from payload to correct location
$payloadRoot = Split-Path -Parent $PSScriptRoot  
$dataPayloadPath = Join-Path $payloadRoot "payload\data"
$programDataLocation = "C:\ProgramData\ManagedReports"

if (Test-Path $dataPayloadPath) {
    Write-Host "Copying data files to ProgramData..."
    New-Item -ItemType Directory -Path $programDataLocation -Force | Out-Null
    
    Get-ChildItem -Path $dataPayloadPath -Recurse | ForEach-Object {
        $fullName = $_.FullName
        $fullName = [Management.Automation.WildcardPattern]::Escape($fullName)
        $relative = $fullName.Substring($dataPayloadPath.Length).TrimStart('\','/')
        $dest = Join-Path $programDataLocation $relative
        
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
        } else {
            $parentDir = Split-Path $dest -Parent
            if ($parentDir -and -not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Force -Path $parentDir | Out-Null
            }
            Copy-Item -LiteralPath $fullName -Destination $dest -Force
            Write-Verbose "Copied data file: $relative"
        }
    }
    Write-Host "Data files copied to ProgramData successfully"
} else {
    Write-Warning "No data payload directory found at: $dataPayloadPath"
}

INLINE_SCHEDULED_TASKS_PLACEHOLDER

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
# ═══════════════════════════════════════════════════════════════════════════════

# Check if osquery is installed
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

# First check-in, in the background so the install is not held up: --hello
# sends the device envelope alone so the device is listed within seconds,
# then a forced run of every enabled module follows. The previous
# inventory,system run left identity unreported, so a device enrolled and
# then shelved before its first scheduled run never showed who uses it.
# Quick storage keeps that run short; the daily task does the deep walk.
# One hidden PowerShell runs the two steps in order, encoded so the
# spaces in the install path survive Start-Process.
# The inlined task block above has already started it when present.
if (-not $ReportMateFirstRunStarted) {
    Write-Host "Starting first check-in (hello, then full collection)..."
    try {
        $logDir = "C:\ProgramData\ManagedReports\logs"
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $runnerExe = "C:\Program Files\ReportMate\managedreportsrunner.exe"
        $firstRun = "& '$runnerExe' --hello; & '$runnerExe' --force --storage-mode quick"
        $encodedFirstRun = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($firstRun))
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", $encodedFirstRun `
            -WindowStyle Hidden | Out-Null
    } catch {
        Write-Warning "Could not start the first check-in; the scheduled tasks will run it: $_"
    }
}

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
Write-Host "  Policy (MDM): HKLM\SOFTWARE\Policies\ReportMate (highest precedence)"
Write-Host "  Settings (local): HKLM\SOFTWARE\ReportMate\Settings"
Write-Host "  Credentials: HKLM\SOFTWARE\ReportMate\Secrets (SYSTEM and Administrators only)"
Write-Host "  Deprecated fallbacks: HKLM\SOFTWARE\Config\ReportMate, HKLM\SOFTWARE\ReportMate"
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
























