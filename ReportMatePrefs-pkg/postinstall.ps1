#!/usr/bin/env pwsh
#Requires -Version 5.0
#Requires -RunAsAdministrator

# =================================================================
# PRODUCTION CONFIGURATION VARIABLES
# =================================================================
# 🔧 CUSTOMIZE THESE VALUES FOR YOUR ENVIRONMENT
# Environment variables take precedence over these script defaults

# 🌐 ReportMate API Configuration
$PROD_API_URL = $env:REPORTMATE_API_URL ?? "https://reportmate.ecuad.ca"
$PROD_PASSPHRASE = $env:REPORTMATE_PASSPHRASE ?? "BGXCQm3KN0LZPfnFzAclTt5"

# 🏷️ Device Configuration  
$DEVICE_ID_PREFIX = $env:REPORTMATE_DEVICE_PREFIX ?? "ECUAD"
$COLLECTION_INTERVAL = [int]($env:REPORTMATE_COLLECTION_INTERVAL ?? 3600)  # 1 hour default
$LOG_LEVEL = $env:REPORTMATE_LOG_LEVEL ?? "Information"

# 🔧 Advanced Settings
$API_TIMEOUT_SECONDS = [int]($env:REPORTMATE_API_TIMEOUT ?? 300)  # 5 minutes
$MAX_RETRY_ATTEMPTS = [int]($env:REPORTMATE_MAX_RETRIES ?? 3)
$VALIDATE_SSL_CERT = [bool]($env:REPORTMATE_VALIDATE_SSL ?? $true)

# 🚀 Deployment Settings
$AUTO_CONFIGURE = [bool]($env:REPORTMATE_AUTO_CONFIGURE ?? $true)     # Automatically configure during install
$FORCE_CONFIGURATION = [bool]($env:REPORTMATE_FORCE_CONFIG ?? $true)  # Overwrite existing configuration
$TEST_CONNECTIVITY = [bool]($env:REPORTMATE_TEST_CONNECTIVITY ?? $true) # Test API connectivity after config

<#
.SYNOPSIS
    ReportMatePrefs Package Post-Installation Script
    
.DESCRIPTION
    This script runs after the ReportMatePrefs package is installed and configures
    ReportMate client preferences directly in the Windows Registry.
    
    Environment Variables (override script defaults):
    - REPORTMATE_API_URL: ReportMate API endpoint
    - REPORTMATE_PASSPHRASE: Client authentication passphrase  
    - REPORTMATE_DEVICE_PREFIX: Device ID prefix
    - REPORTMATE_COLLECTION_INTERVAL: Collection interval in seconds
    - REPORTMATE_LOG_LEVEL: Logging level
    - REPORTMATE_AUTO_CONFIGURE: Auto-configure during install (true/false)
    - REPORTMATE_FORCE_CONFIG: Force overwrite existing config (true/false)
    - REPORTMATE_TEST_CONNECTIVITY: Test connectivity after config (true/false)
    
.NOTES
    This script is called automatically by cimipkg after package installation.
    It contains all necessary functions for ReportMate configuration.
#>

$ErrorActionPreference = "Stop"

# Colors for output
function Write-ColorOutput {
    param(
        [ConsoleColor]$ForegroundColor,
        [string]$Message
    )
    $currentColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $ForegroundColor
    Write-Output $Message
    $Host.UI.RawUI.ForegroundColor = $currentColor
}

function Write-Success { Write-ColorOutput Green "✅ $($args -join ' ')" }
function Write-Warning { Write-ColorOutput Yellow "⚠️  $($args -join ' ')" }
function Write-Error { Write-ColorOutput Red "❌ $($args -join ' ')" }
function Write-Info { Write-ColorOutput Cyan "ℹ️  $($args -join ' ')" }
function Write-Header { Write-ColorOutput Magenta "🚀 $($args -join ' ')" }

# Registry paths (CSP/Group Policy location for highest precedence)
$RegistryPath = "HKLM:\SOFTWARE\Config\ReportMate"

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "String"
    )
    
    try {
        # Create registry key if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Verbose "Created registry key: $Path"
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        Write-Verbose "Set registry value: $Path\$Name = $Value (Type: $Type)"
        return $true
    } catch {
        Write-Error "Failed to set registry value $Path\$Name : $_"
        return $false
    }
}

function Test-ApiConnectivity {
    param(
        [string]$ApiUrl,
        [string]$Passphrase = ""
    )
    
    Write-Info "Testing connectivity to: $ApiUrl"
    
    try {
        # Create HTTP client
        $headers = @{
            'User-Agent' = 'ReportMate-PostInstall/1.0'
            'Accept' = 'application/json'
        }
        
        if ($Passphrase) {
            $headers['X-Client-Passphrase'] = $Passphrase
        }
        
        # Test basic connectivity
        $testUrl = "$ApiUrl/api/health"
        Write-Verbose "Testing URL: $testUrl"
        
        $response = Invoke-RestMethod -Uri $testUrl -Headers $headers -TimeoutSec 30 -ErrorAction Stop
        Write-Success "API connectivity test successful"
        return $true
        
    } catch {
        Write-Warning "API connectivity test failed: $_"
        Write-Info "This may be normal if the API endpoint requires authentication or is not accessible from this network."
        return $false
    }
}

function Get-ReportMateConfiguration {
    $config = @{}
    
    if (Test-Path $RegistryPath) {
        try {
            $regKey = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
            if ($regKey) {
                foreach ($property in $regKey.PSObject.Properties) {
                    if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                        $config[$property.Name] = $property.Value
                    }
                }
            }
        } catch {
            Write-Verbose "Could not read from $RegistryPath : $_"
        }
    }
    
    return $config
}

# =================================================================
# MAIN SCRIPT EXECUTION
# =================================================================

Write-Header "ReportMatePrefs Package Post-Installation"
Write-Output ""

# Check administrative privileges
if (-not (Test-AdminRights)) {
    Write-Error "This script requires administrative privileges to modify registry settings."
    Write-Info "Please ensure the package is installed with administrator rights."
    exit 1
}

Write-Info "ReportMatePrefs Configuration Package"
Write-Info "======================================"
Write-Output ""

# Display current configuration
Write-Info "Configuration Settings:"
Write-Output "  API URL: $PROD_API_URL"
Write-Output "  Device Prefix: $DEVICE_ID_PREFIX"
Write-Output "  Collection Interval: $COLLECTION_INTERVAL seconds"
Write-Output "  Log Level: $LOG_LEVEL"
Write-Output "  Auto Configure: $AUTO_CONFIGURE"
Write-Output "  Force Configuration: $FORCE_CONFIGURATION"
Write-Output "  Test Connectivity: $TEST_CONNECTIVITY"
Write-Output "  Passphrase: $(if ($PROD_PASSPHRASE) { '[CONFIGURED]' } else { '[NOT SET]' })"
Write-Output ""

if ($AUTO_CONFIGURE) {
    try {
        # Validate API URL format
        if (-not $PROD_API_URL.StartsWith('http://') -and -not $PROD_API_URL.StartsWith('https://')) {
            throw "API URL must start with http:// or https://"
        }
        
        # Remove trailing slash from API URL
        $PROD_API_URL = $PROD_API_URL.TrimEnd('/')
        
        Write-Info "Configuring ReportMate client preferences..."
        
        # Check for existing configuration
        $existingConfig = Get-ReportMateConfiguration
        if ($existingConfig.Keys.Count -gt 0 -and -not $FORCE_CONFIGURATION) {
            Write-Warning "Existing ReportMate configuration found."
            Write-Info "Use REPORTMATE_FORCE_CONFIG=true to overwrite existing settings."
            foreach ($key in $existingConfig.Keys) {
                $value = $existingConfig[$key]
                if ($key -in @('Passphrase', 'ApiKey')) {
                    $value = "[REDACTED]"
                }
                Write-Output "  $key : $value"
            }
        } else {
            Write-Info "Setting configuration in: $RegistryPath"
            Write-Output ""
            
            # Set configuration values
            $success = $true
            
            # Required settings
            $success = (Set-RegistryValue -Path $RegistryPath -Name "ApiUrl" -Value $PROD_API_URL -Type "String") -and $success
            Write-Success "Set API URL: $PROD_API_URL"
            
            # Authentication
            if (-not [string]::IsNullOrWhiteSpace($PROD_PASSPHRASE)) {
                $success = (Set-RegistryValue -Path $RegistryPath -Name "Passphrase" -Value $PROD_PASSPHRASE -Type "String") -and $success
                Write-Success "Set Client Passphrase: [CONFIGURED]"
            }
            
            # Device ID with prefix
            if (-not [string]::IsNullOrWhiteSpace($DEVICE_ID_PREFIX)) {
                $hostname = $env:COMPUTERNAME
                $deviceId = "$DEVICE_ID_PREFIX-$hostname"
                $success = (Set-RegistryValue -Path $RegistryPath -Name "DeviceId" -Value $deviceId -Type "String") -and $success
                Write-Success "Set Device ID: $deviceId"
            }
            
            # Operational settings
            $success = (Set-RegistryValue -Path $RegistryPath -Name "CollectionInterval" -Value $COLLECTION_INTERVAL -Type "DWord") -and $success
            Write-Success "Set Collection Interval: $COLLECTION_INTERVAL seconds"
            
            $success = (Set-RegistryValue -Path $RegistryPath -Name "LogLevel" -Value $LOG_LEVEL -Type "String") -and $success
            Write-Success "Set Log Level: $LOG_LEVEL"
            
            $success = (Set-RegistryValue -Path $RegistryPath -Name "ApiTimeoutSeconds" -Value $API_TIMEOUT_SECONDS -Type "DWord") -and $success
            Write-Success "Set API Timeout: $API_TIMEOUT_SECONDS seconds"
            
            $success = (Set-RegistryValue -Path $RegistryPath -Name "MaxRetryAttempts" -Value $MAX_RETRY_ATTEMPTS -Type "DWord") -and $success
            Write-Success "Set Max Retry Attempts: $MAX_RETRY_ATTEMPTS"
            
            $success = (Set-RegistryValue -Path $RegistryPath -Name "ValidateSslCert" -Value $(if ($VALIDATE_SSL_CERT) { 1 } else { 0 }) -Type "DWord") -and $success
            Write-Success "Set SSL Certificate Validation: $VALIDATE_SSL_CERT"
            
            Write-Output ""
            
            if ($success) {
                Write-Success "ReportMate configuration completed successfully!"
                Write-Info "Configuration will take effect on the next ReportMate run."
                
                # Test connectivity if enabled and passphrase is provided
                if ($TEST_CONNECTIVITY -and $PROD_PASSPHRASE) {
                    Write-Output ""
                    Test-ApiConnectivity -ApiUrl $PROD_API_URL -Passphrase $PROD_PASSPHRASE | Out-Null
                }
                
            } else {
                Write-Error "Configuration completed with errors. Check the output above."
                exit 1
            }
        }
        
    } catch {
        Write-Error "Failed to configure ReportMate: $_"
        Write-Info "You can manually configure ReportMate later if needed."
    }
} else {
    Write-Info "Automatic configuration disabled (AUTO_CONFIGURE = false)"
}

Write-Output ""
Write-Info "Registry Configuration Location:"
Write-Output "  $RegistryPath"
Write-Output ""

Write-Info "ReportMate Client Integration:"
Write-Output "  - ReportMate client will read settings from the registry automatically"
Write-Output "  - Configuration takes effect on the next ReportMate run"
Write-Output "  - Test with: C:\Program Files\ReportMate\runner.exe test --verbose"
Write-Output "  - View logs: C:\ProgramData\ManagedReports\logs\"
Write-Output ""

Write-Info "Environment Variables for CI/CD:"
Write-Output ""
Write-Output "  REPORTMATE_API_URL=$PROD_API_URL"
Write-Output "  REPORTMATE_PASSPHRASE=[REDACTED]"
Write-Output "  REPORTMATE_DEVICE_PREFIX=$DEVICE_ID_PREFIX"
Write-Output "  REPORTMATE_COLLECTION_INTERVAL=$COLLECTION_INTERVAL"
Write-Output "  REPORTMATE_LOG_LEVEL=$LOG_LEVEL"
Write-Output "  REPORTMATE_AUTO_CONFIGURE=$AUTO_CONFIGURE"
Write-Output ""

Write-Success "ReportMatePrefs package installation completed successfully!"
Write-Output ""
