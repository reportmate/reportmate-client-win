#!/usr/bin/env pwsh

# =================================================================
# PRODUCTION CONFIGURATION VARIABLES
# =================================================================
# These variables can be set here directly or via environment variables
# Environment variables take precedence over script defaults

# 🌐 API Configuration (set via REPORTMATE_API_URL or REPORTMATE_PASSPHRASE env vars)
$DEFAULT_API_URL = $env:REPORTMATE_API_URL ?? "https://reportmate.ecuad.ca"
$DEFAULT_PASSPHRASE = $env:REPORTMATE_PASSPHRASE ?? "BGXCQm3KN0LZPfnFzAclTt5"

# 🏷️ Device Configuration
$DEFAULT_DEVICE_ID_PREFIX = $env:REPORTMATE_DEVICE_PREFIX ?? "ECUAD"
$DEFAULT_COLLECTION_INTERVAL = [int]($env:REPORTMATE_COLLECTION_INTERVAL ?? 3600)
$DEFAULT_LOG_LEVEL = $env:REPORTMATE_LOG_LEVEL ?? "Information"

# 🔧 Advanced Configuration
$DEFAULT_API_TIMEOUT = [int]($env:REPORTMATE_API_TIMEOUT ?? 300)
$DEFAULT_MAX_RETRIES = [int]($env:REPORTMATE_MAX_RETRIES ?? 3)
$DEFAULT_VALIDATE_SSL = [bool]($env:REPORTMATE_VALIDATE_SSL ?? $true)

# 📂 Path Configuration
$DEFAULT_OSQUERY_PATH = $env:REPORTMATE_OSQUERY_PATH ?? "C:\Program Files\osquery\osqueryi.exe"

<#
.SYNOPSIS
    ReportMate Client Preferences Configuration Script
    
.DESCRIPTION
    This script configures ReportMate client preferences in the Windows Registry.
    Designed to be packaged with cimipkg as 'ReportMatePrefs' for enterprise deployment.
    
    The script sets up the necessary registry values for ReportMate client authentication
    and configuration, including API URL, client passphrase, and collection settings.
    
    Environment Variables (take precedence over script defaults):
    - REPORTMATE_API_URL: ReportMate API endpoint URL
    - REPORTMATE_PASSPHRASE: Client authentication passphrase
    - REPORTMATE_DEVICE_PREFIX: Device ID prefix for organization
    - REPORTMATE_COLLECTION_INTERVAL: Data collection interval in seconds
    - REPORTMATE_LOG_LEVEL: Logging level (Error, Warning, Information, Debug)
    - REPORTMATE_API_TIMEOUT: API request timeout in seconds
    - REPORTMATE_MAX_RETRIES: Maximum retry attempts for failed requests
    - REPORTMATE_VALIDATE_SSL: SSL certificate validation (true/false)
    - REPORTMATE_OSQUERY_PATH: Path to osquery executable
    
.PARAMETER ApiUrl
    ReportMate API endpoint URL (required)
    
.PARAMETER Passphrase
    Client passphrase for authentication with the ReportMate API
    
.PARAMETER DeviceId
    Custom device identifier (optional - auto-generated if not provided)
    
.PARAMETER ApiKey
    API authentication key (optional)
    
.PARAMETER CollectionInterval
    Data collection interval in seconds (default: 3600 = 1 hour)
    
.PARAMETER LogLevel
    Logging level (default: Information)
    Options: Error, Warning, Information, Debug
    
.PARAMETER OsQueryPath
    Path to osquery executable (default: C:\Program Files\osquery\osqueryi.exe)
    
.PARAMETER ApiTimeoutSeconds
    API request timeout in seconds (default: 300 = 5 minutes)
    
.PARAMETER MaxRetryAttempts
    Maximum retry attempts for failed API requests (default: 3)
    
.PARAMETER ValidateSslCert
    Whether to validate SSL certificates (default: $true, set to $false for testing only)
    
.PARAMETER Force
    Overwrite existing configuration without prompting
    
.PARAMETER ShowConfig
    Display current configuration and exit
    
.PARAMETER Remove
    Remove ReportMate configuration from registry
    
.PARAMETER Test
    Test connectivity to the configured API endpoint
    
.PARAMETER Verbose
    Enable verbose output
    
.EXAMPLE
    .\Set-ReportMatePrefs.ps1 -ApiUrl "https://reportmate.yourdomain.com" -Passphrase "your-secure-passphrase-2025"
    
.EXAMPLE
    .\Set-ReportMatePrefs.ps1 -ApiUrl "https://api.reportmate.ecuad.ca" -Passphrase "ECUAD-RM-2025-PROD" -CollectionInterval 7200 -LogLevel "Debug"
    
.EXAMPLE
    .\Set-ReportMatePrefs.ps1 -ShowConfig
    
.EXAMPLE
    .\Set-ReportMatePrefs.ps1 -Test
    
.EXAMPLE
    .\Set-ReportMatePrefs.ps1 -Remove
    
.NOTES
    Version: 1.0
    Author: ReportMate Team
    Created: $(Get-Date -Format 'yyyy-MM-dd')
    
    This script requires administrative privileges to modify HKLM registry keys.
    
    Registry Locations:
    - Primary: HKLM\SOFTWARE\Config\ReportMate (CSP/Group Policy - highest precedence)
    - Fallback: HKLM\SOFTWARE\ReportMate (standard location)
    
    For cimipkg deployment, package this script and call it from postinstall.ps1:
    & "C:\Program Files\Cimian\Set-ReportMatePrefs.ps1" -ApiUrl "https://your-api.com" -Passphrase "your-passphrase"
#>

[CmdletBinding(DefaultParameterSetName='Configure')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Configure')]
    [ValidateNotNullOrEmpty()]
    [string]$ApiUrl,
    
    [Parameter(ParameterSetName='Configure')]
    [string]$Passphrase = "",
    
    [Parameter(ParameterSetName='Configure')]
    [string]$DeviceId = "",
    
    [Parameter(ParameterSetName='Configure')]
    [string]$ApiKey = "",
    
    [Parameter(ParameterSetName='Configure')]
    [ValidateRange(60, 86400)]
    [int]$CollectionInterval = $DEFAULT_COLLECTION_INTERVAL,
    
    [Parameter(ParameterSetName='Configure')]
    [ValidateSet("Error", "Warning", "Information", "Debug")]
    [string]$LogLevel = $DEFAULT_LOG_LEVEL,
    
    [Parameter(ParameterSetName='Configure')]
    [string]$OsQueryPath = $DEFAULT_OSQUERY_PATH,
    
    [Parameter(ParameterSetName='Configure')]
    [ValidateRange(30, 3600)]
    [int]$ApiTimeoutSeconds = $DEFAULT_API_TIMEOUT,
    
    [Parameter(ParameterSetName='Configure')]
    [ValidateRange(1, 10)]
    [int]$MaxRetryAttempts = $DEFAULT_MAX_RETRIES,
    
    [Parameter(ParameterSetName='Configure')]
    [bool]$ValidateSslCert = $DEFAULT_VALIDATE_SSL,
    
    [Parameter(ParameterSetName='Configure')]
    [switch]$Force,
    
    [Parameter(Mandatory=$true, ParameterSetName='ShowConfig')]
    [switch]$ShowConfig,
    
    [Parameter(Mandatory=$true, ParameterSetName='Remove')]
    [switch]$Remove,
    
    [Parameter(Mandatory=$true, ParameterSetName='Test')]
    [switch]$Test,
    
    [switch]$Verbose
)

# Requires PowerShell 5.0 or later
#Requires -Version 5.0
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

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

# Registry paths (in order of precedence)
$PrimaryRegistryPath = "HKLM:\SOFTWARE\Config\ReportMate"      # CSP/Group Policy location (highest precedence)
$StandardRegistryPath = "HKLM:\SOFTWARE\ReportMate"            # Standard application location

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ReportMateConfiguration {
    $config = @{}
    
    # Check both registry locations
    foreach ($regPath in @($PrimaryRegistryPath, $StandardRegistryPath)) {
        if (Test-Path $regPath) {
            $pathName = if ($regPath -eq $PrimaryRegistryPath) { "CSP/Policy" } else { "Standard" }
            Write-Verbose "Checking registry path: $regPath ($pathName)"
            
            try {
                $regKey = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regKey) {
                    $config[$pathName] = @{}
                    foreach ($property in $regKey.PSObject.Properties) {
                        if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            $config[$pathName][$property.Name] = $property.Value
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not read from $regPath : $_"
            }
        }
    }
    
    return $config
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

function Remove-RegistryKey {
    param(
        [string]$Path
    )
    
    try {
        if (Test-Path $Path) {
            Remove-Item -Path $Path -Recurse -Force
            Write-Success "Removed registry key: $Path"
            return $true
        } else {
            Write-Info "Registry key does not exist: $Path"
            return $true
        }
    } catch {
        Write-Error "Failed to remove registry key $Path : $_"
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
            'User-Agent' = 'ReportMate-ConfigScript/1.0'
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
        Write-Info "Response: $($response | ConvertTo-Json -Compress)"
        return $true
        
    } catch {
        Write-Warning "API connectivity test failed: $_"
        Write-Info "This may be normal if the API endpoint requires authentication or is not accessible from this network."
        return $false
    }
}

function Show-CurrentConfiguration {
    Write-Header "ReportMate Current Configuration"
    Write-Output ""
    
    $config = Get-ReportMateConfiguration
    
    if ($config.Keys.Count -eq 0) {
        Write-Info "No ReportMate configuration found in registry."
        return
    }
    
    foreach ($location in $config.Keys) {
        Write-Info "Registry Location: $location"
        $settings = $config[$location]
        
        if ($settings.Keys.Count -eq 0) {
            Write-Output "  No settings configured"
        } else {
            foreach ($setting in $settings.Keys | Sort-Object) {
                $value = $settings[$setting]
                # Mask sensitive values
                if ($setting -in @('Passphrase', 'ApiKey')) {
                    $value = if ([string]::IsNullOrEmpty($value)) { "(not set)" } else { "[REDACTED]" }
                }
                Write-Output "  $setting : $value"
            }
        }
        Write-Output ""
    }
    
    # Show effective configuration precedence
    Write-Info "Configuration Precedence (highest to lowest):"
    Write-Output "  1. HKLM\SOFTWARE\Config\ReportMate (CSP/Group Policy)"
    Write-Output "  2. HKLM\SOFTWARE\ReportMate (Standard location)"
    Write-Output "  3. Environment variables (REPORTMATE_*)"
    Write-Output "  4. Application configuration files"
    Write-Output ""
}

# Main script logic
Write-Header "ReportMate Client Preferences Configuration"
Write-Output ""

# Check administrative privileges
if (-not (Test-AdminRights)) {
    Write-Error "This script requires administrative privileges to modify registry settings."
    Write-Info "Please run as Administrator or use 'Run as Administrator' option."
    exit 1
}

# Handle different parameter sets
switch ($PSCmdlet.ParameterSetName) {
    'ShowConfig' {
        Show-CurrentConfiguration
        exit 0
    }
    
    'Test' {
        $config = Get-ReportMateConfiguration
        $apiUrl = $null
        $passphrase = $null
        
        # Find API URL from configuration
        foreach ($location in @('CSP/Policy', 'Standard')) {
            if ($config[$location] -and $config[$location]['ApiUrl']) {
                $apiUrl = $config[$location]['ApiUrl']
                $passphrase = $config[$location]['Passphrase']
                break
            }
        }
        
        if (-not $apiUrl) {
            Write-Error "No API URL configured. Run with -ShowConfig to view current settings."
            exit 1
        }
        
        $testResult = Test-ApiConnectivity -ApiUrl $apiUrl -Passphrase $passphrase
        exit $(if ($testResult) { 0 } else { 1 })
    }
    
    'Remove' {
        Write-Warning "This will remove all ReportMate configuration from the registry."
        if (-not $Force) {
            $confirm = Read-Host "Are you sure you want to proceed? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Info "Operation cancelled."
                exit 0
            }
        }
        
        $success = $true
        $success = (Remove-RegistryKey -Path $PrimaryRegistryPath) -and $success
        $success = (Remove-RegistryKey -Path $StandardRegistryPath) -and $success
        
        if ($success) {
            Write-Success "ReportMate configuration removed successfully."
        } else {
            Write-Error "Failed to remove some configuration. Check the logs above."
            exit 1
        }
        exit 0
    }
    
    'Configure' {
        # Use defaults if no parameters provided
        if (-not $PSBoundParameters.ContainsKey('ApiUrl')) {
            $ApiUrl = $DEFAULT_API_URL
        }
        if (-not $PSBoundParameters.ContainsKey('Passphrase') -and $DEFAULT_PASSPHRASE) {
            $Passphrase = $DEFAULT_PASSPHRASE
        }
        if (-not $PSBoundParameters.ContainsKey('DeviceId') -and $DEFAULT_DEVICE_ID_PREFIX) {
            $DeviceId = "$DEFAULT_DEVICE_ID_PREFIX-$env:COMPUTERNAME"
        }
        
        # Validate API URL format
        if (-not $ApiUrl.StartsWith('http://') -and -not $ApiUrl.StartsWith('https://')) {
            Write-Error "API URL must start with http:// or https://"
            exit 1
        }
        
        # Remove trailing slash from API URL
        $ApiUrl = $ApiUrl.TrimEnd('/')
        
        Write-Info "Configuring ReportMate client preferences..."
        Write-Output ""
        
        # Check for existing configuration
        $existingConfig = Get-ReportMateConfiguration
        if ($existingConfig.Keys.Count -gt 0 -and -not $Force) {
            Write-Warning "Existing ReportMate configuration found."
            Show-CurrentConfiguration
            $confirm = Read-Host "Overwrite existing configuration? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Info "Configuration cancelled."
                exit 0
            }
        }
        
        # Use primary registry path (CSP/Group Policy location for highest precedence)
        $targetPath = $PrimaryRegistryPath
        
        Write-Info "Setting configuration in: $targetPath"
        Write-Output ""
        
        # Set configuration values
        $success = $true
        
        # Required settings
        $success = (Set-RegistryValue -Path $targetPath -Name "ApiUrl" -Value $ApiUrl -Type "String") -and $success
        Write-Success "Set API URL: $ApiUrl"
        
        # Optional settings (only set if provided)
        if ($Passphrase) {
            $success = (Set-RegistryValue -Path $targetPath -Name "Passphrase" -Value $Passphrase -Type "String") -and $success
            Write-Success "Set Client Passphrase: [REDACTED]"
        }
        
        if ($DeviceId) {
            $success = (Set-RegistryValue -Path $targetPath -Name "DeviceId" -Value $DeviceId -Type "String") -and $success
            Write-Success "Set Device ID: $DeviceId"
        }
        
        if ($ApiKey) {
            $success = (Set-RegistryValue -Path $targetPath -Name "ApiKey" -Value $ApiKey -Type "String") -and $success
            Write-Success "Set API Key: [REDACTED]"
        }
        
        # Always set these operational settings
        $success = (Set-RegistryValue -Path $targetPath -Name "CollectionInterval" -Value $CollectionInterval -Type "DWord") -and $success
        Write-Success "Set Collection Interval: $CollectionInterval seconds"
        
        $success = (Set-RegistryValue -Path $targetPath -Name "LogLevel" -Value $LogLevel -Type "String") -and $success
        Write-Success "Set Log Level: $LogLevel"
        
        $success = (Set-RegistryValue -Path $targetPath -Name "OsQueryPath" -Value $OsQueryPath -Type "String") -and $success
        Write-Success "Set OsQuery Path: $OsQueryPath"
        
        $success = (Set-RegistryValue -Path $targetPath -Name "ApiTimeoutSeconds" -Value $ApiTimeoutSeconds -Type "DWord") -and $success
        Write-Success "Set API Timeout: $ApiTimeoutSeconds seconds"
        
        $success = (Set-RegistryValue -Path $targetPath -Name "MaxRetryAttempts" -Value $MaxRetryAttempts -Type "DWord") -and $success
        Write-Success "Set Max Retry Attempts: $MaxRetryAttempts"
        
        $success = (Set-RegistryValue -Path $targetPath -Name "ValidateSslCert" -Value $(if ($ValidateSslCert) { 1 } else { 0 }) -Type "DWord") -and $success
        Write-Success "Set SSL Certificate Validation: $ValidateSslCert"
        
        Write-Output ""
        
        if ($success) {
            Write-Success "ReportMate configuration completed successfully!"
            Write-Info "Configuration will take effect on the next ReportMate run."
            
            # Test connectivity if passphrase is provided
            if ($Passphrase) {
                Write-Output ""
                Write-Info "Testing API connectivity..."
                Test-ApiConnectivity -ApiUrl $ApiUrl -Passphrase $Passphrase | Out-Null
            }
            
        } else {
            Write-Error "Configuration completed with errors. Check the output above."
            exit 1
        }
        
        Write-Output ""
        Write-Info "Next Steps:"
        Write-Output "  1. Verify ReportMate client is installed: C:\Program Files\ReportMate\runner.exe"
        Write-Output "  2. Test configuration: runner.exe test --verbose"
        Write-Output "  3. Run manual collection: runner.exe collect"
        Write-Output "  4. Check logs: C:\ProgramData\ManagedReports\logs\"
        Write-Output ""
    }
}

Write-Success "Script completed successfully!"
