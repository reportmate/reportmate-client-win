# ReportMate Post-Installation Script
# Configures the ReportMate client af# Set API URL if provided via environment variable or production default
if ([string]::IsNullOrEmpty($ApiUrl) -and -not [string]::IsNullOrEmpty($PROD_API_URL)) {
    $ApiUrl = $PROD_API_URL
}

if (-not [string]::IsNullOrEmpty($ApiUrl)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl -Type String
        Write-Host "Set API URL: $ApiUrl"
    } catch {
        Write-Warning "Failed to set API URL: $_"
    }
}

# Set API Key if provided via environment variable or production default
if ([string]::IsNullOrEmpty($ApiKey) -and -not [string]::IsNullOrEmpty($PROD_API_KEY)) {
    $ApiKey = $PROD_API_KEY
}

if (-not [string]::IsNullOrEmpty($ApiKey)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiKey" -Value $ApiKey -Type String
        Write-Host "Set API Key: [CONFIGURED]"
    } catch {
        Write-Warning "Failed to set API Key: $_"
    }
}

# Set Passphrase if provided via environment variable or production default
if ([string]::IsNullOrEmpty($Passphrase) -and -not [string]::IsNullOrEmpty($PROD_PASSPHRASE)) {
    $Passphrase = $PROD_PASSPHRASE
}# Can be configured via environment variables, registry, or CSP policies

$ErrorActionPreference = "Continue"

# =================================================================
# PRODUCTION CONFIGURATION VARIABLES
# =================================================================
# Environment variables take precedence, fallback to these defaults
$PROD_API_URL = $env:REPORTMATE_API_URL ?? "https://reportmate-api.azurewebsites.net"
$PROD_API_KEY = $env:REPORTMATE_API_KEY ?? "SeJ2GSq6besIs6OR3edFi5tx7auCjTeptlr9l6Cj2irrwVBetg7piBl7xa8zwFEKBWBI679vVIjxILicQjHtjA=="
$PROD_PASSPHRASE = $env:REPORTMATE_PASSPHRASE ?? "BGXCQm3KN0LZPfnFzAclTt5"
$AUTO_CONFIGURE = [bool]($env:REPORTMATE_AUTO_CONFIGURE ?? $true)

# Initialize configuration variables
$ApiUrl = ""
$ApiKey = ""
$Passphrase = ""

Write-Host "ReportMate Post-Installation Script"
Write-Host "=================================================="

# Check for CSP OMA-URI first (management configs)
$CSPRegistryPath = "HKLM\SOFTWARE\Config\ReportMate"
if (Test-Path $CSPRegistryPath) {
    Write-Host "Found CSP OMA-URI configuration"
    $CSPApiUrl = Get-ItemProperty -Path $CSPRegistryPath -Name "ApiUrl" -ErrorAction SilentlyContinue
    if ($CSPApiUrl -and -not [string]::IsNullOrEmpty($CSPApiUrl.ApiUrl)) {
        $ApiUrl = $CSPApiUrl.ApiUrl
        Write-Host "Using CSP-configured API URL"
    }
    
    $CSPApiKey = Get-ItemProperty -Path $CSPRegistryPath -Name "ApiKey" -ErrorAction SilentlyContinue
    if ($CSPApiKey -and -not [string]::IsNullOrEmpty($CSPApiKey.ApiKey)) {
        $ApiKey = $CSPApiKey.ApiKey
        Write-Host "Using CSP-configured API Key"
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
    # Set collection interval (default: 1 hour)
    Set-ItemProperty -Path $RegistryPath -Name "CollectionInterval" -Value 3600 -Type DWord -ErrorAction SilentlyContinue
    
    # Set log level (default: Information)
    Set-ItemProperty -Path $RegistryPath -Name "LogLevel" -Value "Information" -Type String -ErrorAction SilentlyContinue
    
    # Set osquery path (default)
    Set-ItemProperty -Path $RegistryPath -Name "OsQueryPath" -Value "C:\Program Files\osquery\osqueryi.exe" -Type String -ErrorAction SilentlyContinue
    
    # Set osquery config path for ReportMate
    Set-ItemProperty -Path $RegistryPath -Name "OsQueryConfigPath" -Value "C:\ProgramData\ManagedReports\osquery" -Type String -ErrorAction SilentlyContinue
    
    Write-Host "Set default configuration values"
} catch {
    Write-Warning "Failed to set default configuration: $_"
}

# Set API URL if provided via environment variable or use production default
if (-not [string]::IsNullOrEmpty($PROD_API_URL)) {
    $ApiUrl = $PROD_API_URL
}

if (-not [string]::IsNullOrEmpty($ApiUrl)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl -Type String
        Write-Host "Set API URL: $ApiUrl"
    } catch {
        Write-Warning "Failed to set API URL: $_"
    }
}

# Set Passphrase if provided via environment variable or production default
if (-not [string]::IsNullOrEmpty($PROD_PASSPHRASE)) {
    $Passphrase = $PROD_PASSPHRASE
}

if (-not [string]::IsNullOrEmpty($Passphrase)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "Passphrase" -Value $Passphrase -Type String
        Write-Host "Set Client Passphrase: [CONFIGURED]"
    } catch {
        Write-Warning "Failed to set Client Passphrase: $_"
    }
}

# Note: DeviceId is automatically determined by ReportMate using hardware serial number detection
# Registry override is only needed for special cases and should be set manually if required

# Create data directories
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

# Test installation
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
Write-Host "  API Key: $(if ($ApiKey) { '[CONFIGURED]' } else { 'Not set' })"
Write-Host "  Passphrase: $(if ($Passphrase) { '[CONFIGURED]' } else { 'Not set' })"
Write-Host "  Auto-Configure: $AUTO_CONFIGURE"
Write-Host ""
Write-Host "Registry Locations:"
Write-Host "  CSP/Policy: HKLM\SOFTWARE\Config\ReportMate (highest precedence)"
Write-Host "  Standard: HKLM\SOFTWARE\ReportMate"
Write-Host ""
Write-Host "Environment Variables (override defaults):"
Write-Host "  REPORTMATE_API_URL - Override production API URL"
Write-Host "  REPORTMATE_API_KEY - Override production API key"
Write-Host "  REPORTMATE_PASSPHRASE - Override production passphrase"
Write-Host "  REPORTMATE_AUTO_CONFIGURE - Override auto-configuration setting"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Configuration is ready - ReportMate will use registry settings automatically"
Write-Host "2. Test connectivity: & 'C:\Program Files\ReportMate\runner.exe' test"
Write-Host "3. Run data collection: & 'C:\Program Files\ReportMate\runner.exe' run"
