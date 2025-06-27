# ReportMate Windows Client Post-Installation Script
# Configures the ReportMate client after installation

param(
    [string]$ApiUrl = "",
    [string]$DeviceId = "",
    [string]$ApiKey = ""
)

$ErrorActionPreference = "Continue"

Write-Host "ReportMate Windows Client Post-Installation Script"
Write-Host "=================================================="

# Create registry key if it doesn't exist
$RegistryPath = "HKLM:\SOFTWARE\ReportMate"
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
    
    Write-Host "Set default configuration values"
} catch {
    Write-Warning "Failed to set default configuration: $_"
}

# Set API URL if provided via environment variable or parameter
$EnvApiUrl = $env:REPORTMATE_API_URL
if (-not [string]::IsNullOrEmpty($EnvApiUrl)) {
    $ApiUrl = $EnvApiUrl
}

if (-not [string]::IsNullOrEmpty($ApiUrl)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl -Type String
        Write-Host "Set API URL: $ApiUrl"
    } catch {
        Write-Warning "Failed to set API URL: $_"
    }
}

# Set Device ID if provided
$EnvDeviceId = $env:REPORTMATE_DEVICE_ID
if (-not [string]::IsNullOrEmpty($EnvDeviceId)) {
    $DeviceId = $EnvDeviceId
}

if (-not [string]::IsNullOrEmpty($DeviceId)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "DeviceId" -Value $DeviceId -Type String
        Write-Host "Set Device ID: $DeviceId"
    } catch {
        Write-Warning "Failed to set Device ID: $_"
    }
}

# Set API Key if provided
$EnvApiKey = $env:REPORTMATE_API_KEY
if (-not [string]::IsNullOrEmpty($EnvApiKey)) {
    $ApiKey = $EnvApiKey
}

if (-not [string]::IsNullOrEmpty($ApiKey)) {
    try {
        Set-ItemProperty -Path $RegistryPath -Name "ApiKey" -Value $ApiKey -Type String
        Write-Host "Set API Key: [REDACTED]"
    } catch {
        Write-Warning "Failed to set API Key: $_"
    }
}

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
Write-Host "Next steps:"
Write-Host "1. Configure API URL: Set-ItemProperty -Path 'HKLM:\SOFTWARE\ReportMate' -Name 'ApiUrl' -Value 'https://your-api.azurewebsites.net'"
Write-Host "2. Test connectivity: & 'C:\Program Files\ReportMate\runner.exe' test"
Write-Host "3. Run data collection: & 'C:\Program Files\ReportMate\runner.exe' run"
