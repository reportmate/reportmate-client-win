# ReportMate Configuration Setup Script
# Shared between MSI and NUPKG installers
# Handles API configuration and registry setup

param(
    [string]$ApiUrl = "",
    [string]$ApiKey = "",
    [string]$InstallPath = "C:\Program Files\ReportMate",
    [string]$DataPath = "C:\ProgramData\ManagedReports",
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

Write-Log "ReportMate Configuration Setup Started"

# Create data directory if it doesn't exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    Write-Log "Created data directory: $DataPath"
}

# Set up registry configuration
$registryPath = "HKLM:\SOFTWARE\ReportMate"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Log "Created registry key: $registryPath"
}

# Set registry values
Set-ItemProperty -Path $registryPath -Name "InstallPath" -Value $InstallPath
Set-ItemProperty -Path $registryPath -Name "DataPath" -Value $DataPath
Set-ItemProperty -Path $registryPath -Name "ConfiguredDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

if ($ApiUrl) {
    Set-ItemProperty -Path $registryPath -Name "ApiUrl" -Value $ApiUrl
    Write-Log "Configured API URL: $ApiUrl"
}

if ($ApiKey) {
    Set-ItemProperty -Path $registryPath -Name "ApiKey" -Value $ApiKey
    Write-Log "Configured API Key (length: $($ApiKey.Length))"
}

# Set appropriate permissions on data directory
try {
    $acl = Get-Acl $DataPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $DataPath -AclObject $acl
    Write-Log "Set permissions on data directory"
} catch {
    Write-Log "Warning: Could not set permissions on data directory: $($_.Exception.Message)" "WARN"
}

Write-Log "ReportMate Configuration Setup Completed Successfully"
