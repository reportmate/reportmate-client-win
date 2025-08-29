#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy ReportMatePrefs with Environment Variables
    
.DESCRIPTION
    This script sets up environment variables and deploys the ReportMatePrefs package.
    It demonstrates how to configure different environments using environment variables.
    
.PARAMETER Environment
    Target environment (dev, test, prod)
    
.PARAMETER Deploy
    Actually deploy the package (otherwise just show configuration)
    
.PARAMETER Clean
    Clean build before deployment
    
.EXAMPLE
    .\Deploy-ReportMatePrefs.ps1 -Environment prod -Deploy
    
.EXAMPLE
    .\Deploy-ReportMatePrefs.ps1 -Environment dev
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("dev", "test", "prod")]
    [string]$Environment,
    
    [switch]$Deploy,
    [switch]$Clean
)

# =================================================================
# ENVIRONMENT CONFIGURATIONS
# =================================================================

$configurations = @{
    'prod' = @{
        API_URL = "https://reportmate.ecuad.ca"
        PASSPHRASE = "BGXCQm3KN0LZPfnFzAclTt5"
        DEVICE_PREFIX = "ECUAD"
        COLLECTION_INTERVAL = 3600  # 1 hour
        LOG_LEVEL = "Information"
        VALIDATE_SSL = $true
        AUTO_CONFIGURE = $true
        FORCE_CONFIG = $true
        TEST_CONNECTIVITY = $true
    }
    'test' = @{
        API_URL = "https://reportmate-test.ecuad.ca"
        PASSPHRASE = "BGXCQm3KN0LZPfnFzAclTt5-TEST"
        DEVICE_PREFIX = "ECUAD-TEST"
        COLLECTION_INTERVAL = 1800  # 30 minutes
        LOG_LEVEL = "Debug"
        VALIDATE_SSL = $false  # For testing with self-signed certs
        AUTO_CONFIGURE = $true
        FORCE_CONFIG = $true
        TEST_CONNECTIVITY = $true
    }
    'dev' = @{
        API_URL = "https://reportmate-dev.ecuad.ca"
        PASSPHRASE = "BGXCQm3KN0LZPfnFzAclTt5-DEV"
        DEVICE_PREFIX = "ECUAD-DEV"
        COLLECTION_INTERVAL = 900   # 15 minutes
        LOG_LEVEL = "Debug"
        VALIDATE_SSL = $false
        AUTO_CONFIGURE = $true
        FORCE_CONFIG = $true
        TEST_CONNECTIVITY = $false  # Skip connectivity test in dev
    }
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

Write-Header "ReportMatePrefs Deployment Script"
Write-Header "Environment: $Environment"
Write-Output ""

# Get configuration for the specified environment
$config = $configurations[$Environment]
if (-not $config) {
    Write-Error "Unknown environment: $Environment"
    exit 1
}

# Set environment variables
Write-Info "Setting environment variables for $Environment environment..."
$env:REPORTMATE_API_URL = $config.API_URL
$env:REPORTMATE_PASSPHRASE = $config.PASSPHRASE
$env:REPORTMATE_DEVICE_PREFIX = $config.DEVICE_PREFIX
$env:REPORTMATE_COLLECTION_INTERVAL = $config.COLLECTION_INTERVAL.ToString()
$env:REPORTMATE_LOG_LEVEL = $config.LOG_LEVEL
$env:REPORTMATE_VALIDATE_SSL = $config.VALIDATE_SSL.ToString()
$env:REPORTMATE_AUTO_CONFIGURE = $config.AUTO_CONFIGURE.ToString()
$env:REPORTMATE_FORCE_CONFIG = $config.FORCE_CONFIG.ToString()
$env:REPORTMATE_TEST_CONNECTIVITY = $config.TEST_CONNECTIVITY.ToString()

Write-Success "Environment variables configured"
Write-Output ""

# Display configuration
Write-Info "Configuration for $Environment environment:"
Write-Output "  API URL: $($config.API_URL)"
Write-Output "  Device Prefix: $($config.DEVICE_PREFIX)"
Write-Output "  Collection Interval: $($config.COLLECTION_INTERVAL) seconds"
Write-Output "  Log Level: $($config.LOG_LEVEL)"
Write-Output "  SSL Validation: $($config.VALIDATE_SSL)"
Write-Output "  Auto Configure: $($config.AUTO_CONFIGURE)"
Write-Output "  Force Config: $($config.FORCE_CONFIG)"
Write-Output "  Test Connectivity: $($config.TEST_CONNECTIVITY)"
Write-Output "  Passphrase: [REDACTED]"
Write-Output ""

if ($Deploy) {
    # Build the package
    Write-Info "Building ReportMatePrefs package..."
    
    $buildScript = Join-Path $PSScriptRoot "build-pkg.ps1"
    if (-not (Test-Path $buildScript)) {
        Write-Error "Build script not found: $buildScript"
        exit 1
    }
    
    try {
        if ($Clean) {
            & $buildScript -Clean
        } else {
            & $buildScript
        }
        
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed with exit code: $LASTEXITCODE"
        }
        
        Write-Success "Package built successfully"
        
        # Find the generated package
        $nupkgFiles = Get-ChildItem -Path "." -Filter "*.nupkg"
        if ($nupkgFiles) {
            $latestPkg = $nupkgFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Success "Package ready: $($latestPkg.Name)"
            
            Write-Output ""
            Write-Info "Deployment Commands:"
            Write-Output ""
            Write-Output "# Install locally for testing:"
            Write-Output "choco install `"$($latestPkg.FullName)`" --source=. --force --yes"
            Write-Output ""
            Write-Output "# Deploy via Cimian to managed devices:"
            Write-Output "# (Copy $($latestPkg.Name) to your Cimian package repository)"
            Write-Output ""
            
        } else {
            Write-Warning "No package files found after build"
        }
        
    } catch {
        Write-Error "Failed to build package: $_"
        exit 1
    }
    
} else {
    Write-Info "Use -Deploy to actually build and prepare the package"
    Write-Output ""
    Write-Info "To deploy this configuration:"
    Write-Output "  .\Deploy-ReportMatePrefs.ps1 -Environment $Environment -Deploy"
}

Write-Output ""
Write-Info "Environment Variable Export (for CI/CD):"
Write-Output ""
Write-Output "export REPORTMATE_API_URL=`"$($config.API_URL)`""
Write-Output "export REPORTMATE_PASSPHRASE=`"$($config.PASSPHRASE)`""
Write-Output "export REPORTMATE_DEVICE_PREFIX=`"$($config.DEVICE_PREFIX)`""
Write-Output "export REPORTMATE_COLLECTION_INTERVAL=`"$($config.COLLECTION_INTERVAL)`""
Write-Output "export REPORTMATE_LOG_LEVEL=`"$($config.LOG_LEVEL)`""
Write-Output "export REPORTMATE_VALIDATE_SSL=`"$($config.VALIDATE_SSL)`""
Write-Output "export REPORTMATE_AUTO_CONFIGURE=`"$($config.AUTO_CONFIGURE)`""
Write-Output "export REPORTMATE_FORCE_CONFIG=`"$($config.FORCE_CONFIG)`""
Write-Output "export REPORTMATE_TEST_CONNECTIVITY=`"$($config.TEST_CONNECTIVITY)`""
Write-Output ""

Write-Success "Deployment script completed!"
