#!/usr/bin/env pwsh
<#
.SYNOPSIS
    ReportMatePrefs Package Pre-Removal Script
    
.DESCRIPTION
    This script runs before the ReportMatePrefs package is removed.
    It provides options for cleaning up ReportMate configuration.
#>

$ErrorActionPreference = "Continue"  # Continue on errors during cleanup

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
function Write-Info { Write-ColorOutput Cyan "ℹ️  $($args -join ' ')" }
function Write-Header { Write-ColorOutput Magenta "🚀 $($args -join ' ')" }

Write-Header "ReportMatePrefs Package Pre-Removal"
Write-Output ""

$scriptPath = "C:\Program Files\Cimian\Set-ReportMatePrefs.ps1"

# Check if the configuration script is available for cleanup
if (Test-Path $scriptPath) {
    Write-Info "ReportMate configuration script found."
    Write-Info "Checking for existing ReportMate configuration..."
    
    try {
        # Show current configuration
        & $scriptPath -ShowConfig
        
        # Optional: Uncomment the following lines to automatically remove
        # ReportMate configuration when the package is removed
        
        # Write-Info "Removing ReportMate configuration..."
        # & $scriptPath -Remove -Force
        # Write-Success "ReportMate configuration removed."
        
    } catch {
        Write-Warning "Could not check ReportMate configuration: $_"
    }
} else {
    Write-Info "ReportMate configuration script not found (already removed or not installed)."
}

Write-Output ""
Write-Info "Package removal notes:"
Write-Output "  - The ReportMatePrefs configuration script will be removed"
Write-Output "  - ReportMate client configuration in registry will remain intact"
Write-Output "  - To remove ReportMate configuration, run before uninstalling:"
Write-Output "    & `"$scriptPath`" -Remove"
Write-Output ""

Write-Success "Pre-removal checks completed."
