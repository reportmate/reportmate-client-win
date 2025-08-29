#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build script for ReportMatePrefs cimipkg package
    
.DESCRIPTION
    This script builds the ReportMatePrefs package using cimipkg.
    It copies the necessary files and creates the package.
    
.PARAMETER Version
    Package version (default: 1.0.0)
    
.PARAMETER Clean
    Clean the payload directory before building
    
.EXAMPLE
    .\build-pkg.ps1
    
.EXAMPLE
    .\build-pkg.ps1 -Version "1.1.0" -Clean
#>

param(
    [string]$Version = "1.0.0",
    [switch]$Clean
)

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

Write-Header "Building ReportMatePrefs Package"
Write-Output ""

$pkgDir = $PSScriptRoot
$payloadDir = Join-Path $pkgDir "payload"
$sourceScript = Join-Path (Split-Path $pkgDir -Parent) "Set-ReportMatePrefs.ps1"
$buildInfoPath = Join-Path $pkgDir "build-info.yaml"

Write-Info "Package Directory: $pkgDir"
Write-Info "Payload Directory: $payloadDir"
Write-Info "Source Script: $sourceScript"
Write-Output ""

# Clean payload directory if requested
if ($Clean -and (Test-Path $payloadDir)) {
    Write-Info "Cleaning payload directory..."
    Remove-Item $payloadDir -Recurse -Force
    New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
    Write-Success "Payload directory cleaned"
}

# Create payload directory if it doesn't exist
if (-not (Test-Path $payloadDir)) {
    New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
    Write-Info "Created payload directory"
}

# Check if this is the new simplified package structure
$newStructure = $true  # We no longer need the separate Set-ReportMatePrefs.ps1 file

if ($newStructure) {
    Write-Info "Using simplified package structure (postinstall.ps1 only)"
    Write-Success "No additional payload files needed - postinstall.ps1 contains all functionality"
} else {
    # Check if source script exists (old structure)
    if (-not (Test-Path $sourceScript)) {
        Write-Error "Source script not found: $sourceScript"
        Write-Info "Make sure Set-ReportMatePrefs.ps1 exists in the parent directory"
        exit 1
    }

    # Copy the main script to payload
    Write-Info "Copying source script to payload..."
    $destScript = Join-Path $payloadDir "Set-ReportMatePrefs.ps1"
    Copy-Item $sourceScript $destScript -Force
    Write-Success "Copied Set-ReportMatePrefs.ps1 to payload"
}

# Update version in build-info.yaml
if (Test-Path $buildInfoPath) {
    Write-Info "Updating version in build-info.yaml..."
    $content = Get-Content $buildInfoPath -Raw
    $content = $content -replace 'version: ".*?"', "version: `"$Version`""
    Set-Content $buildInfoPath $content -Encoding UTF8 -NoNewline
    Write-Success "Updated version to: $Version"
}

# Check for cimipkg
$cimipkgPath = Get-Command cimipkg -ErrorAction SilentlyContinue
if (-not $cimipkgPath) {
    Write-Warning "cimipkg not found in PATH"
    Write-Info "Looking for cimipkg in common locations..."
    
    # Try to find cimipkg
    $possiblePaths = @(
        ".\cimipkg.exe",
        "..\cimipkg.exe",
        "..\..\cimipkg.exe"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $cimipkgPath = @{ Source = (Resolve-Path $path).Path }
            Write-Success "Found cimipkg at: $($cimipkgPath.Source)"
            break
        }
    }
    
    if (-not $cimipkgPath) {
        Write-Error "cimipkg not found. Please ensure it's in your PATH or current directory."
        Write-Info "Download from: https://github.com/windowsadmins/cimian-pkg/releases"
        exit 1
    }
}

# Build the package
Write-Info "Building package with cimipkg..."
try {
    Push-Location $pkgDir
    
    if ($cimipkgPath.Source) {
        # Use explicit path
        & $cimipkgPath.Source .
    } else {
        # Use from PATH
        cimipkg .
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Package built successfully!"
        
        # Find the generated package
        $nupkgFiles = Get-ChildItem -Path "." -Filter "*.nupkg"
        if ($nupkgFiles) {
            foreach ($pkg in $nupkgFiles) {
                $size = [math]::Round($pkg.Length / 1KB, 1)
                Write-Success "Generated: $($pkg.Name) ($size KB)"
            }
        }
    } else {
        Write-Error "Package build failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    
} catch {
    Write-Error "Failed to build package: $_"
    exit 1
} finally {
    Pop-Location
}

Write-Output ""
Write-Info "Next Steps:"
Write-Output "  1. Test the package: choco install ReportMatePrefs-$Version.nupkg --source=."
Write-Output "  2. Deploy via Cimian package management"
Write-Output "  3. Configure production settings in postinstall.ps1"
Write-Output ""

Write-Success "Build completed successfully!"
