#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    ReportMate Unified Build Script
    
.DESCRIPTION
    One-stop build script that replicates the CI pipeline locally.
    Builds all package types: EXE, NUPKG, and ZIP.
    Supports creating tags and releases when run with appropriate parameters.
    
.PARAMETER Version
    Version to build (default: auto-generated from date in YYYY.MM.DD format)
    
.PARAMETER Configuration
    Build configuration (Release or Debug)
    
.PARAMETER SkipBuild
    Skip the .NET build step
    
.PARAMETER SkipNUPKG
    Skip NUPKG creation
    
.PARAMETER SkipZIP
    Skip ZIP creation

.PARAMETER SkipMSI
    Skip MSI creation
    
.PARAMETER Clean
    Clean all build artifacts first
    
.PARAMETER ApiUrl
    Default API URL to configure in the installer
    
.PARAMETER CreateTag
    Create and push a date-based git tag (YYYY.MM.DD format)
    
.PARAMETER CreateRelease
    Create a GitHub release (requires gh CLI)
    
.PARAMETER Verbose
    Enable verbose output for debugging

.PARAMETER Sign
    Force code signing of the executable

.PARAMETER NoSign
    Disable auto-signing even if enterprise cert is found

.PARAMETER Thumbprint
    Override auto-detection with specific certificate thumbprint

.PARAMETER Install
    Automatically install the built package using the preferred method (MSI if available, otherwise NUPKG via chocolatey) - requires admin privileges
    
.EXAMPLE
    .\build.ps1
    Build with auto-generated version (YYYY.MM.DD format)
    
.EXAMPLE
    .\build.ps1 -Version "2024.06.27" -ApiUrl "https://api.reportmate.com"
    Build specific version with API URL
    
.EXAMPLE
    .\build.ps1 -Clean -Verbose
    Clean build with verbose output
    
.EXAMPLE
    .\build.ps1 -CreateTag -CreateRelease
    Build, create tag, and create GitHub release
    
.EXAMPLE
    .\build.ps1 -Version "2024.06.27" -CreateTag -CreateRelease -ApiUrl "https://api.reportmate.com"
    Full production build with tagging and release

.EXAMPLE
    .\build.ps1 -Sign
    Build with forced code signing

.EXAMPLE
    .\build.ps1 -NoSign
    Build without code signing (even if cert is available)

.EXAMPLE
    .\build.ps1 -Install
    Build and automatically install the MSI package (requires admin privileges)

.EXAMPLE
    .\build.ps1 -SkipNUPKG -SkipZIP
    Build only EXE and MSI (skip NUPKG and ZIP)
#>

param(
    [string]$Version = "",
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [switch]$SkipBuild = $false,
    [switch]$SkipNUPKG = $false,
    [switch]$SkipZIP = $false,
    [switch]$SkipMSI = $false,
    [switch]$Clean = $false,
    [string]$ApiUrl = "",
    [switch]$CreateTag = $false,
    [switch]$CreateRelease = $false,
    [switch]$Verbose = $false,
    [switch]$Sign,
    [switch]$NoSign,
    [switch]$Install = $false,
    [string]$Thumbprint
)

# Ensure we're using PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Colors for output (with emoji for better UX)
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
function Write-Step { Write-ColorOutput Yellow "🔄 $($args -join ' ')" }

# ──────────────────────────  SIGNING FUNCTIONS  ──────────────────────────
# Friendly name (CN) of the enterprise code-signing certificate you push with Intune
$Global:EnterpriseCertCN = 'EmilyCarrU Intune Windows Enterprise Certificate'

function Get-SigningCertThumbprint {
    [OutputType([string])]
    param()

    Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -like "*CN=$Global:EnterpriseCertCN*" -and
            $_.NotAfter -gt (Get-Date) -and
            $_.HasPrivateKey
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1 -ExpandProperty Thumbprint
}

# Function to ensure signtool is available
function Test-SignTool {
    # helper to prepend path only once
    function Add-ToPath([string]$dir) {
        if (-not [string]::IsNullOrWhiteSpace($dir) -and
            -not ($env:Path -split ';' | Where-Object { $_ -ieq $dir })) {
            $env:Path = "$dir;$env:Path"
        }
    }

    # already reachable?
    if (Get-Command signtool.exe -EA SilentlyContinue) { return }

    # harvest possible SDK roots
    $roots = @(
        "${env:ProgramFiles}\Windows Kits\10\bin",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    )

    # add KitsRoot10 from the registry (covers non-standard installs)
    try {
        $kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
                     -EA Stop).KitsRoot10
        if ($kitsRoot) { $roots += (Join-Path $kitsRoot 'bin') }
    } catch { }

    $roots = $roots | Where-Object { Test-Path $_ } | Select-Object -Unique

    # scan every root for any architecture's signtool.exe
    foreach ($root in $roots) {
        $exe = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -EA SilentlyContinue |
               Sort-Object LastWriteTime -Desc | Select-Object -First 1
        if ($exe) {
            Add-ToPath $exe.Directory.FullName
            Write-Success "signtool discovered at $($exe.FullName)"
            return
        }
    }

    # graceful failure
    Write-Error @"
signtool.exe not found.

Install **any** Windows 10/11 SDK _or_ Visual Studio Build Tools  
(choose a workload that includes **Windows SDK Signing Tools**),  
then run the build again.
"@
    exit 1
}

function signPackage {
    <#
      .SYNOPSIS  Authenticode-signs an EXE/MSI/... with our enterprise cert.
      .PARAMETER FilePath     – the file you want to sign
      .PARAMETER Thumbprint   – SHA-1 thumbprint of the cert (defaults to $env:SIGN_THUMB)
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Thumbprint = $env:SIGN_THUMB
    )

    $tsaList = @(
        'http://timestamp.digicert.com',
        'http://timestamp.sectigo.com',
        'http://timestamp.entrust.net/TSS/RFC3161sha2TS'
    )

    foreach ($tsa in $tsaList) {
        Write-Info "Signing '$FilePath' using $tsa ..."
        & signtool.exe sign `
            /sha1  $Thumbprint `
            /fd    SHA256 `
            /tr    $tsa `
            /td    SHA256 `
            /v `
            "$FilePath"

        if ($LASTEXITCODE -eq 0) {
            Write-Success "signtool succeeded with $tsa"
            return
        }
        Write-Warning "signtool failed with $tsa (exit $LASTEXITCODE)"
    }

    throw "signtool failed with all timestamp authorities."
}

# Generate version if not provided (YYYY.MM.DD format)
if (-not $Version) {
    $Version = Get-Date -Format "yyyy.MM.dd"
    Write-Info "Auto-generated version: $Version"
}

# ──────────────────────────  SIGNING DECISION  ─────────────────
# Auto-detect enterprise certificate if available and enforce signing by default
$autoDetectedThumbprint = $null
if (-not $NoSign) {
    try {
        $autoDetectedThumbprint = Get-SigningCertThumbprint
        if ($autoDetectedThumbprint) {
            Write-Info "Auto-detected enterprise certificate $autoDetectedThumbprint - will sign binaries for security."
            $Sign = $true
            $Thumbprint = $autoDetectedThumbprint
        } else {
            Write-Warning "No enterprise certificate found - binaries will be unsigned (may be blocked by Defender)."
            Write-Warning "Consider using -NoSign to explicitly disable signing warnings."
        }
    }
    catch {
        Write-Warning "Could not check for enterprise certificates: $_"
    }
}

if ($NoSign) {
    Write-Info "NoSign parameter specified - skipping all signing."
    $Sign = $false
}

if ($Sign) {
    Test-SignTool
    if (-not $Thumbprint) {
        $Thumbprint = Get-SigningCertThumbprint
        if (-not $Thumbprint) {
            Write-Error "No valid '$Global:EnterpriseCertCN' certificate with a private key found – aborting."
            exit 1
        }
        Write-Info "Auto-selected signing cert $Thumbprint"
    } else {
        Write-Info "Using signing certificate $Thumbprint"
    }
    $env:SIGN_THUMB = $Thumbprint   # used by the signPackage function
} else {
    Write-Info "Build will be unsigned."
}

Write-Header "ReportMate Unified Build Script"
Write-Header "====================================="
Write-Info "Version: $Version"
Write-Info "Configuration: $Configuration"
if ($Sign) {
    Write-Info "🔒 Code signing: ENABLED (Cert: $($Thumbprint.Substring(0,8))...)"
} else {
    Write-Info "🔓 Code signing: DISABLED"
}
Write-Info "PowerShell: $($PSVersionTable.PSVersion)"
Write-Info "Platform: $($PSVersionTable.Platform)"

if ($CreateTag) {
    Write-Info "🏷️  Will create git tag: $Version"
}
if ($CreateRelease) {
    Write-Info "🚀 Will create GitHub release"
}

Write-Output ""

# Set paths (use Join-Path for proper Windows path handling)
$RootDir = $PSScriptRoot
$SrcDir = Join-Path $RootDir "src"
$BuildDir = Join-Path $RootDir "build"
$NupkgDir = Join-Path $BuildDir "nupkg"
$ProgramFilesPayloadDir = Join-Path $NupkgDir "payload"
$ProgramDataPayloadDir = Join-Path $NupkgDir "payload\data"
$CimianPayloadDir = Join-Path $NupkgDir "payload\cimian"
$MsiStagingDir = Join-Path $RootDir "dist\msi-staging"
$PublishDir = Join-Path $RootDir ".publish"
$OutputDir = Join-Path $RootDir "dist"

Write-Info "Root Directory: $RootDir"
Write-Info "Output Directory: $OutputDir"
Write-Output ""

# Clean previous builds if requested
if ($Clean) {
    Write-Step "Cleaning previous builds..."
    @($PublishDir, $OutputDir, $ProgramFilesPayloadDir, $ProgramDataPayloadDir) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue
            Write-Verbose "Cleaned: $_"
        }
    }
    Write-Success "Clean completed"
    Write-Output ""
}

# Clean old binaries from previous builds (always, not just when -Clean is specified)
Write-Step "Cleaning old binaries from .publish and dist directories..."
$cleanupPaths = @(
    (Join-Path $PublishDir "*.exe"),
    (Join-Path $PublishDir "*.dll"), 
    (Join-Path $PublishDir "*.pdb"),
    (Join-Path $OutputDir "*.nupkg"),
    (Join-Path $OutputDir "*.zip"), 
    (Join-Path $OutputDir "*.msi"),
    (Join-Path $OutputDir "*.exe")
)

foreach ($pattern in $cleanupPaths) {
    $oldFiles = Get-ChildItem $pattern -ErrorAction SilentlyContinue
    if ($oldFiles) {
        $oldFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Verbose "Removed old files: $($oldFiles.Name -join ', ')"
    }
}
Write-Success "Old binaries and artifacts cleaned"
Write-Output ""

# Create directories
Write-Step "Creating directories..."
@($PublishDir, $OutputDir, $ProgramFilesPayloadDir, $ProgramDataPayloadDir, $CimianPayloadDir, $MsiStagingDir) | ForEach-Object {
    New-Item -ItemType Directory -Path $_ -Force | Out-Null
    Write-Verbose "Created: $_"
}
Write-Success "Directories created"
Write-Output ""

# Check prerequisites
Write-Step "Checking prerequisites..."

# Check .NET SDK
try {
    $dotnetVersion = dotnet --version
    Write-Success ".NET SDK: $dotnetVersion"
} catch {
    Write-Error ".NET SDK not found. Please install .NET 8.0 SDK"
    exit 1
}

# Check Git (for tagging)
$gitFound = $false
if ($CreateTag -or $CreateRelease) {
    try {
        $gitVersion = git --version
        Write-Success "Git: $gitVersion"
        $gitFound = $true
    } catch {
        Write-Warning "Git not found - tagging and releases will be skipped"
        $CreateTag = $false
        $CreateRelease = $false
    }
}

# Check GitHub CLI (for releases)
$ghFound = $false
if ($CreateRelease) {
    try {
        $ghVersion = gh --version | Select-Object -First 1
        Write-Success "GitHub CLI: $ghVersion"
        $ghFound = $true
    } catch {
        Write-Warning "GitHub CLI not found - release creation will be skipped"
        $CreateRelease = $false
    }
}

# Check cimipkg (for NUPKG)
$cimipkgPath = $null
if (-not $SkipNUPKG) {
    $cimipkgLocations = @(
        (Get-Command cimipkg -ErrorAction SilentlyContinue)?.Source,
        "$RootDir/cimipkg.exe",
        "$OutputDir/cimipkg.exe"
    )
    
    # Find the first location that exists and has content
    foreach ($location in $cimipkgLocations) {
        if ($location -and (Test-Path $location -ErrorAction SilentlyContinue)) {
            $cimipkgPath = $location
            Write-Success "cimipkg found: $cimipkgPath"
            break
        }
    }
    
    if (-not $cimipkgPath) {
        Write-Warning "cimipkg not found - will attempt to download"
    }
}

# Check WiX Toolset v6 (for MSI)
$wixFound = $false
if (-not $SkipMSI) {
    # First, restore any local dotnet tools from manifest
    try {
        Write-Verbose "Restoring dotnet tools from manifest..."
        & dotnet tool restore 2>$null | Out-Null
    } catch {
        Write-Verbose "No dotnet tools manifest found or restoration failed"
    }
    
    # Check if WiX v6 is available via dotnet tool
    try {
        $null = & dotnet wix --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            $wixFound = $true
            Write-Success "WiX Toolset v6 found"
        }
    } catch {
        # Fallback: Check if WiX v6 is installed as dotnet tool (global or local)
        $globalWix = & dotnet tool list --global 2>$null | Select-String "wix"
        $localWix = & dotnet tool list 2>$null | Select-String "wix"
        
        if ($globalWix -or $localWix) {
            $wixFound = $true
            if ($localWix) {
                Write-Success "WiX Toolset v6 found as dotnet local tool"
            } else {
                Write-Success "WiX Toolset v6 found as dotnet global tool"
            }
        }
    }
    
    if (-not $wixFound) {
        Write-Warning "WiX Toolset v6 not found - MSI creation will be skipped"
        Write-Info "Install with: dotnet tool install --global wix --version 6.0.1"
        Write-Info "Or locally: dotnet tool install wix --version 6.0.1"
        $SkipMSI = $true
    }
}

Write-Output ""

# Build .NET application
if (-not $SkipBuild) {
    Write-Step "Building .NET application..."
    
    # Update version in project file - now handled by dynamic VersionPrefix in .csproj
    $csprojPath = Join-Path $SrcDir "ReportMate.WindowsClient.csproj"
    Write-Verbose "Using dynamic versioning from project file: $csprojPath"
    
    Write-Info "Building with version: $Version"
    
    # Restore dependencies
    Write-Verbose "Restoring NuGet packages..."
    dotnet restore $csprojPath --verbosity quiet
    
    # Build
    Write-Verbose "Building in $Configuration configuration..."
    dotnet build $csprojPath --configuration $Configuration --no-restore --verbosity quiet
    
    # Publish self-contained executable
    Write-Verbose "Publishing self-contained executable..."
    dotnet publish $csprojPath `
        --configuration $Configuration `
        --runtime win-x64 `
        --self-contained true `
        --output $PublishDir `
        -p:PublishSingleFile=true `
        -p:PublishTrimmed=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        --verbosity quiet
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Build completed successfully"
        $exeSize = (Get-Item "$PublishDir/runner.exe").Length / 1MB
        Write-Info "Executable size: $([math]::Round($exeSize, 2)) MB"
        
        # ─────────────── SIGN THE EXECUTABLE ───────────────
        if ($Sign) {
            Write-Step "Signing runner.exe..."
            try {
                signPackage -FilePath "$PublishDir/runner.exe"
                Write-Success "Signed runner.exe ✔"
            }
            catch {
                Write-Error "Failed to sign runner.exe: $_"
                exit 1
            }
        }
    } else {
        Write-Error "Build failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} else {
    Write-Info "Skipping build step"
}

Write-Output ""

# Prepare package payload
Write-Step "Preparing package payload..."

# Copy executable to payload root (will be installed to Program Files/ReportMate)
Copy-Item (Join-Path $PublishDir "runner.exe") $ProgramFilesPayloadDir -Force
Write-Verbose "Copied runner.exe to payload root"

# Create version file in payload root
$versionContent = @"
ReportMate
Version: $Version
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Platform: Windows x64
Commit: $env:GITHUB_SHA
"@
$versionContent | Out-File (Join-Path $ProgramFilesPayloadDir "version.txt") -Encoding UTF8

# Copy configuration files to data directory (will be installed to ProgramData/ManagedReports)
Copy-Item (Join-Path $SrcDir "appsettings.yaml") $ProgramDataPayloadDir -Force

# Copy modular osquery configuration from centralized build resources (single source of truth)
$osquerySourceDir = Join-Path $BuildDir "resources\osquery"
$osqueryTargetDataDir = Join-Path $ProgramDataPayloadDir "osquery"
$osqueryTargetProgramDir = Join-Path $ProgramFilesPayloadDir "osquery"

# Copy shared resources from build/resources
$sharedResourcesDir = Join-Path $BuildDir "resources"
# Copy module schedules and task scripts from shared resources
if (Test-Path (Join-Path $sharedResourcesDir "module-schedules.json")) {
    Copy-Item (Join-Path $sharedResourcesDir "module-schedules.json") $ProgramFilesPayloadDir -Force
    Write-Verbose "Copied module-schedules.json from shared resources"
}
if (Test-Path (Join-Path $sharedResourcesDir "install-tasks.ps1")) {
    Copy-Item (Join-Path $sharedResourcesDir "install-tasks.ps1") $ProgramFilesPayloadDir -Force
    Write-Verbose "Copied install-tasks.ps1 from shared resources"
}
if (Test-Path (Join-Path $sharedResourcesDir "uninstall-tasks.ps1")) {
    Copy-Item (Join-Path $sharedResourcesDir "uninstall-tasks.ps1") $ProgramFilesPayloadDir -Force
    Write-Verbose "Copied uninstall-tasks.ps1 from shared resources"
}

# Always ensure target directories are clean first
if (Test-Path $osqueryTargetDataDir) {
    Remove-Item $osqueryTargetDataDir -Recurse -Force
    Write-Verbose "Cleaned existing osquery data directory"
}
if (Test-Path $osqueryTargetProgramDir) {
    Remove-Item $osqueryTargetProgramDir -Recurse -Force
    Write-Verbose "Cleaned existing osquery program directory"
}

if (Test-Path $osquerySourceDir) {
    Write-Step "📋 Copying modular osquery configuration from src..."
    # Copy to both locations - application directory (where code looks) and data directory (for backup/reference)
    Copy-Item $osquerySourceDir $ProgramDataPayloadDir -Recurse -Force
    Copy-Item $osquerySourceDir $ProgramFilesPayloadDir -Recurse -Force
    Write-Success "Modular osquery configuration copied to both application and data directories"
} else {
    Write-Warning "Modular osquery directory not found at: $osquerySourceDir"
    # Fallback to unified file if modular not available
    if (Test-Path (Join-Path $SrcDir "osquery-unified.json")) {
        Write-Verbose "Fallback: Copying unified osquery configuration..."
        Copy-Item (Join-Path $SrcDir "osquery-unified.json") (Join-Path $ProgramDataPayloadDir "osquery-unified.json") -Force
    }
}

Copy-Item (Join-Path $SrcDir "appsettings.yaml") (Join-Path $ProgramDataPayloadDir "appsettings.template.yaml") -Force
Write-Verbose "Copied configuration files to data payload directory"

# Copy additional shared resources to Program Files payload
$sharedResourcesDir = "$BuildDir/resources"
$sharedFiles = @(
    "module-schedules.json",
    "install-tasks.ps1", 
    "uninstall-tasks.ps1"
)

foreach ($file in $sharedFiles) {
    $sourcePath = Join-Path $sharedResourcesDir $file
    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $ProgramFilesPayloadDir -Force
        Write-Verbose "Copied $file from shared resources to Program Files payload"
    } else {
        Write-Warning "Shared resource not found: $sourcePath"
    }
}

# Copy install scripts directory if it exists
$installScriptsDir = Join-Path $sharedResourcesDir "install-scripts"
if (Test-Path $installScriptsDir) {
    Copy-Item $installScriptsDir $ProgramFilesPayloadDir -Recurse -Force
    Write-Verbose "Copied install-scripts directory from shared resources"
}

# Copy Cimian postflight script from shared resources
$cimianPostflightSource = Join-Path $sharedResourcesDir "cimian-postflight.ps1"
if (Test-Path $cimianPostflightSource) {
    Copy-Item $cimianPostflightSource (Join-Path $CimianPayloadDir "postflight.ps1") -Force
    Write-Verbose "Copied Cimian postflight script from shared resources"
} else {
    Write-Warning "Cimian postflight script not found in shared resources: $cimianPostflightSource"
}

# Create chocolatey install script for Cimian package
$chocolateyInstallPath = Join-Path $NupkgDir "tools\chocolateyInstall.ps1"
$chocolateyToolsDir = Join-Path $NupkgDir "tools"
if (-not (Test-Path $chocolateyToolsDir)) {
    New-Item -ItemType Directory -Path $chocolateyToolsDir -Force | Out-Null
}

$chocolateyInstallContent = @'
$ErrorActionPreference = 'Stop'

# Installation paths
$programFilesLocation = 'C:\Program Files\ReportMate\'
$programDataLocation = 'C:\ProgramData\ManagedReports\'
$managedInstallsLocation = 'C:\ProgramData\ManagedInstalls\'

# Create directories if they don't exist
if ($programFilesLocation) { 
    New-Item -ItemType Directory -Force -Path $programFilesLocation | Out-Null 
}
if ($programDataLocation) { 
    New-Item -ItemType Directory -Force -Path $programDataLocation | Out-Null 
}
if ($managedInstallsLocation) { 
    New-Item -ItemType Directory -Force -Path $managedInstallsLocation | Out-Null 
}

$payloadRoot = Join-Path $PSScriptRoot '..\payload'
$payloadRoot = [System.IO.Path]::GetFullPath($payloadRoot)

Write-Host "Installing ReportMate from payload: $payloadRoot"

# Copy executable and version files to Program Files
$programFilesFiles = @('runner.exe', 'version.txt', 'module-schedules.json', 'install-tasks.ps1', 'uninstall-tasks.ps1')
foreach ($file in $programFilesFiles) {
    $sourcePath = Join-Path $payloadRoot $file
    if (Test-Path $sourcePath) {
        $destPath = Join-Path $programFilesLocation $file
        Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force
        Write-Host "Copied $file to Program Files"
        
        if (-not (Test-Path -LiteralPath $destPath)) {
            Write-Error "Failed to copy $file to Program Files"
            exit 1
        }
    }
}

# Copy data directory contents to ProgramData
$dataPayloadPath = Join-Path $payloadRoot 'data'
if (Test-Path $dataPayloadPath) {
    Write-Host "Copying data files to ProgramData..."
    Get-ChildItem -Path $dataPayloadPath -Recurse | ForEach-Object {
        $fullName = $_.FullName
        $fullName = [Management.Automation.WildcardPattern]::Escape($fullName)
        $relative = $fullName.Substring($dataPayloadPath.Length).TrimStart('\','/')
        $dest = Join-Path $programDataLocation $relative
        
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
        } else {
            Copy-Item -LiteralPath $fullName -Destination $dest -Force
            if (-not (Test-Path -LiteralPath $dest)) {
                Write-Error "Failed to copy data file $fullName"
                exit 1
            }
        }
    }
    Write-Host "Data files copied successfully"
} else {
    Write-Warning "No data payload directory found at: $dataPayloadPath"
}

# Copy Cimian integration files to C:\Program Files\Cimian\
$cimianPayloadPath = Join-Path $payloadRoot 'cimian'
if (Test-Path $cimianPayloadPath) {
    $cimianDestPath = 'C:\Program Files\Cimian\'
    Write-Host "Copying Cimian integration files..."
    
    # Create Cimian directory if it doesn't exist
    if (-not (Test-Path $cimianDestPath)) {
        New-Item -ItemType Directory -Force -Path $cimianDestPath | Out-Null
        Write-Host "Created directory: $cimianDestPath"
    }
    
    # Copy all files from cimian payload
    Get-ChildItem -Path $cimianPayloadPath -File | ForEach-Object {
        $destFile = Join-Path $cimianDestPath $_.Name
        Copy-Item -LiteralPath $_.FullName -Destination $destFile -Force
        Write-Host "Copied $($_.Name) to Cimian directory"
        
        if (-not (Test-Path -LiteralPath $destFile)) {
            Write-Error "Failed to copy Cimian file $($_.Name)"
            exit 1
        }
    }
    Write-Host "Cimian integration files copied successfully"
} else {
    Write-Warning "No Cimian payload directory found at: $cimianPayloadPath"
}

Write-Host "ReportMate chocolatey installation completed successfully"

# Clean up executable from payload after installation
$exePayloadPath = Join-Path $payloadRoot 'runner.exe'
if (Test-Path $exePayloadPath) {
    try {
        Remove-Item $exePayloadPath -Force
        Write-Host "Cleaned up runner.exe from payload"
    } catch {
        Write-Verbose "Could not remove runner.exe from payload: $_"
    }
}

'@

$chocolateyInstallContent | Out-File $chocolateyInstallPath -Encoding UTF8

# Update package build-info.yaml
$buildInfoPath = Join-Path $NupkgDir "build-info.yaml"
if (Test-Path $buildInfoPath) {
    $content = Get-Content $buildInfoPath -Raw
    $content = $content -replace 'version: ".*?"', "version: `"$Version`""
    # Remove any trailing newlines and add exactly one
    $content = $content.TrimEnd(@("`r", "`n")) + "`n"
    Set-Content $buildInfoPath $content -Encoding UTF8 -NoNewline
    Write-Verbose "Updated build-info.yaml version"
}

Write-Success "Package payload prepared"
Write-Output ""

Write-Output ""

# Create NUPKG package
if (-not $SkipNUPKG) {
    Write-Step "Creating NUPKG package..."
    
    # Download cimipkg if not found
    if (-not $cimipkgPath) {
        Write-Verbose "Downloading cimipkg..."
        try {
            $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/windowsadmins/cimian-pkg/releases/latest"
            $downloadUrl = $latestRelease.assets | Where-Object { $_.name -like "*windows*" -and $_.name -like "*amd64*" } | Select-Object -First 1 -ExpandProperty browser_download_url
            
            if (-not $downloadUrl) {
                $downloadUrl = $latestRelease.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
            }
            
            if ($downloadUrl) {
                $cimipkgPath = Join-Path $RootDir "cimipkg.exe"
                Invoke-WebRequest -Uri $downloadUrl -OutFile $cimipkgPath
                Write-Success "Downloaded cimipkg: $downloadUrl"
            } else {
                throw "No suitable cimipkg binary found"
            }
        } catch {
            Write-Error "Failed to download cimipkg: $_"
            Write-Info "Download manually from: https://github.com/windowsadmins/cimian-pkg/releases"
            $SkipNUPKG = $true
        }
    }
    
    if (-not $SkipNUPKG -and $cimipkgPath) {
        try {
            Write-Verbose "Running cimipkg from: $cimipkgPath"
            Push-Location $NupkgDir
            
            # Use Start-Process to properly handle output and avoid redirection issues
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $cimipkgPath
            $startInfo.Arguments = "."
            $startInfo.WorkingDirectory = $NupkgDir
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            
            $process = [System.Diagnostics.Process]::Start($startInfo)
            $process.WaitForExit()
            $exitCode = $process.ExitCode
            
            Write-Verbose "cimipkg exit code: $exitCode"
            
            if ($exitCode -eq 0) {
                # Find and move generated nupkg files
                $nupkgFiles = Get-ChildItem -Path "." -Filter "*.nupkg" -Recurse
                if (-not $nupkgFiles) {
                    $nupkgFiles = Get-ChildItem -Path "build" -Filter "*.nupkg" -ErrorAction SilentlyContinue
                }
                
                foreach ($file in $nupkgFiles) {
                    $targetPath = "$OutputDir/$($file.Name)"
                    Move-Item $file.FullName $targetPath -Force
                    $nupkgSize = (Get-Item $targetPath).Length / 1MB
                    Write-Success "NUPKG created: $($file.Name) ($([math]::Round($nupkgSize, 2)) MB)"
                }
                
                # Clean up executable from payload after successful NUPKG creation
                $payloadExe = Join-Path $ProgramFilesPayloadDir "runner.exe"
                if (Test-Path $payloadExe) {
                    try {
                        Remove-Item $payloadExe -Force
                        Write-Verbose "Cleaned up runner.exe from payload after successful build"
                    } catch {
                        Write-Warning "Could not remove runner.exe from payload: $_"
                    }
                }
                
                if (-not $nupkgFiles) {
                    Write-Warning "No .nupkg files found after cimipkg execution"
                }
            } else {
                throw "cimipkg failed with exit code: $exitCode"
            }
        } catch {
            Write-Error "NUPKG creation failed: $_"
        } finally {
            Pop-Location
            
            # Keep osquery files in payload - they're required for installation
            # The osquery configuration files must remain in the payload for deployment
            Write-Verbose "✅ Keeping osquery files in payload for package deployment"
        }
    }
} else {
    Write-Info "Skipping NUPKG creation"
}

Write-Output ""

# Create MSI installer
if (-not $SkipMSI) {
    Write-Step "Creating MSI installer..."
    
    # Check for WiX Toolset
    $wixFound = $false
    $wixBuild = Get-Command wix.exe -ErrorAction SilentlyContinue
    $candle = Get-Command candle.exe -ErrorAction SilentlyContinue
    $light = Get-Command light.exe -ErrorAction SilentlyContinue
    
    if ($wixBuild) {
        $wixFound = $true
        Write-Success "WiX Toolset v6 found"
    } elseif ($candle -and $light) {
        $wixFound = $true
        Write-Success "WiX Toolset v3 (legacy) found"
    } else {
        Write-Warning "WiX Toolset not found in PATH - checking common locations..."
        $wixLocations = @(
            "${env:ProgramFiles}\WiX Toolset v6.0\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v6.0\bin",
            "${env:ProgramFiles}\WiX Toolset v5.0\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v5.0\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
            "${env:ProgramFiles}\WiX Toolset v3.11\bin",
            "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\v7.0A\Bin",
            "${env:ProgramFiles}\Microsoft SDKs\Windows\v7.0A\Bin"
        )
        
        foreach ($location in $wixLocations) {
            if (Test-Path "$location\wix.exe") {
                $env:PATH = "$location;$env:PATH"
                $wixFound = $true
                Write-Success "WiX Toolset v6 found at: $location"
                break
            } elseif ((Test-Path "$location\candle.exe") -and (Test-Path "$location\light.exe")) {
                $env:PATH = "$location;$env:PATH"
                $wixFound = $true
                Write-Success "WiX Toolset v3 (legacy) found at: $location"
                break
            }
        }
    }
    
    if ($wixFound) {
        try {
            Write-Verbose "Preparing MSI staging directory..."
            
            # Clean and prepare MSI staging directory
            if (Test-Path $MsiStagingDir) {
                Remove-Item $MsiStagingDir -Recurse -Force
            }
            New-Item -ItemType Directory -Path $MsiStagingDir -Force | Out-Null
            
            # Copy binary files to staging
            Copy-Item (Join-Path $PublishDir "runner.exe") (Join-Path $MsiStagingDir "runner.exe") -Force
            Write-Verbose "Copied runner.exe to MSI staging"
            
            # Copy configuration files to staging
            Copy-Item (Join-Path $SrcDir "appsettings.json") (Join-Path $MsiStagingDir "appsettings.json") -Force
            Copy-Item (Join-Path $SrcDir "appsettings.yaml") (Join-Path $MsiStagingDir "appsettings.yaml") -Force
            Write-Verbose "Copied configuration files to MSI staging"
            
            # Copy osquery modules to staging (using centralized build resources as single source of truth)
            $osquerySourceDir = Join-Path $BuildDir "resources\osquery"
            if (Test-Path $osquerySourceDir) {
                Copy-Item $osquerySourceDir $MsiStagingDir -Recurse -Force
                Write-Verbose "Copied osquery modules from src to MSI staging"
            }
            
            # Create version.txt for MSI
            $versionContent = @"
ReportMate
Version: $Version
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Platform: Windows x64
Commit: $env:GITHUB_SHA
"@
            $versionContent | Out-File (Join-Path $MsiStagingDir "version.txt") -Encoding UTF8
            Write-Verbose "Created version.txt for MSI"
            
            # Copy license file for MSI
            if (Test-Path (Join-Path $BuildDir "msi\License.rtf")) {
                Copy-Item (Join-Path $BuildDir "msi\License.rtf") (Join-Path $MsiStagingDir "License.rtf") -Force
                Write-Verbose "Copied license file to MSI staging"
            }
            
            # Copy shared installation scripts
            $sharedScriptsDir = Join-Path $BuildDir "resources\install-scripts"
            if (Test-Path $sharedScriptsDir) {
                Copy-Item $sharedScriptsDir (Join-Path $MsiStagingDir "install-scripts") -Recurse -Force
                Write-Verbose "Copied shared installation scripts to MSI staging"
            }
            
            # Copy PowerShell task installation scripts
            $installTasksScript = Join-Path $BuildDir "resources\install-tasks.ps1"
            $uninstallTasksScript = Join-Path $BuildDir "resources\uninstall-tasks.ps1"
            
            if (Test-Path $installTasksScript) {
                Copy-Item $installTasksScript (Join-Path $MsiStagingDir "install-tasks.ps1") -Force
                Write-Verbose "Copied install-tasks.ps1 to MSI staging"
            }
            
            if (Test-Path $uninstallTasksScript) {
                Copy-Item $uninstallTasksScript (Join-Path $MsiStagingDir "uninstall-tasks.ps1") -Force
                Write-Verbose "Copied uninstall-tasks.ps1 to MSI staging"
            }
            
            # Copy module schedules configuration
            $scheduleConfigPath = Join-Path $BuildDir "resources\module-schedules.json"
            if (Test-Path $scheduleConfigPath) {
                Copy-Item $scheduleConfigPath (Join-Path $MsiStagingDir "module-schedules.json") -Force
                Write-Verbose "Copied module schedules configuration to MSI staging"
            }
            
            # Copy Cimian postflight script to MSI staging
            $cimianPostflightPath = Join-Path $BuildDir "resources\cimian-postflight.ps1"
            if (Test-Path $cimianPostflightPath) {
                New-Item -ItemType Directory -Path (Join-Path $MsiStagingDir "cimian") -Force | Out-Null
                Copy-Item $cimianPostflightPath (Join-Path $MsiStagingDir "cimian\postflight.ps1") -Force
                Write-Verbose "Copied Cimian postflight script to MSI staging"
            }
            
            Write-Verbose "Building MSI with WiX..."
            
            # Convert date version to MSI-compatible format
            # 2025.08.03 -> 25.8.3 (MSI versions need parts < 256)
            $msiVersion = $Version -replace '^20(\d{2})\.0?(\d+)\.0?(\d+)$', '$1.$2.$3'
            Write-Verbose "Converting version $Version to MSI-compatible: $msiVersion"
            
            $wxsPath = Join-Path $BuildDir "msi\ReportMate.wxs"
            $msiPath = Join-Path $OutputDir "ReportMate-$Version.msi"
            
            # Use WiX v6 build command
            Write-Verbose "Using WiX v6 build command"
            & dotnet wix build -out $msiPath -arch x64 -define "SourceDir=$MsiStagingDir" -define "ResourceDir=$(Join-Path $BuildDir 'resources')" -define "Version=$msiVersion" -define "APIURL=$ApiUrl" $wxsPath
            if ($LASTEXITCODE -ne 0) {
                throw "WiX v6 build failed with exit code $LASTEXITCODE"
            }
            
            # Sign MSI if signing is enabled
            if ($Sign) {
                Write-Step "Signing MSI..."
                try {
                    signPackage -FilePath $msiPath
                    Write-Success "Signed MSI ✔"
                }
                catch {
                    Write-Error "Failed to sign MSI: $_"
                    exit 1
                }
            }
            
            $msiSize = (Get-Item $msiPath).Length / 1MB
            Write-Success "MSI created: ReportMate-$Version.msi ($([math]::Round($msiSize, 2)) MB)"
            
        } catch {
            Write-Error "MSI creation failed: $($_.Exception.Message)"
            Write-Warning "Continuing without MSI..."
        }
    } else {
        Write-Warning "WiX Toolset not found - MSI creation skipped"
        Write-Info "To build MSI installers, install WiX Toolset v3.11 or later"
        Write-Info "Download from: https://github.com/wixtoolset/wix3/releases"
    }
} else {
    Write-Info "Skipping MSI creation"
}

Write-Output ""

# Create ZIP archive
if (-not $SkipZIP) {
    Write-Step "Creating ZIP archive..."
    $zipPath = Join-Path $OutputDir "ReportMate-$Version.zip"

    $tempZipDir = Join-Path $OutputDir "temp-zip"
    Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $tempZipDir -Force | Out-Null

    # Copy payload structure
    Copy-Item (Join-Path $NupkgDir "payload\*") $tempZipDir -Recurse -Force

    # Add deployment scripts
    $deployScript = @"
@echo off
REM ReportMate Installation Script
echo Installing ReportMate...

REM Copy files
xcopy /E /Y /Q "Program Files\*" "C:\Program Files\" >nul
xcopy /E /Y /Q "ProgramData\*" "C:\ProgramData\" >nul

REM Run configuration
if exist "C:\Program Files\ReportMate\runner.exe" (
    echo Configuring ReportMate...
    "C:\Program Files\ReportMate\runner.exe" install
    echo Installation completed successfully
) else (
    echo ERROR: Installation failed
    exit /b 1
)
"@
    $deployScript | Out-File (Join-Path $tempZipDir "install.bat") -Encoding ASCII

    Compress-Archive -Path (Join-Path $tempZipDir "*") -DestinationPath $zipPath -Force
    Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue

    $zipSize = (Get-Item $zipPath).Length / 1MB
    Write-Success "ZIP created: ReportMate-$Version.zip ($([math]::Round($zipSize, 2)) MB)"
} else {
    Write-Info "Skipping ZIP creation"
}

Write-Output ""

# Create git tag if requested
if ($CreateTag -and $gitFound) {
    Write-Step "Creating git tag..."
    
    try {
        # Only create date-based tags for YYYY.MM.DD format versions
        if ($Version -match '^\d{4}\.\d{2}\.\d{2}$') {
            # Check if tag already exists
            $existingTag = git tag -l $Version 2>$null
            if ($existingTag) {
                Write-Warning "Tag $Version already exists"
            } else {
                # Ensure we have a clean working directory
                $gitStatus = git status --porcelain
                if ($gitStatus) {
                    Write-Warning "Working directory has uncommitted changes:"
                    Write-Output $gitStatus
                    Write-Info "Committing build-related changes..."
                    git add .
                    git commit -m "Build version $Version"
                }
                
                # Create and push tag
                git tag $Version
                Write-Success "Created tag: $Version"
                
                # Try to push tag
                try {
                    git push origin $Version
                    Write-Success "Pushed tag to origin: $Version"
                } catch {
                    Write-Warning "Failed to push tag to origin: $_"
                    Write-Info "You may need to push manually: git push origin $Version"
                }
            }
        } else {
            Write-Warning "Version $Version does not match YYYY.MM.DD format, skipping tag creation"
            Write-Info "Use YYYY.MM.DD format for automatic tagging (e.g., 2024.06.27)"
        }
    } catch {
        Write-Error "Failed to create git tag: $_"
    }
}

# Create GitHub release if requested
if ($CreateRelease -and $ghFound) {
    Write-Step "Creating GitHub release..."
    
    try {
        # Prepare release files
        $releaseFiles = @()
        $outputFiles = Get-ChildItem $OutputDir -File -ErrorAction SilentlyContinue
        
        foreach ($file in $outputFiles) {
            if ($file.Extension -in @('.nupkg', '.zip')) {
                $releaseFiles += $file.FullName
            }
        }
        
        if ($releaseFiles.Count -eq 0) {
            Write-Warning "No release files found to upload"
        } else {
            # Create release notes
            $releaseNotes = @"
## ReportMate $Version

### 📦 Package Types
- **NUPKG Package**: For Chocolatey and Cimian package management  
- **ZIP Archive**: For manual installation and testing

### 🚀 Quick Start

**Chocolatey Installation:**
``````cmd
choco install ReportMate-$Version.nupkg --source=.
``````

**Manual Installation:**
1. Extract the ZIP file
2. Run ``install.bat`` as administrator

### 🔧 Enterprise Configuration
Configure via Registry (CSP/OMA-URI):
- ``HKLM\SOFTWARE\ReportMate\ApiUrl`` - API endpoint URL
- ``HKLM\SOFTWARE\ReportMate\ClientPassphrase`` - Access passphrase
- ``HKLM\SOFTWARE\ReportMate\CollectionInterval`` - Data collection interval

### 📖 Documentation
- [Installation Guide](README.md)
- [Enterprise Deployment](README.md#enterprise-deployment)
- [CSP/OMA-URI Configuration](README.md#cspoma-uri-configuration)

---
*Built from commit $(git rev-parse HEAD)*
"@
            
            # Create the release
            $releaseArgs = @(
                'release', 'create', $Version,
                '--title', "ReportMate $Version",
                '--notes', $releaseNotes
            )
            
            # Add files
            foreach ($file in $releaseFiles) {
                $releaseArgs += $file
            }
            
            & gh @releaseArgs
            
            Write-Success "Created GitHub release: $Version"
            Write-Info "Uploaded $($releaseFiles.Count) files"
        }
    } catch {
        Write-Error "Failed to create GitHub release: $_"
        Write-Info "You can create the release manually with: gh release create $Version"
    }
}

Write-Output ""
# Build summary
Write-Header "Build Summary"
Write-Info "Version: $Version"
Write-Info "Configuration: $Configuration"
Write-Info "Output Directory: $OutputDir"
Write-Output ""

$outputFiles = Get-ChildItem $OutputDir -File -ErrorAction SilentlyContinue
if ($outputFiles) {
    Write-Success "Generated packages:"
    foreach ($file in $outputFiles) {
        $sizeKB = [math]::Round($file.Length / 1KB, 1)
        $icon = switch ($file.Extension) {
            ".nupkg" { "📦" }
            ".zip" { "🗜️ " }
            ".exe" { "⚡" }
            default { "📄" }
        }
        Write-Info "  $icon $($file.Name) ($sizeKB KB)"
    }
} else {
    Write-Warning "No packages were generated"
}

Write-Output ""
Write-Header "Next Steps"
Write-Info "1. Test MSI: msiexec.exe /i `"$(Join-Path $OutputDir "ReportMate-$Version.msi")`" /quiet /norestart"
Write-Info "2. Test NUPKG: choco install `"$(Join-Path $OutputDir "ReportMate-$Version.nupkg")`" --source=."
Write-Info "3. Test ZIP: Extract and run install.bat as administrator"
Write-Info "4. Deploy via Windows Installer, Chocolatey, or manual installation"

if ($ApiUrl) {
    Write-Info "5. Configured API URL: $ApiUrl"
}

if ($CreateTag -and $gitFound) {
    Write-Info "6. Git tag created: $Version"
}

if ($CreateRelease -and $ghFound) {
    Write-Info "7. GitHub release created: $Version"
}

# Install the package if requested
if ($Install) {
    Write-Step "Installing ReportMate package..."
    
    # Prioritize MSI installation if available
    $msiPath = Join-Path $OutputDir "ReportMate-$Version.msi"
    $nupkgPath = Join-Path $OutputDir "ReportMate-$Version.nupkg"
    
    if ((Test-Path $msiPath) -and (-not $SkipMSI)) {
        Write-Info "Installing MSI package: ReportMate-$Version.msi"
        try {
            # Check if running as administrator
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            
            if (-not $isAdmin) {
                Write-Warning "MSI installation requires administrator privileges. Using native Windows sudo..."
                
                # Use msiexec with quiet installation
                $installLogPath = Join-Path $OutputDir "ReportMate-Install.log"
                $installCmd = "msiexec.exe /i `"$msiPath`" /quiet /norestart /l*v `"$installLogPath`""
                
                # Execute with native sudo
                sudo powershell -Command $installCmd
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "MSI installation completed successfully"
                    Write-Info "Installation log: $installLogPath"
                } else {
                    Write-Error "MSI installation failed with exit code: $LASTEXITCODE"
                    Write-Info "Check installation log: $installLogPath"
                    throw "MSI installation failed"
                }
            } else {
                # Already running as admin, install directly
                Write-Verbose "Installing MSI with msiexec: $msiPath"
                $installLogPath = Join-Path $OutputDir "ReportMate-Install.log"
                $installArgs = @(
                    "/i", "`"$msiPath`"",
                    "/quiet",
                    "/norestart",
                    "/l*v", "`"$installLogPath`""
                )
                
                & msiexec.exe @installArgs
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "MSI installation completed successfully"
                    Write-Info "Installation log: $installLogPath"
                } else {
                    Write-Error "MSI installation failed with exit code: $LASTEXITCODE"
                    Write-Info "Check installation log: $installLogPath"
                }
            }
        } catch {
            Write-Error "Failed to install MSI: $_"
            Write-Info "Manual installation: msiexec.exe /i `"$msiPath`" /quiet /norestart"
        }
    } elseif (Test-Path $nupkgPath) {
        Write-Info "Installing NUPKG package: ReportMate-$Version.nupkg"
        try {
            # Check if running as administrator
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            
            if (-not $isAdmin) {
                Write-Warning "NUPKG installation requires administrator privileges. Using native Windows sudo..."
                
                # Use native Windows sudo (available in Windows 11 and modern Windows 10)
                $installCmd = "choco install `"$nupkgPath`" --source=. --force --yes"
                
                # Execute with native sudo
                sudo powershell -Command $installCmd
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "NUPKG installation completed successfully"
                } else {
                    Write-Error "NUPKG installation failed with exit code: $LASTEXITCODE"
                    throw "Chocolatey installation failed"
                }
            } else {
                # Already running as admin, install directly
                Write-Verbose "Installing with chocolatey: $nupkgPath"
                choco install "$nupkgPath" --source=. --force --yes
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "NUPKG installation completed successfully"
                } else {
                    Write-Error "NUPKG installation failed with exit code: $LASTEXITCODE"
                }
            }
        } catch {
            Write-Error "Failed to install NUPKG: $_"
            Write-Info "Manual installation: choco install `"$nupkgPath`" --source=. --force --yes"
        }
    } else {
        Write-Error "No installation packages found"
        Write-Info "Expected files:"
        Write-Info "  - MSI: $msiPath"
        Write-Info "  - NUPKG: $nupkgPath"
        Write-Info "Make sure packages were built successfully"
    }
}

Write-Output ""

# Clean up duplicate osquery files after package creation  
Write-Step "Cleaning up duplicate osquery files..."
$osqueryPayloadDirs = @(
    (Join-Path $ProgramDataPayloadDir "osquery"),
    (Join-Path $ProgramFilesPayloadDir "osquery")
)

foreach ($dir in $osqueryPayloadDirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Verbose "Removed duplicate osquery directory: $dir"
    }
}
Write-Success "Duplicate osquery files cleaned up"

Write-Output ""
Write-Success "Build completed successfully!"
