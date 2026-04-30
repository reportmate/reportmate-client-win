#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    ReportMate Unified Build Script
    
.DESCRIPTION
    One-stop build script that replicates the CI pipeline locally.
    Builds all package types: MSI (primary, via cimipkg), EXE, NUPKG, and ZIP.
    Supports creating tags and releases when run with appropriate parameters.

.PARAMETER Version
    Version to build (default: auto-generated from date in YYYY.MM.DD.HHMM format)

.PARAMETER Configuration
    Build configuration (Release or Debug)

.PARAMETER SkipBuild
    Skip the .NET build step

.PARAMETER SkipNUPKG
    Skip NUPKG creation

.PARAMETER SkipZIP
    Skip ZIP creation

.PARAMETER SkipMSI
    Skip MSI creation (MSI is built via cimipkg)
    
.PARAMETER Clean
    Clean all build artifacts first
    
.PARAMETER ApiUrl
    Default API URL to configure in the installer
    
.PARAMETER CreateTag
    Create and push a date-based git tag (YYYY.MM.DD.HHMM format)
    
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

.PARAMETER Import
    Import the built MSI into the Cimian deployment repo using cimiimport --nointeractive

.PARAMETER Install
    Install the built MSI locally using installer --pkg - requires admin privileges

.EXAMPLE
    .\build.ps1
    Build with auto-generated version (YYYY.MM.DD.HHMM format)
    
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
    .\build.ps1 -Import
    Build and import the MSI into the Cimian deployment repo

.EXAMPLE
    .\build.ps1 -Install
    Build and install the MSI locally using installer --pkg

.EXAMPLE
    .\build.ps1 -SkipNUPKG -SkipZIP
    Build only EXE and MSI (skip NUPKG and ZIP)

.EXAMPLE
    .\build.ps1 -SkipMSI -SkipNUPKG -SkipZIP
    Build only the EXE (skip all package formats)
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
    [switch]$Import = $false,
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

# Resolves the right signtool.exe for the host architecture and stores its
# full path in $script:SignToolPath. The signing step invokes it by full
# path so we don't rely on PATH order — a stale `signtool.exe` already on
# PATH (e.g. from a VS Developer prompt that prepends arm64\) used to win
# the resolution silently and trip "Machine Type Mismatch" at sign time.
function Test-SignTool {
    # The Windows SDK installs signtool.exe under <kit>\bin\<version>\<arch>\.
    # Pick the binary that matches the host architecture — relying on PATH
    # silently selects arm64\signtool.exe on x64 hosts when a Developer
    # prompt has prepended the arm64 dir, causing "Machine Type Mismatch".
    $hostArch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    $archPriority = switch ($hostArch) {
        'x64'   { @('x64', 'x86') }            # x64 hosts can fall back to x86, never arm64
        'arm64' { @('arm64', 'x64', 'x86') }   # arm64 can emulate x64/x86
        'x86'   { @('x86') }
        default { @($hostArch, 'x64', 'x86') }
    }

    # Validate a signtool candidate by reading its PE header — guards against
    # a non-arch-suffixed signtool.exe (e.g. App Certification Kit, VS Build
    # Tools shims) being picked when its actual machine type doesn't match.
    function Test-PeMatchesHost {
        param([string]$Path, [string]$HostArch)
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            if ($bytes.Length -lt 0x3C + 4) { return $false }
            $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
            if ($bytes.Length -lt $peOffset + 6) { return $false }
            # PE signature: 'PE\0\0' then 2-byte machine type
            if ($bytes[$peOffset]    -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45 -or
                $bytes[$peOffset+2]  -ne 0x00 -or $bytes[$peOffset+3] -ne 0x00) { return $false }
            $machine = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
            $expected = switch ($HostArch) {
                'x64'   { 0x8664 }
                'arm64' { 0xAA64 }
                'x86'   { 0x014C }
                default { 0 }
            }
            # x64 hosts can also run x86 (0x014C); arm64 can run x64+x86.
            $compat = switch ($HostArch) {
                'x64'   { @(0x8664, 0x014C) }
                'arm64' { @(0xAA64, 0x8664, 0x014C) }
                'x86'   { @(0x014C) }
                default { @($expected) }
            }
            return $compat -contains $machine
        } catch { return $false }
    }

    # harvest possible SDK roots (plus VS Build Tools shim and App Cert Kit)
    $roots = @(
        "${env:ProgramFiles}\Windows Kits\10\bin",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles(x86)}\Windows Kits\10\App Certification Kit",
        "${env:ProgramFiles}\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    )

    try {
        $kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
                     -EA Stop).KitsRoot10
        if ($kitsRoot) { $roots += (Join-Path $kitsRoot 'bin') }
    } catch { }

    $roots = $roots | Where-Object { Test-Path $_ } | Select-Object -Unique

    $picked = $null
    foreach ($root in $roots) {
        $candidates = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -EA SilentlyContinue
        if (-not $candidates) { continue }

        # Prefer candidates whose immediate parent directory matches host arch.
        foreach ($arch in $archPriority) {
            $match = $candidates |
                     Where-Object { $_.Directory.Name -ieq $arch -and (Test-PeMatchesHost $_.FullName $hostArch) } |
                     Sort-Object LastWriteTime -Desc | Select-Object -First 1
            if ($match) { $picked = $match; break }
        }
        if ($picked) { break }

        # Fallback: any signtool.exe under this root whose PE header passes.
        $picked = $candidates |
                  Where-Object { Test-PeMatchesHost $_.FullName $hostArch } |
                  Sort-Object LastWriteTime -Desc | Select-Object -First 1
        if ($picked) { break }
    }

    if ($picked) {
        $script:SignToolPath = $picked.FullName
        $signDir = $picked.Directory.FullName

        # Prepend the resolved dir to PATH and strip any stale arm64\signtool
        # dir already on PATH. cimipkg.exe (and any other tool we call that
        # resolves signtool via PATH) iterates PATH front-to-back and returns
        # the first match — leaving an arm64 entry ahead of x64 makes it pick
        # the wrong binary on x64 hosts. We can't dictate cimipkg's behavior,
        # but we can hand it a PATH where the right answer comes first.
        $entries = $env:Path -split ';' | Where-Object { $_ -ne '' }
        if ($hostArch -ne 'arm64') {
            $entries = $entries | Where-Object {
                -not ($_.TrimEnd('\') -ilike '*\Windows Kits\10\bin\*\arm64')
            }
        }
        if (-not ($entries | Where-Object { $_ -ieq $signDir })) {
            $entries = ,$signDir + $entries
        } else {
            $entries = ,$signDir + ($entries | Where-Object { $_ -ine $signDir })
        }
        $env:Path = ($entries -join ';')

        Write-Success "signtool discovered at $($picked.FullName)"
        return
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

function Resolve-Cimipkg {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RootDir,
        [string] $ProcessArchitecture
    )

    if (-not $ProcessArchitecture) {
        $ProcessArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    }

    # cimian-pkg releases ship `cimipkg-win-x64.zip` and `cimipkg-win-arm64.zip`.
    # Fail loud on any other host architecture rather than silently picking an
    # asset that won't run.
    $archSuffix = switch ($ProcessArchitecture) {
        'x64'   { 'win-x64' }
        'arm64' { 'win-arm64' }
        default { throw "Unsupported host architecture '$ProcessArchitecture' for cimipkg download — only x64 and arm64 are published" }
    }

    Write-Verbose "Resolving cimipkg release asset for $archSuffix..."
    $latestRelease = Invoke-RestMethod -Uri 'https://api.github.com/repos/windowsadmins/cimian-pkg/releases/latest' -ErrorAction Stop

    $asset = $latestRelease.assets |
        Where-Object { $_.name -like "*$archSuffix*.zip" } |
        Select-Object -First 1

    if (-not $asset) {
        throw "No cimipkg release asset matching '*$archSuffix*.zip' in $($latestRelease.tag_name)"
    }

    $zipPath = Join-Path $RootDir 'cimipkg-download.zip'
    $extractDir = Join-Path $RootDir 'cimipkg-extracted'
    $targetExe = Join-Path $RootDir 'cimipkg.exe'

    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    if (Test-Path $zipPath)    { Remove-Item $zipPath -Force }

    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

        $extractedExe = Get-ChildItem -Path $extractDir -Filter 'cimipkg.exe' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if (-not $extractedExe) {
            throw "cimipkg.exe not found inside $($asset.name)"
        }

        Move-Item $extractedExe.FullName $targetExe -Force
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Write directly to the host instead of via Write-Success — Write-Success
    # routes through Write-Output, which would put the message into the
    # function's success stream and corrupt the returned path.
    Write-Host "✅ Downloaded cimipkg from $($asset.name) ($($latestRelease.tag_name))" -ForegroundColor Green
    return $targetExe
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

    # Always invoke by full path to defeat any PATH that resolves
    # signtool.exe to the wrong architecture (e.g. arm64 on x64 hosts).
    $signToolExe = if ($script:SignToolPath -and (Test-Path $script:SignToolPath)) {
        $script:SignToolPath
    } else {
        (Get-Command signtool.exe -EA Stop).Source
    }

    foreach ($tsa in $tsaList) {
        Write-Info "Signing '$FilePath' using $tsa ..."
        & $signToolExe sign `
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

# Generate version if not provided (YYYY.MM.DD.HHMM format)
if (-not $Version) {
    $Version = Get-Date -Format "yyyy.MM.dd.HHmm"
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
$PkgDir = Join-Path $BuildDir "pkg"
$ProgramFilesPayloadDir = Join-Path $NupkgDir "payload"
$ProgramDataPayloadDir = Join-Path $NupkgDir "payload\data"
$CimianPayloadDir = Join-Path $NupkgDir "payload\cimian"
$PkgPayloadDir = Join-Path $PkgDir "payload"
$MsiStagingDir = Join-Path $RootDir "release\msi-staging"
$PublishDir = Join-Path $RootDir ".publish"
$OutputDir = Join-Path $RootDir "release"

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
Write-Step "Cleaning old binaries from .publish and release directories..."
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
@($PublishDir, $OutputDir, $ProgramFilesPayloadDir, $ProgramDataPayloadDir, $CimianPayloadDir, $PkgPayloadDir, $MsiStagingDir) | ForEach-Object {
    New-Item -ItemType Directory -Path $_ -Force | Out-Null
    Write-Verbose "Created: $_"
}
Write-Success "Directories created"
Write-Output ""

# Always refresh payload directories from resources (clean slate for each build)
Write-Step "Refreshing payload directories from resources..."

# Clean and refresh NUPKG payload directory
if (Test-Path $ProgramFilesPayloadDir) {
    Remove-Item $ProgramFilesPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path $ProgramDataPayloadDir) {
    Remove-Item $ProgramDataPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path $CimianPayloadDir) {
    Remove-Item $CimianPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Clean and refresh PKG payload directory
if (Test-Path $PkgPayloadDir) {
    Remove-Item $PkgPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Recreate payload directories
@($ProgramFilesPayloadDir, $ProgramDataPayloadDir, $CimianPayloadDir, $PkgPayloadDir) | ForEach-Object {
    New-Item -ItemType Directory -Path $_ -Force | Out-Null
    Write-Verbose "Refreshed: $_"
}

Write-Success "Payload directories refreshed from clean slate"
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

# Check cimipkg (used for both NUPKG and MSI now — cimipkg 2026.04.09+ defaults to .msi output)
$cimipkgPath = $null
if (-not $SkipNUPKG -or -not $SkipMSI) {
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

Write-Output ""

# ──────────────────────────  MODULE VERSION GENERATION  ──────────────────────────
# Generate per-module versions derived from git commit dates of each module's source files.
# Format: YYYY.MM.DD.HHMM — reflects the last time each module's code was changed.

Write-Step "Generating per-module versions from git history..."

$moduleFileMap = @{
    "applications" = @("src/Services/Modules/ApplicationsModuleProcessor.cs", "src/Models/Modules/ApplicationsModels.cs", "build/resources/osquery/modules/applications.json")
    "displays"     = @("src/Services/Modules/DisplayModuleProcessor.cs", "src/Models/Modules/DisplayModels.cs", "build/resources/osquery/modules/displays.json")
    "hardware"     = @("src/Services/Modules/HardwareModuleProcessor.cs", "src/Models/Modules/HardwareModels.cs", "build/resources/osquery/modules/hardware.json")
    "identity"     = @("src/Services/Modules/IdentityModuleProcessor.cs", "src/Models/Modules/IdentityModels.cs", "build/resources/osquery/modules/identity.json")
    "installs"     = @("src/Services/Modules/InstallsModuleProcessor.cs", "src/Models/Modules/InstallsModels.cs", "build/resources/osquery/modules/installs.json")
    "inventory"    = @("src/Services/Modules/InventoryModuleProcessor.cs", "src/Models/Modules/InventoryModels.cs", "build/resources/osquery/modules/inventory.json")
    "management"   = @("src/Services/Modules/ManagementModuleProcessor.cs", "src/Models/Modules/ManagementModels.cs", "build/resources/osquery/modules/management.json")
    "network"      = @("src/Services/Modules/NetworkModuleProcessor.cs", "src/Models/Modules/NetworkModels.cs", "build/resources/osquery/modules/network.json")
    "peripherals"  = @("src/Services/Modules/PeripheralsModuleProcessor.cs", "src/Models/Modules/PeripheralsModels.cs", "build/resources/osquery/modules/peripherals.json")
    "printers"     = @("src/Services/Modules/PrinterModuleProcessor.cs", "src/Models/Modules/PrinterModels.cs", "build/resources/osquery/modules/printers.json")
    "security"     = @("src/Services/Modules/SecurityModuleProcessor.cs", "src/Models/Modules/SecurityModels.cs", "build/resources/osquery/modules/security.json")
    "system"       = @("src/Services/Modules/SystemModuleProcessor.cs", "src/Models/Modules/SystemModels.cs", "build/resources/osquery/modules/system.json")
}

$fallbackVersion = Get-Date -Format "yyyy.MM.dd.HHmm"
$versionEntries = @()

foreach ($moduleId in ($moduleFileMap.Keys | Sort-Object)) {
    $files = $moduleFileMap[$moduleId]
    $moduleVersion = $fallbackVersion

    try {
        $gitArgs = @("log", "--format=%cd", "--date=format:%Y.%m.%d.%H%M", "-1", "--") + $files
        $result = & git @gitArgs 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) {
            $moduleVersion = $result.Trim()
        }
    } catch {
        Write-Verbose "Git lookup failed for module $moduleId, using fallback version"
    }

    $versionEntries += "            [`"$moduleId`"] = `"$moduleVersion`","
    Write-Verbose "  $moduleId = $moduleVersion"
}

$generatedDir = Join-Path $SrcDir "Generated"
New-Item -ItemType Directory -Path $generatedDir -Force | Out-Null

$generatedContent = @"
// <auto-generated>
// Generated by build.ps1 — do not edit manually
// </auto-generated>
#nullable enable
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Generated
{
    public static class ModuleVersions
    {
        public static readonly Dictionary<string, string> Versions = new()
        {
$($versionEntries -join "`n")
        };

        public static string GetVersion(string moduleId)
            => Versions.TryGetValue(moduleId, out var v) ? v : "0.0.0.0000";
    }
}
"@

$generatedFile = Join-Path $generatedDir "ModuleVersions.g.cs"
Set-Content $generatedFile $generatedContent -Encoding UTF8
Write-Success "Generated ModuleVersions.g.cs with $($moduleFileMap.Count) module versions"

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
    dotnet build $csprojPath --configuration $Configuration --no-restore --verbosity quiet -p:VersionPrefix=$Version
    
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
        -p:VersionPrefix=$Version `
        --verbosity quiet
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Build completed successfully"
        $exeSize = (Get-Item "$PublishDir/managedreportsrunner.exe").Length / 1MB
        Write-Info "Executable size: $([math]::Round($exeSize, 2)) MB"
        
        # ─────────────── SIGN THE EXECUTABLE ───────────────
        if ($Sign) {
            Write-Step "Signing managedreportsrunner.exe..."
            try {
                signPackage -FilePath "$PublishDir/managedreportsrunner.exe"
                Write-Success "Signed managedreportsrunner.exe"
            }
            catch {
                Write-Error "Failed to sign managedreportsrunner.exe: $_"
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
Copy-Item (Join-Path $PublishDir "managedreportsrunner.exe") $ProgramFilesPayloadDir -Force
Write-Verbose "Copied managedreportsrunner.exe to payload root"

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
    Write-Step "📋 Copying modular osquery configuration..."
    # Only copy to ProgramData payload - will be handled by postinstall script
    Copy-Item $osquerySourceDir $ProgramDataPayloadDir -Recurse -Force
    Write-Success "Modular osquery configuration copied to data payload directory"
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

# Copy shared resources from build/resources - only to Program Files payload
$sharedResourcesDir = Join-Path $BuildDir "resources"
$sharedFiles = @(
    "module-schedules.json",
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

# Ensure Speedtest CLI binary is available, download if missing
$speedtestSourceDir = Join-Path $sharedResourcesDir "speedtest"
$speedtestExe = Join-Path $speedtestSourceDir "speedtest.exe"
if (-not (Test-Path $speedtestExe)) {
    Write-Step "Downloading Speedtest CLI..."
    try {
        # Use Ookla's packagecloud repo for latest signed binaries
        $speedtestZip = Join-Path $env:TEMP "ookla-speedtest-win64.zip"
        $speedtestExtract = Join-Path $env:TEMP "ookla-speedtest-extract"

        # Try packagecloud (signed builds), fall back to legacy CDN
        $downloadUrls = @(
            "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip"
        )

        $downloaded = $false
        foreach ($url in $downloadUrls) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $speedtestZip -UseBasicParsing -ErrorAction Stop
                $downloaded = $true
                Write-Verbose "Downloaded from: $url"
                break
            } catch {
                Write-Verbose "Failed to download from: $url"
            }
        }

        if (-not $downloaded) { throw "All download URLs failed" }

        if (Test-Path $speedtestExtract) { Remove-Item $speedtestExtract -Recurse -Force }
        Expand-Archive -Path $speedtestZip -DestinationPath $speedtestExtract -Force

        # Ensure target directory exists
        if (-not (Test-Path $speedtestSourceDir)) { New-Item -ItemType Directory -Path $speedtestSourceDir -Force | Out-Null }

        # Copy only the exe (skip license/readme from zip)
        Copy-Item (Join-Path $speedtestExtract "speedtest.exe") $speedtestExe -Force
        Write-Success "Downloaded Speedtest CLI to build resources"

        # Sign the binary with our enterprise cert so Defender doesn't block it
        if ($env:SIGN_THUMB) {
            Write-Step "Signing Speedtest CLI with enterprise certificate..."
            try {
                signPackage -FilePath $speedtestExe
                Write-Success "Signed speedtest.exe"
            } catch {
                Write-Warning "Failed to sign speedtest.exe: $_ - may be blocked by Defender on managed endpoints"
            }
        } else {
            Write-Warning "No signing certificate available - speedtest.exe will be unsigned (may be blocked by Defender)"
        }

        # Cleanup temp files
        Remove-Item $speedtestZip -Force -ErrorAction SilentlyContinue
        Remove-Item $speedtestExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to download Speedtest CLI: $_ - network quality testing will be unavailable"
    }
}

# Copy Speedtest CLI to Program Files payload (flat, alongside managedreportsrunner.exe)
if (Test-Path $speedtestExe) {
    Copy-Item $speedtestExe (Join-Path $ProgramFilesPayloadDir "speedtest.exe") -Force
    Write-Success "Speedtest CLI bundled into payload"
} else {
    Write-Warning "Speedtest CLI not available - network quality testing will be unavailable"
}

# Don't copy install-scripts directory to avoid confusion with install-tasks.ps1
# The Configure-ReportMate.ps1 functionality should be integrated into postinstall.ps1

# Copy Cimian postflight script from shared resources
$cimianPostflightSource = Join-Path $sharedResourcesDir "cimian-postflight.ps1"
if (Test-Path $cimianPostflightSource) {
    Copy-Item $cimianPostflightSource (Join-Path $CimianPayloadDir "postflight.ps1") -Force
    Write-Verbose "Copied Cimian postflight script from shared resources"
} else {
    Write-Warning "Cimian postflight script not found in shared resources: $cimianPostflightSource"
}

# Create comprehensive postinstall.ps1 for NUPKG (inline scheduled tasks installation)
Write-Step "Creating comprehensive postinstall.ps1 for NUPKG..."

# Use a clean template to avoid accumulation issues
$postinstallTemplatePath = Join-Path $NupkgDir "scripts\postinstall.ps1"
$postinstallCleanPath = Join-Path $NupkgDir "scripts\postinstall.clean.ps1"

# Always start fresh from the clean template
if (Test-Path $postinstallCleanPath) {
    Copy-Item $postinstallCleanPath $postinstallTemplatePath -Force
    Write-Verbose "Restored from clean template"
} else {
    Write-Warning "Clean template not found at: $postinstallCleanPath"
}

$basePostinstallContent = Get-Content $postinstallTemplatePath -Raw

# Read the install-tasks.ps1 content to inline
$installTasksPath = Join-Path $BuildDir "resources\install-tasks.ps1"
if (Test-Path $installTasksPath) {
    $installTasksContent = Get-Content $installTasksPath -Raw
    
    # Extract the core task installation logic from install-tasks.ps1
    # Get everything between the first try block and the last catch block
    if ($installTasksContent -match '(?s)(\s*# First, remove any existing ReportMate tasks.*?)catch \{[^}]*\}') {
        $coreTaskLogic = $matches[1].Trim()
        
        # Build the comprehensive scheduled tasks installation content
        $scheduledTasksContent = @"
# Install ReportMate scheduled tasks
Write-Host "Installing ReportMate scheduled tasks..."

try {
    `$InstallPath = "C:\Program Files\ReportMate"
    
$coreTaskLogic
    
    Write-Host "✅ Scheduled tasks installed successfully"
    
} catch {
    Write-Warning "Failed to create scheduled tasks: `$_"
}
"@
        
        # Replace the placeholder with the comprehensive logic
        $enhancedPostinstallContent = $basePostinstallContent -replace 'INLINE_SCHEDULED_TASKS_PLACEHOLDER', $scheduledTasksContent
        
        # Write the enhanced postinstall.ps1 (will be restored to clean template after NUPKG build)
        Set-Content $postinstallTemplatePath $enhancedPostinstallContent -Encoding UTF8 -NoNewline
        Write-Success "Enhanced postinstall.ps1 with inline scheduled tasks installation"
    } else {
        Write-Warning "Could not extract task installation logic from install-tasks.ps1"
    }
} else {
    Write-Warning "install-tasks.ps1 not found at: $installTasksPath - using existing postinstall.ps1"
}

# Remove install-tasks.ps1 from Program Files payload since it's now inline in postinstall.ps1
$installTasksInPayload = Join-Path $ProgramFilesPayloadDir "install-tasks.ps1"
if (Test-Path $installTasksInPayload) {
    Remove-Item $installTasksInPayload -Force
    Write-Verbose "Removed install-tasks.ps1 from payload (now inline in postinstall.ps1)"
}

# cimian-pkg will generate the chocolatey install script automatically
# The enhanced postinstall.ps1 in scripts/ directory will be appended to it

# Update package build-info.yaml for NUPKG (replaces {{VERSION}} placeholder; restored after build)
$buildInfoPath = Join-Path $NupkgDir "build-info.yaml"
$nupkgBuildInfoOriginal = $null
if (Test-Path $buildInfoPath) {
    $nupkgBuildInfoOriginal = Get-Content $buildInfoPath -Raw
    $modified = $nupkgBuildInfoOriginal -replace '\{\{VERSION\}\}', $Version
    Set-Content $buildInfoPath $modified -Encoding UTF8 -NoNewline
    Write-Verbose "Updated NUPKG build-info.yaml version to: $Version"
}

# Update reportmate.nuspec for NUPKG (replaces {{VERSION}} placeholder; restored after build)
$nuspecPath = Join-Path $NupkgDir "reportmate.nuspec"
$nupkgNuspecOriginal = $null
if (Test-Path $nuspecPath) {
    $nupkgNuspecOriginal = Get-Content $nuspecPath -Raw
    $modified = $nupkgNuspecOriginal -replace '\{\{VERSION\}\}', $Version
    Set-Content $nuspecPath $modified -Encoding UTF8 -NoNewline
    Write-Verbose "Updated reportmate.nuspec version to: $Version"
}

# Copy .env file from root to NUPKG build directory for cimipkg
$rootEnvFile = Join-Path $RootDir ".env"
$nupkgEnvFile = Join-Path $NupkgDir ".env"
if (Test-Path $rootEnvFile) {
    Copy-Item $rootEnvFile $nupkgEnvFile -Force
    Write-Verbose "Copied .env file to NUPKG build directory for cimipkg"
} else {
    Write-Warning "Root .env file not found at: $rootEnvFile - NUPKG may fail during installation"
}

Write-Success "Package payload prepared"
Write-Output ""

Write-Output ""

# Create NUPKG package
if (-not $SkipNUPKG) {
    Write-Step "Creating NUPKG package..."
    
    # Ensure NuGet CLI is up-to-date before creating NUPKG
    Write-Verbose "Checking NuGet CLI version..."
    try {
        $nugetPath = (Get-Command nuget.exe -ErrorAction SilentlyContinue).Source
        if ($nugetPath) {
            $nugetVersion = & nuget.exe help | Select-String "NuGet Version:" | ForEach-Object { $_.ToString().Split(':')[1].Trim() }
            Write-Verbose "Current NuGet version: $nugetVersion"
            
            # Update NuGet to latest version
            Write-Verbose "Updating NuGet CLI to latest version..."
            & nuget.exe update -self | Out-Null
            Write-Success "NuGet CLI updated successfully"
        } else {
            Write-Warning "NuGet CLI not found in PATH - cimipkg may fail"
        }
    } catch {
        Write-Warning "Failed to check/update NuGet CLI: $_"
    }
    
    # Download cimipkg if not found
    if (-not $cimipkgPath) {
        try {
            $cimipkgPath = Resolve-Cimipkg -RootDir $RootDir
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
            
            # Build NUPKG using cimipkg
            # NOTE: -e flag has issues with argument parsing, skip for now
            Write-Verbose "Running cimipkg to create NUPKG package"
            
            $output = & $cimipkgPath --nupkg . 2>&1
            
            $exitCode = $LASTEXITCODE
            $stdout = ($output | Where-Object { $_ -is [string] }) -join "`n"
            $stderr = ($output | Where-Object { $_ -isnot [string] }) -join "`n"
            
            Write-Verbose "cimipkg stdout: $stdout"
            if ($stderr) {
                Write-Verbose "cimipkg stderr: $stderr"
            }
            Write-Verbose "cimipkg exit code: $exitCode"
            
            if ($exitCode -eq 0) {
                # Find and move generated nupkg files
                $nupkgFiles = Get-ChildItem -Path "." -Filter "*.nupkg" -Recurse
                if (-not $nupkgFiles) {
                    $nupkgFiles = Get-ChildItem -Path "build" -Filter "*.nupkg" -ErrorAction SilentlyContinue
                }
                
                foreach ($file in $nupkgFiles) {
                    # Rename the nupkg file to include the full version format
                    $newFileName = "ReportMate-$Version.nupkg"
                    $targetPath = "$OutputDir/$newFileName"
                    Move-Item $file.FullName $targetPath -Force
                    $nupkgSize = (Get-Item $targetPath).Length / 1MB
                    Write-Success "NUPKG created: $newFileName ($([math]::Round($nupkgSize, 2)) MB)"
                }
                
                # Clean up executable from payload after successful NUPKG creation
                $payloadExe = Join-Path $ProgramFilesPayloadDir "managedreportsrunner.exe"
                if (Test-Path $payloadExe) {
                    try {
                        Remove-Item $payloadExe -Force
                        Write-Verbose "Cleaned up managedreportsrunner.exe from payload after successful build"
                    } catch {
                        Write-Warning "Could not remove managedreportsrunner.exe from payload: $_"
                    }
                }
                
                if (-not $nupkgFiles) {
                    Write-Warning "No .nupkg files found after cimipkg execution"
                }
            } else {
                # Display output when build fails
                if ($stdout) { Write-Host "cimipkg stdout: $stdout" -ForegroundColor Yellow }
                if ($stderr) { Write-Host "cimipkg stderr: $stderr" -ForegroundColor Red }
                throw "cimipkg failed with exit code: $exitCode"
            }
        } catch {
            Write-Error "NUPKG creation failed: $_"
        } finally {
            Pop-Location
            
            # Keep osquery files in payload - they're required for installation
            # The osquery configuration files must remain in the payload for deployment
            Write-Verbose "Keeping osquery files in payload for package deployment"
        }
    }
} else {
    Write-Info "Skipping NUPKG creation"
}

# Restore NUPKG build-info.yaml, reportmate.nuspec, and postinstall.ps1 to placeholder state
if ($nupkgBuildInfoOriginal) {
    Set-Content $buildInfoPath $nupkgBuildInfoOriginal -Encoding UTF8 -NoNewline
    Write-Verbose "Restored NUPKG build-info.yaml to placeholder"
}
if ($nupkgNuspecOriginal) {
    Set-Content $nuspecPath $nupkgNuspecOriginal -Encoding UTF8 -NoNewline
    Write-Verbose "Restored reportmate.nuspec to placeholder"
}
if (Test-Path $postinstallCleanPath) {
    Copy-Item $postinstallCleanPath $postinstallTemplatePath -Force
    Write-Verbose "Restored postinstall.ps1 to clean template"
}

Write-Output ""

# Create MSI package via cimipkg
# cimipkg 2026.04.09+ builds .msi by default using the build/pkg/ project structure
# (payload/, scripts/postinstall.ps1, build-info.yaml). The postinstall script handles
# PATH, registry, scheduled tasks, Cimian integration, and osquery bootstrap — everything
# that used to live in WiX custom actions.
if (-not $SkipMSI) {
    Write-Step "Creating MSI package with cimipkg..."

    # Prepare MSI payload
    Write-Verbose "Preparing cimipkg payload..."

    # Ensure payload directory exists (cimipkg NUPKG step may have removed it)
    New-Item -ItemType Directory -Path $PkgPayloadDir -Force | Out-Null

    # Copy executable to payload (installed to Program Files/ReportMate via build-info.yaml install_location)
    Copy-Item (Join-Path $PublishDir "managedreportsrunner.exe") $PkgPayloadDir -Force
    Write-Verbose "Copied managedreportsrunner.exe to payload"

    # Copy configuration files to payload
    Copy-Item (Join-Path $SrcDir "appsettings.json") $PkgPayloadDir -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $SrcDir "appsettings.yaml") $PkgPayloadDir -Force
    Copy-Item (Join-Path $SrcDir "appsettings.yaml") (Join-Path $PkgPayloadDir "appsettings.template.yaml") -Force
    Write-Verbose "Copied configuration files to payload"

    # Copy osquery modules to payload
    $osquerySourceDir = Join-Path $BuildDir "resources\osquery"
    if (Test-Path $osquerySourceDir) {
        Copy-Item $osquerySourceDir $PkgPayloadDir -Recurse -Force
        Write-Verbose "Copied osquery modules to payload"
    }

    # Copy Speedtest CLI alongside managedreportsrunner.exe
    $speedtestExePath = Join-Path $BuildDir "resources\speedtest\speedtest.exe"
    if (Test-Path $speedtestExePath) {
        Copy-Item $speedtestExePath (Join-Path $PkgPayloadDir "speedtest.exe") -Force
        Write-Verbose "Copied Speedtest CLI to payload"
    }

    # Copy shared resources
    $sharedResourcesDir = Join-Path $BuildDir "resources"
    $sharedFiles = @(
        "module-schedules.json",
        "uninstall-tasks.ps1"
    )

    foreach ($file in $sharedFiles) {
        $sourcePath = Join-Path $sharedResourcesDir $file
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $PkgPayloadDir -Force
            Write-Verbose "Copied $file to payload"
        }
    }

    # Copy Cimian integration files to payload (postinstall.ps1 moves them to C:\Program Files\Cimian)
    $cimianPostflightSource = Join-Path $sharedResourcesDir "cimian-postflight.ps1"
    if (Test-Path $cimianPostflightSource) {
        $pkgCimianDir = Join-Path $PkgPayloadDir "cimian"
        New-Item -ItemType Directory -Path $pkgCimianDir -Force | Out-Null
        Copy-Item $cimianPostflightSource (Join-Path $pkgCimianDir "postflight.ps1") -Force
        Write-Verbose "Copied Cimian integration files to payload"
    }

    # Create version.txt for the installed payload
    $versionContent = @"
ReportMate
Version: $Version
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Platform: Windows x64
Commit: $env:GITHUB_SHA
"@
    $versionContent | Out-File (Join-Path $PkgPayloadDir "version.txt") -Encoding UTF8

    # Update build-info.yaml version (replaces {{VERSION}} placeholder; restored after build)
    $pkgBuildInfoPath = Join-Path $PkgDir "build-info.yaml"
    $pkgBuildInfoOriginal = $null
    if (Test-Path $pkgBuildInfoPath) {
        $pkgBuildInfoOriginal = Get-Content $pkgBuildInfoPath -Raw
        $modified = $pkgBuildInfoOriginal -replace '\{\{VERSION\}\}', $Version
        Set-Content $pkgBuildInfoPath $modified -Encoding UTF8 -NoNewline
        Write-Verbose "Updated build-info.yaml version to: $Version"
    }

    # Copy .env file from root to cimipkg build directory (sourced by postinstall.ps1)
    $rootEnvFile = Join-Path $RootDir ".env"
    $pkgEnvFile = Join-Path $PkgDir ".env"
    if (Test-Path $rootEnvFile) {
        Copy-Item $rootEnvFile $pkgEnvFile -Force
        Write-Verbose "Copied .env file to cimipkg build directory"
    } else {
        Write-Warning "Root .env file not found at: $rootEnvFile - MSI may fail during installation"
    }

    # Download cimipkg if not already resolved
    if (-not $cimipkgPath) {
        try {
            $cimipkgPath = Resolve-Cimipkg -RootDir $RootDir
        } catch {
            Write-Error "Failed to download cimipkg: $_"
            Write-Info "Download manually from: https://github.com/windowsadmins/cimian-pkg/releases"
            $SkipMSI = $true
        }
    }

    if (-not $SkipMSI -and $cimipkgPath) {
        try {
            Write-Verbose "Creating MSI with cimipkg from: $cimipkgPath"
            Push-Location $PkgDir

            # Build MSI using cimipkg (2026.04.09+ defaults to .msi output)
            Write-Verbose "Running cimipkg to create MSI package"

            $cimipkgArgs = @("--verbose", ".")
            if ($Sign -and $Thumbprint) {
                $cimipkgArgs += @("--sign-thumbprint", $Thumbprint)
            }

            $output = & $cimipkgPath @cimipkgArgs 2>&1

            $exitCode = $LASTEXITCODE
            $stdout = ($output | Where-Object { $_ -is [string] }) -join "`n"
            $stderr = ($output | Where-Object { $_ -isnot [string] }) -join "`n"

            Write-Verbose "cimipkg stdout: $stdout"
            if ($stderr) {
                Write-Verbose "cimipkg stderr: $stderr"
            }
            Write-Verbose "cimipkg exit code: $exitCode"

            if ($exitCode -eq 0) {
                # Find generated MSI files
                $msiFiles = Get-ChildItem -Path "build" -Filter "*.msi" -ErrorAction SilentlyContinue
                if (-not $msiFiles) {
                    $msiFiles = Get-ChildItem -Path "." -Filter "*.msi" -Recurse -ErrorAction SilentlyContinue
                }

                foreach ($file in $msiFiles) {
                    # Move MSI file to output directory with proper naming
                    $newFileName = "ReportMate-$Version.msi"
                    $targetPath = Join-Path $OutputDir $newFileName
                    Move-Item $file.FullName $targetPath -Force
                    $msiSize = (Get-Item $targetPath).Length / 1MB
                    Write-Success "MSI created: $newFileName ($([math]::Round($msiSize, 2)) MB)"

                    # Sign MSI if signing is enabled and cimipkg didn't already sign it
                    if ($Sign) {
                        $sigInfo = Get-AuthenticodeSignature $targetPath
                        if ($sigInfo.Status -ne "Valid") {
                            Write-Step "Signing MSI..."
                            try {
                                signPackage -FilePath $targetPath
                                Write-Success "Signed MSI ✔"
                            }
                            catch {
                                Write-Error "Failed to sign MSI: $_"
                                exit 1
                            }
                        } else {
                            Write-Verbose "MSI already signed by cimipkg"
                        }
                    }
                }

                if (-not $msiFiles) {
                    Write-Warning "No .msi files found after cimipkg execution"
                }
            } else {
                # Display output when build fails
                if ($stdout) { Write-Host "cimipkg stdout: $stdout" -ForegroundColor Yellow }
                if ($stderr) { Write-Host "cimipkg stderr: $stderr" -ForegroundColor Red }
                throw "cimipkg failed with exit code: $exitCode"
            }
        } catch {
            # MSI is now the primary artifact — fail the build loudly if creation
            # throws, otherwise CI will report success with no MSI produced.
            Pop-Location
            throw "MSI creation failed: $_"
        } finally {
            # Pop-Location here too so we unwind even if the catch above wasn't hit.
            if ((Get-Location).Path -eq $PkgDir) { Pop-Location }
        }
    }

    # Final sanity check: verify the MSI actually landed in the output directory.
    $expectedMsi = Join-Path $OutputDir "ReportMate-$Version.msi"
    if (-not (Test-Path $expectedMsi)) {
        throw "MSI creation completed without an exception but $expectedMsi is missing"
    }
} else {
    Write-Info "Skipping MSI creation"
}

# Restore build-info.yaml to placeholder state
if ($pkgBuildInfoOriginal) {
    Set-Content $pkgBuildInfoPath $pkgBuildInfoOriginal -Encoding UTF8 -NoNewline
    Write-Verbose "Restored build-info.yaml to placeholder"
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

REM Remove old runner.exe if migrating from older version
if exist "C:\Program Files\ReportMate\runner.exe" (
    echo Removing old runner.exe binary...
    del /F /Q "C:\Program Files\ReportMate\runner.exe"
)

REM Run configuration
if exist "C:\Program Files\ReportMate\managedreportsrunner.exe" (
    echo Configuring ReportMate...
    "C:\Program Files\ReportMate\managedreportsrunner.exe" install
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

# Create git tag if requested - DISABLED (user preference)
# Automatic tag creation disabled per user request
if ($false) {
    # Tag creation code commented out
}

# Create GitHub release if requested
if ($CreateRelease -and $ghFound) {
    Write-Step "Creating GitHub release..."
    
    try {
        # Prepare release files
        $releaseFiles = @()
        $outputFiles = Get-ChildItem $OutputDir -File -ErrorAction SilentlyContinue
        
        foreach ($file in $outputFiles) {
            if ($file.Extension -in @('.msi', '.nupkg', '.zip')) {
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
- **MSI Package**: Windows installer built via cimipkg (primary)
- **NUPKG Package**: For Chocolatey and Cimian package management
- **ZIP Archive**: For manual installation and testing

### 🚀 Quick Start

**MSI Installation (Recommended):**
``````cmd
msiexec.exe /i ReportMate-$Version.msi /quiet
``````

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
            ".msi" { "🔧" }
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
Write-Info "1. Test PKG: Install with sbin-installer or extract manually"
Write-Info "2. Test MSI: msiexec.exe /i `"$(Join-Path $OutputDir "ReportMate-$Version.msi")`" /quiet /norestart"
Write-Info "3. Test NUPKG: choco install `"$(Join-Path $OutputDir "ReportMate-$Version.nupkg")`" --source=."
Write-Info "4. Test ZIP: Extract and run install.bat as administrator"
Write-Info "5. Deploy via PKG (primary), MSI, Chocolatey, or manual installation"

if ($ApiUrl) {
    Write-Info "5. Configured API URL: $ApiUrl"
}

if ($CreateTag -and $gitFound) {
    Write-Info "6. Git tag created: $Version"
}

if ($CreateRelease -and $ghFound) {
    Write-Info "7. GitHub release created: $Version"
}

# Import the MSI into Cimian deployment repo if requested
if ($Import) {
    $msiPath = Join-Path $OutputDir "ReportMate-$Version.msi"

    if ((Test-Path $msiPath) -and (-not $SkipMSI)) {
        Write-Step "Importing MSI into Cimian deployment repo..."
        Write-Info "Running: cimiimport `"$msiPath`" --nointeractive"

        & cimiimport $msiPath --nointeractive

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Cimian import completed successfully"
        } else {
            Write-Error "Cimian import failed with exit code: $LASTEXITCODE"
            Write-Info "Manual import: cimiimport `"$msiPath`" --nointeractive"
        }
    } else {
        Write-Error "No MSI found to import: ReportMate-$Version.msi"
        Write-Info "Make sure MSI was built successfully (don't use -SkipMSI with -Import)"
    }
}

# Install the MSI locally if requested
if ($Install) {
    $msiPath = Join-Path $OutputDir "ReportMate-$Version.msi"

    if ((Test-Path $msiPath) -and (-not $SkipMSI)) {
        Write-Step "Installing MSI package..."
        Write-Info "Running: installer --pkg `"$msiPath`""

        sudo installer --pkg $msiPath

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Installation completed successfully"
        } else {
            Write-Error "Installation failed with exit code: $LASTEXITCODE"
            Write-Info "Manual install: sudo installer --pkg `"$msiPath`""
        }
    } else {
        Write-Error "No MSI found to install: ReportMate-$Version.msi"
        Write-Info "Make sure MSI was built successfully (don't use -SkipMSI with -Install)"
    }
}

Write-Output ""

# Clean up duplicate osquery files after package creation  
Write-Step "Cleaning up duplicate osquery files..."
# Only remove from ProgramFiles payload since we want to keep the data payload osquery files
$osqueryProgramFilesDir = Join-Path $ProgramFilesPayloadDir "osquery"

if (Test-Path $osqueryProgramFilesDir) {
    Remove-Item $osqueryProgramFilesDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose "Removed duplicate osquery directory from Program Files payload"
}
Write-Success "Duplicate osquery files cleaned up"

# Clean up all payload directories after package creation
Write-Step "Cleaning up payload directories after package creation..."
$payloadDirs = @($ProgramFilesPayloadDir, $ProgramDataPayloadDir, $CimianPayloadDir, $PkgPayloadDir)

foreach ($dir in $payloadDirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Verbose "Cleaned up: $dir"
    }
}

Write-Success "All payload directories cleaned up"

Write-Output ""
Write-Success "Build completed successfully!"

# Explicitly exit with success code to prevent stale exit codes from propagating
exit 0
