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
#>

param(
    [string]$Version = "",
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [switch]$SkipBuild = $false,
    [switch]$SkipNUPKG = $false,
    [switch]$SkipZIP = $false,
    [switch]$Clean = $false,
    [string]$ApiUrl = "",
    [switch]$CreateTag = $false,
    [switch]$CreateRelease = $false,
    [switch]$Verbose = $false,
    [switch]$Sign,
    [switch]$NoSign,
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
# Auto-detect enterprise certificate if available
$autoDetectedThumbprint = $null
if (-not $Sign -and -not $NoSign -and -not $Thumbprint) {
    try {
        $autoDetectedThumbprint = Get-SigningCertThumbprint
        if ($autoDetectedThumbprint) {
            Write-Info "Auto-detected enterprise certificate $autoDetectedThumbprint - will sign binaries for security."
            $Sign = $true
            $Thumbprint = $autoDetectedThumbprint
        } else {
            Write-Warning "No enterprise certificate found - binaries will be unsigned (may be blocked by Defender)."
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

# Set paths
$RootDir = $PSScriptRoot
$SrcDir = "$RootDir/src"
$NupkgDir = "$RootDir/nupkg"
$ProgramFilesPayloadDir = "$NupkgDir/payload/Program Files/ReportMate"
$ProgramDataPayloadDir = "$NupkgDir/payload/ProgramData/ManagedReports"
$CimianPayloadDir = "$NupkgDir/payload/Program Files/Cimian"
$PublishDir = "$RootDir/.publish"
$OutputDir = "$RootDir/dist"

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

# Create directories
Write-Step "Creating directories..."
@($PublishDir, $OutputDir, $ProgramFilesPayloadDir, $ProgramDataPayloadDir, $CimianPayloadDir) | ForEach-Object {
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

Write-Output ""

# Build .NET application
if (-not $SkipBuild) {
    Write-Step "Building .NET application..."
    
    # Update version in project file
    $csprojPath = "$SrcDir/ReportMate.WindowsClient.csproj"
    Write-Verbose "Updating version in: $csprojPath"
    
    # Create .NET-compatible version (must be numeric)
    $assemblyVersion = if ($Version -match '^(\d{4})\.(\d{2})\.(\d{2})') {
        # YYYY.MM.DD format - convert to valid assembly version
        "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
    } elseif ($Version -match '^(\d+)\.(\d+)\.(\d+)') {
        # Standard version format - use as-is with .0 build
        "$Version.0"
    } else {
        # Fallback to current date-based version
        $dateVersion = Get-Date -Format "yyyy.M.d"
        "$dateVersion.0"
    }
    
    $content = Get-Content $csprojPath -Raw
    $content = $content -replace '<AssemblyVersion>.*?</AssemblyVersion>', "<AssemblyVersion>$assemblyVersion</AssemblyVersion>"
    $content = $content -replace '<FileVersion>.*?</FileVersion>', "<FileVersion>$assemblyVersion</FileVersion>"
    Set-Content $csprojPath $content -Encoding UTF8
    
    Write-Info "Updated assembly version to: $assemblyVersion"
    
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

# Copy executable to Program Files/ReportMate
Copy-Item "$PublishDir/runner.exe" $ProgramFilesPayloadDir -Force
Write-Verbose "Copied runner.exe to Program Files payload"

# Create version file
$versionContent = @"
ReportMate
Version: $Version
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Platform: Windows x64
Commit: $env:GITHUB_SHA
"@
$versionContent | Out-File "$ProgramFilesPayloadDir/version.txt" -Encoding UTF8

# Copy configuration files to ProgramData
Copy-Item "$SrcDir/appsettings.yaml" $ProgramDataPayloadDir -Force
Copy-Item "$SrcDir/osquery-queries.json" "$ProgramDataPayloadDir/queries.json" -Force
Copy-Item "$SrcDir/appsettings.yaml" "$ProgramDataPayloadDir/appsettings.template.yaml" -Force
Write-Verbose "Copied configuration files to ProgramData payload"

# Ensure Cimian postflight script exists
if (-not (Test-Path "$CimianPayloadDir/postflight.ps1")) {
    Write-Verbose "Creating Cimian postflight script..."
    $postflightContent = @'
# ReportMate Cimian Postflight Script
# This script runs after Cimian installation to execute ReportMate

param(
    [string]$ApiUrl = $env:REPORTMATE_API_URL
)

Write-Host "ReportMate Cimian postflight script starting..."

try {
    $reportMateExe = "C:\Program Files\ReportMate\runner.exe"
    
    if (Test-Path $reportMateExe) {
        Write-Host "Found ReportMate executable: $reportMateExe"
        
        # Configure API URL if provided
        if ($ApiUrl) {
            Write-Host "Configuring API URL: $ApiUrl"
            & $reportMateExe install --api-url $ApiUrl
        }
        
        # Test the installation
        Write-Host "Testing ReportMate installation..."
        & $reportMateExe test
        
        Write-Host "ReportMate postflight completed successfully"
    } else {
        Write-Error "ReportMate executable not found at: $reportMateExe"
        exit 1
    }
} catch {
    Write-Error "ReportMate postflight failed: $_"
    exit 1
}
'@
    $postflightContent | Out-File "$CimianPayloadDir/postflight.ps1" -Encoding UTF8
}

# Update package build-info.yaml
$buildInfoPath = "$NupkgDir/build-info.yaml"
if (Test-Path $buildInfoPath) {
    $content = Get-Content $buildInfoPath -Raw
    $content = $content -replace 'version: ".*?"', "version: `"$Version`""
    Set-Content $buildInfoPath $content -Encoding UTF8
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
                $cimipkgPath = "$RootDir/cimipkg.exe"
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
        }
    }
} else {
    Write-Info "Skipping NUPKG creation"
}

Write-Output ""

# Create ZIP archive
if (-not $SkipZIP) {
    Write-Step "Creating ZIP archive..."
    $zipPath = "$OutputDir/ReportMate-$Version.zip"

    $tempZipDir = "$OutputDir/temp-zip"
    Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $tempZipDir -Force | Out-Null

    # Copy payload structure
    Copy-Item "$NupkgDir/payload/*" $tempZipDir -Recurse -Force

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
    $deployScript | Out-File "$tempZipDir/install.bat" -Encoding ASCII

    Compress-Archive -Path "$tempZipDir/*" -DestinationPath $zipPath -Force
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
Write-Header "============="
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
Write-Info "1. Test NUPKG: choco install `"$OutputDir/ReportMate-$Version.nupkg`" --source=."
Write-Info "2. Test ZIP: Extract and run install.bat as administrator"
Write-Info "3. Deploy via Chocolatey, package management, or manual installation"

if ($ApiUrl) {
    Write-Info "5. Configured API URL: $ApiUrl"
}

if ($CreateTag -and $gitFound) {
    Write-Info "6. Git tag created: $Version"
}

if ($CreateRelease -and $ghFound) {
    Write-Info "7. GitHub release created: $Version"
}

Write-Output ""
Write-Success "Build completed successfully!"
