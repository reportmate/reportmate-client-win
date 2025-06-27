#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    ReportMate Unified Build Script
    
.DESCRIPTION
    One-stop build script that replicates the CI pipeline locally.
    Builds all package types: EXE, MSI, NUPKG, and ZIP.
    Supports creating tags and releases when run with appropriate parameters.
    
.PARAMETER Version
    Version to build (default: auto-generated from date in YYYY.MM.DD format)
    
.PARAMETER Configuration
    Build configuration (Release or Debug)
    
.PARAMETER SkipBuild
    Skip the .NET build step
    
.PARAMETER SkipMSI
    Skip MSI creation
    
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
    
.EXAMPLE
    .\build.ps1
    Build with auto-generated version (YYYY.MM.DD format)
    
.EXAMPLE
    .\build.ps1 -Version "2024.06.27" -ApiUrl "https://api.reportmate.com"
    Build specific version with API URL
    
.EXAMPLE
    .\build.ps1 -Clean -SkipMSI -Verbose
    Clean build, skip MSI creation, with verbose output
    
.EXAMPLE
    .\build.ps1 -CreateTag -CreateRelease
    Build, create tag, and create GitHub release
    
.EXAMPLE
    .\build.ps1 -Version "2024.06.27" -CreateTag -CreateRelease -ApiUrl "https://api.reportmate.com"
    Full production build with tagging and release
#>

param(
    [string]$Version = "",
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [switch]$SkipBuild = $false,
    [switch]$SkipMSI = $false,
    [switch]$SkipNUPKG = $false,
    [switch]$SkipZIP = $false,
    [switch]$Clean = $false,
    [string]$ApiUrl = "",
    [switch]$CreateTag = $false,
    [switch]$CreateRelease = $false,
    [switch]$Verbose = $false
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

# Generate version if not provided (YYYY.MM.DD format)
if (-not $Version) {
    $Version = Get-Date -Format "yyyy.MM.dd"
    Write-Info "Auto-generated version: $Version"
}

Write-Header "ReportMate Unified Build Script"
Write-Header "====================================="
Write-Info "Version: $Version"
Write-Info "Configuration: $Configuration"
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
$BuildDir = "$RootDir/build"
$SrcDir = "$RootDir/src"
$NupkgDir = "$RootDir/nupkg"
$ProgramFilesPayloadDir = "$NupkgDir/payload/Program Files/ReportMate"
$ProgramDataPayloadDir = "$NupkgDir/payload/ProgramData/ManagedReports"
$CimianPayloadDir = "$NupkgDir/payload/Program Files/Cimian"
$PublishDir = "$BuildDir/publish"
$OutputDir = "$BuildDir/output"

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

# Check WiX (for MSI)
$wixFound = $false
if (-not $SkipMSI) {
    try {
        $null = Get-Command "candle.exe" -ErrorAction Stop
        $null = Get-Command "light.exe" -ErrorAction Stop
        Write-Success "WiX Toolset found"
        $wixFound = $true
    } catch {
        Write-Warning "WiX Toolset not found - MSI creation will be skipped"
        Write-Info "Install from: https://wixtoolset.org/releases/"
        $SkipMSI = $true
    }
}

# Check cimipkg (for NUPKG)
$cimipkgPath = $null
if (-not $SkipNUPKG) {
    $cimipkgLocations = @(
        (Get-Command cimipkg -ErrorAction SilentlyContinue)?.Source,
        "$RootDir/cimipkg.exe",
        "$BuildDir/cimipkg.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }
    
    if ($cimipkgLocations) {
        $cimipkgPath = $cimipkgLocations[0]
        Write-Success "cimipkg found: $cimipkgPath"
    } else {
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

# Create MSI installer
if (-not $SkipMSI -and $wixFound) {
    Write-Step "Creating MSI installer..."
    
    try {
        # Generate WiX source
        $wixSource = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  
  <Product Id="*" 
           Name="ReportMate" 
           Language="1033" 
           Version="$Version.0" 
           Manufacturer="ReportMate" 
           UpgradeCode="12345678-1234-1234-1234-123456789012">
    
    <Package InstallerVersion="200" 
             Compressed="yes" 
             InstallScope="perMachine"
             Platform="x64"
             Description="ReportMate for device management and security monitoring"
             Comments="Integrates with Cimian and uses osquery for comprehensive data collection" />
    
    <Condition Message="This application requires Windows 7 or later.">
      <![CDATA[Installed OR (VersionNT >= 601)]]>
    </Condition>
    
    <MajorUpgrade DowngradeErrorMessage="A newer version of ReportMate is already installed." />
    <MediaTemplate EmbedCab="yes" />
    
    <Feature Id="ProductFeature" Title="ReportMate" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="ReportMate" />
      </Directory>
      <Directory Id="CommonAppDataFolder">
        <Directory Id="ManagedReportsFolder" Name="ManagedReports" />
      </Directory>
    </Directory>
    
    <Property Id="API_URL" Value="$ApiUrl" />
    
    <CustomAction Id="ConfigureRegistry"
                  Execute="deferred"
                  Impersonate="no"
                  Directory="INSTALLFOLDER"
                  ExeCommand='runner.exe install --api-url "[API_URL]"'
                  Return="ignore" />
    
    <InstallExecuteSequence>
      <Custom Action="ConfigureRegistry" After="InstallFiles">NOT Installed AND API_URL</Custom>
    </InstallExecuteSequence>
    
    <UI>
      <UIRef Id="WixUI_Minimal" />
    </UI>
    
  </Product>
  
  <Fragment>
    <ComponentGroup Id="ProductComponents">
      
      <Component Id="ReportMateExe" Guid="*" Directory="INSTALLFOLDER" Win64="yes">
        <File Id="ReportMateExe" 
              Source="$ProgramFilesPayloadDir\runner.exe" 
              KeyPath="yes" />
      </Component>
      
      <Component Id="VersionFile" Guid="*" Directory="INSTALLFOLDER" Win64="yes">
        <File Id="VersionFile" 
              Source="$ProgramFilesPayloadDir\version.txt" 
              KeyPath="yes" />
      </Component>
      
      <Component Id="AppSettingsFile" Guid="*" Directory="ManagedReportsFolder" Win64="yes">
        <File Id="AppSettings" 
              Source="$ProgramDataPayloadDir\appsettings.yaml" 
              KeyPath="yes" />
      </Component>
      
      <Component Id="AppSettingsTemplateFile" Guid="*" Directory="ManagedReportsFolder" Win64="yes">
        <File Id="AppSettingsTemplate" 
              Source="$ProgramDataPayloadDir\appsettings.template.yaml" 
              KeyPath="yes" />
      </Component>
      
      <Component Id="OsqueryQueriesFile" Guid="*" Directory="ManagedReportsFolder" Win64="yes">
        <File Id="OsqueryQueries" 
              Source="$ProgramDataPayloadDir\queries.json" 
              KeyPath="yes" />
      </Component>
      
      <Component Id="RegistryEntries" Guid="*" Directory="INSTALLFOLDER" Win64="yes">
        <RegistryKey Root="HKLM" Key="SOFTWARE\ReportMate">
          <RegistryValue Name="InstallPath" Type="string" Value="[INSTALLFOLDER]" KeyPath="yes" />
          <RegistryValue Name="Version" Type="string" Value="$Version" />
          <RegistryValue Name="InstallDate" Type="string" Value="[Date]" />
        </RegistryKey>
      </Component>
      
    </ComponentGroup>
  </Fragment>
  
</Wix>
"@
        
        $wixFile = "$OutputDir/ReportMate.wxs"
        $wixSource | Out-File -FilePath $wixFile -Encoding UTF8
        
        # Compile WiX
        $wixObj = "$OutputDir/ReportMate.wixobj"
        $msiFile = "$OutputDir/ReportMate-$Version.msi"
        
        Write-Verbose "Compiling WiX source..."
        & candle.exe -out $wixObj $wixFile
        if ($LASTEXITCODE -ne 0) {
            throw "WiX compilation failed"
        }
        
        Write-Verbose "Linking MSI..."
        & light.exe -out $msiFile $wixObj -ext WixUIExtension -sw1076
        if ($LASTEXITCODE -ne 0) {
            throw "WiX linking failed"
        }
        
        $msiSize = (Get-Item $msiFile).Length / 1MB
        Write-Success "MSI created: ReportMate-$Version.msi ($([math]::Round($msiSize, 2)) MB)"
        
    } catch {
        Write-Error "MSI creation failed: $_"
        $SkipMSI = $true
    }
} else {
    Write-Info "Skipping MSI creation"
}

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
            Write-Verbose "Running cimipkg..."
            Push-Location $NupkgDir
            & $cimipkgPath .
            
            if ($LASTEXITCODE -eq 0) {
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
                throw "cimipkg failed with exit code: $LASTEXITCODE"
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
- **MSI Installer**: For enterprise deployment via Group Policy, SCCM, or Intune
- **NUPKG Package**: For Chocolatey and Cimian package management  
- **ZIP Archive**: For manual installation and testing

### 🚀 Quick Start

**MSI Installation:**
``````cmd
msiexec /i ReportMate-$Version.msi /quiet
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
            ".msi" { "🏗️ " }
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
Write-Info "1. Test MSI: msiexec /i `"$OutputDir/ReportMate-$Version.msi`" /quiet"
Write-Info "2. Test NUPKG: choco install `"$OutputDir/ReportMate-$Version.nupkg`" --source=."
Write-Info "3. Test ZIP: Extract and run install.bat as administrator"
Write-Info "4. Deploy via Group Policy, SCCM, or Intune"

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
