#!/usr/bin/env pwsh
# ReportMate Windows Client Package Builder
# Creates both MSI and NUPKG packages

param(
    [string]$Version = "1.0.0",
    [string]$Configuration = "Release",
    [switch]$SkipBuild = $false,
    [switch]$SkipMSI = $false,
    [switch]$SkipNUPKG = $false
)

$ErrorActionPreference = "Stop"

Write-Host "ReportMate Windows Client Package Builder" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Version: $Version" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow

# Set paths
$RootDir = Split-Path $PSScriptRoot -Parent
$BuildDir = "$RootDir/build"
$SrcDir = "$RootDir/src"
$NupkgDir = "$RootDir/nupkg"
$ProgramFilesPayloadDir = "$NupkgDir/payload/Program Files/ReportMate"
$ProgramDataPayloadDir = "$NupkgDir/payload/ProgramData/ManagedReports"
$PublishDir = "$BuildDir/publish"
$OutputDir = "$BuildDir/output"

# Clean and create directories
Write-Host "Preparing directories..." -ForegroundColor Yellow
Remove-Item $PublishDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $ProgramFilesPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $ProgramDataPayloadDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $OutputDir -Recurse -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null
New-Item -ItemType Directory -Path $ProgramFilesPayloadDir -Force | Out-Null
New-Item -ItemType Directory -Path $ProgramDataPayloadDir -Force | Out-Null
New-Item -ItemType Directory -Path "$NupkgDir/payload/Program Files/Cimian" -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if (-not $SkipBuild) {
    Write-Host "Building .NET application..." -ForegroundColor Yellow
    
    # Update version in csproj
    $csprojPath = "$SrcDir/ReportMate.WindowsClient.csproj"
    $content = Get-Content $csprojPath -Raw
    $content = $content -replace '<AssemblyVersion>.*?</AssemblyVersion>', "<AssemblyVersion>$Version.0</AssemblyVersion>"
    $content = $content -replace '<FileVersion>.*?</FileVersion>', "<FileVersion>$Version.0</FileVersion>"
    Set-Content $csprojPath $content

    # Restore and build
    dotnet restore $csprojPath
    dotnet build $csprojPath --configuration $Configuration --no-restore

    # Publish self-contained
    dotnet publish $csprojPath `
        --configuration $Configuration `
        --runtime win-x64 `
        --self-contained true `
        --output $PublishDir `
        -p:PublishSingleFile=true `
        -p:PublishTrimmed=true

    Write-Host "✅ Build completed successfully" -ForegroundColor Green
}

# Prepare payload for packaging
Write-Host "Preparing package payload..." -ForegroundColor Yellow

# Copy executable and binaries to Program Files/ReportMate
Copy-Item "$PublishDir/runner.exe" $ProgramFilesPayloadDir -Force

# Note: No configuration files in Program Files - all configs are in ProgramData for CSP/OMA-URI management

# Create version file in Program Files
$versionContent = @"
ReportMate Windows Client
Version: $Version
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Platform: Windows x64
"@
$versionContent | Out-File "$ProgramFilesPayloadDir/version.txt" -Encoding UTF8

# Copy working configuration and queries to ProgramData
Copy-Item "$SrcDir/appsettings.yaml" $ProgramDataPayloadDir -Force
Copy-Item "$SrcDir/osquery-queries.json" "$ProgramDataPayloadDir/queries.json" -Force

# Create enterprise template configuration (CSP/OMA-URI manageable)
Copy-Item "$SrcDir/appsettings.yaml" "$ProgramDataPayloadDir/appsettings.template.yaml" -Force

# Ensure Cimian postflight script is in place
$cimianDir = "$NupkgDir/payload/Program Files/Cimian"
if (-not (Test-Path "$cimianDir/postflight.ps1")) {
    Write-Host "⚠️  Cimian postflight script not found, it should already exist in the repo" -ForegroundColor Yellow
}

# Update package version
$buildInfoPath = "$NupkgDir/build-info.yaml"
$content = Get-Content $buildInfoPath -Raw
$content = $content -replace 'version: ".*?"', "version: `"$Version`""
Set-Content $buildInfoPath $content

Write-Host "✅ Payload prepared" -ForegroundColor Green
Write-Host "   Program Files: $ProgramFilesPayloadDir" -ForegroundColor Blue
Write-Host "   ProgramData: $ProgramDataPayloadDir" -ForegroundColor Blue

# Create MSI installer
if (-not $SkipMSI) {
    Write-Host "Creating MSI installer..." -ForegroundColor Yellow
    
    try {
        & "$BuildDir/create-installer.ps1" -Version $Version -SourcePath $ProgramFilesPayloadDir -OutputPath $OutputDir
        Write-Host "✅ MSI installer created" -ForegroundColor Green
    } catch {
        Write-Warning "MSI creation failed: $_"
        Write-Host "Note: MSI creation requires WiX Toolset to be installed" -ForegroundColor Yellow
    }
}

# Create NUPKG package
if (-not $SkipNUPKG) {
    Write-Host "Creating NUPKG package..." -ForegroundColor Yellow
    
    # Check for cimipkg
    $cimipkg = Get-Command cimipkg -ErrorAction SilentlyContinue
    if (-not $cimipkg) {
        $cimipkg = Get-Command "./cimipkg.exe" -ErrorAction SilentlyContinue
    }
    if (-not $cimipkg) {
        $cimipkg = Get-Command "$BuildDir/cimipkg.exe" -ErrorAction SilentlyContinue
    }
    
    if ($cimipkg) {
        try {
            Push-Location $NupkgDir
            & $cimipkg.Source $NupkgDir
            
            # Move generated nupkg to output
            $nupkgFiles = Get-ChildItem -Path . -Filter "*.nupkg"
            foreach ($file in $nupkgFiles) {
                Move-Item $file.FullName $OutputDir
                Write-Host "✅ Created NUPKG: $($file.Name)" -ForegroundColor Green
            }
        } catch {
            Write-Warning "NUPKG creation failed: $_"
        } finally {
            Pop-Location
        }
    } else {
        Write-Warning "cimipkg not found. Download from: https://github.com/windowsadmins/cimian-pkg/releases"
        Write-Host "To create NUPKG manually:" -ForegroundColor Yellow
        Write-Host "1. Download cimipkg.exe" -ForegroundColor Yellow
        Write-Host "2. Run: cimipkg.exe $NupkgDir" -ForegroundColor Yellow
    }
}

# Create ZIP archive for manual distribution
Write-Host "Creating ZIP archive..." -ForegroundColor Yellow
$zipPath = "$OutputDir/ReportMate-WindowsClient-$Version.zip"

# Create a temporary directory for the ZIP that includes both Program Files and ProgramData structure
$tempZipDir = "$OutputDir/temp-zip"
Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tempZipDir -Force | Out-Null

# Copy both payload structures to the temp directory
Copy-Item "$NupkgDir/payload/*" $tempZipDir -Recurse -Force

Compress-Archive -Path "$tempZipDir/*" -DestinationPath $zipPath -Force
Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "✅ ZIP archive created: $zipPath" -ForegroundColor Green

# Summary
Write-Host "" -ForegroundColor Green
Write-Host "Build Summary" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host "Version: $Version" -ForegroundColor Yellow
Write-Host "Output Directory: $OutputDir" -ForegroundColor Yellow
Write-Host ""

$outputFiles = Get-ChildItem $OutputDir -ErrorAction SilentlyContinue
if ($outputFiles) {
    Write-Host "Generated packages:" -ForegroundColor Green
    foreach ($file in $outputFiles) {
        $sizeKB = [math]::Round($file.Length / 1KB, 1)
        Write-Host "  📦 $($file.Name) ($sizeKB KB)" -ForegroundColor Cyan
    }
} else {
    Write-Host "No packages were generated" -ForegroundColor Red
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "1. Test installation: msiexec /i `"$OutputDir/ReportMate-WindowsClient-$Version.msi`" /quiet" -ForegroundColor Yellow
Write-Host "2. Deploy with Chocolatey: choco install `"$OutputDir/ReportMate-WindowsClient-$Version.nupkg`"" -ForegroundColor Yellow
Write-Host "3. Manual installation: extract ZIP and run postinstall.ps1" -ForegroundColor Yellow
