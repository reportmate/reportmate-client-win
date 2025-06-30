# ReportMate Build Script with Enterprise Signing
# Based on the Cimian signing pattern for secure enterprise deployment

param(
    [switch]$Sign,
    [switch]$NoSign,
    [string]$Thumbprint,
    [ValidateSet("build", "test", "all")]
    [string]$Task = "all"
)

# ──────────────────────────  GLOBALS  ──────────────────────────
# Friendly name (CN) of the enterprise code-signing certificate you push with Intune
$Global:EnterpriseCertCN = 'EmilyCarrU Intune Windows Enterprise Certificate'

# Exit immediately if a command exits with a non-zero status
$ErrorActionPreference = 'Stop'

# Function to display messages with different log levels
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"    { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan }
        "SUCCESS" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
    }
}

# Function to check if a command exists
function Test-Command {
    param (
        [string]$Command
    )
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

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
            Write-Log "signtool discovered at $($exe.FullName)" "SUCCESS"
            return
        }
    }

    # graceful failure
    Write-Log @"
signtool.exe not found.

Install **any** Windows 10/11 SDK _or_ Visual Studio Build Tools  
(choose a workload that includes **Windows SDK Signing Tools**),  
then run the build again.
"@ "ERROR"
    exit 1
}

# ──────────────────────────  SIGNING DECISION  ─────────────────
# Auto-detect enterprise certificate if available
$autoDetectedThumbprint = $null
if (-not $Sign -and -not $NoSign -and -not $Thumbprint) {
    try {
        $autoDetectedThumbprint = Get-SigningCertThumbprint
        if ($autoDetectedThumbprint) {
            Write-Log "Auto-detected enterprise certificate $autoDetectedThumbprint - will sign binaries for security." "INFO"
            $Sign = $true
            $Thumbprint = $autoDetectedThumbprint
        } else {
            Write-Log "No enterprise certificate found - binaries will be unsigned (may be blocked by Defender)." "WARNING"
        }
    }
    catch {
        Write-Log "Could not check for enterprise certificates: $_" "WARNING"
    }
}

if ($NoSign) {
    Write-Log "NoSign parameter specified - skipping all signing." "INFO"
    $Sign = $false
}

if ($Sign) {
    Test-SignTool
    if (-not $Thumbprint) {
        $Thumbprint = Get-SigningCertThumbprint
        if (-not $Thumbprint) {
            Write-Log "No valid '$Global:EnterpriseCertCN' certificate with a private key found – aborting." "ERROR"
            exit 1
        }
        Write-Log "Auto-selected signing cert $Thumbprint" "INFO"
    } else {
        Write-Log "Using signing certificate $Thumbprint" "INFO"
    }
    $env:SIGN_THUMB = $Thumbprint   # used by the signing function
} else {
    Write-Log "Build will be unsigned." "INFO"
}

# ────────────────  SIGNING HELPERS  ────────────────
function signPackage {
    <#
      .SYNOPSIS  Authenticode-signs an EXE/MSI with our enterprise cert.
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
        Write-Log "Signing '$FilePath' using $tsa …" "INFO"
        & signtool.exe sign `
            /sha1  $Thumbprint `
            /fd    SHA256 `
            /tr    $tsa `
            /td    SHA256 `
            /v `
            "$FilePath"

        if ($LASTEXITCODE -eq 0) {
            Write-Log  "signtool succeeded with $tsa" "SUCCESS"
            return
        }
        Write-Log "signtool failed with $tsa (exit $LASTEXITCODE)" "WARNING"
    }

    throw "signtool failed with all timestamp authorities."
}

function Test-BinarySigned {
    param([string]$FilePath)
    
    try {
        & signtool.exe verify /pa "$FilePath" 2>&1 | Out-Null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

# ───────────────────────────────────────────────────
#  BUILD PROCESS STARTS
# ───────────────────────────────────────────────────

Write-Log "🚀 Building ReportMate Windows Client" "INFO"
Write-Log "=====================================" "INFO"

# Check prerequisites
Write-Log "Checking prerequisites..." "INFO"

if (-not (Test-Command "dotnet")) {
    Write-Log ".NET SDK not found. Please install .NET 8.0 SDK" "ERROR"
    exit 1
}

Write-Log ".NET SDK version: $(dotnet --version)" "SUCCESS"

# Build settings
$ProjectDir = Join-Path $PSScriptRoot "..\src"
$OutputDir = Join-Path $PSScriptRoot "output"
$PublishDir = Join-Path $OutputDir "publish"

# Clean and create output directories
Write-Log "Preparing build directories..." "INFO"
if (Test-Path $OutputDir) {
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null

# Build the application
Write-Log "Building ReportMate..." "INFO"
Push-Location $ProjectDir

try {
    # Clean
    dotnet clean --configuration Release
    
    # Restore
    dotnet restore
    
    # Publish self-contained executable
    dotnet publish `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --output $PublishDir `
        -p:PublishSingleFile=true `
        -p:AssemblyName=runner
        
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
    
    Write-Log "Build completed successfully" "SUCCESS"
}
catch {
    Write-Log "Build failed: $_" "ERROR"
    exit 1
}
finally {
    Pop-Location
}

# Sign the binary if requested
$binaryPath = Join-Path $PublishDir "runner.exe"

if (-not (Test-Path $binaryPath)) {
    Write-Log "Binary not found at $binaryPath" "ERROR"
    exit 1
}

if ($Sign) {
    Write-Log "Signing binary..." "INFO"
    try {
        signPackage -FilePath $binaryPath
        Write-Log "Binary signed successfully ✔" "SUCCESS"
    }
    catch {
        Write-Log "Failed to sign binary: $_" "ERROR"
        exit 1
    }
} else {
    Write-Log "Binary not signed (may be blocked by Windows Defender)" "WARNING"
}

# Always verify signing status before allowing execution
Write-Log "Verifying binary signature..." "INFO"
$isSigned = Test-BinarySigned -FilePath $binaryPath

if ($isSigned) {
    Write-Log "✅ Binary is properly signed and ready for execution" "SUCCESS"
} else {
    if ($Sign) {
        Write-Log "❌ Binary signing verification failed!" "ERROR"
        exit 1
    } else {
        Write-Log "⚠️  Binary is not signed - Windows Defender may block execution" "WARNING"
    }
}

if ($Task -eq "test" -or $Task -eq "all") {
    Write-Log "Testing binary..." "INFO"
    
    if (-not $isSigned) {
        Write-Log "⚠️  Cannot test unsigned binary - Windows Defender will block it" "WARNING"
        Write-Log "💡 Use -Sign parameter to sign the binary before testing" "INFO"
    } else {
        try {
            # Test the binary
            & $binaryPath --help
            Write-Log "Binary test completed successfully" "SUCCESS"
        }
        catch {
            Write-Log "Binary test failed: $_" "ERROR"
            exit 1
        }
    }
}

# Display summary
Write-Log "" "INFO"
Write-Log "🎉 Build Summary" "SUCCESS"
Write-Log "================" "INFO"
Write-Log "Binary: $binaryPath" "INFO"
Write-Log "Signed: $(if ($isSigned) { '✅ Yes' } else { '❌ No' })" "INFO"
Write-Log "Size: $([math]::Round((Get-Item $binaryPath).Length / 1MB, 2)) MB" "INFO"
Write-Log "" "INFO"

if ($isSigned) {
    Write-Log "✅ Ready for deployment!" "SUCCESS"
} else {
    Write-Log "⚠️  Sign the binary before deployment to prevent Windows Defender blocks" "WARNING"
    Write-Log "💡 Use: .\build.ps1 -Sign" "INFO"
}
