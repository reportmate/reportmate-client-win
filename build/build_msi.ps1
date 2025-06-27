# ReportMate Windows Client Installer Creation Script
# Creates an MSI installer for the ReportMate Windows Client
# Requires WiX Toolset to be installed

param(
    [string]$Version = "1.0.0",
    [string]$OutputPath = ".\output",
    [string]$SourcePath = ".\publish",
    [string]$ApiUrl = "",
    [switch]$SkipSigning = $false
)

# Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors for output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Green { Write-ColorOutput Green $args }
function Write-Yellow { Write-ColorOutput Yellow $args }
function Write-Red { Write-ColorOutput Red $args }
function Write-Blue { Write-ColorOutput Blue $args }

Write-Green "🚀 Creating ReportMate Windows Client Installer"
Write-Output "================================================"

# Check prerequisites
Write-Yellow "📋 Checking prerequisites..."

# Check if WiX is installed
if (-not (Get-Command "candle.exe" -ErrorAction SilentlyContinue)) {
    Write-Red "❌ WiX Toolset not found. Please install WiX Toolset v3.11 or later"
    Write-Output "Download from: https://wixtoolset.org/releases/"
    exit 1
}

Write-Green "✅ WiX Toolset found"

# Check source files
if (-not (Test-Path $SourcePath)) {
    Write-Red "❌ Source path not found: $SourcePath"
    Write-Output "Please run build.sh first to create the publish directory"
    exit 1
}

$ExePath = Join-Path $SourcePath "runner.exe"
if (-not (Test-Path $ExePath)) {
    Write-Red "❌ runner.exe not found in source path"
    exit 1
}

Write-Green "✅ Source files found"

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Generate WiX source file
Write-Yellow "📝 Generating WiX installer source..."

$WixSource = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  
  <!-- Product definition -->
  <Product Id="*" 
           Name="ReportMate Windows Client" 
           Language="1033" 
           Version="$Version" 
           Manufacturer="ReportMate" 
           UpgradeCode="12345678-1234-1234-1234-123456789012">
    
    <Package InstallerVersion="200" 
             Compressed="yes" 
             InstallScope="perMachine"
             Description="ReportMate Windows Client for device management and security monitoring"
             Comments="Integrates with Cimian and uses osquery for comprehensive data collection" />
    
    <!-- Installation conditions -->
    <Condition Message="This application requires Windows 7 or later.">
      <![CDATA[Installed OR (VersionNT >= 601)]]>
    </Condition>
    
    <!-- Upgrade logic -->
    <MajorUpgrade DowngradeErrorMessage="A newer version of ReportMate Windows Client is already installed." />
    
    <!-- Media -->
    <MediaTemplate EmbedCab="yes" />
    
    <!-- Features -->
    <Feature Id="ProductFeature" Title="ReportMate Windows Client" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    
    <!-- Installation directory structure -->
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="ReportMate">
          <Directory Id="LogsFolder" Name="Logs" />
        </Directory>
      </Directory>
      <Directory Id="ProgramMenuFolder">
        <Directory Id="ApplicationProgramsFolder" Name="ReportMate" />
      </Directory>
      <Directory Id="CommonAppDataFolder">
        <Directory Id="AppDataFolder" Name="ReportMate">
          <Directory Id="AppDataLogsFolder" Name="logs" />
        </Directory>
      </Directory>
    </Directory>
    
    <!-- Custom actions for configuration -->
    <CustomAction Id="SetApiUrl" 
                  Property="API_URL" 
                  Value="$ApiUrl" />
    
    <CustomAction Id="ConfigureRegistry"
                  Execute="deferred"
                  Impersonate="no"
                  ExeCommand='[INSTALLFOLDER]runner.exe install --api-url "[API_URL]"'
                  Return="ignore" />
    
    <!-- Installation sequence -->
    <InstallExecuteSequence>
      <Custom Action="SetApiUrl" Before="ConfigureRegistry">NOT Installed</Custom>
      <Custom Action="ConfigureRegistry" After="InstallFiles">NOT Installed AND API_URL</Custom>
    </InstallExecuteSequence>
    
    <!-- UI for configuration -->
    <UI>
      <UIRef Id="WixUI_Minimal" />
      <Publish Dialog="ExitDialog"
               Control="Finish" 
               Event="DoAction" 
               Value="LaunchApplication">WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish>
    </UI>
    
    <Property Id="WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT" Value="Launch ReportMate Configuration" />
    <Property Id="WixShellExecTarget" Value="[#ReportMateExe]" />
    <CustomAction Id="LaunchApplication"
                  BinaryKey="WixCA"
                  DllEntry="WixShellExec"
                  Impersonate="yes" />
    
  </Product>
  
  <!-- Component group for all files -->
  <Fragment>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      
      <!-- Main executable -->
      <Component Id="ReportMateExe" Guid="*">
        <File Id="ReportMateExe" 
              Source="$($SourcePath)\runner.exe" 
              KeyPath="yes" />
      </Component>
      
      <!-- Configuration files -->
      <Component Id="ConfigFiles" Guid="*">
        <File Id="AppSettings" 
              Source="$($SourcePath)\appsettings.json" />
        <File Id="AppSettingsYaml" 
              Source="$($SourcePath)\appsettings.yaml" />
        <File Id="OsqueryQueries" 
              Source="$($SourcePath)\osquery-queries.json" />
      </Component>
      
      <!-- Registry entries -->
      <Component Id="RegistryEntries" Guid="*">
        <RegistryKey Root="HKLM" Key="SOFTWARE\ReportMate">
          <RegistryValue Name="InstallPath" 
                         Type="string" 
                         Value="[INSTALLFOLDER]" 
                         KeyPath="yes" />
          <RegistryValue Name="Version" 
                         Type="string" 
                         Value="$Version" />
          <RegistryValue Name="InstallDate" 
                         Type="string" 
                         Value="[Date]" />
        </RegistryKey>
      </Component>
      
      <!-- Logs directory -->
      <Component Id="LogsDirectory" Guid="*" Directory="AppDataLogsFolder">
        <CreateFolder />
        <RemoveFolder Id="RemoveAppDataLogsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" 
                       Key="SOFTWARE\ReportMate" 
                       Name="LogsPath" 
                       Type="string" 
                       Value="[AppDataLogsFolder]" 
                       KeyPath="yes" />
      </Component>
      
      <!-- Start menu shortcut -->
      <Component Id="StartMenuShortcut" Guid="*" Directory="ApplicationProgramsFolder">
        <Shortcut Id="ReportMateShortcut"
                  Name="ReportMate Client"
                  Description="ReportMate Windows Client"
                  Target="[INSTALLFOLDER]runner.exe"
                  Arguments="info"
                  WorkingDirectory="INSTALLFOLDER" />
        <RemoveFolder Id="RemoveApplicationProgramsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" 
                       Key="SOFTWARE\ReportMate" 
                       Name="StartMenuShortcut" 
                       Type="integer" 
                       Value="1" 
                       KeyPath="yes" />
      </Component>
      
    </ComponentGroup>
  </Fragment>
  
</Wix>
"@

$WixFile = Join-Path $OutputPath "ReportMate.wxs"
$WixSource | Out-File -FilePath $WixFile -Encoding UTF8

Write-Green "✅ WiX source generated: $WixFile"

# Compile the installer
Write-Yellow "🔨 Compiling MSI installer..."

$WixObj = Join-Path $OutputPath "ReportMate.wixobj"
$MsiFile = Join-Path $OutputPath "ReportMate-WindowsClient-$Version.msi"

try {
    # Compile WiX source
    & candle.exe -out $WixObj $WixFile
    if ($LASTEXITCODE -ne 0) {
        throw "Candle compilation failed"
    }
    
    # Link to create MSI
    & light.exe -out $MsiFile $WixObj -ext WixUIExtension
    if ($LASTEXITCODE -ne 0) {
        throw "Light linking failed"
    }
    
    Write-Green "✅ MSI installer created successfully!"
    
} catch {
    Write-Red "❌ Installer compilation failed: $_"
    exit 1
}

# Sign the installer (if not skipped)
if (-not $SkipSigning) {
    Write-Yellow "🔏 Signing installer..."
    Write-Output "Note: Code signing requires a valid certificate. Skipping for now."
    Write-Output "For production deployment, use: signtool sign /f certificate.pfx /p password $MsiFile"
}

# Create silent installation script
Write-Yellow "📝 Creating deployment scripts..."

$SilentInstallScript = @"
@echo off
REM ReportMate Windows Client Silent Installation Script
REM For use with Group Policy or Configuration Manager

echo Installing ReportMate Windows Client...

REM Install silently with logging
msiexec /i "ReportMate-WindowsClient-VERSION_PLACEHOLDER.msi" /quiet /l*v "%TEMP%\ReportMate-Install.log"

if %ERRORLEVEL% EQU 0 (
    echo Installation completed successfully
    echo Log file: %TEMP%\ReportMate-Install.log
) else (
    echo Installation failed with error code %ERRORLEVEL%
    echo Check log file: %TEMP%\ReportMate-Install.log
    exit /b %ERRORLEVEL%
)

REM Configure API URL if provided
if not "%REPORTMATE_API_URL%"=="" (
    echo Configuring API URL...
    "C:\Program Files\ReportMate\runner.exe" install --api-url "%REPORTMATE_API_URL%"
)

echo ReportMate Windows Client installation completed
"@

# Replace the placeholder with the actual version
$SilentInstallScript = $SilentInstallScript -replace "VERSION_PLACEHOLDER", $Version

$SilentInstallScript | Out-File -FilePath (Join-Path $OutputPath "install-silent.bat") -Encoding ASCII

# Create uninstallation script
$UninstallScript = @"
@echo off
REM ReportMate Windows Client Uninstallation Script

echo Uninstalling ReportMate Windows Client...

REM Get product code from registry
for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "ReportMate Windows Client" /k 2^>nul ^| find "HKEY_LOCAL_MACHINE"') do (
    set PRODUCT_CODE=%%b
    goto :found
)

:found
if not "%PRODUCT_CODE%"=="" (
    echo Found product code: %PRODUCT_CODE%
    msiexec /x "%PRODUCT_CODE%" /quiet /l*v "%TEMP%\ReportMate-Uninstall.log"
    echo Uninstallation completed
) else (
    echo ReportMate Windows Client not found in registry
)
"@

$UninstallScript | Out-File -FilePath (Join-Path $OutputPath "uninstall.bat") -Encoding ASCII

# Create PowerShell deployment script
$PowerShellScript = @"
# ReportMate Windows Client PowerShell Deployment Script
# For use with PowerShell DSC or remote execution

param(
    [string]$ApiUrl = "",
    [switch]$Uninstall = `$false
)

if (`$Uninstall) {
    Write-Host "Uninstalling ReportMate Windows Client..."
    
    # Find and uninstall existing version
    `$app = Get-WmiObject -Class Win32_Product | Where-Object { `$_.Name -like "*ReportMate*" }
    if (`$app) {
        `$app.Uninstall()
        Write-Host "Uninstallation completed"
    } else {
        Write-Host "ReportMate Windows Client not found"
    }
} else {
    Write-Host "Installing ReportMate Windows Client..."
    
    # Install MSI
    `$msiPath = Join-Path `$PSScriptRoot "ReportMate-WindowsClient-VERSION_PLACEHOLDER.msi"
    `$logPath = Join-Path `$env:TEMP "ReportMate-Install.log"
    
    `$process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`$msiPath", "/quiet", "/l*v", "`$logPath" -Wait -PassThru
    
    if (`$process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully"
        
        # Configure API URL if provided
        if (`$ApiUrl) {
            Write-Host "Configuring API URL: `$ApiUrl"
            & "C:\Program Files\ReportMate\runner.exe" install --api-url "`$ApiUrl"
        }
        
        # Test installation
        & "C:\Program Files\ReportMate\runner.exe" test
        
    } else {
        Write-Error "Installation failed with exit code: `$(`$process.ExitCode)"
        Write-Host "Check log file: `$logPath"
    }
}
"@

$PowerShellScript | Out-File -FilePath (Join-Path $OutputPath "Deploy-ReportMate.ps1") -Encoding UTF8

# Replace version placeholders in the generated scripts
$deployScriptPath = Join-Path $OutputPath "Deploy-ReportMate.ps1"
$deployContent = Get-Content $deployScriptPath -Raw
$deployContent = $deployContent -replace "VERSION_PLACEHOLDER", $Version
$deployContent | Out-File -FilePath $deployScriptPath -Encoding UTF8

# Display summary
Write-Output ""
Write-Green "🎉 Installer Creation Complete!"
Write-Output "==============================="
Write-Output "MSI Package: $MsiFile"
Write-Output "Size: $((Get-Item $MsiFile).Length / 1MB | ForEach-Object { [math]::Round($_, 2) }) MB"
Write-Output ""
Write-Blue "📦 Deployment Files Created:"
Write-Output "• $((Get-Item $MsiFile).Name) - MSI installer package"
Write-Output "• install-silent.bat - Silent installation script"
Write-Output "• uninstall.bat - Uninstallation script"
Write-Output "• Deploy-ReportMate.ps1 - PowerShell deployment script"
Write-Output ""
Write-Blue "📖 Next Steps:"
Write-Output "1. Test the installer on a clean Windows machine"
Write-Output "2. Sign the MSI for production deployment"
Write-Output "3. Deploy via Group Policy, SCCM, or Intune"
Write-Output "4. Configure Cimian postflight scripts"
Write-Output ""
Write-Green "✨ Ready for deployment!"
