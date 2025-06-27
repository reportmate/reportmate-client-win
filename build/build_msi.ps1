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

Write-Green "[CREATING] ReportMate Windows Client Installer"
Write-Output "================================================"

# Check prerequisites
Write-Yellow "[CHECKING] Prerequisites..."

# Check if WiX is installed
if (-not (Get-Command "candle.exe" -ErrorAction SilentlyContinue)) {
    Write-Red "[ERROR] WiX Toolset not found. Please install WiX Toolset v3.11 or later"
    Write-Output "Download from: https://wixtoolset.org/releases/"
    exit 1
}

Write-Green "[OK] WiX Toolset found"

# Check source files
if (-not (Test-Path $SourcePath)) {
    Write-Red "[ERROR] Source path not found: $SourcePath"
    Write-Output "Please run build.sh first to create the publish directory"
    exit 1
}

$ExePath = Join-Path $SourcePath "runner.exe"
if (-not (Test-Path $ExePath)) {
    Write-Red "[ERROR] runner.exe not found in source path"
    exit 1
}

Write-Green "[OK] Source files found"

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Generate WiX source file
Write-Yellow "[CREATING] Generating WiX installer source..."

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

Write-Green "[OK] WiX source generated: $WixFile"

# Compile the installer
Write-Yellow "[COMPILING] Compiling MSI installer..."

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
    
    Write-Green "[OK] MSI installer created successfully!"
    
} catch {
    Write-Red "[ERROR] Installer compilation failed: $_"
    exit 1
}

# Sign the installer (if not skipped)
if (-not $SkipSigning) {
    Write-Yellow "[SIGNING] Signing installer..."
    Write-Output "Note: Code signing requires a valid certificate. Skipping for now."
    Write-Output "For production deployment, use: signtool sign /f certificate.pfx /p password $MsiFile"
}

# Create silent installation script
Write-Yellow "[CREATING] Creating deployment scripts..."

# Build the silent install script content using string concatenation instead of here-strings
$SilentInstallScript = "@echo off`r`n"
$SilentInstallScript += "REM ReportMate Windows Client Silent Installation Script`r`n"
$SilentInstallScript += "REM For use with Group Policy or Configuration Manager`r`n"
$SilentInstallScript += "`r`n"
$SilentInstallScript += "echo Installing ReportMate Windows Client...`r`n"
$SilentInstallScript += "`r`n"
$SilentInstallScript += "REM Install silently with logging`r`n"
$SilentInstallScript += "msiexec /i `"ReportMate-WindowsClient-$Version.msi`" /quiet /l*v `"%TEMP%\ReportMate-Install.log`"`r`n"
$SilentInstallScript += "`r`n"
$SilentInstallScript += "if %ERRORLEVEL% EQU 0 (`r`n"
$SilentInstallScript += "    echo Installation completed successfully`r`n"
$SilentInstallScript += "    echo Log file: %TEMP%\ReportMate-Install.log`r`n"
$SilentInstallScript += ") else (`r`n"
$SilentInstallScript += "    echo Installation failed with error code %ERRORLEVEL%`r`n"
$SilentInstallScript += "    echo Check log file: %TEMP%\ReportMate-Install.log`r`n"
$SilentInstallScript += "    exit /b %ERRORLEVEL%`r`n"
$SilentInstallScript += ")`r`n"
$SilentInstallScript += "`r`n"
$SilentInstallScript += "REM Configure API URL if provided`r`n"
$SilentInstallScript += "if not `"%REPORTMATE_API_URL%`"==`"`" (`r`n"
$SilentInstallScript += "    echo Configuring API URL...`r`n"
$SilentInstallScript += "    `"C:\Program Files\ReportMate\runner.exe`" install --api-url `"%REPORTMATE_API_URL%`"`r`n"
$SilentInstallScript += ")`r`n"
$SilentInstallScript += "`r`n"
$SilentInstallScript += "echo ReportMate Windows Client installation completed`r`n"

# Replace the placeholder with the actual version
$SilentInstallScript = $SilentInstallScript -replace "VERSION_PLACEHOLDER", $Version

$SilentInstallScript | Out-File -FilePath (Join-Path $OutputPath "install-silent.bat") -Encoding ASCII

# Create uninstallation script
# Build the uninstall script content using string concatenation instead of here-strings
$UninstallScript = "@echo off`r`n"
$UninstallScript += "REM ReportMate Windows Client Uninstallation Script`r`n"
$UninstallScript += "`r`n"
$UninstallScript += "echo Uninstalling ReportMate Windows Client...`r`n"
$UninstallScript += "`r`n"
$UninstallScript += "REM Get product code from registry`r`n"
$UninstallScript += "for /f `"tokens=2*`" %%a in ('reg query `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`" /s /f `"ReportMate Windows Client`" /k 2^>nul ^| find `"HKEY_LOCAL_MACHINE`"') do (`r`n"
$UninstallScript += "    set PRODUCT_CODE=%%b`r`n"
$UninstallScript += "    goto :found`r`n"
$UninstallScript += ")`r`n"
$UninstallScript += "`r`n"
$UninstallScript += ":found`r`n"
$UninstallScript += "if not `"%PRODUCT_CODE%`"==`"`" (`r`n"
$UninstallScript += "    echo Found product code: %PRODUCT_CODE%`r`n"
$UninstallScript += "    msiexec /x `"%PRODUCT_CODE%`" /quiet /l*v `"%TEMP%\ReportMate-Uninstall.log`"`r`n"
$UninstallScript += "    echo Uninstallation completed`r`n"
$UninstallScript += ") else (`r`n"
$UninstallScript += "    echo ReportMate Windows Client not found in registry`r`n"
$UninstallScript += ")`r`n"

$UninstallScript | Out-File -FilePath (Join-Path $OutputPath "uninstall.bat") -Encoding ASCII

# Create PowerShell deployment script
# Build the PowerShell script content using single quotes and careful escaping
$PowerShellScript = '# ReportMate Windows Client PowerShell Deployment Script' + "`r`n"
$PowerShellScript += '# For use with PowerShell DSC or remote execution' + "`r`n"
$PowerShellScript += "`r`n"
$PowerShellScript += 'param(' + "`r`n"
$PowerShellScript += '    [string]$ApiUrl = "",' + "`r`n"
$PowerShellScript += '    [switch]$Uninstall = $false' + "`r`n"
$PowerShellScript += ')' + "`r`n"
$PowerShellScript += "`r`n"
$PowerShellScript += 'if ($Uninstall) {' + "`r`n"
$PowerShellScript += '    Write-Host "Uninstalling ReportMate Windows Client..."' + "`r`n"
$PowerShellScript += '    ' + "`r`n"
$PowerShellScript += '    # Find and uninstall existing version' + "`r`n"
$PowerShellScript += '    $app = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*ReportMate*" }' + "`r`n"
$PowerShellScript += '    if ($app) {' + "`r`n"
$PowerShellScript += '        $app.Uninstall()' + "`r`n"
$PowerShellScript += '        Write-Host "Uninstallation completed"' + "`r`n"
$PowerShellScript += '    } else {' + "`r`n"
$PowerShellScript += '        Write-Host "ReportMate Windows Client not found"' + "`r`n"
$PowerShellScript += '    }' + "`r`n"
$PowerShellScript += '} else {' + "`r`n"
$PowerShellScript += '    Write-Host "Installing ReportMate Windows Client..."' + "`r`n"
$PowerShellScript += '    ' + "`r`n"
$PowerShellScript += '    # Install MSI' + "`r`n"
$PowerShellScript += '    $msiPath = Join-Path $PSScriptRoot "ReportMate-WindowsClient-' + $Version + '.msi"' + "`r`n"
$PowerShellScript += '    $logPath = Join-Path $env:TEMP "ReportMate-Install.log"' + "`r`n"
$PowerShellScript += '    ' + "`r`n"
$PowerShellScript += '    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "$msiPath", "/quiet", "/l*v", "$logPath" -Wait -PassThru' + "`r`n"
$PowerShellScript += '    ' + "`r`n"
$PowerShellScript += '    if ($process.ExitCode -eq 0) {' + "`r`n"
$PowerShellScript += '        Write-Host "Installation completed successfully"' + "`r`n"
$PowerShellScript += '        ' + "`r`n"
$PowerShellScript += '        # Configure API URL if provided' + "`r`n"
$PowerShellScript += '        if ($ApiUrl) {' + "`r`n"
$PowerShellScript += '            Write-Host "Configuring API URL: $ApiUrl"' + "`r`n"
$PowerShellScript += '            & "C:\Program Files\ReportMate\runner.exe" install --api-url "$ApiUrl"' + "`r`n"
$PowerShellScript += '        }' + "`r`n"
$PowerShellScript += '        ' + "`r`n"
$PowerShellScript += '        # Test installation' + "`r`n"
$PowerShellScript += '        & "C:\Program Files\ReportMate\runner.exe" test' + "`r`n"
$PowerShellScript += '        ' + "`r`n"
$PowerShellScript += '    } else {' + "`r`n"
$PowerShellScript += '        Write-Error "Installation failed with exit code: $($process.ExitCode)"' + "`r`n"
$PowerShellScript += '        Write-Host "Check log file: $logPath"' + "`r`n"
$PowerShellScript += '    }' + "`r`n"
$PowerShellScript += '}' + "`r`n"

$PowerShellScript | Out-File -FilePath (Join-Path $OutputPath "Deploy-ReportMate.ps1") -Encoding UTF8

# Replace version placeholders in the generated scripts
$deployScriptPath = Join-Path $OutputPath "Deploy-ReportMate.ps1"
$deployContent = Get-Content $deployScriptPath -Raw
$deployContent = $deployContent -replace "VERSION_PLACEHOLDER", $Version
$deployContent | Out-File -FilePath $deployScriptPath -Encoding UTF8

# Display summary
Write-Output ""
Write-Green "[COMPLETE] Installer Creation Complete!"
Write-Output "==============================="
Write-Output "MSI Package: $MsiFile"
Write-Output "Size: $((Get-Item $MsiFile).Length / 1MB | ForEach-Object { [math]::Round($_, 2) }) MB"
Write-Output ""
Write-Blue "[FILES] Deployment Files Created:"
Write-Output "- $((Get-Item $MsiFile).Name) - MSI installer package"
Write-Output "- install-silent.bat - Silent installation script"
Write-Output "- uninstall.bat - Uninstallation script"
Write-Output "- Deploy-ReportMate.ps1 - PowerShell deployment script"
Write-Output ""
Write-Blue "[NEXT] Next Steps:"
Write-Output "1. Test the installer on a clean Windows machine"
Write-Output "2. Sign the MSI for production deployment"
Write-Output "3. Deploy via Group Policy, SCCM, or Intune"
Write-Output "4. Configure Cimian postflight scripts"
Write-Output ""
Write-Green "[READY] Ready for deployment!"
