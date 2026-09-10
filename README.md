# ReportMate Windows Client

ReportMate Client side Windows installer for gathering endpoint telemetry for monitoring dashboard using `osquery`.

Written in C# .NET 8. Designed to run on its own or as a postflight script after Cimian's managed software update process. It collects detailed device information using `osquery` and securely transmits it to the ReportMate API.

## Quick Start

### Building ReportMate

The project includes a unified PowerShell 7 build script that handles all package types:

```powershell
# Simple build with auto-generated date version
.\build.ps1 -Sign

# Build specific version
.\build.ps1 -Version "2024.06.27" -Sign

# Clean build for release
.\build.ps1 -Clean -Version "2024.06.27" -ApiUrl "https://api.reportmate.com" -Sign
```

**📋 Prerequisites:**
- PowerShell 7+ ([Download](https://github.com/PowerShell/PowerShell/releases))
- .NET 8.0 SDK ([Download](https://dotnet.microsoft.com/download))
- WiX Toolset v3.11 for MSI creation ([Download](https://wixtoolset.org/releases/))

**📦 Output:** Three deployment packages in `build/output/`
- `ReportMate-{version}.msi` - Enterprise MSI installer
- `ReportMate-{version}.nupkg` - Chocolatey/Cimian package  
- `ReportMate-{version}.zip` - Manual installation archive

See [BUILD.md](BUILD.md) for detailed build instructions and troubleshooting.

## Directory Structure

The project uses a unified package structure that supports all deployment formats:

```
reportmate-client-win/
├── src/                    # C# source code
├── build/                  # Build outputs and legacy scripts
│   ├── output/            # Generated packages (MSI, NUPKG, ZIP)
│   ├── publish/           # .NET publish output
│   └── legacy/            # Legacy build scripts (deprecated)
├── build.ps1              # 🚀 Unified build script (PowerShell 7)
├── BUILD.md               # Detailed build documentation
├── nupkg/                 # Package structure (populated by build)
│   ├── build-info.yaml   # Package metadata
│   ├── payload/
│   │   ├── Program Files/
│   │   │   ├── Cimian/
│   │   │   │   └── postflight.ps1     # Cimian integration
│   │   │   └── ReportMate/
│   │   │       ├── managedreportsrunner.exe         # Main executable
│   │   │       └── version.txt        # Build info
│   │   └── ProgramData/
│   │       └── ManagedReports/
│   │           ├── appsettings.yaml   # Working config
│   │           ├── appsettings.template.yaml  # Enterprise template
│   │           └── queries.json       # OSQuery definitions
│   └── scripts/
│       ├── preinstall.ps1   # Pre-installation script
│       └── postinstall.ps1  # Post-installation script
└── .github/workflows/       # CI/CD automation
```

## Installation Locations

After deployment, files are organized following Windows conventions:

### Binaries (`C:\Program Files\ReportMate\`)

- `managedreportsrunner.exe` - Main ReportMate executable
- `version.txt` - Build and version information

### Working Data (`C:\ProgramData\ManagedReports\`)

- `appsettings.yaml` - Active configuration file (editable)
- `appsettings.template.yaml` - Enterprise template configuration (CSP/OMA-URI manageable)
- `osquery/` - Modular osquery configuration directory
  - `enabled-modules.json` - Module configuration
  - `modules/` - Individual module query files
    - `hardware.json` - Hardware detection queries
    - `system.json` - OS and system queries
    - `network.json` - Network configuration queries
    - `security.json` - Security feature queries
    - `applications.json` - Software inventory queries
    - `inventory.json` - Device identification queries
- Cache and log files (created at runtime)

### Cimian Integration (`C:\Program Files\Cimian\`)

- `postflight.ps1` - Executed by Cimian after software updates

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         ReportMate                             │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │   Program   │ │Configuration│ │ Data        │ │   osquery   │ │
│ │   Main      │ │  Service    │ │ Collection  │ │   Service   │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │    API      │ │ Device Info │ │  Registry   │ │   Logging   │ │
│ │  Service    │ │   Service   │ │ Provider    │ │  & Events   │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Cimian Integration                           │
├─────────────────────────────────────────────────────────────────┤
│  managedsoftwareupdate.exe → postflight.ps1 → managedreportsrunner.exe       │
│                                                                 │
│  Postflight runs the collector; the GUI app reads its cache     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Data Collection                             │
├─────────────────────────────────────────────────────────────────┤
│ • System Information (WMI + osquery)                           │
│ • Security Status (Defender, Firewall, BitLocker)              │
│ • Hardware Inventory (CPU, Memory, Disks)                      │
│ • Software Inventory (Programs, Services, Patches)             │
│ • Network Configuration                                         │
│ • Event Logs & Security Events                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   ReportMate API (Azure)                       │
├─────────────────────────────────────────────────────────────────┤
│ • Secure HTTPS transmission                                     │
│ • Authentication & authorization                                │
│ • Real-time dashboard updates                                   │
│ • Data storage & analytics                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration Management

The application uses a configuration hierarchy to support enterprise deployment and management:

1. **Windows Registry** (`HKLM\SOFTWARE\Config\ReportMate`) - CSP/MDM configuration managed (highest precedence)
2. **Environment Variables** (prefix: `REPORTMATE_`) - Container/deployment specific
3. **Working Configuration** (`ProgramData/ManagedReports/appsettings.yaml`) - Runtime editable
4. **Enterprise Template Configuration** (`ProgramData/ManagedReports/appsettings.template.yaml`) - CSP/OMA-URI manageable defaults
5. **Application Defaults** (Embedded in binary) - Fallback values

Higher priority sources override lower priority ones, allowing flexible deployment and customization.

### Enterprise Deployment with CSP/OMA-URI

For enterprise environments, configuration can be managed through:

- **Configuration Service Provider (CSP)**: Deploy `appsettings.template.yaml` to `ProgramData/ManagedReports/`
- **MDM configuration**: Set registry values under `HKLM\SOFTWARE\ReportMate`
- **OMA-URI**: Push configuration files and registry settings remotely

All configuration files are stored in `ProgramData` (not `Program Files`) to ensure they are accessible by CSP and MDM configuration management tools.

#### Example Complete Configuration

**Intune Custom Configuration Profile (XML):**
```xml
<!-- Intune Custom Configuration Profile -->
<OMASettings>
  <OMADevice>
    <OMAApplicationData>
      <Name>ReportMate Client Configuration</Name>
      <OMAConfigurationData>
        <Item>
          <Target>./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiUrl</Target>
          <Data>https://api.reportmate.contoso.com</Data>
        </Item>
        <Item>
          <Target>./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/Passphrase</Target>
          <Data>your-secure-passphrase</Data>
        </Item>
        <Item>
          <Target>./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/CollectionInterval</Target>
          <Data>3600</Data>
        </Item>
        <Item>
          <Target>./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/LogLevel</Target>
          <Data>Information</Data>
        </Item>
      </OMAConfigurationData>
    </OMAApplicationData>
  </OMADevice>
</OMASettings>
```

#### Troubleshooting Enterprise Configuration

**Common Issues:**

1. **Registry Access Denied**: Ensure the profile is applied to computer configuration, not user configuration
2. **Configuration Not Applied**: Check that the device is receiving and processing the policy
3. **Invalid API URL**: Ensure the URL includes the protocol (https://) and is accessible from the client

**Validation Steps:**

1. Verify registry values are created correctly
2. Test API connectivity: `managedreportsrunner.exe test`
3. Check Windows Event Log for ReportMate entries
4. Review configuration hierarchy: `managedreportsrunner.exe info`

## Building and Deployment

### Development Workflow

1. **Source Code**: All C# source files in `src/`
2. **Build**: Run `./build/build_exe.sh` to compile and populate `nupkg/payload/`
3. **Package**: Use PowerShell scripts to create MSI, NUPKG, or ZIP formats
4. **Deploy**: All formats install to the same standardized Windows locations

### Build Scripts

```bash
# Cross-platform build (macOS/Linux/Windows)
./build/build_exe.sh

# Windows-specific package creation
.\build\build_nupkg.ps1 -Version "1.0.0"
.\build\build_msi.ps1 -Version "1.0.0"
```

### Automated CI/CD

The project includes GitHub Actions workflows that:
- Build all package formats on every tag push
- Run automated tests and validation
- Create GitHub releases with downloadable artifacts
- Support semantic versioning (e.g., `v1.0.0`)

### Manual Deployment Options

#### MSI Installation (Recommended)
```powershell
# Silent installation for enterprise deployment
msiexec /i ReportMateClient.msi /quiet API_URL="https://api.reportmate.com"
```

#### Cimian/Chocolatey Package

```powershell
choco install reportmate-windows-client.nupkg
```

#### Direct Executable

```powershell
# Manual installation and setup
.\managedreportsrunner.exe install --api-url "https://api.reportmate.com"
.\managedreportsrunner.exe run
```

## Key Features

### Core Functionality

- **osquery Integration**: Leverages osquery for comprehensive system data collection
- **Cimian Integration**: Postflight script execution after each managed software run
- **Managed Reports Runner app**: A native WPF app that renders this device's report from the local cache, tab for tab with the web device page, and runs collections, tails logs and edits settings
- **Secure Communication**: HTTPS with proper certificate validation
- **Configuration Management**: Multi-source configuration with Windows Registry support
- **Error Handling**: Robust retry logic and comprehensive logging
- **Performance Optimization**: Efficient data collection with caching
- **Application Usage Analytics**: Tracks launch counts and session durations using Windows kernel process telemetry

### Security Features

- **Privilege Management**: Runs with appropriate administrator privileges
- **Secure Storage**: No hardcoded credentials, uses Windows registry securely
- **Data Encryption**: All API communications encrypted in transit
- **Certificate Validation**: Proper SSL/TLS certificate verification
- **Access Control**: Managed identity integration ready

### Enterprise Ready

- **MSI Installer**: Professional Windows Installer package
- **MDM configuration Support**: Silent installation and configuration
- **Logging & Monitoring**: Comprehensive Windows Event Log integration
- **Configuration Management**: Multiple configuration sources (Registry, JSON, Environment)
- **Deployment Scripts**: Batch, PowerShell, and silent installation options

## Managed Reports Runner (GUI)

`Managed Reports Runner.exe` is a native Windows app installed next to the runner. It reads the newest per-module JSON the runner writes under `C:\ProgramData\ManagedReports\cache\` and renders the same device page the ReportMate web app shows, with no network access needed:

- **Device**: the device header (name, asset tag, serial, IP, collection age) and eleven tabs mirroring the web device page: Info, Installs, Applications, System, Management, Identity, Hardware, Peripherals, Security, Network and Events.
- **Run**: launches `managedreportsrunner.exe` elevated for all or selected modules and streams its log; the Device tab refreshes when the run finishes.
- **Logs**: browses and filters the runner's log files.
- **Settings**: edits the registry-backed configuration, with policy-managed keys shown locked.

The app compiles the client's own payload models, so it deserialises the cache with the classes that wrote it. It is built and packaged by `build.ps1` alongside the runner.

## Command Line Interface

```powershell
# Run data collection (default action)
managedreportsrunner.exe run [--force] [--device-id ID] [--api-url URL]

# Test configuration and connectivity  
managedreportsrunner.exe test [--verbose]

# Display system information
managedreportsrunner.exe info

# Install and configure
managedreportsrunner.exe install --api-url URL [--device-id ID] [--api-key KEY]
```

## Requirements

### Runtime Requirements
- Windows 10/11 or Windows Server 2016+
- .NET 8.0 Runtime (included in self-contained builds)
- Administrator privileges (for full data collection)
- Network connectivity to ReportMate API

### Build Requirements
- .NET 8.0 SDK
- PowerShell 5.1+ (for Windows build scripts)
- WiX Toolset 3.11+ (for MSI creation)
- cimipkg (for NUPKG creation) - [Download here](https://github.com/windowsadmins/cimian-pkg/releases)

### Optional Dependencies
- osquery (for enhanced data collection) - Automatically detected at `C:\Program Files\osquery\`

## Integration Examples

### Cimian Postflight Script
The included `postflight.ps1` script automatically executes ReportMate after Cimian runs `managedsoftwareupdate.exe`:

```powershell
# Located at: C:\Program Files\Cimian\postflight.ps1
& "C:\Program Files\ReportMate\managedreportsrunner.exe" run --force
```

### Deploy via startup script or scheduled task

```powershell
schtasks /create /tn "ReportMate Data Collection" /tr "C:\Program Files\ReportMate\managedreportsrunner.exe run" /sc daily /st 09:00
```

### Manual Integration

```powershell
# Run from any automation system
C:\Program Files\ReportMate\managedreportsrunner.exe run
```

The `nupkg/` directory serves as the canonical package structure that all build processes populate and reference.

### Windows Structure

#### Executables (Program Files)

```pwsh
C:\Program Files\ReportMate\
├── managedreportsrunner.exe                    # Main ReportMate executable
├── appsettings.yaml              # Default configuration template
├── osquery-queries.json          # osquery query definitions
└── version.txt                   # Version information
```

#### Data & Configuration (ProgramData)

```pwsh
C:\ProgramData\ManagedReports\
├── config\                       # Configuration files
│   ├── reportmate.yaml           # Main configuration
│   └── registry.config           # Registry-based settings
├── logs\                         # Log files
│   ├── reportmate.log            # Main application log
│   ├── postflight.log            # Postflight script log
│   ├── error.log                 # Error log
│   └── osquery.log               # osquery execution log
├── cache\                        # Temporary cache files
│   ├── device-info.json         # Cached device information
│   └── last-run.timestamp        # Last execution timestamp
└── data\                         # Persistent data storage
    ├── device-id.txt             # Device identifier
    └── api-keys.encrypted        # Encrypted API credentials
```

### Configuration Priority

ReportMate uses the following configuration priority (highest to lowest):

1. **Command-line arguments** (`--api-url`, `--device-id`, etc.)
2. **Environment variables** (`REPORTMATE_API_URL`, `REPORTMATE_DEVICE_ID`, etc.)
3. **Registry values** (Windows) / **YAML Preferences** (macOS)
4. **YAML configuration files** in data directory
5. **Default YAML configuration** in program directory

## Package Formats

ReportMate supports three deployment formats, all built from the same unified source structure:

### 1. NUPKG Package (Recommended)

- **Use Case**: Chocolatey and Cimian deployment
- **Benefits**: Automatic dependency management, uninstall support, integration with existing package managers
- **Installation**: `choco install ReportMate` or `cimipkg install`

### 2. MSI Installer  

- **Use Case**: Traditional Windows enterprise deployment (MDM configuration, SCCM, Intune)
- **Benefits**: Windows Installer features, proper Add/Remove Programs integration, silent installation
- **Installation**: `msiexec /i ReportMate-1.0.0.msi /quiet`

### 3. ZIP Archive

- **Use Case**: Manual deployment, custom automation scripts
- **Benefits**: Simple extraction, complete control over installation process
- **Installation**: Manual extraction and configuration

### Package Structure

All packages deploy to the same standardized locations:

```
C:\Program Files\ReportMate\          # Binaries and executable files
├── managedreportsrunner.exe                       # Main ReportMate executable
├── appsettings.yaml                  # Template configuration
└── version.txt                      # Build version information

C:\ProgramData\ManagedReports\        # Working data and configuration
├── appsettings.yaml                  # Active configuration file
└── queries.json                     # OSQuery definitions

C:\Program Files\Cimian\              # Cimian integration
└── postflight.ps1                   # Postflight execution script
```

### Build Requirements

- **.NET 8.0 SDK** - For building the executable
- **PowerShell 7+** - For cross-platform build scripts (recommended)
- **WiX Toolset 3.11+** - For MSI creation (Windows only)
- **cimipkg** - For NUPKG creation ([Download here](https://github.com/windowsadmins/cimian-pkg/releases))

### Environment Variables for Build

The build and installation scripts recognize these environment variables:

- `REPORTMATE_API_URL` - Sets the default API endpoint
- `REPORTMATE_DEVICE_ID` - Sets custom device identifier
- `REPORTMATE_API_KEY` - Sets API authentication key

Example:
```bash
export REPORTMATE_API_URL="https://your-reportmate-api.azurewebsites.net"
./build/build_exe.sh
```

## Installation & Deployment

### Prerequisites

- Windows 7 or later (Windows 10+ recommended)
- .NET 8.0 Runtime (included in self-contained build)
- Administrator privileges for installation
- osquery (optional but recommended for full functionality)

### Quick Deployment Steps

#### Step 1: Build the Application

```bash
# Navigate to the Windows client directory
cd reportmate-client-win

# Build the executable using the unified build script
./build/build_exe.sh
```

This creates:
- Self-contained executable at `build/publish/managedreportsrunner.exe`
- Properly structured nupkg payload at `nupkg/payload/`
- ZIP deployment package at `build/output/`

#### Step 2: Create Installers

**Automated Build with GitHub Actions**

Push a version tag to automatically build MSI, NUPKG, and ZIP packages:

```bash
git tag v1.0.0
git push origin v1.0.0
```

**Local Build (All Formats)**

```bash
# Build executable and prepare nupkg structure
./build/build_exe.sh

# Create MSI and NUPKG packages (Windows with PowerShell)
pwsh ./build/build_nupkg.ps1 -Version "1.0.0"
```

**MSI Only (Legacy)**

```powershell
# Run on Windows machine with WiX Toolset installed
.\build\build_msi.ps1 -Version "1.0.0" -SourcePath "nupkg/payload" -OutputPath "build/output"
```

This creates:
- `ReportMate-1.0.0.msi` - Traditional Windows installer
- `ReportMate-1.0.0.nupkg` - Chocolatey/Cimian compatible package  
- `ReportMate-1.0.0.zip` - Manual installation archive

#### Step 3: Deploy to Target Machines

**Option A: MDM configuration Deployment**

1. Copy MSI to network share
2. Create MDM configuration Object
3. Assign software installation to computer objects
4. Configure registry settings via GPO

**Option B: SCCM/Intune Deployment**

1. Import MSI into SCCM/Intune

2. Create application with silent install command:

`msiexec /i "ReportMate-1.0.0.msi" /quiet /l*v "%TEMP%\reportmate-install.log"`

3. Deploy to device collections

**Option C: Manual/Script Deployment**

```pwsh
# Copy and run deployment script
.\Deploy-ReportMate.ps1 -ApiUrl "https://your-reportmate-api.azurewebsites.net"
```

### Installation Methods

#### 1. NUPKG Package (Recommended for Cimian)

```powershell
# Install via Chocolatey/Cimian
choco install ReportMate --source="path\to\package"

# Or install with cimipkg directly
cimipkg install ReportMate-1.0.0.nupkg
```

#### 2. MSI Installer

```powershell
# Download and install
Invoke-WebRequest -Uri "https://releases.reportmate.io/ReportMate-1.0.0.msi" -OutFile "reportmate.msi"
msiexec /i reportmate.msi /quiet /l*v install.log

# Configure
Set-ItemProperty -Path "HKLM:\SOFTWARE\ReportMate" -Name "ApiUrl" -Value "https://your-api.azurewebsites.net"
```

#### 3. Manual Installation

```powershell
# Extract ZIP to correct locations
Expand-Archive "ReportMate-1.0.0.zip" -DestinationPath "C:\Temp\ReportMate"

# Copy binaries to Program Files
Copy-Item "C:\Temp\ReportMate\Program Files\ReportMate\*" "C:\Program Files\ReportMate\" -Recurse -Force

# Copy working files to ProgramData  
Copy-Item "C:\Temp\ReportMate\ProgramData\ManagedReports\*" "C:\ProgramData\ManagedReports\" -Recurse -Force

# Copy Cimian integration
Copy-Item "C:\Temp\ReportMate\Program Files\Cimian\*" "C:\Program Files\Cimian\" -Recurse -Force

# Run post-installation configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\ReportMate" -Name "ApiUrl" -Value "https://your-api.azurewebsites.net"
```

#### 2. Silent Deployment

```batch
@echo off
REM MDM configuration or SCCM deployment
msiexec /i "ReportMate-1.0.0.msi" /quiet /l*v "%TEMP%\reportmate-install.log"
"C:\Program Files\ReportMate\managedreportsrunner.exe" install --api-url "https://your-api.azurewebsites.net"
```

#### 3. PowerShell DSC

```pwsh
Configuration ReportMateClient {
    Node "localhost" {
        Package ReportMate {
            Name = "ReportMate"
            Path = "\\server\share\ReportMate-1.0.0.msi"
            ProductId = "{12345678-1234-1234-1234-123456789012}"
            Ensure = "Present"
        }
        
        Registry ReportMateApiUrl {
            Key = "HKLM:\SOFTWARE\ReportMate"
            ValueName = "ApiUrl"
            ValueData = "https://your-api.azurewebsites.net"
            ValueType = "String"
            Ensure = "Present"
            DependsOn = "[Package]ReportMate"
        }
    }
}
```

## Configuration

### Registry Settings

All configuration is stored in `HKLM:\SOFTWARE\ReportMate`:

| Setting | Description | Default |
|---------|-------------|---------|
| `ApiUrl` | ReportMate API endpoint | *Required* |
| `DeviceId` | Custom device identifier | Auto-generated |
| `ApiKey` | API authentication key | None |
| `Passphrase` | Client passphrase for restricted access/reporting | None |
| `CollectionInterval` | Data collection interval (seconds) | 3600 |
| `LogLevel` | Logging level | Information |
| `OsQueryPath` | Path to osquery executable | `C:\Program Files\osquery\osqueryi.exe` |

### Enterprise Configuration via CSP/OMA-URI

ReportMate supports enterprise configuration management through Configuration Service Provider (CSP) and OMA-URI profiles, enabling centralized management via Microsoft Intune, System Center Configuration Manager (SCCM), or MDM configuration.

#### Registry Configuration Paths

The application reads configuration from the following Windows Registry locations:

1. **Standard Registry**: `HKLM\SOFTWARE\ReportMate`
2. **CSP/MDM configuration**: `HKLM\SOFTWARE\Config\ReportMate` (higher precedence)

#### OMA-URI Configuration for Microsoft Intune

**Create Custom Configuration Profile:**

1. In Microsoft Intune, navigate to **Devices** > **Configuration profiles**
2. Create a new profile:
   - Platform: **Windows 10 and later**
   - Profile type: **Custom**
   - Name: **ReportMate Client Configuration**

**OMA-URI Settings:**

**API Configuration:**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiUrl
Data type: String
Value: https://api.reportmate.yourdomain.com
```

**Device ID (Optional - auto-generated if not specified):**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/DeviceId
Data type: String
Value: {custom-device-identifier}
```

**API Authentication Key (Optional):**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiKey
Data type: String
Value: {your-api-key}
```

**Client Passphrase (Optional - for restricted access/reporting):**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/Passphrase
Data type: String
Value: {client-passphrase}
```

**Collection Interval (Optional - default: 3600 seconds):**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/CollectionInterval
Data type: Integer
Value: 7200
```

**Log Level (Optional - default: Information):**
```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/LogLevel
Data type: String
Value: Information
```

#### MDM configuration Configuration

**Using MDM configuration Registry Editor:**

1. Open **MDM configuration Management Console**
2. Edit the desired GPO
3. Navigate to **Computer Configuration** > **Preferences** > **Windows Settings** > **Registry**
4. Create new registry items with the following details:

**Registry Key Configuration:**
- **Hive**: HKEY_LOCAL_MACHINE
- **Key Path**: SOFTWARE\Config\ReportMate
- **Action**: Update

**Registry Values:**
| Value Name | Type | Data |
|------------|------|------|
| ApiUrl | REG_SZ | https://api.reportmate.yourdomain.com |
| DeviceId | REG_SZ | {custom-device-identifier} |
| ApiKey | REG_SZ | {your-api-key} |
| Passphrase | REG_SZ | {client-passphrase} |
| CollectionInterval | REG_DWORD | 7200 |
| LogLevel | REG_SZ | Information |
| OsQueryPath | REG_SZ | C:\Program Files\osquery\osqueryi.exe |
| ForceCollection | REG_DWORD | 0 |
| ValidateSslCert | REG_DWORD | 1 |

#### PowerShell Script for Mass Deployment

```powershell
# ReportMate Enterprise Configuration Script
# Run with administrative privileges

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiUrl,
    
    [string]$DeviceId = "",
    [string]$ApiKey = "",
    [string]$Passphrase = "",
    [int]$CollectionInterval = 3600,
    [string]$LogLevel = "Information"
)

$RegistryPath = "HKLM:\SOFTWARE\Config\ReportMate"

# Create registry key if it doesn't exist
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set configuration values
Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl -Type String
Write-Host "✅ Set API URL: $ApiUrl"

if ($DeviceId) {
    Set-ItemProperty -Path $RegistryPath -Name "DeviceId" -Value $DeviceId -Type String
    Write-Host "✅ Set Device ID: $DeviceId"
}

if ($ApiKey) {
    Set-ItemProperty -Path $RegistryPath -Name "ApiKey" -Value $ApiKey -Type String
    Write-Host "✅ Set API Key: [REDACTED]"
}

if ($Passphrase) {
    Set-ItemProperty -Path $RegistryPath -Name "Passphrase" -Value $Passphrase -Type String
    Write-Host "✅ Set Client Passphrase: [REDACTED]"
}

Set-ItemProperty -Path $RegistryPath -Name "CollectionInterval" -Value $CollectionInterval -Type DWord
Write-Host "✅ Set Collection Interval: $CollectionInterval seconds"

Set-ItemProperty -Path $RegistryPath -Name "LogLevel" -Value $LogLevel -Type String
Write-Host "✅ Set Log Level: $LogLevel"

Write-Host "`n🎉 ReportMate configuration completed successfully!"
Write-Host "Configuration will take effect on the next ReportMate run."
```

#### Configuration Validation Commands

**Test Configuration:**
```powershell
# Verify registry configuration
Get-ItemProperty -Path "HKLM:\SOFTWARE\Config\ReportMate" -ErrorAction SilentlyContinue

# Test ReportMate configuration
& "C:\Program Files\ReportMate\managedreportsrunner.exe" test --verbose

# View current configuration
& "C:\Program Files\ReportMate\managedreportsrunner.exe" info
```

**Monitor Configuration Application:**
```powershell
# Check Windows Event Log for ReportMate events
Get-WinEvent -LogName Application -Source "ReportMate" -MaxEvents 10
```

#### Troubleshooting Enterprise Configuration

**Common Issues:**

1. **Registry Access Denied**: Ensure the profile is applied to computer configuration, not user configuration
2. **Configuration Not Applied**: Check that the device is receiving and processing the policy
3. **Invalid API URL**: Ensure the URL includes the protocol (https://) and is accessible from the client

**Validation Steps:**

1. Verify registry values are created correctly
2. Test API connectivity: `managedreportsrunner.exe test`
3. Check Windows Event Log for ReportMate entries
4. Review configuration hierarchy: `managedreportsrunner.exe info`

#### Security Considerations

- Store sensitive values (API keys, passphrases) securely using Intune's encrypted storage
- Use HTTPS endpoints for all API communications
- Implement certificate pinning in high-security environments
- Regularly rotate API keys and passphrases, updating configurations accordingly
- Monitor configuration compliance through Intune reporting

## Troubleshooting

### Common Issues

1. **"API URL not configured"**
   ```pwsh
   # Set the API URL
   & "C:\Program Files\ReportMate\managedreportsrunner.exe" install --api-url "https://your-api.azurewebsites.net"
   ```

2. **"osquery not found"**
   ```pwsh
   # Install osquery or set custom path
   Set-ItemProperty -Path "HKLM:\SOFTWARE\ReportMate" -Name "OsQueryPath" -Value "C:\Tools\osquery\osqueryi.exe"
   ```

3. **"API connectivity failed"**
   ```pwsh
   # Test network connectivity
   Test-NetConnection -ComputerName "your-reportmate-api.azurewebsites.net" -Port 443
   
   # Test with verbose logging
   & "C:\Program Files\ReportMate\managedreportsrunner.exe" test --verbose
   ```

4. **"Access denied" errors**
   ```pwsh
   # Run as administrator
   Start-Process -FilePath "C:\Program Files\ReportMate\managedreportsrunner.exe" -Verb RunAs -ArgumentList "run", "--force"
   ```

### Debug Mode

Enable detailed logging:
```pwsh
Set-ItemProperty -Path "HKLM:\SOFTWARE\ReportMate" -Name "LogLevel" -Value "DEBUG"
& "C:\Program Files\ReportMate\managedreportsrunner.exe" --debug
```

## Building from Source

### Development Build

```bash
# Clone repository
git clone <repository-url>
cd reportmate-client-win

# Build the executable
chmod +x build/build.sh
./build/build.sh
```

### Production Build

```pwsh
# Create MSI installer
cd build
.\create-installer.ps1 -Version "1.0.0" -ApiUrl "https://your-api.azurewebsites.net"

# Sign installer (production)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com output/ReportMate-1.0.0.msi
```

### Project Structure

```
reportmate-client-win/
├── src/                           # Source code
│   ├── Program.cs                 # Main application entry point
│   ├── ReportMate.WindowsClient.csproj  # Project file
│   ├── appsettings.json          # Configuration settings
│   ├── appsettings.yaml          # YAML configuration
│   ├── osquery-queries.json      # osquery query definitions
│   ├── app.manifest              # Windows application manifest
│   ├── Configuration/            # Configuration management
│   │   ├── ReportMateClientConfiguration.cs
│   │   └── WindowsRegistryConfigurationProvider.cs
│   └── Services/                 # Core services
│       ├── ApiService.cs         # API communication
│       ├── ConfigurationService.cs  # Configuration management
│       ├── DataCollectionService.cs # Main data collection orchestration
│       ├── DeviceInfoService.cs  # Device information gathering
│       └── OsQueryService.cs     # osquery execution and management
├── build/                        # Build and packaging scripts
│   ├── build_exe.sh              # Cross-platform executable build script
│   ├── build_msi.ps1             # MSI installer creation
│   └── build_nupkg.ps1           # NUPKG package creation
├── nupkg/                        # Unified package structure (canonical)
│   ├── build-info.yaml           # Package metadata and configuration
│   ├── payload/                  # Files to be installed (populated during build)
│   │   ├── Program Files/
│   │   │   ├── Cimian/
│   │   │   │   └── postflight.ps1    # Cimian postflight integration
│   │   │   └── ReportMate/
│   │   │       ├── managedreportsrunner.exe         # Main executable (populated by build)
│   │   │       ├── appsettings.yaml   # Template configuration
│   │   │       └── version.txt        # Version information
│   │   └── ProgramData/
│   │       └── ManagedReports/
│   │           ├── appsettings.yaml   # Working configuration
│   │           └── queries.json       # OSQuery definitions
│   └── scripts/                  # Installation scripts
│       ├── preinstall.ps1        # Pre-installation script
│       └── postinstall.ps1       # Post-installation script
├── .github/workflows/            # CI/CD automation
│   └── build-and-release.yml     # Automated builds and releases
└── README.md                     # This documentation
```

## Performance

### Optimization Features
- **Caching**: Avoids redundant data collection within configurable intervals
- **Parallel Processing**: Concurrent osquery execution where safe
- **Memory Management**: Efficient JSON serialization and streaming
- **Network Optimization**: Connection pooling and compression support
- **Resource Limits**: Configurable timeouts and retry policies

### Resource Usage
- **Memory**: ~50-100MB during execution, ~10MB at rest
- **CPU**: Low impact, brief spikes during data collection
- **Network**: Varies by data volume, typically <1MB per run
- **Disk**: Minimal, logs with automatic rotation

## Benefits of This Structure

- **Clear separation** between binaries and data
- **Easy updates** - replace executable without losing configuration
- **Secure permissions** - data directory can have restricted access
- **Consistent with platform conventions** (Cimian/Munki pattern)
- **Enterprise-friendly** - supports MDM configuration and Configuration Profiles
- **Clean uninstallation** - remove program files, preserve or clean data as needed

## Permissions

### Windows
- **Program Files**: Read-only for users, Write for administrators
- **ProgramData**: Write access for SYSTEM and ReportMate service account

This structure ensures ReportMate integrates cleanly with enterprise management tools while maintaining security and following platform best practices.

## Next Steps

### Immediate Actions
1. **Test on a few pilot machines** before wide deployment
2. **Verify data appears** in your ReportMate dashboard
3. **Configure monitoring alerts** for failed data collection
4. **Document your specific configuration** for your environment

### Production Deployment
1. **Sign the MSI installer** with your code signing certificate
2. **Create deployment packages** for your distribution method
3. **Schedule regular data collection** (default: every hour)
4. **Set up centralized logging** and monitoring

### Advanced Configuration
1. **Customize osquery queries** in `osquery-queries.json`
2. **Configure proxy settings** if needed
3. **Set up certificate-based authentication** 
4. **Integrate with your SIEM/monitoring tools**

## Support

If you encounter issues:

1. **Check logs** first - they contain detailed error information
2. **Verify configuration** with `managedreportsrunner.exe info`
3. **Test connectivity** with `managedreportsrunner.exe test --verbose`
4. **Review the implementation documentation** for advanced scenarios
