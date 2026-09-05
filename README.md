# ReportMate Windows Client

ReportMate Client side Windows installer for gathering endpoint telemetry for monitoring dashboard using `osquery`.

Written in C# on .NET 10. Designed to run on its own or as a postflight script after Cimian's managed software update process. It collects detailed device information using `osquery` and securely transmits it to the ReportMate API.

Full documentation lives in the [wiki](https://github.com/reportmate/reportmate-client-win/wiki). This README covers the essentials.

## Quick Start

### Building ReportMate

The project includes a unified PowerShell 7 build script that handles all package types:

Build everything with an auto-generated date version:

```powershell
.\build.ps1
```

Build a specific version:

```powershell
.\build.ps1 -Version "2026.09.03.1430"
```

Clean build with signing forced on:

```powershell
.\build.ps1 -Clean -Version "2026.09.03.1430" -Sign
```

**📋 Prerequisites:**
- PowerShell 7+ ([Download](https://github.com/PowerShell/PowerShell/releases)) — the script refuses to run on Windows PowerShell 5.1
- .NET 10 SDK ([Download](https://dotnet.microsoft.com/download))
- `cimipkg` for MSI and NUPKG creation — downloaded automatically by `build.ps1` if it is not on `PATH` or in the repo root

**📦 Output:** Three deployment packages in `release/`
- `ReportMate-{version}.msi` - Enterprise MSI installer (primary artifact)
- `ReportMate-{version}.nupkg` - Chocolatey/Cimian package
- `ReportMate-{version}.zip` - Manual installation archive

See [BUILD.md](BUILD.md) and the [Building and Releasing](https://github.com/reportmate/reportmate-client-win/wiki/Building-and-Releasing) wiki page for detailed build instructions and troubleshooting.

## Directory Structure

The project uses a unified package structure that supports all deployment formats:

```
reportmate-client-win/
├── src/                    # C# source code for managedreportsrunner.exe
├── usagetracker/           # C# source code for usagetracker.exe
├── tests/                  # xUnit test project
├── build/                  # Packaging inputs
│   ├── nupkg/             # cimipkg project for the NUPKG
│   │   ├── build-info.yaml   # Package metadata ({{VERSION}} substituted at build time)
│   │   ├── reportmate.nuspec
│   │   └── scripts/          # preinstall.ps1, postinstall.ps1
│   ├── pkg/               # cimipkg project for the MSI
│   │   ├── build-info.yaml
│   │   └── scripts/          # preinstall.ps1, postinstall.ps1
│   └── resources/         # Payload assets shared by both packages
│       ├── osquery/          # Modular osquery configuration
│       ├── module-schedules.json
│       ├── cimian-postflight.ps1
│       ├── install-tasks.ps1
│       └── uninstall-tasks.ps1
├── build.ps1              # 🚀 Unified build script (PowerShell 7)
├── BUILD.md               # Detailed build documentation
├── .publish/              # .NET publish output (generated)
├── release/               # Generated packages (generated)
└── .github/workflows/     # CI/CD automation (ci.yml, release.yml)
```

## Installation Locations

After deployment, files are organized following Windows conventions:

### Binaries (`C:\Program Files\ReportMate\`)

- `managedreportsrunner.exe` - Main ReportMate executable (added to the machine `PATH` by the installer)
- `usagetracker.exe` - Per-user session companion that records application foreground and active time
- `speedtest.exe` - Ookla Speedtest CLI, used by the network module
- `appsettings.yaml` / `appsettings.template.yaml` - Configuration seeds, copied to `ProgramData` at install time
- `module-schedules.json` - Module-to-schedule mapping used to register the scheduled tasks
- `osquery/` - Query packs, copied to `ProgramData` at install time
- `version.txt` - Build and version information

### Working Data (`C:\ProgramData\ManagedReports\`)

- `appsettings.yaml` - Active configuration file (editable)
- `appsettings.template.yaml` - Enterprise template configuration (CSP/OMA-URI manageable)
- `osquery/` - Modular osquery configuration directory
  - `enabled-modules.json` - Module configuration
  - `modules/` - Individual module query files: `applications.json`, `hardware.json`, `identity.json`, `installs.json`, `inventory.json`, `management.json`, `network.json`, `peripherals.json`, `security.json`, `system.json`
- `config/`, `logs/`, `cache/`, `data/` - Created by the installer and populated at runtime

### Cimian Integration (`C:\Program Files\Cimian\`)

- `postflight.ps1` - Executed by Cimian after software updates

### Scheduled Tasks

The installer registers four SYSTEM collection tasks (`ReportMate Hourly Collection`, `ReportMate 4-Hourly Collection`, `ReportMate Daily Collection`, `ReportMate All Modules Collection`) plus `ReportMate User Session Tracker` for the per-user usage tracker. Which modules run on which schedule is defined in `build/resources/module-schedules.json`.

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
│  Simple postflight execution - no GUI status integration       │
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
│                       ReportMate API                            │
├─────────────────────────────────────────────────────────────────┤
│ • Secure HTTPS transmission                                     │
│ • Authentication & authorization                                │
│ • Real-time dashboard updates                                   │
│ • Data storage & analytics                                      │
└─────────────────────────────────────────────────────────────────┘
```

See the [Architecture](https://github.com/reportmate/reportmate-client-win/wiki/Architecture) and [Modules](https://github.com/reportmate/reportmate-client-win/wiki/Modules) wiki pages for the run flow and the payload each module emits.

## Configuration Management

The application uses a configuration hierarchy to support enterprise deployment and management. From lowest to highest precedence:

1. **Application Defaults** (embedded in the binary) - Fallback values
2. **Working Configuration** (`ProgramData/ManagedReports/appsettings.yaml`) - Runtime editable
3. **Environment Variables** (prefix: `REPORTMATE_`) - Container/deployment specific
4. **Windows Registry** (`HKLM\SOFTWARE\ReportMate`, then `HKLM\SOFTWARE\Config\ReportMate` for CSP/MDM) - Highest precedence

`appsettings.template.yaml` is shipped alongside the working configuration as an unmodified enterprise reference copy; the client itself only reads `appsettings.yaml`.

All configuration files are stored in `ProgramData` (not `Program Files`) to ensure they are accessible by CSP and MDM configuration management tools.

### Enterprise Deployment with CSP/OMA-URI

For enterprise environments, configuration can be managed through:

- **Configuration Service Provider (CSP)**: Deploy `appsettings.template.yaml` to `ProgramData/ManagedReports/`
- **MDM configuration**: Set registry values under `HKLM\SOFTWARE\ReportMate`
- **OMA-URI**: Push configuration files and registry settings remotely

#### Example Complete Configuration

**Intune Custom Configuration Profile (XML):**

```xml
<OMASettings>
  <OMADevice>
    <OMAApplicationData>
      <Name>ReportMate Client Configuration</Name>
      <OMAConfigurationData>
        <Item>
          <Target>./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiUrl</Target>
          <Data>https://api.example.com</Data>
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

## Building and Deployment

### Development Workflow

1. **Source Code**: C# source files in `src/` (agent) and `usagetracker/` (per-user companion)
2. **Build**: Run `.\build.ps1` to publish the executables and assemble the package payloads
3. **Package**: The same script produces the MSI and NUPKG via `cimipkg`, plus a ZIP archive
4. **Deploy**: All formats install to the same standardized Windows locations

### Automated CI/CD

The project includes two GitHub Actions workflows:

- `ci.yml` — runs on pull requests to `main` and on pushes to `main`. Builds with `.\build.ps1 -NoSign -SkipMSI -SkipNUPKG -SkipZIP -Configuration Release`, then runs the xUnit test project. There is no scheduled build.
- `release.yml` — runs on pushed tags matching `v*` or a bare `YYYY.MM.DD.NNNN` date stamp. Builds with `.\build.ps1 -NoSign`, then creates a GitHub release and uploads every `.msi`, `.nupkg` and `.zip` under `release/`.

**Release artifacts are unsigned.** Sign the binaries and the installer with your own code signing certificate before fleet distribution; the generated release notes include the `signtool` commands.

### Manual Deployment Options

#### MSI Installation (Recommended)

The MSI takes its API URL from a `.env` file baked into the package at build time (`PROD_API_URL` or `REPORTMATE_API_URL`); it does not accept an `API_URL` msiexec property.

```powershell
msiexec /i ReportMate-{version}.msi /quiet /l*v "%TEMP%\reportmate-install.log"
```

#### Direct Executable

```powershell
.\managedreportsrunner.exe install --api-url "https://api.example.com"
.\managedreportsrunner.exe run
```

## Key Features

### Core Functionality

- **osquery Integration**: Leverages osquery for comprehensive system data collection
- **Cimian Integration**: Simple postflight script execution (no GUI integration)
- **Secure Communication**: HTTPS with proper certificate validation
- **Configuration Management**: Multi-source configuration with Windows Registry support
- **Error Handling**: Robust retry logic and comprehensive logging
- **Performance Optimization**: Efficient data collection with caching
- **Application Usage Analytics**: Tracks launch counts and session durations from an in-session companion process

### Security Features

- **Privilege Management**: Requires administrator privileges (`requireAdministrator` in the application manifest)
- **Secure Storage**: No hardcoded credentials, uses Windows registry securely
- **Data Encryption**: All API communications encrypted in transit
- **Certificate Validation**: Proper SSL/TLS certificate verification

### Enterprise Ready

- **MSI Installer**: Windows Installer package built by `cimipkg`
- **MDM configuration Support**: Silent installation and configuration
- **Logging & Monitoring**: Windows Event Log integration under the `ReportMate` source
- **Configuration Management**: Multiple configuration sources (Registry, YAML, Environment)

## Command Line Interface

Run data collection (the default action when no command is given):

```powershell
managedreportsrunner.exe run [--force] [--collect-only] [--transmit-only] [--run-module ID] [--run-modules A,B] [--device-id ID] [--api-url URL] [--storage-mode quick|deep|auto]
```

Transmit the most recent cached payload without collecting:

```powershell
managedreportsrunner.exe transmit
```

Display device identity and current configuration:

```powershell
managedreportsrunner.exe info
```

Write the `HKLM\SOFTWARE\ReportMate` configuration key:

```powershell
managedreportsrunner.exe install --api-url URL [--device-id ID] [--api-key KEY]
```

Print the client version:

```powershell
managedreportsrunner.exe version
```

Verbosity is controlled by `--verbose[=N]` (0–3) or the `-v` / `-vv` / `-vvv` shorthands. The full option and exit-code table is in the [Command Line Reference](https://github.com/reportmate/reportmate-client-win/wiki/Command-Line-Reference) wiki page.

## Requirements

### Runtime Requirements

- Windows 10/11 or Windows Server 2016+
- No .NET runtime on the endpoint — the agent and the usage tracker are published self-contained for `win-x64`
- Administrator privileges (required by the application manifest)
- Network connectivity to the ReportMate API

### Build Requirements

- .NET 10 SDK
- PowerShell 7+ (`build.ps1` enforces this)
- `cimipkg` for MSI and NUPKG creation, auto-downloaded from the [cimian-pkg releases](https://github.com/windowsadmins/cimian-pkg/releases) when missing
- `nuget` on `PATH` for the NUPKG step
- `gh` for `-CreateRelease`

### Optional Dependencies

- osquery (for enhanced data collection) - Automatically detected at `C:\Program Files\osquery\`

## Integration Examples

### Cimian Postflight Script

The included `postflight.ps1` script automatically executes ReportMate after Cimian runs `managedsoftwareupdate.exe`. It is installed to `C:\Program Files\Cimian\postflight.ps1` from `build/resources/cimian-postflight.ps1`.

### Manual Integration

```powershell
& "C:\Program Files\ReportMate\managedreportsrunner.exe" run
```

## Package Formats

ReportMate supports three deployment formats, all built from the same unified source structure:

### 1. MSI Installer (Primary)

- **Use Case**: Traditional Windows enterprise deployment (MDM configuration, SCCM, Intune)
- **Built by**: `cimipkg` from `build/pkg/`; there is no WiX authoring in this repository
- **Benefits**: Windows Installer features, Add/Remove Programs integration, silent installation

### 2. NUPKG Package

- **Use Case**: Chocolatey and Cimian package management
- **Built by**: `cimipkg --nupkg` from `build/nupkg/`

### 3. ZIP Archive

- **Use Case**: Manual deployment and testing
- **Installation**: Extract and run the generated `install.bat` as administrator

## Configuration

### Registry Settings

Configuration is read from `HKLM\SOFTWARE\ReportMate`, and then from `HKLM\SOFTWARE\Config\ReportMate` (CSP/MDM), which takes precedence. These value names are mapped explicitly:

| Setting | Description | Default |
|---------|-------------|---------|
| `ApiUrl` | ReportMate API endpoint | *Required* |
| `DeviceId` | Custom device identifier | Auto-generated |
| `ApiKey` | API authentication key | None |
| `Passphrase` | Client passphrase for restricted access/reporting | None |
| `CollectionInterval` | Data collection interval (seconds) | 3600 |
| `LogLevel` | Logging level | Information |
| `OsQueryPath` | Path to osquery executable | `C:\Program Files\osquery\osqueryi.exe` |

Under the CSP key, `ServerUrl` is also accepted as an alias for `ApiUrl`. Any other value name is passed through as `ReportMate:<ValueName>`.

Every configuration key the client reads is listed on the [Configuration](https://github.com/reportmate/reportmate-client-win/wiki/Configuration) wiki page.

#### OMA-URI Configuration for Microsoft Intune

**Create Custom Configuration Profile:**

1. In Microsoft Intune, navigate to **Devices** > **Configuration profiles**
2. Create a new profile:
   - Platform: **Windows 10 and later**
   - Profile type: **Custom**
   - Name: **ReportMate Client Configuration**

**API Configuration:**

```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiUrl
Data type: String
Value: https://api.example.com
```

**Device ID (Optional - auto-generated if not specified):**

```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/DeviceId
Data type: String
Value: WS-0001
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

#### Group Policy Preferences

Registry items can equally be delivered through **Computer Configuration** > **Preferences** > **Windows Settings** > **Registry**, using hive `HKEY_LOCAL_MACHINE` and key path `SOFTWARE\Config\ReportMate` with the value names from the table above.

#### PowerShell Script for Mass Deployment

```powershell
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

if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

Set-ItemProperty -Path $RegistryPath -Name "ApiUrl" -Value $ApiUrl -Type String

if ($DeviceId) {
    Set-ItemProperty -Path $RegistryPath -Name "DeviceId" -Value $DeviceId -Type String
}

if ($ApiKey) {
    Set-ItemProperty -Path $RegistryPath -Name "ApiKey" -Value $ApiKey -Type String
}

if ($Passphrase) {
    Set-ItemProperty -Path $RegistryPath -Name "Passphrase" -Value $Passphrase -Type String
}

Set-ItemProperty -Path $RegistryPath -Name "CollectionInterval" -Value $CollectionInterval -Type DWord
Set-ItemProperty -Path $RegistryPath -Name "LogLevel" -Value $LogLevel -Type String
```

#### Configuration Validation Commands

Verify the registry configuration:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Config\ReportMate" -ErrorAction SilentlyContinue
```

View the configuration the client actually resolved:

```powershell
& "C:\Program Files\ReportMate\managedreportsrunner.exe" info
```

Check the Windows Event Log for ReportMate events:

```powershell
Get-WinEvent -LogName Application -ProviderName "ReportMate" -MaxEvents 10
```

#### Security Considerations

- Store sensitive values (API keys, passphrases) securely using Intune's encrypted storage
- Use HTTPS endpoints for all API communications
- Regularly rotate API keys and passphrases, updating configurations accordingly
- Monitor configuration compliance through Intune reporting

## Troubleshooting

The [Troubleshooting](https://github.com/reportmate/reportmate-client-win/wiki/Troubleshooting) wiki page covers the failure modes visible in the code. The most common starting points:

**"API URL not configured"** — set it and write the registry key:

```powershell
& "C:\Program Files\ReportMate\managedreportsrunner.exe" install --api-url "https://api.example.com"
```

**"osquery not found"** — install osquery, or point the client at a custom path:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\ReportMate" -Name "OsQueryPath" -Value "C:\Tools\osquery\osqueryi.exe"
```

**API connectivity** — collect without transmitting and inspect the payload:

```powershell
& "C:\Program Files\ReportMate\managedreportsrunner.exe" run --collect-only -vvv
```

**"Access denied" errors** — the agent requires administrator rights:

```powershell
Start-Process -FilePath "C:\Program Files\ReportMate\managedreportsrunner.exe" -Verb RunAs -ArgumentList "run", "--force"
```

### Logs

The rolling Serilog file is `C:\ProgramData\ManagedReports\logs\reportmate-<yyyyMMdd>.log`. Per-run module output and the merged payload are written under `C:\ProgramData\ManagedReports\cache\<timestamp>\`. Verbosity is raised with `-v`, `-vv` or `-vvv` on the run itself; see the [Logging](https://github.com/reportmate/reportmate-client-win/wiki/Logging) wiki page.

## Project Structure

```
reportmate-client-win/
├── src/                           # Agent source code
│   ├── Program.cs                 # Entry point and command line
│   ├── ReportMate.WindowsClient.csproj
│   ├── appsettings.json           # Configuration settings
│   ├── appsettings.yaml           # YAML configuration
│   ├── app.manifest               # Windows application manifest
│   ├── App/                       # WinUI configuration app
│   ├── Configuration/             # Configuration management
│   ├── DataProcessing/            # Payload assembly
│   ├── Models/                    # Payload models
│   └── Services/                  # Core services
│       ├── ApiService.cs          # API communication
│       ├── ConfigurationService.cs
│       ├── DataCollectionService.cs
│       ├── ModularDataCollectionService.cs
│       ├── ModularOsQueryService.cs
│       ├── DeviceInfoService.cs
│       ├── Logger.cs
│       └── Modules/               # Per-module processors
├── usagetracker/                  # Per-user usage tracker
├── tests/                         # xUnit test project
├── build/                         # Packaging inputs (see Directory Structure)
├── build.ps1                      # Unified build script
├── .github/workflows/             # ci.yml and release.yml
└── README.md                      # This documentation
```

## Permissions

- **Program Files**: Read-only for users, write for administrators
- **ProgramData**: Write access for SYSTEM

This structure ensures ReportMate integrates cleanly with enterprise management tools while maintaining security and following platform best practices.

## Support

If you encounter issues:

1. **Check logs** first - they contain detailed error information
2. **Verify configuration** with `managedreportsrunner.exe info`
3. **Reproduce with verbose output** using `managedreportsrunner.exe run --collect-only -vvv`
4. **Review the [wiki](https://github.com/reportmate/reportmate-client-win/wiki)** for advanced scenarios
