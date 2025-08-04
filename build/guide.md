# ReportMate Windows Client - Build System Guide

This comprehensive guide covers the ReportMate Windows client build system, installation methods, and enterprise deployment strategies with modern WiX v6 MSI packaging.

## Overview

ReportMate Windows client supports multiple deployment formats with intelligent module scheduling optimized for different data collection frequencies. The system uses a centralized build architecture with dynamic versioning and automated scheduled task management.

## Package Types Comparison

| Package Type | Use Case | Size | Deployment | Task Setup | Enterprise Ready |
|--------------|----------|------|------------|------------|------------------|
| **MSI Installer** | Enterprise deployment | ~9.5MB | Windows Installer | Automatic | ✅ **Recommended** |
| **Chocolatey NUPKG** | Package managers | ~8MB | choco install | Post-install script | ✅ Good |
| **Portable ZIP** | Manual/Air-gapped | ~7MB | Manual extraction | Manual setup | ⚠️ Limited |
| **Standalone EXE** | Development/Testing | ~6MB | Direct execution | None | ❌ Not recommended |

### 1. MSI Installer (.msi) - **Enterprise Recommended**
- **Built with**: WiX Toolset v6.0.1 (modern .NET tooling)
- **Features**: Full Windows Installer package with professional installation experience
- **Scheduling**: Automatically creates optimized scheduled tasks during installation
- **Management**: Supports Group Policy deployment and enterprise management
- **Configuration**: Registry-based configuration with CSP/Intune support
- **Maintenance**: Clean uninstallation and seamless upgrade handling
- **Security**: Code-signed with enterprise certificates
- **Size**: ~9.5MB (includes all components and resources)

### 2. Chocolatey Package (.nupkg)
- **Management**: Chocolatey-compatible package for automated deployments
- **Resources**: Leverages centralized resource management from build system
- **Configuration**: Post-install scripts for automated configuration
- **Integration**: Works with existing package management workflows

### 3. Portable ZIP Archive (.zip)
- **Deployment**: Self-contained deployment package
- **Setup**: Manual installation and configuration required
- **Resources**: Includes all necessary dependencies and OSQuery modules
- **Environment**: Ideal for isolated or air-gapped environments

### 4. Standalone Executable (.exe)
- **Format**: Single-file, self-contained executable built with .NET 8
- **Footprint**: Minimal installation footprint
- **Tasks**: Manual scheduled task setup required
- **Purpose**: Development and testing use cases

## Build System Architecture

### Directory Structure

```
clients/windows/
├── build/                                       # Centralized build resources
│   ├── resources/                               # Shared resources for all packages
│   │   ├── osquery/                             # OSQuery modules (single source of truth)
│   │   │   ├── enabled-modules.json             # Module enable/disable configuration
│   │   │   └── modules/                         # Individual module configurations
│   │   │       ├── applications.json           # Software inventory and processes
│   │   │       ├── displays.json               # Display hardware and configuration
│   │   │       ├── hardware.json               # Physical hardware inventory
│   │   │       ├── installs.json               # Cimian managed software tracking
│   │   │       ├── inventory.json              # Device identification and assets
│   │   │       ├── management.json             # MDM enrollment and device management
│   │   │       ├── network.json                # Network interfaces and connectivity
│   │   │       ├── printers.json               # Printer hardware and configuration
│   │   │       ├── profiles.json               # Configuration profiles and policies
│   │   │       ├── security.json               # Security features and protection status
│   │   │       └── system.json                 # Operating system and configuration
│   │   ├── scheduledtasks/                     # Scheduled task management
│   │   │   └── Create-ScheduledTasks.ps1       # Task creation and management script
│   │   ├── install-scripts/                    # Common installation scripts
│   │   │   ├── Configure-ReportMate.ps1        # Shared configuration setup
│   │   │   └── Setup-ScheduledTasks.ps1        # Shared task scheduler setup
│   │   ├── module-schedules.json               # Schedule definitions and task settings
│   │   ├── install-tasks.ps1                   # MSI install script (creates tasks)
│   │   └── uninstall-tasks.ps1                 # MSI uninstall script (removes tasks)
│   ├── msi/                                    # MSI installer configuration (WiX v6)
│   │   ├── ReportMate.wxs                      # WiX v6 source file
│   │   ├── ReportMate.wixproj                  # WiX project file  
│   │   └── License.rtf                         # License for MSI installer
│   └── nupkg/                                  # Chocolatey package resources
│       ├── scripts/                            # Pre/post install scripts
│       ├── templates/                          # Package templates
│       └── tools/                              # Chocolatey tools and install scripts
├── src/                                        # Source code (no duplication)
│   ├── ReportMate.WindowsClient.csproj         # Project with dynamic versioning
│   ├── Program.cs                              # Main application entry point
│   ├── appsettings.json                        # Default configuration
│   ├── appsettings.yaml                        # YAML configuration template
│   └── Services/                               # Application services
├── dist/                                       # Build outputs
│   ├── ReportMate-2025.08.03.msi              # MSI installer
│   ├── ReportMate-2025.08.03.nupkg            # Chocolatey package
│   ├── ReportMate-2025.08.03.zip              # ZIP archive
│   └── runner.exe                              # Standalone executable
└── .publish/                                   # Temporary build artifacts
```

## MSI Installation Layout

The MSI installer deploys ReportMate to the following Windows system locations:

### Program Files Installation Tree
```
C:\Program Files\ReportMate\
├── runner.exe                                  # Main executable (code-signed)
├── appsettings.json                            # Application configuration
├── appsettings.yaml                            # YAML configuration template
├── module-schedules.json                       # Task scheduling configuration
├── install-tasks.ps1                          # Task installation script
└── uninstall-tasks.ps1                        # Task removal script
```

### Program Data Installation Tree
```
C:\ProgramData\ManagedReports\
├── osquery/                                   # OSQuery module configurations
│   ├── enabled-modules.json                   # Module enable/disable settings
│   └── modules/                               # Individual module query definitions
│       ├── applications.json                  # Software and process monitoring
│       ├── displays.json                      # Display hardware queries
│       ├── hardware.json                      # Physical hardware inventory
│       ├── installs.json                      # Cimian installation tracking
│       ├── inventory.json                     # Device identification
│       ├── management.json                    # MDM and device management
│       ├── network.json                       # Network interface monitoring
│       ├── printers.json                      # Printer hardware and drivers
│       ├── profiles.json                      # Policy and configuration profiles
│       ├── security.json                      # Security status and features
│       └── system.json                        # OS and system configuration
├── logs/                                      # Application and collection logs
└── cache/                                     # Temporary data and caches
```

### Registry Configuration
```
HKLM\SOFTWARE\ReportMate\
├── InstallPath         : "C:\Program Files\ReportMate"
├── DataPath           : "C:\ProgramData\ManagedReports"
├── ApiUrl             : (configured during/after installation)
├── ApiKey             : (configured during/after installation)
├── ConfiguredDate     : Installation timestamp
└── Version            : Current version (YYYY.MM.DD format)
```

### Scheduled Tasks Created
```
Task Scheduler\ReportMate\
├── ReportMate Hourly Collection               # Security-critical modules (1h interval)
│   └── Modules: security, installs, profiles, system, network
├── ReportMate 4-Hourly Collection            # Moderate change modules (4h interval)
│   └── Modules: applications, inventory
├── ReportMate Daily Collection               # Stable modules (24h interval)
│   └── Modules: hardware, management, printers, displays
└── ReportMate Data Transmission              # Upload collected data (15min after collection)
```

## Dynamic Versioning System

All packages use automatic date-based versioning in `YYYY.MM.DD` format:

```xml
<!-- In ReportMate.WindowsClient.csproj -->
<VersionPrefix>$([System.DateTime]::Now.ToString("yyyy.MM.dd"))</VersionPrefix>
<AssemblyVersion>$(VersionPrefix)</AssemblyVersion>
<FileVersion>$(VersionPrefix)</FileVersion>
```

**MSI Version Conversion**: 
- Build version: `2025.08.03` → MSI version: `25.8.3` (3-part format required)
- Automatic conversion during MSI build process
- Ensures compatibility with Windows Installer requirements

**Benefits:**
- ✅ Automatic version generation at build time
- ✅ No manual version management required  
- ✅ Date-based versioning for easy tracking
- ✅ Consistent versioning across all package types
- ✅ MSI upgrade logic works seamlessly

## Module Collection Schedules

ReportMate optimizes data collection with differentiated scheduling based on data change frequency:

### Hourly Collection (Security-Critical)
- **Modules**: `security`, `installs`, `profiles`, `system`, `network`
- **Interval**: 60 minutes
- **Purpose**: Frequent monitoring of security status, software changes, and configuration updates
- **Staggered Start**: 5-minute offsets to distribute system load

### 4-Hourly Collection (Moderate Changes)  
- **Modules**: `applications`, `inventory`
- **Interval**: 240 minutes (4 hours)
- **Purpose**: Software installation tracking and basic device inventory
- **Optimized**: Balances data freshness with system resource usage

### Daily Collection (Stable Data)
- **Modules**: `hardware`, `management`, `printers`, `displays`  
- **Interval**: 1440 minutes (24 hours)
- **Purpose**: Physical hardware, device management status, and peripheral devices
- **Efficient**: Minimal system impact for rarely-changing data

### Data Transmission
- **Schedule**: 15 minutes after each collection cycle
- **Purpose**: Upload collected data to ReportMate API
- **Retry Logic**: Automatic retry with exponential backoff
- **Network Aware**: Only runs when network is available

## Build Process Workflow

1. **Source Compilation**: .NET 8 self-contained build from `src/`
2. **Resource Staging**: Copy shared resources from `build/resources/`
3. **Package Assembly**: Create payload structures for each package type
4. **MSI Creation**: WiX v6 build with automatic scheduled task installation
5. **Code Signing**: Enterprise certificate signing for all executables
6. **Cleanup**: Remove temporary build artifacts and duplicate files
7. **Validation**: Test package integrity and installation

## WiX v6 Modern MSI Building

ReportMate uses the latest WiX Toolset v6.0.1 for professional MSI creation:

### Build Command
```powershell
dotnet tool run wix -- build -out ReportMate-2025.08.03.msi 
  -define "SourceDir=$MsiStagingDir" 
  -define "ResourceDir=$BuildDir/resources" 
  -define "Version=25.8.3" 
  -define "APIURL=$ApiUrl" 
  build/msi/ReportMate.wxs
```

### Key Features
- **Modern Tooling**: .NET-based WiX v6 with improved performance
- **Custom Actions**: PowerShell scripts for scheduled task management
- **Upgrade Logic**: Seamless major/minor upgrades with data preservation
- **Property-based Configuration**: Support for MSI properties and transforms
- **Enterprise Integration**: Group Policy deployment ready

## Enterprise Deployment

### Group Policy Deployment
```
Computer Configuration\
├── Software Settings\
│   └── Software Installation\
│       └── ReportMate-2025.08.03.msi
└── Administrative Templates\
    └── ReportMate Configuration\
        ├── API URL Setting
        └── Collection Schedules
```

### SCCM/Intune Deployment
- **Detection Method**: Registry key `HKLM\SOFTWARE\ReportMate\Version`
- **Install Command**: `msiexec /i ReportMate-2025.08.03.msi /quiet APIURL="https://api.example.com"`
- **Uninstall Command**: `msiexec /x {8A5D2E3F-7B6C-4891-A0B2-C3D4E5F60718} /quiet`
- **Return Codes**: Standard MSI return codes for deployment status

This modern build system ensures reliable, enterprise-ready deployments with minimal administrative overhead and maximum compatibility across Windows environments.
