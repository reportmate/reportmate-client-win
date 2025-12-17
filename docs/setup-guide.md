# ReportMate Windows Client Setup Guide

This guide walks through setting up a Windows machine to report to the ReportMate dashboard.

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Network connectivity to the ReportMate API endpoint (`https://reportmate.ecuad.ca`)
- Optional: osquery installed for enhanced data collection

## Quick Start

### 1. Build the Client

Build and sign the client using the unified build script:

```powershell
cd clients\windows
.\build.ps1 -Sign
```

This produces packages in the `dist/` directory:
- `ReportMate-{version}.nupkg` - Chocolatey package (recommended)
- `ReportMate-{version}.msi` - MSI installer
- `ReportMate-{version}.zip` - Manual installation archive

### 2. Install the Client

**Option A: Chocolatey Package (Recommended)**

```powershell
# Install from local package
sudo choco install com.github.reportmate.windows --source=".\clients\windows\dist\" --yes --force
```

**Option B: MSI Installer**

```powershell
# Run the MSI installer
msiexec /i "dist\ReportMate-{version}.msi" /qn
```

**Option C: Build and Install in One Step**

```powershell
.\build.ps1 -Sign -Install
```

### 3. Configure the Client

Edit the configuration file at `C:\ProgramData\ManagedReports\appsettings.yaml`:

```yaml
ReportMate:
  ApiUrl: "https://reportmate.ecuad.ca"
  Passphrase: "your-passphrase"  # Optional, for authenticated access
```

Or use the install command:

```powershell
& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' install --api-url "https://reportmate.ecuad.ca"
```

### 4. Test the Installation

```powershell
# View system information
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' info"

# Collect data (without transmitting)
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --collect-only"

# Transmit cached data
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --transmit-only"
```

## Command Reference

The `managedreportsmanagedreportsrunner.exe` binary supports the following commands and options:

### Root Command (Default: Run Collection)

```powershell
managedreportsmanagedreportsrunner.exe [options]
```

**Options:**
- `-v`, `-vv`, `-vvv`, `-vvvv` - Verbose logging levels (Warning, Info, Debug, Trace)
- `--force` - Force data collection even if recent run detected
- `--collect-only` - Collect data without transmitting to API
- `--transmit-only` - Transmit cached data without collecting new data
- `--run-module <name>` - Run only a specific module (e.g., `network`, `hardware`, `security`)
- `--run-modules <list>` - Run multiple modules separated by commas (e.g., `hardware,installs,security`)
- `--device-id <id>` - Override device ID
- `--api-url <url>` - Override API URL

### Subcommands

```powershell
# Run data collection (same as default)
managedreportsmanagedreportsrunner.exe run [options]

# Transmit cached data only
managedreportsmanagedreportsrunner.exe transmit

# Display system and configuration information
managedreportsmanagedreportsrunner.exe info

# Install and configure the client
managedreportsmanagedreportsrunner.exe install --api-url "https://reportmate.ecuad.ca"

# Display version information
managedreportsmanagedreportsrunner.exe version
```

### Module Testing

Test individual modules during development:

```powershell
# Test hardware module
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --run-module hardware"

# Test installs module
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --run-module installs"

# Test multiple modules
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --run-modules hardware,security,network"
```

## Available Modules

The client collects data from these modules:

| Module | Description |
|--------|-------------|
| `applications` | Installed applications inventory |
| `displays` | Display/monitor information |
| `hardware` | CPU, memory, storage details |
| `installs` | Cimian managed software installs |
| `inventory` | Device name, serial, asset tag |
| `management` | MDM enrollment status |
| `network` | Network interfaces and connectivity |
| `peripherals` | Connected peripherals |
| `printers` | Installed printers |
| `profiles` | MDM profiles and policies |
| `security` | TPM, BitLocker, Defender status |
| `system` | Operating system information |

## File Locations

### Binaries

```
C:\Program Files\ReportMate\
  managedreportsmanagedreportsrunner.exe         # Main executable
  version.txt        # Build information
```

### Configuration and Data

```
C:\ProgramData\ManagedReports\
  appsettings.yaml   # Configuration file
  logs/              # Log files
  cache/             # Cached collection data
  config/            # Additional configuration
```

### Log Files

Log files are written to `C:\ProgramData\ManagedReports\logs\` with filenames like `reportmate-YYYYMMDD.log`.

## Configuration Options

The `appsettings.yaml` file supports these options:

```yaml
ReportMate:
  # Required
  ApiUrl: "https://reportmate.ecuad.ca"
  
  # Optional
  DeviceId: ""                      # Auto-generated if empty
  Passphrase: ""                    # For authenticated access
  ApiKey: ""                        # API authentication key
  
  # Collection Settings
  CollectionIntervalSeconds: 3600   # 1 hour
  MaxDataAgeMinutes: 30
  ApiTimeoutSeconds: 300            # 5 minutes
  MaxRetryAttempts: 3
  
  # Paths
  OsQueryPath: "C:\\Program Files\\osquery\\osqueryi.exe"
  DataDirectory: "C:\\ProgramData\\ManagedReports"
  LogDirectory: "C:\\ProgramData\\ManagedReports\\logs"
  CacheDirectory: "C:\\ProgramData\\ManagedReports\\cache"
```

### Environment Variables

Configuration can also be set via environment variables with the `REPORTMATE_` prefix:

```powershell
$env:REPORTMATE_API_URL = "https://reportmate.ecuad.ca"
$env:REPORTMATE_PASSPHRASE = "your-passphrase"
```

## Troubleshooting

### osquery Not Found

Install osquery using winget:

```powershell
winget install osquery.osquery --silent
```

Or download from: https://osquery.io/downloads/official

The client will continue to work without osquery but with reduced data collection.

### Permission Errors

The client requires administrator privileges. Run PowerShell as Administrator or use `sudo`:

```powershell
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --collect-only"
```

### Network Connectivity

Test connectivity to the API:

```powershell
Test-NetConnection reportmate.ecuad.ca -Port 443
curl https://reportmate.ecuad.ca/api/health
```

### View Logs

Check the log files for detailed error information:

```powershell
Get-Content "C:\ProgramData\ManagedReports\logs\reportmate-*.log" -Tail 50
```

## Scheduled Collection

The MSI and Chocolatey installers create a scheduled task that runs the client hourly. To verify:

```powershell
Get-ScheduledTask -TaskName "*ReportMate*"
```

To manually trigger collection:

```powershell
Start-ScheduledTask -TaskName "ReportMate Data Collection"
```

## Cimian Integration

When installed alongside Cimian, the client runs automatically as a postflight script after managed software updates. The integration script is installed at:

```
C:\Program Files\Cimian\postflight.ps1
```

## Uninstallation

**Chocolatey:**
```powershell
sudo choco uninstall com.github.reportmate.windows --yes
```

**MSI:**
```powershell
msiexec /x "{ProductCode}" /qn
```

**Manual:**
```powershell
# Remove scheduled task
Unregister-ScheduledTask -TaskName "ReportMate Data Collection" -Confirm:$false

# Remove files
Remove-Item "C:\Program Files\ReportMate" -Recurse -Force
Remove-Item "C:\ProgramData\ManagedReports" -Recurse -Force
```
