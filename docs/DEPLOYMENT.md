# ReportMate Windows Client Deployment Guide

This guide provides instructions for deploying the ReportMate Windows client across your organization.

## Overview

The ReportMate Windows client (`managedreportsmanagedreportsrunner.exe`) collects system information using osquery and transmits it to the ReportMate API. The client is a self-contained .NET 8 executable that can be deployed via:

- Chocolatey package (`.nupkg`) - Recommended for Cimian environments
- MSI installer - Recommended for Group Policy/Intune deployment
- ZIP archive - Manual installation

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- Administrator privileges for installation
- Network access to the ReportMate API server
- Optional: osquery for enhanced data collection

## Building Packages

Build signed packages using the unified build script:

```powershell
cd clients\windows
.\build.ps1 -Sign
```

**Output packages in `dist/`:**
- `ReportMate-{version}.nupkg` - Chocolatey package
- `ReportMate-{version}.msi` - MSI installer
- `ReportMate-{version}.zip` - ZIP archive

**Build options:**
```powershell
# Skip specific package types
.\build.ps1 -Sign -SkipMSI
.\build.ps1 -Sign -SkipNUPKG -SkipZIP

# Build and install immediately
.\build.ps1 -Sign -Install

# Clean build
.\build.ps1 -Sign -Clean
```

## Deployment Methods

### Method 1: Chocolatey Package (Recommended)

Best for environments using Cimian or Chocolatey for package management.

**Local installation:**
```powershell
sudo choco install com.github.reportmate.windows --source=".\dist\" --yes --force
```

**Network share installation:**
```powershell
choco install com.github.reportmate.windows --source="\\server\share\packages" --yes
```

### Method 2: MSI Installer

Best for Group Policy or Intune deployment.

**Silent installation:**
```powershell
msiexec /i "ReportMate-{version}.msi" /qn APIURL="https://reportmate.ecuad.ca"
```

**Group Policy deployment:**
1. Copy MSI to a network share accessible by target computers
2. Create a Group Policy Object (GPO)
3. Navigate to Computer Configuration > Policies > Software Settings > Software Installation
4. Add the MSI package

**Intune deployment:**
1. Upload the MSI to Intune as a Line-of-business app
2. Configure installation command: `msiexec /i "ReportMate.msi" /qn`
3. Assign to device groups

### Method 3: Manual Installation

For testing or small-scale deployments.

```powershell
# Extract ZIP
Expand-Archive "ReportMate-{version}.zip" -DestinationPath "C:\Program Files\ReportMate"

# Create data directories
New-Item -ItemType Directory -Path "C:\ProgramData\ManagedReports\logs" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\ManagedReports\cache" -Force

# Copy configuration
Copy-Item "appsettings.yaml" "C:\ProgramData\ManagedReports\"

# Create scheduled task
$action = New-ScheduledTaskAction -Execute "C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe"
$trigger = New-ScheduledTaskTrigger -Daily -At "8:00AM"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "ReportMate Data Collection" -Action $action -Trigger $trigger -Principal $principal
```

## Configuration

### Configuration File

The primary configuration file is `C:\ProgramData\ManagedReports\appsettings.yaml`:

```yaml
ReportMate:
  ApiUrl: "https://reportmate.ecuad.ca"
  Passphrase: ""                    # Optional authentication
  CollectionIntervalSeconds: 3600   # 1 hour
  MaxRetryAttempts: 3
```

### Registry Configuration

Settings can also be managed via registry at `HKLM\SOFTWARE\Config\ReportMate`:

| Value | Type | Description |
|-------|------|-------------|
| ApiUrl | REG_SZ | API endpoint URL |
| Passphrase | REG_SZ | Authentication passphrase |
| DeviceId | REG_SZ | Custom device identifier |

### MDM/CSP Configuration

For Intune or other MDM solutions, use OMA-URI settings:

```
./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/ApiUrl
Type: String
Value: https://reportmate.ecuad.ca

./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/Passphrase
Type: String
Value: your-passphrase
```

### Environment Variables

Configuration can be set via environment variables:

```powershell
$env:REPORTMATE_API_URL = "https://reportmate.ecuad.ca"
$env:REPORTMATE_PASSPHRASE = "your-passphrase"
```

## Scheduled Task

The installers create a scheduled task named "ReportMate Data Collection" that runs hourly under the SYSTEM account.

**Verify the task:**
```powershell
Get-ScheduledTask -TaskName "ReportMate Data Collection"
```

**Manually trigger collection:**
```powershell
Start-ScheduledTask -TaskName "ReportMate Data Collection"
```

## Verification

After deployment, verify the installation:

```powershell
# Check installation
Test-Path "C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe"

# View version
& "C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe" version

# Test collection (run as admin)
sudo pwsh -c "& 'C:\Program Files\ReportMate\managedreportsmanagedreportsrunner.exe' -vv --collect-only"

# Check scheduled task
Get-ScheduledTask -TaskName "ReportMate Data Collection" | Get-ScheduledTaskInfo
```

## Uninstallation

**Chocolatey:**
```powershell
sudo choco uninstall com.github.reportmate.windows --yes
```

**MSI:**
```powershell
msiexec /x "{ProductCode}" /qn
# Or via Programs and Features
```

**Manual:**
```powershell
Unregister-ScheduledTask -TaskName "ReportMate Data Collection" -Confirm:$false
Remove-Item "C:\Program Files\ReportMate" -Recurse -Force
Remove-Item "C:\ProgramData\ManagedReports" -Recurse -Force
Remove-Item "HKLM:\SOFTWARE\Config\ReportMate" -Recurse -Force -ErrorAction SilentlyContinue
```

## Troubleshooting

### Check Logs

```powershell
Get-Content "C:\ProgramData\ManagedReports\logs\reportmate-*.log" -Tail 100
```

### Test Connectivity

```powershell
Test-NetConnection reportmate.ecuad.ca -Port 443
Invoke-RestMethod "https://reportmate.ecuad.ca/api/health"
```

### Common Issues

**Issue: Client not running**
- Verify scheduled task is enabled: `Get-ScheduledTask -TaskName "ReportMate*"`
- Check task history in Task Scheduler

**Issue: Data not appearing in dashboard**
- Verify API URL in configuration
- Check logs for transmission errors
- Test API connectivity

**Issue: osquery errors**
- Install osquery: `winget install osquery.osquery --silent`
- The client works without osquery but with reduced data collection

## Security Considerations

1. **Use authentication** - Configure a passphrase for production deployments
2. **HTTPS only** - The client only communicates over HTTPS
3. **Signed binaries** - Always deploy signed executables
4. **Least privilege** - The scheduled task runs as SYSTEM but only needs read access to collect data
5. **Secure distribution** - Distribute passphrases via MDM/GPO, not in scripts

## Enterprise Deployment Checklist

- [ ] Build signed packages with `.\build.ps1 -Sign`
- [ ] Configure API URL
- [ ] Generate authentication passphrase
- [ ] Test on pilot machines
- [ ] Deploy via chosen method (Chocolatey/MSI/Manual)
- [ ] Verify data appears in dashboard
- [ ] Document deployment parameters
- [ ] Set up monitoring for client health
