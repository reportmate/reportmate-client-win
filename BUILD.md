# ReportMate Build Guide

This repository contains a unified PowerShell 7 build script that replicates the CI/CD pipeline locally and supports all package types.

The [Building and Releasing](https://github.com/reportmate/reportmate-client-win/wiki/Building-and-Releasing) wiki page covers the same ground in more depth, including signing and versioning.

## Prerequisites

### Required

- **PowerShell 7+**: Download from [Microsoft PowerShell](https://github.com/PowerShell/PowerShell). `build.ps1` declares `#Requires -Version 7.0` and exits on Windows PowerShell 5.1.
- **.NET 10 SDK**: Download from [Microsoft .NET](https://dotnet.microsoft.com/download/dotnet/10.0). Every project in the solution targets `net10.0-windows`.

### Optional (for specific package types)

- **cimipkg**: Builds both the MSI and the NUPKG. `build.ps1` downloads the matching `cimipkg-win-x64.zip` or `cimipkg-win-arm64.zip` from the latest [cimian-pkg release](https://github.com/windowsadmins/cimian-pkg/releases) if it is not on `PATH` or in the repo root.
- **NuGet CLI**: On `PATH`, for the NUPKG step.
- **A code signing certificate** in `Cert:\CurrentUser\My`, for `-Sign`. Certificate selection is driven by the `ENTERPRISE_CERT_CN` environment variable; without it the script refuses to pick a certificate rather than sign with an arbitrary one.
- **Git**: For version control.
- **GitHub CLI**: For release creation - [Download](https://cli.github.com/)

There is no WiX Toolset dependency. Everything a WiX custom action would have done — `PATH`, registry, scheduled tasks, osquery deployment — lives in `build/pkg/scripts/postinstall.ps1`.

## Quick Start

### Basic Build

Build all packages with an auto-generated version (`YYYY.MM.DD.HHMM`):

```powershell
.\build.ps1
```

Build a specific version:

```powershell
.\build.ps1 -Version "2026.09.03.1430"
```

Clean build, removing previous artifacts first:

```powershell
.\build.ps1 -Clean
```

### Package-Specific Builds

Skip the MSI:

```powershell
.\build.ps1 -SkipMSI
```

Skip NUPKG and ZIP creation:

```powershell
.\build.ps1 -SkipNUPKG -SkipZIP
```

Build only the executables, which is what CI does:

```powershell
.\build.ps1 -NoSign -SkipMSI -SkipNUPKG -SkipZIP -Configuration Release
```

### Debug and Development

Debug build with verbose output:

```powershell
.\build.ps1 -Configuration Debug -Verbose
```

Reuse the existing .NET output and just repackage:

```powershell
.\build.ps1 -SkipBuild
```

### Signing

Signing is automatic when a suitable certificate is found in `Cert:\CurrentUser\My`. Force it on, or off:

```powershell
.\build.ps1 -Sign
```

```powershell
.\build.ps1 -NoSign
```

Select a specific certificate:

```powershell
.\build.ps1 -Sign -Thumbprint "<sha1-thumbprint>"
```

### Releases

Create a GitHub release from the built artifacts with `gh`:

```powershell
.\build.ps1 -CreateRelease
```

## Script Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Version` | String | Auto-generated (YYYY.MM.DD.HHMM) | Version to build |
| `Configuration` | String | "Release" | Build configuration (Release/Debug) |
| `SkipBuild` | Switch | False | Skip the .NET build step |
| `SkipMSI` | Switch | False | Skip MSI creation |
| `SkipNUPKG` | Switch | False | Skip NUPKG creation |
| `SkipZIP` | Switch | False | Skip ZIP creation |
| `Clean` | Switch | False | Clean all build artifacts first |
| `ApiUrl` | String | Empty | Default API URL. Currently only echoed in the build summary — the MSI takes its API URL from the bundled `.env` |
| `Sign` | Switch | Off | Force code signing of the executable |
| `NoSign` | Switch | Off | Disable auto-signing even if a certificate is found |
| `Thumbprint` | String | Auto-detect | Use a specific certificate thumbprint |
| `Import` | Switch | False | Import the built MSI into a downstream Cimian deployment repo via `cimiimport --nointeractive` |
| `Install` | Switch | False | Install the built MSI locally (requires admin) |
| `CreateTag` | Switch | False | Accepted, but tag creation is currently disabled in the script |
| `CreateRelease` | Switch | False | Create GitHub release |
| `Verbose` | Switch | False | Enable verbose output |

## Package Types

### 💿 MSI Installer (`ReportMate-{version}.msi`)

- **Purpose**: Enterprise deployment via MDM, SCCM or Intune. This is the primary artifact.
- **Installation**: `msiexec /i ReportMate-{version}.msi /quiet`
- **Requirements**: cimipkg (auto-downloaded if missing)
- **Built from**: `build/pkg/`

### 📦 NUPKG Package (`ReportMate-{version}.nupkg`)

- **Purpose**: Chocolatey and Cimian package management
- **Requirements**: cimipkg (auto-downloaded if missing), NuGet CLI on `PATH`
- **Built from**: `build/nupkg/`

### 🗜️ ZIP Archive (`ReportMate-{version}.zip`)

- **Purpose**: Manual installation and testing
- **Installation**: Extract and run the generated `install.bat` as administrator
- **Requirements**: None

## Output

The build script creates three package types in `release/`:

```text
release/
├── ReportMate-{version}.msi     # Windows installer (primary)
├── ReportMate-{version}.nupkg   # Chocolatey/Cimian package
└── ReportMate-{version}.zip     # ZIP archive

.publish/
└── managedreportsrunner.exe     # Self-contained executable
```

After the MSI is produced, `build.ps1` opens its File table and verifies that every file `build/pkg/scripts/postinstall.ps1` lists in `$expectedPayload` is present. A payload gap fails the build rather than shipping an MSI that disables collection at install time.

## Package Contents

All packages deploy the same file structure:

```text
C:\Program Files\ReportMate\
├── managedreportsrunner.exe     # Main executable
├── usagetracker.exe             # Per-user session companion
├── speedtest.exe                # Ookla Speedtest CLI
├── appsettings.yaml             # Configuration seed
├── appsettings.template.yaml    # Enterprise template
├── module-schedules.json        # Module-to-schedule mapping
├── version.txt                  # Version information
└── osquery\                     # Query packs (copied to ProgramData on install)

C:\ProgramData\ManagedReports\
├── appsettings.yaml             # Runtime configuration
├── appsettings.template.yaml    # Enterprise template
├── config\ logs\ cache\ data\   # Created by postinstall.ps1
└── osquery\                     # Modular osquery configuration
    ├── enabled-modules.json     # Module configuration
    └── modules\                 # One file per module
        ├── applications.json
        ├── hardware.json
        ├── identity.json
        ├── installs.json
        ├── inventory.json
        ├── management.json
        ├── network.json
        ├── peripherals.json
        ├── security.json
        └── system.json

C:\Program Files\Cimian\
└── postflight.ps1               # Cimian integration script
```

## CI/CD Integration

The unified build script is what the GitHub Actions workflows run.

### Version Strategy

Versions are date stamps in `YYYY.MM.DD.HHMM` format. `build.ps1` passes an explicit one to MSBuild via `-p:VersionPrefix=`; the `.csproj` generates one from the current time when none is supplied.

Per-module versions are generated separately into `src/Generated/ModuleVersions.g.cs` before compiling, from the last commit date touching each module's files. The client does not compile without that file, which is why CI runs `build.ps1` before `dotnet test`.

### Workflows

- **`ci.yml`**: pull requests to `main` and pushes to `main`. Runs `.\build.ps1 -NoSign -SkipMSI -SkipNUPKG -SkipZIP -Configuration Release`, then the xUnit test project. There is no scheduled build.
- **`release.yml`**: pushed tags matching `v*` or a bare `YYYY.MM.DD.NNNN` date stamp. Runs `.\build.ps1 -NoSign`, then creates the GitHub release and uploads every `.msi`, `.nupkg` and `.zip` under `release/`.

Release artifacts are unsigned; the generated release notes carry the `signtool` commands for signing them with your own certificate.

## Troubleshooting

### cimipkg Issues

The script auto-downloads cimipkg. To build without it, skip the packages it produces:

```powershell
.\build.ps1 -SkipMSI -SkipNUPKG
```

### PowerShell Version

Check the PowerShell version — 7 or later is required:

```powershell
$PSVersionTable.PSVersion
```

Install PowerShell 7 on Windows:

```powershell
winget install Microsoft.PowerShell
```

### Build Verification

Print the version of the built executable:

```powershell
& ".publish\managedreportsrunner.exe" version
```

Check the configuration deployment on an installed machine:

```powershell
Test-Path "C:\ProgramData\ManagedReports\appsettings.yaml"
```

## Development Workflow

Local development build:

```powershell
.\build.ps1 -Configuration Debug -NoSign -SkipMSI -SkipNUPKG -SkipZIP
```

Run the tests, after a build has generated `ModuleVersions.g.cs`:

```powershell
dotnet test tests\ReportMate.WindowsClient.Tests\ReportMate.WindowsClient.Tests.csproj --configuration Release
```

Release preparation:

```powershell
.\build.ps1 -Clean -Version "2026.09.03.1430"
```

Create and push a date-stamp tag to trigger the release workflow:

```bash
git tag $(date +%Y.%m.%d.%H%M)
git push origin $(date +%Y.%m.%d.%H%M)
```

## Integration Examples

### Group Policy Deployment

Configure via the registry:

```cmd
reg add "HKLM\SOFTWARE\Config\ReportMate" /v "ApiUrl" /t REG_SZ /d "https://api.example.com"
```

### Manual Enterprise Deployment

Extract the ZIP and run its generated installer:

```powershell
Expand-Archive "ReportMate-2026.09.03.1430.zip" -DestinationPath "C:\Temp\ReportMate"
```

```powershell
& "C:\Temp\ReportMate\install.bat"
```
