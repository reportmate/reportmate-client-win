# ReportMate Build Guide

This repository contains a unified PowerShell 7 build script that replicates the CI/CD pipeline locally and supports all package types.

## Prerequisites

### Required

- **PowerShell 7+**: Download from [Microsoft PowerShell](https://github.com/PowerShell/PowerShell)
- **.NET 8 SDK**: Download from [Microsoft .NET](https://dotnet.microsoft.com/download/dotnet/8.0)

### Optional (for specific package types)

- **Git**: For tagging and version control
- **GitHub CLI**: For release creation - [Download](https://cli.github.com/)

## Quick Start

### Basic Build

```powershell
# Build all packages with auto-generated version (YYYY.MM.DD)
.\build.ps1

# Build with specific version
.\build.ps1 -Version "2024.06.27"

# Clean build (remove previous artifacts)
.\build.ps1 -Clean
```

### Package-Specific Builds

```powershell
# Skip NUPKG creation
.\build.ps1 -SkipNUPKG

# Skip ZIP creation
.\build.ps1 -SkipZIP

# Only build executable (skip all packages)
.\build.ps1 -SkipNUPKG -SkipZIP
```

### Debug and Development

```powershell
# Debug build with verbose output
.\build.ps1 -Configuration Debug -Verbose

# Skip .NET build (use existing build)
.\build.ps1 -SkipBuild
```

### Production Builds with Tagging and Releases

```powershell
# Build and create git tag
.\build.ps1 -CreateTag

# Build, tag, and create GitHub release
.\build.ps1 -CreateTag -CreateRelease

# Full production build with API URL
.\build.ps1 -Version "2024.06.27" -CreateTag -CreateRelease -ApiUrl "https://api.reportmate.com"
```

## Script Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Version` | String | Auto-generated (YYYY.MM.DD) | Version to build |
| `Configuration` | String | "Release" | Build configuration (Release/Debug) |
| `SkipBuild` | Switch | False | Skip the .NET build step |
| `SkipNUPKG` | Switch | False | Skip NUPKG creation |
| `SkipZIP` | Switch | False | Skip ZIP creation |
| `Clean` | Switch | False | Clean all build artifacts first |
| `ApiUrl` | String | Empty | Default API URL to configure |
| `CreateTag` | Switch | False | Create and push git tag (YYYY.MM.DD) |
| `CreateRelease` | Switch | False | Create GitHub release |
| `Verbose` | Switch | False | Enable verbose output |

## Package Types

### 📦 NUPKG Package (`ReportMate-{version}.nupkg`)

- **Purpose**: Chocolatey and Cimian package management
- **Installation**: `choco install ReportMate-{version}.nupkg --source=.`
- **Requirements**: cimipkg (auto-downloaded if missing)
- **Features**: Chocolatey compatible, Cimian integration

### 🗜️ ZIP Archive (`ReportMate-{version}.zip`)

- **Purpose**: Manual installation and testing
- **Installation**: Extract and run `install.bat` as administrator
- **Requirements**: None
- **Features**: Self-contained, no dependencies, easy distribution

### Simple Build
```powershell
# Build with auto-generated date version (YYYY.MM.DD)
.\build.ps1

# Build specific version
.\build.ps1 -Version "2024.06.27"

# Clean build
.\build.ps1 -Clean
```

### Advanced Options
```powershell
# Skip NUPKG creation (if cimipkg not available)
.\build.ps1 -SkipNUPKG

# Build with API URL pre-configured
.\build.ps1 -ApiUrl "https://api.reportmate.com"

# Debug build
.\build.ps1 -Configuration Debug
```

## Output

The build script creates two package types in `dist/`:

### 📦 NUPKG Package (`ReportMate-{version}.nupkg`)  

- **Use Case**: Chocolatey and Cimian package management
- **Installation**: `choco install ReportMate-{version}.nupkg --source=.`
- **Features**: Dependency management, Cimian postflight integration

### 🗜️ ZIP Archive (`ReportMate-{version}.zip`)

- **Use Case**: Manual installation and testing
- **Installation**: Extract and run `install.bat` as administrator
- **Features**: Portable deployment, no installer required

## File Structure

After building, the output structure is:

```text
dist/
├── ReportMate-{version}.nupkg   # Chocolatey package
└── ReportMate-{version}.zip     # ZIP archive

.publish/
└── runner.exe                   # Self-contained executable
```

## Package Contents

All packages deploy the same file structure:

```text
C:\Program Files\ReportMate\
├── runner.exe                   # Main executable
└── version.txt                  # Version information

C:\ProgramData\ManagedReports\
├── appsettings.yaml             # Runtime configuration
├── appsettings.template.yaml    # Enterprise template
└── queries.json                 # OSquery definitions

C:\Program Files\Cimian\         # (NUPKG only)
└── postflight.ps1              # Cimian integration script
```

## CI/CD Integration

The unified build script replicates the GitHub Actions pipeline locally:

### Version Strategy
- **Tagged releases**: Use git tag version (e.g., `v1.0.0` → `1.0.0`)
- **Date-based releases**: Use `YYYY.MM.DD` format
- **Development builds**: Use `YYYY.MM.DD-dev.{build_number}`
- **Manual builds**: Use provided version or auto-generate date

### Automatic Releases
- **Daily builds**: Scheduled at 2 AM UTC on `main` branch
- **Tagged pushes**: Any `v*` or `YYYY.MM.DD*` tag triggers release
- **Manual dispatch**: Can create releases and date-based tags

## Troubleshooting

### cimipkg Issues

```powershell
# The script will auto-download cimipkg, or skip if unavailable
.\build.ps1 -SkipNUPKG
```

### PowerShell Version
```powershell
# Check PowerShell version (requires 7+)
$PSVersionTable.PSVersion

# Install PowerShell 7 on Windows
winget install Microsoft.PowerShell
```

### Build Verification

```powershell
# Test executable
& "C:\Program Files\ReportMate\runner.exe" --help

# Check configuration deployment
Test-Path "C:\ProgramData\ManagedReports\appsettings.yaml"
```

## Development Workflow

1. **Local Development**:
   ```powershell
   .\build.ps1 -Configuration Debug
   ```

2. **Testing Changes**:
   ```powershell
   .\build.ps1 -Clean -Version "test.$(Get-Date -Format 'HHmm')"
   ```

3. **Release Preparation**:
   ```powershell
   .\build.ps1 -Version "2024.06.27" -ApiUrl "https://production-api.reportmate.com"
   ```

4. **Create Release**:
   ```bash
   # Create and push date-based tag
   git tag $(date +%Y.%m.%d)
   git push origin $(date +%Y.%m.%d)
   ```

## Integration Examples

### Group Policy Deployment

```cmd
REM Configure via registry
reg add "HKLM\SOFTWARE\ReportMate" /v "ApiUrl" /t REG_SZ /d "https://api.company.com"
```

### Chocolatey Deployment
```powershell
# Install via Chocolatey
choco install ReportMate --source="https://packages.company.com"

# Update existing installation
choco upgrade ReportMate
```

### Manual Enterprise Deployment
```powershell
# Extract and deploy via PowerShell DSC or similar
Expand-Archive "ReportMate-2024.06.27.zip" -DestinationPath "C:\Temp\ReportMate"
& "C:\Temp\ReportMate\install.bat"
```
