# ReportMatePrefs Package

This package contains a single self-contained PowerShell script that configures ReportMate client preferences during package installation with production credentials from your terraform.tfvars.

## 🚀 Quick Start

### Option 1: Environment Variables (Recommended)
```powershell
# Set environment variables for your configuration
$env:REPORTMATE_API_URL = "https://reportmate.ecuad.ca"
$env:REPORTMATE_PASSPHRASE = "BGXCQm3KN0LZPfnFzAclTt5"
$env:REPORTMATE_DEVICE_PREFIX = "ECUAD"

# Deploy the package
.\Deploy-ReportMatePrefs.ps1 -Environment prod -Deploy
```

### Option 2: Direct Configuration
Edit the variables at the top of `postinstall.ps1` and rebuild the package.

## Package Contents

- `postinstall.ps1` - Self-contained configuration script (runs automatically after install)
- `Deploy-ReportMatePrefs.ps1` - Deployment helper script
- `.env.template` - Environment variables template
- `build-pkg.ps1` - Package build script

## How It Works

1. **Package Installation**: The cimipkg package is installed on the target machine
2. **Automatic Configuration**: `postinstall.ps1` runs automatically with admin privileges
3. **Registry Setup**: ReportMate settings are written to `HKLM\SOFTWARE\Config\ReportMate`
4. **Client Integration**: ReportMate client reads configuration from registry automatically

## Key Features

- ✅ **Zero-touch deployment** - Automatic configuration during package install
- ✅ **Production credentials** - Pre-configured with your terraform.tfvars values
- ✅ **Environment variables** - Override settings via environment variables
- ✅ **Registry integration** - Uses CSP/Group Policy registry location for highest precedence
- ✅ **Device identification** - Automatic device ID generation with organization prefix
- ✅ **API connectivity testing** - Validates configuration after setup

## Configuration Variables

All configuration can be set via environment variables or by editing the script variables:

| Environment Variable | Script Variable | Description | Default |
|---------------------|-----------------|-------------|---------|
| `REPORTMATE_API_URL` | `$DEFAULT_API_URL` | ReportMate API endpoint | https://reportmate.ecuad.ca |
| `REPORTMATE_PASSPHRASE` | `$DEFAULT_PASSPHRASE` | Client authentication passphrase | BGXCQm3KN0LZPfnFzAclTt5 |
| `REPORTMATE_DEVICE_PREFIX` | `$DEFAULT_DEVICE_ID_PREFIX` | Device ID prefix | ECUAD |
| `REPORTMATE_COLLECTION_INTERVAL` | `$DEFAULT_COLLECTION_INTERVAL` | Collection interval (seconds) | 3600 |
| `REPORTMATE_LOG_LEVEL` | `$DEFAULT_LOG_LEVEL` | Logging level | Information |
| `REPORTMATE_AUTO_CONFIGURE` | `$AUTO_CONFIGURE` | Auto-configure during install | true |
| `REPORTMATE_FORCE_CONFIG` | `$FORCE_CONFIGURATION` | Overwrite existing config | true |
| `REPORTMATE_TEST_CONNECTIVITY` | `$TEST_CONNECTIVITY` | Test API after config | true |

## Environment-Based Deployment

### Using Deploy Script
```powershell
# Production deployment
.\Deploy-ReportMatePrefs.ps1 -Environment prod -Deploy

# Test environment  
.\Deploy-ReportMatePrefs.ps1 -Environment test -Deploy

# Development environment
.\Deploy-ReportMatePrefs.ps1 -Environment dev -Deploy
```

### Using Environment Variables Directly
```powershell
# Copy and customize environment template
Copy-Item .env.template .env
# Edit .env with your settings

# Load environment variables (PowerShell)
Get-Content .env | ForEach-Object { 
    $key,$value = $_.Split('=',2)
    [Environment]::SetEnvironmentVariable($key, $value)
}

# Build and deploy
.\build-pkg.ps1
```

## Building the Package

To build this package with `cimipkg`:

```powershell
# Navigate to the package directory
cd ReportMatePrefs-pkg

# Build the package (simplified - no payload copy needed)
.\build-pkg.ps1

# Or with custom version
.\build-pkg.ps1 -Version "1.1.0"
```

## Usage After Installation

The package automatically configures ReportMate during installation. No manual steps required!

### Manual Registry Check
```powershell
# View current configuration
Get-ItemProperty -Path "HKLM:\SOFTWARE\Config\ReportMate" -ErrorAction SilentlyContinue

# Test ReportMate configuration  
& "C:\Program Files\ReportMate\runner.exe" test --verbose
```

## Registry Configuration

The script configures ReportMate settings in the Windows Registry:

- **Primary Location**: `HKLM\SOFTWARE\Config\ReportMate` (CSP/Group Policy)
- **Standard Location**: `HKLM\SOFTWARE\ReportMate`

### Registry Values Set

| Value Name | Type | Description |
|------------|------|-------------|
| `ApiUrl` | REG_SZ | ReportMate API endpoint URL |
| `Passphrase` | REG_SZ | Client authentication passphrase |
| `DeviceId` | REG_SZ | Custom device identifier (optional) |
| `ApiKey` | REG_SZ | API authentication key (optional) |
| `CollectionInterval` | REG_DWORD | Data collection interval in seconds |
| `LogLevel` | REG_SZ | Logging level (Error, Warning, Information, Debug) |
| `OsQueryPath` | REG_SZ | Path to osquery executable |
| `ApiTimeoutSeconds` | REG_DWORD | API request timeout |
| `MaxRetryAttempts` | REG_DWORD | Maximum retry attempts |
| `ValidateSslCert` | REG_DWORD | SSL certificate validation (1=enabled, 0=disabled) |

## Security Considerations

- The script requires administrative privileges to modify registry settings
- Passphrases are stored in the Windows Registry (consider enterprise key management)
- Use HTTPS API endpoints in production
- Validate SSL certificates in production environments

## Integration with ReportMate Client

This configuration package is designed to work with the ReportMate Windows client. After configuration:

1. ReportMate client will read settings from the registry
2. Settings take effect on the next ReportMate run
3. Use `runner.exe test --verbose` to verify configuration
4. Check logs at `C:\ProgramData\ManagedReports\logs\`

## Deployment Scenarios

### Scenario 1: Cimian Package Management
Deploy via Cimian to managed devices with automatic configuration.

### Scenario 2: Manual Configuration
Install package and manually run configuration script with custom parameters.

### Scenario 3: Group Policy Integration
Use with Group Policy for centralized configuration management.

### Scenario 4: MDM/Intune Integration
Combine with Intune OMA-URI policies for enterprise device management.
