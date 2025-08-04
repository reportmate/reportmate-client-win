# WiX v6.0.1 Upgrade Summary

## Overview
Successfully upgraded the ReportMate MSI build system from WiX v3 to WiX v6.0.1 for future-proofing and enhanced capabilities.

## Changes Made

### 1. WiX Source File (`build/msi/ReportMate.wxs`)
- **Updated XML namespace**: Changed from `http://schemas.microsoft.com/wix/2006/wi` to `http://wixtoolset.org/schemas/v4/wxs`
- **New Package element**: WiX v6 uses `<Package>` as root element instead of `<Product>`
- **Simplified directory structure**: Uses `<StandardDirectory>` instead of nested `<Directory>` elements
- **Custom actions for scheduled tasks**: Replaced deprecated `<util:TaskScheduler>` with PowerShell custom actions
- **Improved media handling**: Uses explicit `<Media>` element instead of `<MediaTemplate>`

### 2. Build Script Updates (`build.ps1`)
- **Dual WiX support**: Automatically detects and uses either WiX v6 or WiX v3
- **Updated detection logic**: Checks for `wix.exe` (v6) first, falls back to `candle.exe`/`light.exe` (v3)
- **New build commands**: Uses `wix.exe build` for v6, maintains legacy commands for v3
- **Enhanced path detection**: Searches for WiX v6 installations in common locations

### 3. Installation Script (`install-wix-v6.ps1`)
- **Automated WiX v6 installation**: Installs WiX as .NET global tool
- **Prerequisites check**: Verifies .NET 8 SDK is available
- **Version validation**: Confirms successful installation

### 4. Project Files
- **New WiX v6 project**: `ReportMateV6.wixproj` using modern SDK-style format
- **Package references**: Uses WiX.Extensions.Util v6.0.1

### 5. Documentation Updates
- **Updated prerequisites**: Now recommends WiX v6.0.1
- **Installation instructions**: Provides both WiX v6 and v3 installation options
- **Build compatibility**: Notes automatic version detection

## Benefits of WiX v6

1. **Future-proof**: Latest WiX version with ongoing support
2. **Modern tooling**: Uses .NET global tools for easy installation
3. **Simplified syntax**: Cleaner, more intuitive authoring experience
4. **Better error messages**: Improved diagnostics and troubleshooting
5. **SDK-style projects**: Modern MSBuild integration
6. **Backward compatibility**: Build script supports both v6 and v3

## Installation

### Quick Install (Recommended)
```powershell
.\install-wix-v6.ps1
```

### Manual Install
```powershell
dotnet tool install --global wix --version 6.0.1
```

## Build Commands

All existing build commands work unchanged:

```powershell
# MSI only
.\build.ps1 -SkipNUPKG -SkipZIP -Sign

# All packages
.\build.ps1 -Sign
```

## Version Detection

The build script automatically detects available WiX versions:
- **First choice**: WiX v6 (`wix.exe`)
- **Fallback**: WiX v3 (`candle.exe` + `light.exe`)
- **Build process**: Uses appropriate commands for detected version

## Testing

- ✅ Build script detects WiX v6.0.1 correctly
- ✅ Version conversion (2025.08.03 → 25.8.3) works with both versions
- ✅ Scheduled task installation via PowerShell custom actions
- ✅ Backward compatibility with WiX v3 maintained

## Migration Notes

- **No breaking changes**: Existing WiX v3 installations continue to work
- **Gradual migration**: Teams can upgrade at their own pace
- **Same output**: Generated MSI packages remain functionally identical
- **Enhanced features**: WiX v6 provides better tooling experience

The ReportMate build system is now future-ready with WiX v6 while maintaining full backward compatibility!
