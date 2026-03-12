# Application Version Collection Enhancement

## Problem
KeyShot Studio and similar applications were showing incomplete version numbers (e.g., "2025" instead of "2025.3.14.2") in the ReportMate application inventory. The Windows Registry sometimes only stores major versions without minor/patch details.

## Solution
Enhanced the Windows client's `ApplicationsModuleProcessor` to detect incomplete registry versions and fall back to reading the actual executable file's version information.

## Changes Made

### 1. Updated osquery Module Configuration
**Files Modified:**
- `clients/windows/.publish/osquery/modules/applications.json`
- `clients/windows/build/resources/osquery/modules/applications.json`

**Changes:**
- Updated module version from 1.0.0 to 1.1.0
- Updated description to reflect "enhanced version detection"

### 2. Enhanced ApplicationsModuleProcessor
**File Modified:**
- `clients/windows/src/Services/Modules/ApplicationsModuleProcessor.cs`

**New Methods Added:**

#### `GetFileVersionFromInstallLocation(string installLocation, string appName)`
- Searches the install location directory for .exe files
- Attempts to find an executable matching the application name
- Falls back to the first .exe if no exact match
- Extracts the ProductVersion or FileVersion from the executable
- Returns detailed version string if found

#### `IsIncompleteVersion(string version)`
Detects incomplete version strings:
- Returns `true` if version is null/empty
- Returns `true` if version is just a number with no dots (e.g., "2025")
- Returns `true` if version looks like a year with .0 (e.g., "2025.0")
- Returns `false` for complete versions (e.g., "2025.3.14.2")

**Modified Processing Logic:**
The `ProcessModuleAsync` method now:
1. Gets the version from Windows Registry (osquery)
2. Checks if the version seems incomplete using `IsIncompleteVersion()`
3. If incomplete AND install_location exists, calls `GetFileVersionFromInstallLocation()`
4. Uses the enhanced file version if found, otherwise keeps the registry version

## How It Works

### Before
```
Windows Registry → osquery → "2025" → Stored as "2025"
```

### After
```
Windows Registry → osquery → "2025" 
  ↓ (Detected as incomplete)
Install Location → Find KeyShot.exe → Read FileVersionInfo → "2025.3.14.2"
  ↓
Stored as "2025.3.14.2"
```

## Benefits

1. **More Accurate Version Tracking**: Applications with incomplete registry entries now show full version numbers
2. **Better Version Analytics**: The web dashboard can now differentiate between minor versions (e.g., 2025.2.14.1 vs 2025.3.14.2)
3. **Backward Compatible**: Apps with complete registry versions are unaffected
4. **Robust Fallback**: If file version cannot be read, it gracefully falls back to registry version
5. **Minimal Performance Impact**: Only processes applications with incomplete versions

## Applications That Will Benefit

Based on the device logs, applications with year-based versioning will benefit most:
- **KeyShot**: 2025 → 2025.3.14.2
- **Maya**: Potentially better subversion detection
- **Houdini**: More detailed version tracking
- **Various Creative Cloud apps**: Better version granularity

## Testing

To test the enhancement:

1. Build and deploy the updated Windows client
2. Wait for the next applications module collection cycle (runs every hour)
3. Check the web dashboard's "Version Distribution" widget
4. KeyShot Studio should now show detailed versions like "2025.3.14.2" instead of just "2025"

## Performance Considerations

- File version lookup only happens for applications with incomplete registry versions
- Only top-level directory is searched (no recursive search)
- Failures are caught and logged at trace level
- No impact on data collection if file version lookup fails

## Future Enhancements

Potential improvements:
1. Cache file version lookups to avoid repeated file system access
2. Add configuration to enable/disable file version fallback
3. Extend to check alternate executable naming patterns
4. Add metrics to track how often fallback is used
