#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// System module processor - Operating system information
    /// </summary>
    public class SystemModuleProcessor : BaseModuleProcessor<SystemData>
    {
        private readonly ILogger<SystemModuleProcessor> _logger;

        public override string ModuleId => "system";

        public SystemModuleProcessor(ILogger<SystemModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<SystemData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing System module for device {DeviceId}", deviceId);

            var data = new SystemData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process operating system info
            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Count > 0)
            {
                var os = osVersion[0];
                data.OperatingSystem.Name = GetStringValue(os, "name");
                data.OperatingSystem.Version = GetStringValue(os, "version");
                data.OperatingSystem.Build = GetStringValue(os, "build");
                data.OperatingSystem.Architecture = GetStringValue(os, "arch");
                data.OperatingSystem.Major = GetIntValue(os, "major");
                data.OperatingSystem.Minor = GetIntValue(os, "minor");
                data.OperatingSystem.Patch = GetIntValue(os, "patch");

                // Process install date if available
                var installDateStr = GetStringValue(os, "install_date");
                if (!string.IsNullOrEmpty(installDateStr) && long.TryParse(installDateStr, out var installDateUnix))
                {
                    data.OperatingSystem.InstallDate = DateTimeOffset.FromUnixTimeSeconds(installDateUnix).DateTime;
                }
            }

            // Process display version from registry
            if (osqueryResults.TryGetValue("display_version", out var displayVersion))
            {
                foreach (var entry in displayVersion)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name == "DisplayVersion" && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.DisplayVersion = regData;
                        break;
                    }
                    else if (name == "ReleaseId" && !string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.OperatingSystem.DisplayVersion))
                    {
                        data.OperatingSystem.DisplayVersion = regData;
                    }
                }
            }

            // Process OS edition from registry
            if (osqueryResults.TryGetValue("os_edition", out var osEdition))
            {
                foreach (var entry in osEdition)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name == "EditionID" && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.Edition = regData;
                        break;
                    }
                    else if (name == "ProductName" && !string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.OperatingSystem.Edition))
                    {
                        data.OperatingSystem.Edition = regData;
                    }
                }
            }

            // Process locale and timezone info
            if (osqueryResults.TryGetValue("locale_info", out var localeInfo))
            {
                foreach (var entry in localeInfo)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name == "TimeZoneKeyName" && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.TimeZone = regData;
                    }
                    else if (name == "LocaleName" && !string.IsNullOrEmpty(regData))
                    {
                        // This should give us the proper locale format like "en-CA"
                        data.OperatingSystem.Locale = regData;
                    }
                    else if (name == "sLanguage" && !string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.OperatingSystem.Locale))
                    {
                        // Fallback to language code if LocaleName is not available
                        data.OperatingSystem.Locale = regData;
                    }
                    else if (name == "Default" && !string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.OperatingSystem.Locale))
                    {
                        // Final fallback to LCID if nothing else is available
                        data.OperatingSystem.Locale = regData;
                    }
                }
            }

            // Process keyboard layouts - only get user preloaded layouts (not all system layouts)
            _logger.LogDebug("Processing keyboard layouts from osquery results");
            if (osqueryResults.TryGetValue("keyboard_layouts", out var keyboardLayouts) && keyboardLayouts.Any())
            {
                _logger.LogDebug("Found {Count} keyboard layout entries from osquery", keyboardLayouts.Count);
                foreach (var entry in keyboardLayouts)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    var path = GetStringValue(entry, "path");
                    
                    _logger.LogDebug("Keyboard layout entry: name='{Name}', data='{Data}', path='{Path}'", name, regData, path);
                    
                    // Process preload entries (user's installed layouts) - registry names are like "1", "2", etc.
                    // The actual path would be something like "HKEY_USERS\S-1-...\Keyboard Layout\Preload\1"
                    if (!string.IsNullOrEmpty(regData) && regData.Length == 8)
                    {
                        var layoutName = MapKeyboardLayoutId(regData);
                        _logger.LogDebug("Mapped keyboard layout '{LayoutId}' to '{LayoutName}'", regData, layoutName);
                        if (!data.OperatingSystem.KeyboardLayouts.Contains(layoutName))
                        {
                            data.OperatingSystem.KeyboardLayouts.Add(layoutName);
                            _logger.LogDebug("Added keyboard layout: {LayoutName}", layoutName);
                        }
                    }
                    else
                    {
                        _logger.LogDebug("Skipping keyboard layout entry: data is null or wrong length={DataLength}", regData?.Length);
                    }
                }
                
                _logger.LogDebug("Total keyboard layouts after processing: {Count}", data.OperatingSystem.KeyboardLayouts.Count);
            }
            else
            {
                // Fallback: Use .NET Registry to get keyboard layouts when osquery queries fail
                _logger.LogDebug("No keyboard layouts from osquery, using .NET registry fallback");
                try
                {
                    var keyboardLayoutIds = GetKeyboardLayoutsViaPowerShell();
                    _logger.LogDebug("Found {Count} keyboard layouts via .NET registry", keyboardLayoutIds.Count);
                    foreach (var layoutId in keyboardLayoutIds)
                    {
                        var layoutName = MapKeyboardLayoutId(layoutId);
                        if (!data.OperatingSystem.KeyboardLayouts.Contains(layoutName))
                        {
                            data.OperatingSystem.KeyboardLayouts.Add(layoutName);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to get keyboard layouts via .NET registry fallback");
                }
            }

            // Process active keyboard layout
            if (osqueryResults.TryGetValue("active_keyboard_layout", out var activeLayout) && activeLayout.Any())
            {
                foreach (var entry in activeLayout)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name == "Layout Hotkey" && !string.IsNullOrEmpty(regData))
                    {
                        // The hotkey value corresponds to the index in the preloaded layouts
                        if (int.TryParse(regData, out var layoutIndex) && layoutIndex > 0 && layoutIndex <= data.OperatingSystem.KeyboardLayouts.Count)
                        {
                            // Index is 1-based, so subtract 1 for 0-based array access
                            data.OperatingSystem.ActiveKeyboardLayout = data.OperatingSystem.KeyboardLayouts[layoutIndex - 1];
                        }
                        break;
                    }
                }
            }
            else if (data.OperatingSystem.KeyboardLayouts.Count > 0)
            {
                // Fallback: Use the first layout as active if no hotkey registry found
                data.OperatingSystem.ActiveKeyboardLayout = data.OperatingSystem.KeyboardLayouts[0];
            }

            // If no active layout found from hotkey registry, use the first preloaded layout
            if (string.IsNullOrEmpty(data.OperatingSystem.ActiveKeyboardLayout) && data.OperatingSystem.KeyboardLayouts.Count > 0)
            {
                data.OperatingSystem.ActiveKeyboardLayout = data.OperatingSystem.KeyboardLayouts[0];
            }

            // Don't process system keyboard layouts anymore - they add too many unused layouts
            // The user's actual layouts are captured in the preload section above

            // Process Windows services
            if (osqueryResults.TryGetValue("services", out var services))
            {
                foreach (var service in services)
                {
                    var serviceInfo = new SystemService
                    {
                        Name = GetStringValue(service, "name"),
                        DisplayName = GetStringValue(service, "display_name"),
                        Description = GetStringValue(service, "description"),
                        Status = GetStringValue(service, "status"),
                        StartType = GetStringValue(service, "start_type"),
                        Path = GetStringValue(service, "path")
                    };
                    
                    data.Services.Add(serviceInfo);
                }
            }

            // Process environment variables
            if (osqueryResults.TryGetValue("environment_variables", out var envVars))
            {
                foreach (var envVar in envVars)
                {
                    var environmentVariable = new EnvironmentVariable
                    {
                        Name = GetStringValue(envVar, "name"),
                        Value = GetStringValue(envVar, "value")
                    };
                    
                    data.Environment.Add(environmentVariable);
                }
            }

            // Process Windows updates/patches
            if (osqueryResults.TryGetValue("windows_patches", out var patches))
            {
                foreach (var patch in patches)
                {
                    var update = new SystemUpdate
                    {
                        Id = GetStringValue(patch, "hotfix_id"),
                        Title = GetStringValue(patch, "description"),
                        Category = "Windows Update"
                    };

                    var installedOnStr = GetStringValue(patch, "installed_on");
                    if (!string.IsNullOrEmpty(installedOnStr) && DateTime.TryParse(installedOnStr, out var installedOn))
                    {
                        update.InstallDate = installedOn;
                    }
                    
                    data.Updates.Add(update);
                }
            }

            // Process feature update information - get UBR and build to construct proper experience pack version
            string buildNumber = "";
            string ubrNumber = "";
            
            if (osqueryResults.TryGetValue("detailed_build", out var buildInfo))
            {
                foreach (var entry in buildInfo)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name == "CurrentBuild" && !string.IsNullOrEmpty(regData))
                    {
                        buildNumber = regData;
                    }
                    else if (name == "UBR" && !string.IsNullOrEmpty(regData))
                    {
                        ubrNumber = regData;
                    }
                }
            }
            
            // Build the experience pack version in the format: Windows Feature Experience Pack 1000.{build}.{ubr}.0
            if (!string.IsNullOrEmpty(buildNumber) && !string.IsNullOrEmpty(ubrNumber))
            {
                data.OperatingSystem.FeatureUpdate = $"Windows Feature Experience Pack 1000.{buildNumber}.{ubrNumber}.0";
            }
            else if (osqueryResults.TryGetValue("experience_pack", out var experiencePack))
            {
                foreach (var entry in experiencePack)
                {
                    var path = GetStringValue(entry, "path");
                    var regData = GetStringValue(entry, "data");
                    
                    if (path?.Contains("WindowsFeatureExperience") == true && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.FeatureUpdate = $"Windows Feature Experience Pack {regData}";
                        break;
                    }
                }
                
                // If no Feature Experience Pack found, Windows 11+ doesn't use traditional service packs
                if (string.IsNullOrEmpty(data.OperatingSystem.FeatureUpdate))
                {
                    // For Windows 11, the DisplayVersion (like "24H2") serves as the feature update identifier
                    if (!string.IsNullOrEmpty(data.OperatingSystem.DisplayVersion))
                    {
                        data.OperatingSystem.FeatureUpdate = $"Feature Update {data.OperatingSystem.DisplayVersion}";
                    }
                    else
                    {
                        data.OperatingSystem.FeatureUpdate = "No feature update information available";
                    }
                }
            }

            // Process uptime directly if available
            if (osqueryResults.TryGetValue("uptime", out var uptime) && uptime.Count > 0)
            {
                var uptimeInfo = uptime[0];
                var totalSeconds = GetIntValue(uptimeInfo, "total_seconds");
                if (totalSeconds > 0)
                {
                    data.Uptime = TimeSpan.FromSeconds(totalSeconds);
                    data.UptimeString = FormatUptime(data.Uptime.Value);
                    data.LastBootTime = DateTime.UtcNow - data.Uptime.Value;
                }
            }

            // Process system info for additional details
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                var bootTimeStr = GetStringValue(info, "boot_time");
                if (!string.IsNullOrEmpty(bootTimeStr) && long.TryParse(bootTimeStr, out var bootTimeUnix))
                {
                    data.LastBootTime = DateTimeOffset.FromUnixTimeSeconds(bootTimeUnix).DateTime;
                    data.Uptime = DateTime.UtcNow - data.LastBootTime.Value;
                    data.UptimeString = FormatUptime(data.Uptime.Value);
                }
            }

            _logger.LogInformation("System module processed - OS: {OS} {Version}, Edition: {Edition}, DisplayVersion: {DisplayVersion}, Locale: {Locale}, TimeZone: {TimeZone}, Uptime: {Uptime}", 
                data.OperatingSystem.Name, data.OperatingSystem.Version, data.OperatingSystem.Edition, 
                data.OperatingSystem.DisplayVersion, data.OperatingSystem.Locale, data.OperatingSystem.TimeZone, data.UptimeString);

            return Task.FromResult(data);
        }

        private string FormatUptime(TimeSpan uptime)
        {
            if (uptime.TotalDays >= 1)
                return $"{(int)uptime.TotalDays} days, {uptime.Hours} hours, {uptime.Minutes} minutes";
            else if (uptime.TotalHours >= 1)
                return $"{uptime.Hours} hours, {uptime.Minutes} minutes";
            else
                return $"{uptime.Minutes} minutes";
        }

        public override async Task<bool> ValidateModuleDataAsync(SystemData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && 
                         data.ModuleId == ModuleId &&
                         !string.IsNullOrEmpty(data.OperatingSystem.Name);

            if (!isValid)
            {
                _logger.LogWarning("System module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        /// <summary>
        /// Maps keyboard layout IDs to readable names
        /// </summary>
        private string MapKeyboardLayoutId(string layoutId)
        {
            if (string.IsNullOrEmpty(layoutId))
                return "Unknown";

            // Common Windows keyboard layout IDs
            var layouts = new Dictionary<string, string>
            {
                ["00000409"] = "English (United States)",
                ["00001009"] = "English (Canada)",
                ["00000809"] = "English (United Kingdom)",
                ["0000040c"] = "French (France)",
                ["00000c0c"] = "French (Canada)",
                ["00000407"] = "German (Germany)",
                ["0000040a"] = "Spanish (Spain)",
                ["0000080a"] = "Spanish (Mexico)",
                ["00000410"] = "Italian (Italy)",
                ["00000413"] = "Dutch (Netherlands)",
                ["00000416"] = "Portuguese (Brazil)",
                ["00000816"] = "Portuguese (Portugal)",
                ["00000419"] = "Russian",
                ["00000411"] = "Japanese",
                ["00000412"] = "Korean",
                ["00000804"] = "Chinese (Simplified)",
                ["00000404"] = "Chinese (Traditional)",
                ["0000041f"] = "Turkish",
                ["0000041d"] = "Swedish",
                ["0000041e"] = "Thai",
                ["00000401"] = "Arabic (Saudi Arabia)",
                ["0000040d"] = "Hebrew"
            };

            // Try exact match first
            if (layouts.TryGetValue(layoutId.ToUpperInvariant(), out var layoutName))
            {
                return layoutName;
            }

            // Try partial match (first 8 characters for primary language)
            if (layoutId.Length >= 8)
            {
                var primaryId = layoutId.Substring(0, 8).ToUpperInvariant();
                if (layouts.TryGetValue(primaryId, out var primaryLayoutName))
                {
                    return primaryLayoutName;
                }
            }

            // Return the original ID if no mapping found
            return $"Layout {layoutId}";
        }

        /// <summary>
        /// Gets keyboard layouts using .NET registry access when osquery fails
        /// </summary>
        private List<string> GetKeyboardLayoutsViaPowerShell()
        {
            var layouts = new List<string>();
            
            try
            {
                // Try to access the current user's keyboard layout preload settings
                using (var preloadKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Keyboard Layout\Preload"))
                {
                    if (preloadKey != null)
                    {
                        var valueNames = preloadKey.GetValueNames();
                        foreach (var valueName in valueNames.OrderBy(v => v))
                        {
                            var layoutId = preloadKey.GetValue(valueName)?.ToString();
                            if (!string.IsNullOrEmpty(layoutId) && layoutId.Length == 8)
                            {
                                layouts.Add(layoutId);
                            }
                        }
                    }
                }
                
                // If no layouts found, add common fallbacks based on system locale
                if (!layouts.Any())
                {
                    _logger.LogDebug("No keyboard layouts found in registry, using locale-based fallbacks");
                    
                    // Check system locale to provide appropriate defaults
                    var culture = System.Globalization.CultureInfo.CurrentCulture;
                    if (culture.Name.StartsWith("en-CA"))
                    {
                        layouts.Add("00001009"); // English (Canada)
                        layouts.Add("00000409"); // English (United States)
                    }
                    else if (culture.Name.StartsWith("en-US"))
                    {
                        layouts.Add("00000409"); // English (United States)
                        layouts.Add("00001009"); // English (Canada)
                    }
                    else if (culture.Name.StartsWith("fr-CA"))
                    {
                        layouts.Add("00000c0c"); // French (Canada)
                        layouts.Add("00001009"); // English (Canada)
                    }
                    else
                    {
                        // Default fallback
                        layouts.Add("00001009"); // English (Canada)
                        layouts.Add("00000409"); // English (United States)
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Registry keyboard layout detection failed, using defaults");
                
                // Ultimate fallback - add common English layouts
                layouts.Add("00001009"); // English (Canada)
                layouts.Add("00000409"); // English (United States)
            }
            
            return layouts.Distinct().ToList();
        }
    }
}
