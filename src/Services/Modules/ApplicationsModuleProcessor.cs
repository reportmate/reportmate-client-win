#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Applications module processor - Software inventory and management
    /// Includes usage tracking via Windows Kernel Process telemetry
    /// </summary>
    public class ApplicationsModuleProcessor : BaseModuleProcessor<ApplicationsData>
    {
        private readonly ILogger<ApplicationsModuleProcessor> _logger;
        private readonly ApplicationUsageService _usageService;

        public override string ModuleId => "applications";

        public ApplicationsModuleProcessor(
            ILogger<ApplicationsModuleProcessor> logger,
            ApplicationUsageService usageService)
        {
            _logger = logger;
            _usageService = usageService;
        }

        public override async Task<ApplicationsData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Applications module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new ApplicationsData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process installed programs
            if (osqueryResults.TryGetValue("programs", out var programs))
            {
                _logger.LogDebug("Processing {Count} installed programs", programs.Count);
                
                foreach (var program in programs)
                {
                    var appName = GetStringValue(program, "name");
                    var registryVersion = GetStringValue(program, "version");
                    var installLocation = GetStringValue(program, "install_location");
                    
                    // Check if registry version seems incomplete and try to get file version
                    var finalVersion = registryVersion;
                    if (IsIncompleteVersion(registryVersion) && !string.IsNullOrEmpty(installLocation))
                    {
                        var fileVersion = GetFileVersionFromInstallLocation(installLocation, appName);
                        if (!string.IsNullOrEmpty(fileVersion))
                        {
                            _logger.LogDebug("Enhanced version for {AppName}: {FileVersion} (registry had: {RegistryVersion})", 
                                appName, fileVersion, registryVersion);
                            finalVersion = fileVersion;
                        }
                    }
                    
                    var app = new InstalledApplication
                    {
                        Name = appName,
                        Version = finalVersion,
                        Publisher = GetStringValue(program, "publisher"),
                        InstallLocation = installLocation,
                        Architecture = GetStringValue(program, "uninstall_string").Contains("x64") ? "x64" : "x86",
                        Source = GetStringValue(program, "install_source")
                    };

                    // Parse install date if available
                    var installDateStr = GetStringValue(program, "install_date");
                    if (!string.IsNullOrEmpty(installDateStr) && DateTime.TryParse(installDateStr, out var installDate))
                    {
                        app.InstallDate = installDate;
                    }

                    // Size not available from osquery programs table
                    // Could be derived from install_location directory size if needed

                    data.InstalledApplications.Add(app);
                }
            }
            else
            {
                _logger.LogWarning("No programs data found in osquery results");
            }

            // Process running processes
            if (osqueryResults.TryGetValue("processes", out var processes))
            {
                _logger.LogDebug("Processing {Count} running processes", processes.Count);
                
                foreach (var process in processes)
                {
                    var proc = new RunningProcess
                    {
                        ProcessId = GetIntValue(process, "pid"),
                        Name = GetStringValue(process, "name"),
                        Path = GetStringValue(process, "path"),
                        MemoryUsage = GetLongValue(process, "resident_size"),
                        CpuPercent = GetDoubleValue(process, "percent_processor_time")
                    };

                    // Parse start time if available
                    var startTimeStr = GetStringValue(process, "start_time");
                    if (!string.IsNullOrEmpty(startTimeStr) && DateTime.TryParse(startTimeStr, out var startTime))
                    {
                        proc.StartTime = startTime;
                    }
                    else
                    {
                        proc.StartTime = DateTime.UtcNow; // Default fallback
                    }

                    data.RunningProcesses.Add(proc);
                }
            }
            else
            {
                _logger.LogWarning("No processes data found in osquery results");
            }

            // Process startup items
            if (osqueryResults.TryGetValue("startup_items", out var startupItems))
            {
                _logger.LogDebug("Processing {Count} startup items", startupItems.Count);
                
                foreach (var item in startupItems)
                {
                    var startup = new StartupProgram
                    {
                        Name = GetStringValue(item, "name"),
                        Path = GetStringValue(item, "path"),
                        Location = GetStringValue(item, "source"),
                        Enabled = GetStringValue(item, "status").ToLowerInvariant() != "disabled"
                    };

                    data.StartupPrograms.Add(startup);
                }
            }
            else
            {
                _logger.LogWarning("No startup_items data found in osquery results");
            }

            _logger.LogInformation("Applications module processed - {AppCount} applications, {ProcessCount} processes, {StartupCount} startup items", 
                data.InstalledApplications.Count, data.RunningProcesses.Count, data.StartupPrograms.Count);

            // Set totals for validation
            data.TotalApplications = data.InstalledApplications.Count;
            data.LastInventoryUpdate = DateTime.UtcNow;

            // Collect application usage data from kernel process telemetry
            // This runs every 4 hours (matching the applications module schedule)
            _logger.LogDebug("Collecting application usage data from kernel process telemetry...");
            try
            {
                data.Usage = await _usageService.CollectUsageDataAsync(data.InstalledApplications, lookbackHours: 4);
                
                if (data.Usage.IsCaptureEnabled)
                {
                    _logger.LogInformation(
                        "Usage tracking complete: {SessionCount} sessions, {ActiveCount} active, {AppsWithUsage} apps with usage data",
                        data.Usage.TotalLaunches,
                        data.Usage.ActiveSessions.Count,
                        data.ApplicationsWithUsage);

                    // Build daily per-app summaries for historical retention
                    data.DailyUsageHistory = _usageService.BuildDailySummaries(data.Usage.ActiveSessions);
                }
                else
                {
                    _logger.LogWarning("Usage tracking unavailable: {Status}", data.Usage.Status);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect application usage data");
                data.Usage = ApplicationUsageSnapshot.CreateUnavailable($"Collection error: {ex.Message}");
            }

            return data;
        }

        public override async Task<bool> ValidateModuleDataAsync(ApplicationsData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            // Additional validation for applications module
            var isValid = baseValid &&
                         data.ModuleId == ModuleId &&
                         data.TotalApplications >= 0 &&
                         data.InstalledApplications.Count == data.TotalApplications;

            if (!isValid)
            {
                _logger.LogWarning("Applications module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        public override Task<List<ReportMateEvent>> GenerateEventsAsync(ApplicationsData data)
        {
            var events = new List<ReportMateEvent>();

            // Usage tracking is currently disabled/unavailable
            if (!data.Usage.IsCaptureEnabled)
            {
                // Only generate event if there are specific warnings other than default
                if (data.Usage.Warnings.Any(w => !w.Contains("not initialized")))
                {
                    var details = new Dictionary<string, object>
                    {
                        ["status"] = data.Usage.Status,
                        ["warnings"] = data.Usage.Warnings
                    };

                    events.Add(CreateEvent(
                        "usage.disabled",
                        "Application usage tracking is currently unavailable",
                        details));
                }
            }

            return Task.FromResult(events);
        }

        /// <summary>
        /// Attempts to get the product/file version from an executable in the install location
        /// </summary>
        /// <param name="installLocation">Install location path from registry</param>
        /// <param name="appName">Application name for matching</param>
        /// <returns>Product version if found, otherwise null</returns>
        private string? GetFileVersionFromInstallLocation(string installLocation, string appName)
        {
            try
            {
                if (!Directory.Exists(installLocation))
                    return null;

                // Look for .exe files with names similar to the app name
                var exeFiles = Directory.GetFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly);
                
                // First, try to find an exe that matches the app name
                var matchingExe = exeFiles.FirstOrDefault(exe => 
                    Path.GetFileNameWithoutExtension(exe).Equals(appName, StringComparison.OrdinalIgnoreCase));
                
                // If no exact match, try the first .exe in the directory (usually the main executable)
                var targetExe = matchingExe ?? exeFiles.FirstOrDefault();
                
                if (targetExe != null && File.Exists(targetExe))
                {
                    var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(targetExe);
                    
                    // Try ProductVersion first, then FileVersion
                    var version = versionInfo.ProductVersion ?? versionInfo.FileVersion;
                    
                    if (!string.IsNullOrEmpty(version))
                    {
                        _logger.LogTrace("Found file version for {AppName} from {ExePath}: {Version}", 
                            appName, targetExe, version);
                        return version;
                    }
                }
            }
            catch (Exception ex)
            {
                // Silently fail - this is a best-effort enhancement
                _logger.LogTrace("Could not get file version for {AppName} from {InstallLocation}: {Error}", 
                    appName, installLocation, ex.Message);
            }
            
            return null;
        }

        /// <summary>
        /// Determines if a version string seems incomplete and should use file version fallback
        /// </summary>
        /// <param name="version">Version string from Windows Registry</param>
        /// <returns>True if version appears incomplete (e.g., just "2025" or "10.0")</returns>
        private static bool IsIncompleteVersion(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return true;

            // If version has no dots and is just a number (e.g., "2025"), it's likely incomplete
            if (!version.Contains('.') && int.TryParse(version, out _))
                return true;

            // If version has only one dot and appears to be a simple major.minor like "2025.0", it might be incomplete
            // But allow common patterns like "1.0" for simple apps
            var parts = version.Split('.');
            if (parts.Length == 2)
            {
                // If both parts are numbers and the first part is > 1000 (likely a year), might be incomplete
                if (int.TryParse(parts[0], out var major) && major > 1000 && int.TryParse(parts[1], out var minor) && minor == 0)
                    return true;
            }

            return false;
        }
    }
}
