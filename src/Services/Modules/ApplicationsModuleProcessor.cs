#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Services.Usage;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Applications module processor - Software inventory and management
    /// </summary>
    public class ApplicationsModuleProcessor : BaseModuleProcessor<ApplicationsData>
    {
        private readonly ILogger<ApplicationsModuleProcessor> _logger;
        private readonly IApplicationUsageTracker _usageTracker;

        public override string ModuleId => "applications";

        public ApplicationsModuleProcessor(ILogger<ApplicationsModuleProcessor> logger, IApplicationUsageTracker usageTracker)
        {
            _logger = logger;
            _usageTracker = usageTracker;
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
                    var app = new InstalledApplication
                    {
                        Name = GetStringValue(program, "name"),
                        Version = GetStringValue(program, "version"),
                        Publisher = GetStringValue(program, "publisher"),
                        InstallLocation = GetStringValue(program, "install_location"),
                        Architecture = GetStringValue(program, "uninstall_string").Contains("x64") ? "x64" : "x86",
                        Source = GetStringValue(program, "install_source")
                    };

                    // Parse install date if available
                    var installDateStr = GetStringValue(program, "install_date");
                    if (!string.IsNullOrEmpty(installDateStr) && DateTime.TryParse(installDateStr, out var installDate))
                    {
                        app.InstallDate = installDate;
                    }

                    // Parse size if available
                    var sizeStr = GetStringValue(program, "estimated_size");
                    if (!string.IsNullOrEmpty(sizeStr) && long.TryParse(sizeStr, out var size))
                    {
                        app.Size = size;
                    }

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

            // Capture application usage analytics
            try
            {
                var usageSnapshot = await _usageTracker.CollectUsageAsync(deviceId).ConfigureAwait(false);
                if (usageSnapshot != null)
                {
                    EnhanceUsageSnapshotWithInventory(usageSnapshot, data.InstalledApplications);
                    data.Usage = usageSnapshot;

                    _logger.LogInformation(
                        "Application usage analytics captured - {TrackedCount} apps, {LaunchCount} launches, {ActiveSessions} active",
                        usageSnapshot.Applications.Count,
                        usageSnapshot.TotalLaunches,
                        usageSnapshot.ActiveSessions.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to capture application usage analytics");
                data.Usage = ApplicationUsageSnapshot.CreateUnavailable($"Application usage tracking failed: {ex.Message}");
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

            var usageSummaries = data.InstalledApplications
                .Where(app => app.Usage is not null)
                .Select(app => app.Usage!)
                .ToList();

            if (data.Usage.IsCaptureEnabled && usageSummaries.Any())
            {
                var topApplications = usageSummaries
                    .OrderByDescending(app => app.TotalUsageSeconds + app.ActiveUsageSeconds)
                    .ThenByDescending(app => app.LaunchCount)
                    .Take(5)
                    .Select(app => new Dictionary<string, object>
                    {
                        ["name"] = app.Name,
                        ["publisher"] = app.Publisher,
                        ["launchCount"] = app.LaunchCount,
                        ["totalUsageHours"] = Math.Round((app.TotalUsageSeconds + app.ActiveUsageSeconds) / 3600, 2)
                    })
                    .ToList();

                var details = new Dictionary<string, object>
                {
                    ["windowStart"] = data.Usage.WindowStart,
                    ["windowEnd"] = data.Usage.WindowEnd,
                    ["trackedApplications"] = usageSummaries.Count,
                    ["totalLaunches"] = data.Usage.TotalLaunches,
                    ["topApplications"] = topApplications
                };

                events.Add(CreateEvent(
                    "usage.summary",
                    $"Tracked {usageSummaries.Count} applications across {data.Usage.TotalLaunches} launches",
                    details));
            }
            else if (!data.Usage.IsCaptureEnabled)
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

            return Task.FromResult(events);
        }

        private static void EnhanceUsageSnapshotWithInventory(ApplicationUsageSnapshot usageSnapshot, List<InstalledApplication> inventory)
        {
            if (usageSnapshot.Applications.Count == 0 || inventory.Count == 0)
            {
                return;
            }

            foreach (var summary in usageSnapshot.Applications)
            {
                var match = FindInstalledApplication(summary, inventory);
                if (match == null)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(summary.Name) || summary.Name.Equals(summary.Executable, StringComparison.OrdinalIgnoreCase))
                {
                    summary.Name = match.Name;
                }

                if (string.IsNullOrWhiteSpace(summary.Publisher) && !string.IsNullOrWhiteSpace(match.Publisher))
                {
                    summary.Publisher = match.Publisher;
                }

                if (string.IsNullOrWhiteSpace(summary.Path) && !string.IsNullOrWhiteSpace(match.InstallLocation))
                {
                    summary.Path = match.InstallLocation;
                }

                match.Usage = summary;
            }
        }

        private static InstalledApplication? FindInstalledApplication(ApplicationUsageSummary summary, List<InstalledApplication> inventory)
        {
            if (!string.IsNullOrWhiteSpace(summary.Path))
            {
                var directory = Path.GetDirectoryName(summary.Path);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    var byLocation = inventory.FirstOrDefault(app =>
                        !string.IsNullOrWhiteSpace(app.InstallLocation) &&
                        summary.Path.StartsWith(app.InstallLocation, StringComparison.OrdinalIgnoreCase));

                    if (byLocation != null)
                    {
                        return byLocation;
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(summary.Name))
            {
                var byName = inventory.FirstOrDefault(app => app.Name.Equals(summary.Name, StringComparison.OrdinalIgnoreCase));
                if (byName != null)
                {
                    return byName;
                }
            }

            if (!string.IsNullOrWhiteSpace(summary.Executable))
            {
                var executableName = summary.Executable;
                var byExecutable = inventory.FirstOrDefault(app =>
                    !string.IsNullOrWhiteSpace(app.InstallLocation) &&
                    executableName.Equals(Path.GetFileName(app.InstallLocation.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)), StringComparison.OrdinalIgnoreCase));

                if (byExecutable != null)
                {
                    return byExecutable;
                }
            }

            return null;
        }
    }
}
