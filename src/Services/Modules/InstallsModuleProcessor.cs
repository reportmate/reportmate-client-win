#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json;
using System.Linq;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
        /// <summary>
        /// Installs module processor - Managed software systems with enhanced Cimian integration
        /// </summary>
        public class InstallsModuleProcessor : BaseModuleProcessor<InstallsData>
        {
            private readonly ILogger<InstallsModuleProcessor> _logger;

            public override string ModuleId => "installs";

            public InstallsModuleProcessor(ILogger<InstallsModuleProcessor> logger)
            {
                _logger = logger;
            }

            /// <summary>
            /// Maps Cimian's detailed status values to ReportMate's simplified dashboard statuses
            /// Uses only: Installed, Pending, Warning, Error, Removed
            /// </summary>
            private static string MapCimianStatusToReportMate(string cimianStatus, bool hasInstallLoop = false)
            {
                if (string.IsNullOrEmpty(cimianStatus))
                    return "Pending";  // Default unknown to Pending

                // If install loop is detected, override status to "Installed" regardless of current_status
                if (hasInstallLoop)
                    return "Installed";

                return cimianStatus.ToLowerInvariant() switch
                {
                    // Installed - Successfully installed and working
                    "installed" => "Installed",
                    "success" => "Installed",
                    "install loop" => "Installed", // Install Loop → Installed
                    
                    // Pending - Needs action or in progress  
                    "available" => "Pending",
                    "pending" => "Pending", 
                    "update available" => "Pending", // Update Available → Pending
                    "downloading" => "Pending", // Downloading → Pending
                    "installing" => "Pending", // Installing → Pending
                    
                    // Warning - Installed but with issues
                    "warning" => "Warning",
                    
                    // Error - Failed installation or critical issues
                    "failed" => "Error",  // Failed → Error
                    "error" => "Error",
                    "fail" => "Error",
                    
                    // Removed - Uninstalled or removed
                    "removed" => "Removed",
                    "uninstalled" => "Removed",
                    
                    _ => "Pending" // Default unknown to Pending
                };
            }        public override Task<InstallsData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Installs module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new InstallsData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process Cimian information
            data.Cimian = ProcessCimianInfo(osqueryResults);
            
            // Process Cimian configuration (config.yaml)
            ProcessCimianConfiguration(osqueryResults, data);
            
            // Process Cimian reports data (sessions, items, events)
            ProcessCimianReports(osqueryResults, data);
            
            // Process recent installs and deployments
            ProcessRecentInstalls(osqueryResults, data);
            
            // Process cache status
            ProcessCacheStatus(osqueryResults, data);

            // Generate enhanced analytics from the processed data
            var analytics = GenerateEnhancedAnalytics(data);
            var recommendations = GeneratePerformanceRecommendations(analytics);
            
            // Store analytics in the data for API consumption
            data.CacheStatus["enhanced_analytics"] = analytics;
            data.CacheStatus["performance_recommendations"] = recommendations;

            data.LastCheckIn = DateTime.UtcNow;

            _logger.LogInformation("Installs module processed for device {DeviceId} - Cimian installed: {CimianInstalled}, Sessions: {SessionCount}, Events: {EventCount}", 
                deviceId, data.Cimian?.IsInstalled ?? false, data.RecentSessions.Count, data.RecentEvents.Count);

            return Task.FromResult(data);
        }

        private CimianInfo ProcessCimianInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var cimianInfo = new CimianInfo();

            // Check Cimian installation from services
            if (osqueryResults.TryGetValue("cimian_service_status", out var services))
            {
                foreach (var service in services)
                {
                    var serviceName = GetStringValue(service, "name");
                    var status = GetStringValue(service, "status");
                    cimianInfo.Services.Add($"{serviceName}: {status}");
                    
                    if (status.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    {
                        cimianInfo.Status = "Active";
                        cimianInfo.IsInstalled = true;
                    }
                }
            }

            // Check active Cimian processes
            if (osqueryResults.TryGetValue("cimian_active_processes", out var processes))
            {
                foreach (var process in processes)
                {
                    var processName = GetStringValue(process, "name");
                    var path = GetStringValue(process, "path");
                    cimianInfo.ActiveProcesses.Add($"{processName} ({path})");
                }
                
                if (processes.Any())
                {
                    cimianInfo.Status = "Running";
                }
            }

            // Check registry configuration
            if (osqueryResults.TryGetValue("cimian_package_registry", out var regConfig))
            {
                foreach (var config in regConfig)
                {
                    var name = GetStringValue(config, "name");
                    var data = GetStringValue(config, "data");
                    cimianInfo.RegistryConfig[name] = data;
                }
            }

            // Check bootstrap mode
            if (osqueryResults.TryGetValue("cimian_bootstrap_status", out var bootstrapFlag))
            {
                cimianInfo.BootstrapFlagPresent = bootstrapFlag.Any();
            }

            // Collect pending packages from various sources
            CollectPendingPackages(osqueryResults, cimianInfo);

            // Check recent session activity
            if (osqueryResults.TryGetValue("cimian_log_sessions", out var logDirs))
            {
                cimianInfo.TotalSessions = logDirs.Count;
                
                if (logDirs.Any())
                {
                    var latestSession = logDirs
                        .OrderByDescending(d => GetStringValue(d, "mtime"))
                        .FirstOrDefault();
                        
                    if (latestSession != null)
                    {
                        var mtimeStr = GetStringValue(latestSession, "mtime");
                        if (DateTime.TryParse(mtimeStr, out var mtime))
                        {
                            cimianInfo.LastSessionTime = mtime;
                        }
                    }
                }
            }

            // Check managed software version info and Cimian executable version
            if (osqueryResults.TryGetValue("cimian_managed_software", out var managedSoft))
            {
                var cimianSoftware = managedSoft.FirstOrDefault();
                if (cimianSoftware != null)
                {
                    cimianInfo.Version = GetStringValue(cimianSoftware, "version");
                    var installDateStr = GetStringValue(cimianSoftware, "install_date");
                    if (DateTime.TryParse(installDateStr, out var installDate))
                    {
                        cimianInfo.LastRun = installDate;
                    }
                }
            }

            // Check executable version directly from file system
            if (osqueryResults.TryGetValue("cimian_executable_version", out var exeVersion))
            {
                var cimianExe = exeVersion.FirstOrDefault();
                if (cimianExe != null)
                {
                    var version = GetStringValue(cimianExe, "version");
                    if (!string.IsNullOrEmpty(version))
                    {
                        cimianInfo.Version = version;
                        cimianInfo.IsInstalled = true;
                        _logger.LogDebug("Found Cimian executable version: {Version}", version);
                    }
                }
            }

            // Fallback: Try to get version directly from the executable file if osquery version is empty
            if (string.IsNullOrEmpty(cimianInfo.Version))
            {
                try
                {
                    var cimianExePath = @"C:\Program Files\Cimian\managedsoftwareupdate.exe";
                    if (File.Exists(cimianExePath))
                    {
                        var versionInfo = FileVersionInfo.GetVersionInfo(cimianExePath);
                        if (!string.IsNullOrEmpty(versionInfo.FileVersion))
                        {
                            cimianInfo.Version = versionInfo.FileVersion;
                            cimianInfo.IsInstalled = true;
                            _logger.LogDebug("Found Cimian executable version via direct file access: {Version}", versionInfo.FileVersion);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to get Cimian executable version directly: {Error}", ex.Message);
                }
            }

            // Final fallback: Check Windows registry for Cimian in installed programs
            if (string.IsNullOrEmpty(cimianInfo.Version))
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (key != null)
                    {
                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            if (subKey != null)
                            {
                                var displayName = subKey.GetValue("DisplayName")?.ToString();
                                var displayVersion = subKey.GetValue("DisplayVersion")?.ToString();
                                
                                if (!string.IsNullOrEmpty(displayName) && displayName.Contains("Cimian", StringComparison.OrdinalIgnoreCase))
                                {
                                    if (!string.IsNullOrEmpty(displayVersion))
                                    {
                                        cimianInfo.Version = displayVersion;
                                        cimianInfo.IsInstalled = true;
                                        _logger.LogDebug("Found Cimian version in Windows registry: {Version}", displayVersion);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to get Cimian version from Windows registry: {Error}", ex.Message);
                }
            }

            // Check reports and configuration data
            if (osqueryResults.TryGetValue("cimian_managed_items", out var reports))
            {
                foreach (var report in reports)
                {
                    var filename = GetStringValue(report, "filename");
                    var path = GetStringValue(report, "path");
                    var size = GetStringValue(report, "size");
                    var mtime = GetStringValue(report, "mtime");
                    
                    if (!string.IsNullOrEmpty(filename))
                    {
                        cimianInfo.Reports[filename] = new CimianReportFileInfo { Size = size, Mtime = mtime };
                        _logger.LogDebug("Found Cimian report: {Filename} (Size: {Size}, Modified: {Mtime})", filename, size, mtime);
                    }
                }
            }

            // Also populate reports from cimian_reports_* queries for completeness
            var reportQueries = new[] { "cimian_reports_sessions", "cimian_reports_items", "cimian_reports_events" };
            foreach (var queryName in reportQueries)
            {
                if (osqueryResults.TryGetValue(queryName, out var reportFiles))
                {
                    foreach (var reportFile in reportFiles)
                    {
                        var path = GetStringValue(reportFile, "path");
                        var size = GetStringValue(reportFile, "size");
                        var mtime = GetStringValue(reportFile, "mtime");
                        
                        if (!string.IsNullOrEmpty(path))
                        {
                            var filename = Path.GetFileName(path);
                            if (!cimianInfo.Reports.ContainsKey(filename))
                            {
                                cimianInfo.Reports[filename] = new CimianReportFileInfo { Size = size, Mtime = mtime };
                                _logger.LogDebug("Found Cimian report file from {QueryName}: {Filename} (Size: {Size}, Modified: {Mtime})", queryName, filename, size, mtime);
                            }
                        }
                    }
                }
            }

            // Set default status if not already set
            if (string.IsNullOrEmpty(cimianInfo.Status))
            {
                cimianInfo.Status = cimianInfo.IsInstalled ? "Installed" : "Not Installed";
            }

            return cimianInfo;
        }

        private void ProcessCimianConfiguration(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, InstallsData data)
        {
            _logger.LogDebug("Processing Cimian configuration...");
            
            // First, try to read config.yaml directly from the standard path
            var standardConfigPath = @"C:\ProgramData\ManagedInstalls\config.yaml";
            var cimianConfig = ReadCimianConfigurationFile(standardConfigPath);
            
            if (cimianConfig != null)
            {
                _logger.LogInformation("Successfully loaded Cimian config.yaml from standard path: {ConfigPath}", standardConfigPath);
                
                // Add configuration information to the Cimian data
                if (data.Cimian == null)
                {
                    data.Cimian = new CimianInfo();
                }
                
                // Store primary configuration data from config.yaml
                data.Cimian.Config = cimianConfig;
                
                _logger.LogInformation("Loaded Cimian configuration with {ConfigCount} settings from {ConfigPath}", 
                    cimianConfig.Count, standardConfigPath);
                return;
            }
            
            // Fallback: Process Cimian configuration file from osquery results if direct read fails
            if (osqueryResults.TryGetValue("cimian_configuration", out var configFiles))
            {
                var configFile = configFiles.FirstOrDefault();
                if (configFile != null)
                {
                    var configPath = GetStringValue(configFile, "path");
                    var configSize = GetStringValue(configFile, "size");
                    var configMtime = GetStringValue(configFile, "mtime");
                    
                    _logger.LogDebug("Processing Cimian configuration from osquery: {ConfigPath} (Size: {Size}, Modified: {Mtime})", 
                        configPath, configSize, configMtime);
                    
                    // Read and parse the config.yaml file
                    cimianConfig = ReadCimianConfigurationFile(configPath);
                    if (cimianConfig != null)
                    {
                        // Add configuration information to the Cimian data
                        if (data.Cimian == null)
                        {
                            data.Cimian = new CimianInfo();
                        }
                        
                        // Store primary configuration data from config.yaml
                        data.Cimian.Config = cimianConfig;
                        
                        _logger.LogInformation("Loaded Cimian configuration with {ConfigCount} settings from {ConfigPath}", 
                            cimianConfig.Count, configPath);
                    }
                }
            }
            else
            {
                _logger.LogDebug("No cimian_configuration data found in osquery results");
            }
        }

        private Dictionary<string, object>? ReadCimianConfigurationFile(string configPath)
        {
            try
            {
                _logger.LogDebug("Attempting to read Cimian config file: {ConfigPath}", configPath);
                
                if (!File.Exists(configPath))
                {
                    _logger.LogDebug("Cimian configuration file not found: {ConfigPath}", configPath);
                    return null;
                }

                var yamlContent = File.ReadAllText(configPath);
                _logger.LogDebug("Read {ByteCount} bytes from config file: {ConfigPath}", yamlContent.Length, configPath);
                
                if (string.IsNullOrWhiteSpace(yamlContent))
                {
                    _logger.LogWarning("Cimian configuration file is empty: {ConfigPath}", configPath);
                    return null;
                }
                
                // Parse YAML content using simple parsing (since we don't have YamlDotNet dependency)
                // This is a basic YAML parser for simple key-value pairs
                var config = new Dictionary<string, object>();
                var lines = yamlContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                
                _logger.LogDebug("Processing {LineCount} lines from YAML config", lines.Length);
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                        continue;
                        
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        var key = trimmedLine.Substring(0, colonIndex).Trim();
                        var value = trimmedLine.Substring(colonIndex + 1).Trim();
                        
                        // Remove quotes if present
                        if ((value.StartsWith("\"") && value.EndsWith("\"")) || 
                            (value.StartsWith("'") && value.EndsWith("'")))
                        {
                            value = value.Substring(1, value.Length - 2);
                        }
                        
                        // Handle boolean values
                        if (value.Equals("true", StringComparison.OrdinalIgnoreCase))
                        {
                            config[key] = true;
                        }
                        else if (value.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            config[key] = false;
                        }
                        // Handle numeric values
                        else if (int.TryParse(value, out var intValue))
                        {
                            config[key] = intValue;
                        }
                        else
                        {
                            config[key] = value;
                        }
                        
                        _logger.LogDebug("Parsed config key: {Key} = {Value}", key, config[key]);
                    }
                }
                
                _logger.LogInformation("Successfully parsed Cimian configuration file with {ConfigCount} settings from {ConfigPath}", config.Count, configPath);
                
                // Log key configuration values for debugging
                if (config.ContainsKey("ClientIdentifier"))
                    _logger.LogDebug("Found ClientIdentifier: {ClientId}", config["ClientIdentifier"]);
                if (config.ContainsKey("SoftwareRepoURL"))
                    _logger.LogDebug("Found SoftwareRepoURL: {RepoURL}", config["SoftwareRepoURL"]);
                
                return config;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read Cimian configuration file from {ConfigPath}", configPath);
                return null;
            }
        }

        private void ProcessRecentInstalls(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, InstallsData data)
        {
            // Process managed software installs from Cimian
            if (osqueryResults.TryGetValue("cimian_managed_software", out var recentInstalls))
            {
                foreach (var install in recentInstalls)
                {
                    var managedInstall = new ManagedInstall
                    {
                        Name = GetStringValue(install, "name"),
                        Version = GetStringValue(install, "version"),
                        Status = "Installed",
                        Source = GetStringValue(install, "publisher"),
                        InstallLocation = GetStringValue(install, "install_location")
                    };

                    var installDateStr = GetStringValue(install, "install_date");
                    if (DateTime.TryParse(installDateStr, out var installDate))
                    {
                        managedInstall.InstallDate = installDate;
                    }

                    data.RecentInstalls.Add(managedInstall);
                }
            }

            // Process pending packages from cache
            if (osqueryResults.TryGetValue("cimian_cached_packages", out var deployments))
            {
                foreach (var deployment in deployments)
                {
                    var pendingInstall = new ManagedInstall
                    {
                        Name = GetStringValue(deployment, "package_name"),
                        Status = "Cached",
                        Source = "Cimian Cache"
                    };

                    var mtimeStr = GetStringValue(deployment, "mtime");
                    if (DateTime.TryParse(mtimeStr, out var mtime))
                    {
                        pendingInstall.InstallDate = mtime;
                    }

                    data.PendingInstalls.Add(pendingInstall);
                }
            }
        }

        private void ProcessCimianReports(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, InstallsData data)
        {
            try
            {
                const string CIMIAN_REPORTS_PATH = @"C:\ProgramData\ManagedInstalls\reports";
                
                // Process sessions report - always try direct file access first
                var sessionsPath = Path.Combine(CIMIAN_REPORTS_PATH, "sessions.json");
                if (File.Exists(sessionsPath))
                {
                    var sessions = ReadCimianSessionsReport(sessionsPath);
                    data.RecentSessions.AddRange(sessions.Take(20)); // Limit to 20 most recent sessions
                    // Also populate CimianInfo.Sessions collection
                    if (data.Cimian != null)
                    {
                        data.Cimian.Sessions.AddRange(sessions.Take(20));
                    }
                    _logger.LogInformation("Loaded {Count} sessions from enhanced Cimian sessions report", sessions.Count);
                }
                else if (osqueryResults.TryGetValue("cimian_reports_sessions", out var sessionsQuery))
                {
                    // Fallback to osquery result if direct file access fails
                    var sessionsFile = sessionsQuery.FirstOrDefault();
                    if (sessionsFile != null)
                    {
                        var path = GetStringValue(sessionsFile, "path");
                        var sessions = ReadCimianSessionsReport(path);
                        data.RecentSessions.AddRange(sessions.Take(20));
                        // Also populate CimianInfo.Sessions collection
                        if (data.Cimian != null)
                        {
                            data.Cimian.Sessions.AddRange(sessions.Take(20));
                        }
                        _logger.LogDebug("Loaded {Count} sessions from Cimian reports (osquery fallback)", sessions.Count);
                    }
                }

                // Process items report - enhanced package intelligence
                var itemsPath = Path.Combine(CIMIAN_REPORTS_PATH, "items.json");
                if (File.Exists(itemsPath))
                {
                    var items = ReadCimianItemsReport(itemsPath);
                    ProcessManagedItemsFromReport(items, data);
                    _logger.LogInformation("Loaded {Count} managed items from enhanced Cimian items report", items.Count);
                }
                else if (osqueryResults.TryGetValue("cimian_reports_items", out var itemsQuery))
                {
                    // Fallback to osquery result
                    var itemsFile = itemsQuery.FirstOrDefault();
                    if (itemsFile != null)
                    {
                        var path = GetStringValue(itemsFile, "path");
                        var items = ReadCimianItemsReport(path);
                        ProcessManagedItemsFromReport(items, data);
                        _logger.LogDebug("Loaded {Count} managed items from Cimian reports (osquery fallback)", items.Count);
                    }
                }

                // Process events report - structured event intelligence
                var eventsPath = Path.Combine(CIMIAN_REPORTS_PATH, "events.json");
                if (File.Exists(eventsPath))
                {
                    var events = ReadCimianEventsReport(eventsPath);
                    data.RecentEvents.AddRange(events.Take(100)); // Limit to 100 most recent events
                    // Also populate CimianInfo.Events collection
                    if (data.Cimian != null)
                    {
                        data.Cimian.Events.AddRange(events.Take(100));
                    }
                    _logger.LogInformation("Loaded {Count} events from enhanced Cimian events report", events.Count);
                }
                else if (osqueryResults.TryGetValue("cimian_reports_events", out var eventsQuery))
                {
                    // Fallback to osquery result
                    var eventsFile = eventsQuery.FirstOrDefault();
                    if (eventsFile != null)
                    {
                        var path = GetStringValue(eventsFile, "path");
                        var events = ReadCimianEventsReport(path);
                        data.RecentEvents.AddRange(events.Take(100));
                        // Also populate CimianInfo.Events collection
                        if (data.Cimian != null)
                        {
                            data.Cimian.Events.AddRange(events.Take(100));
                        }
                        _logger.LogDebug("Loaded {Count} events from Cimian reports (osquery fallback)", events.Count);
                    }
                }

                // Set bootstrap mode status
                if (data.Cimian != null)
                {
                    data.BootstrapModeActive = data.Cimian.BootstrapFlagPresent;
                }

                // Enhanced cache status from most recent session
                if (data.RecentSessions.Any())
                {
                    var latestSession = data.RecentSessions.First();
                    if (latestSession.CacheSizeMb > 0)
                    {
                        data.CacheStatus["cache_size_mb"] = latestSession.CacheSizeMb;
                        data.CacheStatus["last_updated"] = latestSession.StartTime.ToString("O");
                    }
                }

                _logger.LogInformation("Enhanced Cimian reports processing completed - Sessions: {Sessions}, Items: {Items}, Events: {Events}", 
                    data.RecentSessions.Count, data.RecentInstalls.Count, data.RecentEvents.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing enhanced Cimian reports data");
            }
        }

        private void ProcessCacheStatus(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, InstallsData data)
        {
            if (osqueryResults.TryGetValue("cimian_cached_packages", out var cacheFiles))
            {
                var totalSize = 0L;
                var fileCount = cacheFiles.Count;
                var latestFile = "";
                DateTime latestMtime = DateTime.MinValue;

                foreach (var file in cacheFiles)
                {
                    var sizeStr = GetStringValue(file, "size");
                    if (long.TryParse(sizeStr, out var size))
                    {
                        totalSize += size;
                    }

                    var mtimeStr = GetStringValue(file, "mtime");
                    if (DateTime.TryParse(mtimeStr, out var mtime) && mtime > latestMtime)
                    {
                        latestMtime = mtime;
                        latestFile = GetStringValue(file, "filename");
                    }
                }

                // Store as individual properties instead of anonymous object
                data.CacheStatus["total_size_bytes"] = totalSize;
                data.CacheStatus["file_count"] = fileCount;
                data.CacheStatus["latest_file"] = latestFile;
                data.CacheStatus["latest_modification"] = latestMtime.ToString("O");
            }
        }

        private CimianSession? ReadCimianSessionData(string sessionDir, string sessionId)
        {
            try
            {
                var sessionFile = Path.Combine(sessionDir, "session.json");
                if (!File.Exists(sessionFile))
                {
                    return null;
                }

                var json = File.ReadAllText(sessionFile);
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;

                var session = new CimianSession
                {
                    SessionId = sessionId,
                    RunType = root.GetProperty("run_type").GetString() ?? "",
                    Status = root.GetProperty("status").GetString() ?? ""
                };

                if (root.TryGetProperty("start_time", out var startTimeProp))
                {
                    if (DateTime.TryParse(startTimeProp.GetString(), out var startTime))
                    {
                        session.StartTime = startTime;
                    }
                }

                if (root.TryGetProperty("end_time", out var endTimeProp) && endTimeProp.ValueKind != JsonValueKind.Null)
                {
                    if (DateTime.TryParse(endTimeProp.GetString(), out var endTime))
                    {
                        session.EndTime = endTime;
                        session.Duration = endTime - session.StartTime;
                    }
                }

                if (root.TryGetProperty("summary", out var summaryProp))
                {
                    session.TotalActions = summaryProp.GetProperty("total_actions").GetInt32();
                    session.Installs = summaryProp.GetProperty("installs").GetInt32();
                    session.Updates = summaryProp.GetProperty("updates").GetInt32();
                    session.Removals = summaryProp.GetProperty("removals").GetInt32();
                    session.Successes = summaryProp.GetProperty("successes").GetInt32();
                    session.Failures = summaryProp.GetProperty("failures").GetInt32();

                    if (summaryProp.TryGetProperty("packages_handled", out var packagesProp))
                    {
                        foreach (var pkg in packagesProp.EnumerateArray())
                        {
                            session.PackagesHandled.Add(pkg.GetString() ?? "");
                        }
                    }
                }

                if (root.TryGetProperty("environment", out var envProp))
                {
                    foreach (var envItem in envProp.EnumerateObject())
                    {
                        session.Environment[envItem.Name] = envItem.Value.ToString();
                    }
                }

                // Enhanced logging metadata extraction
                if (root.TryGetProperty("system_info", out var systemInfoProp))
                {
                    foreach (var sysItem in systemInfoProp.EnumerateObject())
                    {
                        session.SystemInfo[sysItem.Name] = sysItem.Value.ToString();
                    }
                }

                if (root.TryGetProperty("flags", out var flagsProp))
                {
                    foreach (var flagItem in flagsProp.EnumerateObject())
                    {
                        if (flagItem.Value.ValueKind == JsonValueKind.True || flagItem.Value.ValueKind == JsonValueKind.False)
                        {
                            session.Flags[flagItem.Name] = flagItem.Value.GetBoolean();
                        }
                    }
                }

                if (root.TryGetProperty("performance_metrics", out var perfProp))
                {
                    foreach (var perfItem in perfProp.EnumerateObject())
                    {
                        session.PerformanceMetrics[perfItem.Name] = perfItem.Value.ToString();
                    }
                }

                if (root.TryGetProperty("failed_items", out var failedItemsProp))
                {
                    foreach (var failedItem in failedItemsProp.EnumerateArray())
                    {
                        var failedPackage = failedItem.GetString();
                        if (!string.IsNullOrEmpty(failedPackage))
                        {
                            session.FailedItems.Add(failedPackage);
                        }
                    }
                }

                if (root.TryGetProperty("blocking_applications", out var blockingAppsProp))
                {
                    foreach (var blockingItem in blockingAppsProp.EnumerateObject())
                    {
                        var packageName = blockingItem.Name;
                        var blockingApps = new List<string>();
                        
                        foreach (var appItem in blockingItem.Value.EnumerateArray())
                        {
                            var appName = appItem.GetString();
                            if (!string.IsNullOrEmpty(appName))
                            {
                                blockingApps.Add(appName);
                            }
                        }
                        
                        if (blockingApps.Any())
                        {
                            session.BlockingApplications[packageName] = blockingApps;
                        }
                    }
                }

                return session;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to read Cimian session data from {SessionDir}: {Error}", sessionDir, ex.Message);
                return null;
            }
        }

        private List<CimianEvent> ReadCimianEventData(string sessionDir, string sessionId)
        {
            var events = new List<CimianEvent>();
            
            try
            {
                var eventsFile = Path.Combine(sessionDir, "events.jsonl");
                if (!File.Exists(eventsFile))
                {
                    return events;
                }

                var lines = File.ReadAllLines(eventsFile);
                foreach (var line in lines.TakeLast(20)) // Take last 20 events
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    try
                    {
                        using var document = JsonDocument.Parse(line);
                        var root = document.RootElement;

                        var cimianEvent = new CimianEvent
                        {
                            EventId = root.GetProperty("event_id").GetString() ?? "",
                            SessionId = sessionId,
                            Level = root.GetProperty("level").GetString() ?? "",
                            EventType = root.GetProperty("event_type").GetString() ?? "",
                            Action = root.GetProperty("action").GetString() ?? "",
                            Status = root.GetProperty("status").GetString() ?? "",
                            Message = root.GetProperty("message").GetString() ?? ""
                        };

                        if (root.TryGetProperty("timestamp", out var timestampProp))
                        {
                            if (DateTime.TryParse(timestampProp.GetString(), out var timestamp))
                            {
                                cimianEvent.Timestamp = timestamp;
                            }
                        }

                        if (root.TryGetProperty("package", out var packageProp) && packageProp.ValueKind != JsonValueKind.Null)
                        {
                            cimianEvent.Package = packageProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("version", out var versionProp) && versionProp.ValueKind != JsonValueKind.Null)
                        {
                            cimianEvent.Version = versionProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("error", out var errorProp) && errorProp.ValueKind != JsonValueKind.Null)
                        {
                            cimianEvent.Error = errorProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("progress", out var progressProp) && progressProp.ValueKind != JsonValueKind.Null)
                        {
                            cimianEvent.Progress = progressProp.GetInt32();
                        }

                        if (root.TryGetProperty("duration", out var durationProp) && durationProp.ValueKind != JsonValueKind.Null)
                        {
                            if (long.TryParse(durationProp.GetString(), out var durationMs))
                            {
                                cimianEvent.Duration = TimeSpan.FromMilliseconds(durationMs);
                            }
                        }

                        if (root.TryGetProperty("source", out var sourceProp))
                        {
                            if (sourceProp.TryGetProperty("file", out var fileProp))
                            {
                                cimianEvent.SourceFile = fileProp.GetString() ?? "";
                            }
                            if (sourceProp.TryGetProperty("function", out var funcProp))
                            {
                                cimianEvent.SourceFunction = funcProp.GetString() ?? "";
                            }
                            if (sourceProp.TryGetProperty("line", out var lineProp))
                            {
                                cimianEvent.SourceLine = lineProp.GetInt32();
                            }
                        }

                        if (root.TryGetProperty("context", out var contextProp))
                        {
                            foreach (var contextItem in contextProp.EnumerateObject())
                            {
                                cimianEvent.Context[contextItem.Name] = contextItem.Value.ToString();
                            }
                        }

                        // Enhanced logging data extraction
                        if (root.TryGetProperty("batch_id", out var batchIdProp))
                        {
                            cimianEvent.BatchId = batchIdProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("installer_type", out var installerTypeProp))
                        {
                            cimianEvent.InstallerType = installerTypeProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("installer_path", out var installerPathProp))
                        {
                            cimianEvent.InstallerPath = installerPathProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("installer_output", out var installerOutputProp))
                        {
                            cimianEvent.InstallerOutput = installerOutputProp.GetString() ?? "";
                        }

                        if (root.TryGetProperty("checkonly_mode", out var checkOnlyProp))
                        {
                            cimianEvent.CheckOnlyMode = checkOnlyProp.GetBoolean();
                        }

                        if (root.TryGetProperty("system_context", out var systemContextProp))
                        {
                            foreach (var contextItem in systemContextProp.EnumerateObject())
                            {
                                cimianEvent.SystemContext[contextItem.Name] = contextItem.Value.ToString();
                            }
                        }

                        if (root.TryGetProperty("performance_counters", out var perfCountersProp))
                        {
                            foreach (var counterItem in perfCountersProp.EnumerateObject())
                            {
                                cimianEvent.PerformanceCounters[counterItem.Name] = counterItem.Value.ToString();
                            }
                        }

                        events.Add(cimianEvent);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("Failed to parse Cimian event line: {Error}", ex.Message);
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to read Cimian event data from {SessionDir}: {Error}", sessionDir, ex.Message);
            }

            return events;
        }

        private List<CimianSession> ReadCimianSessionsReport(string filePath)
        {
            var sessions = new List<CimianSession>();
            
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogDebug("Cimian sessions report file not found: {FilePath}", filePath);
                    return sessions;
                }

                var json = File.ReadAllText(filePath);
                using var document = JsonDocument.Parse(json);
                
                foreach (var sessionElement in document.RootElement.EnumerateArray())
                {
                    var session = new CimianSession
                    {
                        SessionId = sessionElement.GetProperty("session_id").GetString() ?? "",
                        RunType = sessionElement.GetProperty("run_type").GetString() ?? "",
                        Status = sessionElement.GetProperty("status").GetString() ?? "",
                        DurationSeconds = sessionElement.GetProperty("duration_seconds").GetInt32(),
                        Hostname = sessionElement.GetProperty("hostname").GetString() ?? "",
                        User = sessionElement.GetProperty("user").GetString() ?? "",
                        ProcessId = sessionElement.GetProperty("process_id").GetInt32(),
                        LogVersion = sessionElement.GetProperty("log_version").GetString() ?? ""
                    };

                    // Parse config section with enhanced Cimian configuration data
                    if (sessionElement.TryGetProperty("config", out var configProp))
                    {
                        foreach (var configItem in configProp.EnumerateObject())
                        {
                            session.Config[configItem.Name] = configItem.Value.ToString();
                        }
                    }

                    // Parse enhanced summary section
                    if (sessionElement.TryGetProperty("summary", out var summaryProp))
                    {
                        if (summaryProp.TryGetProperty("total_packages_managed", out var totalPackagesProp))
                            session.TotalPackagesManaged = totalPackagesProp.GetInt32();
                        if (summaryProp.TryGetProperty("packages_installed", out var packagesInstalledProp))
                            session.PackagesInstalled = packagesInstalledProp.GetInt32();
                        if (summaryProp.TryGetProperty("packages_pending", out var packagesPendingProp))
                            session.PackagesPending = packagesPendingProp.GetInt32();
                        if (summaryProp.TryGetProperty("packages_failed", out var packagesFailedProp))
                            session.PackagesFailed = packagesFailedProp.GetInt32();
                        if (summaryProp.TryGetProperty("cache_size_mb", out var cacheSizeProp))
                            session.CacheSizeMb = cacheSizeProp.GetDouble();
                        
                        // Legacy fields for backwards compatibility
                        if (summaryProp.TryGetProperty("total_actions", out var totalActionsProp))
                            session.TotalActions = totalActionsProp.GetInt32();
                        if (summaryProp.TryGetProperty("installs", out var installsProp))
                            session.Installs = installsProp.GetInt32();
                        if (summaryProp.TryGetProperty("updates", out var updatesProp))
                            session.Updates = updatesProp.GetInt32();
                        if (summaryProp.TryGetProperty("removals", out var removalsProp))
                            session.Removals = removalsProp.GetInt32();
                        if (summaryProp.TryGetProperty("successes", out var successesProp))
                            session.Successes = successesProp.GetInt32();
                        if (summaryProp.TryGetProperty("failures", out var failuresProp))
                            session.Failures = failuresProp.GetInt32();

                        if (summaryProp.TryGetProperty("packages_handled", out var packagesProp))
                        {
                            foreach (var pkg in packagesProp.EnumerateArray())
                            {
                                var packageName = pkg.GetString();
                                if (!string.IsNullOrEmpty(packageName))
                                {
                                    session.PackagesHandled.Add(packageName);
                                }
                            }
                        }
                    }

                    if (sessionElement.TryGetProperty("start_time", out var startTimeProp) && 
                        startTimeProp.ValueKind != JsonValueKind.Null &&
                        DateTime.TryParse(startTimeProp.GetString(), out var startTime))
                    {
                        session.StartTime = startTime;
                    }

                    if (sessionElement.TryGetProperty("end_time", out var endTimeProp) && 
                        endTimeProp.ValueKind != JsonValueKind.Null &&
                        DateTime.TryParse(endTimeProp.GetString(), out var endTime))
                    {
                        session.EndTime = endTime;
                        session.Duration = endTime - session.StartTime;
                    }

                    if (sessionElement.TryGetProperty("environment", out var envProp))
                    {
                        foreach (var envItem in envProp.EnumerateObject())
                        {
                            session.Environment[envItem.Name] = envItem.Value.ToString();
                        }
                    }

                    sessions.Add(session);
                }

                // Sort by start time descending (most recent first)
                sessions = sessions.OrderByDescending(s => s.StartTime).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read Cimian sessions report from {FilePath}", filePath);
            }

            return sessions;
        }

        private List<Dictionary<string, object>> ReadCimianItemsReport(string filePath)
        {
            var items = new List<Dictionary<string, object>>();
            
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogDebug("Cimian items report file not found: {FilePath}", filePath);
                    return items;
                }

                var json = File.ReadAllText(filePath);
                using var document = JsonDocument.Parse(json);
                
                foreach (var itemElement in document.RootElement.EnumerateArray())
                {
                    var item = new Dictionary<string, object>();
                    
                    foreach (var property in itemElement.EnumerateObject())
                    {
                        switch (property.Value.ValueKind)
                        {
                            case JsonValueKind.String:
                                item[property.Name] = property.Value.GetString() ?? "";
                                break;
                            case JsonValueKind.Number:
                                item[property.Name] = property.Value.GetInt32();
                                break;
                            case JsonValueKind.True:
                            case JsonValueKind.False:
                                item[property.Name] = property.Value.GetBoolean();
                                break;
                            case JsonValueKind.Array:
                                var arrayItems = new List<Dictionary<string, object>>();
                                foreach (var arrayElement in property.Value.EnumerateArray())
                                {
                                    var arrayItem = new Dictionary<string, object>();
                                    foreach (var arrayProp in arrayElement.EnumerateObject())
                                    {
                                        arrayItem[arrayProp.Name] = arrayProp.Value.GetString() ?? "";
                                    }
                                    arrayItems.Add(arrayItem);
                                }
                                item[property.Name] = arrayItems;
                                break;
                            default:
                                item[property.Name] = property.Value.ToString();
                                break;
                        }
                    }
                    
                    items.Add(item);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read Cimian items report from {FilePath}", filePath);
            }

            return items;
        }

        private List<CimianEvent> ReadCimianEventsReport(string filePath)
        {
            var events = new List<CimianEvent>();
            
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogDebug("Cimian events report file not found: {FilePath}", filePath);
                    return events;
                }

                var json = File.ReadAllText(filePath);
                using var document = JsonDocument.Parse(json);
                
                foreach (var eventElement in document.RootElement.EnumerateArray())
                {
                    var cimianEvent = new CimianEvent
                    {
                        EventId = eventElement.GetProperty("event_id").GetString() ?? "",
                        SessionId = eventElement.GetProperty("session_id").GetString() ?? "",
                        Level = eventElement.GetProperty("level").GetString() ?? "",
                        EventType = eventElement.GetProperty("event_type").GetString() ?? "",
                        Action = eventElement.GetProperty("action").GetString() ?? "",
                        Status = eventElement.GetProperty("status").GetString() ?? "",
                        Message = eventElement.GetProperty("message").GetString() ?? "",
                        SourceFile = eventElement.GetProperty("source_file").GetString() ?? "",
                        SourceFunction = eventElement.GetProperty("source_function").GetString() ?? "",
                        SourceLine = eventElement.GetProperty("source_line").GetInt32()
                    };

                    // Enhanced fields from new Cimian structure
                    if (eventElement.TryGetProperty("package", out var packageProp) && packageProp.ValueKind != JsonValueKind.Null)
                    {
                        cimianEvent.Package = packageProp.GetString() ?? "";
                    }

                    if (eventElement.TryGetProperty("version", out var versionProp) && versionProp.ValueKind != JsonValueKind.Null)
                    {
                        cimianEvent.Version = versionProp.GetString() ?? "";
                    }

                    if (eventElement.TryGetProperty("log_file", out var logFileProp) && logFileProp.ValueKind != JsonValueKind.Null)
                    {
                        cimianEvent.LogFile = logFileProp.GetString() ?? "";
                    }

                    if (eventElement.TryGetProperty("context", out var contextProp) && contextProp.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var contextItem in contextProp.EnumerateObject())
                        {
                            cimianEvent.Context[contextItem.Name] = contextItem.Value.ToString();
                        }
                    }

                    if (eventElement.TryGetProperty("timestamp", out var timestampProp) &&
                        DateTime.TryParse(timestampProp.GetString(), out var timestamp))
                    {
                        cimianEvent.Timestamp = timestamp;
                    }

                    if (eventElement.TryGetProperty("error", out var errorProp) && errorProp.ValueKind != JsonValueKind.Null)
                    {
                        cimianEvent.Error = errorProp.GetString() ?? "";
                    }

                    if (eventElement.TryGetProperty("progress", out var progressProp) && progressProp.ValueKind != JsonValueKind.Null)
                    {
                        cimianEvent.Progress = progressProp.GetInt32();
                    }

                    events.Add(cimianEvent);
                }

                // Sort by timestamp descending (most recent first)
                events = events.OrderByDescending(e => e.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read Cimian events report from {FilePath}", filePath);
            }

            return events;
        }

        private void ProcessManagedItemsFromReport(List<Dictionary<string, object>> items, InstallsData data)
        {
            try
            {
                _logger.LogInformation("Processing {ItemCount} items from Cimian report", items.Count);
                
                foreach (var item in items)
                {
                    // Debug: Log all available keys in this item
                    var availableKeys = string.Join(", ", item.Keys);
                    _logger.LogDebug("Processing item with keys: {AvailableKeys}", availableKeys);
                    
                    // Enhanced: Extract version and status from recent_attempts array
                    string extractedVersion = "";
                    string cimianStatus = "";
                    
                    if (item.TryGetValue("recent_attempts", out var attemptsList) && 
                        attemptsList is List<Dictionary<string, object>> attemptArray && 
                        attemptArray.Count > 0)
                    {
                        // Get the most recent attempt (latest entry in the array)
                        var latestAttempt = attemptArray.LastOrDefault();
                        if (latestAttempt != null)
                        {
                            extractedVersion = GetDictValue(latestAttempt, "version");
                            cimianStatus = GetDictValue(latestAttempt, "status");
                            _logger.LogDebug("Extracted from recent_attempts - version: '{Version}', status: '{Status}'", 
                                extractedVersion, cimianStatus);
                        }
                    }
                    
                    // Primary fields - use new Cimian field names with proper empty string handling
                    if (string.IsNullOrEmpty(extractedVersion))
                    {
                        var latestVersion = GetDictValue(item, "latest_version");
                        var installedVersion = GetDictValue(item, "installed_version");
                        
                        // Debug logging to see what we're actually getting
                        var debugItemId = GetDictValue(item, "id");
                        _logger.LogInformation("DEBUG VERSION EXTRACTION - Item: {ItemId}, latest_version: '{LatestVersion}', installed_version: '{InstalledVersion}'", 
                            debugItemId, latestVersion, installedVersion);
                        
                        if (!string.IsNullOrEmpty(latestVersion))
                        {
                            extractedVersion = latestVersion;
                            _logger.LogInformation("DEBUG VERSION - Using latest_version: {Version} for {ItemId}", latestVersion, debugItemId);
                        }
                        else if (!string.IsNullOrEmpty(installedVersion))
                        {
                            extractedVersion = installedVersion;
                            _logger.LogInformation("DEBUG VERSION - Using installed_version: {Version} for {ItemId}", installedVersion, debugItemId);
                        }
                        else
                        {
                            extractedVersion = "Unknown";
                            _logger.LogInformation("DEBUG VERSION - No version found, using Unknown for {ItemId}", debugItemId);
                        }
                    }
                    if (string.IsNullOrEmpty(cimianStatus))
                    {
                        cimianStatus = GetDictValue(item, "current_status") ?? "Unknown";
                    }
                    
                    // Check for install loop detection flag
                    bool hasInstallLoop = false;
                    if (item.TryGetValue("install_loop_detected", out var installLoopObj) && 
                        installLoopObj != null &&
                        bool.TryParse(installLoopObj.ToString(), out var loopDetected))
                    {
                        hasInstallLoop = loopDetected;
                    }
                    
                    // ENHANCEMENT: If version is "Unknown", override status to "Error" regardless of current_status
                    if (extractedVersion == "Unknown" || string.IsNullOrEmpty(extractedVersion))
                    {
                        cimianStatus = "Error"; // Use uppercase to match existing patterns
                        _logger.LogInformation("OVERRIDE STATUS - Item {ItemId}: version='{Version}' -> forcing status to 'Error'", 
                            GetDictValue(item, "id"), extractedVersion);
                    }
                    
                    // Map Cimian's detailed status to ReportMate's simplified dashboard status
                    var reportMateStatus = MapCimianStatusToReportMate(cimianStatus, hasInstallLoop);
                    
                    // Debug: Log key field values
                    var itemId = GetDictValue(item, "id");
                    var itemName = GetDictValue(item, "item_name") ?? GetDictValue(item, "name") ?? itemId;
                    var displayName = GetDictValue(item, "display_name") ?? itemName;
                    
                    _logger.LogInformation("Item [{ItemId}]: name='{ItemName}', display_name='{DisplayName}', version='{Version}', cimian_status='{CimianStatus}' -> mapped_status='{ReportMateStatus}'", 
                        itemId, itemName, displayName, extractedVersion, cimianStatus, reportMateStatus);

                    var managedInstall = new ManagedInstall
                    {
                        Id = itemId,
                        Name = itemName,
                        DisplayName = displayName,
                        ItemType = GetDictValue(item, "item_type"),
                        Status = reportMateStatus, // Enhanced: Use mapped ReportMate status
                        Version = extractedVersion, // Enhanced: Use version from recent_attempts
                        InstalledVersion = GetDictValue(item, "installed_version"),
                        LastSeenInSession = GetDictValue(item, "last_seen_in_session"),
                        LastAttemptStatus = GetDictValue(item, "last_attempt_status"),
                        InstallMethod = GetDictValue(item, "install_method"),
                        Type = GetDictValue(item, "type"),
                        Source = "Cimian"
                    };

                    // Also create CimianItem for the CimianInfo.Items collection  
                    var cimianItem = new CimianItem
                    {
                        Id = itemId,
                        ItemName = itemName,
                        DisplayName = displayName,
                        ItemType = GetDictValue(item, "item_type"),
                        CurrentStatus = cimianStatus, // Enhanced: Store original Cimian status for detailed tracking
                        LatestVersion = extractedVersion, // Enhanced: Use version from recent_attempts
                        InstalledVersion = GetDictValue(item, "installed_version"),
                        LastSeenInSession = GetDictValue(item, "last_seen_in_session"),
                        LastAttemptStatus = GetDictValue(item, "last_attempt_status"),
                        InstallMethod = GetDictValue(item, "install_method"),
                        Type = GetDictValue(item, "type")
                    };

                    // Parse timestamps
                    if (item.TryGetValue("last_successful_time", out var lastSuccessObj) && 
                        DateTime.TryParse(lastSuccessObj.ToString(), out var lastSuccess))
                    {
                        managedInstall.LastSuccessfulTime = lastSuccess;
                        managedInstall.InstallDate = lastSuccess; // Keep compatibility
                        cimianItem.LastSuccessfulTime = lastSuccess;
                    }

                    if (item.TryGetValue("last_attempt_time", out var lastAttemptObj) && 
                        DateTime.TryParse(lastAttemptObj.ToString(), out var lastAttempt))
                    {
                        managedInstall.LastAttemptTime = lastAttempt;
                        cimianItem.LastAttemptTime = lastAttempt;
                    }

                    if (item.TryGetValue("last_update", out var lastUpdateObj) && 
                        DateTime.TryParse(lastUpdateObj.ToString(), out var lastUpdate))
                    {
                        managedInstall.LastUpdate = lastUpdate;
                        cimianItem.LastUpdate = lastUpdate;
                    }

                    // Parse boolean values
                    if (item.TryGetValue("install_loop_detected", out var loopObj) && 
                        bool.TryParse(loopObj.ToString(), out var hasLoop))
                    {
                        managedInstall.HasInstallLoop = hasLoop;
                        cimianItem.InstallLoopDetected = hasLoop;
                    }

                    // Parse counts  
                    if (item.TryGetValue("install_runs", out var installRunsObj) && 
                        int.TryParse(installRunsObj.ToString(), out var installRuns))
                    {
                        managedInstall.InstallCount = installRuns;
                        cimianItem.InstallCount = installRuns;
                    }

                    if (item.TryGetValue("update_count", out var updateCountObj) && 
                        int.TryParse(updateCountObj.ToString(), out var updateCount))
                    {
                        managedInstall.UpdateCount = updateCount;
                        cimianItem.UpdateCount = updateCount;
                    }

                    if (item.TryGetValue("failure_count", out var failureCountObj) && 
                        int.TryParse(failureCountObj.ToString(), out var failureCount))
                    {
                        managedInstall.FailureCount = failureCount;
                        cimianItem.FailureCount = failureCount;
                    }

                    // Enhanced fields: Log additional counts for debugging
                    var removalCount = GetDictValue(item, "removal_count");
                    var warningCount = GetDictValue(item, "warning_count");
                    if (!string.IsNullOrEmpty(removalCount) || !string.IsNullOrEmpty(warningCount))
                    {
                        _logger.LogDebug("Item [{ItemId}]: removal_count='{RemovalCount}', warning_count='{WarningCount}'", 
                            itemId, removalCount, warningCount);
                    }

                    if (item.TryGetValue("total_sessions", out var totalSessionsObj) && 
                        int.TryParse(totalSessionsObj.ToString(), out var totalSessions))
                    {
                        managedInstall.TotalSessions = totalSessions;
                        cimianItem.TotalSessions = totalSessions;
                    }

                    // Parse recent attempts array
                    if (item.TryGetValue("recent_attempts", out var recentAttemptsObj) && 
                        recentAttemptsObj is List<Dictionary<string, object>> recentAttempts)
                    {
                        managedInstall.RecentAttempts = recentAttempts;
                        cimianItem.RecentAttempts = recentAttempts;
                    }

                    // Add CimianItem to the CimianInfo.Items collection
                    if (data.Cimian != null)
                    {
                        data.Cimian.Items.Add(cimianItem);
                    }

                    // Add to pending packages list if not installed
                    if (data.Cimian != null && 
                        (managedInstall.Status.Equals("Pending", StringComparison.OrdinalIgnoreCase) ||
                         managedInstall.Status.Equals("Install Loop", StringComparison.OrdinalIgnoreCase) ||
                         managedInstall.Status.Equals("Failed", StringComparison.OrdinalIgnoreCase)))
                    {
                        var packageName = !string.IsNullOrEmpty(managedInstall.DisplayName) ? managedInstall.DisplayName : managedInstall.Name;
                        if (!string.IsNullOrEmpty(packageName) && !data.Cimian.PendingPackages.Contains(packageName))
                        {
                            data.Cimian.PendingPackages.Add(packageName);
                        }
                    }

                    // Categorize based on status for better organization
                    if (managedInstall.Status.Equals("Failed", StringComparison.OrdinalIgnoreCase) ||
                        managedInstall.Status.Equals("Install Loop", StringComparison.OrdinalIgnoreCase))
                    {
                        data.RecentInstalls.Add(managedInstall); // Failed items go to RecentInstalls for visibility
                    }
                    else
                    {
                        data.RecentInstalls.Add(managedInstall); // All items for now
                    }

                    _logger.LogDebug("Processed managed item: {Name} (Status: {Status}, Version: {Version}, Install Method: {Method})", 
                        managedInstall.Name, managedInstall.Status, managedInstall.Version, managedInstall.InstallMethod);
                }

                _logger.LogInformation("Processed {Count} managed items from Cimian reports, {PendingCount} pending packages identified", 
                    items.Count, data.Cimian?.PendingPackages.Count ?? 0);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing managed items from report");
            }
        }

        private string GetDictValue(Dictionary<string, object> dict, string key)
        {
            return dict.TryGetValue(key, out var value) ? value?.ToString() ?? "" : "";
        }

        /// <summary>
        /// Generate ReportMate events from processed Cimian data for dashboard display
        /// </summary>
        public override Task<List<ReportMateEvent>> GenerateEventsAsync(InstallsData data)
        {
            var events = new List<ReportMateEvent>();
            
            try
            {
                // Generate events from Cimian ERROR/WARN events
                if (data.RecentEvents?.Any() == true)
                {
                    // Process high priority events (ERROR, WARN) first
                    var priorityEvents = data.RecentEvents
                        .Where(e => e.Level.Equals("ERROR", StringComparison.OrdinalIgnoreCase) || 
                                   e.Level.Equals("WARN", StringComparison.OrdinalIgnoreCase))
                        .OrderByDescending(e => e.Timestamp)
                        .Take(10); // Limit to 10 most recent priority events

                    foreach (var cimianEvent in priorityEvents)
                    {
                        var eventType = cimianEvent.Level.ToLowerInvariant() == "error" ? "error" : "warning";
                        var message = $"Cimian {cimianEvent.EventType}: {cimianEvent.Message}";
                        
                        var details = new Dictionary<string, object>
                        {
                            ["action"] = cimianEvent.Action,
                            ["status"] = cimianEvent.Status,
                            ["session_id"] = cimianEvent.SessionId,
                            ["event_id"] = cimianEvent.EventId
                        };

                        if (!string.IsNullOrEmpty(cimianEvent.Package))
                            details["package"] = cimianEvent.Package;
                        if (!string.IsNullOrEmpty(cimianEvent.Version))
                            details["version"] = cimianEvent.Version;
                        if (!string.IsNullOrEmpty(cimianEvent.Error))
                            details["error_details"] = cimianEvent.Error;
                        if (!string.IsNullOrEmpty(cimianEvent.SourceFile))
                            details["source"] = $"{cimianEvent.SourceFile}:{cimianEvent.SourceLine}";

                        events.Add(CreateEvent(eventType, message, details, cimianEvent.Timestamp));
                    }
                }
                
                // Generate events from session failures
                if (data.RecentSessions?.Any() == true)
                {
                    var failedSessions = data.RecentSessions
                        .Where(s => s.Status.Equals("FAILED", StringComparison.OrdinalIgnoreCase) || s.Failures > 0)
                        .OrderByDescending(s => s.StartTime)
                        .Take(5); // Limit to 5 most recent failed sessions

                    foreach (var session in failedSessions)
                    {
                        var eventType = session.Status.Equals("FAILED", StringComparison.OrdinalIgnoreCase) ? "error" : "warning";
                        var message = $"Cimian session {session.SessionId} completed with {session.Failures} failures";
                        
                        var details = new Dictionary<string, object>
                        {
                            ["session_id"] = session.SessionId,
                            ["run_type"] = session.RunType,
                            ["failures"] = session.Failures,
                            ["successes"] = session.Successes,
                            ["total_actions"] = session.TotalActions,
                            ["duration_seconds"] = session.DurationSeconds
                        };

                        if (session.PackagesHandled?.Any() == true)
                            details["packages"] = string.Join(", ", session.PackagesHandled.Take(5));

                        events.Add(CreateEvent(eventType, message, details, session.StartTime));
                    }
                }

                // Generate info events for successful operations (limited)
                if (data.Cimian?.IsInstalled == true && events.Count < 3)
                {
                    var recentSuccessfulSessions = data.RecentSessions?
                        .Where(s => s.Status.Equals("SUCCESS", StringComparison.OrdinalIgnoreCase) && s.Successes > 0)
                        .OrderByDescending(s => s.StartTime)
                        .Take(2);

                    foreach (var session in recentSuccessfulSessions ?? Enumerable.Empty<CimianSession>())
                    {
                        var message = $"Cimian session completed successfully with {session.Successes} packages processed";
                        var details = new Dictionary<string, object>
                        {
                            ["session_id"] = session.SessionId,
                            ["successes"] = session.Successes,
                            ["installs"] = session.Installs,
                            ["updates"] = session.Updates,
                            ["removals"] = session.Removals
                        };

                        events.Add(CreateEvent("success", message, details, session.StartTime));
                    }
                }

                // Generate events from enhanced analytics and recommendations
                if (data.CacheStatus.TryGetValue("enhanced_analytics", out var analyticsObj) && analyticsObj is Dictionary<string, object> analytics)
                {
                    // Generate performance alert events
                    if (analytics.TryGetValue("performance", out var perfObj) && perfObj is object perfData)
                    {
                        try
                        {
                            var perfDict = JsonSerializer.Deserialize<Dictionary<string, object>>(JsonSerializer.Serialize(perfData));
                            
                            if (perfDict?.TryGetValue("success_rate", out var successRateObj) == true 
                                && double.TryParse(successRateObj.ToString(), out var successRate))
                            {
                                if (successRate < 50)
                                {
                                    events.Add(CreateEvent("error", 
                                        $"Critical: Cimian session success rate is {successRate:F1}%", 
                                        new Dictionary<string, object> 
                                        { 
                                            ["success_rate"] = successRate,
                                            ["threshold"] = 50,
                                            ["category"] = "performance_alert"
                                        }));
                                }
                                else if (successRate < 80)
                                {
                                    events.Add(CreateEvent("warning", 
                                        $"Cimian session success rate is {successRate:F1}%", 
                                        new Dictionary<string, object> 
                                        { 
                                            ["success_rate"] = successRate,
                                            ["threshold"] = 80,
                                            ["category"] = "performance_warning"
                                        }));
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug("Error processing performance analytics for events: {Error}", ex.Message);
                        }
                    }

                    // Generate blocking application events
                    if (analytics.TryGetValue("blocking_applications", out var blockingObj))
                    {
                        events.Add(CreateEvent("warning", 
                            "Blocking applications detected during Cimian sessions", 
                            new Dictionary<string, object> 
                            { 
                                ["category"] = "blocking_applications",
                                ["recommendation"] = "Schedule installations during maintenance windows"
                            }));
                    }

                    // Generate events from performance recommendations
                    if (data.CacheStatus.TryGetValue("performance_recommendations", out var recommendationsObj) 
                        && recommendationsObj is List<string> recommendations && recommendations.Any())
                    {
                        var criticalRecommendations = recommendations.Where(r => r.StartsWith("Critical:")).ToList();
                        var warningRecommendations = recommendations.Except(criticalRecommendations).Take(2).ToList();

                        foreach (var criticalRec in criticalRecommendations.Take(1))
                        {
                            events.Add(CreateEvent("error", criticalRec, 
                                new Dictionary<string, object> 
                                { 
                                    ["category"] = "critical_recommendation",
                                    ["type"] = "performance_issue"
                                }));
                        }

                        foreach (var warningRec in warningRecommendations)
                        {
                            events.Add(CreateEvent("warning", warningRec, 
                                new Dictionary<string, object> 
                                { 
                                    ["category"] = "performance_recommendation",
                                    ["type"] = "optimization_opportunity"
                                }));
                        }
                    }
                }

                _logger.LogDebug("Generated {EventCount} ReportMate events from Cimian data", events.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error generating events from Cimian data");
                
                // Add error event for the generation failure itself
                events.Add(CreateEvent("error", "Failed to process Cimian events for dashboard display", 
                    new Dictionary<string, object> { ["error"] = ex.Message }));
            }

            return Task.FromResult(events);
        }

        private void CollectPendingPackages(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, CimianInfo cimianInfo)
        {
            try
            {
                // Try to collect pending packages from manifest files
                if (osqueryResults.TryGetValue("cimian_manifests_structure", out var manifests))
                {
                    foreach (var manifest in manifests)
                    {
                        var manifestPath = GetStringValue(manifest, "path");
                        var manifestName = GetStringValue(manifest, "manifest_name");
                        
                        if (!string.IsNullOrEmpty(manifestPath) && File.Exists(manifestPath))
                        {
                            try
                            {
                                var yamlContent = File.ReadAllText(manifestPath);
                                // Simple parsing for managed_installs - you could use a proper YAML parser here
                                if (yamlContent.Contains("managed_installs:"))
                                {
                                    var lines = yamlContent.Split('\n');
                                    bool inManagedInstalls = false;
                                    
                                    foreach (var line in lines)
                                    {
                                        var trimmedLine = line.Trim();
                                        if (trimmedLine.StartsWith("managed_installs:"))
                                        {
                                            inManagedInstalls = true;
                                            continue;
                                        }
                                        
                                        if (inManagedInstalls)
                                        {
                                            if (trimmedLine.StartsWith("-"))
                                            {
                                                var packageName = trimmedLine.Substring(1).Trim();
                                                if (!string.IsNullOrEmpty(packageName) && !cimianInfo.PendingPackages.Contains(packageName))
                                                {
                                                    cimianInfo.PendingPackages.Add(packageName);
                                                }
                                            }
                                            else if (!trimmedLine.StartsWith(" ") && !string.IsNullOrEmpty(trimmedLine))
                                            {
                                                // We've moved to a different section
                                                inManagedInstalls = false;
                                            }
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Failed to parse manifest file {ManifestPath}: {Error}", manifestPath, ex.Message);
                            }
                        }
                    }
                }

                // Also try to get pending packages from self-serve manifest
                if (osqueryResults.TryGetValue("cimian_self_serve_manifest", out var selfServeManifests))
                {
                    foreach (var selfServe in selfServeManifests)
                    {
                        var selfServePath = GetStringValue(selfServe, "path");
                        if (!string.IsNullOrEmpty(selfServePath) && File.Exists(selfServePath))
                        {
                            try
                            {
                                var yamlContent = File.ReadAllText(selfServePath);
                                if (yamlContent.Contains("managed_installs:"))
                                {
                                    var lines = yamlContent.Split('\n');
                                    bool inManagedInstalls = false;
                                    
                                    foreach (var line in lines)
                                    {
                                        var trimmedLine = line.Trim();
                                        if (trimmedLine.StartsWith("managed_installs:"))
                                        {
                                            inManagedInstalls = true;
                                            continue;
                                        }
                                        
                                        if (inManagedInstalls && trimmedLine.StartsWith("-"))
                                        {
                                            var packageName = trimmedLine.Substring(1).Trim();
                                            if (!string.IsNullOrEmpty(packageName) && !cimianInfo.PendingPackages.Contains(packageName))
                                            {
                                                cimianInfo.PendingPackages.Add(packageName);
                                            }
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Failed to parse self-serve manifest file {SelfServePath}: {Error}", selfServePath, ex.Message);
                            }
                        }
                    }
                }

                _logger.LogDebug("Collected {Count} pending packages from Cimian manifests", cimianInfo.PendingPackages.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error collecting pending packages from Cimian data");
            }
        }

        public override async Task<bool> ValidateModuleDataAsync(InstallsData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && data.ModuleId == ModuleId;

            if (!isValid)
            {
                _logger.LogWarning("Installs module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        /// <summary>
        /// Generate enhanced analytics from structured logging data
        /// </summary>
        private Dictionary<string, object> GenerateEnhancedAnalytics(InstallsData data)
        {
            var analytics = new Dictionary<string, object>();

            try
            {
                // Performance analytics
                if (data.RecentSessions?.Any() == true)
                {
                    var sessions = data.RecentSessions;
                    analytics["performance"] = new PerformanceAnalytics
                    {
                        AvgSessionDuration = sessions.Average(s => s.DurationSeconds),
                        TotalSessions = sessions.Count,
                        SuccessfulSessions = sessions.Count(s => s.Status.Equals("completed", StringComparison.OrdinalIgnoreCase)),
                        FailedSessions = sessions.Count(s => s.Status.Equals("failed", StringComparison.OrdinalIgnoreCase)),
                        SuccessRate = sessions.Any() ? (double)sessions.Count(s => s.Status.Equals("completed", StringComparison.OrdinalIgnoreCase)) / sessions.Count * 100 : 0,
                        AvgPackagesPerSession = sessions.Average(s => s.TotalPackagesManaged),
                        TotalInstalls = sessions.Sum(s => s.Installs),
                        TotalUpdates = sessions.Sum(s => s.Updates),
                        TotalRemovals = sessions.Sum(s => s.Removals)
                    };

                    // Batch operations analytics
                    var batchOperations = sessions.SelectMany(s => s.BatchOperations).ToList();
                    if (batchOperations.Any())
                    {
                        analytics["batch_operations"] = new BatchOperationsAnalytics
                        {
                            TotalBatches = batchOperations.Count,
                            AvgBatchSize = batchOperations.Average(b => b.TotalItems),
                            BatchSuccessRate = (double)batchOperations.Sum(b => b.SuccessfulItems) / batchOperations.Sum(b => b.TotalItems) * 100,
                            AvgBatchDuration = batchOperations.Where(b => b.Duration.HasValue).Any() ? 
                                               batchOperations.Where(b => b.Duration.HasValue).Average(b => b.Duration!.Value.TotalSeconds) : 0
                        };
                    }

                    // Blocking applications analytics
                    var allBlockingApps = sessions.SelectMany(s => s.BlockingApplications).ToList();
                    if (allBlockingApps.Any())
                    {
                        var blockingAppsDict = allBlockingApps
                            .SelectMany(ba => ba.Value.Select(app => new { Package = ba.Key, App = app }))
                            .GroupBy(x => x.App)
                            .OrderByDescending(g => g.Count())
                            .Take(10)
                            .ToDictionary(g => g.Key, g => new BlockingApplicationInfo
                            {
                                Count = g.Count(),
                                AffectedPackages = g.Select(x => x.Package).Distinct().ToList()
                            });
                        
                        analytics["blocking_applications"] = blockingAppsDict;
                    }

                    // Performance trends (if we have timestamped data)
                    var sortedSessions = sessions.OrderBy(s => s.StartTime).ToList();
                    if (sortedSessions.Count >= 5)
                    {
                        var recentSessions = sortedSessions.TakeLast(5).ToList();
                        var olderSessions = sortedSessions.Take(sortedSessions.Count - 5).ToList();
                        
                        if (olderSessions.Any())
                        {
                            analytics["performance_trends"] = new PerformanceTrends
                            {
                                RecentAvgDuration = recentSessions.Average(s => s.DurationSeconds),
                                HistoricalAvgDuration = olderSessions.Average(s => s.DurationSeconds),
                                RecentSuccessRate = (double)recentSessions.Count(s => s.Successes > s.Failures) / recentSessions.Count * 100,
                                HistoricalSuccessRate = (double)olderSessions.Count(s => s.Successes > s.Failures) / olderSessions.Count * 100
                            };
                        }
                    }
                }

                // Event-level analytics
                if (data.RecentEvents?.Any() == true)
                {
                    var events = data.RecentEvents;
                    
                    analytics["events"] = new EventAnalytics
                    {
                        TotalEvents = events.Count,
                        ErrorEvents = events.Count(e => e.Level.Equals("ERROR", StringComparison.OrdinalIgnoreCase)),
                        WarningEvents = events.Count(e => e.Level.Equals("WARNING", StringComparison.OrdinalIgnoreCase)),
                        InstallEvents = events.Count(e => e.EventType.Equals("install", StringComparison.OrdinalIgnoreCase)),
                        AvgInstallDuration = events.Where(e => e.EventType.Equals("install", StringComparison.OrdinalIgnoreCase) && e.Duration.HasValue).Any() ?
                                                        events.Where(e => e.EventType.Equals("install", StringComparison.OrdinalIgnoreCase) && e.Duration.HasValue)
                                                              .Average(e => e.Duration!.Value.TotalSeconds) : 0,
                        MostCommonErrors = events.Where(e => !string.IsNullOrEmpty(e.Error))
                                                      .GroupBy(e => e.Error)
                                                      .OrderByDescending(g => g.Count())
                                                      .Take(5)
                                                      .ToDictionary(g => g.Key, g => g.Count())
                    };

                    // Package-specific analytics
                    var packageEvents = events.Where(e => !string.IsNullOrEmpty(e.Package)).ToList();
                    if (packageEvents.Any())
                    {
                        var packageAnalyticsDict = packageEvents
                            .GroupBy(e => e.Package)
                            .OrderByDescending(g => g.Count())
                            .Take(10)
                            .ToDictionary(g => g.Key, g => new PackageAnalytics
                            {
                                TotalEvents = g.Count(),
                                SuccessEvents = g.Count(e => e.Status.Equals("completed", StringComparison.OrdinalIgnoreCase)),
                                ErrorEvents = g.Count(e => e.Status.Equals("failed", StringComparison.OrdinalIgnoreCase)),
                                AvgDuration = g.Where(e => e.Duration.HasValue).Any() ? 
                                             g.Where(e => e.Duration.HasValue).Average(e => e.Duration!.Value.TotalSeconds) : 0
                            });
                        
                        analytics["package_analytics"] = packageAnalyticsDict;
                    }
                }

                _logger.LogDebug("Generated enhanced analytics with {AnalyticsCount} categories", analytics.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error generating enhanced analytics");
                analytics["error"] = "Failed to generate analytics";
            }

            return analytics;
        }

        /// <summary>
        /// Generate performance recommendations based on analytics
        /// </summary>
        private List<string> GeneratePerformanceRecommendations(Dictionary<string, object> analytics)
        {
            var recommendations = new List<string>();

            try
            {
                // Check session performance
                if (analytics.TryGetValue("performance", out var perfObj) && perfObj is PerformanceAnalytics perfData)
                {
                    if (perfData.SuccessRate < 80)
                    {
                        recommendations.Add($"Session success rate is {perfData.SuccessRate:F1}% - consider investigating common failure patterns");
                    }
                    
                    if (perfData.SuccessRate < 50)
                    {
                        recommendations.Add("Critical: Session success rate is below 50% - immediate attention required");
                    }

                    if (perfData.AvgSessionDuration > 1800) // 30 minutes
                    {
                        recommendations.Add($"Average session duration is {perfData.AvgSessionDuration/60:F1} minutes - consider optimizing package installation order");
                    }
                }

                // Check blocking applications
                if (analytics.TryGetValue("blocking_applications", out var blockingObj))
                {
                    recommendations.Add("Blocking applications detected - consider scheduling installations during maintenance windows");
                }

                // Check performance trends
                if (analytics.TryGetValue("performance_trends", out var trendsObj) && trendsObj is PerformanceTrends trendsData)
                {
                    if (trendsData.RecentAvgDuration > trendsData.HistoricalAvgDuration * 1.5)
                    {
                        recommendations.Add("Recent sessions are taking significantly longer than historical average - investigate system performance");
                    }
                }

                // Check error patterns
                if (analytics.TryGetValue("events", out var eventsObj) && eventsObj is EventAnalytics eventsData)
                {
                    var errorRate = eventsData.TotalEvents > 0 ? (double)eventsData.ErrorEvents / eventsData.TotalEvents * 100 : 0;
                    if (errorRate > 20)
                    {
                        recommendations.Add($"High error rate detected ({errorRate:F1}%) - review error patterns and system health");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error generating performance recommendations");
                recommendations.Add("Unable to generate performance recommendations due to analysis error");
            }

            return recommendations;
        }
    }
}
