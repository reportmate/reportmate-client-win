#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json;
using System.Linq;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services.Modules
{
        /// <summary>
        /// Installs module processor - Managed software systems with enhanced Cimian integration
        /// </summary>
        public class InstallsModuleProcessor : BaseModuleProcessor<InstallsData>
        {
            private readonly ILogger<InstallsModuleProcessor> _logger;
            
            // JSON serializer options to support reflection-based deserialization
            private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                TypeInfoResolver = ReportMateJsonContext.Default
            };

        public override string ModuleId => "installs";

        /// <summary>
        /// Flag to bypass the running process check.
        /// Set to true when running in a triggered context (e.g. --run-module) where we know it's safe.
        /// </summary>
        public bool BypassRunningCheck { get; set; } = false;

        public InstallsModuleProcessor(ILogger<InstallsModuleProcessor> logger)
        {
            _logger = logger;
        }            /// <summary>
            /// Maps Cimian's detailed status values to ReportMate's simplified dashboard statuses
            /// Uses only: Installed, Pending, Warning, Error, Removed
            /// Updated for Cimian v2025.09.03+ enhanced status vocabulary
            /// </summary>
            private static string MapCimianStatusToReportMate(string cimianStatus, bool hasInstallLoop = false)
            {
                if (string.IsNullOrEmpty(cimianStatus))
                    return "Pending";  // Default unknown to Pending

                // Map enhanced Cimian status vocabulary to ReportMate statuses
                return cimianStatus.ToLowerInvariant() switch
                {
                    // SUCCESS MAPPINGS - Successfully installed and working
                    "installed" => "Installed",
                    "success" => "Installed",
                    
                    // ERROR MAPPINGS - Failed installation or critical issues
                    "failed" => "Error",
                    "error" => "Error", 
                    "fail" => "Error",
                    
                    // WARNING MAPPINGS - Installed but with issues or install loops
                    "warning" => "Warning",
                    "install loop" => "Warning",  // Install Loop → Warning (per spec)
                    "not installed" => "Warning", // Not Installed → Warning (per spec)
                    
                    // PENDING MAPPINGS - Needs action or in progress
                    "pending" => "Pending",
                    "pending install" => "Pending", // Pending Install → Pending (per spec)
                    "skipped" => "Pending",         // Skipped → Pending (per spec)
                    "unknown" => "Pending",         // Unknown → Pending (per spec)
                    "available" => "Pending",
                    "update available" => "Pending",
                    "downloading" => "Pending",
                    "installing" => "Pending",
                    
                    // REMOVED - Uninstalled or removed
                    "removed" => "Removed",
                    "uninstalled" => "Removed",
                    
                    _ => "Pending" // Default unknown to Pending
                };
            }

            /// <summary>
            /// Maps Cimian event status values to ReportMate dashboard statuses
            /// Specifically for events.json status field mapping per Cimian v25.9.3+ specification
            /// </summary>
            private static string MapCimianEventStatusToReportMate(string eventStatus)
            {
                if (string.IsNullOrEmpty(eventStatus))
                    return "Pending";  // Default unknown to Pending

                // Map Cimian event status vocabulary to ReportMate statuses
                return eventStatus.ToLowerInvariant() switch
                {
                    // SUCCESS MAPPINGS - Operation completed successfully
                    "success" => "Installed",  // Success → Installed (per spec)
                    
                    // ERROR MAPPINGS - Operation failed with error  
                    "failed" => "Error",       // Failed → Error (per spec)
                    
                    // WARNING MAPPINGS - Operation completed with warnings
                    "warning" => "Warning",    // Warning → Warning (per spec)
                    
                    // PENDING MAPPINGS - Operation waiting/queued/skipped/unknown
                    "pending" => "Pending",    // Pending → Pending (per spec)
                    "skipped" => "Pending",    // Skipped → Pending (per spec)
                    "unknown" => "Pending",    // Unknown → Pending (per spec)
                    
                    _ => "Pending" // Default unknown to Pending
                };
            }        public override async Task<InstallsData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            // Check if managedsoftwareupdate is running to avoid race conditions
            // Skip this check if BypassRunningCheck is true (e.g. triggered run)
            if (!BypassRunningCheck && IsManagedSoftwareUpdateRunning())
            {
                var msg = "Cimian managedsoftwareupdate is currently running. Skipping Installs module collection to avoid race conditions.";
                _logger.LogWarning(msg);
                throw new InvalidOperationException(msg);
            }

            _logger.LogDebug("Processing Installs module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new InstallsData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process Cimian information
            data.Cimian = await ProcessCimianInfo(osqueryResults);
            
            // Process Cimian configuration (config.yaml)
            ProcessCimianConfiguration(osqueryResults, data);
            
            // Process Cimian reports data (sessions, items, events)
            ProcessCimianReports(osqueryResults, data);
            
            // Process cache status
            ProcessCacheStatus(osqueryResults, data);

            // Process run log
            ProcessRunLog(data);

            data.LastCheckIn = DateTime.UtcNow;

            _logger.LogInformation("Installs module processed for device {DeviceId} - Cimian installed: {CimianInstalled}, Items: {ItemCount}", 
                deviceId, data.Cimian?.IsInstalled ?? false, data.Cimian?.Items?.Count ?? 0);

            return data;
        }

        private bool IsManagedSoftwareUpdateRunning()
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    if (p.ProcessName.Equals("managedsoftwareupdate", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check if managedsoftwareupdate is running");
                return false; // Assume not running if check fails
            }
        }

        private async Task<CimianInfo> ProcessCimianInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
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

            // Check for Cimian scheduled tasks
            await CheckCimianScheduledTasks(cimianInfo);

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
                    var registryVersion = GetStringValue(cimianSoftware, "version");
                    
                    // Instead of using registry version directly, try to get full version from executable
                    var cimianExePath = @"C:\Program Files\Cimian\managedsoftwareupdate.exe";
                    if (File.Exists(cimianExePath))
                    {
                        var versionFromExecution = await ExecuteManagedsoftwareupdateVersionAsync(cimianExePath);
                        if (!string.IsNullOrEmpty(versionFromExecution))
                        {
                            cimianInfo.Version = versionFromExecution;
                            _logger.LogDebug("Set Cimian version from --version command: {Version}", versionFromExecution);
                        }
                        else if (!string.IsNullOrEmpty(registryVersion))
                        {
                            // Transform registry version to full format (add 20 prefix if missing)
                            var fullVersion = registryVersion.StartsWith("20") ? registryVersion : "20" + registryVersion;
                            cimianInfo.Version = fullVersion;
                            _logger.LogDebug("Set Cimian version from registry (transformed): {RegistryVersion} -> {FullVersion}", registryVersion, fullVersion);
                        }
                    }
                    else if (!string.IsNullOrEmpty(registryVersion))
                    {
                        // Transform registry version to full format (add 20 prefix if missing)
                        var fullVersion = registryVersion.StartsWith("20") ? registryVersion : "20" + registryVersion;
                        cimianInfo.Version = fullVersion;
                        _logger.LogDebug("Set Cimian version from registry (exe not found, transformed): {RegistryVersion} -> {FullVersion}", registryVersion, fullVersion);
                    }
                    
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

            // Fallback: Try to get version directly from executing the executable with --version flag
            if (string.IsNullOrEmpty(cimianInfo.Version))
            {
                try
                {
                    var cimianExePath = @"C:\Program Files\Cimian\managedsoftwareupdate.exe";
                    if (File.Exists(cimianExePath))
                    {
                        // First try to execute with --version flag to get the full version string
                        var versionFromExecution = await ExecuteManagedsoftwareupdateVersionAsync(cimianExePath);
                        if (!string.IsNullOrEmpty(versionFromExecution))
                        {
                            cimianInfo.Version = versionFromExecution;
                            cimianInfo.IsInstalled = true;
                            _logger.LogDebug("Found Cimian executable version via --version command: {Version}", versionFromExecution);
                        }
                        else
                        {
                            // Fallback to FileVersionInfo if command execution fails
                            var versionInfo = FileVersionInfo.GetVersionInfo(cimianExePath);
                            if (!string.IsNullOrEmpty(versionInfo.FileVersion))
                            {
                                cimianInfo.Version = versionInfo.FileVersion;
                                cimianInfo.IsInstalled = true;
                                _logger.LogDebug("Found Cimian executable version via FileVersionInfo fallback: {Version}", versionInfo.FileVersion);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to get Cimian executable version: {Error}", ex.Message);
                }
            }

            // Final fallback: Check Windows registry for Cimian in installed programs, 
            // but if found, try to get the full version from the executable instead
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
                                        // Try to get the full version from the executable instead of using registry version
                                        var cimianExePath = @"C:\Program Files\Cimian\managedsoftwareupdate.exe";
                                        if (File.Exists(cimianExePath))
                                        {
                                            var versionFromExecution = await ExecuteManagedsoftwareupdateVersionAsync(cimianExePath);
                                            if (!string.IsNullOrEmpty(versionFromExecution))
                                            {
                                                cimianInfo.Version = versionFromExecution;
                                                _logger.LogDebug("Found Cimian version via --version command (registry fallback): {Version}", versionFromExecution);
                                            }
                                            else
                                            {
                                                // Use registry version as final fallback
                                                cimianInfo.Version = displayVersion;
                                                _logger.LogDebug("Found Cimian version in Windows registry (command failed): {Version}", displayVersion);
                                            }
                                        }
                                        else
                                        {
                                            // Use registry version if executable not found
                                            cimianInfo.Version = displayVersion;
                                            _logger.LogDebug("Found Cimian version in Windows registry (exe not found): {Version}", displayVersion);
                                        }
                                        
                                        cimianInfo.IsInstalled = true;
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
            }            // Check reports and configuration data
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
                    // Store sessions in Cimian data structure only
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
                        // Store sessions in Cimian data structure only
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

                // Process events from the LATEST SESSION's events.jsonl (authoritative for what happened this run)
                // This is the key fix: read from the session's events.jsonl, not reports/events.json
                const string CIMIAN_LOGS_PATH = @"C:\ProgramData\ManagedInstalls\logs";
                _logger.LogDebug("Looking for session events in: {LogsPath}", CIMIAN_LOGS_PATH);
                
                if (Directory.Exists(CIMIAN_LOGS_PATH) && data.Cimian != null)
                {
                    var sessionDirs = Directory.GetDirectories(CIMIAN_LOGS_PATH)
                        .OrderByDescending(d => Path.GetFileName(d))
                        .ToList();
                    
                    _logger.LogDebug("Found {SessionCount} session directories in logs", sessionDirs.Count);
                    
                    if (sessionDirs.Any())
                    {
                        var latestSessionDir = sessionDirs.First();
                        var latestSessionId = Path.GetFileName(latestSessionDir);
                        _logger.LogDebug("Reading events from latest session: {SessionId} ({SessionDir})", latestSessionId, latestSessionDir);
                        
                        // Read events from the latest session's events.jsonl
                        var sessionEvents = ReadCimianEventData(latestSessionDir, latestSessionId);
                        if (sessionEvents.Any())
                        {
                            data.Cimian.Events.AddRange(sessionEvents);
                            _logger.LogInformation("Loaded {Count} events from latest session {SessionId} events.jsonl", 
                                sessionEvents.Count, latestSessionId);
                        }
                        else
                        {
                            _logger.LogDebug("No events found in session {SessionId}", latestSessionId);
                        }
                    }
                }
                else
                {
                    _logger.LogDebug("Cimian logs path does not exist or Cimian data is null");
                }
                
                // Fallback: Try reports/events.json if no session events loaded
                if (data.Cimian?.Events?.Count == 0)
                {
                    var eventsPath = Path.Combine(CIMIAN_REPORTS_PATH, "events.json");
                    if (File.Exists(eventsPath))
                    {
                        var events = ReadCimianEventsReport(eventsPath);
                        if (data.Cimian != null && events.Any())
                        {
                            data.Cimian.Events.AddRange(events.Take(100));
                            _logger.LogDebug("Loaded {Count} events from reports/events.json (fallback)", events.Count);
                        }
                    }
                }

                // Set bootstrap mode status
                if (data.Cimian != null)
                {
                    data.BootstrapModeActive = data.Cimian.BootstrapFlagPresent;
                }

                // Enhanced cache status from most recent session
                if (data.Cimian?.Sessions?.Any() == true)
                {
                    var latestSession = data.Cimian?.Sessions?.FirstOrDefault();
                    if (latestSession?.CacheSizeMb > 0)
                    {
                        data.CacheStatus["cache_size_mb"] = latestSession.CacheSizeMb;
                        data.CacheStatus["last_updated"] = latestSession.StartTime.ToString("O");
                    }
                }

                _logger.LogInformation("Enhanced Cimian reports processing completed - Sessions: {Sessions}, Items: {Items}, Events: {Events}", 
                    (data.Cimian?.Sessions?.Count ?? 0), (data.Cimian?.Items?.Count ?? 0), (data.Cimian?.Events?.Count ?? 0));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing enhanced Cimian reports data");
            }
        }

        /// <summary>
        /// Determines status from recent attempts in the reports data
        /// </summary>
        private string DetermineStatusFromRecentAttempts(Dictionary<string, object> reportItem)
        {
            try
            {
                // Check if recent_attempts exists and has data
                if (reportItem.TryGetValue("recent_attempts", out var attemptsObj) && attemptsObj != null)
                {
                    var attemptsJson = JsonSerializer.Serialize(attemptsObj, JsonOptions);
                    var attempts = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(attemptsJson, JsonOptions);
                    
                    if (attempts != null && attempts.Count > 0)
                    {
                        // Get the most recent attempt status
                        var lastAttempt = attempts.Last();
                        if (lastAttempt.TryGetValue("status", out var statusObj))
                        {
                            var status = statusObj?.ToString();
                            if (!string.IsNullOrEmpty(status))
                            {
                                return status;
                            }
                        }
                    }
                }

                // Check if there's a current_status field
                if (reportItem.TryGetValue("current_status", out var currentStatusObj))
                {
                    var currentStatus = currentStatusObj?.ToString();
                    if (!string.IsNullOrEmpty(currentStatus))
                    {
                        return currentStatus;
                    }
                }

                // Fallback - determine status from installed vs latest versions
                var installedVersion = GetDictValue(reportItem, "installed_version");
                var latestVersion = GetDictValue(reportItem, "latest_version");
                
                if (string.IsNullOrEmpty(installedVersion) || installedVersion == "Unknown")
                {
                    return "Error"; // Not installed
                }
                
                if (!string.IsNullOrEmpty(latestVersion) && installedVersion != latestVersion)
                {
                    return "Pending"; // Update available
                }
                
                return "Installed"; // Up to date
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error determining status from recent attempts, using fallback");
                return "Unknown";
            }
        }

        /// <summary>
        /// Generates clean Cimian data snapshot directly from Cimian reports for clean integration
        /// This replaces the external PowerShell script approach
        /// Stores snapshot data directly in InstallsData.CimianSnapshot instead of separate file
        /// </summary>
        private void GenerateCimianSnapshot(InstallsData data, string sessionId)
        {
            try
            {
                _logger.LogDebug("Generating Cimian data snapshot internally for session {SessionId}...", sessionId);
                
                const string CIMIAN_REPORTS_PATH = @"C:\ProgramData\ManagedInstalls\reports";
                
                // No longer saving to file system - storing directly in data object
                // This keeps snapshot data contained within the module data structure
                
                // Check if Cimian reports exist
                if (!Directory.Exists(CIMIAN_REPORTS_PATH))
                {
                    _logger.LogDebug("Cimian reports directory not found: {Path}", CIMIAN_REPORTS_PATH);
                    return;
                }

                var itemsPath = Path.Combine(CIMIAN_REPORTS_PATH, "items.json");
                var sessionsPath = Path.Combine(CIMIAN_REPORTS_PATH, "sessions.json");
                var eventsPath = Path.Combine(CIMIAN_REPORTS_PATH, "events.json");

                if (!File.Exists(itemsPath) || !File.Exists(sessionsPath))
                {
                    _logger.LogDebug("Required Cimian report files not found for data generation");
                    return;
                }

                // Load data using source generator context
                var items = JsonSerializer.Deserialize(File.ReadAllText(itemsPath), ReportMateJsonContext.Default.ListDictionaryStringObject);
                var sessions = JsonSerializer.Deserialize(File.ReadAllText(sessionsPath), ReportMateJsonContext.Default.ListDictionaryStringObject);
                
                List<Dictionary<string, object>>? events = null;
                if (File.Exists(eventsPath))
                {
                    events = JsonSerializer.Deserialize(File.ReadAllText(eventsPath), ReportMateJsonContext.Default.ListDictionaryStringObject);
                }

                if (items == null || sessions == null)
                {
                    _logger.LogWarning("Failed to parse Cimian report data for data generation");
                    return;
                }

                // Get latest session
                var latestSession = sessions
                    .Where(s => s.ContainsKey("end_time") && s["end_time"] != null)
                    .OrderByDescending(s => s["end_time"]?.ToString())
                    .FirstOrDefault();
                    
                if (latestSession == null)
                {
                    latestSession = sessions
                        .OrderByDescending(s => s.ContainsKey("start_time") ? s["start_time"]?.ToString() : "")
                        .FirstOrDefault();
                }

                if (latestSession == null)
                {
                    _logger.LogWarning("No sessions found for data generation");
                    return;
                }

                // Build managed packages from items
                var managedPackages = new List<Dictionary<string, object>>();
                foreach (var item in items)
                {
                    var packageName = item.GetValueOrDefault("item_name", "Unknown")?.ToString() ?? "Unknown";
                    var currentVersion = item.GetValueOrDefault("installed_version", "Not Installed")?.ToString() ?? "Not Installed";
                    var latestVersion = item.GetValueOrDefault("latest_version", "Unknown")?.ToString() ?? "Unknown";
                    
                    // Determine status based on item data and recent attempts
                    var status = "Unknown";
                    var hasErrors = false;
                    
                    // Check recent attempts for status
                    if (item.ContainsKey("recent_attempts") && item["recent_attempts"] is JsonElement attemptsElement)
                    {
                        var attempts = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(attemptsElement.GetRawText());
                        if (attempts?.Any() == true)
                        {
                            var latestAttempt = attempts.OrderByDescending(a => a.GetValueOrDefault("timestamp", "")?.ToString()).FirstOrDefault();
                            if (latestAttempt?.GetValueOrDefault("status", "")?.ToString() == "Error")
                            {
                                hasErrors = true;
                            }
                        }
                    }
                    
                    // Determine final status
                    if (hasErrors)
                    {
                        status = "Error";
                    }
                    else if (!string.IsNullOrEmpty(currentVersion) && currentVersion != "Not Installed")
                    {
                        if (!string.IsNullOrEmpty(latestVersion) && currentVersion != latestVersion)
                        {
                            status = "Update Available";
                        }
                        else
                        {
                            status = "Installed";
                        }
                    }
                    else
                    {
                        status = "Pending Install";
                    }
                    
                    managedPackages.Add(new Dictionary<string, object>
                    {
                        ["name"] = packageName,
                        ["version"] = currentVersion,
                        ["latestVersion"] = latestVersion,
                        ["status"] = status,
                        ["lastUpdate"] = latestSession.GetValueOrDefault("start_time", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffK"))
                    });
                }

                // Extract warnings and errors from events
                var recentWarnings = new List<Dictionary<string, object>>();
                var recentErrors = new List<Dictionary<string, object>>();
                
                if (events != null)
                {
                    recentWarnings = events
                        .Where(e => e.GetValueOrDefault("level", "")?.ToString()?.ToUpper() is "WARNING" or "WARN")
                        .OrderByDescending(e => e.GetValueOrDefault("timestamp", "")?.ToString())
                        .Take(10)
                        .Select(e => new Dictionary<string, object>
                        {
                            ["sessionId"] = latestSession.GetValueOrDefault("session_id", ""),
                            ["package"] = e.GetValueOrDefault("package", ""),
                            ["message"] = e.GetValueOrDefault("message", ""),
                            ["timestamp"] = e.GetValueOrDefault("timestamp", "")
                        })
                        .ToList();
                        
                    recentErrors = events
                        .Where(e => e.GetValueOrDefault("level", "")?.ToString()?.ToUpper() == "ERROR")
                        .OrderByDescending(e => e.GetValueOrDefault("timestamp", "")?.ToString())
                        .Take(5)
                        .Select(e => new Dictionary<string, object>
                        {
                            ["sessionId"] = latestSession.GetValueOrDefault("session_id", ""),
                            ["package"] = e.GetValueOrDefault("package", ""),
                            ["message"] = e.GetValueOrDefault("message", ""),
                            ["timestamp"] = e.GetValueOrDefault("timestamp", "")
                        })
                        .ToList();
                }

                // Calculate cache size
                var cachePath = latestSession.ContainsKey("config") && latestSession["config"] is JsonElement configElement
                    ? JsonSerializer.Deserialize<Dictionary<string, object>>(configElement.GetRawText())?.GetValueOrDefault("cache_path", "")?.ToString()
                    : "";
                    
                var cacheSizeMb = 0.0;
                if (!string.IsNullOrEmpty(cachePath) && Directory.Exists(cachePath))
                {
                    try
                    {
                        var cacheSize = Directory.GetFiles(cachePath, "*", SearchOption.AllDirectories)
                            .Sum(file => new FileInfo(file).Length);
                        cacheSizeMb = Math.Round(cacheSize / (1024.0 * 1024.0), 2);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error calculating cache size for path: {CachePath}", cachePath);
                    }
                }

                // Build Cimian data snapshot
                var cimianSnapshot = new Dictionary<string, object>
                {
                    ["timestamp"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffK"),
                    ["summary"] = new Dictionary<string, object>
                    {
                        ["cacheSizeMb"] = cacheSizeMb,
                        ["totalPackagesManaged"] = managedPackages.Count,
                        ["packagesWithWarnings"] = recentWarnings.Select(w => w["package"]).Distinct().Count(),
                        ["packagesWithErrors"] = recentErrors.Select(e => e["package"]).Distinct().Count(),
                        ["packagesWithUpdates"] = managedPackages.Count(p => p["status"]?.ToString() == "Update Available")
                    },
                    ["lastRun"] = new Dictionary<string, object>
                    {
                        ["sessionId"] = latestSession.GetValueOrDefault("session_id", ""),
                        ["timestamp"] = latestSession.GetValueOrDefault("start_time", ""),
                        ["startTime"] = latestSession.GetValueOrDefault("start_time", ""),
                        ["endTime"] = latestSession.ContainsKey("end_time") && latestSession["end_time"] != null ? latestSession["end_time"] : "",
                        ["runType"] = latestSession.GetValueOrDefault("run_type", ""),
                        ["status"] = latestSession.GetValueOrDefault("status", ""),
                        ["durationSeconds"] = latestSession.GetValueOrDefault("duration_seconds", 0),
                        ["packagesHandled"] = latestSession.ContainsKey("packages_handled") ? latestSession["packages_handled"] : new List<object>(),
                        ["installLoopDetected"] = latestSession.GetValueOrDefault("install_loop_detected", false)
                    },
                    ["config"] = latestSession.ContainsKey("config") && latestSession["config"] is JsonElement configEl
                        ? JsonSerializer.Deserialize<Dictionary<string, object>>(configEl.GetRawText(), JsonOptions) ?? new Dictionary<string, object>()
                        : new Dictionary<string, object>(),
                    ["managedPackages"] = managedPackages,
                    ["recentWarnings"] = recentWarnings,
                    ["recentErrors"] = recentErrors.Any() ? recentErrors.First() : new Dictionary<string, object>()
                };

                // Store Cimian data snapshot directly in InstallsData object
                // This keeps the snapshot as part of the module data structure
                data.CimianSnapshot = cimianSnapshot;
                
                _logger.LogInformation("Cimian data snapshot generated for session {SessionId} and stored in module data - {PackageCount} packages, {UpdateCount} updates, {ErrorCount} errors", 
                    sessionId, managedPackages.Count, managedPackages.Count(p => p["status"]?.ToString() == "Update Available"), recentErrors.Count);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating Cimian snapshot internally");
            }
        }

        /// <summary>
        /// Process Cimian data structure for clean, focused reporting
        /// Transforms current complex Cimian data into the format needed for dashboard
        /// Returns true if processing was successful, false if fallback processing should be used
        /// Reads from CimianSnapshot stored in InstallsData object
        /// </summary>
        private bool ProcessCimianData(InstallsData data, string sessionId)
        {
            try
            {
                _logger.LogInformation("Processing Cimian data from object snapshot for {SessionId}...", sessionId);
                
                // Check if Cimian snapshot exists in the data object
                if (data.CimianSnapshot == null)
                {
                    _logger.LogWarning("Cimian snapshot not found in data object for session {SessionId}, falling back to standard processing", sessionId);
                    ProcessCimianDataFallback(data);
                    return false;
                }

                // Use Cimian snapshot from data object
                var cimianSnapshot = data.CimianSnapshot;
                
                if (cimianSnapshot == null)
                {
                    _logger.LogWarning("Failed to access Cimian snapshot from data object, falling back to standard processing");
                    ProcessCimianDataFallback(data);
                    return false;
                }

                _logger.LogInformation("Successfully loaded Cimian snapshot, processing clean Cimian data format");

                // Ensure data.Cimian exists
                if (data.Cimian == null)
                {
                    data.Cimian = new CimianInfo();
                }

                // Extract managed packages from Cimian snapshot
                if (cimianSnapshot.ContainsKey("managedPackages") && cimianSnapshot["managedPackages"] is JsonElement packagesElement)
                {
                    var packages = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(packagesElement.GetRawText(), JsonOptions);
                    
                    data.Cimian.Items.Clear();
                    
                    foreach (var package in packages ?? new())
                    {
                        var originalStatus = package.GetValueOrDefault("status", "Unknown").ToString() ?? "Unknown";
                        var latestVersion = package.GetValueOrDefault("latestVersion", "Unknown").ToString() ?? "Unknown";
                        var installedVersion = package.GetValueOrDefault("version", "Unknown").ToString() ?? "Unknown";
                        
                        var item = new CimianItem
                        {
                            ItemName = package.GetValueOrDefault("name", "Unknown").ToString() ?? "Unknown",
                            InstalledVersion = installedVersion, 
                            LatestVersion = latestVersion,
                            CurrentStatus = originalStatus,
                            LastUpdate = package.ContainsKey("lastUpdate") && DateTime.TryParse(package["lastUpdate"].ToString(), out var lastUpdate) ? lastUpdate : DateTime.UtcNow,
                            InstallCount = 0,
                            UpdateCount = 0,
                            FailureCount = 0,
                            LastSeenInSession = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffK"),
                            Type = "cimian",
                            PendingReason = package.GetValueOrDefault("pendingReason", "").ToString() ?? ""
                        };
                        
                        // Derive PendingReason if status is Pending and reason not provided
                        if ((originalStatus.Equals("Pending", StringComparison.OrdinalIgnoreCase) || 
                             (latestVersion != installedVersion && installedVersion != "Unknown")) && 
                            string.IsNullOrEmpty(item.PendingReason))
                        {
                            item.PendingReason = DerivePendingReason(item, originalStatus);
                        }
                        
                        data.Cimian.Items.Add(item);
                    }
                    
                    _logger.LogInformation("Loaded {PackageCount} packages from Cimian snapshot", data.Cimian.Items.Count);
                }

                // Extract configuration from Cimian snapshot
                if (cimianSnapshot.ContainsKey("config") && cimianSnapshot["config"] is JsonElement configElement)
                {
                    data.Cimian.Config = JsonSerializer.Deserialize<Dictionary<string, object>>(configElement.GetRawText(), JsonOptions) ?? new();
                }

                // Extract last run info from Cimian snapshot  
                if (cimianSnapshot.ContainsKey("lastRun") && cimianSnapshot["lastRun"] is JsonElement lastRunElement)
                {
                    var lastRun = JsonSerializer.Deserialize<Dictionary<string, object>>(lastRunElement.GetRawText(), JsonOptions);
                    if (lastRun != null)
                    {
                        // Add to CacheStatus for API consumption
                        data.CacheStatus["cimian_last_run"] = lastRun;
                        data.CacheStatus["cimian_packages_handled"] = lastRun.GetValueOrDefault("packagesHandled", new List<object>());
                        data.CacheStatus["cimian_duration_seconds"] = lastRun.GetValueOrDefault("durationSeconds", 0);
                        data.CacheStatus["cimian_install_loop_detected"] = lastRun.GetValueOrDefault("installLoopDetected", false);
                    }
                }

                // Extract summary stats from Cimian snapshot
                if (cimianSnapshot.ContainsKey("summary") && cimianSnapshot["summary"] is JsonElement summaryElement)
                {
                    var summary = JsonSerializer.Deserialize<Dictionary<string, object>>(summaryElement.GetRawText(), JsonOptions);
                    if (summary != null)
                    {
                        data.CacheStatus["cimian_total_packages"] = summary.GetValueOrDefault("totalPackagesManaged", 0);
                        data.CacheStatus["cimian_packages_with_updates"] = summary.GetValueOrDefault("packagesWithUpdates", 0);
                        data.CacheStatus["cimian_packages_with_warnings"] = summary.GetValueOrDefault("packagesWithWarnings", 0);
                        data.CacheStatus["cimian_packages_with_errors"] = summary.GetValueOrDefault("packagesWithErrors", 0);
                        data.CacheStatus["cimian_cache_size_mb"] = summary.GetValueOrDefault("cacheSizeMb", 0.0);
                    }
                }

                _logger.LogInformation("Cimian data integration completed successfully");
                return true;

            } catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Cimian snapshot, falling back to standard processing");
                ProcessCimianDataFallback(data);
                return false;
            }
        }

        private void ProcessCimianDataFallback(InstallsData data)
        {
            try
            {
                _logger.LogDebug("Processing Cimian data transformation...");
                
                const string CIMIAN_REPORTS_PATH = @"C:\ProgramData\ManagedInstalls\reports";
                
                // Check if Cimian reports exist
                if (!Directory.Exists(CIMIAN_REPORTS_PATH))
                {
                    _logger.LogDebug("Cimian reports directory not found: {Path}", CIMIAN_REPORTS_PATH);
                    return;
                }

                var itemsPath = Path.Combine(CIMIAN_REPORTS_PATH, "items.json");
                var sessionsPath = Path.Combine(CIMIAN_REPORTS_PATH, "sessions.json");
                var eventsPath = Path.Combine(CIMIAN_REPORTS_PATH, "events.json");

                if (!File.Exists(itemsPath) || !File.Exists(sessionsPath))
                {
                    _logger.LogDebug("Required Cimian report files not found");
                    return;
                }

                // Load and process the Cimian reports using source generator context
                var items = JsonSerializer.Deserialize(File.ReadAllText(itemsPath), ReportMateJsonContext.Default.ListDictionaryStringObject);
                var sessions = JsonSerializer.Deserialize(File.ReadAllText(sessionsPath), ReportMateJsonContext.Default.ListDictionaryStringObject);
                
                if (items == null || sessions == null)
                {
                    _logger.LogWarning("Failed to parse Cimian report data");
                    return;
                }

                // Get latest session for config and timing
                var latestSession = sessions.OrderByDescending(s => 
                    s.ContainsKey("start_time") ? s["start_time"].ToString() : "").FirstOrDefault();

                if (latestSession == null)
                {
                    _logger.LogWarning("No sessions found in Cimian reports");
                    return;
                }

                // Build Cimian structure - ensure data.Cimian exists
                if (data.Cimian == null)
                {
                    data.Cimian = new CimianInfo();
                }

                // Update Cimian configuration from latest session
                if (latestSession.ContainsKey("config") && latestSession["config"] is JsonElement configElement)
                {
                    data.Cimian.Config = JsonSerializer.Deserialize<Dictionary<string, object>>(configElement.GetRawText()) ?? new();
                }

                // Process managed packages with clean status mapping
                data.Cimian.Items.Clear();
                var errorsCount = 0;
                var warningsCount = 0;
                var updatesCount = 0;

                foreach (var itemDict in items)
                {
                    var originalStatus = GetDictValue(itemDict, "current_status");
                    
                    var item = new CimianItem
                    {
                        Id = GetDictValue(itemDict, "id"),
                        ItemName = GetDictValue(itemDict, "item_name"),
                        DisplayName = GetDictValue(itemDict, "display_name"),
                        CurrentStatus = originalStatus,  // Preserve original Cimian status
                        LatestVersion = GetDictValue(itemDict, "latest_version"),
                        InstalledVersion = GetDictValue(itemDict, "installed_version"),
                        LastSeenInSession = GetDictValue(itemDict, "last_seen_in_session"),
                        LastError = GetDictValue(itemDict, "last_error") ?? string.Empty, // Error messages
                        LastWarning = GetDictValue(itemDict, "last_warning") ?? string.Empty, // Warning messages
                        PendingReason = GetDictValue(itemDict, "pending_reason") ?? string.Empty // Pending reason from Cimian
                    };

                    // Clean status mapping for Cimian - PRIORITIZE FAILURE STATES
                    var mappedStatus = "Unknown";
                    
                    // Check failure states FIRST before version matching
                    // This creates a SIMPLIFIED status for filtering while preserving original in CurrentStatus
                    if (originalStatus?.Equals("Error", StringComparison.OrdinalIgnoreCase) == true ||
                        originalStatus?.Equals("Install Loop", StringComparison.OrdinalIgnoreCase) == true ||
                        originalStatus?.Equals("Failed", StringComparison.OrdinalIgnoreCase) == true ||
                        HasFailedAttempts(itemDict))
                    {
                        mappedStatus = "Failed";  // Map Install Loop and failures to Failed
                        errorsCount++;
                    }
                    else if (originalStatus?.Equals("Pending", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        mappedStatus = "Pending";
                        updatesCount++;
                    }
                    else if (!string.IsNullOrEmpty(item.InstalledVersion) && !string.IsNullOrEmpty(item.LatestVersion))
                    {
                        if (item.InstalledVersion == item.LatestVersion)
                        {
                            mappedStatus = "Installed";
                        }
                        else
                        {
                            mappedStatus = "Pending";  // Update available → Pending
                            updatesCount++;
                        }
                    }
                    else if (!string.IsNullOrEmpty(item.InstalledVersion))
                    {
                        mappedStatus = "Installed";
                    }
                    else
                    {
                        mappedStatus = "Pending";
                    }

                    // Log the status determination for debugging
                    _logger.LogInformation("ITEM STATUS MAPPING - Item [{id}]: original_status='{originalStatus}', failure_count={failureCount}, mapped_status='{mappedStatus}'", 
                        GetDictValue(itemDict, "id"), 
                        item.CurrentStatus ?? "null", 
                        GetDictValue(itemDict, "failure_count") ?? "0",
                        mappedStatus);

                    // Check for warnings
                    if (HasWarningAttempts(itemDict) && mappedStatus != "Failed")
                    {
                        mappedStatus = "Warning";
                        warningsCount++;
                    }

                    // CRITICAL FIX: Store mapped status separately, preserve original CurrentStatus
                    item.MappedStatus = mappedStatus;  // Simplified for filtering: Failed/Pending/Warning/Installed/Unknown
                    // item.CurrentStatus already contains original: Error/Install Loop/Not Available/Warning/Pending/Installed
                    
                    // Derive PendingReason if not provided by Cimian and status is Pending
                    if (mappedStatus == "Pending" && string.IsNullOrEmpty(item.PendingReason))
                    {
                        item.PendingReason = DerivePendingReason(item, originalStatus);
                    }
                    
                    data.Cimian.Items.Add(item);
                }

                // Update summary data
                data.Cimian.Status = errorsCount > 0 ? "Error" : warningsCount > 0 ? "Warning" : "Active";

                // Store Cimian summary in CacheStatus for easy access
                data.CacheStatus["cimian_total_packages"] = data.Cimian.Items.Count;
                data.CacheStatus["cimian_updates_available"] = updatesCount;
                data.CacheStatus["cimian_errors"] = errorsCount;
                data.CacheStatus["cimian_warnings"] = warningsCount;
                data.CacheStatus["cimian_last_run"] = GetDictValue(latestSession, "end_time") ?? GetDictValue(latestSession, "start_time");

                _logger.LogInformation("Processed Cimian Cimian data: {Packages} packages, {Updates} updates, {Errors} errors, {Warnings} warnings", 
                    data.Cimian.Items.Count, updatesCount, errorsCount, warningsCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing Cimian Cimian data");
            }
        }

        private bool HasFailedAttempts(Dictionary<string, object> itemDict)
        {
            if (itemDict.ContainsKey("recent_attempts") && itemDict["recent_attempts"] is JsonElement attemptsElement)
            {
                try
                {
                    foreach (var attempt in attemptsElement.EnumerateArray())
                    {
                        if (attempt.TryGetProperty("status", out var statusProp) && 
                            statusProp.GetString() == "Error")
                        {
                            return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }

        private bool HasWarningAttempts(Dictionary<string, object> itemDict)
        {
            // Don't use historical warnings to override correct status from version comparison
            // Status should be: Installed (versions match), Pending (update available), or Error (current failures)
            // Historical warnings should not change a correctly "Installed" package to "Warning"
            return false;
        }


        /// <summary>
        /// Derives a human-readable pending reason based on the item's status and version information.
        /// This provides context for why a package is pending installation/update.
        /// </summary>
        private string DerivePendingReason(CimianItem item, string? originalStatus)
        {
            // Check if there's a version mismatch indicating an update
            if (!string.IsNullOrEmpty(item.InstalledVersion) && !string.IsNullOrEmpty(item.LatestVersion))
            {
                if (item.InstalledVersion != item.LatestVersion)
                {
                    return $"Update available: {item.InstalledVersion} → {item.LatestVersion}";
                }
            }
            
            // Check original Cimian status for context
            if (!string.IsNullOrEmpty(originalStatus))
            {
                switch (originalStatus.ToLowerInvariant())
                {
                    case "not available":
                    case "not_available":
                    case "notavailable":
                        return "Package metadata not available on server";
                    case "skipped":
                        return "Installation was skipped";
                    case "pending":
                        if (string.IsNullOrEmpty(item.InstalledVersion))
                            return "Not yet installed";
                        return "Pending next run";
                    case "downloading":
                        return "Download in progress";
                    case "queued":
                        return "Queued for installation";
                    case "scheduled":
                        return "Scheduled for maintenance window";
                    case "user deferred":
                    case "userdeferred":
                    case "user_deferred":
                        return "User deferred installation";
                }
            }
            
            // If no installed version, it's a new install
            if (string.IsNullOrEmpty(item.InstalledVersion))
            {
                return "Not yet installed";
            }
            
            // Default reason
            return "Awaiting next scheduled run";
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
                    _logger.LogDebug("Session events file not found: {EventsFile}", eventsFile);
                    return events;
                }

                var lines = File.ReadAllLines(eventsFile);
                _logger.LogDebug("Reading {LineCount} lines from events.jsonl in session {SessionId}", lines.Length, sessionId);
                
                // Read ALL events from the session (not just last 20)
                foreach (var line in lines)
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
                        
                        // Legacy fields - try summary first, then top-level for backwards compatibility
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
                if (string.IsNullOrWhiteSpace(json) || json.Trim() == "null")
                {
                    _logger.LogDebug("Cimian items report is null or empty: {FilePath}", filePath);
                    return items;
                }

                using var document = JsonDocument.Parse(json);
                
                // Check if the root element is null or not an array
                if (document.RootElement.ValueKind == JsonValueKind.Null)
                {
                    _logger.LogDebug("Cimian items report contains null value: {FilePath}", filePath);
                    return items;
                }

                if (document.RootElement.ValueKind != JsonValueKind.Array)
                {
                    _logger.LogDebug("Cimian items report is not an array (found {ValueKind}): {FilePath}", document.RootElement.ValueKind, filePath);
                    return items;
                }
                
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
                
                // Handle null or empty JSON
                if (document.RootElement.ValueKind == JsonValueKind.Null)
                {
                    _logger.LogDebug("Cimian events report contains null - no events to process");
                    return events;
                }
                
                // Handle non-array JSON
                if (document.RootElement.ValueKind != JsonValueKind.Array)
                {
                    _logger.LogDebug("Cimian events report is not an array - no events to process");
                    return events;
                }
                
                foreach (var eventElement in document.RootElement.EnumerateArray())
                {
                    var cimianEvent = new CimianEvent
                    {
                        EventId = eventElement.GetProperty("event_id").GetString() ?? "",
                        SessionId = eventElement.GetProperty("session_id").GetString() ?? "",
                        Level = eventElement.GetProperty("level").GetString() ?? "",
                        EventType = eventElement.GetProperty("event_type").GetString() ?? "",
                        Action = eventElement.GetProperty("action").GetString() ?? "",
                        Status = MapCimianEventStatusToReportMate(eventElement.GetProperty("status").GetString() ?? ""), // Apply event status mapping
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
                
                // Cimian's items.json is already the authoritative, filtered view of managed software.
                
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
                    
                    // Primary fields - use actual Cimian field names (Cimian uses "installed_version" for installed, "latest_version" for latest)
                    var latestVersion = GetDictValue(item, "latest_version");
                    var installedVersion = GetDictValue(item, "installed_version"); // FIXED: Cimian uses "installed_version" not "version"
                    
                    // ENHANCED: Prioritize direct fields over recent_attempts for more reliable version data
                    if (string.IsNullOrEmpty(extractedVersion))
                    {
                        // Use installed_version as primary, fall back to latest_version
                        if (!string.IsNullOrEmpty(installedVersion))
                        {
                            extractedVersion = installedVersion;
                            _logger.LogDebug("Using installed_version: {Version} for item {ItemId}", installedVersion, GetDictValue(item, "id"));
                        }
                        else if (!string.IsNullOrEmpty(latestVersion))
                        {
                            extractedVersion = latestVersion;
                            _logger.LogDebug("Using latest_version: {Version} for item {ItemId}", latestVersion, GetDictValue(item, "id"));
                        }
                        else
                        {
                            extractedVersion = "Unknown";
                            _logger.LogWarning("No version found for item {ItemId}", GetDictValue(item, "id"));
                        }
                    }
                    
                    // CRITICAL FIX: Determine status based on failure states FIRST, then version comparison
                    // PRESERVE ORIGINAL: Store original Cimian status before any transformations
                    var originalCimianStatus = GetDictValue(item, "current_status");
                    string determinedStatus;
                    
                    // PRIORITY 1: Check for failure states BEFORE version matching
                    if (originalCimianStatus?.Equals("Error", StringComparison.OrdinalIgnoreCase) == true ||
                        originalCimianStatus?.Equals("Install Loop", StringComparison.OrdinalIgnoreCase) == true ||
                        originalCimianStatus?.Equals("Failed", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        determinedStatus = "Failed";
                        _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: current_status='{CurrentStatus}' -> 'Failed' (prioritizing failure state over version comparison)", 
                            GetDictValue(item, "id"), originalCimianStatus);
                    }
                    else if (!string.IsNullOrEmpty(latestVersion) && !string.IsNullOrEmpty(installedVersion))
                    {
                        try
                        {
                            // Parse versions for semantic comparison
                            var installedVer = new Version(installedVersion);
                            var latestVer = new Version(latestVersion);
                            
                            if (installedVer >= latestVer)
                            {
                                determinedStatus = "Installed"; // Installed version is current or newer
                                _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: installed_version='{InstalledVersion}' >= latest_version='{LatestVersion}' -> 'Installed'", 
                                    GetDictValue(item, "id"), installedVersion, latestVersion);
                            }
                            else
                            {
                                determinedStatus = "Pending"; // Update available
                                _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: installed_version='{InstalledVersion}' < latest_version='{LatestVersion}' -> 'Pending'", 
                                    GetDictValue(item, "id"), installedVersion, latestVersion);
                            }
                        }
                        catch (Exception ex)
                        {
                            // Fall back to string comparison if version parsing fails
                            if (latestVersion.Equals(installedVersion, StringComparison.OrdinalIgnoreCase))
                            {
                                determinedStatus = "Installed";
                                _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: String comparison - versions match -> 'Installed'", 
                                    GetDictValue(item, "id"));
                            }
                            else
                            {
                                determinedStatus = "Pending";
                                _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: String comparison - versions differ -> 'Pending' (parse error: {Error})", 
                                    GetDictValue(item, "id"), ex.Message);
                            }
                        }
                    }
                    else
                    {
                        // Fall back to Cimian status if version comparison isn't possible
                        determinedStatus = string.IsNullOrEmpty(cimianStatus) ? 
                            (originalCimianStatus ?? "Unknown") : cimianStatus;
                        _logger.LogInformation("STATUS DETERMINATION - Item {ItemId}: No version comparison possible, using fallback status: '{Status}'", 
                            GetDictValue(item, "id"), determinedStatus);
                    }
                    
                    // Use the determined status for mapping purposes (simplified status)
                    // but keep originalCimianStatus for detailed tracking
                    var mappedStatus = determinedStatus;
                    
                    // Check for install loop detection flag
                    bool hasInstallLoop = false;
                    if (item.TryGetValue("install_loop_detected", out var installLoopObj) && 
                        installLoopObj != null &&
                        bool.TryParse(installLoopObj.ToString(), out var loopDetected))
                    {
                        hasInstallLoop = loopDetected;
                    }
                    
                    // FIXED: Don't force status to Error just because version is unknown
                    // Trust the actual current_status from Cimian items.json
                    if (extractedVersion == "Unknown" || string.IsNullOrEmpty(extractedVersion))
                    {
                        _logger.LogWarning("Version unknown for item {ItemId}, but preserving actual status: '{Status}'", 
                            GetDictValue(item, "id"), cimianStatus);
                        // Keep the determined status from version comparison or current_status fallback
                    }
                    
                    // Map Cimian's detailed status to ReportMate's simplified dashboard status
                    var reportMateStatus = MapCimianStatusToReportMate(mappedStatus, hasInstallLoop);
                    
                    // Debug: Log key field values
                    var itemId = GetDictValue(item, "id");
                    var itemName = GetDictValue(item, "item_name") ?? GetDictValue(item, "name") ?? itemId;
                    var displayName = GetDictValue(item, "display_name") ?? itemName;
                    
                    _logger.LogInformation("Item [{ItemId}]: name='{ItemName}', display_name='{DisplayName}', version='{Version}', original_status='{OriginalStatus}', mapped_status='{MappedStatus}' -> reportmate_status='{ReportMateStatus}'", 
                        itemId, itemName, displayName, extractedVersion, originalCimianStatus, mappedStatus, reportMateStatus);

                    var managedInstall = new ManagedInstall
                    {
                        Id = itemId,
                        Name = itemName,
                        DisplayName = displayName,
                        ItemType = GetDictValue(item, "item_type"),
                        Status = reportMateStatus, // Enhanced: Use mapped ReportMate status
                        Version = extractedVersion, // Enhanced: Use version from recent_attempts
                        InstalledVersion = GetDictValue(item, "installed_version"), // FIXED: Use correct Cimian field name
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
                        CurrentStatus = originalCimianStatus ?? "Unknown", // Store ORIGINAL Cimian status (Error, Install Loop, etc.)
                        MappedStatus = mappedStatus, // Store simplified status (Failed, Pending, Installed, etc.)
                        LatestVersion = extractedVersion, // Enhanced: Use version from recent_attempts
                        InstalledVersion = GetDictValue(item, "installed_version"), // FIXED: Use correct Cimian field name
                        LastSeenInSession = GetDictValue(item, "last_seen_in_session"),
                        LastAttemptStatus = GetDictValue(item, "last_attempt_status"),
                        InstallMethod = GetDictValue(item, "install_method"),
                        Type = GetDictValue(item, "type"),
                        LastError = GetDictValue(item, "last_error") ?? string.Empty, // Error messages for failed installs
                        LastWarning = GetDictValue(item, "last_warning") ?? string.Empty, // Warning messages for install loops
                        PendingReason = GetDictValue(item, "pending_reason") ?? string.Empty, // Pending reason from Cimian
                        Category = GetDictValue(item, "category") ?? string.Empty, // Category from pkgsinfo
                        Developer = GetDictValue(item, "developer") ?? string.Empty // Developer from pkgsinfo
                    };
                    
                    // Derive PendingReason if not provided by Cimian and status is Pending
                    if (mappedStatus == "Pending" && string.IsNullOrEmpty(cimianItem.PendingReason))
                    {
                        cimianItem.PendingReason = DerivePendingReason(cimianItem, originalCimianStatus);
                    }

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

                    // Enhanced fields: Parse additional counts
                    if (item.TryGetValue("warning_count", out var warningCountObj) && 
                        int.TryParse(warningCountObj.ToString(), out var warningCount))
                    {
                        cimianItem.WarningCount = warningCount;
                    }
                    
                    if (item.TryGetValue("removal_count", out var removalCountObj) && 
                        int.TryParse(removalCountObj.ToString(), out var removalCount))
                    {
                        // Store removal count if we add it to model later
                        _logger.LogDebug("Item [{ItemId}]: removal_count='{RemovalCount}'", itemId, removalCount);
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
                        // Removed deprecated RecentInstalls usage
                    }
                    else
                    {
                        // Removed deprecated RecentInstalls usage
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
        /// Extract package name from Cimian error/warning messages
        /// </summary>
        private string? ExtractPackageNameFromMessage(string? message)
        {
            if (string.IsNullOrEmpty(message))
                return null;

            // Common patterns in Cimian error messages:
            // "Package 'PackageName' install failed"
            // "Failed to install PackageName"
            // "Error installing 'PackageName'"
            // "PackageName.nupkg could not be installed"
            // "Download failed for PackageName"
            
            // Pattern 1: Package 'Name' or Package "Name"
            var pattern1 = @"Package\s+['""]([^'""]+)['""]";
            var match1 = System.Text.RegularExpressions.Regex.Match(message, pattern1, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match1.Success)
                return match1.Groups[1].Value;

            // Pattern 2: installing 'Name' or installing "Name"
            var pattern2 = @"installing\s+['""]([^'""]+)['""]";
            var match2 = System.Text.RegularExpressions.Regex.Match(message, pattern2, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match2.Success)
                return match2.Groups[1].Value;

            // Pattern 3: Name.nupkg
            var pattern3 = @"([a-zA-Z0-9\.\-_]+)\.nupkg";
            var match3 = System.Text.RegularExpressions.Regex.Match(message, pattern3, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match3.Success)
                return match3.Groups[1].Value;

            // Pattern 4: Failed to install PackageName (look for word after "install")
            var pattern4 = @"(?:failed\s+to\s+install|install\s+failed)\s+([a-zA-Z0-9\.\-_]+)";
            var match4 = System.Text.RegularExpressions.Regex.Match(message, pattern4, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match4.Success)
                return match4.Groups[1].Value;

            // Pattern 5: Download failed for PackageName
            var pattern5 = @"(?:download\s+failed\s+for|failed\s+to\s+download)\s+([a-zA-Z0-9\.\-_]+)";
            var match5 = System.Text.RegularExpressions.Regex.Match(message, pattern5, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match5.Success)
                return match5.Groups[1].Value;

            return null;
        }

        /// Priority: Error > Warning > Success (only generate one event per device)
        /// FIXED: Now counts from items.json current_status to match what Items table displays
        /// This ensures event message counts match the items table filter counts
        /// </summary>
        public override Task<List<ReportMateEvent>> GenerateEventsAsync(InstallsData data)
        {
            var events = new List<ReportMateEvent>();
            
            try
            {
                _logger.LogInformation("Starting consolidated event generation for device {DeviceId}", data.DeviceId);
                
                // Get session events (for logging only)
                var sessionEvents = data.Cimian?.Events ?? new List<CimianEvent>();
                
                // Get all items from items.json - this is the SOURCE OF TRUTH for counts
                // The Items table displays items based on their current_status from items.json
                // Event message counts MUST match what the Items table shows
                var allItems = data.Cimian?.Items ?? new List<CimianItem>();
                
                // Count FAILED items from items.json current_status
                // These are the items that will show as "Error" in the Items table
                var failedItemStatuses = new[] { "Error", "Failed", "Install Loop" };
                var failedItems = allItems
                    .Where(i => 
                        failedItemStatuses.Any(s =>
                            i.CurrentStatus.Equals(s, StringComparison.OrdinalIgnoreCase) ||
                            (i.MappedStatus?.Equals("Failed", StringComparison.OrdinalIgnoreCase) == true)) ||
                        // CRITICAL: Also check if LastError is populated - this indicates a real failure
                        !string.IsNullOrEmpty(i.LastError))
                    .Select(i => i.ItemName)
                    .Where(n => !string.IsNullOrEmpty(n))
                    .Distinct()
                    .ToList();
                
                // Count WARNING items from items.json current_status
                // These are the items that will show as "Warning" in the Items table
                var warningItemStatuses = new[] { "Warning", "Not Available" };
                var warningItems = allItems
                    .Where(i => 
                        warningItemStatuses.Any(s =>
                            i.CurrentStatus.Equals(s, StringComparison.OrdinalIgnoreCase) ||
                            (i.MappedStatus?.Equals("Warning", StringComparison.OrdinalIgnoreCase) == true)) ||
                        // Also check if LastWarning is populated (but not if LastError is set - errors take precedence)
                        (!string.IsNullOrEmpty(i.LastWarning) && string.IsNullOrEmpty(i.LastError)))
                    .Where(i => !failedItems.Contains(i.ItemName, StringComparer.OrdinalIgnoreCase)) // Don't double-count
                    .Select(i => i.ItemName)
                    .Where(n => !string.IsNullOrEmpty(n))
                    .Distinct()
                    .ToList();
                
                // Build set of known item names
                var knownItemNames = allItems
                    .Select(i => i.ItemName)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                
                // Session-level warnings are no longer tracked separately
                // Only item-level errors and warnings matter for module status
                var sessionLevelWarnings = new List<CimianEvent>(); // Empty - not used
                
                // Get installed item names for context
                var installedItemNames = allItems
                    .Where(i => i.CurrentStatus.Equals("Installed", StringComparison.OrdinalIgnoreCase) ||
                               i.MappedStatus?.Equals("Installed", StringComparison.OrdinalIgnoreCase) == true)
                    .Select(i => i.ItemName)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                
                // Get ACTUAL session activity counts from the latest session
                // This is what happened in THIS run, not total items managed
                var latestSessionForCounts = data.Cimian?.Sessions?.OrderByDescending(s => s.StartTime).FirstOrDefault();
                var sessionInstalls = latestSessionForCounts?.Installs ?? 0;
                var sessionUpdates = latestSessionForCounts?.Updates ?? 0;
                var sessionSuccesses = latestSessionForCounts?.Successes ?? 0;
                var sessionActivityCount = sessionInstalls + sessionUpdates;
                
                // Also track total managed items for context (but not for messaging)
                var totalManagedItems = allItems.Count;
                var totalInstalledItems = installedItemNames.Count;
                
                _logger.LogInformation("Event count analysis from items.json - Failed Items: {ErrorCount} ({FailedItems}), Warning Items: {WarningCount} ({WarnItems}), Installed: {InstalledCount}, Session Warnings: {SessionWarnCount}, Session Activity: {SessionActivity} (installs: {Installs}, updates: {Updates})", 
                    failedItems.Count, string.Join(", ", failedItems.Take(5)),
                    warningItems.Count, string.Join(", ", warningItems.Take(5)),
                    totalInstalledItems,
                    sessionLevelWarnings.Count,
                    sessionActivityCount, sessionInstalls, sessionUpdates);
                
                // Build consolidated message and determine event type
                string eventType;
                string message;
                var details = new Dictionary<string, object>();
                
                // Add session info to details if available
                var latestSession = data.Cimian?.Sessions?.OrderByDescending(s => s.StartTime).FirstOrDefault();
                if (latestSession != null)
                {
                    details["session_id"] = latestSession.SessionId ?? "unknown";
                    details["run_type"] = latestSession.RunType ?? "unknown";
                    details["duration_seconds"] = latestSession.DurationSeconds;
                }
                
                // REMOVED: operational_warnings no longer tracked - only item errors/warnings matter
                
                // PRIORITY 1: ERROR - If there are any failed items in this session
                if (failedItems.Any())
                {
                    eventType = "error";
                    var messageParts = new List<string>();
                    
                    // Always mention failed installs first
                    messageParts.Add($"{failedItems.Count} failed install{(failedItems.Count == 1 ? "" : "s")}");
                    
                    // Add item warnings if any
                    if (warningItems.Any())
                        messageParts.Add($"{warningItems.Count} item warning{(warningItems.Count == 1 ? "" : "s")}");
                    
                    // Session-level warnings no longer affect status
                    
                    // Add session activity count if any actual installs/updates occurred
                    if (sessionActivityCount > 0)
                        messageParts.Add($"{sessionActivityCount} successful{(sessionActivityCount == 1 ? "" : "s")}");
                    
                    message = string.Join(", ", messageParts);
                    
                    details["error_count"] = failedItems.Count;
                    details["warning_count"] = warningItems.Count;
                    details["session_installs"] = sessionInstalls;
                    details["session_updates"] = sessionUpdates;
                    details["session_successes"] = sessionSuccesses;
                    details["total_managed_items"] = totalManagedItems;
                    details["module_status"] = "error";
                    details["failed_items"] = failedItems.Take(10).ToList();
                    
                    _logger.LogInformation("Generated single ERROR event: {Message}", message);
                }
                // PRIORITY 2: WARNING - If there are item warnings but no errors
                else if (warningItems.Any())
                {
                    eventType = "warning";
                    var messageParts = new List<string>();
                    
                    // Always mention item warnings first
                    messageParts.Add($"{warningItems.Count} item warning{(warningItems.Count == 1 ? "" : "s")}");
                    
                    // Session-level warnings no longer affect status
                    
                    // Add session activity count if any actual installs/updates occurred
                    if (sessionActivityCount > 0)
                        messageParts.Add($"{sessionActivityCount} successful{(sessionActivityCount == 1 ? "" : "s")}");
                    
                    message = string.Join(", ", messageParts);
                    
                    details["warning_count"] = warningItems.Count;
                    details["session_installs"] = sessionInstalls;
                    details["session_updates"] = sessionUpdates;
                    details["session_successes"] = sessionSuccesses;
                    details["total_managed_items"] = totalManagedItems;
                    details["module_status"] = "warning";
                    details["warning_items"] = warningItems.Take(10).ToList();
                    
                    _logger.LogInformation("Generated single WARNING event: {Message}", message);
                }
                // PRIORITY 3: SUCCESS - if there was actual session activity (installs/updates)
                else if (sessionActivityCount > 0)
                {
                    // Report success
                    eventType = "success";
                    var messageParts = new List<string>();
                    
                    // Report actual session activity
                    if (sessionInstalls > 0 && sessionUpdates > 0)
                        messageParts.Add($"{sessionInstalls} install{(sessionInstalls == 1 ? "" : "s")}, {sessionUpdates} update{(sessionUpdates == 1 ? "" : "s")}");
                    else if (sessionInstalls > 0)
                        messageParts.Add($"{sessionInstalls} install{(sessionInstalls == 1 ? "" : "s")}");
                    else if (sessionUpdates > 0)
                        messageParts.Add($"{sessionUpdates} update{(sessionUpdates == 1 ? "" : "s")}");
                    
                    
                    message = string.Join(", ", messageParts);
                    
                    details["session_installs"] = sessionInstalls;
                    details["session_updates"] = sessionUpdates;
                    details["session_successes"] = sessionSuccesses;
                    details["total_managed_items"] = totalManagedItems;
                    details["module_status"] = "success";
                    
                    _logger.LogInformation("Generated single SUCCESS event: {Message}", message);
                }
                // NO SESSION ACTIVITY - report as maintenance check
                // REMOVED: Session-level warnings no longer trigger status changes
                // NO SESSION ACTIVITY AND NO WARNINGS: All items are managed, nothing to do
                else if (totalManagedItems > 0)
                {
                    // Don't generate events for "all managed" state - it's normal operation
                    // The items are all accounted for in the items.json, no action needed
                    _logger.LogInformation("All {TotalItems} managed items accounted for, no session activity - no event generated", totalManagedItems);
                    return Task.FromResult(events); // Return empty list
                }
                // NO ITEMS AND NO ACTIVITY
                else
                {
                    // Only generate an event if Cimian is not installed (warning case)
                    if (data.Cimian?.IsInstalled != true)
                    {
                        eventType = "warning";
                        message = "Installs system not available";
                        details["recommendation"] = "Install Cimian for managed software deployment";
                        details["module_status"] = "warning";
                        
                        _logger.LogInformation("Generated single WARNING event - Cimian not detected");
                    }
                    else
                    {
                        // Cimian is installed but no items configured - could be initial setup
                        _logger.LogInformation("No managed items configured - no event generated");
                        return Task.FromResult(events); // Return empty list
                    }
                }
                
                // Create the single consolidated event
                events.Add(CreateEvent(eventType, message, details, DateTime.UtcNow));
                
                _logger.LogInformation("Generated 1 consolidated event of type '{EventType}' for device {DeviceId}", 
                    eventType, data.DeviceId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating consolidated event from Cimian data");
                
                // Add error event for the generation failure itself
                events.Add(CreateEvent("error", "Installs monitoring error", 
                    new Dictionary<string, object> { 
                        ["error"] = ex.Message,
                        ["module_status"] = "error"
                    }));
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
                if (data.Cimian?.Sessions?.Any() == true)
                {
                    var sessions = data.Cimian?.Sessions ?? new List<CimianSession>();
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
                            .SelectMany(ba => ba.Value.Select(app => new Dictionary<string, object> { ["Package"] = ba.Key, ["App"] = app }))
                            .GroupBy(x => (string)x["App"])
                            .OrderByDescending(g => g.Count())
                            .Take(10)
                            .ToDictionary(g => g.Key, g => new BlockingApplicationInfo
                            {
                                Count = g.Count(),
                                AffectedPackages = g.Select(x => (string)x["Package"]).Distinct().ToList()
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
                if (data.Cimian?.Events?.Any() == true)
                {
                    var events = data.Cimian?.Events ?? new List<CimianEvent>();
                    
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

        /// <summary>
        /// Determines if a warning message represents an expected/non-actionable condition
        /// for PACKAGE-LEVEL warnings only. 
        /// </summary>
        private static bool IsExpectedWarning(string message)
        {
            if (string.IsNullOrEmpty(message)) return false;
            
            // Filter out warnings that are expected for package operations
            // These are normal, expected conditions - not problems
            var expectedWarnings = new[]
            {
                // Architecture mismatch warnings - expected on ARM64 systems with x64 packages
                "Architecture mismatch, skipping",
                "architecture mismatch",
                // Version downgrade prevention - expected behavior, not a problem
                "Refusing downgrade; local version newer",
                "refusing downgrade"
            };
            
            return expectedWarnings.Any(warning => 
                message.Contains(warning, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Dynamically parses Cimian manifest files to get currently managed packages
        /// Follows the manifest hierarchy to collect all managed_installs entries
        /// </summary>
        private HashSet<string> GetActivelyManagedPackagesFromManifests()
        {
            var managedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var processedManifests = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            try
            {
                const string MANIFESTS_PATH = @"C:\ProgramData\ManagedInstalls\manifests";
                
                if (!Directory.Exists(MANIFESTS_PATH))
                {
                    _logger.LogWarning("Manifests directory not found: {Path}", MANIFESTS_PATH);
                    return managedPackages;
                }

                // Start with the user's specific manifest and follow the inclusion chain
                var userManifest = GetUserSpecificManifest(MANIFESTS_PATH);
                if (!string.IsNullOrEmpty(userManifest))
                {
                    _logger.LogInformation("Starting manifest parsing from user manifest: {UserManifest}", userManifest);
                    ParseManifestRecursively(Path.Combine(MANIFESTS_PATH, userManifest), MANIFESTS_PATH, managedPackages, processedManifests);
                }
                else
                {
                    _logger.LogWarning("Could not determine user-specific manifest, falling back to root manifests");
                    // Fallback: Parse common root manifests
                    var rootManifests = new[] { "Assigned.yaml", "CoreManifest.yaml" };
                    foreach (var manifest in rootManifests)
                    {
                        var manifestPath = Path.Combine(MANIFESTS_PATH, manifest);
                        if (File.Exists(manifestPath))
                        {
                            ParseManifestRecursively(manifestPath, MANIFESTS_PATH, managedPackages, processedManifests);
                        }
                    }
                }

                _logger.LogInformation("Parsed manifests to find {PackageCount} actively managed packages: {Packages}", 
                    managedPackages.Count, string.Join(", ", managedPackages.OrderBy(p => p)));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing Cimian manifests dynamically");
            }

            return managedPackages;
        }

        /// <summary>
        /// Gets the Cimian ClientIdentifier from the configuration file
        /// </summary>
        private string? GetCimianClientIdentifier()
        {
            try
            {
                var standardConfigPath = @"C:\ProgramData\ManagedInstalls\config.yaml";
                var cimianConfig = ReadCimianConfigurationFile(standardConfigPath);
                
                if (cimianConfig != null && cimianConfig.ContainsKey("ClientIdentifier"))
                {
                    return cimianConfig["ClientIdentifier"]?.ToString();
                }
                
                _logger.LogWarning("Could not find ClientIdentifier in Cimian configuration");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading Cimian ClientIdentifier");
                return null;
            }
        }

        /// <summary>
        /// Gets the most specific manifest file for the current user/machine
        /// </summary>
        private string GetUserSpecificManifest(string manifestsPath)
        {
            try
            {
                // First try to determine the manifest path from Cimian's ClientIdentifier
                var clientIdentifier = GetCimianClientIdentifier();
                if (!string.IsNullOrEmpty(clientIdentifier))
                {
                    _logger.LogDebug("Using Cimian ClientIdentifier for manifest discovery: {ClientIdentifier}", clientIdentifier);
                    
                    // Convert ClientIdentifier path to Windows path separators
                    var manifestPath = clientIdentifier.Replace('/', '\\') + ".yaml";
                    var fullManifestPath = Path.Combine(manifestsPath, manifestPath);
                    
                    if (File.Exists(fullManifestPath))
                    {
                        _logger.LogInformation("Found manifest using ClientIdentifier: {ManifestPath}", manifestPath);
                        return manifestPath;
                    }
                    else
                    {
                        _logger.LogWarning("Manifest not found at ClientIdentifier path: {FullPath}", fullManifestPath);
                    }
                }
                
                // Fallback: Dynamic discovery by recursively searching all manifests
                _logger.LogInformation("ClientIdentifier not available, performing dynamic manifest discovery");
                
                var currentUser = Environment.UserName;
                var computerName = Environment.MachineName;
                
                // Recursively search all manifest directories for user or machine-specific files
                var allManifestFiles = Directory.GetFiles(manifestsPath, "*.yaml", SearchOption.AllDirectories)
                    .Where(f => !Path.GetFileName(f).StartsWith(".")) // Skip hidden files
                    .OrderBy(f => f.Length) // Prefer more specific (longer) paths
                    .ToArray();
                
                // First priority: Look for user-specific manifests
                var userManifests = allManifestFiles
                    .Where(f => Path.GetFileNameWithoutExtension(f).Equals(currentUser, StringComparison.OrdinalIgnoreCase) ||
                               Path.GetFileNameWithoutExtension(f).Equals($"{char.ToUpper(currentUser[0])}{currentUser.Substring(1)}", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                
                if (userManifests.Any())
                {
                    var userManifest = userManifests.First();
                    var relativePath = Path.GetRelativePath(manifestsPath, userManifest).Replace('/', '\\');
                    _logger.LogInformation("Found user-specific manifest: {UserManifest}", relativePath);
                    return relativePath;
                }
                
                // Second priority: Look for machine-specific manifests
                var machineManifests = allManifestFiles
                    .Where(f => Path.GetFileNameWithoutExtension(f).Equals(computerName, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                
                if (machineManifests.Any())
                {
                    var machineManifest = machineManifests.First();
                    var relativePath = Path.GetRelativePath(manifestsPath, machineManifest).Replace('/', '\\');
                    _logger.LogInformation("Found machine-specific manifest: {MachineManifest}", relativePath);
                    return relativePath;
                }
                
                // Third priority: Look for any manifest file (use first available)
                if (allManifestFiles.Any())
                {
                    var anyManifest = allManifestFiles.First();
                    var relativePath = Path.GetRelativePath(manifestsPath, anyManifest).Replace('/', '\\');
                    _logger.LogInformation("Using fallback manifest: {FallbackManifest}", relativePath);
                    return relativePath;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error determining user-specific manifest");
            }

            return "";
        }

        /// <summary>
        /// Recursively parses a manifest file and its included manifests
        /// </summary>
        private void ParseManifestRecursively(string manifestPath, string manifestsBasePath, HashSet<string> managedPackages, HashSet<string> processedManifests)
        {
            try
            {
                // Prevent infinite loops
                var normalizedPath = Path.GetFullPath(manifestPath).ToLowerInvariant();
                if (processedManifests.Contains(normalizedPath))
                {
                    return;
                }
                processedManifests.Add(normalizedPath);

                if (!File.Exists(manifestPath))
                {
                    _logger.LogDebug("Manifest file not found: {ManifestPath}", manifestPath);
                    return;
                }

                _logger.LogDebug("Parsing manifest: {ManifestPath}", manifestPath);
                var yamlContent = File.ReadAllText(manifestPath);
                
                if (string.IsNullOrWhiteSpace(yamlContent))
                {
                    return;
                }

                // Parse YAML content - look for managed_installs and included_manifests sections
                var lines = yamlContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                bool inManagedInstalls = false;
                bool inIncludedManifests = false;
                
                _logger.LogDebug("Parsing {LineCount} lines from {ManifestPath}", lines.Length, Path.GetFileName(manifestPath));
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    
                    if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                        continue;

                    // Check for section headers
                    if (trimmedLine.StartsWith("managed_installs:", StringComparison.OrdinalIgnoreCase))
                    {
                        inManagedInstalls = true;
                        inIncludedManifests = false;
                        _logger.LogDebug("Entered managed_installs section in {ManifestPath}", Path.GetFileName(manifestPath));
                        continue;
                    }
                    else if (trimmedLine.StartsWith("included_manifests:", StringComparison.OrdinalIgnoreCase))
                    {
                        inManagedInstalls = false;
                        inIncludedManifests = true;
                        _logger.LogDebug("Entered included_manifests section in {ManifestPath}", Path.GetFileName(manifestPath));
                        continue;
                    }
                    else if (trimmedLine.EndsWith(":") && !trimmedLine.StartsWith("-"))
                    {
                        // New section started
                        inManagedInstalls = false;
                        inIncludedManifests = false;
                        continue;
                    }

                    // Parse list items (lines starting with -)
                    if (trimmedLine.StartsWith("- "))
                    {
                        var itemValue = trimmedLine.Substring(2).Trim();
                        
                        if (inManagedInstalls && !string.IsNullOrEmpty(itemValue))
                        {
                            managedPackages.Add(itemValue);
                            _logger.LogInformation("Found managed package: {Package} in {Manifest}", itemValue, Path.GetFileName(manifestPath));
                        }
                        else if (inIncludedManifests && !string.IsNullOrEmpty(itemValue))
                        {
                            // Recursively parse included manifest
                            string includedManifestPath;
                            if (itemValue.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                            {
                                // Already has .yaml extension
                                includedManifestPath = Path.Combine(manifestsBasePath, itemValue);
                            }
                            else
                            {
                                // Add .yaml extension
                                includedManifestPath = Path.Combine(manifestsBasePath, itemValue + ".yaml");
                            }
                            
                            _logger.LogInformation("Following included manifest: {IncludedManifest} -> {IncludedPath}", itemValue, includedManifestPath);
                            ParseManifestRecursively(includedManifestPath, manifestsBasePath, managedPackages, processedManifests);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing manifest file: {ManifestPath}", manifestPath);
            }
        }

        /// <summary>
        /// Execute managedsoftwareupdate.exe --version to get the full version string
        /// Falls back to version transformation if command execution fails
        /// </summary>
        private async Task<string?> ExecuteManagedsoftwareupdateVersionAsync(string executablePath)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = executablePath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = processInfo };
                process.Start();

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();

                // Give the process up to 5 seconds to complete
                var completed = await Task.Run(() => process.WaitForExit(5000));
                
                if (!completed)
                {
                    try
                    {
                        process.Kill(true);
                    }
                    catch
                    {
                        // Ignore kill errors
                    }
                    _logger.LogDebug("managedsoftwareupdate.exe --version command timed out");
                    return null;
                }

                if (process.ExitCode == 0)
                {
                    var version = output?.Trim();
                    if (!string.IsNullOrEmpty(version))
                    {
                        _logger.LogDebug("Successfully retrieved version from managedsoftwareupdate.exe: {Version}", version);
                        return version;
                    }
                }
                else
                {
                    _logger.LogDebug("managedsoftwareupdate.exe --version failed with exit code {ExitCode}: {Error}", process.ExitCode, error?.Trim());
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error executing managedsoftwareupdate.exe --version: {Error}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Check for Cimian scheduled tasks by looking in the task scheduler registry
        /// </summary>
        private async Task CheckCimianScheduledTasks(CimianInfo cimianInfo)
        {
            try
            {
                _logger.LogDebug("Checking for Cimian scheduled tasks");

                // First try schtasks approach
                await TryScheduledTasksCommand(cimianInfo);
                
                // Also try registry approach as fallback
                await TryScheduledTasksRegistry(cimianInfo);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error checking Cimian scheduled tasks: {Error}", ex.Message);
            }
        }

        private async Task TryScheduledTasksCommand(CimianInfo cimianInfo)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /tn \"Cimian Managed Software Update Hourly\" /fo list",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = processInfo };
                process.Start();

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();

                var completed = await Task.Run(() => process.WaitForExit(5000));

                if (!completed)
                {
                    try
                    {
                        process.Kill(true);
                    }
                    catch
                    {
                        // Ignore kill errors
                    }
                    _logger.LogDebug("schtasks command timed out");
                    return;
                }

                if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    string? status = null;

                    foreach (var line in lines)
                    {
                        var trimmedLine = line.Trim();
                        if (trimmedLine.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                        {
                            status = trimmedLine.Substring(7).Trim();
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(status))
                    {
                        cimianInfo.Services.Add($"CimianHourlyRunTask: {status.ToUpperInvariant()}");
                        _logger.LogDebug("Found Cimian scheduled task with status: {Status}", status);
                    }
                }
                else
                {
                    _logger.LogDebug("schtasks query for specific task failed with exit code {ExitCode}", process.ExitCode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error checking scheduled task via schtasks: {Error}", ex.Message);
            }
        }

        private Task TryScheduledTasksRegistry(CimianInfo cimianInfo)
        {
            try
            {
                // Check if Cimian task is registered in the task scheduler registry
                var taskPaths = new[]
                {
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Cimian Managed Software Update Hourly",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Cimian Managed Software Update Hourly"
                };

                foreach (var taskPath in taskPaths)
                {
                    try
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(taskPath);
                        if (key != null)
                        {
                            // Task exists in registry
                            cimianInfo.Services.Add("CimianHourlyRunTask: REGISTERED");
                            _logger.LogDebug("Found Cimian scheduled task in registry: {Path}", taskPath);
                            return Task.CompletedTask;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("Could not check registry path {Path}: {Error}", taskPath, ex.Message);
                    }
                }

                _logger.LogDebug("Cimian scheduled task not found in registry");
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error checking scheduled task via registry: {Error}", ex.Message);
                return Task.CompletedTask;
            }
        }

        private void ProcessRunLog(InstallsData data)
        {
            try
            {
                var logPath = @"C:\ProgramData\ManagedInstalls\reports\run.log";
                if (File.Exists(logPath))
                {
                    // Read the log file
                    // Use FileShare.ReadWrite to avoid locking issues if Cimian is running
                    using (var fileStream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var streamReader = new StreamReader(fileStream))
                    {
                        data.RunLog = streamReader.ReadToEnd();
                    }
                    _logger.LogInformation("Loaded Cimian run log ({Length} chars)", data.RunLog?.Length ?? 0);
                }
                else
                {
                    _logger.LogDebug("Cimian run log not found at {Path}", logPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read Cimian run log");
            }
        }
    }
}










