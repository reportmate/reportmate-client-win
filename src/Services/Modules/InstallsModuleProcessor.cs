#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json;
using System.Linq;
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

        public override Task<InstallsData> ProcessModuleAsync(
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
            
            // Process Cimian reports data (sessions, items, events)
            ProcessCimianReports(osqueryResults, data);
            
            // Process recent installs and deployments
            ProcessRecentInstalls(osqueryResults, data);
            
            // Process cache status
            ProcessCacheStatus(osqueryResults, data);

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

            // Check managed software version info
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

            // Check manifests and configuration data
            if (osqueryResults.TryGetValue("cimian_managed_items", out var reports))
            {
                foreach (var report in reports)
                {
                    var filename = GetStringValue(report, "path");
                    var size = GetStringValue(report, "size");
                    var mtime = GetStringValue(report, "mtime");
                    cimianInfo.Reports[filename] = new CimianReportFileInfo { Size = size, Mtime = mtime };
                }
            }

            // Set default status if not already set
            if (string.IsNullOrEmpty(cimianInfo.Status))
            {
                cimianInfo.Status = cimianInfo.IsInstalled ? "Installed" : "Not Installed";
            }

            return cimianInfo;
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
                // Process sessions report
                if (osqueryResults.TryGetValue("cimian_reports_sessions", out var sessionsQuery))
                {
                    var sessionsFile = sessionsQuery.FirstOrDefault();
                    if (sessionsFile != null)
                    {
                        var path = GetStringValue(sessionsFile, "path");
                        var sessions = ReadCimianSessionsReport(path);
                        data.RecentSessions.AddRange(sessions.Take(20)); // Limit to 20 most recent sessions
                        _logger.LogDebug("Loaded {Count} sessions from Cimian reports", sessions.Count);
                    }
                }

                // Process items report  
                if (osqueryResults.TryGetValue("cimian_reports_items", out var itemsQuery))
                {
                    var itemsFile = itemsQuery.FirstOrDefault();
                    if (itemsFile != null)
                    {
                        var path = GetStringValue(itemsFile, "path");
                        var items = ReadCimianItemsReport(path);
                        ProcessManagedItemsFromReport(items, data);
                        _logger.LogDebug("Loaded {Count} managed items from Cimian reports", items.Count);
                    }
                }

                // Process events report
                if (osqueryResults.TryGetValue("cimian_reports_events", out var eventsQuery))
                {
                    var eventsFile = eventsQuery.FirstOrDefault();
                    if (eventsFile != null)
                    {
                        var path = GetStringValue(eventsFile, "path");
                        var events = ReadCimianEventsReport(path);
                        data.RecentEvents.AddRange(events.Take(100)); // Limit to 100 most recent events
                        _logger.LogDebug("Loaded {Count} events from Cimian reports", events.Count);
                    }
                }

                // Set bootstrap mode status
                if (data.Cimian != null)
                {
                    data.BootstrapModeActive = data.Cimian.BootstrapFlagPresent;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing Cimian reports data");
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
                        TotalActions = sessionElement.GetProperty("total_actions").GetInt32(),
                        Installs = sessionElement.GetProperty("installs").GetInt32(),
                        Updates = sessionElement.GetProperty("updates").GetInt32(),
                        Removals = sessionElement.GetProperty("removals").GetInt32(),
                        Successes = sessionElement.GetProperty("successes").GetInt32(),
                        Failures = sessionElement.GetProperty("failures").GetInt32(),
                        Hostname = sessionElement.GetProperty("hostname").GetString() ?? "",
                        User = sessionElement.GetProperty("user").GetString() ?? "",
                        ProcessId = sessionElement.GetProperty("process_id").GetInt32(),
                        LogVersion = sessionElement.GetProperty("log_version").GetString() ?? ""
                    };

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

                    if (eventElement.TryGetProperty("timestamp", out var timestampProp) &&
                        DateTime.TryParse(timestampProp.GetString(), out var timestamp))
                    {
                        cimianEvent.Timestamp = timestamp;
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
                foreach (var item in items)
                {
                    var managedInstall = new ManagedInstall
                    {
                        Name = GetDictValue(item, "item_name"),
                        Status = GetDictValue(item, "current_status"),
                        Version = GetDictValue(item, "latest_version"),
                        Source = "Cimian"
                    };

                    if (item.TryGetValue("last_successful_time", out var lastSuccessObj) && 
                        DateTime.TryParse(lastSuccessObj.ToString(), out var lastSuccess))
                    {
                        managedInstall.InstallDate = lastSuccess;
                    }

                    if (item.TryGetValue("install_loop_detected", out var loopObj) && 
                        bool.TryParse(loopObj.ToString(), out var hasLoop))
                    {
                        managedInstall.HasInstallLoop = hasLoop;
                    }

                    if (item.TryGetValue("install_count", out var installCountObj) && 
                        int.TryParse(installCountObj.ToString(), out var installCount))
                    {
                        managedInstall.InstallCount = installCount;
                    }

                    if (item.TryGetValue("failure_count", out var failureCountObj) && 
                        int.TryParse(failureCountObj.ToString(), out var failureCount))
                    {
                        managedInstall.FailureCount = failureCount;
                    }

                    data.RecentInstalls.Add(managedInstall);
                }
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
    }
}
