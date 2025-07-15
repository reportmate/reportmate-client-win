#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Configuration;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Service for advanced Cimian integration and structured logging support
    /// </summary>
    public interface ICimianIntegrationService
    {
        Task<bool> IsCimianInstalledAsync();
        Task<CimianInfo?> GetCimianStatusAsync();
        Task<List<CimianSession>> GetRecentSessionsAsync(int limitHours = 24);
        Task<List<CimianEvent>> GetRecentEventsAsync(int limitHours = 24);
        Task<Dictionary<string, object>> GetCimianReportsDataAsync();
        Task<bool> ExportReportMateDataForCimianAsync(string outputPath);
    }

    public class CimianIntegrationService : ICimianIntegrationService
    {
        private readonly ILogger<CimianIntegrationService> _logger;
        private readonly ReportMateClientConfiguration _configuration;
        
        private const string CIMIAN_LOGS_PATH = @"C:\ProgramData\ManagedInstalls\logs";
        private const string CIMIAN_REPORTS_PATH = @"C:\ProgramData\ManagedInstalls\reports";
        private const string CIMIAN_CACHE_PATH = @"C:\ProgramData\ManagedInstalls\Cache";
        private const string BOOTSTRAP_FLAG_FILE = @"C:\ProgramData\ManagedInstalls\.cimian.bootstrap";

        public CimianIntegrationService(
            ILogger<CimianIntegrationService> logger,
            ReportMateClientConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public Task<bool> IsCimianInstalledAsync()
        {
            try
            {
                // Check for Cimian installation indicators
                var cimianPaths = new[]
                {
                    @"C:\Program Files\Cimian",
                    @"C:\ProgramData\ManagedInstalls",
                    CIMIAN_LOGS_PATH
                };

                foreach (var path in cimianPaths)
                {
                    if (Directory.Exists(path))
                    {
                        _logger.LogDebug("Found Cimian path: {Path}", path);
                        return Task.FromResult(true);
                    }
                }

                return Task.FromResult(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Error checking Cimian installation: {Error}", ex.Message);
                return Task.FromResult(false);
            }
        }

        public async Task<CimianInfo?> GetCimianStatusAsync()
        {
            try
            {
                if (!await IsCimianInstalledAsync())
                {
                    return null;
                }

                var cimianInfo = new CimianInfo
                {
                    IsInstalled = true,
                    Status = "Installed"
                };

                // Check bootstrap mode
                cimianInfo.BootstrapFlagPresent = File.Exists(BOOTSTRAP_FLAG_FILE);

                // Get session count and last session time
                if (Directory.Exists(CIMIAN_LOGS_PATH))
                {
                    var sessionDirs = Directory.GetDirectories(CIMIAN_LOGS_PATH);
                    cimianInfo.TotalSessions = sessionDirs.Length;

                    if (sessionDirs.Length > 0)
                    {
                        Array.Sort(sessionDirs);
                        var latestSessionDir = sessionDirs[^1];
                        var sessionName = Path.GetFileName(latestSessionDir);
                        
                        if (DateTime.TryParseExact(sessionName, "yyyyMMdd-HHmmss", null, 
                            System.Globalization.DateTimeStyles.None, out var sessionTime))
                        {
                            cimianInfo.LastSessionTime = sessionTime;
                        }
                    }
                }

                // Check reports data
                if (Directory.Exists(CIMIAN_REPORTS_PATH))
                {
                    var reportFiles = Directory.GetFiles(CIMIAN_REPORTS_PATH, "*.json");
                    foreach (var reportFile in reportFiles)
                    {
                        var fileName = Path.GetFileName(reportFile);
                        var fileInfo = new FileInfo(reportFile);
                        cimianInfo.Reports[fileName] = new CimianReportFileInfo
                        {
                            Size = fileInfo.Length.ToString(),
                            Mtime = fileInfo.LastWriteTime.ToString("O")
                        };
                    }
                }

                return cimianInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError("Error getting Cimian status: {Error}", ex.Message);
                return null;
            }
        }

        public async Task<List<CimianSession>> GetRecentSessionsAsync(int limitHours = 24)
        {
            var sessions = new List<CimianSession>();
            
            try
            {
                if (!Directory.Exists(CIMIAN_LOGS_PATH))
                {
                    return sessions;
                }

                var cutoffTime = DateTime.Now.AddHours(-limitHours);
                var sessionDirs = Directory.GetDirectories(CIMIAN_LOGS_PATH);
                
                foreach (var sessionDir in sessionDirs)
                {
                    var sessionName = Path.GetFileName(sessionDir);
                    
                    if (DateTime.TryParseExact(sessionName, "yyyyMMdd-HHmmss", null,
                        System.Globalization.DateTimeStyles.None, out var sessionTime))
                    {
                        if (sessionTime >= cutoffTime)
                        {
                            var session = await ReadSessionDataAsync(sessionDir, sessionName);
                            if (session != null)
                            {
                                sessions.Add(session);
                            }
                        }
                    }
                }

                sessions.Sort((x, y) => y.StartTime.CompareTo(x.StartTime));
            }
            catch (Exception ex)
            {
                _logger.LogError("Error reading recent Cimian sessions: {Error}", ex.Message);
            }

            return sessions;
        }

        public async Task<List<CimianEvent>> GetRecentEventsAsync(int limitHours = 24)
        {
            var events = new List<CimianEvent>();
            
            try
            {
                var recentSessions = await GetRecentSessionsAsync(limitHours);
                
                var limitedSessions = recentSessions.Count > 5 ? recentSessions.GetRange(0, 5) : recentSessions;
                foreach (var session in limitedSessions) // Limit to 5 most recent sessions
                {
                    var sessionEvents = await ReadSessionEventsAsync(
                        Path.Combine(CIMIAN_LOGS_PATH, session.SessionId), 
                        session.SessionId);
                        
                    var limitedEvents = sessionEvents.Count > 20 ? sessionEvents.GetRange(0, 20) : sessionEvents;
                    events.AddRange(limitedEvents); // Limit events per session
                }

                events.Sort((x, y) => y.Timestamp.CompareTo(x.Timestamp));
            }
            catch (Exception ex)
            {
                _logger.LogError("Error reading recent Cimian events: {Error}", ex.Message);
            }

            var finalEvents = events.Count > 100 ? events.GetRange(0, 100) : events;
            return finalEvents; // Overall limit of 100 events
        }

        public async Task<Dictionary<string, object>> GetCimianReportsDataAsync()
        {
            var reportsData = new Dictionary<string, object>();
            
            try
            {
                if (!Directory.Exists(CIMIAN_REPORTS_PATH))
                {
                    return reportsData;
                }

                var reportFiles = new[] { "sessions.json", "events.json", "packages.json" };
                
                foreach (var reportFile in reportFiles)
                {
                    var filePath = Path.Combine(CIMIAN_REPORTS_PATH, reportFile);
                    if (File.Exists(filePath))
                    {
                        try
                        {
                            var json = await File.ReadAllTextAsync(filePath);
                            using var document = JsonDocument.Parse(json);
                            reportsData[Path.GetFileNameWithoutExtension(reportFile)] = 
                                JsonSerializer.Deserialize<object>(json) ?? new object();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning("Failed to read Cimian report file {File}: {Error}", 
                                reportFile, ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Error reading Cimian reports data: {Error}", ex.Message);
            }

            return reportsData;
        }

        public async Task<bool> ExportReportMateDataForCimianAsync(string outputPath)
        {
            try
            {
                // Create a ReportMate data export that follows Cimian's structured logging format
                var exportData = new
                {
                    export_timestamp = DateTime.UtcNow.ToString("O"),
                    source = "ReportMate",
                    version = "1.0.0",
                    device_id = _configuration.DeviceId ?? "unknown",
                    platform = "Windows",
                    data_collection = new
                    {
                        api_url = _configuration.ApiUrl,
                        collection_interval = _configuration.CollectionIntervalSeconds,
                        last_collection = DateTime.UtcNow.ToString("O"),
                        modules_enabled = new[] { "hardware", "system", "network", "inventory", "applications", "security", "installs", "management", "profiles" }
                    },
                    cimian_integration = new
                    {
                        enabled = _configuration.CimianIntegrationEnabled,
                        status = await IsCimianInstalledAsync() ? "detected" : "not_detected",
                        bootstrap_mode = File.Exists(BOOTSTRAP_FLAG_FILE)
                    }
                };

                var json = JsonSerializer.Serialize(exportData, new JsonSerializerOptions 
                { 
                    WriteIndented = true 
                });
                
                await File.WriteAllTextAsync(outputPath, json);
                
                _logger.LogInformation("Exported ReportMate data for Cimian integration to {OutputPath}", outputPath);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to export ReportMate data for Cimian: {Error}", ex.Message);
                return false;
            }
        }

        private async Task<CimianSession?> ReadSessionDataAsync(string sessionDir, string sessionId)
        {
            try
            {
                var sessionFile = Path.Combine(sessionDir, "session.json");
                if (!File.Exists(sessionFile))
                {
                    return null;
                }

                var json = await File.ReadAllTextAsync(sessionFile);
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

                if (root.TryGetProperty("end_time", out var endTimeProp) && 
                    endTimeProp.ValueKind != JsonValueKind.Null)
                {
                    if (DateTime.TryParse(endTimeProp.GetString(), out var endTime))
                    {
                        session.EndTime = endTime;
                        session.Duration = endTime - session.StartTime;
                    }
                }

                if (root.TryGetProperty("summary", out var summaryProp))
                {
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
                _logger.LogDebug("Failed to read session data from {SessionDir}: {Error}", sessionDir, ex.Message);
                return null;
            }
        }

        private async Task<List<CimianEvent>> ReadSessionEventsAsync(string sessionDir, string sessionId)
        {
            var events = new List<CimianEvent>();
            
            try
            {
                var eventsFile = Path.Combine(sessionDir, "events.jsonl");
                if (!File.Exists(eventsFile))
                {
                    return events;
                }

                var lines = await File.ReadAllLinesAsync(eventsFile);
                var recentLines = lines.Length > 20 ? lines.Skip(lines.Length - 20).ToArray() : lines;
                foreach (var line in recentLines) // Limit to last 20 events per session
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

                        events.Add(cimianEvent);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("Failed to parse event line in session {SessionId}: {Error}", sessionId, ex.Message);
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Failed to read events from session {SessionId}: {Error}", sessionId, ex.Message);
            }

            return events;
        }
    }
}
