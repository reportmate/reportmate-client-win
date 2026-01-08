#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Service for collecting application usage data from Windows process telemetry.
    /// Uses multiple event sources in priority order:
    /// 1. Security Log (Event 4688/4689) - Available on Windows 10/11 when audit policy enabled
    /// 2. Microsoft-Windows-Kernel-Process/Operational - Older Windows versions
    /// Tracks:
    /// - Process start/stop events with user context
    /// - Session duration calculation
    /// - Per-user application usage statistics
    /// </summary>
    public class ApplicationUsageService
    {
        private readonly ILogger<ApplicationUsageService> _logger;
        
        // Kernel Process Event IDs (older Windows)
        private const int KernelProcessStartEventId = 1;
        private const int KernelProcessStopEventId = 2;
        
        // Security Log Event IDs (Windows 10/11)
        private const int SecurityProcessCreationEventId = 4688;
        private const int SecurityProcessTerminationEventId = 4689;
        
        // System Event IDs for shutdown detection
        private const int SystemShutdownEventId = 1074;
        private const int UnexpectedShutdownEventId = 6008;
        
        // Session tracking
        private const int MaxSessionHours = 24; // Mark sessions as interrupted if no stop event within 24h
        private const int DefaultLookbackHours = 4; // Match the applications module schedule (every 4 hours)
        
        // Cache for SID to username resolution
        private readonly Dictionary<string, string> _sidCache = new();
        
        // Track which event source we're using
        private enum EventSource { None, SecurityLog, KernelLog }
        private EventSource _activeEventSource = EventSource.None;
        private int _skipLogCount = 0;  // For debug logging
        
        public ApplicationUsageService(ILogger<ApplicationUsageService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Collect application usage data from process events.
        /// </summary>
        /// <param name="installedApps">List of installed applications for matching executables</param>
        /// <param name="lookbackHours">Hours to look back for events (default: 4 to match schedule)</param>
        /// <returns>Usage snapshot with per-application and per-user statistics</returns>
        public async Task<ApplicationUsageSnapshot> CollectUsageDataAsync(
            List<InstalledApplication> installedApps, 
            int lookbackHours = DefaultLookbackHours)
        {
            var snapshot = new ApplicationUsageSnapshot
            {
                GeneratedAt = DateTime.UtcNow,
                WindowStart = DateTime.UtcNow.AddHours(-lookbackHours),
                WindowEnd = DateTime.UtcNow
            };

            try
            {
                // Check available event sources (try Security log first, then Kernel log)
                _activeEventSource = await DetermineEventSourceAsync();
                
                if (_activeEventSource == EventSource.None)
                {
                    snapshot.Status = "unavailable";
                    snapshot.IsCaptureEnabled = false;
                    snapshot.Warnings.Add("No process event source available. Enable process auditing or Kernel-Process log.");
                    return snapshot;
                }

                snapshot.IsCaptureEnabled = true;
                snapshot.Status = "collecting";
                _logger.LogInformation("Using event source: {Source}", _activeEventSource);

                // Get system shutdown events to mark interrupted sessions
                var shutdownTimes = await GetShutdownEventsAsync(lookbackHours);
                
                // Collect process start and stop events from the available source
                var processEvents = await CollectProcessEventsAsync(lookbackHours);
                
                if (processEvents.Count == 0)
                {
                    snapshot.Status = "no_data";
                    snapshot.Warnings.Add($"No process events found in the last {lookbackHours} hours");
                    return snapshot;
                }

                _logger.LogDebug("Collected {Count} process events from {Source}", processEvents.Count, _activeEventSource);

                // Build sessions from start/stop event pairs
                var sessions = BuildSessionsFromEvents(processEvents, shutdownTimes, installedApps);
                
                // Aggregate into per-application summaries
                var appSummaries = AggregateSessionsByApplication(sessions, installedApps);
                
                // Populate snapshot
                snapshot.Status = "complete";
                snapshot.Applications = appSummaries;
                snapshot.ActiveSessions = sessions.Where(s => s.IsActive).ToList();
                snapshot.TotalLaunches = sessions.Count;
                snapshot.TotalUsageSeconds = sessions.Sum(s => s.DurationSeconds);

                // Update installed apps with their usage summaries
                // Use a HashSet to track which summaries have been assigned to prevent duplicates
                var assignedSummaries = new HashSet<ApplicationUsageSummary>();
                
                // First pass: Match apps that have install locations (most reliable)
                foreach (var app in installedApps.Where(a => !string.IsNullOrEmpty(a.InstallLocation)))
                {
                    var matchingSummary = appSummaries
                        .Where(s => !assignedSummaries.Contains(s))
                        .FirstOrDefault(s => MatchesApplication(s.Path, app));
                    if (matchingSummary != null)
                    {
                        app.Usage = matchingSummary;
                        assignedSummaries.Add(matchingSummary);
                    }
                }
                
                // Second pass: Match apps without install locations (less reliable, use remaining summaries)
                foreach (var app in installedApps.Where(a => string.IsNullOrEmpty(a.InstallLocation) && a.Usage == null))
                {
                    var matchingSummary = appSummaries
                        .Where(s => !assignedSummaries.Contains(s))
                        .FirstOrDefault(s => MatchesApplication(s.Path, app));
                    if (matchingSummary != null)
                    {
                        app.Usage = matchingSummary;
                        assignedSummaries.Add(matchingSummary);
                    }
                }

                _logger.LogInformation(
                    "Usage collection complete: {SessionCount} sessions, {ActiveCount} active, {TotalHours:F1}h total usage",
                    sessions.Count,
                    snapshot.ActiveSessions.Count,
                    snapshot.TotalUsageSeconds / 3600);

                return snapshot;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect application usage data");
                snapshot.Status = "error";
                snapshot.IsCaptureEnabled = false;
                snapshot.Warnings.Add($"Error collecting usage data: {ex.Message}");
                return snapshot;
            }
        }

        /// <summary>
        /// Determine which event source is available for process tracking.
        /// Priority: Security Log (4688) > Kernel-Process/Operational
        /// </summary>
        private Task<EventSource> DetermineEventSourceAsync()
        {
            return Task.Run(() =>
            {
                // Try Security Log first (more reliable on Windows 10/11)
                try
                {
                    var testTime = DateTime.UtcNow.AddHours(-24);
                    var securityQuery = new EventLogQuery(
                        "Security",
                        PathType.LogName,
                        $"*[System[(EventID={SecurityProcessCreationEventId}) and TimeCreated[@SystemTime>='{testTime:o}']]]");
                    
                    using var reader = new EventLogReader(securityQuery);
                    var testEvent = reader.ReadEvent();
                    if (testEvent != null)
                    {
                        testEvent.Dispose();
                        _logger.LogInformation("Security log process auditing is available (Event 4688)");
                        return EventSource.SecurityLog;
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    _logger.LogWarning("Access denied to Security log - requires elevated privileges");
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Security log not available: {Message}", ex.Message);
                }

                // Fall back to Kernel-Process/Operational log
                try
                {
                    const string logName = "Microsoft-Windows-Kernel-Process/Operational";
                    using var session = new EventLogSession();
                    var logInfo = session.GetLogInformation(logName, PathType.LogName);
                    
                    if (logInfo.RecordCount.HasValue && logInfo.RecordCount.Value > 0)
                    {
                        _logger.LogInformation("Kernel process log available with {Count} records", logInfo.RecordCount.Value);
                        return EventSource.KernelLog;
                    }
                    
                    _logger.LogWarning("Kernel process log exists but has no records");
                }
                catch (EventLogNotFoundException)
                {
                    _logger.LogWarning("Kernel process log not found on this system");
                }
                catch (UnauthorizedAccessException)
                {
                    _logger.LogWarning("Access denied to kernel process log");
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Kernel process log not available: {Message}", ex.Message);
                }

                _logger.LogWarning("No process event source available. To enable usage tracking, configure process auditing via Group Policy.");
                return EventSource.None;
            });
        }

        /// <summary>
        /// Get system shutdown events to detect interrupted sessions.
        /// </summary>
        private Task<List<DateTime>> GetShutdownEventsAsync(int lookbackHours)
        {
            return Task.Run(() =>
            {
                var shutdownTimes = new List<DateTime>();
                var startTime = DateTime.UtcNow.AddHours(-lookbackHours);

                try
                {
                    // Query System log for shutdown events
                    var query = new EventLogQuery(
                        "System",
                        PathType.LogName,
                        $"*[System[(EventID={SystemShutdownEventId} or EventID={UnexpectedShutdownEventId}) and TimeCreated[@SystemTime>='{startTime:o}']]]");

                    using var reader = new EventLogReader(query);
                    EventRecord? record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            if (record.TimeCreated.HasValue)
                            {
                                shutdownTimes.Add(record.TimeCreated.Value.ToUniversalTime());
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to query system shutdown events");
                }

                return shutdownTimes;
            });
        }

        /// <summary>
        /// Collect process start and stop events from the active event source.
        /// </summary>
        private Task<List<ProcessEventRecord>> CollectProcessEventsAsync(int lookbackHours)
        {
            return _activeEventSource switch
            {
                EventSource.SecurityLog => CollectSecurityLogEventsAsync(lookbackHours),
                EventSource.KernelLog => CollectKernelLogEventsAsync(lookbackHours),
                _ => Task.FromResult(new List<ProcessEventRecord>())
            };
        }

        /// <summary>
        /// Collect process events from Security Log (Event 4688/4689).
        /// </summary>
        private Task<List<ProcessEventRecord>> CollectSecurityLogEventsAsync(int lookbackHours)
        {
            return Task.Run(() =>
            {
                var events = new List<ProcessEventRecord>();
                var startTime = DateTime.Now.AddHours(-lookbackHours);  // Use local time for query
                
                _logger.LogDebug("Security log query: Looking for events since {StartTime:o} (local)", startTime);

                try
                {
                    // Query for process creation (4688) and termination (4689) events
                    // Note: Windows Event Log timestamps are in local time despite showing "Z" suffix in wevtutil
                    var queryString = $"*[System[(EventID={SecurityProcessCreationEventId} or EventID={SecurityProcessTerminationEventId}) and TimeCreated[@SystemTime>='{startTime.ToUniversalTime():o}']]]";
                    _logger.LogInformation("Security log XPath query: {Query}", queryString);
                    
                    var query = new EventLogQuery(
                        "Security",
                        PathType.LogName,
                        queryString);

                    using var reader = new EventLogReader(query);
                    EventRecord? record;
                    int rawCount = 0;
                    int parsedCount = 0;
                    
                    while ((record = reader.ReadEvent()) != null)
                    {
                        rawCount++;
                        using (record)
                        {
                            var processEvent = ParseSecurityProcessEvent(record);
                            if (processEvent != null)
                            {
                                parsedCount++;
                                events.Add(processEvent);
                            }
                        }
                    }
                    
                    _logger.LogInformation("Security log: {RawCount} raw events, {ParsedCount} parsed, {FinalCount} kept after filtering", 
                        rawCount, parsedCount, events.Count);
                }
                catch (UnauthorizedAccessException)
                {
                    _logger.LogWarning("Access denied to Security log - requires elevated privileges");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error reading Security log events");
                }

                return events;
            });
        }

        /// <summary>
        /// Collect process events from Kernel-Process/Operational log.
        /// </summary>
        private Task<List<ProcessEventRecord>> CollectKernelLogEventsAsync(int lookbackHours)
        {
            return Task.Run(() =>
            {
                var events = new List<ProcessEventRecord>();
                var startTime = DateTime.UtcNow.AddHours(-lookbackHours);

                try
                {
                    const string logName = "Microsoft-Windows-Kernel-Process/Operational";
                    
                    // Query for process start (1) and stop (2) events
                    var query = new EventLogQuery(
                        logName,
                        PathType.LogName,
                        $"*[System[(EventID={KernelProcessStartEventId} or EventID={KernelProcessStopEventId}) and TimeCreated[@SystemTime>='{startTime:o}']]]");

                    using var reader = new EventLogReader(query);
                    EventRecord? record;
                    
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            var processEvent = ParseKernelProcessEvent(record);
                            if (processEvent != null)
                            {
                                events.Add(processEvent);
                            }
                        }
                    }
                    
                    _logger.LogDebug("Collected {Count} events from Kernel-Process log", events.Count);
                }
                catch (EventLogNotFoundException)
                {
                    _logger.LogWarning("Kernel process log not found");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error reading kernel process events");
                }

                return events;
            });
        }

        /// <summary>
        /// Parse a Security log process event (4688/4689) into our model.
        /// </summary>
        private ProcessEventRecord? ParseSecurityProcessEvent(EventRecord record)
        {
            try
            {
                if (!record.TimeCreated.HasValue || record.Id == 0)
                    return null;

                var processEvent = new ProcessEventRecord
                {
                    EventId = record.Id,
                    TimeCreated = record.TimeCreated.Value.ToUniversalTime(),
                    IsStart = record.Id == SecurityProcessCreationEventId
                };

                // Parse event XML for data
                var xml = record.ToXml();
                
                // Event 4688 structure:
                // - SubjectUserSid, SubjectUserName, SubjectDomainName
                // - NewProcessId, NewProcessName
                // - ProcessId (parent), CommandLine
                
                // Event 4689 structure:
                // - SubjectUserSid, SubjectUserName, SubjectDomainName  
                // - ProcessId, ProcessName

                if (record.Id == SecurityProcessCreationEventId)
                {
                    // Process Creation (4688)
                    // Note: Windows Event XML uses single quotes for attribute values
                    var pidMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]NewProcessId['""]>(0x[0-9a-fA-F]+|\d+)</Data>");
                    if (pidMatch.Success)
                    {
                        var pidStr = pidMatch.Groups[1].Value;
                        processEvent.ProcessId = pidStr.StartsWith("0x") 
                            ? Convert.ToInt32(pidStr, 16) 
                            : int.Parse(pidStr);
                    }

                    var imageMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]NewProcessName['""]>([^<]+)</Data>");
                    if (imageMatch.Success)
                    {
                        processEvent.ImagePath = imageMatch.Groups[1].Value;
                        processEvent.ProcessName = System.IO.Path.GetFileName(processEvent.ImagePath);
                    }
                }
                else
                {
                    // Process Termination (4689)
                    var pidMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]ProcessId['""]>(0x[0-9a-fA-F]+|\d+)</Data>");
                    if (pidMatch.Success)
                    {
                        var pidStr = pidMatch.Groups[1].Value;
                        processEvent.ProcessId = pidStr.StartsWith("0x") 
                            ? Convert.ToInt32(pidStr, 16) 
                            : int.Parse(pidStr);
                    }

                    var imageMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]ProcessName['""]>([^<]+)</Data>");
                    if (imageMatch.Success)
                    {
                        processEvent.ImagePath = imageMatch.Groups[1].Value;
                        processEvent.ProcessName = System.IO.Path.GetFileName(processEvent.ImagePath);
                    }
                }

                // Extract user info (same for both events)
                var sidMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]SubjectUserSid['""]>(S-[^<]+)</Data>");
                if (sidMatch.Success)
                {
                    processEvent.UserSid = sidMatch.Groups[1].Value;
                }

                var userMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]SubjectUserName['""]>([^<]+)</Data>");
                var domainMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=['""]SubjectDomainName['""]>([^<]+)</Data>");
                if (userMatch.Success)
                {
                    var domain = domainMatch.Success ? domainMatch.Groups[1].Value : "";
                    var user = userMatch.Groups[1].Value;
                    processEvent.Username = string.IsNullOrEmpty(domain) || domain == "-" 
                        ? user 
                        : $"{domain}\\{user}";
                }
                else if (!string.IsNullOrEmpty(processEvent.UserSid))
                {
                    processEvent.Username = ResolveUsername(processEvent.UserSid);
                }

                // Skip system processes and empty paths
                if (string.IsNullOrEmpty(processEvent.ImagePath))
                {
                    // Debug: log that we couldn't parse the path
                    if (_skipLogCount < 3)
                    {
                        _logger.LogDebug("No image path found in event. EventId={EventId}", record.Id);
                    }
                    return null;
                }
                
                // Debug: Log a sample of paths we're seeing
                if (_skipLogCount < 10)
                {
                    _logger.LogDebug("Parsed process: {Path}, Skip={Skip}", processEvent.ImagePath, ShouldSkipProcess(processEvent.ImagePath));
                    _skipLogCount++;
                }
                
                if (ShouldSkipProcess(processEvent.ImagePath))
                {
                    return null;
                }

                return processEvent;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse security event record");
                return null;
            }
        }

        /// <summary>
        /// Parse a kernel process event record into our model.
        /// </summary>
        private ProcessEventRecord? ParseKernelProcessEvent(EventRecord record)
        {
            try
            {
                if (!record.TimeCreated.HasValue || record.Id == 0)
                    return null;

                var processEvent = new ProcessEventRecord
                {
                    EventId = record.Id,
                    TimeCreated = record.TimeCreated.Value.ToUniversalTime(),
                    IsStart = record.Id == KernelProcessStartEventId
                };

                // Parse event properties
                // Event data structure for Kernel-Process events:
                // ProcessId, ImageFileName, UserSid, SessionId, etc.
                if (record.Properties != null && record.Properties.Count > 0)
                {
                    // Property indices vary by Windows version, extract by parsing XML
                    var xml = record.ToXml();
                    
                    // Extract ProcessId
                    var pidMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=""ProcessId"">(\d+)</Data>");
                    if (pidMatch.Success && int.TryParse(pidMatch.Groups[1].Value, out var pid))
                    {
                        processEvent.ProcessId = pid;
                    }

                    // Extract ImageFileName (process path)
                    var imageMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=""ImageFileName"">([^<]+)</Data>");
                    if (imageMatch.Success)
                    {
                        processEvent.ImagePath = imageMatch.Groups[1].Value;
                        processEvent.ProcessName = System.IO.Path.GetFileName(processEvent.ImagePath);
                    }

                    // Extract UserSid
                    var sidMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=""UserSID"">(S-[^<]+)</Data>");
                    if (sidMatch.Success)
                    {
                        processEvent.UserSid = sidMatch.Groups[1].Value;
                        processEvent.Username = ResolveUsername(processEvent.UserSid);
                    }

                    // Extract SessionId (terminal services session)
                    var sessionMatch = System.Text.RegularExpressions.Regex.Match(xml, @"<Data Name=""SessionId"">(\d+)</Data>");
                    if (sessionMatch.Success && int.TryParse(sessionMatch.Groups[1].Value, out var sessionId))
                    {
                        processEvent.SessionId = sessionId;
                    }
                }

                // Skip system processes and empty paths
                if (string.IsNullOrEmpty(processEvent.ImagePath) ||
                    ShouldSkipProcess(processEvent.ImagePath))
                {
                    return null;
                }

                return processEvent;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse kernel process event record");
                return null;
            }
        }

        /// <summary>
        /// Check if a process should be skipped (system processes, services, etc.)
        /// </summary>
        private static bool ShouldSkipProcess(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath))
                return true;

            var lowerPath = imagePath.ToLowerInvariant();
            
            // Skip kernel/system paths
            if (lowerPath.StartsWith(@"\systemroot") ||
                lowerPath.StartsWith(@"\device\") ||
                lowerPath.StartsWith(@"system32\") ||
                lowerPath.Contains(@"\windows\system32\") ||
                lowerPath.Contains(@"\windows\syswow64\"))
            {
                // But allow specific apps from System32
                var filename = System.IO.Path.GetFileName(lowerPath);
                var allowedSystem32Apps = new[] { "notepad.exe", "mspaint.exe", "calc.exe", "snippingtool.exe", "mstsc.exe" };
                if (!allowedSystem32Apps.Contains(filename))
                {
                    return true;
                }
            }

            // Skip common system services
            var skipProcesses = new[]
            {
                "svchost.exe", "csrss.exe", "smss.exe", "services.exe", "lsass.exe",
                "wininit.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe",
                "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe", "searchhost.exe",
                "securityhealthservice.exe", "securityhealthsystray.exe", "spoolsv.exe",
                "audiodg.exe", "conhost.exe", "ctfmon.exe", "dllhost.exe", "msiexec.exe",
                "wuauclt.exe", "trustedinstaller.exe", "tiworker.exe", "wmiprvse.exe",
                "microsoftedgeupdate.exe", "googleupdate.exe"  // Skip browser UPDATE processes only
            };
            
            var processName = System.IO.Path.GetFileName(lowerPath);
            return skipProcesses.Contains(processName);
        }

        /// <summary>
        /// Resolve a Windows SID to a username (DOMAIN\User format).
        /// Uses caching for performance.
        /// </summary>
        private string ResolveUsername(string sidString)
        {
            if (string.IsNullOrEmpty(sidString))
                return "UNKNOWN";

            // Check cache first
            if (_sidCache.TryGetValue(sidString, out var cachedUsername))
                return cachedUsername;

            try
            {
                var sid = new SecurityIdentifier(sidString);
                var account = sid.Translate(typeof(NTAccount)) as NTAccount;
                var username = account?.Value ?? sidString;
                
                _sidCache[sidString] = username;
                return username;
            }
            catch (IdentityNotMappedException)
            {
                // SID doesn't map to a known account (deleted user, etc.)
                _sidCache[sidString] = sidString;
                return sidString;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to resolve SID {Sid}", sidString);
                _sidCache[sidString] = sidString;
                return sidString;
            }
        }

        /// <summary>
        /// Build usage sessions by pairing start and stop events.
        /// </summary>
        private List<ApplicationUsageSession> BuildSessionsFromEvents(
            List<ProcessEventRecord> events,
            List<DateTime> shutdownTimes,
            List<InstalledApplication> installedApps)
        {
            var sessions = new List<ApplicationUsageSession>();
            
            // Group events by ProcessId
            var eventsByPid = events
                .GroupBy(e => e.ProcessId)
                .ToDictionary(g => g.Key, g => g.OrderBy(e => e.TimeCreated).ToList());

            foreach (var kvp in eventsByPid)
            {
                var pidEvents = kvp.Value;
                var startEvents = pidEvents.Where(e => e.IsStart).ToList();
                var stopEvents = pidEvents.Where(e => !e.IsStart).ToList();

                foreach (var start in startEvents)
                {
                    var session = new ApplicationUsageSession
                    {
                        SessionId = $"{start.ProcessId}-{start.TimeCreated.Ticks}",
                        ProcessId = start.ProcessId,
                        Name = start.ProcessName,
                        Path = start.ImagePath,
                        User = start.Username,
                        UserSid = start.UserSid,
                        StartTime = start.TimeCreated
                    };

                    // Find matching stop event (first stop after this start)
                    var matchingStop = stopEvents.FirstOrDefault(s => s.TimeCreated > start.TimeCreated);
                    
                    if (matchingStop != null)
                    {
                        // Complete session
                        session.EndTime = matchingStop.TimeCreated;
                        session.DurationSeconds = (matchingStop.TimeCreated - start.TimeCreated).TotalSeconds;
                        session.IsActive = false;
                        
                        // Remove used stop event
                        stopEvents.Remove(matchingStop);
                    }
                    else
                    {
                        // Check if there was a shutdown that would end this session
                        var shutdownAfterStart = shutdownTimes.FirstOrDefault(s => s > start.TimeCreated);
                        if (shutdownAfterStart != default)
                        {
                            session.EndTime = shutdownAfterStart;
                            session.DurationSeconds = (shutdownAfterStart - start.TimeCreated).TotalSeconds;
                            session.IsActive = false;
                        }
                        else if ((DateTime.UtcNow - start.TimeCreated).TotalHours > MaxSessionHours)
                        {
                            // Mark as interrupted if older than 24h with no stop
                            session.EndTime = start.TimeCreated.AddHours(MaxSessionHours);
                            session.DurationSeconds = MaxSessionHours * 3600;
                            session.IsActive = false;
                        }
                        else
                        {
                            // Currently active session
                            session.EndTime = null;
                            session.DurationSeconds = (DateTime.UtcNow - start.TimeCreated).TotalSeconds;
                            session.IsActive = true;
                        }
                    }

                    // Match to installed application - ONLY track usage for known installed apps
                    // Skip process executables that don't match the inventory (system processes, scripts, etc.)
                    var matchedApp = installedApps.FirstOrDefault(app => MatchesApplication(session.Path, app));
                    if (matchedApp != null)
                    {
                        session.Name = matchedApp.Name;
                        session.Publisher = matchedApp.Publisher;
                        sessions.Add(session);
                    }
                    else
                    {
                        // Log unmatched sessions at debug level to help diagnose missing app tracking
                        _logger.LogDebug("Session not matched to installed app - Path: {Path}, Process: {ProcessName}", 
                            session.Path, start.ProcessName);
                    }
                }
            }

            return sessions;
        }

        /// <summary>
        /// Check if a process path matches an installed application.
        /// Uses intelligent matching strategies (no hardcoded mappings):
        /// 1. Install location prefix matching (most reliable)
        /// 2. Path component analysis - extracts meaningful words from path and matches against app name/publisher
        /// 3. Process filename to app name matching (fallback)
        /// </summary>
        private bool MatchesApplication(string processPath, InstalledApplication app)
        {
            if (string.IsNullOrEmpty(processPath))
                return false;

            var normalizedProcessPath = processPath.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();

            // Strategy 1: Install location prefix match (most accurate)
            if (!string.IsNullOrEmpty(app.InstallLocation))
            {
                var normalizedInstallPath = app.InstallLocation.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
                if (normalizedProcessPath.StartsWith(normalizedInstallPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Strategy 2: Intelligent path component matching
            // Extract meaningful words from path like: C:\Program Files\Google\Chrome\Application\chrome.exe
            // Match against app name words and publisher words
            var pathComponents = ExtractPathComponents(normalizedProcessPath);
            var appNameWords = ExtractWords(app.Name);
            var publisherWords = !string.IsNullOrEmpty(app.Publisher) ? ExtractWords(app.Publisher) : new List<string>();

            var matchScore = CalculateMatchScore(pathComponents, appNameWords, publisherWords);
            
            // Require 50% match of significant app words found in path
            if (matchScore >= 0.5)
            {
                return true;
            }

            // Strategy 3: Process filename directly matches app name word (minimum 4 chars to avoid false positives)
            var processFileName = System.IO.Path.GetFileNameWithoutExtension(normalizedProcessPath);
            if (processFileName.Length >= 4 && !string.IsNullOrEmpty(app.Name))
            {
                var appNameLower = app.Name.ToLowerInvariant();
                if (appNameLower.Contains(processFileName))
                {
                    return true;
                }
            }

            // Strategy 4: App name word matches process filename (reverse of Strategy 3)
            // Handles cases like "Google Chrome" where we look for "chrome" in the process path
            if (!string.IsNullOrEmpty(app.Name))
            {
                var nameWords = app.Name.ToLowerInvariant()
                    .Split(new[] { ' ', '-', '_', '.' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(w => w.Length >= 4)
                    .Where(w => !IsCommonWord(w));
                    
                foreach (var word in nameWords)
                {
                    // Check if app name word appears in process filename or path
                    if (processFileName.Contains(word) || normalizedProcessPath.Contains(word))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Extract meaningful components from a file path for matching.
        /// Filters out common path words like "Program Files", "x86", etc.
        /// </summary>
        private static List<string> ExtractPathComponents(string path)
        {
            var components = path
                .Split(new[] { '\\', '/', ' ', '-', '_' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(c => c.Length >= 3)
                .Where(c => !IsCommonPathWord(c))
                .Select(c => c.ToLowerInvariant().Replace(".exe", ""))
                .Distinct()
                .ToList();

            return components;
        }

        /// <summary>
        /// Extract meaningful words from an app name or publisher string.
        /// </summary>
        private static List<string> ExtractWords(string? text)
        {
            if (string.IsNullOrEmpty(text))
                return new List<string>();

            return text
                .Split(new[] { ' ', '-', '_', '.', '(', ')' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(w => w.Length >= 3)
                .Where(w => !IsCommonWord(w))
                .Select(w => w.ToLowerInvariant())
                .Distinct()
                .ToList();
        }

        /// <summary>
        /// Common path words that should be ignored during matching.
        /// NOTE: Vendor names (microsoft, google, apple, adobe) are intentionally NOT filtered
        /// because they are critical for matching apps like Chrome, VS Code, Teams, etc.
        /// </summary>
        private static bool IsCommonPathWord(string word)
        {
            var commonWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Path structure words
                "program", "files", "x86", "x64", "application", "applications", "app", "apps",
                "bin", "exe", "dll", "common", "shared", "resources", "lib", "usr", "local",
                "windowsapps", "appdata", "roaming", "users", "programdata",
                // Version/architecture patterns
                "win32", "win64", "amd64", "arm64",
                // SDK/Tool paths (not vendor names)
                "sdks", "cli2", "cli", "tools", "sdk", "kits",
                // OS-related paths
                "windows", "system", "system32", "syswow64"
                // NOTE: Do NOT filter vendor names like microsoft, google, apple, adobe, mozilla, etc.
                // These are essential for matching apps like "Google Chrome", "Microsoft Teams", etc.
            };
            return commonWords.Contains(word);
        }

        /// <summary>
        /// Common words in app names/publishers that should be ignored during matching.
        /// These words are too generic to reliably identify an application.
        /// NOTE: Vendor names (microsoft, google, etc.) are intentionally NOT filtered
        /// because they help match apps like "Google Chrome", "Microsoft Teams".
        /// </summary>
        private static bool IsCommonWord(string word)
        {
            var commonWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Generic business suffixes
                "inc", "llc", "ltd", "corp", "corporation", "software", "technologies",
                // Common generic app name words
                "the", "for", "and", "pro", "free", "edition", "version", "update",
                // OS-related generic words
                "desktop", "runtime", "client", "installer", "setup"
                // NOTE: Do NOT filter vendor names like microsoft, google, apple, adobe, etc.
                // These are essential for matching apps by their full names.
            };
            return commonWords.Contains(word);
        }

        /// <summary>
        /// Calculate a match score between path components and app name/publisher words.
        /// Returns a score from 0.0 to 1.0 indicating match confidence.
        /// Requires multiple significant word matches to avoid false positives.
        /// </summary>
        private static double CalculateMatchScore(List<string> pathComponents, List<string> appNameWords, List<string> publisherWords)
        {
            // Need at least 1 meaningful app name word (after filtering common words)
            if (appNameWords.Count == 0)
                return 0;

            // Count how many app name words match path components
            var appNameMatches = 0;
            foreach (var appWord in appNameWords)
            {
                // Skip short words - they cause too many false positives
                if (appWord.Length < 4)
                    continue;
                    
                foreach (var pathComp in pathComponents)
                {
                    if (pathComp.Length < 4)
                        continue;
                        
                    // Require exact match or strong containment (not just partial overlap)
                    if (pathComp == appWord || 
                        pathComp.StartsWith(appWord) || 
                        appWord.StartsWith(pathComp))
                    {
                        appNameMatches++;
                        break;
                    }
                }
            }

            // Require at least 1 significant app name match
            if (appNameMatches == 0)
                return 0;

            // Calculate score based on app name matches only (publisher is bonus, not required)
            var score = (double)appNameMatches / appNameWords.Count;
            
            // Bonus for publisher match (but don't rely on it alone)
            if (publisherWords.Count > 0)
            {
                var publisherMatches = publisherWords.Count(pw =>
                    pw.Length >= 4 && pathComponents.Any(pc => pc.Length >= 4 && (pc == pw || pc.StartsWith(pw) || pw.StartsWith(pc))));
                if (publisherMatches > 0)
                {
                    score = Math.Min(1.0, score + 0.1);
                }
            }

            return score;
        }

        /// <summary>
        /// Aggregate sessions into per-application usage summaries.
        /// </summary>
        private List<ApplicationUsageSummary> AggregateSessionsByApplication(
            List<ApplicationUsageSession> sessions,
            List<InstalledApplication> installedApps)
        {
            var summaries = new List<ApplicationUsageSummary>();

            // Group sessions by normalized path (application)
            var sessionsByApp = sessions
                .GroupBy(s => NormalizeAppKey(s.Path, s.Name))
                .Where(g => !string.IsNullOrEmpty(g.Key));

            foreach (var appGroup in sessionsByApp)
            {
                var appSessions = appGroup.ToList();
                var firstSession = appSessions.OrderBy(s => s.StartTime).First();
                var lastSession = appSessions.OrderByDescending(s => s.StartTime).First();
                
                // Get unique users
                var users = appSessions
                    .Select(s => s.User)
                    .Where(u => !string.IsNullOrEmpty(u) && u != "UNKNOWN")
                    .Distinct()
                    .ToList();

                // Try to match to installed app for publisher info
                var matchedApp = installedApps.FirstOrDefault(app => 
                    MatchesApplication(firstSession.Path, app));

                var summary = new ApplicationUsageSummary
                {
                    Name = matchedApp?.Name ?? firstSession.Name,
                    Executable = System.IO.Path.GetFileName(firstSession.Path),
                    Path = firstSession.Path,
                    Publisher = matchedApp?.Publisher ?? string.Empty,
                    FirstSeen = firstSession.StartTime,
                    LastLaunchTime = lastSession.StartTime,
                    LastExitTime = appSessions.Where(s => s.EndTime.HasValue)
                        .OrderByDescending(s => s.EndTime)
                        .FirstOrDefault()?.EndTime,
                    LaunchCount = appSessions.Count,
                    TotalUsageSeconds = appSessions.Sum(s => s.DurationSeconds),
                    ActiveUsageSeconds = appSessions.Sum(s => s.DurationSeconds), // Same for now, could track foreground time later
                    AverageSessionSeconds = appSessions.Count > 0 
                        ? appSessions.Average(s => s.DurationSeconds) 
                        : 0,
                    ActiveSessionCount = appSessions.Count(s => s.IsActive),
                    UniqueUserCount = users.Count,
                    Users = users,
                    RecentSessions = appSessions
                        .OrderByDescending(s => s.StartTime)
                        .Take(10)
                        .ToList()
                };

                summaries.Add(summary);
            }

            return summaries.OrderByDescending(s => s.TotalUsageSeconds).ToList();
        }

        /// <summary>
        /// Create a normalized key for grouping sessions by application.
        /// </summary>
        private string NormalizeAppKey(string path, string name)
        {
            if (!string.IsNullOrEmpty(path))
            {
                // Use directory path as key (without filename)
                var directory = System.IO.Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory))
                {
                    return directory.ToLowerInvariant();
                }
            }
            
            return name?.ToLowerInvariant() ?? string.Empty;
        }

        /// <summary>
        /// Internal class for tracking process events during parsing.
        /// </summary>
        private class ProcessEventRecord
        {
            public int EventId { get; set; }
            public DateTime TimeCreated { get; set; }
            public bool IsStart { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public string ImagePath { get; set; } = string.Empty;
            public string UserSid { get; set; } = string.Empty;
            public string Username { get; set; } = string.Empty;
            public int SessionId { get; set; }
        }
    }
}
