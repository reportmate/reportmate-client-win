#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Usage;

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

        // Upper bound on how far back a single collection will read the event log.
        // This is a cap, not the window itself -- the window normally starts at the
        // watermark left by the previous collection (see ResolveWindowStart). The cap
        // stops a device that has been offline for days from trying to parse an
        // enormous Security Log span in one pass.
        private const int DefaultLookbackHours = 4;

        // Watermark marking the end of the last successfully collected usage window.
        // Sessions are attributed by process-creation time, and the server accumulates
        // whatever it receives (ON CONFLICT ... total_seconds = total_seconds + EXCLUDED),
        // so any window that overlaps a previous one is counted twice. A fixed
        // now-minus-4h lookback only produced disjoint windows when this module was
        // called on exactly the 4-hourly schedule; the all-modules task calls it too,
        // and re-collected the overlap every run. Anchoring the window to the previous
        // window's end makes collections disjoint at any cadence and from any caller.
        private static readonly string UsageWindowWatermarkFile =
            Path.Combine(TrackerStateDir, "_last_window_end.txt");
        
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
        /// <param name="lookbackHours">Maximum hours to look back; the window normally starts at the previous window's end</param>
        /// <returns>Usage snapshot with per-application and per-user statistics</returns>
        public async Task<ApplicationUsageSnapshot> CollectUsageDataAsync(
            List<InstalledApplication> installedApps,
            int lookbackHours = DefaultLookbackHours)
        {
            var windowEnd = DateTime.UtcNow;
            var windowStart = ResolveWindowStart(windowEnd, lookbackHours);

            var snapshot = new ApplicationUsageSnapshot
            {
                GeneratedAt = windowEnd,
                WindowStart = windowStart,
                WindowEnd = windowEnd
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
                var shutdownTimes = await GetShutdownEventsAsync(windowStart);

                // Collect process start and stop events from the available source
                var processEvents = await CollectProcessEventsAsync(windowStart);

                if (processEvents.Count == 0)
                {
                    snapshot.Status = "no_data";
                    snapshot.Warnings.Add($"No process events found between {windowStart:o} and {windowEnd:o}");
                    // An empty window is still a collected window -- advance the
                    // watermark so the next run does not re-scan this span.
                    SaveWindowWatermark(windowEnd);
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
                // Include ALL sessions (complete + active) so the API can aggregate fleet-wide usage.
                // Previously only active (still-running) sessions were included, causing empty data.
                snapshot.ActiveSessions = sessions;
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
                        .FirstOrDefault(s => UsageAppNameResolver.MatchesApplication(s.Path, app));
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
                        .FirstOrDefault(s => UsageAppNameResolver.MatchesApplication(s.Path, app));
                    if (matchingSummary != null)
                    {
                        app.Usage = matchingSummary;
                        assignedSummaries.Add(matchingSummary);
                    }
                }

                _logger.LogInformation(
                    "Usage collection complete: {SessionCount} sessions, {ActiveCount} active, {TotalHours:F1}h total usage, window {Start:o} to {End:o}",
                    sessions.Count,
                    snapshot.ActiveSessions.Count,
                    snapshot.TotalUsageSeconds / 3600,
                    windowStart,
                    windowEnd);

                // Advance the watermark only once the window has been collected
                // successfully. Persisting at collection time rather than after
                // transmission matches what the usagetracker delta path already does
                // (see MergeUserSessionTrackerData): a failed transmission loses this
                // window rather than replaying it. Given the server accumulates
                // unconditionally, losing a window is far cheaper than double-counting
                // one, and the API-side fix for that is tracked as [tracked internally].
                SaveWindowWatermark(windowEnd);

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
        /// Resolve the start of this collection's window: the end of the previously
        /// collected window, clamped so a single pass never reads more than
        /// <paramref name="maxLookbackHours"/> of event log.
        /// </summary>
        private DateTime ResolveWindowStart(DateTime windowEnd, int maxLookbackHours)
        {
            var earliest = windowEnd.AddHours(-maxLookbackHours);
            var watermark = LoadWindowWatermark();

            if (watermark is null)
            {
                _logger.LogDebug("No usage window watermark; starting at the {Hours}h cap", maxLookbackHours);
                return earliest;
            }

            // A watermark ahead of now means the clock moved backwards (time sync,
            // VM restore). Fall back to the cap rather than producing an empty or
            // inverted window.
            if (watermark.Value > windowEnd)
            {
                _logger.LogWarning(
                    "Usage window watermark {Watermark:o} is in the future relative to {Now:o}; ignoring it",
                    watermark.Value, windowEnd);
                return earliest;
            }

            if (watermark.Value < earliest)
            {
                _logger.LogInformation(
                    "Usage window watermark {Watermark:o} is older than the {Hours}h cap; collecting from {Start:o} and accepting the gap",
                    watermark.Value, maxLookbackHours, earliest);
                return earliest;
            }

            return watermark.Value;
        }

        private DateTime? LoadWindowWatermark()
        {
            try
            {
                if (!File.Exists(UsageWindowWatermarkFile)) return null;

                var raw = File.ReadAllText(UsageWindowWatermarkFile).Trim();

                // AdjustToUniversal normalises whatever offset the file carries;
                // AssumeUniversal covers a value written without one. RoundtripKind
                // must not be combined with either -- TryParse throws ArgumentException
                // on that pairing rather than returning false, which silently sent every
                // read down the catch below and made the watermark write-only.
                if (DateTime.TryParse(
                        raw,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
                        out var parsed))
                {
                    return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
                }

                _logger.LogWarning("Unparseable usage window watermark '{Raw}'; treating as absent", raw);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to read usage window watermark ({Message}); treating as absent", ex.Message);
                return null;
            }
        }

        private void SaveWindowWatermark(DateTime windowEnd)
        {
            try
            {
                Directory.CreateDirectory(TrackerStateDir);
                var tmp = UsageWindowWatermarkFile + ".tmp";
                File.WriteAllText(tmp, windowEnd.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture));
                if (File.Exists(UsageWindowWatermarkFile))
                    File.Replace(tmp, UsageWindowWatermarkFile, destinationBackupFileName: null);
                else
                    File.Move(tmp, UsageWindowWatermarkFile);
            }
            catch (Exception ex)
            {
                // Non-fatal: the next collection falls back to the lookback cap, which
                // overlaps this window. That is the old behaviour, not a regression.
                _logger.LogWarning("Failed to persist usage window watermark: {Message}", ex.Message);
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
        private Task<List<DateTime>> GetShutdownEventsAsync(DateTime startTime)
        {
            return Task.Run(() =>
            {
                var shutdownTimes = new List<DateTime>();

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
        private Task<List<ProcessEventRecord>> CollectProcessEventsAsync(DateTime startTime)
        {
            return _activeEventSource switch
            {
                EventSource.SecurityLog => CollectSecurityLogEventsAsync(startTime),
                EventSource.KernelLog => CollectKernelLogEventsAsync(startTime),
                _ => Task.FromResult(new List<ProcessEventRecord>())
            };
        }

        /// <summary>
        /// Collect process events from Security Log (Event 4688/4689).
        /// </summary>
        private Task<List<ProcessEventRecord>> CollectSecurityLogEventsAsync(DateTime startTime)
        {
            return Task.Run(() =>
            {
                var events = new List<ProcessEventRecord>();

                _logger.LogDebug("Security log query: Looking for events since {StartTime:o} (UTC)", startTime);

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
        private Task<List<ProcessEventRecord>> CollectKernelLogEventsAsync(DateTime startTime)
        {
            return Task.Run(() =>
            {
                var events = new List<ProcessEventRecord>();

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
                "microsoftedgeupdate.exe", "googleupdate.exe",  // Skip browser UPDATE processes only
                "lockapp.exe", "logonui.exe"  // Lock screen / logon UI: idle time, not usage
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
                    var matchedApp = UsageAppNameResolver.ResolveInstalledApp(session.Path, installedApps);
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
                var matchedApp = UsageAppNameResolver.ResolveInstalledApp(firstSession.Path, installedApps);

                var summary = new ApplicationUsageSummary
                {
                    Name = matchedApp?.Name ?? firstSession.Name,
                    Executable = System.IO.Path.GetFileName(firstSession.Path),
                    Path = firstSession.Path,
                    Publisher = matchedApp?.Publisher ?? string.Empty,
                    FirstSeen = firstSession.StartTime,
                    LastUsed = lastSession.StartTime,
                    LastExitTime = appSessions.Where(s => s.EndTime.HasValue)
                        .OrderByDescending(s => s.EndTime)
                        .FirstOrDefault()?.EndTime,
                    LaunchCount = appSessions.Count,
                    TotalSeconds = appSessions.Sum(s => s.DurationSeconds),
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

            return summaries.OrderByDescending(s => s.TotalSeconds).ToList();
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
        /// Build daily per-application usage summaries from matched sessions.
        /// Groups sessions by (date, app name) and produces cumulative totals.
        /// The API uses UPSERT semantics so last collection of the day wins.
        /// </summary>
        // ─────────────────────────────────────────────────────────────────
        // User-session foreground/active time merge
        //
        // managedreportsrunner.exe runs as SYSTEM in session 0, where
        // GetForegroundWindow / GetLastInputInfo can't observe the user's
        // input or focus. The companion usagetracker.exe runs in each user's
        // session via a logon-triggered scheduled task and persists
        // cumulative {foregroundSeconds, activeSeconds} per (exe-path, date)
        // to %ProgramData%\ManagedReports\usagetracker\{username}.json.
        //
        // MergeUserSessionTrackerData reads those files, computes the delta
        // since the last collection (max(0, current - last) — handles
        // tracker process restarts), matches exe paths to InstalledApplication
        // names, and augments the DailyUsageSummary list with the new fields.
        // The server then accumulates the deltas per (device, date, app).
        // ─────────────────────────────────────────────────────────────────

        private const string TrackerStateDir = @"C:\ProgramData\ManagedReports\usagetracker";
        private const string TrackerLastTransmittedFile = "_last_transmitted.json";

        // Lock-screen / logon pseudo-apps. Time while these hold focus is idle
        // time, not application usage. The tracker itself no longer attributes
        // ticks to them (see usagetracker/Program.cs, LockScreenExecutables),
        // but state files written by older trackers still carry accumulated
        // counters, so they are filtered again here at merge time — by exe
        // filename before delta computation, and by resolved app name (the
        // Appx inventory maps LockApp.exe to "Microsoft.LockApp") before
        // summaries are emitted. Keep the two sets in sync.
        private static readonly HashSet<string> LockScreenExecutables = new(StringComparer.OrdinalIgnoreCase)
        {
            "LockApp.exe",
            "LogonUI.exe",
        };

        private static readonly HashSet<string> LockScreenAppNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "LockApp",
            "Microsoft.LockApp",
            "LogonUI",
        };

        public List<DailyUsageSummary> MergeUserSessionTrackerData(
            List<DailyUsageSummary> summaries,
            List<InstalledApplication> installedApps)
        {
            try
            {
                if (!Directory.Exists(TrackerStateDir))
                {
                    _logger.LogDebug("UsageTracker directory not present; skipping foreground/active merge");
                    return summaries;
                }

                // 1. Read all per-user tracker files; sum cumulative across users.
                //    Key: (exePath, date) -> (fgSec, activeSec)
                var cumulative = new Dictionary<(string ExePath, string Date), (double Fg, double Active)>(
                    new ExePathDateComparer());

                foreach (var path in Directory.EnumerateFiles(TrackerStateDir, "*.json"))
                {
                    var fname = Path.GetFileName(path);
                    if (fname.StartsWith("_")) continue; // skip internal state files

                    try
                    {
                        var json = File.ReadAllText(path);
                        var state = JsonSerializer.Deserialize(json, TrackerStateJsonContext.Default.TrackerStateMirror);
                        if (state?.ByAppByDate == null) continue;

                        foreach (var (exePath, byDate) in state.ByAppByDate)
                        {
                            if (LockScreenExecutables.Contains(Path.GetFileName(exePath)))
                                continue;

                            foreach (var (dateKey, counters) in byDate)
                            {
                                var key = (exePath, dateKey);
                                cumulative.TryGetValue(key, out var existing);
                                cumulative[key] = (
                                    existing.Fg + counters.ForegroundSeconds,
                                    existing.Active + counters.ActiveSeconds);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Failed to parse usagetracker file {Path}: {Message}", path, ex.Message);
                    }
                }

                if (cumulative.Count == 0)
                {
                    _logger.LogDebug("UsageTracker files present but contained no entries");
                    return summaries;
                }

                // 2. Read last-transmitted state.
                var lastPath = Path.Combine(TrackerStateDir, TrackerLastTransmittedFile);
                var last = new Dictionary<string, AppDayCountersMirror>(StringComparer.Ordinal);
                if (File.Exists(lastPath))
                {
                    try
                    {
                        var lastJson = File.ReadAllText(lastPath);
                        last = JsonSerializer.Deserialize(lastJson, TrackerStateJsonContext.Default.LastTransmittedMap)
                               ?? last;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Failed to parse last-transmitted state ({Message}); treating as empty", ex.Message);
                    }
                }

                // 3. Compute deltas; build new last-transmitted state.
                var deltas = new Dictionary<(string ExePath, string Date), (double Fg, double Active)>(
                    new ExePathDateComparer());
                var nextLast = new Dictionary<string, AppDayCountersMirror>(StringComparer.Ordinal);

                foreach (var (key, current) in cumulative)
                {
                    var lookup = $"{key.ExePath}||{key.Date}";
                    last.TryGetValue(lookup, out var prev);
                    var prevFg = prev?.ForegroundSeconds ?? 0;
                    var prevActive = prev?.ActiveSeconds ?? 0;

                    var deltaFg = Math.Max(0, current.Fg - prevFg);
                    var deltaActive = Math.Max(0, current.Active - prevActive);
                    if (deltaFg > 0 || deltaActive > 0)
                        deltas[key] = (deltaFg, deltaActive);

                    nextLast[lookup] = new AppDayCountersMirror
                    {
                        ForegroundSeconds = current.Fg,
                        ActiveSeconds = current.Active,
                    };
                }

                // 4. Persist updated last-transmitted state atomically.
                try
                {
                    var tmp = lastPath + ".tmp";
                    File.WriteAllText(tmp, JsonSerializer.Serialize(nextLast, TrackerStateJsonContext.Default.LastTransmittedMap));
                    if (File.Exists(lastPath))
                        File.Replace(tmp, lastPath, destinationBackupFileName: null);
                    else
                        File.Move(tmp, lastPath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to persist last-transmitted state: {Message}", ex.Message);
                    // Continue anyway — we still emit deltas this round; next round
                    // will see cumulative again and emit it as a delta (slight double-count).
                }

                if (deltas.Count == 0)
                {
                    _logger.LogDebug("UsageTracker: no foreground/active delta since last collection");
                    return summaries;
                }

                // 5. Match exe paths to app names; aggregate by (date, app_name).
                var byDateApp = new Dictionary<(string Date, string AppName), (double Fg, double Active)>(
                    new DateAppNameComparer());

                foreach (var ((exePath, date), (fg, active)) in deltas)
                {
                    var appName = UsageAppNameResolver.ResolveTrackerAppName(exePath, installedApps);
                    if (string.IsNullOrEmpty(appName)) continue;
                    if (LockScreenAppNames.Contains(appName)) continue;

                    var key = (date, appName);
                    byDateApp.TryGetValue(key, out var existing);
                    byDateApp[key] = (existing.Fg + fg, existing.Active + active);
                }

                // 6. Augment passed summaries; append entries that don't have a
                //    Security-Log-derived match.
                var summaryIndex = summaries
                    .GroupBy(s => (s.Date, s.AppName), new DateAppNameComparer())
                    .ToDictionary(g => g.Key, g => g.First(), new DateAppNameComparer());

                int augmented = 0, appended = 0;
                foreach (var (key, (fg, active)) in byDateApp)
                {
                    if (summaryIndex.TryGetValue(key, out var existing))
                    {
                        existing.ForegroundSeconds += fg;
                        existing.ActiveSeconds += active;
                        augmented++;
                    }
                    else
                    {
                        // Tracker has activity for an app the Security Log path
                        // didn't pick up (e.g. process started outside the 4h
                        // lookback). Emit a new summary; use foreground as the
                        // approximation of total_seconds since we have no
                        // session data.
                        summaries.Add(new DailyUsageSummary
                        {
                            Date = key.Date,
                            AppName = key.AppName,
                            Publisher = "",
                            Launches = 0,
                            TotalSeconds = fg,
                            ForegroundSeconds = fg,
                            ActiveSeconds = active,
                            Users = new List<string>(),
                        });
                        appended++;
                    }
                }

                _logger.LogInformation(
                    "UsageTracker merge: {Augmented} summaries augmented, {Appended} new summaries from tracker-only apps",
                    augmented, appended);

                return summaries;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MergeUserSessionTrackerData failed; returning summaries unchanged");
                return summaries;
            }
        }

        internal sealed class TrackerStateMirror
        {
            [JsonPropertyName("ByAppByDate")]
            public Dictionary<string, Dictionary<string, AppDayCountersMirror>>? ByAppByDate { get; set; }
        }

        internal sealed class AppDayCountersMirror
        {
            [JsonPropertyName("ForegroundSeconds")]
            public double ForegroundSeconds { get; set; }
            [JsonPropertyName("ActiveSeconds")]
            public double ActiveSeconds { get; set; }
        }

        private sealed class ExePathDateComparer : IEqualityComparer<(string ExePath, string Date)>
        {
            public bool Equals((string ExePath, string Date) a, (string ExePath, string Date) b) =>
                StringComparer.OrdinalIgnoreCase.Equals(a.ExePath, b.ExePath) &&
                StringComparer.Ordinal.Equals(a.Date, b.Date);
            public int GetHashCode((string ExePath, string Date) k) =>
                HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(k.ExePath ?? ""),
                                 StringComparer.Ordinal.GetHashCode(k.Date ?? ""));
        }

        private sealed class DateAppNameComparer : IEqualityComparer<(string Date, string AppName)>
        {
            public bool Equals((string Date, string AppName) a, (string Date, string AppName) b) =>
                StringComparer.Ordinal.Equals(a.Date, b.Date) &&
                StringComparer.OrdinalIgnoreCase.Equals(a.AppName, b.AppName);
            public int GetHashCode((string Date, string AppName) k) =>
                HashCode.Combine(StringComparer.Ordinal.GetHashCode(k.Date ?? ""),
                                 StringComparer.OrdinalIgnoreCase.GetHashCode(k.AppName ?? ""));
        }

        public List<DailyUsageSummary> BuildDailySummaries(List<ApplicationUsageSession> sessions)
        {
            if (sessions.Count == 0)
                return new List<DailyUsageSummary>();

            var summaries = sessions
                .GroupBy(s => new { Date = s.StartTime.ToString("yyyy-MM-dd"), s.Name })
                .Where(g => !string.IsNullOrEmpty(g.Key.Name))
                .Select(g =>
                {
                    var users = g
                        .Select(s => s.User)
                        .Where(u => !string.IsNullOrEmpty(u) && u != "UNKNOWN")
                        .Distinct()
                        .ToList();

                    return new DailyUsageSummary
                    {
                        Date = g.Key.Date,
                        AppName = g.Key.Name,
                        Publisher = g.First().Publisher,
                        Launches = g.Count(),
                        TotalSeconds = g.Sum(s => s.DurationSeconds),
                        // Foreground/active counters stay at 0 until the
                        // user-context usagetracker.exe companion is shipped
                        // and feeds session-level fg/active deltas into the
                        // ApplicationUsageSession objects this method consumes.
                        ForegroundSeconds = g.Sum(s => s.ForegroundSeconds),
                        ActiveSeconds = g.Sum(s => s.ActiveSeconds),
                        Users = users
                    };
                })
                .OrderBy(s => s.Date)
                .ThenByDescending(s => s.TotalSeconds)
                .ToList();

            _logger.LogInformation("Built {Count} daily usage summaries across {Days} day(s)",
                summaries.Count, summaries.Select(s => s.Date).Distinct().Count());

            return summaries;
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

    /// <summary>
    /// Source-generated JSON context for the usagetracker state mirror types.
    /// Reflection-based deserialization (Newtonsoft) is stripped by PublishTrimmed,
    /// which silently dropped every tracker file and zeroed foreground/active
    /// fleet-wide. Source generation is trim-safe. Case-insensitive matching reads
    /// both the tracker's PascalCase output and any legacy camelCase
    /// _last_transmitted.json written before this change.
    /// </summary>
    [JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true, WriteIndented = false)]
    [JsonSerializable(typeof(ApplicationUsageService.TrackerStateMirror))]
    [JsonSerializable(typeof(Dictionary<string, ApplicationUsageService.AppDayCountersMirror>),
        TypeInfoPropertyName = "LastTransmittedMap")]
    internal partial class TrackerStateJsonContext : JsonSerializerContext
    {
    }
}
