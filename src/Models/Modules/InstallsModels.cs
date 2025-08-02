#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Installs module data - Managed software systems with enhanced Cimian integration
    /// </summary>
    public class InstallsData : BaseModuleData
    {
        public CimianInfo? Cimian { get; set; }
        public MunkiInfo? Munki { get; set; }
        public List<ManagedInstall> PendingInstalls { get; set; } = new();
        public List<ManagedInstall> RecentInstalls { get; set; } = new();
        public List<CimianSession> RecentSessions { get; set; } = new();
        public List<CimianEvent> RecentEvents { get; set; } = new();
        public DateTime? LastCheckIn { get; set; }
        public bool BootstrapModeActive { get; set; }
        public Dictionary<string, object> CacheStatus { get; set; } = new();
    }

    public class CimianInfo
    {
        public bool IsInstalled { get; set; }
        public string Version { get; set; } = string.Empty;
        public DateTime? LastRun { get; set; }
        public string Status { get; set; } = string.Empty; // Active, Inactive, Error
        public List<string> PendingPackages { get; set; } = new();
        public List<string> Services { get; set; } = new();
        public List<string> ActiveProcesses { get; set; } = new();
        public Dictionary<string, string> RegistryConfig { get; set; } = new();
        public Dictionary<string, object> Config { get; set; } = new(); // Primary config.yaml data
        public bool BootstrapFlagPresent { get; set; }
        public DateTime? LastSessionTime { get; set; }
        public int TotalSessions { get; set; }
        public Dictionary<string, CimianReportFileInfo> Reports { get; set; } = new();
        
        // Enhanced Cimian reporting data
        public List<CimianItem> Items { get; set; } = new();
        public List<CimianSession> Sessions { get; set; } = new();
        public List<CimianEvent> Events { get; set; } = new();
    }

    public class CimianReportFileInfo
    {
        public string Size { get; set; } = string.Empty;
        public string Mtime { get; set; } = string.Empty;
    }

    public class CimianItem
    {
        public string Id { get; set; } = string.Empty;
        public string ItemName { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string ItemType { get; set; } = string.Empty;
        public string CurrentStatus { get; set; } = string.Empty;
        public string LatestVersion { get; set; } = string.Empty;
        public string InstalledVersion { get; set; } = string.Empty;
        public string LastSeenInSession { get; set; } = string.Empty;
        public DateTime? LastSuccessfulTime { get; set; }
        public DateTime? LastAttemptTime { get; set; }
        public string LastAttemptStatus { get; set; } = string.Empty;
        public DateTime? LastUpdate { get; set; }
        public int InstallCount { get; set; }
        public int UpdateCount { get; set; }
        public int FailureCount { get; set; }
        public int TotalSessions { get; set; }
        public bool InstallLoopDetected { get; set; }
        public string InstallMethod { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public List<Dictionary<string, object>> RecentAttempts { get; set; } = new();
    }

    public class CimianSession
    {
        public string SessionId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string RunType { get; set; } = string.Empty; // auto, manual, bootstrap, ondemand
        public string Status { get; set; } = string.Empty; // running, completed, failed, interrupted
        public int TotalActions { get; set; }
        public int TotalPackagesManaged { get; set; }
        public int PackagesInstalled { get; set; }
        public int PackagesPending { get; set; }
        public int PackagesFailed { get; set; }
        public int Installs { get; set; }
        public int Updates { get; set; }
        public int Removals { get; set; }
        public int Successes { get; set; }
        public int Failures { get; set; }
        public TimeSpan Duration { get; set; }
        public int DurationSeconds { get; set; }
        public double CacheSizeMb { get; set; }
        public string Hostname { get; set; } = string.Empty;
        public string User { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string LogVersion { get; set; } = string.Empty;
        public List<string> PackagesHandled { get; set; } = new();
        public Dictionary<string, object> Environment { get; set; } = new();
        public Dictionary<string, object> Config { get; set; } = new(); // Session-specific config
        
        // Enhanced session data from sessions.json
        public Dictionary<string, object> Summary { get; set; } = new(); // totalPackagesManaged, packagesInstalled, etc
        
        // Enhanced logging improvements data
        public Dictionary<string, object> SystemInfo { get; set; } = new(); // System context from enhanced logging
        public Dictionary<string, bool> Flags { get; set; } = new(); // Command flags and options
        public List<BatchOperation> BatchOperations { get; set; } = new(); // Batch install/uninstall operations
        public Dictionary<string, object> PerformanceMetrics { get; set; } = new(); // Timing and performance data
        public List<string> FailedItems { get; set; } = new(); // Failed package names for troubleshooting
        public Dictionary<string, List<string>> BlockingApplications { get; set; } = new(); // Package -> blocking apps mapping
    }

    public class BatchOperation
    {
        public string OperationType { get; set; } = string.Empty; // install, uninstall, update
        public string BatchId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan? Duration { get; set; }
        public int TotalItems { get; set; }
        public int SuccessfulItems { get; set; }
        public int FailedItems { get; set; }
        public List<string> SuccessfulPackages { get; set; } = new();
        public List<string> FailedPackages { get; set; } = new();
        public Dictionary<string, object> Context { get; set; } = new(); // Additional context data
    }

    public class CimianEvent
    {
        public string EventId { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Level { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // install, remove, update, status_check, error, general
        public string Package { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // Success, Failed, Warning, started, progress, completed
        public string Message { get; set; } = string.Empty;
        public TimeSpan? Duration { get; set; }
        public int? Progress { get; set; } // 0-100 or -1 for indeterminate
        public string Error { get; set; } = string.Empty;
        public Dictionary<string, object> Context { get; set; } = new();
        public string SourceFile { get; set; } = string.Empty;
        public string SourceFunction { get; set; } = string.Empty;
        public int SourceLine { get; set; }
        public string LogFile { get; set; } = string.Empty;
        
        // Enhanced logging improvements data
        public string BatchId { get; set; } = string.Empty; // Link to batch operations
        public string InstallerType { get; set; } = string.Empty; // MSI, NUPKG, EXE, etc.
        public string InstallerPath { get; set; } = string.Empty;
        public string InstallerOutput { get; set; } = string.Empty; // Capture installer stdout/stderr
        public Dictionary<string, object> SystemContext { get; set; } = new(); // System state during event
        public List<string> RelatedPackages { get; set; } = new(); // Dependencies or related packages
        public Dictionary<string, string> PerformanceCounters { get; set; } = new(); // CPU, memory, disk usage
        public bool CheckOnlyMode { get; set; } // Whether this was a check-only operation
    }

    public class MunkiInfo
    {
        public bool IsInstalled { get; set; }
        public string Version { get; set; } = string.Empty;
        public DateTime? LastRun { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> PendingPackages { get; set; } = new();
        public List<string> Logs { get; set; } = new();
    }

    public class ManagedInstall
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string ItemType { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string InstalledVersion { get; set; } = string.Empty;
        public string LastSeenInSession { get; set; } = string.Empty;
        public DateTime? LastSuccessfulTime { get; set; }
        public DateTime? LastAttemptTime { get; set; }
        public string LastAttemptStatus { get; set; } = string.Empty;
        public DateTime? LastUpdate { get; set; }
        public DateTime? ScheduledTime { get; set; }
        public string Source { get; set; } = string.Empty;
        public string InstallLocation { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public bool HasInstallLoop { get; set; }
        public int InstallCount { get; set; }
        public int UpdateCount { get; set; }
        public int FailureCount { get; set; }
        public int TotalSessions { get; set; }
        public string InstallMethod { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public List<Dictionary<string, object>> RecentAttempts { get; set; } = new();
    }
}
