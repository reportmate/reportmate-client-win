#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Installs module data - Managed software systems with enhanced Cimian integration
    /// </summary>
    public class InstallsData : BaseModuleData
    {
        public CimianInfo? Cimian { get; set; }
        public DateTime? LastCheckIn { get; set; }
        public bool BootstrapModeActive { get; set; }
        public Dictionary<string, object> CacheStatus { get; set; } = new();
        
        /// <summary>
        /// Session-specific snapshot data for this collection run
        /// Contains processed Cimian data for the current session
        /// </summary>
        public Dictionary<string, object>? CimianSnapshot { get; set; }
        
        /// <summary>
        /// Enhanced Cimian session statistics for event generation
        /// Based on sessions.json from Cimian technical specification
        /// </summary>
        public CimianSessionData? CimianSessionStats { get; set; }
        
        /// <summary>
        /// Full verbose run log from the last Cimian execution
        /// </summary>
        public string? RunLog { get; set; }
    }

    /// <summary>
    /// Cimian session data from sessions.json according to technical specification
    /// </summary>
    public class CimianSessionData
    {
        public string SessionId { get; set; } = string.Empty;
        public string StartTime { get; set; } = string.Empty;
        public string EndTime { get; set; } = string.Empty;
        public int DurationSeconds { get; set; }
        public string Hostname { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string ManifestPath { get; set; } = string.Empty;
        
        // Package Statistics
        public int TotalManagedPackages { get; set; }
        public int PackagesProcessed { get; set; }
        public int SuccessfulInstalls { get; set; }
        public int SuccessfulUpdates { get; set; }
        public int FailedOperations { get; set; }
        public int WarningsGenerated { get; set; }
        public int ErrorsEncountered { get; set; }
        public int InstallLoopsDetected { get; set; }
        public int ArchitectureMismatches { get; set; }
        
        // System Context
        public string SystemArchitecture { get; set; } = string.Empty;
        public string CimianVersion { get; set; } = string.Empty;
        public string ExecutionMode { get; set; } = string.Empty;
        public bool PreflightSkipped { get; set; }
        public string ManifestValidationStatus { get; set; } = string.Empty;
        public bool CatalogRefreshRequired { get; set; }
        public int ConditionalItemsEvaluated { get; set; }
        public int ConditionalItemsMatched { get; set; }
        
        // System Health Metrics
        public string NetworkConnectivityStatus { get; set; } = string.Empty;
        public double DiskSpaceAvailableGb { get; set; }
        public double MemoryUsagePeakMb { get; set; }
        
        // Exit Information
        public int ExitCode { get; set; }
        public string ExitReason { get; set; } = string.Empty;
    }

    /// <summary>
    /// Cimian package item from items.json according to technical specification
    /// </summary>
    public class CimianPackageItem
    {
        public string Id { get; set; } = string.Empty;
        public string ItemName { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string CurrentStatus { get; set; } = string.Empty;
        
        // Metrics
        public int InstallCount { get; set; }
        public int UpdateCount { get; set; }
        public int FailureCount { get; set; }
        public int WarningCount { get; set; }
        
        // Error and Warning Context
        public string LastError { get; set; } = string.Empty;
        public string LastWarning { get; set; } = string.Empty;
        public string LastInstallDate { get; set; } = string.Empty;
        public string LastUpdateDate { get; set; } = string.Empty;
        
        // Package Information
        public string Version { get; set; } = string.Empty;
        public List<string> SupportedArchitectures { get; set; } = new();
        public bool InstallLoopDetected { get; set; }
        public CimianLoopDetails? LoopDetails { get; set; }
        
        // Recent Activity
        public List<CimianPackageAttempt> RecentAttempts { get; set; } = new();
        public string LastAttemptTime { get; set; } = string.Empty;
        public string LastAttemptStatus { get; set; } = string.Empty;
        
        // Technical Details
        public string InstallMethod { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public double SizeMb { get; set; }
        public string DownloadUrl { get; set; } = string.Empty;
        public string CatalogSource { get; set; } = string.Empty;
        public List<string> Dependencies { get; set; } = new();
        public List<string> Conflicts { get; set; } = new();
        public CimianSystemRequirements? SystemRequirements { get; set; }
    }

    /// <summary>
    /// Cimian install loop detection details
    /// </summary>
    public class CimianLoopDetails
    {
        public string DetectionCriteria { get; set; } = string.Empty;
        public string LoopStartSession { get; set; } = string.Empty;
        public string SuspectedCause { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Cimian package attempt record
    /// </summary>
    public class CimianPackageAttempt
    {
        public string SessionId { get; set; } = string.Empty;
        public string Timestamp { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
    }

    /// <summary>
    /// Cimian system requirements
    /// </summary>
    public class CimianSystemRequirements
    {
        public int MinimumRamGb { get; set; }
        public int MinimumDiskGb { get; set; }
        public List<string> SupportedOs { get; set; } = new();
    }

    /// <summary>
    /// Cimian event data from events.jsonl according to technical specification
    /// </summary>
    public class CimianEventData
    {
        public string Timestamp { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public string? Hostname { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? PackageName { get; set; }
        public string? Version { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, object>? Details { get; set; }
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
        public string CurrentStatus { get; set; } = string.Empty;  // Original Cimian status (Error, Install Loop, Not Available, etc.)
        public string MappedStatus { get; set; } = string.Empty;    // Simplified status for filtering (Failed, Pending, Warning, Installed, Unknown)
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
        public int WarningCount { get; set; }
        public int TotalSessions { get; set; }
        public bool InstallLoopDetected { get; set; }
        public bool HasInstallLoop { get; set; }
        public string LastError { get; set; } = string.Empty;
        public string LastWarning { get; set; } = string.Empty;
        public string PendingReason { get; set; } = string.Empty;  // Why the package is pending (e.g., "Update available", "Not yet installed", "Skipped")
        public string InstallMethod { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public List<Dictionary<string, object>> RecentAttempts { get; set; } = new();
    }

    public class CimianSession
    {
        [JsonPropertyName("session_id")]
        public string SessionId { get; set; } = string.Empty;
        
        [JsonPropertyName("start_time")]
        public DateTime StartTime { get; set; }
        
        [JsonPropertyName("end_time")]
        public DateTime? EndTime { get; set; }
        
        [JsonPropertyName("run_type")]
        public string RunType { get; set; } = string.Empty; // auto, manual, bootstrap, ondemand
        
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty; // running, completed, failed, interrupted
        
        [JsonPropertyName("total_actions")]
        public int TotalActions { get; set; }
        
        [JsonPropertyName("total_packages_managed")]
        public int TotalPackagesManaged { get; set; }
        
        [JsonPropertyName("packages_installed")]
        public int PackagesInstalled { get; set; }
        
        [JsonPropertyName("packages_pending")]
        public int PackagesPending { get; set; }
        
        [JsonPropertyName("packages_failed")]
        public int PackagesFailed { get; set; }
        
        [JsonPropertyName("installs")]
        public int Installs { get; set; }
        
        [JsonPropertyName("updates")]
        public int Updates { get; set; }
        
        [JsonPropertyName("removals")]
        public int Removals { get; set; }
        
        [JsonPropertyName("successes")]
        public int Successes { get; set; }
        
        [JsonPropertyName("failures")]
        public int Failures { get; set; }
        
        public TimeSpan Duration { get; set; }
        
        [JsonPropertyName("duration_seconds")]
        public int DurationSeconds { get; set; }
        
        [JsonPropertyName("cache_size_mb")]
        public double CacheSizeMb { get; set; }
        
        [JsonPropertyName("hostname")]
        public string Hostname { get; set; } = string.Empty;
        
        [JsonPropertyName("user")]
        public string User { get; set; } = string.Empty;
        
        [JsonPropertyName("process_id")]
        public int ProcessId { get; set; }
        
        [JsonPropertyName("log_version")]
        public string LogVersion { get; set; } = string.Empty;
        
        [JsonPropertyName("packages_handled")]
        public List<string> PackagesHandled { get; set; } = new();
        
        [JsonPropertyName("environment")]
        public Dictionary<string, object> Environment { get; set; } = new();
        
        [JsonPropertyName("config")]
        public Dictionary<string, object> Config { get; set; } = new(); // Session-specific config
        
        // Enhanced session data from sessions.json
        [JsonPropertyName("summary")]
        public Dictionary<string, object> Summary { get; set; } = new(); // totalPackagesManaged, packagesInstalled, etc
        
        // Enhanced logging improvements data
        [JsonPropertyName("system_info")]
        public Dictionary<string, object> SystemInfo { get; set; } = new(); // System context from enhanced logging
        
        [JsonPropertyName("flags")]
        public Dictionary<string, bool> Flags { get; set; } = new(); // Command flags and options
        
        [JsonPropertyName("batch_operations")]
        public List<BatchOperation> BatchOperations { get; set; } = new(); // Batch install/uninstall operations
        
        [JsonPropertyName("performance_metrics")]
        public Dictionary<string, object> PerformanceMetrics { get; set; } = new(); // Timing and performance data
        
        [JsonPropertyName("failed_items")]
        public List<string> FailedItems { get; set; } = new(); // Failed package names for troubleshooting
        
        [JsonPropertyName("blocking_applications")]
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
