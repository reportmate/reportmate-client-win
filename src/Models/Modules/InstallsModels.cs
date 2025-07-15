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
        public string Status { get; set; } = string.Empty;
        public List<string> PendingPackages { get; set; } = new();
        public List<string> Services { get; set; } = new();
        public List<string> ActiveProcesses { get; set; } = new();
        public Dictionary<string, string> RegistryConfig { get; set; } = new();
        public bool BootstrapFlagPresent { get; set; }
        public DateTime? LastSessionTime { get; set; }
        public int TotalSessions { get; set; }
        public Dictionary<string, CimianReportFileInfo> Reports { get; set; } = new();
    }

    public class CimianReportFileInfo
    {
        public string Size { get; set; } = string.Empty;
        public string Mtime { get; set; } = string.Empty;
    }

    public class CimianSession
    {
        public string SessionId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string RunType { get; set; } = string.Empty; // auto, manual, bootstrap, ondemand
        public string Status { get; set; } = string.Empty; // running, completed, failed, interrupted
        public int TotalActions { get; set; }
        public int Installs { get; set; }
        public int Updates { get; set; }
        public int Removals { get; set; }
        public int Successes { get; set; }
        public int Failures { get; set; }
        public TimeSpan Duration { get; set; }
        public int DurationSeconds { get; set; }
        public string Hostname { get; set; } = string.Empty;
        public string User { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string LogVersion { get; set; } = string.Empty;
        public List<string> PackagesHandled { get; set; } = new();
        public Dictionary<string, object> Environment { get; set; } = new();
    }

    public class CimianEvent
    {
        public string EventId { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Level { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // install, remove, update, status_check, error
        public string Package { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // started, progress, completed, failed
        public string Message { get; set; } = string.Empty;
        public TimeSpan? Duration { get; set; }
        public int? Progress { get; set; } // 0-100 or -1 for indeterminate
        public string Error { get; set; } = string.Empty;
        public Dictionary<string, object> Context { get; set; } = new();
        public string SourceFile { get; set; } = string.Empty;
        public string SourceFunction { get; set; } = string.Empty;
        public int SourceLine { get; set; }
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
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public DateTime? ScheduledTime { get; set; }
        public string Source { get; set; } = string.Empty;
        public string InstallLocation { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public bool HasInstallLoop { get; set; }
        public int InstallCount { get; set; }
        public int FailureCount { get; set; }
    }
}
