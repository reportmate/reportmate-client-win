#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Applications module data - Software inventory and management
    /// </summary>
    public class ApplicationsData : BaseModuleData
    {
        public List<InstalledApplication> InstalledApplications { get; set; } = new();
        public List<RunningProcess> RunningProcesses { get; set; } = new();
        public List<StartupProgram> StartupPrograms { get; set; } = new();
        public int TotalApplications { get; set; }
        public DateTime LastInventoryUpdate { get; set; }
        public ApplicationUsageSnapshot Usage { get; set; } = ApplicationUsageSnapshot.CreateUnavailable();
    public int ApplicationsWithUsage => InstalledApplications.Count(app => app.Usage is not null);
    }

    public class InstalledApplication
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public string InstallLocation { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public long? Size { get; set; }
        public string Architecture { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // Microsoft Store, MSI, etc.
        public ApplicationUsageSummary? Usage { get; set; }
    }

    public class RunningProcess
    {
        public string Name { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string Path { get; set; } = string.Empty;
        public long MemoryUsage { get; set; }
        public double CpuPercent { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class StartupProgram
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty; // Registry, Startup folder, etc.
        public bool Enabled { get; set; }
    }

    public class ApplicationUsageSnapshot
    {
        private const string DefaultUnavailableMessage = "Application usage tracking is not initialized";

        public bool IsCaptureEnabled { get; set; }
        public string Status { get; set; } = "uninitialized";
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public DateTime WindowStart { get; set; } = DateTime.UtcNow;
        public DateTime WindowEnd { get; set; } = DateTime.UtcNow;
        public long TotalLaunches { get; set; }
        public double TotalUsageSeconds { get; set; }
        [JsonIgnore]
        public List<ApplicationUsageSummary> Applications { get; set; } = new();
        public List<ApplicationUsageSession> ActiveSessions { get; set; } = new();
        public List<string> Warnings { get; set; } = new();

        public static ApplicationUsageSnapshot CreateUnavailable(string? message = null)
        {
            var snapshot = new ApplicationUsageSnapshot
            {
                IsCaptureEnabled = false,
                Status = "unavailable",
                GeneratedAt = DateTime.UtcNow,
                WindowStart = DateTime.UtcNow,
                WindowEnd = DateTime.UtcNow,
            };

            if (!string.IsNullOrWhiteSpace(message))
            {
                snapshot.Warnings.Add(message);
            }
            else
            {
                snapshot.Warnings.Add(DefaultUnavailableMessage);
            }

            return snapshot;
        }
    }

    public class ApplicationUsageSummary
    {
        public string Name { get; set; } = string.Empty;
        public string Executable { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public DateTime? FirstSeen { get; set; }
        public DateTime? LastLaunchTime { get; set; }
        public DateTime? LastExitTime { get; set; }
        public long LaunchCount { get; set; }
        public double TotalUsageSeconds { get; set; }
        public double ActiveUsageSeconds { get; set; }
        public double AverageSessionSeconds { get; set; }
        public int ActiveSessionCount { get; set; }
        public int UniqueUserCount { get; set; }
        public List<string> Users { get; set; } = new();
        public List<ApplicationUsageSession> RecentSessions { get; set; } = new();
    }

    public class ApplicationUsageSession
    {
        public string SessionId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string User { get; set; } = string.Empty;
        public string UserSid { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public double DurationSeconds { get; set; }
        public bool IsActive { get; set; }
    }
}
