#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Installs module data - Managed software systems
    /// </summary>
    public class InstallsData : BaseModuleData
    {
        public CimianInfo? Cimian { get; set; }
        public MunkiInfo? Munki { get; set; }
        public List<ManagedInstall> PendingInstalls { get; set; } = new();
        public List<ManagedInstall> RecentInstalls { get; set; } = new();
        public DateTime? LastCheckIn { get; set; }
    }

    public class CimianInfo
    {
        public bool IsInstalled { get; set; }
        public string Version { get; set; } = string.Empty;
        public DateTime? LastRun { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> PendingPackages { get; set; } = new();
        public List<string> Logs { get; set; } = new();
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
    }
}
