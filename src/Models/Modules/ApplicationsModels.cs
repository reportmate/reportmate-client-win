#nullable enable
using System;
using System.Collections.Generic;
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
}
