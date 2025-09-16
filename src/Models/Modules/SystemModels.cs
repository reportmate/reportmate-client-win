#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// System module data - Operating system information
    /// </summary>
    public class SystemData : BaseModuleData
    {
        public OperatingSystemInfo OperatingSystem { get; set; } = new();
        public List<SystemUpdate> Updates { get; set; } = new();
        public List<SystemService> Services { get; set; } = new();
        public List<EnvironmentVariable> Environment { get; set; } = new();
        public List<ScheduledTask> ScheduledTasks { get; set; } = new();
        public DateTime? LastBootTime { get; set; }
        public TimeSpan? Uptime { get; set; }
        public string UptimeString { get; set; } = string.Empty;
    }

    public class OperatingSystemInfo
    {
        [JsonPropertyOrder(1)]
        public string Name { get; set; } = string.Empty;
        
        [JsonPropertyOrder(2)]
        public string Architecture { get; set; } = string.Empty;
        
        [JsonPropertyOrder(3)]
        public string DisplayVersion { get; set; } = string.Empty; // e.g., "24H2"
        
        [JsonPropertyOrder(4)]
        public string Version { get; set; } = string.Empty;
        
        [JsonPropertyOrder(5)]
        public string Build { get; set; } = string.Empty;
        
        [JsonPropertyOrder(6)]
        public int Major { get; set; }
        
        [JsonPropertyOrder(7)]
        public int Minor { get; set; }
        
        [JsonPropertyOrder(8)]
        public int Patch { get; set; }
        
        [JsonPropertyOrder(9)]
        public DateTime? InstallDate { get; set; }
        
        [JsonPropertyOrder(10)]
        public string Locale { get; set; } = string.Empty;
        
        [JsonPropertyOrder(11)]
        public string TimeZone { get; set; } = string.Empty;
        
        [JsonPropertyOrder(12)]
        public string Edition { get; set; } = string.Empty;
        
        [JsonPropertyOrder(13)]
        public string FeatureUpdate { get; set; } = string.Empty;
        
        [JsonPropertyOrder(14)]
        public List<string> KeyboardLayouts { get; set; } = new();
        
        [JsonPropertyOrder(15)]
        public string ActiveKeyboardLayout { get; set; } = string.Empty;
    }

    public class SystemUpdate
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public DateTime? ReleaseDate { get; set; }
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty;
        public bool RequiresRestart { get; set; }
    }

    public class SystemService
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // Running, Stopped, etc.
        public string StartType { get; set; } = string.Empty; // Automatic, Manual, Disabled
        public string Path { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    public class EnvironmentVariable
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty; // System, User
    }

    public class SystemPerformance
    {
        public double CpuUsage { get; set; }
        public double MemoryUsage { get; set; }
        public double DiskUsage { get; set; }
        public double NetworkUsage { get; set; }
        public int ProcessCount { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
    }

    public class ScheduledTask
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public string Action { get; set; } = string.Empty;
        public bool Hidden { get; set; }
        public string State { get; set; } = string.Empty;
        public DateTime? LastRunTime { get; set; }
        public DateTime? NextRunTime { get; set; }
        public string LastRunCode { get; set; } = string.Empty;
        public string LastRunMessage { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }
}
