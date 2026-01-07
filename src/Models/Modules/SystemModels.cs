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
        
        [JsonPropertyOrder(16)]
        public ActivationInfo? Activation { get; set; }
    }

    public class ActivationInfo
    {
        /// <summary>
        /// Whether Windows is activated (Licensed)
        /// </summary>
        public bool IsActivated { get; set; }
        
        /// <summary>
        /// License status: Licensed, Unlicensed, OOBGrace, OOTGrace, NonGenuineGrace, Notification, ExtendedGrace
        /// </summary>
        public string Status { get; set; } = string.Empty;
        
        /// <summary>
        /// License status code: 0=Unlicensed, 1=Licensed, 2=OOBGrace, 3=OOTGrace, 4=NonGenuineGrace, 5=Notification, 6=ExtendedGrace
        /// </summary>
        public int StatusCode { get; set; }
        
        /// <summary>
        /// Partial product key (last 5 characters)
        /// </summary>
        public string? PartialProductKey { get; set; }
        
        /// <summary>
        /// License type/edition name from SoftwareLicensingProduct
        /// </summary>
        public string? LicenseType { get; set; }
        
        /// <summary>
        /// Whether the device has a firmware-embedded (UEFI/BIOS OA3) Windows license key
        /// that is usable for domain/Entra ID joined devices (Pro, Enterprise, Education).
        /// Windows Home firmware licenses don't count as they can't join domains.
        /// Devices with Pro/Enterprise firmware licenses retain activation when migrating from AD to Entra ID.
        /// Devices without usable firmware licenses may lose activation when unbound from on-prem AD/KMS.
        /// </summary>
        public bool HasFirmwareLicense { get; set; }
        
        /// <summary>
        /// The Windows edition embedded in firmware (OA3xOriginalProductKeyDescription).
        /// Examples: "Professional OEM:DM", "Core OEM:DM" (Core = Home), "Enterprise OEM:DM"
        /// This indicates what license the device can fall back to if KMS/MAK activation fails.
        /// </summary>
        public string? FirmwareEdition { get; set; }
        
        /// <summary>
        /// License source: Firmware (OA3/UEFI embedded), KMS (Key Management Service), 
        /// MAK (Multiple Activation Key), Retail, Volume, or Unknown
        /// </summary>
        public string? LicenseSource { get; set; }
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
