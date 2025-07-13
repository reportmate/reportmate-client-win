#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ReportMate.WindowsClient.Models
{
    /// <summary>
    /// Base class for all module data structures
    /// </summary>
    public abstract class BaseModuleData
    {
        public string ModuleId { get; set; } = string.Empty;
        public string Version { get; set; } = "1.0.0";
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
        public string DeviceId { get; set; } = string.Empty;
    }

    /// <summary>
    /// Unified payload structure containing all module data
    /// </summary>
    public class UnifiedDevicePayload
    {
        public string DeviceId { get; set; } = string.Empty;
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
        public string ClientVersion { get; set; } = string.Empty;
        public string Platform { get; set; } = "Windows";
        
        // Module data sections
        public ApplicationsData? Applications { get; set; }
        public HardwareData? Hardware { get; set; }
        public InventoryData? Inventory { get; set; }
        public InstallsData? Installs { get; set; }
        public ManagementData? Management { get; set; }
        public NetworkData? Network { get; set; }
        public ProfilesData? Profiles { get; set; }
        public SecurityData? Security { get; set; }
        public SystemData? System { get; set; }

        // Metadata
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    // ===== MODULE DATA STRUCTURES =====

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

    /// <summary>
    /// Hardware module data - Physical device information
    /// </summary>
    public class HardwareData : BaseModuleData
    {
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public ProcessorInfo Processor { get; set; } = new();
        public MemoryInfo Memory { get; set; } = new();
        public List<StorageDevice> Storage { get; set; } = new();
        public GraphicsInfo Graphics { get; set; } = new();
        public List<UsbDevice> UsbDevices { get; set; } = new();
        public BatteryInfo? Battery { get; set; }
        public ThermalInfo? Thermal { get; set; }
    }

    public class ProcessorInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public int Cores { get; set; }
        public int LogicalProcessors { get; set; }
        public string Architecture { get; set; } = string.Empty;
        public double BaseSpeed { get; set; } // GHz
        public double MaxSpeed { get; set; } // GHz
        public string Socket { get; set; } = string.Empty;
    }

    public class MemoryInfo
    {
        public long TotalPhysical { get; set; } // bytes
        public long AvailablePhysical { get; set; } // bytes
        public long TotalVirtual { get; set; } // bytes
        public long AvailableVirtual { get; set; } // bytes
        public List<MemoryModule> Modules { get; set; } = new();
    }

    public class MemoryModule
    {
        public string Manufacturer { get; set; } = string.Empty;
        public long Capacity { get; set; } // bytes
        public string Type { get; set; } = string.Empty; // DDR4, DDR5, etc.
        public int Speed { get; set; } // MHz
        public string Location { get; set; } = string.Empty;
    }

    public class StorageDevice
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // SSD, HDD, NVMe
        public long Capacity { get; set; } // bytes
        public long FreeSpace { get; set; } // bytes
        public string Interface { get; set; } = string.Empty; // SATA, PCIe, etc.
        public string Health { get; set; } = string.Empty;
    }

    public class GraphicsInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public long MemorySize { get; set; } // bytes
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
    }

    public class UsbDevice
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string VendorId { get; set; } = string.Empty;
        public string ProductId { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
    }

    public class BatteryInfo
    {
        public int ChargePercent { get; set; }
        public bool IsCharging { get; set; }
        public TimeSpan? EstimatedRuntime { get; set; }
        public int CycleCount { get; set; }
        public string Health { get; set; } = string.Empty;
    }

    public class ThermalInfo
    {
        public double CpuTemperature { get; set; }
        public double GpuTemperature { get; set; }
        public List<FanInfo> Fans { get; set; } = new();
    }

    public class FanInfo
    {
        public string Name { get; set; } = string.Empty;
        public int Speed { get; set; } // RPM
        public int MaxSpeed { get; set; } // RPM
    }

    /// <summary>
    /// Inventory module data - Device identification and assets
    /// </summary>
    public class InventoryData : BaseModuleData
    {
        public string DeviceName { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string AssetTag { get; set; } = string.Empty;
        public string UUID { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string Owner { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public DateTime? PurchaseDate { get; set; }
        public DateTime? WarrantyExpiration { get; set; }
        
        // Additional fields from external inventory source
        public string Catalog { get; set; } = string.Empty;    // From Inventory.yaml catalog field
        public string Usage { get; set; } = string.Empty;      // From Inventory.yaml usage field
    }

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

    /// <summary>
    /// Management module data - Mobile device management
    /// </summary>
    public class ManagementData : BaseModuleData
    {
        public MdmEnrollmentInfo MdmEnrollment { get; set; } = new();
        public List<MdmProfile> Profiles { get; set; } = new();
        public List<CompliancePolicy> CompliancePolicies { get; set; } = new();
        public string OwnershipType { get; set; } = string.Empty; // Corporate, Personal, etc.
        public DateTime? LastSync { get; set; }
    }

    public class MdmEnrollmentInfo
    {
        public bool IsEnrolled { get; set; }
        public string Provider { get; set; } = string.Empty; // Intune, JAMF, etc.
        public string EnrollmentId { get; set; } = string.Empty;
        public DateTime? EnrollmentDate { get; set; }
        public string ManagementUrl { get; set; } = string.Empty;
        public string UserPrincipalName { get; set; } = string.Empty;
    }

    public class MdmProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class CompliancePolicy
    {
        public string Name { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // Compliant, NonCompliant, etc.
        public DateTime? LastEvaluated { get; set; }
        public List<string> Violations { get; set; } = new();
    }

    /// <summary>
    /// Network module data - Connectivity and configuration
    /// </summary>
    public class NetworkData : BaseModuleData
    {
        public List<NetworkInterface> Interfaces { get; set; } = new();
        public List<WifiNetwork> WifiNetworks { get; set; } = new();
        public DnsConfiguration Dns { get; set; } = new();
        public List<NetworkRoute> Routes { get; set; } = new();
        public List<ListeningPort> ListeningPorts { get; set; } = new();
        public string PrimaryInterface { get; set; } = string.Empty;
    }

    public class NetworkInterface
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // Ethernet, WiFi, etc.
        public string MacAddress { get; set; } = string.Empty;
        public List<string> IpAddresses { get; set; } = new();
        public string Status { get; set; } = string.Empty;
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int Mtu { get; set; }
    }

    public class WifiNetwork
    {
        public string Ssid { get; set; } = string.Empty;
        public string Security { get; set; } = string.Empty;
        public int SignalStrength { get; set; }
        public bool IsConnected { get; set; }
        public string Channel { get; set; } = string.Empty;
    }

    public class DnsConfiguration
    {
        public List<string> Servers { get; set; } = new();
        public string Domain { get; set; } = string.Empty;
        public List<string> SearchDomains { get; set; } = new();
    }

    public class NetworkRoute
    {
        public string Destination { get; set; } = string.Empty;
        public string Gateway { get; set; } = string.Empty;
        public string Interface { get; set; } = string.Empty;
        public int Metric { get; set; }
    }

    public class ListeningPort
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty; // TCP, UDP
        public string Process { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
    }

    /// <summary>
    /// Profiles module data - Policy and configuration management
    /// </summary>
    public class ProfilesData : BaseModuleData
    {
        public List<ConfigurationProfile> ConfigurationProfiles { get; set; } = new();
        public List<GroupPolicyObject> GroupPolicies { get; set; } = new();
        public List<RegistryPolicy> RegistryPolicies { get; set; } = new();
        public DateTime? LastPolicyUpdate { get; set; }
    }

    public class ConfigurationProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // MDM, Group Policy, etc.
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty;
        public Dictionary<string, object> Settings { get; set; } = new();
    }

    public class GroupPolicyObject
    {
        public string Name { get; set; } = string.Empty;
        public string Guid { get; set; } = string.Empty;
        public DateTime? LastApplied { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> Settings { get; set; } = new();
    }

    public class RegistryPolicy
    {
        public string KeyPath { get; set; } = string.Empty;
        public string ValueName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
    }

    /// <summary>
    /// Security module data - Protection and compliance
    /// </summary>
    public class SecurityData : BaseModuleData
    {
        public AntivirusInfo Antivirus { get; set; } = new();
        public FirewallInfo Firewall { get; set; } = new();
        public EncryptionInfo Encryption { get; set; } = new();
        public TpmInfo Tpm { get; set; } = new();
        public List<SecurityUpdate> SecurityUpdates { get; set; } = new();
        public List<SecurityEvent> SecurityEvents { get; set; } = new();
        public DateTime? LastSecurityScan { get; set; }
    }

    public class AntivirusInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public bool IsUpToDate { get; set; }
        public DateTime? LastUpdate { get; set; }
        public DateTime? LastScan { get; set; }
        public string ScanType { get; set; } = string.Empty;
    }

    public class FirewallInfo
    {
        public bool IsEnabled { get; set; }
        public string Profile { get; set; } = string.Empty; // Domain, Private, Public
        public List<FirewallRule> Rules { get; set; } = new();
    }

    public class FirewallRule
    {
        public string Name { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public string Direction { get; set; } = string.Empty; // Inbound, Outbound
        public string Action { get; set; } = string.Empty; // Allow, Block
        public string Protocol { get; set; } = string.Empty;
        public string Port { get; set; } = string.Empty;
    }

    public class EncryptionInfo
    {
        public BitLockerInfo BitLocker { get; set; } = new();
        public bool DeviceEncryption { get; set; }
        public List<EncryptedVolume> EncryptedVolumes { get; set; } = new();
    }

    public class BitLockerInfo
    {
        public bool IsEnabled { get; set; }
        public string Status { get; set; } = string.Empty;
        public string RecoveryKeyId { get; set; } = string.Empty;
        public List<string> EncryptedDrives { get; set; } = new();
    }

    public class EncryptedVolume
    {
        public string DriveLetter { get; set; } = string.Empty;
        public string EncryptionMethod { get; set; } = string.Empty;
        public double EncryptionPercentage { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class TpmInfo
    {
        public bool IsPresent { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsActivated { get; set; }
        public string Version { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
    }

    public class SecurityUpdate
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public DateTime? ReleaseDate { get; set; }
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty; // Installed, Pending, Failed
    }

    public class SecurityEvent
    {
        public int EventId { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty; // Information, Warning, Error
        public DateTime Timestamp { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// System module data - Operating system information
    /// </summary>
    public class SystemData : BaseModuleData
    {
        public OperatingSystemInfo OperatingSystem { get; set; } = new();
        public List<SystemUpdate> Updates { get; set; } = new();
        public List<SystemService> Services { get; set; } = new();
        public List<EnvironmentVariable> Environment { get; set; } = new();
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
        public string ServicePack { get; set; } = string.Empty;
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
}
