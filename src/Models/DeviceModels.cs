#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Comprehensive device information model organized by dashboard sections
/// </summary>
public class DeviceInfo
{
    // Core device identification (main info tab)
    public string DeviceId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public DateTime LastSeen { get; set; }
    public string ClientVersion { get; set; } = string.Empty;
    public string AssetTag { get; set; } = string.Empty;
    public string Status { get; set; } = "online";
    public int TotalEvents { get; set; }
    public DateTime LastEventTime { get; set; }
    
    // Legacy fields for service compatibility
    public string ExperiencePack { get; set; } = string.Empty;
    public string IpAddressV4 { get; set; } = string.Empty;
    public string IpAddressV6 { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string MdmEnrollmentId { get; set; } = string.Empty;
    public string BiosVersion { get; set; } = string.Empty;
    public string TpmPresent { get; set; } = string.Empty;
    public string BitLockerStatus { get; set; } = string.Empty;
    public string DefenderEnabled { get; set; } = string.Empty;
    public string DefenderVersion { get; set; } = string.Empty;
    public string FirewallEnabled { get; set; } = string.Empty;
    public DateTime? LastBootTime { get; set; }
    public long TotalMemory { get; set; }
    public long AvailableMemory { get; set; }
    public double CpuUsage { get; set; }
    public int UptimeDays { get; set; }
    public string TimeZone { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string MdmEnrollmentState { get; set; } = string.Empty;
    public string MdmManagementUrl { get; set; } = string.Empty;
    
    // Additional legacy compatibility properties
    public string OperatingSystem { get; set; } = string.Empty;
    public double TotalMemoryGB { get; set; }
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string OsArchitecture { get; set; } = string.Empty;
    public string MdmEnrollmentType { get; set; } = string.Empty;
    public string Processor { get; set; } = string.Empty;
    public int? Cores { get; set; }
    public string Memory { get; set; } = string.Empty;
    public string AvailableRAM { get; set; } = string.Empty;
    public string Storage { get; set; } = string.Empty;
    public string AvailableStorage { get; set; } = string.Empty;
    public string StorageType { get; set; } = string.Empty;
    public string Graphics { get; set; } = string.Empty;
    public string Vram { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string Uptime { get; set; } = string.Empty;
    public string BootTime { get; set; } = string.Empty;
    public double? DiskUtilization { get; set; }
    public double? MemoryUtilization { get; set; }
    public string? BatteryLevel { get; set; }
    
    // Organized dashboard sections
    public BasicInfo Basic { get; set; } = new();
    public OperatingSystemInfo Os { get; set; } = new();
    public HardwareInfo Hardware { get; set; } = new();
    public NetworkInfo Network { get; set; } = new();
    public DeviceSecurityInfo Security { get; set; } = new();
    public MdmInfo Mdm { get; set; } = new();
    public SystemMetrics Metrics { get; set; } = new();
    public List<InstalledApplication> Applications { get; set; } = new();
    public List<RunningService> Services { get; set; } = new();
    public List<NetworkInterface> NetworkInterfaces { get; set; } = new();
    public List<StartupItem> StartupItems { get; set; } = new();
    public List<SecurityPatch> Patches { get; set; } = new();
    public List<ScheduledTask> ScheduledTasks { get; set; } = new();
    public List<ListeningPort> ListeningPorts { get; set; } = new();
    public List<LogicalDrive> LogicalDrives { get; set; } = new();
    public List<ProcessInfo> CriticalProcesses { get; set; } = new();
    public List<UserInfo> LoggedInUsers { get; set; } = new();
}

/// <summary>
/// Basic device information for main info widget
/// </summary>
public class BasicInfo
{
    public string Hostname { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string AssetTag { get; set; } = string.Empty;
    public DateTime? LastBootTime { get; set; }
    public TimeSpan? Uptime { get; set; }
    public string TimeZone { get; set; } = string.Empty;
}

/// <summary>
/// Operating system information
/// </summary>
public class OperatingSystemInfo
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Build { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public DateTime? InstallDate { get; set; }
    public string ExperiencePack { get; set; } = string.Empty;
    public string Edition { get; set; } = string.Empty;
    public string ServicePack { get; set; } = string.Empty;
}

/// <summary>
/// Hardware information for hardware widgets
/// </summary>
public class HardwareInfo
{
    public ProcessorInfo Processor { get; set; } = new();
    public MemoryInfo Memory { get; set; } = new();
    public List<DiskInfo> Storage { get; set; } = new();
    public VideoInfo Graphics { get; set; } = new();
    public string SystemBoard { get; set; } = string.Empty;
    public string BiosInfo { get; set; } = string.Empty;
}

/// <summary>
/// Processor information
/// </summary>
public class ProcessorInfo
{
    public string Name { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public int PhysicalCores { get; set; }
    public int LogicalCores { get; set; }
    public int MaxClockSpeed { get; set; }
    public int CurrentClockSpeed { get; set; }
    public string Architecture { get; set; } = string.Empty;
    public string Family { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
}

/// <summary>
/// Memory information
/// </summary>
public class MemoryInfo
{
    public long TotalMemoryBytes { get; set; }
    public long AvailableMemoryBytes { get; set; }
    public double TotalMemoryGB => TotalMemoryBytes / 1024.0 / 1024.0 / 1024.0;
    public double AvailableMemoryGB => AvailableMemoryBytes / 1024.0 / 1024.0 / 1024.0;
    public double UsedMemoryGB => TotalMemoryGB - AvailableMemoryGB;
    public double MemoryUtilizationPercent => TotalMemoryGB > 0 ? (UsedMemoryGB / TotalMemoryGB) * 100 : 0;
    public List<MemoryDevice> Devices { get; set; } = new();
}

/// <summary>
/// Memory device information
/// </summary>
public class MemoryDevice
{
    public string DeviceLocator { get; set; } = string.Empty;
    public string MemoryType { get; set; } = string.Empty;
    public long Size { get; set; }
    public string FormFactor { get; set; } = string.Empty;
    public int ConfiguredClockSpeed { get; set; }
    public string Manufacturer { get; set; } = string.Empty;
    public string PartNumber { get; set; } = string.Empty;
}

/// <summary>
/// Video/Graphics information
/// </summary>
public class VideoInfo
{
    public string Model { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string DriverVersion { get; set; } = string.Empty;
    public string DriverDate { get; set; } = string.Empty;
    public string VideoMemory { get; set; } = string.Empty;
    public string Resolution { get; set; } = string.Empty;
}

/// <summary>
/// Network information for network widgets
/// </summary>
public class NetworkInfo
{
    public string PrimaryIPv4 { get; set; } = string.Empty;
    public string PrimaryIPv6 { get; set; } = string.Empty;
    public string PrimaryMacAddress { get; set; } = string.Empty;
    public List<NetworkInterface> Interfaces { get; set; } = new();
    public List<NetworkAddress> Addresses { get; set; } = new();
    public List<WifiNetwork> WifiNetworks { get; set; } = new();
    public List<RouteEntry> Routes { get; set; } = new();
}

/// <summary>
/// Network interface information
/// </summary>
public class NetworkInterface
{
    public string Interface { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public int Mtu { get; set; }
    public string FriendlyName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string ConnectionId { get; set; } = string.Empty;
    public bool DhcpEnabled { get; set; }
    public string DhcpServer { get; set; } = string.Empty;
}

/// <summary>
/// Network address information
/// </summary>
public class NetworkAddress
{
    public string Interface { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Mask { get; set; } = string.Empty;
    public string Broadcast { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
}

/// <summary>
/// WiFi network information
/// </summary>
public class WifiNetwork
{
    public string Ssid { get; set; } = string.Empty;
    public string SecurityType { get; set; } = string.Empty;
    public int SignalStrength { get; set; }
    public string ConnectionMode { get; set; } = string.Empty;
    public string AuthenticationMode { get; set; } = string.Empty;
}

/// <summary>
/// Route entry information
/// </summary>
public class RouteEntry
{
    public string Destination { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
    public string Mask { get; set; } = string.Empty;
    public string Interface { get; set; } = string.Empty;
    public int Metric { get; set; }
    public string Type { get; set; } = string.Empty;
}

/// <summary>
/// Device security information for security widgets
/// </summary>
public class DeviceSecurityInfo
{
    public string AntivirusStatus { get; set; } = string.Empty;
    public string AntivirusProduct { get; set; } = string.Empty;
    public string AntispywareStatus { get; set; } = string.Empty;
    public string FirewallStatus { get; set; } = string.Empty;
    public string AutoUpdateStatus { get; set; } = string.Empty;
    public bool UacEnabled { get; set; }
    public string UacLevel { get; set; } = string.Empty;
    public bool SecureBootEnabled { get; set; }
    public TpmInfo Tpm { get; set; } = new();
    public List<BitLockerInfo> BitLockerDrives { get; set; } = new();
    public List<SecurityPolicy> SecurityPolicies { get; set; } = new();
    public List<DefenderInfo> DefenderStatus { get; set; } = new();
}

/// <summary>
/// TPM (Trusted Platform Module) information
/// </summary>
public class TpmInfo
{
    public bool Activated { get; set; }
    public bool Enabled { get; set; }
    public bool Owned { get; set; }
    public string ManufacturerVersion { get; set; } = string.Empty;
    public string ManufacturerId { get; set; } = string.Empty;
    public string ManufacturerName { get; set; } = string.Empty;
    public string SpecVersion { get; set; } = string.Empty;
}

/// <summary>
/// BitLocker drive encryption information
/// </summary>
public class BitLockerInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string DriveLetter { get; set; } = string.Empty;
    public string ConversionStatus { get; set; } = string.Empty;
    public string ProtectionStatus { get; set; } = string.Empty;
    public string LockStatus { get; set; } = string.Empty;
    public string EncryptionMethod { get; set; } = string.Empty;
    public double PercentEncrypted { get; set; }
}

/// <summary>
/// Security policy information
/// </summary>
public class SecurityPolicy
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Windows Defender information
/// </summary>
public class DefenderInfo
{
    public string ComponentName { get; set; } = string.Empty;
    public string ComponentVersion { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public DateTime? LastUpdate { get; set; }
    public string Status { get; set; } = string.Empty;
}

/// <summary>
/// MDM (Mobile Device Management) information
/// </summary>
public class MdmInfo
{
    public string EnrollmentId { get; set; } = string.Empty;
    public string EnrollmentType { get; set; } = string.Empty;
    public string EnrollmentState { get; set; } = string.Empty;
    public string ManagementUrl { get; set; } = string.Empty;
    public string ProviderName { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public DateTime? EnrollmentDate { get; set; }
    public DateTime? LastSyncTime { get; set; }
    public string ComplianceState { get; set; } = string.Empty;
    public List<MdmPolicy> Policies { get; set; } = new();
    public List<MdmCertificate> Certificates { get; set; } = new();
}

/// <summary>
/// MDM policy information
/// </summary>
public class MdmPolicy
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DateTime? LastModified { get; set; }
    public string Status { get; set; } = string.Empty;
}

/// <summary>
/// MDM certificate information
/// </summary>
public class MdmCertificate
{
    public string Thumbprint { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime? ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
    public string Purpose { get; set; } = string.Empty;
}

/// <summary>
/// System metrics and performance information
/// </summary>
public class SystemMetrics
{
    public double CpuUtilizationPercent { get; set; }
    public double MemoryUtilizationPercent { get; set; }
    public double DiskUtilizationPercent { get; set; }
    public TimeSpan Uptime { get; set; }
    public DateTime? LastBootTime { get; set; }
    public int ProcessCount { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public long PageFileUsage { get; set; }
    public long KernelMemoryUsage { get; set; }
    public List<PerformanceCounter> Counters { get; set; } = new();
}

/// <summary>
/// Performance counter information
/// </summary>
public class PerformanceCounter
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Instance { get; set; } = string.Empty;
    public double Value { get; set; }
    public string Unit { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Installed application information for Applications tab
/// </summary>
public class InstalledApplication
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public string UpdateDate { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string RequiredVersion { get; set; } = string.Empty;
    public string AvailableVersion { get; set; } = string.Empty;
    public bool UpdateAvailable { get; set; }
    public string InstallMethod { get; set; } = string.Empty;
    public long? SizeBytes { get; set; }
}

/// <summary>
/// Running service information for Services section
/// </summary>
public class RunningService
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string StartType { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string ServiceType { get; set; } = string.Empty;
    public string Account { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public long MemoryUsage { get; set; }
}

/// <summary>
/// Startup item information
/// </summary>
public class StartupItem
{
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

/// <summary>
/// Security patch information
/// </summary>
public class SecurityPatch
{
    public string ComputerName { get; set; } = string.Empty;
    public string HotfixId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string InstalledOn { get; set; } = string.Empty;
    public string InstalledBy { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public long? SizeBytes { get; set; }
    public string Severity { get; set; } = string.Empty;
}

/// <summary>
/// Scheduled task information
/// </summary>
public class ScheduledTask
{
    public string Name { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string State { get; set; } = string.Empty;
    public string LastRunTime { get; set; } = string.Empty;
    public string NextRunTime { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Triggers { get; set; } = string.Empty;
}

/// <summary>
/// Listening port information for Network Security tab
/// </summary>
public class ListeningPort
{
    public int ProcessId { get; set; }
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Family { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
}

/// <summary>
/// Logical drive information
/// </summary>
public class LogicalDrive
{
    public string DeviceId { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public long Size { get; set; }
    public long FreeSpace { get; set; }
    public string FileSystem { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public double UsedSpacePercent => Size > 0 ? ((Size - FreeSpace) / (double)Size) * 100 : 0;
    public bool Compressed { get; set; }
    public bool Encrypted { get; set; }
}

/// <summary>
/// Process information
/// </summary>
public class ProcessInfo
{
    public int ProcessId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public int Threads { get; set; }
    public long WorkingSetSize { get; set; }
    public long VirtualSize { get; set; }
    public double CpuPercent { get; set; }
    public string Username { get; set; } = string.Empty;
    public DateTime? StartTime { get; set; }
}

/// <summary>
/// User information
/// </summary>
public class UserInfo
{
    public string Username { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Time { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string SessionType { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
}

/// <summary>
/// Disk information from osquery
/// </summary>
public class DiskInfo
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public long DiskSize { get; set; }
    public string HardwareModel { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string Interface { get; set; } = string.Empty;
    public int SectorSize { get; set; }
    public string Health { get; set; } = string.Empty;
    public double Temperature { get; set; }
    public long PowerOnHours { get; set; }
}

/// <summary>
/// Managed install information for Managed Installs tab
/// </summary>
public class ManagedInstall
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public string UpdateDate { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string RequiredVersion { get; set; } = string.Empty;
    public string AvailableVersion { get; set; } = string.Empty;
    public bool UpdateAvailable { get; set; }
    public string InstallMethod { get; set; } = string.Empty;
    public long? SizeBytes { get; set; }
}

/// <summary>
/// Event information for Events tab
/// </summary>
public class EventInfo
{
    public string Id { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Level { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string User { get; set; } = string.Empty;
    public string Computer { get; set; } = string.Empty;
    public Dictionary<string, object> Details { get; set; } = new();
}

/// <summary>
/// File system information
/// </summary>
public class FileSystemInfo
{
    public string Path { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public long Size { get; set; }
    public DateTime? ModifiedTime { get; set; }
    public DateTime? AccessedTime { get; set; }
    public DateTime? CreatedTime { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public string Owner { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
}

/// <summary>
/// System information model extracted from osquery
/// </summary>
public class SystemInfo
{
    public string Hostname { get; set; } = string.Empty;
    public string CpuBrand { get; set; } = string.Empty;
    public int CpuPhysicalCores { get; set; }
    public int CpuLogicalCores { get; set; }
    public long PhysicalMemory { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string LocalHostname { get; set; } = string.Empty;
    public TimeSpan Uptime { get; set; }
    public DateTime? BootTime { get; set; }
    public string PlatformLike { get; set; } = string.Empty;
}

/// <summary>
/// Complete raw osquery results for backend processing
/// </summary>
public class OsQueryResults
{
    public Dictionary<string, List<Dictionary<string, object>>> Tables { get; set; } = new();
    public DateTime CollectionTime { get; set; }
    public string ClientVersion { get; set; } = string.Empty;
    public int TotalQueries { get; set; }
    public int SuccessfulQueries { get; set; }
    public int FailedQueries { get; set; }
    public List<string> Errors { get; set; } = new();
}


