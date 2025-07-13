#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Device information model for legacy compatibility.
/// This class is maintained for compatibility with legacy services but new development
/// should use the modular data models in ModularDataModels.cs
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
    public long TotalMemory { get; set; }
    public long AvailableMemory { get; set; }
    public double CpuUsage { get; set; }
    public int UptimeDays { get; set; }
    public string TimeZone { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string MdmEnrollmentState { get; set; } = string.Empty;
    public string MdmManagementUrl { get; set; } = string.Empty;
    public string MdmEnrollmentId { get; set; } = string.Empty;
    
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
}

/// <summary>
/// Service interface for collecting device information
/// </summary>
public interface IDeviceInfoService
{
    Task<DeviceInfo> GetBasicDeviceInfoAsync();
    Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync();
}

/// <summary>
/// Legacy system information structure for compatibility
/// </summary>
public class SystemInfo
{
    public string ComputerName { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string UUID { get; set; } = string.Empty;
    public long CPUBrand { get; set; }
    public long CPUPhysicalCores { get; set; }
    public long CPULogicalCores { get; set; }
    public long CPUType { get; set; }
    public string CPUSubtype { get; set; } = string.Empty;
    public long CPUMicrocode { get; set; }
    public long PhysicalMemory { get; set; }
    public long HardwareVendor { get; set; }
    public string HardwareModel { get; set; } = string.Empty;
    public string HardwareVersion { get; set; } = string.Empty;
    public string HardwareSerial { get; set; } = string.Empty;
    public string BoardVendor { get; set; } = string.Empty;
    public string BoardModel { get; set; } = string.Empty;
    public string BoardVersion { get; set; } = string.Empty;
    public string BoardSerial { get; set; } = string.Empty;
}

/// <summary>
/// Legacy device security information structure for compatibility
/// </summary>
public class DeviceSecurityInfo
{
    public string SecureBootEnabled { get; set; } = string.Empty;
    public string TPMReady { get; set; } = string.Empty;
    public string TPMVersion { get; set; } = string.Empty;
    public string BitLockerStatus { get; set; } = string.Empty;
    public string DefenderEnabled { get; set; } = string.Empty;
    public string FirewallEnabled { get; set; } = string.Empty;
    public List<string> SecurityPolicies { get; set; } = new();
}

/// <summary>
/// Legacy disk information structure for compatibility
/// </summary>
public class DiskInfo
{
    public string Device { get; set; } = string.Empty;
    public string DiskIndex { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string ID { get; set; } = string.Empty;
    public string PNPDeviceID { get; set; } = string.Empty;
    public long DiskSize { get; set; }
    public string Manufacturer { get; set; } = string.Empty;
    public string HardwareModel { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Serial { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}