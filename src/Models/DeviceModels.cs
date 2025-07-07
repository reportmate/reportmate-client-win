#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Basic device information model
/// </summary>
public class DeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public double TotalMemoryGB { get; set; }
    public DateTime LastSeen { get; set; }
    public string ClientVersion { get; set; } = string.Empty;
    public string AssetTag { get; set; } = string.Empty;
    
    // Granular OS information
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string OsArchitecture { get; set; } = string.Empty;
    public DateTime? OsInstallDate { get; set; }
    public string ExperiencePack { get; set; } = string.Empty;
    
    // Network information
    public string IpAddressV4 { get; set; } = string.Empty;
    public string IpAddressV6 { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    
    // MDM/Management information
    public string MdmEnrollmentId { get; set; } = string.Empty;
    public string MdmEnrollmentType { get; set; } = string.Empty;
    public string MdmEnrollmentState { get; set; } = string.Empty;
    public string MdmManagementUrl { get; set; } = string.Empty;
}

/// <summary>
/// System information model
/// </summary>
public class SystemInfo
{
    public string ProcessorName { get; set; } = string.Empty;
    public int ProcessorSpeedMHz { get; set; }
    public int ProcessorCount { get; set; }
    public double TotalMemoryGB { get; set; }
    public double AvailableMemoryGB { get; set; }
    public double UsedMemoryGB { get; set; }
    public int MemoryUtilizationPercent { get; set; }
    public string TimeZone { get; set; } = string.Empty;
    public List<DiskInfo> Disks { get; set; } = new();
    
    // Additional system information
    public string OperatingSystem { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public TimeSpan Uptime { get; set; }
    public DateTime? LastBootTime { get; set; }
    public List<DiskInfo> DiskInfo { get; set; } = new();
}

/// <summary>
/// Security information model
/// </summary>
public class SecurityInfo
{
    public bool WindowsDefenderEnabled { get; set; }
    public string WindowsDefenderStatus { get; set; } = string.Empty;
    public bool UacEnabled { get; set; }
    public string UacLevel { get; set; } = string.Empty;
    public bool BitLockerEnabled { get; set; }
    public string BitLockerStatus { get; set; } = string.Empty;
    public bool TmpEnabled { get; set; }
    public string TmpStatus { get; set; } = string.Empty;
    public bool WindowsUpdateEnabled { get; set; }
    public string WindowsUpdateStatus { get; set; } = string.Empty;
    public DateTime? LastUpdateCheck { get; set; }
    
    // Additional security information
    public bool FirewallEnabled { get; set; }
    public bool TmpAvailable { get; set; }
}

/// <summary>
/// Disk information model
/// </summary>
public class DiskInfo
{
    public string DriveLetter { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string FileSystem { get; set; } = string.Empty;
    public long TotalSizeBytes { get; set; }
    public long AvailableSizeBytes { get; set; }
    public long UsedSizeBytes { get; set; }
    public int UtilizationPercent { get; set; }
    public string DriveType { get; set; } = string.Empty;
    
    // Additional disk information
    public string Drive { get; set; } = string.Empty;
    public double TotalSizeGB { get; set; }
    public double FreeSpaceGB { get; set; }
    public double UsedSpaceGB { get; set; }
    public double UsedPercentage { get; set; }
}
