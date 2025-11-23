#nullable enable
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.DataProcessing;

namespace ReportMate.WindowsClient.Models;

/// <summary>
/// JSON serialization context for NativeAOT compatibility
/// This enables source-generated JSON serialization instead of reflection
/// Only includes types that are actually serialized by the application
/// </summary>
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, List<Dictionary<string, object>>>))]
[JsonSerializable(typeof(List<Dictionary<string, object>>))]
[JsonSerializable(typeof(List<object>))]
[JsonSerializable(typeof(object))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(double))]
[JsonSerializable(typeof(float))]
[JsonSerializable(typeof(decimal))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(System.Text.Json.JsonElement))]
[JsonSerializable(typeof(System.Text.Json.JsonDocument))]
[JsonSerializable(typeof(DeviceRegistrationRequest))]
[JsonSerializable(typeof(DeviceEventRequest))]
[JsonSerializable(typeof(StructuredEventRequest))]
[JsonSerializable(typeof(DeviceDataRequest))]
[JsonSerializable(typeof(DeviceDataPayload))]
// Note: DeviceInfo is from Services namespace (legacy compatibility)
[JsonSerializable(typeof(Services.DeviceInfo))]
// Data processing types (legacy)
[JsonSerializable(typeof(DataProcessing.ProcessedDeviceData))]
[JsonSerializable(typeof(DataProcessing.BasicDeviceInfo))]
[JsonSerializable(typeof(DataProcessing.OperatingSystemInfo), TypeInfoPropertyName = "LegacyOperatingSystemInfo")]
[JsonSerializable(typeof(DataProcessing.HardwareInfo), TypeInfoPropertyName = "LegacyHardwareInfo")]
[JsonSerializable(typeof(DataProcessing.NetworkInfo), TypeInfoPropertyName = "LegacyNetworkInfo")]
[JsonSerializable(typeof(DataProcessing.SecurityInfo))]
[JsonSerializable(typeof(DataProcessing.ManagementInfo))]
[JsonSerializable(typeof(DataProcessing.ApplicationInfo), TypeInfoPropertyName = "LegacyApplicationInfo")]
[JsonSerializable(typeof(List<DataProcessing.ApplicationInfo>), TypeInfoPropertyName = "LegacyApplicationInfoList")]
// Modular data types (new architecture)
// Module data classes
[JsonSerializable(typeof(BaseModuleData))]
[JsonSerializable(typeof(EventMetadata))]
[JsonSerializable(typeof(UnifiedDevicePayload))]
[JsonSerializable(typeof(ApplicationsData))]
[JsonSerializable(typeof(ApplicationUsageSnapshot))]
[JsonSerializable(typeof(ApplicationUsageSummary))]
[JsonSerializable(typeof(ApplicationUsageSession))]
[JsonSerializable(typeof(List<ApplicationUsageSummary>), TypeInfoPropertyName = "ApplicationUsageSummaryList")]
[JsonSerializable(typeof(List<ApplicationUsageSession>), TypeInfoPropertyName = "ApplicationUsageSessionList")]
[JsonSerializable(typeof(HardwareData), TypeInfoPropertyName = "ModularHardwareData")]
[JsonSerializable(typeof(InventoryData))]
[JsonSerializable(typeof(InstallsData))]
[JsonSerializable(typeof(CimianReportFileInfo))]
// Cimian Technical Specification v1.0 models
[JsonSerializable(typeof(Modules.CimianSessionData))]
[JsonSerializable(typeof(Modules.CimianPackageItem))]
[JsonSerializable(typeof(Modules.CimianEventData))]
[JsonSerializable(typeof(List<Modules.CimianPackageItem>))]
[JsonSerializable(typeof(List<Modules.CimianEventData>))]
[JsonSerializable(typeof(ManagementData), TypeInfoPropertyName = "ModularManagementData")]
[JsonSerializable(typeof(NetworkData), TypeInfoPropertyName = "ModularNetworkData")]
[JsonSerializable(typeof(PeripheralsModuleData))]
[JsonSerializable(typeof(PrinterData))]
[JsonSerializable(typeof(ProfilesData))]
[JsonSerializable(typeof(SecurityData), TypeInfoPropertyName = "ModularSecurityData")]
[JsonSerializable(typeof(SystemData))]
// Individual modular model types (to resolve conflicts)
[JsonSerializable(typeof(Modules.ProcessorInfo), TypeInfoPropertyName = "ModularProcessorInfo")]
[JsonSerializable(typeof(Modules.MemoryInfo), TypeInfoPropertyName = "ModularMemoryInfo")]
[JsonSerializable(typeof(Modules.OperatingSystemInfo), TypeInfoPropertyName = "ModularOperatingSystemInfo")]
[JsonSerializable(typeof(Modules.InstalledApplication), TypeInfoPropertyName = "ModularInstalledApplication")]
[JsonSerializable(typeof(Modules.NetworkInterface), TypeInfoPropertyName = "ModularNetworkInterface")]
[JsonSerializable(typeof(Modules.WifiNetwork), TypeInfoPropertyName = "ModularWifiNetwork")]
[JsonSerializable(typeof(Modules.ActiveConnectionInfo), TypeInfoPropertyName = "ModularActiveConnectionInfo")]

[JsonSerializable(typeof(Modules.BitLockerInfo), TypeInfoPropertyName = "ModularBitLockerInfo")]
[JsonSerializable(typeof(List<Modules.InstalledApplication>), TypeInfoPropertyName = "ModularInstalledApplicationList")]
[JsonSerializable(typeof(List<Modules.NetworkInterface>), TypeInfoPropertyName = "ModularNetworkInterfaceList")]
[JsonSerializable(typeof(List<Modules.WifiNetwork>), TypeInfoPropertyName = "ModularWifiNetworkList")]
// Modular osquery types
[JsonSerializable(typeof(Services.EnabledModulesConfig))]
[JsonSerializable(typeof(Services.OsQueryModule))]
// Profile module policy collection result
[JsonSerializable(typeof(Modules.PolicyCollectionResult[]), TypeInfoPropertyName = "PolicyCollectionResultArray")]
// Analytics types for performance data
[JsonSerializable(typeof(Modules.PerformanceAnalytics))]
[JsonSerializable(typeof(Modules.BatchOperationsAnalytics))]
[JsonSerializable(typeof(Modules.BlockingApplicationInfo))]
[JsonSerializable(typeof(Modules.PerformanceTrends))]
[JsonSerializable(typeof(Modules.EventAnalytics))]
[JsonSerializable(typeof(Modules.PackageAnalytics))]
[JsonSerializable(typeof(Modules.CacheStatusAnalytics))]
[JsonSerializable(typeof(Dictionary<string, Modules.BlockingApplicationInfo>))]
[JsonSerializable(typeof(Dictionary<string, Modules.PackageAnalytics>))]
[JsonSerializable(typeof(Dictionary<string, int>))]
// Storage Management types for hardware module
[JsonSerializable(typeof(Modules.StorageDevice))]
[JsonSerializable(typeof(Modules.DirectoryInformation))]
[JsonSerializable(typeof(Modules.FileInformation))]
[JsonSerializable(typeof(List<Modules.StorageDevice>))]
[JsonSerializable(typeof(List<Modules.DirectoryInformation>))]
[JsonSerializable(typeof(List<Modules.FileInformation>))]
[JsonSerializable(typeof(Modules.DirectoryCategory))]
// Anonymous types used in data transmission
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(object))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    AllowTrailingCommas = true,
    // Enable reflection-based fallback for anonymous types while maintaining AOT compatibility
    UseStringEnumConverter = true
)]
public partial class ReportMateJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Device registration request model
/// </summary>
public class DeviceRegistrationRequest
{
    public string? DeviceId { get; set; }
    public string? Name { get; set; }
    public string? Model { get; set; }
    public string? SerialNumber { get; set; }
    public string? OS { get; set; }
    public string? Architecture { get; set; }
    public string? IpAddress { get; set; }
    public string? IpAddressV4 { get; set; }
    public string? IpAddressV6 { get; set; }
    public string? MacAddress { get; set; }
    public string? Location { get; set; }
    public Dictionary<string, object>? DeviceData { get; set; }
    public Dictionary<string, object>? SystemInfo { get; set; }
    public Dictionary<string, object>? SecurityInfo { get; set; }
    public Dictionary<string, List<Dictionary<string, object>>>? OsQueryData { get; set; }
    public Dictionary<string, object>? ClientInfo { get; set; }
}

/// <summary>
/// Device event request model
/// </summary>
public class DeviceEventRequest
{
    public string? DeviceId { get; set; }
    public string? EventType { get; set; }
    public string? Timestamp { get; set; }
    public Dictionary<string, object>? Payload { get; set; }
    public string? Severity { get; set; }
    public string? Message { get; set; }
}

/// <summary>
/// Structured event request for sending event.json data to /api/events
/// </summary>
public class StructuredEventRequest
{
    public required string Device { get; set; }
    public required string Kind { get; set; }
    public required string Ts { get; set; }
    public required Dictionary<string, object> Payload { get; set; }
}

/// <summary>
/// Device data API request payload
/// </summary>
public class DeviceDataRequest
{
    public string Device { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Kind { get; set; } = "Info";
    public string Ts { get; set; } = string.Empty;
    public DeviceDataPayload Payload { get; set; } = new();
    public string? Passphrase { get; set; }
}

/// <summary>
/// Device data payload structure
/// </summary>
public class DeviceDataPayload
{
    public Dictionary<string, object> Device { get; set; } = new();
    public Dictionary<string, object>? System { get; set; }
    public Dictionary<string, object>? Security { get; set; }
    public Dictionary<string, object>? OsQuery { get; set; }
    public string CollectionTimestamp { get; set; } = string.Empty;
    public string ClientVersion { get; set; } = string.Empty;
    public string CollectionType { get; set; } = "comprehensive";
    public string ManagedInstallsSystem { get; set; } = "Cimian";
    public string Source { get; set; } = "runner.exe";
    public object[]? Metadata { get; set; } = null; // Events array for API compatibility
}
