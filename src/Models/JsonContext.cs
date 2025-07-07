#nullable enable
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Services;

namespace ReportMate.WindowsClient.Models;

/// <summary>
/// JSON serialization context for NativeAOT compatibility
/// This enables source-generated JSON serialization instead of reflection
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
[JsonSerializable(typeof(DeviceInfo))]
[JsonSerializable(typeof(SystemInfo))]
[JsonSerializable(typeof(SecurityInfo))]
[JsonSerializable(typeof(DiskInfo))]
[JsonSerializable(typeof(List<DiskInfo>))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    AllowTrailingCommas = true
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
