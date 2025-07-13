#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.DataProcessing
{
    /// <summary>
    /// Client-side data processor that converts raw osquery results into structured data
    /// </summary>
    public class DataProcessor
    {
        private readonly ILogger? _logger;

        public DataProcessor(ILogger? logger = null)
        {
            _logger = logger;
        }

        /// <summary>
        /// Process raw osquery data into structured device information
        /// </summary>
        public ProcessedDeviceData ProcessDeviceData(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            try
            {
                _logger?.LogInformation("Processing osquery data on client side...");

                var processedData = new ProcessedDeviceData
                {
                    DeviceId = ExtractDeviceId(osqueryResults),
                    BasicInfo = ProcessBasicInfo(osqueryResults),
                    OperatingSystem = ProcessOperatingSystem(osqueryResults),
                    Hardware = ProcessHardware(osqueryResults),
                    Network = ProcessNetwork(osqueryResults),
                    Security = ProcessSecurity(osqueryResults),
                    Management = ProcessManagement(osqueryResults),
                    Applications = ProcessApplications(osqueryResults),
                    LastUpdated = DateTime.UtcNow,
                    ClientVersion = GetClientVersion(),
                    Platform = "Windows"
                };

                _logger?.LogInformation("Client-side data processing completed successfully");
                _logger?.LogInformation($"   Device: {processedData.BasicInfo.Name}");
                _logger?.LogInformation($"   Processor: {processedData.Hardware.Processor} ({processedData.Hardware.Cores} cores)");
                _logger?.LogInformation($"   Graphics: {processedData.Hardware.Graphics}");

                return processedData;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error processing device data on client");
                throw;
            }
        }

        private string ExtractDeviceId(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // Try multiple sources for device ID
            var sources = new[] { "system_info", "hardware_serial", "wmi_bios" };
            
            foreach (var source in sources)
            {
                if (osqueryResults.TryGetValue(source, out var results) && results.Any())
                {
                    var firstResult = results.First();
                    
                    // Look for various ID fields - UUID has highest priority
                    var idFields = new[] { "uuid", "hardware_serial", "serial_number", "computer_name" };
                    
                    foreach (var field in idFields)
                    {
                        if (firstResult.TryGetValue(field, out var value) && 
                            value != null && 
                            !string.IsNullOrWhiteSpace(value.ToString()))
                        {
                            var deviceId = value.ToString()!;
                            _logger?.LogInformation($"Device ID extracted from {source}.{field}: {deviceId}");
                            return deviceId;
                        }
                    }
                }
            }

            _logger?.LogWarning("No device ID found in osquery data, using machine name fallback");
            return Environment.MachineName; // Fallback
        }

        private BasicDeviceInfo ProcessBasicInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var basicInfo = new BasicDeviceInfo();

            // Get system info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Any())
            {
                var info = systemInfo.First();
                basicInfo.Name = GetStringValue(info, "computer_name") ?? Environment.MachineName;
                basicInfo.SerialNumber = GetStringValue(info, "hardware_serial") ?? "";
            }

            // Get hardware model info
            if (osqueryResults.TryGetValue("wmi_computersystem", out var computerSystem) && computerSystem.Any())
            {
                var system = computerSystem.First();
                basicInfo.Model = GetStringValue(system, "Model") ?? "";
                basicInfo.Manufacturer = GetStringValue(system, "Manufacturer") ?? "";
            }

            // Check for asset tag from various sources
            var assetTagSources = new[] { "asset_tag", "wmi_bios", "chassis_info" };
            foreach (var source in assetTagSources)
            {
                if (osqueryResults.TryGetValue(source, out var results) && results.Any())
                {
                    var assetTag = GetStringValue(results.First(), "asset_tag") ?? 
                                   GetStringValue(results.First(), "AssetTag") ?? "";
                    if (!string.IsNullOrWhiteSpace(assetTag))
                    {
                        basicInfo.AssetTag = assetTag;
                        break;
                    }
                }
            }

            return basicInfo;
        }

        private OperatingSystemInfo ProcessOperatingSystem(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var osInfo = new OperatingSystemInfo();

            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Any())
            {
                var version = osVersion.First();
                var osName = GetStringValue(version, "name") ?? "";
                var osVersionString = GetStringValue(version, "version") ?? "";
                var buildString = GetStringValue(version, "build") ?? "";

                // Parse OS information
                var parsed = ParseOperatingSystem(osName, osVersionString, buildString);
                osInfo.Name = parsed.name;
                osInfo.Version = parsed.version;
                osInfo.Build = parsed.build;
            }

            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Any())
            {
                var info = systemInfo.First();
                osInfo.Architecture = GetStringValue(info, "cpu_subtype") ?? 
                                     GetStringValue(info, "hardware_type") ?? "";
            }

            return osInfo;
        }

        private HardwareInfo ProcessHardware(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var hardware = new HardwareInfo();

            // Enhanced processor detection with priority order
            // Priority 1: Check processor_registry for ProcessorNameString (most accurate for Snapdragon)
            if (osqueryResults.TryGetValue("processor_registry", out var processorRegistry) && processorRegistry.Any())
            {
                foreach (var entry in processorRegistry)
                {
                    var name = GetStringValue(entry, "name");
                    var data = GetStringValue(entry, "data");
                    
                    if (name == "ProcessorNameString" && !string.IsNullOrWhiteSpace(data))
                    {
                        hardware.Processor = CleanProcessorName(data);
                        _logger?.LogInformation($"Found processor from registry: {data}");
                        break;
                    }
                }
            }
            
            // Priority 2: Fallback to system_info cpu_brand if not found in registry
            if (string.IsNullOrWhiteSpace(hardware.Processor))
            {
                if (osqueryResults.TryGetValue("system_info", out var systemInfoData) && systemInfoData.Any())
                {
                    var cpuBrand = GetStringValue(systemInfoData.First(), "cpu_brand");
                    if (!string.IsNullOrWhiteSpace(cpuBrand) && 
                        !cpuBrand.Contains("Virtual CPU", StringComparison.OrdinalIgnoreCase))
                    {
                        hardware.Processor = CleanProcessorName(cpuBrand);
                        _logger?.LogInformation($"Found processor from system_info: {cpuBrand}");
                    }
                }
            }

            // Get core count
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Any())
            {
                var info = systemInfo.First();
                if (int.TryParse(GetStringValue(info, "cpu_physical_cores"), out var cores))
                {
                    hardware.Cores = cores;
                }
                
                // Memory information
                if (long.TryParse(GetStringValue(info, "physical_memory"), out var memoryBytes))
                {
                    hardware.Memory = FormatMemorySize(memoryBytes);
                }
            }

            // Enhanced graphics detection
            var graphicsSources = new[]
            {
                ("graphics_registry", "name"),
                ("graphics_detailed", "description"),
                ("wmi_graphics", "name")
            };

            foreach (var (source, field) in graphicsSources)
            {
                if (osqueryResults.TryGetValue(source, out var results) && results.Any())
                {
                    var graphicsName = GetStringValue(results.First(), field);
                    if (!string.IsNullOrWhiteSpace(graphicsName))
                    {
                        hardware.Graphics = CleanGraphicsName(graphicsName);
                        break;
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(hardware.Graphics))
            {
                hardware.Graphics = "Unknown";
            }

            return hardware;
        }

        private NetworkInfo ProcessNetwork(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var network = new NetworkInfo
            {
                Hostname = Environment.MachineName
            };

            if (osqueryResults.TryGetValue("interface_addresses", out var interfaces) && interfaces.Any())
            {
                var primaryInterface = interfaces
                    .Where(i => GetStringValue(i, "interface") != "Loopback Pseudo-Interface 1")
                    .FirstOrDefault();

                if (primaryInterface != null)
                {
                    network.IpAddress = GetStringValue(primaryInterface, "address") ?? "";
                }
            }

            if (osqueryResults.TryGetValue("interface_details", out var interfaceDetails) && interfaceDetails.Any())
            {
                var primaryDetail = interfaceDetails
                    .Where(i => !string.IsNullOrWhiteSpace(GetStringValue(i, "mac")))
                    .FirstOrDefault();

                if (primaryDetail != null)
                {
                    network.MacAddress = GetStringValue(primaryDetail, "mac") ?? "";
                    network.ConnectionType = GetStringValue(primaryDetail, "type") ?? "Unknown";
                }
            }

            return network;
        }

        private SecurityInfo ProcessSecurity(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var security = new SecurityInfo();

            // Process various security features based on available osquery data
            // This would be expanded based on your specific security queries

            return security;
        }

        private ManagementInfo ProcessManagement(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var management = new ManagementInfo();

            // Process MDM enrollment information
            // This would be expanded based on your specific management queries

            return management;
        }

        private List<ApplicationInfo> ProcessApplications(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var applications = new List<ApplicationInfo>();

            if (osqueryResults.TryGetValue("programs", out var programs))
            {
                foreach (var program in programs)
                {
                    var app = new ApplicationInfo
                    {
                        Name = GetStringValue(program, "name") ?? "",
                        Version = GetStringValue(program, "version") ?? "",
                        Publisher = GetStringValue(program, "publisher") ?? ""
                    };

                    if (!string.IsNullOrWhiteSpace(app.Name))
                    {
                        applications.Add(app);
                    }
                }
            }

            return applications;
        }

        private string CleanProcessorName(string processorName)
        {
            // Clean up processor names to extract the main brand and model
            if (string.IsNullOrWhiteSpace(processorName))
                return "Unknown";

            // Handle Snapdragon processors with specific model detection
            if (processorName.Contains("Snapdragon", StringComparison.OrdinalIgnoreCase))
            {
                // Specific Snapdragon X Elite/Plus detection
                if (processorName.Contains("X", StringComparison.OrdinalIgnoreCase))
                {
                    if (processorName.Contains("12-core", StringComparison.OrdinalIgnoreCase) ||
                        processorName.Contains("X1E80100", StringComparison.OrdinalIgnoreCase))
                    {
                        return "Snapdragon X Elite";
                    }
                    else if (processorName.Contains("10-core", StringComparison.OrdinalIgnoreCase) ||
                             processorName.Contains("X1P64100", StringComparison.OrdinalIgnoreCase))
                    {
                        return "Snapdragon X Plus";
                    }
                    // Default for any Snapdragon X series
                    return "Snapdragon X Elite";
                }
                
                // Generic Snapdragon parsing for other models
                var snapdragonMatch = Regex.Match(processorName, @"Snapdragon\s+([^@\s]+)", RegexOptions.IgnoreCase);
                if (snapdragonMatch.Success)
                {
                    return $"Snapdragon {snapdragonMatch.Groups[1].Value.Trim()}";
                }
                
                return "Snapdragon";
            }

            // Handle Intel processors
            if (processorName.Contains("Intel", StringComparison.OrdinalIgnoreCase))
            {
                var cleaned = processorName
                    .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                    .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                    .Trim();
                
                // Remove speed information
                var atIndex = cleaned.IndexOf(" @ ", StringComparison.OrdinalIgnoreCase);
                if (atIndex > 0)
                {
                    cleaned = cleaned.Substring(0, atIndex);
                }
                
                return cleaned;
            }

            // Handle AMD processors
            if (processorName.Contains("AMD", StringComparison.OrdinalIgnoreCase))
            {
                var cleaned = processorName.Trim();
                
                // Remove speed information
                var atIndex = cleaned.IndexOf(" @ ", StringComparison.OrdinalIgnoreCase);
                if (atIndex > 0)
                {
                    cleaned = cleaned.Substring(0, atIndex);
                }
                
                return cleaned;
            }

            // Remove speed information and extra details for any processor
            var result = Regex.Replace(processorName, @"@.*$", "").Trim();
            result = Regex.Replace(result, @"\s+\(.*?\)", "").Trim();
            result = result.Replace("(R)", "").Replace("(TM)", "").Trim();

            return result;
        }

        private string CleanGraphicsName(string graphicsName)
        {
            if (string.IsNullOrWhiteSpace(graphicsName))
                return "Unknown";

            // Handle Qualcomm Adreno
            if (graphicsName.Contains("Adreno", StringComparison.OrdinalIgnoreCase))
            {
                return "Qualcomm Adreno";
            }

            // Handle NVIDIA
            if (graphicsName.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || 
                graphicsName.Contains("GeForce", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(graphicsName, @"(NVIDIA|GeForce).*", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return match.Value.Trim();
                }
            }

            // Handle AMD
            if (graphicsName.Contains("AMD", StringComparison.OrdinalIgnoreCase) || 
                graphicsName.Contains("Radeon", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(graphicsName, @"(AMD|Radeon).*", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return match.Value.Trim();
                }
            }

            // Handle Intel
            if (graphicsName.Contains("Intel", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(graphicsName, @"Intel.*", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return match.Value.Trim();
                }
            }

            return graphicsName;
        }

        private (string name, string version, string build) ParseOperatingSystem(string osName, string osVersion, string build)
        {
            if (string.IsNullOrWhiteSpace(osName))
                return ("Unknown", "Unknown", "Unknown");

            // Windows version mapping
            if (osName.Contains("Windows", StringComparison.OrdinalIgnoreCase))
            {
                var versionMap = new Dictionary<string, string>
                {
                    { "10.0.26100", "24H2" },
                    { "10.0.22631", "23H2" },
                    { "10.0.22621", "22H2" },
                    { "10.0.19045", "22H2" },
                    { "10.0.19044", "21H2" }
                };

                var versionName = versionMap.TryGetValue(osVersion, out var mapped) ? mapped : osVersion;
                
                return (osName, versionName, osVersion);
            }

            return (osName, osVersion, build);
        }

        private string FormatMemorySize(long bytes)
        {
            const long gb = 1024 * 1024 * 1024;
            const long mb = 1024 * 1024;

            if (bytes >= gb)
            {
                return $"{bytes / gb} GB";
            }
            else if (bytes >= mb)
            {
                return $"{bytes / mb} MB";
            }

            return $"{bytes} bytes";
        }

        private string? GetStringValue(Dictionary<string, object> dict, string key)
        {
            return dict.TryGetValue(key, out var value) ? value?.ToString() : null;
        }

        private string GetClientVersion()
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            return assembly.GetName().Version?.ToString() ?? "1.0.0.0";
        }
    }
}
