#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for collecting device information
/// Uses osquery as the primary data source for comprehensive device information
/// </summary>
public interface IDeviceInfoService
{
    Task<DeviceInfo> GetBasicDeviceInfoAsync();
    Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync();
}

public class DeviceInfoService : IDeviceInfoService
{
    private readonly ILogger<DeviceInfoService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IOsQueryService _osQueryService;

    public DeviceInfoService(
        ILogger<DeviceInfoService> logger, 
        IConfiguration configuration,
        IOsQueryService osQueryService)
    {
        _logger = logger;
        _configuration = configuration;
        _osQueryService = osQueryService;
    }

    public async Task<DeviceInfo> GetBasicDeviceInfoAsync()
    {
        try
        {
            // Get hardware UUID as the primary device ID
            var hardwareUuid = await GetHardwareUuidFromOsQueryAsync();
            
            // Get hardware info from osquery
            var (manufacturer, model, serialNumber) = await GetHardwareInfoFromOsQueryAsync();
            
            // Get the Windows sharing name (NetBIOS name)
            var computerName = await GetWindowsSharingNameFromOsQueryAsync();
            var domain = GetDomainName();
            
            // Get asset tag from inventory file
            var assetTag = await GetAssetTagFromInventoryAsync();
            
            // Get granular OS information
            var (osName, osVersion, osBuild, osArchitecture, fullOsString) = await GetOperatingSystemInfoFromOsQueryAsync();
            var osInstallDate = await GetOsInstallDateFromOsQueryAsync();
            var experiencePack = await GetExperiencePackVersionFromOsQueryAsync();
            
            // Get MDM enrollment information
            var (mdmEnrollmentId, mdmEnrollmentType, mdmEnrollmentState, mdmManagementUrl) = await GetMdmEnrollmentInfoFromOsQueryAsync();

            // Get network information
            var (ipv4Address, ipv6Address, macAddress) = await GetNetworkInfoFromOsQueryAsync();

            var deviceInfo = new DeviceInfo
            {
                // Core device identification
                DeviceId = hardwareUuid,
                SerialNumber = serialNumber ?? "UNKNOWN-" + Environment.MachineName,
                ComputerName = computerName,
                Domain = domain,
                Manufacturer = manufacturer ?? "Unknown",
                Model = model ?? "Unknown",
                LastSeen = DateTime.UtcNow,
                ClientVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0",
                AssetTag = assetTag,
                Status = "online",

                // Populate organized dashboard sections with comprehensive osquery data
                Basic = await PopulateBasicInfoAsync(computerName, assetTag),
                Os = await PopulateOperatingSystemInfoAsync(osName, osVersion, osBuild, osArchitecture, osInstallDate, experiencePack),
                Hardware = await PopulateHardwareInfoAsync(),
                Network = await PopulateNetworkInfoAsync(ipv4Address, ipv6Address, macAddress),
                Security = await PopulateSecurityInfoAsync(),
                Mdm = await PopulateMdmInfoAsync(mdmEnrollmentId, mdmEnrollmentType, mdmEnrollmentState, mdmManagementUrl),
                Metrics = await PopulateSystemMetricsAsync(),
                
                // Populate lists with actual osquery data
                Applications = await PopulateApplicationsAsync(),
                Services = await PopulateServicesAsync(),
                NetworkInterfaces = await PopulateNetworkInterfacesAsync(),
                StartupItems = await PopulateStartupItemsAsync(),
                Patches = await PopulateSecurityPatchesAsync(),
                ScheduledTasks = await PopulateScheduledTasksAsync(),
                ListeningPorts = await PopulateListeningPortsAsync(),
                LogicalDrives = await PopulateLogicalDrivesAsync(),
                CriticalProcesses = await PopulateCriticalProcessesAsync(),
                LoggedInUsers = await PopulateLoggedInUsersAsync()
            };

            // Get memory info for backward compatibility
            try
            {
                var systemInfoResult = await _osQueryService.ExecuteQueryAsync("SELECT physical_memory FROM system_info;");
                if (systemInfoResult?.Any() == true && systemInfoResult.TryGetValue("physical_memory", out var memoryBytes))
                {
                    if (long.TryParse(memoryBytes?.ToString(), out var memBytes))
                    {
                        // Memory info is now handled in Hardware.Memory section
                        _logger.LogDebug("System memory: {MemoryGB}GB", Math.Round(memBytes / (1024.0 * 1024.0 * 1024.0), 2));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not get memory info from osquery");
            }

            _logger.LogInformation("DeviceInfo created with comprehensive dashboard data - DeviceId: '{DeviceId}', SerialNumber: '{SerialNumber}', ComputerName: '{ComputerName}', OS: '{OsName} {OsVersion}'", 
                deviceInfo.DeviceId, deviceInfo.SerialNumber, deviceInfo.ComputerName, osName, osVersion);
            
            return deviceInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting comprehensive device info");
            throw;
        }
    }

    public async Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync()
    {
        try
        {
            _logger.LogInformation("Collecting streamlined device data (device + osquery only)");

            var data = new Dictionary<string, object>();

            // Comprehensive device info - this includes main field population from osquery data
            var deviceInfo = await GetComprehensiveDeviceInfoAsync();
            data["device"] = deviceInfo;

            // STREAMLINED PAYLOAD: Remove system and security sections to eliminate duplication
            // The Azure Function backend will extract all system and security information from osquery data
            _logger.LogInformation("Skipping system and security sections - data will be extracted from osquery on backend");

            // osquery data (if available) - this is the primary data source
            if (await _osQueryService.IsOsQueryAvailableAsync())
            {
                try
                {
                    var programDataPath = ConfigurationService.GetWorkingDataDirectory();
                    var osqueryQueriesFile = Path.Combine(programDataPath, "queries.json");
                    
                    if (!File.Exists(osqueryQueriesFile))
                    {
                        osqueryQueriesFile = Path.Combine(ConfigurationService.GetApplicationDirectory(), "osquery-queries.json");
                    }
                    
                    if (File.Exists(osqueryQueriesFile))
                    {
                        var osqueryResults = await _osQueryService.ExecuteQueriesFromFileAsync(osqueryQueriesFile);
                        data["osquery"] = osqueryResults;
                        _logger.LogInformation("Successfully collected osquery data with {Count} query results", osqueryResults.Count);
                        _logger.LogInformation("osquery data will be processed by backend to extract system and security information");
                    }
                    else
                    {
                        _logger.LogWarning("osquery queries file not found");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error collecting osquery data");
                    data["osquery_error"] = ex.Message;
                }
            }
            else
            {
                _logger.LogWarning("osquery not available - system and security data will be limited");
                data["osquery_available"] = false;
            }

            // Collection metadata
            data["collection_timestamp"] = DateTime.UtcNow.ToString("O");
            data["client_version"] = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0";
            data["collection_type"] = "comprehensive";

            _logger.LogInformation("Comprehensive device data collection completed successfully");
            return data;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting comprehensive device data");
            throw;
        }
    }

    /// <summary>
    /// Creates a comprehensive DeviceInfo object with all dashboard data populated from osquery results
    /// </summary>
    public async Task<DeviceInfo> GetComprehensiveDeviceInfoAsync()
    {
        try
        {
            _logger.LogInformation("Building comprehensive DeviceInfo object with all dashboard data");
            
            var deviceInfo = await GetBasicDeviceInfoAsync();
            
            if (!await _osQueryService.IsOsQueryAvailableAsync())
            {
                _logger.LogWarning("osquery not available - returning basic device info only");
                return deviceInfo;
            }

            // Get osquery results
            var programDataPath = ConfigurationService.GetWorkingDataDirectory();
            var osqueryQueriesFile = Path.Combine(programDataPath, "queries.json");
            
            if (!File.Exists(osqueryQueriesFile))
            {
                osqueryQueriesFile = Path.Combine(ConfigurationService.GetApplicationDirectory(), "osquery-queries.json");
            }
            
            if (!File.Exists(osqueryQueriesFile))
            {
                _logger.LogWarning("osquery queries file not found - returning basic device info only");
                return deviceInfo;
            }

            var osqueryResults = await _osQueryService.ExecuteQueriesFromFileAsync(osqueryQueriesFile);
            _logger.LogInformation("Retrieved osquery results for comprehensive device info processing");

            // Populate comprehensive sections from osquery data
            PopulateBasicInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateOperatingSystemInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateHardwareInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateNetworkInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateSecurityInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateMdmInfoFromOsQuery(deviceInfo, osqueryResults);
            PopulateSystemMetricsFromOsQuery(deviceInfo, osqueryResults);
            PopulateApplicationsFromOsQuery(deviceInfo, osqueryResults);
            PopulateServicesFromOsQuery(deviceInfo, osqueryResults);
            PopulateNetworkInterfacesFromOsQuery(deviceInfo, osqueryResults);
            PopulateStartupItemsFromOsQuery(deviceInfo, osqueryResults);
            PopulatePatchesFromOsQuery(deviceInfo, osqueryResults);
            PopulateScheduledTasksFromOsQuery(deviceInfo, osqueryResults);
            PopulateListeningPortsFromOsQuery(deviceInfo, osqueryResults);
            PopulateLogicalDrivesFromOsQuery(deviceInfo, osqueryResults);
            PopulateCriticalProcessesFromOsQuery(deviceInfo, osqueryResults);
            PopulateLoggedInUsersFromOsQuery(deviceInfo, osqueryResults);

            _logger.LogInformation("Comprehensive DeviceInfo object populated successfully");
            return deviceInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error building comprehensive DeviceInfo object");
            throw;
        }
    }

    /// <summary>
    /// Populates BasicInfo section from osquery results
    /// </summary>
    private void PopulateBasicInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                deviceInfo.Basic.Hostname = GetStringValue(info, "hostname");
                deviceInfo.Basic.Platform = $"{GetStringValue(info, "cpu_brand")} ({GetStringValue(info, "cpu_physical_cores")} cores)";
                
                // Update main DeviceInfo fields
                if (long.TryParse(GetStringValue(info, "physical_memory"), out var memoryBytes))
                {
                    deviceInfo.TotalMemoryGB = Math.Round(memoryBytes / 1024.0 / 1024.0 / 1024.0, 2);
                }
            }

            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Count > 0)
            {
                var info = osVersion[0];
                deviceInfo.Basic.Platform = GetStringValue(info, "platform");
            }

            // Add uptime calculation from system boot time
            // Add timezone information
            deviceInfo.Basic.AssetTag = deviceInfo.AssetTag;
            deviceInfo.Basic.TimeZone = TimeZoneInfo.Local.DisplayName;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating BasicInfo from osquery");
        }
    }

    /// <summary>
    /// Populates OperatingSystemInfo section from osquery results
    /// </summary>
    private void PopulateOperatingSystemInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Count > 0)
            {
                var info = osVersion[0];
                var osName = GetStringValue(info, "name");
                var osVersionStr = GetStringValue(info, "version");
                var osBuild = GetStringValue(info, "build");
                var osArch = GetStringValue(info, "arch");
                
                // Update nested Os object
                deviceInfo.Os.Name = osName;
                deviceInfo.Os.Version = osVersionStr;
                deviceInfo.Os.Build = osBuild;
                deviceInfo.Os.Architecture = osArch;
                
                // Update main DeviceInfo fields for API payload
                deviceInfo.OsName = osName;
                deviceInfo.OsVersion = osVersionStr;
                deviceInfo.OsBuild = osBuild;
                deviceInfo.OsArchitecture = osArch;
                
                var installDateStr = GetStringValue(info, "install_date");
                if (DateTime.TryParse(installDateStr, out var installDate))
                {
                    deviceInfo.Os.InstallDate = installDate;
                }
            }

            // Get experience pack and edition info from registry queries
            deviceInfo.Os.ExperiencePack = deviceInfo.ExperiencePack;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating OperatingSystemInfo from osquery");
        }
    }

    /// <summary>
    /// Populates HardwareInfo section from osquery results
    /// </summary>
    private void PopulateHardwareInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // Processor info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                deviceInfo.Hardware.Processor.Name = GetStringValue(info, "cpu_brand");
                deviceInfo.Hardware.Processor.PhysicalCores = GetIntValue(info, "cpu_physical_cores");
                deviceInfo.Hardware.Processor.LogicalCores = GetIntValue(info, "cpu_logical_cores");
            }

            // Memory info
            if (osqueryResults.TryGetValue("memory_info", out var memoryInfo) && memoryInfo.Count > 0)
            {
                foreach (var memory in memoryInfo)
                {
                    var memDevice = new MemoryDevice
                    {
                        DeviceLocator = GetStringValue(memory, "device_locator"),
                        MemoryType = GetStringValue(memory, "memory_type"),
                        Size = GetLongValue(memory, "size"),
                        FormFactor = GetStringValue(memory, "form_factor"),
                        ConfiguredClockSpeed = GetIntValue(memory, "configured_clock_speed")
                    };
                    deviceInfo.Hardware.Memory.Devices.Add(memDevice);
                }

                // Calculate total memory
                deviceInfo.Hardware.Memory.TotalMemoryBytes = deviceInfo.Hardware.Memory.Devices.Sum(d => d.Size);
            }

            // Storage info
            if (osqueryResults.TryGetValue("disk_info", out var diskInfo) && diskInfo.Count > 0)
            {
                foreach (var disk in diskInfo)
                {
                    var diskDevice = new DiskInfo
                    {
                        Id = GetStringValue(disk, "id"),
                        Type = GetStringValue(disk, "type"),
                        DiskSize = GetLongValue(disk, "disk_size"),
                        HardwareModel = GetStringValue(disk, "hardware_model")
                    };
                    deviceInfo.Hardware.Storage.Add(diskDevice);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating HardwareInfo from osquery");
        }
    }

    /// <summary>
    /// Populates NetworkInfo section from osquery results
    /// </summary>
    private void PopulateNetworkInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // First, extract primary network info from osquery data
            string primaryIPv4 = "";
            string primaryIPv6 = "";
            string primaryMac = "";

            // Get primary IP addresses from network_addresses
            if (osqueryResults.TryGetValue("network_addresses", out var addresses) && addresses.Count > 0)
            {
                // Find the primary IPv4 address (non-loopback, non-link-local)
                foreach (var addr in addresses)
                {
                    var address = GetStringValue(addr, "address");
                    var type = GetStringValue(addr, "type");
                    
                    if (string.IsNullOrEmpty(primaryIPv4) && IsValidIPv4(address) && !IsLoopbackOrLinkLocal(address))
                    {
                        primaryIPv4 = address;
                    }
                    else if (string.IsNullOrEmpty(primaryIPv6) && IsValidIPv6(address) && !IsLoopbackOrLinkLocal(address))
                    {
                        primaryIPv6 = address;
                    }
                }
            }

            // Get primary MAC address from network_interfaces
            if (osqueryResults.TryGetValue("network_interfaces", out var interfaces) && interfaces.Count > 0)
            {
                // Find the first non-empty MAC address from a physical interface
                foreach (var iface in interfaces)
                {
                    var mac = GetStringValue(iface, "mac");
                    var type = GetStringValue(iface, "type");
                    var description = GetStringValue(iface, "description");
                    
                    if (!string.IsNullOrEmpty(mac) && !mac.StartsWith("00:00:00") && 
                        !description.Contains("Loopback") && string.IsNullOrEmpty(primaryMac))
                    {
                        primaryMac = mac;
                        break;
                    }
                }
            }

            // Update main DeviceInfo fields
            deviceInfo.IpAddressV4 = primaryIPv4;
            deviceInfo.IpAddressV6 = primaryIPv6;
            deviceInfo.MacAddress = primaryMac;

            // Set network section
            deviceInfo.Network.PrimaryIPv4 = primaryIPv4;
            deviceInfo.Network.PrimaryIPv6 = primaryIPv6;
            deviceInfo.Network.PrimaryMacAddress = primaryMac;

            // Network interfaces
            if (interfaces != null && interfaces.Count > 0)
            {
                foreach (var iface in interfaces)
                {
                    var networkInterface = new NetworkInterface
                    {
                        Interface = GetStringValue(iface, "interface"),
                        MacAddress = GetStringValue(iface, "mac"),
                        Type = GetStringValue(iface, "type"),
                        Mtu = GetIntValue(iface, "mtu"),
                        FriendlyName = GetStringValue(iface, "friendly_name"),
                        Description = GetStringValue(iface, "description"),
                        Manufacturer = GetStringValue(iface, "manufacturer")
                    };
                    deviceInfo.Network.Interfaces.Add(networkInterface);
                }
            }

            // Network addresses
            if (addresses != null && addresses.Count > 0)
            {
                foreach (var addr in addresses)
                {
                    var networkAddress = new NetworkAddress
                    {
                        Interface = GetStringValue(addr, "interface"),
                        Address = GetStringValue(addr, "address"),
                        Mask = GetStringValue(addr, "mask"),
                        Broadcast = GetStringValue(addr, "broadcast"),
                        Type = GetStringValue(addr, "type")
                    };
                    deviceInfo.Network.Addresses.Add(networkAddress);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating NetworkInfo from osquery");
        }
    }

    /// <summary>
    /// Populates SecurityInfo section from osquery results
    /// </summary>
    private void PopulateSecurityInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // Security center info
            if (osqueryResults.TryGetValue("security_center", out var securityCenter) && securityCenter.Count > 0)
            {
                var info = securityCenter[0];
                deviceInfo.Security.AntivirusStatus = GetStringValue(info, "antivirus");
                deviceInfo.Security.AntispywareStatus = GetStringValue(info, "antispyware");
                deviceInfo.Security.FirewallStatus = GetStringValue(info, "firewall");
                deviceInfo.Security.AutoUpdateStatus = GetStringValue(info, "autoupdate");
            }

            // TPM info
            if (osqueryResults.TryGetValue("tpm_info", out var tpmInfo) && tpmInfo.Count > 0)
            {
                var info = tpmInfo[0];
                deviceInfo.Security.Tpm.Activated = GetBoolValue(info, "activated");
                deviceInfo.Security.Tpm.Enabled = GetBoolValue(info, "enabled");
                deviceInfo.Security.Tpm.Owned = GetBoolValue(info, "owned");
                deviceInfo.Security.Tpm.ManufacturerVersion = GetStringValue(info, "manufacturer_version");
                deviceInfo.Security.Tpm.ManufacturerId = GetStringValue(info, "manufacturer_id");
                deviceInfo.Security.Tpm.ManufacturerName = GetStringValue(info, "manufacturer_name");
                deviceInfo.Security.Tpm.SpecVersion = GetStringValue(info, "spec_version");
            }

            // BitLocker info
            if (osqueryResults.TryGetValue("bitlocker_info", out var bitlockerInfo) && bitlockerInfo.Count > 0)
            {
                foreach (var bl in bitlockerInfo)
                {
                    var bitlocker = new BitLockerInfo
                    {
                        DeviceId = GetStringValue(bl, "device_id"),
                        DriveLetter = GetStringValue(bl, "drive_letter"),
                        ConversionStatus = GetStringValue(bl, "conversion_status"),
                        ProtectionStatus = GetStringValue(bl, "protection_status"),
                        LockStatus = GetStringValue(bl, "lock_status"),
                        EncryptionMethod = GetStringValue(bl, "encryption_method")
                    };
                    deviceInfo.Security.BitLockerDrives.Add(bitlocker);
                }
            }

            // Security policies
            if (osqueryResults.TryGetValue("security_policies", out var policies) && policies.Count > 0)
            {
                foreach (var policy in policies)
                {
                    var securityPolicy = new SecurityPolicy
                    {
                        Name = GetStringValue(policy, "name"),
                        Value = GetStringValue(policy, "data"),
                        Type = GetStringValue(policy, "type"),
                        Category = "System Security"
                    };
                    deviceInfo.Security.SecurityPolicies.Add(securityPolicy);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating SecurityInfo from osquery");
        }
    }

    /// <summary>
    /// Populates MdmInfo section from existing MDM data
    /// </summary>
    private void PopulateMdmInfoFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // Use existing MDM info from basic device info
            deviceInfo.Mdm.EnrollmentId = deviceInfo.MdmEnrollmentId;
            deviceInfo.Mdm.EnrollmentState = deviceInfo.MdmEnrollmentState;
            deviceInfo.Mdm.ManagementUrl = deviceInfo.MdmManagementUrl;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating MdmInfo from osquery");
        }
    }

    /// <summary>
    /// Populates SystemMetrics section from osquery results
    /// </summary>
    private void PopulateSystemMetricsFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // Basic system metrics from system_info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                // Calculate uptime and other metrics
                deviceInfo.Metrics.Uptime = DateTime.Now - (deviceInfo.Basic.LastBootTime ?? DateTime.Now.AddDays(-1));
            }

            // Process count from critical_processes and any other process queries
            if (osqueryResults.TryGetValue("critical_processes", out var processes))
            {
                deviceInfo.Metrics.ProcessCount = processes.Count;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating SystemMetrics from osquery");
        }
    }

    /// <summary>
    /// Populates Applications list from osquery results
    /// </summary>
    private void PopulateApplicationsFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("installed_programs", out var programs) && programs.Count > 0)
            {
                foreach (var program in programs)
                {
                    var app = new InstalledApplication
                    {
                        Name = GetStringValue(program, "name"),
                        Version = GetStringValue(program, "version"),
                        Publisher = GetStringValue(program, "publisher"),
                        InstallDate = GetStringValue(program, "install_date")
                    };
                    deviceInfo.Applications.Add(app);
                }
                _logger.LogDebug("Populated {Count} applications from osquery", deviceInfo.Applications.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating Applications from osquery");
        }
    }

    /// <summary>
    /// Populates Services list from osquery results
    /// </summary>
    private void PopulateServicesFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("running_services", out var services) && services.Count > 0)
            {
                foreach (var service in services)
                {
                    var svc = new RunningService
                    {
                        Name = GetStringValue(service, "name"),
                        DisplayName = GetStringValue(service, "display_name"),
                        Status = GetStringValue(service, "status"),
                        StartType = GetStringValue(service, "start_type"),
                        Path = GetStringValue(service, "path")
                    };
                    deviceInfo.Services.Add(svc);
                }
                _logger.LogDebug("Populated {Count} services from osquery", deviceInfo.Services.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating Services from osquery");
        }
    }

    /// <summary>
    /// Populates NetworkInterfaces list from osquery results
    /// </summary>
    private void PopulateNetworkInterfacesFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            // This data is already populated in PopulateNetworkInfoFromOsQuery
            // Network interfaces are part of the Network section
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating NetworkInterfaces from osquery");
        }
    }

    /// <summary>
    /// Populates StartupItems list from osquery results
    /// </summary>
    private void PopulateStartupItemsFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("startup_items", out var startupItems) && startupItems.Count > 0)
            {
                foreach (var item in startupItems)
                {
                    var startup = new StartupItem
                    {
                        Name = GetStringValue(item, "name"),
                        Path = GetStringValue(item, "path"),
                        Source = GetStringValue(item, "source"),
                        Status = GetStringValue(item, "status"),
                        Username = GetStringValue(item, "username")
                    };
                    deviceInfo.StartupItems.Add(startup);
                }
                _logger.LogDebug("Populated {Count} startup items from osquery", deviceInfo.StartupItems.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating StartupItems from osquery");
        }
    }

    /// <summary>
    /// Populates Patches list from osquery results
    /// </summary>
    private void PopulatePatchesFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("recent_patches", out var patches) && patches.Count > 0)
            {
                foreach (var patch in patches)
                {
                    var securityPatch = new SecurityPatch
                    {
                        ComputerName = GetStringValue(patch, "csname"),
                        HotfixId = GetStringValue(patch, "hotfix_id"),
                        Description = GetStringValue(patch, "description"),
                        InstalledOn = GetStringValue(patch, "installed_on")
                    };
                    deviceInfo.Patches.Add(securityPatch);
                }
                _logger.LogDebug("Populated {Count} patches from osquery", deviceInfo.Patches.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating Patches from osquery");
        }
    }

    /// <summary>
    /// Populates ScheduledTasks list from osquery results
    /// </summary>
    private void PopulateScheduledTasksFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("active_tasks", out var tasks) && tasks.Count > 0)
            {
                foreach (var task in tasks)
                {
                    var scheduledTask = new ScheduledTask
                    {
                        Name = GetStringValue(task, "name"),
                        Action = GetStringValue(task, "action"),
                        Path = GetStringValue(task, "path"),
                        Enabled = GetBoolValue(task, "enabled"),
                        State = GetStringValue(task, "state"),
                        LastRunTime = GetStringValue(task, "last_run_time"),
                        NextRunTime = GetStringValue(task, "next_run_time")
                    };
                    deviceInfo.ScheduledTasks.Add(scheduledTask);
                }
                _logger.LogDebug("Populated {Count} scheduled tasks from osquery", deviceInfo.ScheduledTasks.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating ScheduledTasks from osquery");
        }
    }

    /// <summary>
    /// Populates ListeningPorts list from osquery results
    /// </summary>
    private void PopulateListeningPortsFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("listening_ports", out var ports) && ports.Count > 0)
            {
                foreach (var port in ports)
                {
                    var listeningPort = new ListeningPort
                    {
                        ProcessId = GetIntValue(port, "pid"),
                        Port = GetIntValue(port, "port"),
                        Protocol = GetStringValue(port, "protocol"),
                        Family = GetStringValue(port, "family"),
                        Address = GetStringValue(port, "address"),
                        Path = GetStringValue(port, "path")
                    };
                    deviceInfo.ListeningPorts.Add(listeningPort);
                }
                _logger.LogDebug("Populated {Count} listening ports from osquery", deviceInfo.ListeningPorts.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating ListeningPorts from osquery");
        }
    }

    /// <summary>
    /// Populates LogicalDrives list from osquery results
    /// </summary>
    private void PopulateLogicalDrivesFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("logical_drives", out var drives) && drives.Count > 0)
            {
                foreach (var drive in drives)
                {
                    var logicalDrive = new LogicalDrive
                    {
                        DeviceId = GetStringValue(drive, "device_id"),
                        Type = GetStringValue(drive, "type"),
                        Description = GetStringValue(drive, "description"),
                        Size = GetLongValue(drive, "size"),
                        FreeSpace = GetLongValue(drive, "free_space"),
                        FileSystem = GetStringValue(drive, "file_system")
                    };
                    deviceInfo.LogicalDrives.Add(logicalDrive);
                }
                _logger.LogDebug("Populated {Count} logical drives from osquery", deviceInfo.LogicalDrives.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating LogicalDrives from osquery");
        }
    }

    /// <summary>
    /// Populates CriticalProcesses list from osquery results
    /// </summary>
    private void PopulateCriticalProcessesFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("critical_processes", out var processes) && processes.Count > 0)
            {
                foreach (var process in processes)
                {
                    var processInfo = new ProcessInfo
                    {
                        ProcessId = GetIntValue(process, "pid"),
                        Name = GetStringValue(process, "name"),
                        Path = GetStringValue(process, "path"),
                        CommandLine = GetStringValue(process, "cmdline"),
                        ParentProcessId = GetIntValue(process, "parent"),
                        Threads = GetIntValue(process, "threads")
                    };
                    deviceInfo.CriticalProcesses.Add(processInfo);
                }
                _logger.LogDebug("Populated {Count} critical processes from osquery", deviceInfo.CriticalProcesses.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating CriticalProcesses from osquery");
        }
    }

    /// <summary>
    /// Populates LoggedInUsers list from osquery results
    /// </summary>
    private void PopulateLoggedInUsersFromOsQuery(DeviceInfo deviceInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
    {
        try
        {
            if (osqueryResults.TryGetValue("logged_in_users", out var users) && users.Count > 0)
            {
                foreach (var user in users)
                {
                    var userInfo = new UserInfo
                    {
                        Username = GetStringValue(user, "user"),
                        Host = GetStringValue(user, "host"),
                        Time = GetStringValue(user, "time"),
                        ProcessId = GetIntValue(user, "pid")
                    };
                    deviceInfo.LoggedInUsers.Add(userInfo);
                }
                _logger.LogDebug("Populated {Count} logged in users from osquery", deviceInfo.LoggedInUsers.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error populating LoggedInUsers from osquery");
        }
    }

    // Helper methods for safe data extraction
    private string GetStringValue(Dictionary<string, object> dict, string key)
    {
        return dict.TryGetValue(key, out var value) && value != null ? value.ToString() ?? string.Empty : string.Empty;
    }

    private int GetIntValue(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value != null)
        {
            if (int.TryParse(value.ToString(), out var intValue))
                return intValue;
        }
        return 0;
    }

    private long GetLongValue(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value != null)
        {
            if (long.TryParse(value.ToString(), out var longValue))
                return longValue;
        }
        return 0;
    }

    private bool GetBoolValue(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value != null)
        {
            var str = value.ToString()?.ToLower();
            return str == "true" || str == "1" || str == "yes" || str == "enabled";
        }
        return false;
    }

    private double GetDoubleValue(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value != null)
        {
            if (double.TryParse(value.ToString(), out var doubleValue))
                return doubleValue;
        }
        return 0.0;
    }

    private async Task<string> GetHardwareUuidFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT uuid FROM system_info;");
            return GetStringValue(result, "uuid");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get hardware UUID from osquery");
            return Guid.NewGuid().ToString();
        }
    }

    private async Task<(string manufacturer, string model, string serialNumber)> GetHardwareInfoFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT hardware_vendor, hardware_model, hardware_serial FROM system_info;");
            return (
                GetStringValue(result, "hardware_vendor"), 
                GetStringValue(result, "hardware_model"), 
                GetStringValue(result, "hardware_serial")
            );
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get hardware info from osquery");
            return ("Unknown", "Unknown", "Unknown");
        }
    }

    private async Task<string> GetWindowsSharingNameFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT data FROM registry WHERE path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\\ComputerName';");
            return GetStringValue(result, "data") ?? Environment.MachineName;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get computer name from osquery");
            return Environment.MachineName;
        }
    }

    private string GetDomainName()
    {
        try
        {
            return Environment.UserDomainName;
        }
        catch
        {
            return "WORKGROUP";
        }
    }

    private async Task<string> GetAssetTagFromInventoryAsync()
    {
        try
        {
            // Check inventory file for asset tag
            var inventoryPath = Path.Combine(ConfigurationService.GetWorkingDataDirectory(), "device_inventory.json");
            if (File.Exists(inventoryPath))
            {
                var json = await File.ReadAllTextAsync(inventoryPath);
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("asset_tag", out var assetTag))
                {
                    return assetTag.GetString() ?? "";
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get asset tag from inventory file");
        }
        return "";
    }

    private async Task<(string osName, string osVersion, string osBuild, string osArchitecture, string fullOsString)> GetOperatingSystemInfoFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT name, version, build, platform, arch FROM os_version;");
            var osName = ProcessWindowsOsName(GetStringValue(result, "name"));
            var osVersion = GetStringValue(result, "version");
            var osBuild = GetStringValue(result, "build");
            var osArchitecture = GetStringValue(result, "arch");
            
            // Get UBR for full build number
            try
            {
                var ubrResult = await _osQueryService.ExecuteQueryAsync("SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'UBR';");
                var ubr = GetStringValue(ubrResult, "data");
                if (!string.IsNullOrEmpty(ubr))
                {
                    osBuild = $"{osBuild}.{ubr}";
                }
            }
            catch { }

            var fullOsString = $"{osName} {osVersion} (Build {osBuild}) {osArchitecture}";
            return (osName, osVersion, osBuild, osArchitecture, fullOsString);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get OS info from osquery");
            return ("Windows", "Unknown", "Unknown", "Unknown", "Windows Unknown");
        }
    }

    private string ProcessWindowsOsName(string rawName)
    {
        if (string.IsNullOrEmpty(rawName))
            return "Windows";

        return rawName
            .Replace("Microsoft ", "")
            .Replace(" Operating System", "")
            .Trim();
    }

    private async Task<DateTime?> GetOsInstallDateFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT install_date FROM os_version;");
            var installDateStr = GetStringValue(result, "install_date");
            if (DateTime.TryParse(installDateStr, out var installDate))
            {
                return installDate;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get OS install date from osquery");
        }
        return null;
    }

    private async Task<string> GetExperiencePackVersionFromOsQueryAsync()
    {
        try
        {
            var ubrResult = await _osQueryService.ExecuteQueryAsync("SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'UBR';");
            var ubr = GetStringValue(ubrResult, "data");
            
            var buildResult = await _osQueryService.ExecuteQueryAsync("SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'CurrentBuild';");
            var build = GetStringValue(buildResult, "data");

            if (!string.IsNullOrEmpty(ubr) && !string.IsNullOrEmpty(build))
            {
                return $"1000.{build}.{ubr}.0";
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get experience pack version from osquery");
        }
        return "";
    }

    private async Task<(string enrollmentId, string enrollmentType, string enrollmentState, string managementUrl)> GetMdmEnrollmentInfoFromOsQueryAsync()
    {
        try
        {
            var result = await _osQueryService.ExecuteQueryAsync("SELECT name, data FROM registry WHERE path = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments';");
            // This is a simplified version - in reality you'd need to parse the complex MDM registry structure
            return ("", "Microsoft Intune", "Enrolled", "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get MDM enrollment info from osquery");
            return ("", "", "", "");
        }
    }

    private async Task<(string ipv4Address, string ipv6Address, string macAddress)> GetNetworkInfoFromOsQueryAsync()
    {
        try
        {
            var ipResult = await _osQueryService.ExecuteQueryAsync("SELECT address FROM interface_addresses WHERE address IS NOT NULL AND address NOT LIKE '127.%' AND address NOT LIKE '169.254.%' AND address NOT LIKE 'fe80:%' ORDER BY address;");
            var macResult = await _osQueryService.ExecuteQueryAsync("SELECT mac FROM interface_details WHERE type = 6 AND mac IS NOT NULL AND mac != '' AND mac != '00:00:00:00:00:00' LIMIT 1;");
            
            return ("", "", GetStringValue(macResult, "mac"));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get network info from osquery");
            return ("", "", "");
        }
    }

    // Stub methods for the comprehensive DeviceInfo population - these would need full implementation
    private Task<BasicInfo> PopulateBasicInfoAsync(string computerName, string assetTag)
    {
        return Task.FromResult(new BasicInfo
        {
            Hostname = computerName,
            AssetTag = assetTag,
            TimeZone = TimeZoneInfo.Local.DisplayName
        });
    }

    private Task<OperatingSystemInfo> PopulateOperatingSystemInfoAsync(string osName, string osVersion, string osBuild, string osArchitecture, DateTime? osInstallDate, string experiencePack)
    {
        return Task.FromResult(new OperatingSystemInfo
        {
            Name = osName,
            Version = osVersion,
            Build = osBuild,
            Architecture = osArchitecture,
            InstallDate = osInstallDate,
            ExperiencePack = experiencePack
        });
    }

    private Task<HardwareInfo> PopulateHardwareInfoAsync()
    {
        return Task.FromResult(new HardwareInfo());
    }

    private Task<NetworkInfo> PopulateNetworkInfoAsync(string ipv4Address, string ipv6Address, string macAddress)
    {
        return Task.FromResult(new NetworkInfo
        {
            PrimaryIPv4 = ipv4Address,
            PrimaryIPv6 = ipv6Address,
            PrimaryMacAddress = macAddress
        });
    }

    private Task<DeviceSecurityInfo> PopulateSecurityInfoAsync()
    {
        return Task.FromResult(new DeviceSecurityInfo());
    }

    private Task<MdmInfo> PopulateMdmInfoAsync(string enrollmentId, string enrollmentType, string enrollmentState, string managementUrl)
    {
        return Task.FromResult(new MdmInfo
        {
            EnrollmentId = enrollmentId,
            EnrollmentType = enrollmentType,
            EnrollmentState = enrollmentState,
            ManagementUrl = managementUrl
        });
    }

    private Task<SystemMetrics> PopulateSystemMetricsAsync()
    {
        return Task.FromResult(new SystemMetrics());
    }

    private Task<List<InstalledApplication>> PopulateApplicationsAsync()
    {
        return Task.FromResult(new List<InstalledApplication>());
    }

    private Task<List<RunningService>> PopulateServicesAsync()
    {
        return Task.FromResult(new List<RunningService>());
    }

    private Task<List<NetworkInterface>> PopulateNetworkInterfacesAsync()
    {
        return Task.FromResult(new List<NetworkInterface>());
    }

    private Task<List<StartupItem>> PopulateStartupItemsAsync()
    {
        return Task.FromResult(new List<StartupItem>());
    }

    private Task<List<SecurityPatch>> PopulateSecurityPatchesAsync()
    {
        return Task.FromResult(new List<SecurityPatch>());
    }

    private Task<List<ScheduledTask>> PopulateScheduledTasksAsync()
    {
        return Task.FromResult(new List<ScheduledTask>());
    }

    private Task<List<ListeningPort>> PopulateListeningPortsAsync()
    {
        return Task.FromResult(new List<ListeningPort>());
    }

    private Task<List<LogicalDrive>> PopulateLogicalDrivesAsync()
    {
        return Task.FromResult(new List<LogicalDrive>());
    }

    private Task<List<ProcessInfo>> PopulateCriticalProcessesAsync()
    {
        return Task.FromResult(new List<ProcessInfo>());
    }

    private Task<List<UserInfo>> PopulateLoggedInUsersAsync()
    {
        return Task.FromResult(new List<UserInfo>());
    }

    /// <summary>
    /// Helper methods for network validation
    /// </summary>
    private bool IsValidIPv4(string address)
    {
        return System.Net.IPAddress.TryParse(address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    }

    private bool IsValidIPv6(string address)
    {
        return System.Net.IPAddress.TryParse(address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    }

    private bool IsLoopbackOrLinkLocal(string address)
    {
        if (string.IsNullOrEmpty(address)) return true;
        
        // IPv4 checks
        if (address.StartsWith("127.") || address.StartsWith("169.254."))
            return true;
            
        // IPv6 checks
        if (address.StartsWith("::1") || address.StartsWith("fe80:"))
            return true;
            
        return false;
    }
}
