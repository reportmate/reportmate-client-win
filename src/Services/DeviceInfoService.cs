using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.Json;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for collecting device information
/// Combines data from multiple sources including WMI, Registry, and osquery
/// </summary>
public interface IDeviceInfoService
{
    Task<DeviceInfo> GetBasicDeviceInfoAsync();
    Task<SystemInfo> GetSystemInfoAsync();
    Task<SecurityInfo> GetSecurityInfoAsync();
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
            // Get hardware serial number first - this is the unique device identifier
            var serialNumber = await GetHardwareSerialNumberAsync();
            
            var deviceInfo = new DeviceInfo
            {
                DeviceId = _configuration["ReportMate:DeviceId"] ?? serialNumber ?? Environment.MachineName,
                SerialNumber = serialNumber ?? "UNKNOWN-" + Environment.MachineName,
                ComputerName = Environment.MachineName,
                Domain = Environment.UserDomainName,
                OperatingSystem = GetOperatingSystemInfo(),
                LastSeen = DateTime.UtcNow,
                ClientVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0"
            };

            // Try to get additional info from WMI
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    deviceInfo.Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                    deviceInfo.Model = obj["Model"]?.ToString() ?? "Unknown";
                    
                    if (obj["TotalPhysicalMemory"] != null && ulong.TryParse(obj["TotalPhysicalMemory"].ToString(), out var memory))
                    {
                        deviceInfo.TotalMemoryGB = Math.Round(memory / (1024.0 * 1024.0 * 1024.0), 2);
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve additional device info from WMI");
            }

            return deviceInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting basic device info");
            throw;
        }
    }

    public async Task<SystemInfo> GetSystemInfoAsync()
    {
        try
        {
            var systemInfo = new SystemInfo
            {
                OperatingSystem = GetOperatingSystemInfo(),
                Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                ProcessorCount = Environment.ProcessorCount,
                Uptime = GetSystemUptime(),
                LastBootTime = GetLastBootTime(),
                TimeZone = TimeZoneInfo.Local.DisplayName
            };

            // Get processor info from WMI
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Name, MaxClockSpeed FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    systemInfo.ProcessorName = obj["Name"]?.ToString() ?? "Unknown";
                    if (obj["MaxClockSpeed"] != null && uint.TryParse(obj["MaxClockSpeed"].ToString(), out var clockSpeed))
                    {
                        systemInfo.ProcessorSpeedMHz = clockSpeed;
                    }
                    break; // Just get the first processor
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve processor info from WMI");
            }

            // Get disk info
            systemInfo.DiskInfo = await GetDiskInfoAsync();

            return systemInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting system info");
            throw;
        }
    }

    public async Task<SecurityInfo> GetSecurityInfoAsync()
    {
        try
        {
            var securityInfo = new SecurityInfo
            {
                WindowsDefenderEnabled = await CheckWindowsDefenderAsync(),
                FirewallEnabled = await CheckFirewallStatusAsync(),
                UacEnabled = CheckUacStatus(),
                BitLockerEnabled = await CheckBitLockerStatusAsync(),
                TpmAvailable = await CheckTpmStatusAsync(),
                LastUpdateCheck = await GetLastUpdateCheckAsync()
            };

            return securityInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting security info");
            throw;
        }
    }

    public async Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync()
    {
        try
        {
            _logger.LogInformation("Collecting comprehensive device data");

            var data = new Dictionary<string, object>();

            // Basic device info
            var deviceInfo = await GetBasicDeviceInfoAsync();
            data["device"] = deviceInfo;

            // System info
            var systemInfo = await GetSystemInfoAsync();
            data["system"] = systemInfo;

            // Security info
            var securityInfo = await GetSecurityInfoAsync();
            data["security"] = securityInfo;

            // osquery data (if available)
            if (await _osQueryService.IsOsQueryAvailableAsync())
            {
                try
                {
                    // Look for queries.json in ProgramData/ManagedReports (working directory)
                    var programDataPath = ConfigurationService.GetWorkingDataDirectory();
                    var osqueryQueriesFile = Path.Combine(programDataPath, "queries.json");
                    
                    // Fallback to old location in Program Files if not found in ProgramData
                    if (!File.Exists(osqueryQueriesFile))
                    {
                        osqueryQueriesFile = Path.Combine(ConfigurationService.GetApplicationDirectory(), "osquery-queries.json");
                    }
                    
                    if (File.Exists(osqueryQueriesFile))
                    {
                        var osqueryResults = await _osQueryService.ExecuteQueriesFromFileAsync(osqueryQueriesFile);
                        data["osquery"] = osqueryResults;
                        _logger.LogInformation("Successfully collected osquery data with {Count} query results", osqueryResults.Count);
                    }
                    else
                    {
                        _logger.LogWarning("osquery queries file not found in either {ProgramData} or {ProgramFiles}", 
                            Path.Combine(programDataPath, "queries.json"),
                            Path.Combine(ConfigurationService.GetApplicationDirectory(), "osquery-queries.json"));
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
                _logger.LogInformation("osquery not available, skipping osquery data collection");
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

    private string GetOperatingSystemInfo()
    {
        try
        {
            var os = Environment.OSVersion;
            var version = os.Version;
            var servicePack = os.ServicePack;
            
            var osName = "Windows";
            
            // Try to get more specific Windows version
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    osName = obj["Caption"]?.ToString() ?? "Windows";
                    break;
                }
            }
            catch
            {
                // Fallback to generic Windows version
            }
            
            var result = $"{osName} {version}";
            if (!string.IsNullOrEmpty(servicePack))
            {
                result += $" {servicePack}";
            }
            
            return result;
        }
        catch
        {
            return "Windows (Unknown Version)";
        }
    }

    private TimeSpan GetSystemUptime()
    {
        try
        {
            return TimeSpan.FromMilliseconds(Environment.TickCount64);
        }
        catch
        {
            return TimeSpan.Zero;
        }
    }

    private DateTime? GetLastBootTime()
    {
        try
        {
            var uptime = GetSystemUptime();
            return DateTime.UtcNow - uptime;
        }
        catch
        {
            return null;
        }
    }

    private async Task<List<DiskInfo>> GetDiskInfoAsync()
    {
        var diskInfoList = new List<DiskInfo>();

        try
        {
            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed);
            
            foreach (var drive in drives)
            {
                try
                {
                    var diskInfo = new DiskInfo
                    {
                        Drive = drive.Name,
                        TotalSizeGB = Math.Round(drive.TotalSize / (1024.0 * 1024.0 * 1024.0), 2),
                        FreeSpaceGB = Math.Round(drive.TotalFreeSpace / (1024.0 * 1024.0 * 1024.0), 2),
                        FileSystem = drive.DriveFormat
                    };
                    
                    diskInfo.UsedSpaceGB = diskInfo.TotalSizeGB - diskInfo.FreeSpaceGB;
                    diskInfo.UsedPercentage = diskInfo.TotalSizeGB > 0 ? Math.Round((diskInfo.UsedSpaceGB / diskInfo.TotalSizeGB) * 100, 1) : 0;
                    
                    diskInfoList.Add(diskInfo);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error getting info for drive {Drive}", drive.Name);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting disk information");
        }

        return diskInfoList;
    }

    private async Task<bool> CheckWindowsDefenderAsync()
    {
        try
        {
            // Check Windows Defender status using WMI
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT AntivirusEnabled FROM MSFT_MpComputerStatus");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["AntivirusEnabled"] != null && (bool)obj["AntivirusEnabled"];
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check Windows Defender status");
        }
        
        return false;
    }

    private async Task<bool> CheckFirewallStatusAsync()
    {
        try
        {
            // Check Windows Firewall status for domain profile
            using var searcher = new ManagementObjectSearcher("SELECT EnabledDomainProfile FROM Win32_FirewallProfile WHERE ProfileName='Domain'");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["EnabledDomainProfile"] != null && (bool)obj["EnabledDomainProfile"];
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check firewall status");
        }
        
        return false;
    }

    private bool CheckUacStatus()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var value = key?.GetValue("EnableLUA");
            return value != null && (int)value == 1;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check UAC status");
            return false;
        }
    }

    private async Task<bool> CheckBitLockerStatusAsync()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2\security\microsoftvolumeencryption", "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='C:'");
            foreach (ManagementObject obj in searcher.Get())
            {
                var status = obj["ProtectionStatus"];
                return status != null && (uint)status == 1; // 1 = Protection On
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check BitLocker status");
        }
        
        return false;
    }

    private async Task<bool> CheckTpmStatusAsync()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2\security\microsofttpm", "SELECT IsEnabled_InitialValue FROM Win32_Tpm");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["IsEnabled_InitialValue"] != null && (bool)obj["IsEnabled_InitialValue"];
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check TPM status");
        }
        
        return false;
    }

    private async Task<DateTime?> GetLastUpdateCheckAsync()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect");
            var lastCheck = key?.GetValue("LastSuccessTime")?.ToString();
            
            if (!string.IsNullOrEmpty(lastCheck) && DateTime.TryParseExact(lastCheck, "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out var date))
            {
                return date;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get last update check time");
        }
        
        return null;
    }

    private async Task<string?> GetHardwareSerialNumberAsync()
    {
        try
        {
            // Try to get the BIOS serial number first (most reliable for physical machines)
            using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
            foreach (ManagementObject obj in searcher.Get())
            {
                var serial = obj["SerialNumber"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                {
                    _logger.LogDebug("Found BIOS serial number: {Serial}", serial);
                    return serial;
                }
            }

            // Fallback to motherboard serial number
            using var mbSearcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
            foreach (ManagementObject obj in mbSearcher.Get())
            {
                var serial = obj["SerialNumber"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                {
                    _logger.LogDebug("Found motherboard serial number: {Serial}", serial);
                    return serial;
                }
            }

            // Fallback to computer system UUID
            using var csSearcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject obj in csSearcher.Get())
            {
                var uuid = obj["UUID"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(uuid) && !IsGenericSerial(uuid))
                {
                    _logger.LogDebug("Found computer system UUID: {UUID}", uuid);
                    return uuid;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not retrieve hardware serial number");
        }

        _logger.LogWarning("Could not find a valid hardware serial number, will use machine name");
        return null;
    }

    private bool IsGenericSerial(string serial)
    {
        // Filter out common generic/placeholder serial numbers
        var genericSerials = new[]
        {
            "To be filled by O.E.M.",
            "System Serial Number",
            "INVALID",
            "Default string",
            "Not Specified",
            "None",
            "N/A",
            "0123456789",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
        };

        return genericSerials.Any(g => string.Equals(serial, g, StringComparison.OrdinalIgnoreCase)) ||
               serial.All(c => c == '0' || c == 'F' || c == '-');
    }
}

// Data transfer objects
public class DeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public double TotalMemoryGB { get; set; }
    public DateTime LastSeen { get; set; }
    public string ClientVersion { get; set; } = string.Empty;
}

public class SystemInfo
{
    public string OperatingSystem { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public int ProcessorCount { get; set; }
    public string ProcessorName { get; set; } = string.Empty;
    public uint ProcessorSpeedMHz { get; set; }
    public TimeSpan Uptime { get; set; }
    public DateTime? LastBootTime { get; set; }
    public string TimeZone { get; set; } = string.Empty;
    public List<DiskInfo> DiskInfo { get; set; } = new();
}

public class DiskInfo
{
    public string Drive { get; set; } = string.Empty;
    public double TotalSizeGB { get; set; }
    public double FreeSpaceGB { get; set; }
    public double UsedSpaceGB { get; set; }
    public double UsedPercentage { get; set; }
    public string FileSystem { get; set; } = string.Empty;
}

public class SecurityInfo
{
    public bool WindowsDefenderEnabled { get; set; }
    public bool FirewallEnabled { get; set; }
    public bool UacEnabled { get; set; }
    public bool BitLockerEnabled { get; set; }
    public bool TpmAvailable { get; set; }
    public DateTime? LastUpdateCheck { get; set; }
}
