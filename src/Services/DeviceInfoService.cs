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
            // Get hardware info from osquery
            var (manufacturer, model, serialNumber) = await GetHardwareInfoFromOsQueryAsync();
            
            // Use hardware serial as device ID if available, otherwise fall back to environment
            var deviceId = !string.IsNullOrEmpty(serialNumber) && !IsGenericSerial(serialNumber)
                ? serialNumber
                : Environment.MachineName;

            var deviceInfo = new DeviceInfo
            {
                DeviceId = deviceId,
                SerialNumber = serialNumber ?? "UNKNOWN-" + Environment.MachineName,
                ComputerName = Environment.MachineName,
                Domain = Environment.UserDomainName,
                OperatingSystem = await GetOperatingSystemInfoAsync(),
                Manufacturer = manufacturer ?? "Unknown",
                Model = model ?? "Unknown",
                LastSeen = DateTime.UtcNow,
                ClientVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0"
            };

            _logger.LogInformation("DeviceInfo created - DeviceId: '{DeviceId}', SerialNumber: '{SerialNumber}', ComputerName: '{ComputerName}'", 
                deviceInfo.DeviceId, deviceInfo.SerialNumber, deviceInfo.ComputerName);
            
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
                OperatingSystem = await GetOperatingSystemInfoAsync(),
                Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                ProcessorCount = Environment.ProcessorCount,
                Uptime = GetSystemUptime(),
                LastBootTime = GetLastBootTime(),
                TimeZone = TimeZoneInfo.Local.DisplayName
            };

            // Get processor info from osquery
            try
            {
                var systemInfoResult = await _osQueryService.ExecuteQueryAsync("SELECT cpu_brand, cpu_physical_cores, cpu_logical_cores, physical_memory FROM system_info;");
                
                if (systemInfoResult?.Any() == true)
                {
                    if (systemInfoResult.TryGetValue("cpu_brand", out var cpuBrand) && !string.IsNullOrEmpty(cpuBrand?.ToString()))
                    {
                        systemInfo.ProcessorName = cpuBrand.ToString()!;
                    }
                    
                    if (systemInfoResult.TryGetValue("cpu_physical_cores", out var physicalCores) && 
                        int.TryParse(physicalCores?.ToString(), out var physicalCount))
                    {
                        systemInfo.ProcessorCount = physicalCount;
                    }
                    
                    if (systemInfoResult.TryGetValue("physical_memory", out var memoryBytes) && 
                        long.TryParse(memoryBytes?.ToString(), out var memBytes))
                    {
                        systemInfo.TotalMemoryGB = Math.Round(memBytes / (1024.0 * 1024.0 * 1024.0), 2);
                    }
                    
                    _logger.LogDebug("osquery processor info: {ProcessorName}, {ProcessorCount} cores, {TotalMemoryGB}GB RAM", 
                        systemInfo.ProcessorName, systemInfo.ProcessorCount, systemInfo.TotalMemoryGB);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve processor info from osquery, using fallback values");
                systemInfo.ProcessorName = "Unknown";
                systemInfo.ProcessorSpeedMHz = 0;
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
                TmpAvailable = await CheckTmpStatusAsync(),
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

    private async Task<string> GetOperatingSystemInfoAsync()
    {
        try
        {
            var osVersionResult = await _osQueryService.ExecuteQueryAsync("SELECT name, version, build, platform, arch FROM os_version;");
            
            if (osVersionResult?.Any() == true)
            {
                string osName = osVersionResult.TryGetValue("name", out var name) ? name?.ToString() ?? "Windows" : "Windows";
                string osVersion = osVersionResult.TryGetValue("version", out var version) ? version?.ToString() ?? "" : "";
                string osBuild = osVersionResult.TryGetValue("build", out var build) ? build?.ToString() ?? "" : "";
                string osArch = osVersionResult.TryGetValue("arch", out var arch) ? arch?.ToString() ?? "" : "";
                
                var result = osName ?? "Windows";
                if (!string.IsNullOrEmpty(osVersion))
                {
                    result += $" {osVersion}";
                }
                if (!string.IsNullOrEmpty(osBuild))
                {
                    result += $" (Build {osBuild})";
                }
                if (!string.IsNullOrEmpty(osArch))
                {
                    result += $" {osArch}";
                }
                
                _logger.LogDebug("osquery OS info: {OSInfo}", result);
                return result;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not retrieve OS info from osquery, using fallback");
        }
        
        // Fallback to Environment.OSVersion
        try
        {
            var os = Environment.OSVersion;
            var result = $"Windows {os.Version}";
            if (!string.IsNullOrEmpty(os.ServicePack))
            {
                result += $" {os.ServicePack}";
            }
            
            return result;
        }
        catch
        {
            return "Windows (Unknown Version)";
        }
    }

    private async Task<(string? manufacturer, string? model, string? serialNumber)> GetHardwareInfoFromOsQueryAsync()
    {
        try
        {
            var hardwareResult = await _osQueryService.ExecuteQueryAsync("SELECT hardware_vendor, hardware_model, hardware_serial FROM system_info;");
            
            if (hardwareResult?.Any() == true)
            {
                var manufacturer = hardwareResult.TryGetValue("hardware_vendor", out var vendor) ? vendor?.ToString() : null;
                var model = hardwareResult.TryGetValue("hardware_model", out var modelObj) ? modelObj?.ToString() : null;
                var serialNumber = hardwareResult.TryGetValue("hardware_serial", out var serial) ? serial?.ToString() : null;
                
                _logger.LogDebug("osquery hardware info: Manufacturer={Manufacturer}, Model={Model}, Serial={Serial}", 
                    manufacturer, model, serialNumber);
                
                return (manufacturer, model, serialNumber);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not retrieve hardware info from osquery");
        }
        
        return (null, null, null);
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

    private Task<List<DiskInfo>> GetDiskInfoAsync()
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

        return Task.FromResult(diskInfoList);
    }

    private async Task<bool> CheckWindowsDefenderAsync()
    {
        try
        {
            var securityCenterResult = await _osQueryService.ExecuteQueryAsync("SELECT antivirus FROM windows_security_center;");
            
            if (securityCenterResult?.Any() == true)
            {
                if (securityCenterResult.TryGetValue("antivirus", out var antivirus) && !string.IsNullOrEmpty(antivirus?.ToString()))
                {
                    var antivirusStr = antivirus.ToString()!;
                    var defenderEnabled = antivirusStr.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) ||
                                         antivirusStr.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase);
                    
                    _logger.LogDebug("osquery antivirus status: {Antivirus}, Defender enabled: {DefenderEnabled}", 
                        antivirusStr, defenderEnabled);
                    
                    return defenderEnabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check Windows Defender status via osquery, trying PowerShell fallback");
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrWhiteSpace(output) && bool.TryParse(output.Trim(), out var enabled))
                {
                    _logger.LogDebug("PowerShell Defender status: {Enabled}", enabled);
                    return enabled;
                }
            }
            catch (Exception psEx)
            {
                _logger.LogDebug(psEx, "PowerShell fallback also failed for Windows Defender status");
            }
        }
        
        return false;
    }

    private async Task<bool> CheckFirewallStatusAsync()
    {
        try
        {
            var securityCenterResult = await _osQueryService.ExecuteQueryAsync("SELECT firewall FROM windows_security_center;");
            
            if (securityCenterResult?.Any() == true)
            {
                if (securityCenterResult.TryGetValue("firewall", out var firewall) && !string.IsNullOrEmpty(firewall?.ToString()))
                {
                    var firewallStr = firewall.ToString()!;
                    var firewallEnabled = firewallStr.Contains("On", StringComparison.OrdinalIgnoreCase) ||
                                         firewallStr.Contains("Enabled", StringComparison.OrdinalIgnoreCase);
                    
                    _logger.LogDebug("osquery firewall status: {Firewall}, Enabled: {FirewallEnabled}", 
                        firewallStr, firewallEnabled);
                    
                    return firewallEnabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check firewall status via osquery, trying PowerShell fallback");
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty Enabled\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrWhiteSpace(output) && bool.TryParse(output.Trim(), out var enabled))
                {
                    _logger.LogDebug("PowerShell firewall status: {Enabled}", enabled);
                    return enabled;
                }
            }
            catch (Exception psEx)
            {
                _logger.LogDebug(psEx, "PowerShell fallback also failed for firewall status");
            }
        }
        
        return false;
    }

    private bool CheckUacStatus()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var enableLua = key?.GetValue("EnableLUA");
            return enableLua != null && enableLua.ToString() == "1";
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
            var bitlockerResult = await _osQueryService.ExecuteQueryAsync("SELECT device_id, conversion_status, protection_status FROM bitlocker_info WHERE drive_letter = 'C:';");
            
            if (bitlockerResult?.Any() == true)
            {
                if (bitlockerResult.TryGetValue("protection_status", out var protectionStatus) && !string.IsNullOrEmpty(protectionStatus?.ToString()))
                {
                    var protectionStr = protectionStatus.ToString()!;
                    var isProtected = protectionStr.Equals("On", StringComparison.OrdinalIgnoreCase) ||
                                     protectionStr.Equals("1", StringComparison.OrdinalIgnoreCase);
                    
                    _logger.LogDebug("osquery BitLocker status: {ProtectionStatus}, Protected: {IsProtected}", 
                        protectionStr, isProtected);
                    
                    return isProtected;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check BitLocker status via osquery, trying PowerShell fallback");
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty ProtectionStatus\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrWhiteSpace(output))
                {
                    var result = output.Trim();
                    var isProtected = result.Equals("On", StringComparison.OrdinalIgnoreCase);
                    _logger.LogDebug("PowerShell BitLocker status: {ProtectionStatus}", result);
                    return isProtected;
                }
            }
            catch (Exception psEx)
            {
                _logger.LogDebug(psEx, "PowerShell fallback also failed for BitLocker status");
            }
        }
        
        return false;
    }

    private async Task<bool> CheckTmpStatusAsync()
    {
        try
        {
            var tpmResult = await _osQueryService.ExecuteQueryAsync("SELECT activated, enabled FROM tpm_info;");
            
            if (tpmResult?.Any() == true)
            {
                if (tpmResult.TryGetValue("activated", out var activated) && tpmResult.TryGetValue("enabled", out var enabled))
                {
                    var isActivated = (activated?.ToString() == "1") || (activated?.ToString()?.Equals("true", StringComparison.OrdinalIgnoreCase) == true);
                    var isEnabled = (enabled?.ToString() == "1") || (enabled?.ToString()?.Equals("true", StringComparison.OrdinalIgnoreCase) == true);
                    
                    var tpmAvailable = isActivated && isEnabled;
                    _logger.LogDebug("osquery TPM status: Activated={Activated}, Enabled={Enabled}, Available={Available}", 
                        isActivated, isEnabled, tpmAvailable);
                    
                    return tpmAvailable;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check TPM status via osquery, trying PowerShell fallback");
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-Tpm | Select-Object -ExpandProperty TmpPresent\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrWhiteSpace(output) && bool.TryParse(output.Trim(), out var present))
                {
                    _logger.LogDebug("PowerShell TPM status: {TmpPresent}", present);
                    return present;
                }
            }
            catch (Exception psEx)
            {
                _logger.LogDebug(psEx, "PowerShell fallback also failed for TPM status");
            }
        }
        
        return false;
    }

    private Task<DateTime?> GetLastUpdateCheckAsync()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect");
            var lastCheck = key?.GetValue("LastSuccessTime")?.ToString();
            
            if (!string.IsNullOrEmpty(lastCheck) && DateTime.TryParseExact(lastCheck, "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out var date))
            {
                return Task.FromResult<DateTime?>(date);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get last update check time");
        }
        
        return Task.FromResult<DateTime?>(null);
    }

    private bool IsGenericSerial(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
            return true;
            
        var genericSerials = new[]
        {
            "0000000000", "1234567890", "123456789", "000000000",
            "FFFFFFFF", "00000000", "11111111", "12345678",
            "System Serial Number", "To be filled by O.E.M.", "Default string",
            "Not Specified", "Not Available", "N/A", "None", "Unknown",
            "INVALID", "CHASSIS", "DESKTOP", "LAPTOP", "NOTEBOOK",
            "XXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXX"
        };
        
        return genericSerials.Any(g => string.Equals(serial, g, StringComparison.OrdinalIgnoreCase));
    }
}

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
}

public class SystemInfo
{
    public string OperatingSystem { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public int ProcessorCount { get; set; }
    public string ProcessorName { get; set; } = string.Empty;
    public uint ProcessorSpeedMHz { get; set; }
    public double TotalMemoryGB { get; set; }
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
    public bool TmpAvailable { get; set; }
    public DateTime? LastUpdateCheck { get; set; }
}
