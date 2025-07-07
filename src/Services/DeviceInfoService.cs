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
            // Get hardware UUID as the primary device ID
            var hardwareUuid = await GetHardwareUuidAsync();
            
            // Get hardware info from osquery
            var (manufacturer, model, serialNumber) = await GetHardwareInfoFromOsQueryAsync();
            
            // Get the Windows sharing name (NetBIOS name)
            var computerName = await GetWindowsSharingNameAsync();
            var domain = GetDomainName();
            
            // Get asset tag from inventory file
            var assetTag = await GetAssetTagFromInventoryAsync();
            
            // Get granular OS information
            var (osName, osVersion, osBuild, osArchitecture, fullOsString) = await GetOperatingSystemInfoAsync();
            var osInstallDate = await GetOsInstallDateAsync();
            var experiencePack = await GetExperiencePackVersionAsync();
            
            // Get MDM enrollment information
            var (mdmEnrollmentId, mdmEnrollmentType, mdmEnrollmentState, mdmManagementUrl) = await GetMdmEnrollmentInfoAsync();

            var deviceInfo = new DeviceInfo
            {
                DeviceId = hardwareUuid,
                SerialNumber = serialNumber ?? "UNKNOWN-" + Environment.MachineName,
                ComputerName = computerName,
                Domain = domain,
                OperatingSystem = fullOsString,
                Manufacturer = manufacturer ?? "Unknown",
                Model = model ?? "Unknown",
                LastSeen = DateTime.UtcNow,
                ClientVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0",
                AssetTag = assetTag,
                OsName = osName,
                OsVersion = osVersion,
                OsBuild = osBuild,
                OsArchitecture = osArchitecture,
                OsInstallDate = osInstallDate,
                ExperiencePack = experiencePack,
                MdmEnrollmentId = mdmEnrollmentId,
                MdmEnrollmentType = mdmEnrollmentType,
                MdmEnrollmentState = mdmEnrollmentState,
                MdmManagementUrl = mdmManagementUrl
            };

            // Get memory info for the device
            try
            {
                var systemInfoResult = await _osQueryService.ExecuteQueryAsync("SELECT physical_memory FROM system_info;");
                if (systemInfoResult?.Any() == true && systemInfoResult.TryGetValue("physical_memory", out var memoryBytes))
                {
                    if (long.TryParse(memoryBytes?.ToString(), out var memBytes))
                    {
                        deviceInfo.TotalMemoryGB = Math.Round(memBytes / (1024.0 * 1024.0 * 1024.0), 2);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not get memory info from osquery");
            }

            _logger.LogInformation("DeviceInfo created - DeviceId: '{DeviceId}', SerialNumber: '{SerialNumber}', ComputerName: '{ComputerName}', OS: '{OsName} {OsVersion}'", 
                deviceInfo.DeviceId, deviceInfo.SerialNumber, deviceInfo.ComputerName, deviceInfo.OsName, deviceInfo.OsVersion);
            
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
            // Get granular OS information
            var (osName, osVersion, osBuild, osArchitecture, fullOsString) = await GetOperatingSystemInfoAsync();
            
            var systemInfo = new SystemInfo
            {
                OperatingSystem = fullOsString,
                Architecture = osArchitecture,
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

            // Try to get more detailed hardware info from osquery
            try
            {
                var cpuInfoResult = await _osQueryService.ExecuteQueryAsync("SELECT max_clock_speed FROM cpu_info LIMIT 1;");
                if (cpuInfoResult?.Any() == true && cpuInfoResult.TryGetValue("max_clock_speed", out var clockSpeed))
                {
                    if (uint.TryParse(clockSpeed?.ToString(), out var speed))
                    {
                        systemInfo.ProcessorSpeedMHz = speed;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve CPU clock speed from osquery");
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

    private async Task<(string osName, string osVersion, string osBuild, string osArchitecture, string fullOsString)> GetOperatingSystemInfoAsync()
    {
        string osName = "Windows";
        string osVersion = "";
        string osBuild = "";
        string osArchitecture = "";
        
        try
        {
            var osVersionResult = await _osQueryService.ExecuteQueryAsync("SELECT name, version, build, platform, arch FROM os_version;");
            
            if (osVersionResult?.Any() == true)
            {
                var rawName = osVersionResult.TryGetValue("name", out var name) ? name?.ToString() ?? "Windows" : "Windows";
                var rawVersion = osVersionResult.TryGetValue("version", out var version) ? version?.ToString() ?? "" : "";
                var rawBuild = osVersionResult.TryGetValue("build", out var build) ? build?.ToString() ?? "" : "";
                osArchitecture = osVersionResult.TryGetValue("arch", out var arch) ? arch?.ToString() ?? "" : "";
                
                // Get UBR (Update Build Revision) to create full build number
                var fullBuild = rawBuild;
                try
                {
                    var ubrResult = await _osQueryService.ExecuteQueryAsync(
                        "SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'UBR';");
                    
                    if (ubrResult?.Any() == true && ubrResult.TryGetValue("data", out var ubrData))
                    {
                        var ubrStr = ubrData?.ToString();
                        if (!string.IsNullOrEmpty(ubrStr) && !string.IsNullOrEmpty(rawBuild))
                        {
                            fullBuild = $"{rawBuild}.{ubrStr}";
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not get UBR from registry");
                }
                
                // Process the OS name to extract clean version
                osName = ProcessWindowsOsName(rawName);
                osVersion = ProcessWindowsVersion(rawVersion, rawBuild);
                osBuild = fullBuild;
                
                var fullOsString = $"{osName} {osVersion} (Build {osBuild})";
                
                _logger.LogDebug("Processed OS info: {OSName} {OSVersion} Build {OSBuild} {OSArchitecture}", 
                    osName, osVersion, osBuild, osArchitecture);
                
                return (osName, osVersion, osBuild, osArchitecture, fullOsString);
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
            osName = "Windows";
            osVersion = GetWindowsVersionName(os.Version);
            osBuild = os.Version.Build.ToString();
            osArchitecture = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            
            var fullOsString = $"{osName} {osVersion} (Build {osBuild})";
            
            return (osName, osVersion, osBuild, osArchitecture, fullOsString);
        }
        catch
        {
            return ("Windows", "Unknown", "", "", "Windows (Unknown Version)");
        }
    }

    private string ProcessWindowsOsName(string rawName)
    {
        if (string.IsNullOrEmpty(rawName))
            return "Windows";

        // Extract the clean OS name (e.g., "Microsoft Windows 11 Enterprise" -> "Windows 11 Enterprise")
        var cleanName = rawName.Replace("Microsoft ", "");
        
        // Remove version numbers and build info from the name
        var parts = cleanName.Split(' ');
        var processedParts = new List<string>();
        
        foreach (var part in parts)
        {
            // Skip parts that look like version numbers or build info
            if (part.Contains('.') || part.StartsWith('(') || part.StartsWith("10.0"))
                break;
            processedParts.Add(part);
        }
        
        return string.Join(" ", processedParts);
    }

    private string ProcessWindowsVersion(string rawVersion, string rawBuild)
    {
        if (string.IsNullOrEmpty(rawVersion))
            return "";

        // Map Windows 10/11 builds to version names
        if (int.TryParse(rawBuild, out var buildNumber))
        {
            return GetWindowsVersionFromBuild(buildNumber);
        }

        // Extract version from raw version string (e.g., "10.0.26100" -> "24H2")
        var versionParts = rawVersion.Split('.');
        if (versionParts.Length >= 3 && int.TryParse(versionParts[2], out var build))
        {
            return GetWindowsVersionFromBuild(build);
        }

        return rawVersion;
    }

    private string ProcessWindowsBuild(string rawBuild)
    {
        if (string.IsNullOrEmpty(rawBuild))
            return "";

        // Try to get the detailed build number including UBR (Update Build Revision)
        // This should return something like "26100.4349" instead of just "26100"
        return rawBuild;
    }

    private string GetWindowsVersionFromBuild(int buildNumber)
    {
        // Windows 11 version mapping
        if (buildNumber >= 22000)
        {
            return buildNumber switch
            {
                >= 26100 => "24H2",
                >= 22631 => "23H2", 
                >= 22621 => "22H2",
                >= 22000 => "21H2",
                _ => "Unknown"
            };
        }
        
        // Windows 10 version mapping
        if (buildNumber >= 10240)
        {
            return buildNumber switch
            {
                >= 19045 => "22H2",
                >= 19044 => "21H2",
                >= 19043 => "21H1",
                >= 19042 => "20H2",
                >= 19041 => "2004",
                >= 18363 => "1909",
                >= 18362 => "1903",
                >= 17763 => "1809",
                >= 17134 => "1803",
                >= 16299 => "1709",
                >= 15063 => "1703",
                >= 14393 => "1607",
                >= 10586 => "1511",
                >= 10240 => "1507",
                _ => "Unknown"
            };
        }

        return buildNumber.ToString();
    }

    private string GetWindowsVersionName(Version version)
    {
        // Fallback version mapping based on Version object
        if (version.Major == 10)
        {
            return GetWindowsVersionFromBuild(version.Build);
        }
        
        return version.ToString();
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

    private async Task<string> GetHardwareUuidAsync()
    {
        try
        {
            // Try to get hardware UUID from osquery first
            var uuidResult = await _osQueryService.ExecuteQueryAsync("SELECT uuid FROM system_info;");
            if (uuidResult?.Any() == true && uuidResult.TryGetValue("uuid", out var uuid) && !string.IsNullOrEmpty(uuid?.ToString()))
            {
                var uuidStr = uuid.ToString()!;
                if (IsValidUuid(uuidStr))
                {
                    _logger.LogDebug("Hardware UUID from osquery: {UUID}", uuidStr);
                    return uuidStr;
                }
            }

            // Fallback to WMI if osquery doesn't work
            var wmiUuid = await GetUuidFromWmiAsync();
            if (!string.IsNullOrEmpty(wmiUuid) && IsValidUuid(wmiUuid))
            {
                _logger.LogDebug("Hardware UUID from WMI: {UUID}", wmiUuid);
                return wmiUuid;
            }

            // Last resort: generate a persistent UUID based on hardware characteristics
            var fallbackUuid = await GeneratePersistentUuidAsync();
            _logger.LogWarning("Using generated persistent UUID: {UUID}", fallbackUuid);
            return fallbackUuid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting hardware UUID, using fallback");
            return await GeneratePersistentUuidAsync();
        }
    }

    private async Task<string> GetUuidFromWmiAsync()
    {
        try
        {
            // First try to get UUID from system_info table
            var result = await _osQueryService.ExecuteQueryAsync("SELECT uuid FROM system_info;");
            if (result?.Any() == true && result.TryGetValue("uuid", out var uuid))
            {
                var uuidStr = uuid?.ToString();
                if (!string.IsNullOrEmpty(uuidStr) && IsValidUuid(uuidStr))
                {
                    _logger.LogDebug("UUID from system_info: {UUID}", uuidStr);
                    return uuidStr;
                }
            }

            // Try alternative WMI approach via osquery
            var wmiResult = await _osQueryService.ExecuteQueryAsync("SELECT SerialNumber FROM Win32_ComputerSystemProduct;");
            if (wmiResult?.Any() == true && wmiResult.TryGetValue("SerialNumber", out var serialUuid))
            {
                var serialUuidStr = serialUuid?.ToString();
                if (!string.IsNullOrEmpty(serialUuidStr) && IsValidUuid(serialUuidStr))
                {
                    _logger.LogDebug("UUID from Win32_ComputerSystemProduct: {UUID}", serialUuidStr);
                    return serialUuidStr;
                }
            }

            // Try to get UUID from BIOS
            var biosResult = await _osQueryService.ExecuteQueryAsync("SELECT uuid FROM wmi_bios_data;");
            if (biosResult?.Any() == true && biosResult.TryGetValue("uuid", out var biosUuid))
            {
                var biosUuidStr = biosUuid?.ToString();
                if (!string.IsNullOrEmpty(biosUuidStr) && IsValidUuid(biosUuidStr))
                {
                    _logger.LogDebug("UUID from BIOS: {UUID}", biosUuidStr);
                    return biosUuidStr;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get UUID from WMI via osquery");
        }
        return "";
    }

    private async Task<string> GeneratePersistentUuidAsync()
    {
        try
        {
            // Get hardware characteristics for generating a persistent UUID
            var (manufacturer, model, serialNumber) = await GetHardwareInfoFromOsQueryAsync();
            var machineName = Environment.MachineName;
            
            // Create a consistent seed from hardware info
            var seed = $"{manufacturer}-{model}-{serialNumber}-{machineName}";
            var hash = System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(seed));
            
            // Convert to UUID format
            var uuid = new Guid(hash).ToString();
            return uuid;
        }
        catch
        {
            return Guid.NewGuid().ToString();
        }
    }

    private static bool IsValidUuid(string uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid))
            return false;

        // Check if it's a valid GUID format
        if (!Guid.TryParse(uuid, out var guid))
            return false;

        // Reject common invalid/default UUIDs
        var invalidUuids = new[]
        {
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "03000200-0400-0500-0006-000700080009" // Common default
        };

        return !invalidUuids.Contains(uuid.ToUpperInvariant());
    }

    private async Task<string> GetWindowsSharingNameAsync()
    {
        try
        {
            // First try to get the current computer name from the registry via osquery
            // This preserves the original casing as set by the user
            var registryResult = await _osQueryService.ExecuteQueryAsync(
                "SELECT data FROM registry WHERE path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\\ComputerName';"
            );
            if (registryResult?.Any() == true && registryResult.TryGetValue("data", out var registryData))
            {
                var registryName = registryData?.ToString();
                if (!string.IsNullOrEmpty(registryName))
                {
                    _logger.LogDebug("Computer name from registry via osquery: {ComputerName}", registryName);
                    return registryName;
                }
            }

            // Fallback to hostname from system_info - this may be uppercase/lowercase
            var hostnameResult = await _osQueryService.ExecuteQueryAsync("SELECT hostname FROM system_info;");
            if (hostnameResult?.Any() == true && hostnameResult.TryGetValue("hostname", out var hostname))
            {
                var hostnameStr = hostname?.ToString();
                if (!string.IsNullOrEmpty(hostnameStr))
                {
                    _logger.LogDebug("Computer name from osquery hostname: {ComputerName}", hostnameStr);
                    return hostnameStr;
                }
            }

            // Fallback to registry to get the original computer name (preserves case)
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName");
                var registryName = key?.GetValue("ComputerName")?.ToString();
                if (!string.IsNullOrEmpty(registryName))
                {
                    _logger.LogDebug("Computer name from registry: {ComputerName}", registryName);
                    return registryName;
                }
            }
            catch (Exception regEx)
            {
                _logger.LogDebug(regEx, "Could not get computer name from registry");
            }

            // Try alternative registry location
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName");
                var registryName = key?.GetValue("ComputerName")?.ToString();
                if (!string.IsNullOrEmpty(registryName))
                {
                    _logger.LogDebug("Computer name from ActiveComputerName registry: {ComputerName}", registryName);
                    return registryName;
                }
            }
            catch (Exception regEx)
            {
                _logger.LogDebug(regEx, "Could not get computer name from ActiveComputerName registry");
            }

            // Last resort: Environment.MachineName - use as-is without case conversion
            var machineName = Environment.MachineName;
            if (!string.IsNullOrEmpty(machineName))
            {
                _logger.LogDebug("Using Environment.MachineName as-is: {MachineName}", machineName);
                return machineName;
            }
            
            return "Unknown";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get Windows sharing name");
            // Return Environment.MachineName as-is without case conversion
            return Environment.MachineName;
        }
    }

    private string GetDomainName()
    {
        try
        {
            return Environment.UserDomainName ?? "WORKGROUP";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get domain name");
            return "WORKGROUP";
        }
    }

    private async Task<string> GetAssetTagFromInventoryAsync()
    {
        try
        {
            var inventoryPath = @"C:\ProgramData\Management\Inventory.yaml";
            if (!File.Exists(inventoryPath))
            {
                _logger.LogDebug("Inventory file not found at {Path}", inventoryPath);
                return "";
            }

            var content = await File.ReadAllTextAsync(inventoryPath);
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                if (trimmedLine.StartsWith("asset:", StringComparison.OrdinalIgnoreCase))
                {
                    var assetTag = trimmedLine.Substring(6).Trim();
                    _logger.LogDebug("Found asset tag in inventory: {AssetTag}", assetTag);
                    return assetTag;
                }
            }

            _logger.LogDebug("No asset tag found in inventory file");
            return "";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read asset tag from inventory file");
            return "";
        }
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

    private async Task<DateTime?> GetOsInstallDateAsync()
    {
        try
        {
            // Try to get install date from osquery
            var osDetailsResult = await _osQueryService.ExecuteQueryAsync("SELECT install_date FROM os_version;");
            if (osDetailsResult?.Any() == true && osDetailsResult.TryGetValue("install_date", out var installDate))
            {
                var installDateStr = installDate?.ToString();
                if (!string.IsNullOrEmpty(installDateStr))
                {
                    // Try to parse Unix timestamp
                    if (long.TryParse(installDateStr, out var timestamp))
                    {
                        var dateTime = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
                        _logger.LogDebug("OS install date from osquery: {InstallDate}", dateTime);
                        return dateTime;
                    }
                    
                    // Try to parse regular date format
                    if (DateTime.TryParse(installDateStr, out var parsedDate))
                    {
                        _logger.LogDebug("OS install date from osquery (parsed): {InstallDate}", parsedDate);
                        return parsedDate;
                    }
                }
            }

            // Fallback to registry
            var registryResult = await _osQueryService.ExecuteQueryAsync(
                "SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'InstallDate';");
            
            if (registryResult?.Any() == true && registryResult.TryGetValue("data", out var regData))
            {
                var regDataStr = regData?.ToString();
                if (!string.IsNullOrEmpty(regDataStr) && uint.TryParse(regDataStr, out var regTimestamp))
                {
                    // Registry InstallDate is a Unix timestamp
                    var dateTime = DateTimeOffset.FromUnixTimeSeconds(regTimestamp).DateTime;
                    _logger.LogDebug("OS install date from registry: {InstallDate}", dateTime);
                    return dateTime;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get OS install date");
        }
        
        return null;
    }

    private async Task<string> GetExperiencePackVersionAsync()
    {
        try
        {
            // Get UBR (Update Build Revision) from registry
            var ubrResult = await _osQueryService.ExecuteQueryAsync(
                "SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'UBR';");
            
            if (ubrResult?.Any() == true && ubrResult.TryGetValue("data", out var ubrData))
            {
                var ubrStr = ubrData?.ToString();
                if (!string.IsNullOrEmpty(ubrStr))
                {
                    // Get current build number
                    var buildResult = await _osQueryService.ExecuteQueryAsync(
                        "SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' AND name = 'CurrentBuild';");
                    
                    if (buildResult?.Any() == true && buildResult.TryGetValue("data", out var buildData))
                    {
                        var buildStr = buildData?.ToString();
                        if (!string.IsNullOrEmpty(buildStr))
                        {
                            var experiencePack = $"1000.{buildStr}.{ubrStr}.0";
                            _logger.LogDebug("Experience pack version: {ExperiencePack}", experiencePack);
                            return experiencePack;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get experience pack version");
        }
        
        return "";
    }

    private async Task<(string enrollmentId, string enrollmentType, string enrollmentState, string managementUrl)> GetMdmEnrollmentInfoAsync()
    {
        try
        {
            // Try to get MDM enrollment from osquery mdm_enrollment table
            var mdmResult = await _osQueryService.ExecuteQueryAsync("SELECT enrollment_id, enrollment_type, enrollment_state, management_service_url FROM mdm_enrollment;");
            
            if (mdmResult?.Any() == true)
            {
                var enrollmentId = mdmResult.TryGetValue("enrollment_id", out var id) ? id?.ToString() ?? "" : "";
                var enrollmentType = mdmResult.TryGetValue("enrollment_type", out var type) ? type?.ToString() ?? "" : "";
                var enrollmentState = mdmResult.TryGetValue("enrollment_state", out var state) ? state?.ToString() ?? "" : "";
                var managementUrl = mdmResult.TryGetValue("management_service_url", out var url) ? url?.ToString() ?? "" : "";
                
                if (!string.IsNullOrEmpty(enrollmentId) || !string.IsNullOrEmpty(enrollmentType))
                {
                    _logger.LogDebug("MDM enrollment info from osquery: ID={EnrollmentId}, Type={EnrollmentType}, State={EnrollmentState}", 
                        enrollmentId, enrollmentType, enrollmentState);
                    return (enrollmentId, enrollmentType, enrollmentState, managementUrl);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "osquery MDM table not available, trying registry fallback");
        }

        // Fallback to direct registry access for MDM enrollment detection
        try
        {
            // Check for Intune enrollment in registry
            using var enrollmentsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments");
            if (enrollmentsKey != null)
            {
                foreach (var subKeyName in enrollmentsKey.GetSubKeyNames())
                {
                    using var enrollmentKey = enrollmentsKey.OpenSubKey(subKeyName);
                    if (enrollmentKey != null)
                    {
                        var providerID = enrollmentKey.GetValue("ProviderID")?.ToString();
                        var upn = enrollmentKey.GetValue("UPN")?.ToString();
                        var enrollmentState = enrollmentKey.GetValue("EnrollmentState")?.ToString();
                        var discoveryServiceFullUrl = enrollmentKey.GetValue("DiscoveryServiceFullURL")?.ToString();
                        
                        // Check if this is a Microsoft Intune enrollment
                        if (!string.IsNullOrEmpty(providerID) && 
                            (providerID.Contains("MS DM Server", StringComparison.OrdinalIgnoreCase) ||
                             providerID.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)))
                        {
                            var enrollmentType = "Microsoft Intune";
                            var state = "Enrolled";
                            
                            // Check enrollment state
                            if (!string.IsNullOrEmpty(enrollmentState))
                            {
                                switch (enrollmentState)
                                {
                                    case "1":
                                        state = "Enrolled";
                                        break;
                                    case "2":
                                        state = "Pending";
                                        break;
                                    case "3":
                                        state = "Failed";
                                        break;
                                    default:
                                        state = "Unknown";
                                        break;
                                }
                            }
                            
                            _logger.LogDebug("MDM enrollment info from registry: Type={EnrollmentType}, State={State}, UPN={UPN}", 
                                enrollmentType, state, upn);
                            
                            return (subKeyName, enrollmentType, state, discoveryServiceFullUrl ?? "");
                        }
                    }
                }
            }
            
            // Check for Azure AD join (which often implies Intune enrollment)
            using var aadKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo");
            if (aadKey != null && aadKey.GetSubKeyNames().Length > 0)
            {
                _logger.LogDebug("Azure AD joined device detected");
                return ("", "Azure AD", "Joined", "");
            }
            
            // Check for domain join
            var domain = GetDomainName();
            if (!string.IsNullOrEmpty(domain) && !domain.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug("Domain joined device detected: {Domain}", domain);
                return ("", "Active Directory", "Domain Joined", "");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get MDM enrollment information from registry");
        }
        
        return ("", "", "", "");
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
    public string AssetTag { get; set; } = string.Empty;
    
    // Granular OS information
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string OsArchitecture { get; set; } = string.Empty;
    public DateTime? OsInstallDate { get; set; }
    public string ExperiencePack { get; set; } = string.Empty;
    
    // MDM/Management information
    public string MdmEnrollmentId { get; set; } = string.Empty;
    public string MdmEnrollmentType { get; set; } = string.Empty;
    public string MdmEnrollmentState { get; set; } = string.Empty;
    public string MdmManagementUrl { get; set; } = string.Empty;
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
