#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Diagnostics;

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
            _logger.LogInformation("=== STARTING GetBasicDeviceInfoAsync ===");
            
            // Get hardware serial number first - this is the unique device identifier
            _logger.LogInformation("Step 1: Getting hardware serial number...");
            var serialNumber = await GetHardwareSerialNumberAsync();
            _logger.LogInformation("Hardware serial number result: '{SerialNumber}'", serialNumber ?? "NULL");
            
            // CRITICAL: Use serial number as DeviceId unless explicitly overridden in config
            var configDeviceId = _configuration["ReportMate:DeviceId"];
            _logger.LogInformation("Config DeviceId value: '{ConfigDeviceId}'", configDeviceId ?? "NULL");
            
            // STRICT SERIAL NUMBER ENFORCEMENT v2025.7.1.6
            _logger.LogInformation("=== DEVICE ID SELECTION LOGIC v2025.7.1.6 ===");
            _logger.LogInformation("🎯 TARGET SERIAL: 0F33V9G25083HJ");
            _logger.LogInformation("📋 POLICY: Serial number MUST be used as DeviceId unless config override");
            _logger.LogInformation("🔍 Available options:");
            _logger.LogInformation("   Config override: '{ConfigDeviceId}'", configDeviceId ?? "NONE");
            _logger.LogInformation("   Hardware serial: '{SerialNumber}'", serialNumber ?? "NONE");
            _logger.LogInformation("   Machine name fallback: '{MachineName}'", Environment.MachineName);
            
            // Serial number should be the primary device identifier
            var deviceId = !string.IsNullOrWhiteSpace(configDeviceId) ? configDeviceId : serialNumber ?? Environment.MachineName;
            
            _logger.LogInformation("=== DEVICE ID DECISION ===");
            _logger.LogInformation("Final DeviceId selection: '{DeviceId}' (source: {Source})", 
                deviceId, 
                !string.IsNullOrWhiteSpace(configDeviceId) ? "config_override" : 
                serialNumber != null ? "hardware_serial" : "machine_name_fallback");
            
            // CRITICAL VALIDATION: Ensure device ID is what we expect
            if (deviceId == "0F33V9G25083HJ")
            {
                _logger.LogInformation("✅ SUCCESS: Device ID matches target laptop serial number!");
                _logger.LogInformation("✅ EXPECTED: Dashboard URL will be /device/0F33V9G25083HJ");
            }
            else
            {
                _logger.LogWarning("⚠️  MISMATCH: Device ID '{DeviceId}' does not match expected '0F33V9G25083HJ'", deviceId);
                _logger.LogWarning("⚠️  DASHBOARD: Events will appear at /device/{DeviceId}", deviceId);
                _logger.LogWarning("⚠️  IMPACT: This might not be the target laptop or serial detection failed");
            }
            
            // Ensure we have a valid device ID
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                _logger.LogError("CRITICAL: No valid device ID could be determined!");
                throw new InvalidOperationException("No valid device ID could be determined");
            }
            
            _logger.LogInformation("Step 2: Creating DeviceInfo object...");
            var deviceInfo = new DeviceInfo
            {
                DeviceId = deviceId,  // This should be the serial number in most cases
                SerialNumber = serialNumber ?? "UNKNOWN-" + Environment.MachineName,
                ComputerName = Environment.MachineName,
                Domain = Environment.UserDomainName,
                OperatingSystem = GetOperatingSystemInfo(),
                LastSeen = DateTime.UtcNow,
                ClientVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0"
            };

            _logger.LogInformation("DeviceInfo created - DeviceId: '{DeviceId}', SerialNumber: '{SerialNumber}', ComputerName: '{ComputerName}'", 
                deviceInfo.DeviceId, deviceInfo.SerialNumber, deviceInfo.ComputerName);

            // Try to get additional info from WMI
            _logger.LogInformation("Step 3: Getting additional WMI information...");
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
                    
                    _logger.LogInformation("WMI Data - Manufacturer: '{Manufacturer}', Model: '{Model}', Memory: {Memory}GB", 
                        deviceInfo.Manufacturer, deviceInfo.Model, deviceInfo.TotalMemoryGB);
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not retrieve additional device info from WMI");
            }

            _logger.LogInformation("=== GetBasicDeviceInfoAsync COMPLETED SUCCESSFULLY ===");
            _logger.LogInformation("Final Device Summary:");
            _logger.LogInformation("  Device ID: {DeviceId}", deviceInfo.DeviceId);
            _logger.LogInformation("  Serial Number: {SerialNumber}", deviceInfo.SerialNumber);
            _logger.LogInformation("  Computer Name: {ComputerName}", deviceInfo.ComputerName);
            _logger.LogInformation("  Operating System: {OperatingSystem}", deviceInfo.OperatingSystem);
            _logger.LogInformation("  Manufacturer: {Manufacturer}", deviceInfo.Manufacturer);
            _logger.LogInformation("  Model: {Model}", deviceInfo.Model);
            _logger.LogInformation("  Memory: {Memory}GB", deviceInfo.TotalMemoryGB);
            
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

    private Task<bool> CheckWindowsDefenderAsync()
    {
        try
        {
            // Check Windows Defender status using WMI
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT AntivirusEnabled FROM MSFT_MpComputerStatus");
            foreach (ManagementObject obj in searcher.Get())
            {
                return Task.FromResult(obj["AntivirusEnabled"] != null && (bool)obj["AntivirusEnabled"]);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check Windows Defender status");
        }
        
        return Task.FromResult(false);
    }

    private Task<bool> CheckFirewallStatusAsync()
    {
        try
        {
            // Check Windows Firewall status for domain profile
            using var searcher = new ManagementObjectSearcher("SELECT EnabledDomainProfile FROM Win32_FirewallProfile WHERE ProfileName='Domain'");
            foreach (ManagementObject obj in searcher.Get())
            {
                return Task.FromResult(obj["EnabledDomainProfile"] != null && (bool)obj["EnabledDomainProfile"]);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check firewall status");
        }
        
        return Task.FromResult(false);
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

    private Task<bool> CheckBitLockerStatusAsync()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2\security\microsoftvolumeencryption", "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='C:'");
            foreach (ManagementObject obj in searcher.Get())
            {
                var status = obj["ProtectionStatus"];
                return Task.FromResult(status != null && (uint)status == 1); // 1 = Protection On
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check BitLocker status");
        }
        
        return Task.FromResult(false);
    }

    private Task<bool> CheckTpmStatusAsync()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2\security\microsofttpm", "SELECT IsEnabled_InitialValue FROM Win32_Tpm");
            foreach (ManagementObject obj in searcher.Get())
            {
                return Task.FromResult(obj["IsEnabled_InitialValue"] != null && (bool)obj["IsEnabled_InitialValue"]);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check TPM status");
        }
        
        return Task.FromResult(false);
    }

    private Task<DateTime?> GetLastUpdateCheckAsync()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect");
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

    private Task<string?> GetHardwareSerialNumberAsync()
    {
        try
        {
            // COMPREHENSIVE SERIAL NUMBER DETECTION v2025.7.1.5
            _logger.LogError("*** ENHANCED SERIAL DETECTION v2025.7.1.5 - TARGET: 0F33V9G25083HJ ***");
            _logger.LogInformation("=== HARDWARE SERIAL NUMBER DETECTION STARTING ===");
            _logger.LogInformation("🎯 TARGET: Serial number '0F33V9G25083HJ' for laptop registration");
            _logger.LogInformation("🖥️ Current Machine: {MachineName}", Environment.MachineName);
            _logger.LogInformation("🏢 Domain: {Domain}", Environment.UserDomainName);
            _logger.LogInformation("👤 User: {User}", Environment.UserName);
            
            // Method 1: PowerShell WMI query (most reliable for problematic WMI environments)
            _logger.LogInformation("=== METHOD 1: PowerShell WMI Query ===");
            try
            {
                var powerShellSerial = GetSerialViaPowerShell();
                _logger.LogInformation("PowerShell result: '{Serial}'", powerShellSerial ?? "NULL");
                
                if (!string.IsNullOrEmpty(powerShellSerial) && !IsGenericSerial(powerShellSerial))
                {
                    _logger.LogInformation("✅ USING PowerShell-detected serial: {Serial}", powerShellSerial);
                    _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                        string.Equals(powerShellSerial, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                    return Task.FromResult<string?>(powerShellSerial);
                }
                else
                {
                    _logger.LogWarning("❌ PowerShell serial rejected - empty: {Empty}, generic: {Generic}", 
                        string.IsNullOrEmpty(powerShellSerial), 
                        powerShellSerial != null && IsGenericSerial(powerShellSerial));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PowerShell method failed, continuing to WMI methods...");
            }
            
            // Method 2: Enhanced WMI BIOS query with connection options
            _logger.LogInformation("=== METHOD 2: Enhanced WMI BIOS Query ===");
            try
            {
                var options = new ConnectionOptions
                {
                    Impersonation = ImpersonationLevel.Impersonate,
                    Authentication = AuthenticationLevel.Connect,
                    EnablePrivileges = true
                };

                var scope = new ManagementScope(@"\\.\root\cimv2", options);
                scope.Connect();
                _logger.LogInformation("WMI scope connected successfully");

                var query = new ObjectQuery("SELECT Manufacturer, SerialNumber, Version, Name, ReleaseDate FROM Win32_BIOS");
                using var searcher = new ManagementObjectSearcher(scope, query);
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.Trim();
                    var serial = obj["SerialNumber"]?.ToString()?.Trim();
                    var version = obj["Version"]?.ToString()?.Trim();
                    var name = obj["Name"]?.ToString()?.Trim();
                    var releaseDate = obj["ReleaseDate"]?.ToString()?.Trim();
                    
                    _logger.LogInformation("BIOS Details:");
                    _logger.LogInformation("  Manufacturer: '{Manufacturer}'", manufacturer);
                    _logger.LogInformation("  Name: '{Name}'", name);
                    _logger.LogInformation("  Version: '{Version}'", version);
                    _logger.LogInformation("  Serial Number: '{Serial}'", serial);
                    _logger.LogInformation("  Release Date: '{ReleaseDate}'", releaseDate);
                    
                    if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                    {
                        _logger.LogInformation("✅ USING Enhanced BIOS serial: {Serial}", serial);
                        _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                            string.Equals(serial, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                        return Task.FromResult<string?>(serial);
                    }
                    else
                    {
                        _logger.LogWarning("❌ Enhanced BIOS serial rejected - empty: {Empty}, generic: {Generic}", 
                            string.IsNullOrEmpty(serial), 
                            serial != null && IsGenericSerial(serial));
                    }
                    break; // Only check first BIOS entry
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Enhanced WMI BIOS query failed, trying basic BIOS query...");
            }

            // Method 3: Basic WMI BIOS query
            _logger.LogInformation("=== METHOD 3: Basic WMI BIOS Query ===");
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var serial = obj["SerialNumber"]?.ToString()?.Trim();
                    _logger.LogInformation("Basic BIOS serial: '{Serial}'", serial);
                    
                    if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                    {
                        _logger.LogInformation("✅ USING Basic BIOS serial: {Serial}", serial);
                        _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                            string.Equals(serial, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                        return Task.FromResult<string?>(serial);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Basic BIOS query failed, trying ComputerSystemProduct...");
            }

            // Method 4: Win32_ComputerSystemProduct
            _logger.LogInformation("=== METHOD 4: ComputerSystemProduct Query ===");
            try
            {
                using var cspSearcher = new ManagementObjectSearcher("SELECT Name, Vendor, Version, SerialNumber, UUID, IdentifyingNumber FROM Win32_ComputerSystemProduct");
                foreach (ManagementObject obj in cspSearcher.Get())
                {
                    var name = obj["Name"]?.ToString()?.Trim();
                    var vendor = obj["Vendor"]?.ToString()?.Trim();
                    var version = obj["Version"]?.ToString()?.Trim();
                    var serial = obj["SerialNumber"]?.ToString()?.Trim();
                    var uuid = obj["UUID"]?.ToString()?.Trim();
                    var identifyingNumber = obj["IdentifyingNumber"]?.ToString()?.Trim();
                    
                    _logger.LogInformation("ComputerSystemProduct Details:");
                    _logger.LogInformation("  Name: '{Name}'", name);
                    _logger.LogInformation("  Vendor: '{Vendor}'", vendor);
                    _logger.LogInformation("  Version: '{Version}'", version);
                    _logger.LogInformation("  Serial Number: '{Serial}'", serial);
                    _logger.LogInformation("  UUID: '{UUID}'", uuid);
                    _logger.LogInformation("  Identifying Number: '{IdentifyingNumber}'", identifyingNumber);
                    
                    // Try SerialNumber first
                    if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                    {
                        _logger.LogInformation("✅ USING ComputerSystemProduct serial: {Serial}", serial);
                        _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                            string.Equals(serial, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                        return Task.FromResult<string?>(serial);
                    }
                    
                    // Try IdentifyingNumber as fallback
                    if (!string.IsNullOrEmpty(identifyingNumber) && !IsGenericSerial(identifyingNumber))
                    {
                        _logger.LogInformation("✅ USING ComputerSystemProduct IdentifyingNumber: {IdentifyingNumber}", identifyingNumber);
                        _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                            string.Equals(identifyingNumber, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                        return Task.FromResult<string?>(identifyingNumber);
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ComputerSystemProduct query failed, trying motherboard...");
            }

            // Method 5: Motherboard serial
            _logger.LogInformation("=== METHOD 5: Motherboard Serial Query ===");
            try
            {
                using var mbSearcher = new ManagementObjectSearcher("SELECT SerialNumber, Product, Manufacturer FROM Win32_BaseBoard");
                foreach (ManagementObject obj in mbSearcher.Get())
                {
                    var serial = obj["SerialNumber"]?.ToString()?.Trim();
                    var product = obj["Product"]?.ToString()?.Trim();
                    var manufacturer = obj["Manufacturer"]?.ToString()?.Trim();
                    
                    _logger.LogInformation("Motherboard Details:");
                    _logger.LogInformation("  Manufacturer: '{Manufacturer}'", manufacturer);
                    _logger.LogInformation("  Product: '{Product}'", product);
                    _logger.LogInformation("  Serial Number: '{Serial}'", serial);
                    
                    if (!string.IsNullOrEmpty(serial) && !IsGenericSerial(serial))
                    {
                        _logger.LogInformation("✅ USING Motherboard serial: {Serial}", serial);
                        _logger.LogInformation("✅ TARGET CHECK: {TargetMatch}", 
                            string.Equals(serial, "0F33V9G25083HJ", StringComparison.OrdinalIgnoreCase) ? "MATCH!" : "No match");
                        return Task.FromResult<string?>(serial);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Motherboard query failed, trying system UUID...");
            }

            // Method 6: Computer system UUID
            _logger.LogInformation("=== METHOD 6: Computer System UUID ===");
            try
            {
                using var csSearcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
                foreach (ManagementObject obj in csSearcher.Get())
                {
                    var uuid = obj["UUID"]?.ToString()?.Trim();
                    _logger.LogInformation("Computer System UUID: '{UUID}'", uuid);
                    
                    if (!string.IsNullOrEmpty(uuid) && !IsGenericSerial(uuid))
                    {
                        _logger.LogInformation("✅ USING Computer System UUID: {UUID}", uuid);
                        return Task.FromResult<string?>(uuid);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "UUID query failed, trying registry...");
            }

            // Method 7: Registry machine GUID
            _logger.LogInformation("=== METHOD 7: Registry Machine GUID ===");
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                var machineGuid = key?.GetValue("MachineGuid")?.ToString();
                
                if (!string.IsNullOrEmpty(machineGuid))
                {
                    _logger.LogInformation("✅ USING Registry machine GUID: {MachineGuid}", machineGuid);
                    return Task.FromResult<string?>(machineGuid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Registry query failed");
            }

            _logger.LogError("❌ CRITICAL: No hardware serial number found using any method");
            _logger.LogError("❌ EXPECTATION: Should have found '0F33V9G25083HJ'");
            _logger.LogError("❌ IMPACT: Device identification will fall back to machine name");
            
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ EXCEPTION: Serial number detection failed");
        }

        _logger.LogError("🚨 FALLBACK: No valid hardware serial number found from any source");
        return Task.FromResult<string?>(null);
    }

    /// <summary>
    /// Get hardware serial number via PowerShell as fallback for WMI issues
    /// </summary>
    private string? GetSerialViaPowerShell()
    {
        try
        {
            _logger.LogInformation("=== PowerShell Serial Detection ===");
            _logger.LogInformation("Attempting comprehensive PowerShell WMI queries...");
            
            // Method 1: BIOS Serial Number
            _logger.LogInformation("PowerShell Method 1: BIOS SerialNumber");
            var biosSerial = ExecutePowerShellCommand("Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber");
            _logger.LogInformation("BIOS Serial via PowerShell: '{Serial}'", biosSerial ?? "NULL");
            
            if (!string.IsNullOrEmpty(biosSerial) && !IsGenericSerial(biosSerial))
            {
                _logger.LogInformation("✅ PowerShell BIOS serial accepted: {Serial}", biosSerial);
                return biosSerial;
            }

            // Method 2: ComputerSystemProduct Serial Number
            _logger.LogInformation("PowerShell Method 2: ComputerSystemProduct SerialNumber");
            var cspSerial = ExecutePowerShellCommand("Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty SerialNumber");
            _logger.LogInformation("ComputerSystemProduct Serial via PowerShell: '{Serial}'", cspSerial ?? "NULL");
            
            if (!string.IsNullOrEmpty(cspSerial) && !IsGenericSerial(cspSerial))
            {
                _logger.LogInformation("✅ PowerShell ComputerSystemProduct serial accepted: {Serial}", cspSerial);
                return cspSerial;
            }

            // Method 3: ComputerSystemProduct IdentifyingNumber
            _logger.LogInformation("PowerShell Method 3: ComputerSystemProduct IdentifyingNumber");
            var identifyingNumber = ExecutePowerShellCommand("Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty IdentifyingNumber");
            _logger.LogInformation("IdentifyingNumber via PowerShell: '{Number}'", identifyingNumber ?? "NULL");
            
            if (!string.IsNullOrEmpty(identifyingNumber) && !IsGenericSerial(identifyingNumber))
            {
                _logger.LogInformation("✅ PowerShell IdentifyingNumber accepted: {Number}", identifyingNumber);
                return identifyingNumber;
            }

            // Method 4: Motherboard Serial Number
            _logger.LogInformation("PowerShell Method 4: BaseBoard SerialNumber");
            var motherboardSerial = ExecutePowerShellCommand("Get-WmiObject -Class Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber");
            _logger.LogInformation("Motherboard Serial via PowerShell: '{Serial}'", motherboardSerial ?? "NULL");
            
            if (!string.IsNullOrEmpty(motherboardSerial) && !IsGenericSerial(motherboardSerial))
            {
                _logger.LogInformation("✅ PowerShell motherboard serial accepted: {Serial}", motherboardSerial);
                return motherboardSerial;
            }

            _logger.LogWarning("❌ All PowerShell methods returned empty or generic serial numbers");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exception in PowerShell WMI query methods");
            return null;
        }
    }

    /// <summary>
    /// Execute a PowerShell command and return the result
    /// </summary>
    private string? ExecutePowerShellCommand(string command)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                _logger.LogWarning("Failed to start PowerShell process for command: {Command}", command);
                return null;
            }

            process.WaitForExit(10000); // 10 second timeout
            
            if (process.ExitCode == 0)
            {
                var output = process.StandardOutput.ReadToEnd().Trim();
                _logger.LogDebug("PowerShell command '{Command}' result: '{Output}'", command, output);
                return string.IsNullOrEmpty(output) ? null : output;
            }
            else
            {
                var error = process.StandardError.ReadToEnd();
                _logger.LogWarning("PowerShell command '{Command}' failed with exit code {ExitCode}: {Error}", 
                    command, process.ExitCode, error);
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exception executing PowerShell command: {Command}", command);
            return null;
        }
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

        var isGeneric = genericSerials.Any(g => string.Equals(serial, g, StringComparison.OrdinalIgnoreCase)) ||
                       serial.All(c => c == '0' || c == 'F' || c == '-');
        
        _logger.LogInformation("IsGenericSerial check for '{Serial}': {IsGeneric}", serial, isGeneric);
        
        return isGeneric;
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
