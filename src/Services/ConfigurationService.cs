using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using ReportMate.WindowsClient.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Principal;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for managing ReportMate client configuration
/// Handles registry settings, validation, and installation
/// </summary>
public interface IConfigurationService
{
    Task<ConfigurationValidationResult> ValidateConfigurationAsync();
    Task<CurrentConfiguration> GetCurrentConfigurationAsync();
    Task InstallConfigurationAsync();
    Task UpdateLastRunTimeAsync();
    Task<bool> IsRecentRunAsync();
}

public class ConfigurationService : IConfigurationService
{
    private const string REGISTRY_KEY_PATH = @"SOFTWARE\ReportMate";
    private readonly ILogger<ConfigurationService> _logger;
    private readonly IConfiguration _configuration;

    public ConfigurationService(ILogger<ConfigurationService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// Gets the path to the working data directory (ProgramData/ManagedReports)
    /// </summary>
    public static string GetWorkingDataDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedReports");
    }

    /// <summary>
    /// Gets the path to the application binary directory (Program Files/ReportMate)
    /// </summary>
    public static string GetApplicationDirectory()
    {
        return AppContext.BaseDirectory;
    }

    public async Task<ConfigurationValidationResult> ValidateConfigurationAsync()
    {
        var result = new ConfigurationValidationResult();

        try
        {
            // Check API URL
            var apiUrl = _configuration["ReportMate:ApiUrl"];
            if (string.IsNullOrEmpty(apiUrl))
            {
                result.Errors.Add("API URL is not configured");
            }
            else if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out var uri) || 
                     (uri.Scheme != "https" && uri.Scheme != "http"))
            {
                result.Errors.Add("API URL is not a valid HTTP/HTTPS URL");
            }

            // Check osquery installation
            var osqueryPath = _configuration["ReportMate:OsQueryPath"] ?? @"C:\Program Files\osquery\osqueryi.exe";
            if (!File.Exists(osqueryPath))
            {
                result.Warnings.Add($"osquery not found at {osqueryPath}. Data collection will be limited.");
            }

            // Check permissions
            if (!IsRunningAsAdministrator())
            {
                result.Warnings.Add("Not running as administrator. Some data collection may be limited.");
            }

            // Check network connectivity
            if (!string.IsNullOrEmpty(apiUrl))
            {
                try
                {
                    using var client = new HttpClient();
                    client.Timeout = TimeSpan.FromSeconds(10);
                    
                    // Just check if we can reach the host
                    var uri = new Uri(apiUrl);
                    var response = await client.GetAsync($"{uri.Scheme}://{uri.Host}");
                    // We don't care about the response code, just that we can reach the server
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Cannot reach API endpoint: {ex.Message}");
                }
            }

            result.IsValid = result.Errors.Count == 0;
            
            _logger.LogInformation("Configuration validation completed. Valid: {IsValid}, Errors: {ErrorCount}, Warnings: {WarningCount}",
                result.IsValid, result.Errors.Count, result.Warnings.Count);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during configuration validation");
            result.Errors.Add($"Validation error: {ex.Message}");
            result.IsValid = false;
            return result;
        }
    }

    public async Task<CurrentConfiguration> GetCurrentConfigurationAsync()
    {
        try
        {
            var config = new CurrentConfiguration
            {
                ApiUrl = _configuration["ReportMate:ApiUrl"] ?? string.Empty,
                DeviceId = _configuration["ReportMate:DeviceId"] ?? await GenerateDeviceIdAsync(),
                Version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown",
                IsConfigured = !string.IsNullOrEmpty(_configuration["ReportMate:ApiUrl"])
            };

            // Try to get last run time from registry
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY_PATH, false);
                var lastRunValue = key?.GetValue("LastRunTime")?.ToString();
                if (!string.IsNullOrEmpty(lastRunValue) && DateTime.TryParse(lastRunValue, out var lastRun))
                {
                    config.LastRunTime = lastRun;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not read last run time from registry");
            }

            return config;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current configuration");
            throw;
        }
    }

    public async Task InstallConfigurationAsync()
    {
        try
        {
            if (!IsRunningAsAdministrator())
            {
                throw new UnauthorizedAccessException("Administrator privileges required for installation");
            }

            _logger.LogInformation("Installing ReportMate configuration to registry");

            using var key = Registry.LocalMachine.CreateSubKey(REGISTRY_KEY_PATH, true);
            if (key == null)
            {
                throw new InvalidOperationException("Could not create registry key");
            }

            // Set basic configuration
            var apiUrl = _configuration["ReportMate:ApiUrl"];
            if (!string.IsNullOrEmpty(apiUrl))
            {
                key.SetValue("ApiUrl", apiUrl, RegistryValueKind.String);
            }

            var deviceId = _configuration["ReportMate:DeviceId"] ?? await GenerateDeviceIdAsync();
            key.SetValue("DeviceId", deviceId, RegistryValueKind.String);

            var apiKey = _configuration["ReportMate:ApiKey"];
            if (!string.IsNullOrEmpty(apiKey))
            {
                key.SetValue("ApiKey", apiKey, RegistryValueKind.String);
            }

            // Set default values
            key.SetValue("CollectionInterval", _configuration.GetValue<int>("ReportMate:CollectionIntervalSeconds", 3600), RegistryValueKind.DWord);
            key.SetValue("LogLevel", _configuration["Logging:LogLevel:Default"] ?? "Information", RegistryValueKind.String);
            key.SetValue("OsQueryPath", _configuration["ReportMate:OsQueryPath"] ?? @"C:\Program Files\osquery\osqueryi.exe", RegistryValueKind.String);
            key.SetValue("CimianIntegrationEnabled", _configuration.GetValue<bool>("ReportMate:CimianIntegrationEnabled", true) ? 1 : 0, RegistryValueKind.DWord);

            // Set installation timestamp
            key.SetValue("InstallTime", DateTime.UtcNow.ToString("O"), RegistryValueKind.String);
            key.SetValue("Version", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0", RegistryValueKind.String);

            _logger.LogInformation("Configuration installed successfully to registry");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error installing configuration");
            throw;
        }
    }

    public async Task UpdateLastRunTimeAsync()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY_PATH, true);
            if (key != null)
            {
                key.SetValue("LastRunTime", DateTime.UtcNow.ToString("O"), RegistryValueKind.String);
                _logger.LogDebug("Updated last run time in registry");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not update last run time in registry");
            // Don't throw - this is not critical
        }
        
        await Task.CompletedTask;
    }

    public async Task<bool> IsRecentRunAsync()
    {
        try
        {
            var config = await GetCurrentConfigurationAsync();
            if (!config.LastRunTime.HasValue)
            {
                return false;
            }

            var maxAge = TimeSpan.FromMinutes(_configuration.GetValue<int>("ReportMate:MaxDataAgeMinutes", 30));
            var age = DateTime.UtcNow - config.LastRunTime.Value;
            
            var isRecent = age < maxAge;
            _logger.LogDebug("Last run was {Age} ago, max age is {MaxAge}, recent: {IsRecent}", 
                age, maxAge, isRecent);
            
            return isRecent;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error checking last run time");
            return false;
        }
    }

    private Task<string> GenerateDeviceIdAsync()
    {
        try
        {
            // Use computer name + domain + hardware ID for consistency
            var computerName = Environment.MachineName;
            var domain = Environment.UserDomainName;
            
            // Try to get hardware UUID from WMI
            string hardwareId = "unknown";
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    hardwareId = obj["UUID"]?.ToString() ?? "unknown";
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve hardware UUID, using fallback");
                hardwareId = Environment.MachineName;
            }

            var deviceId = $"{computerName}.{domain}.{hardwareId}".ToLowerInvariant();
            _logger.LogDebug("Generated device ID: {DeviceId}", deviceId);
            
            return Task.FromResult(deviceId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error generating device ID, using fallback");
            return Task.FromResult($"{Environment.MachineName}.{Environment.UserDomainName}".ToLowerInvariant());
        }
    }

    private static bool IsRunningAsAdministrator()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
