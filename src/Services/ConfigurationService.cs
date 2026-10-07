using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using ReportMate.Shared;
using ReportMate.WindowsClient.Configuration;
using System;
using System.IO;
using System.Linq;
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
    private readonly IOsQueryService _osQueryService;

    public ConfigurationService(ILogger<ConfigurationService> logger, IConfiguration configuration, IOsQueryService osQueryService)
    {
        _logger = logger;
        _configuration = configuration;
        _osQueryService = osQueryService;
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

            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            // Legacy keys are copied into Settings where Settings lacks a value, and left as
            // they are; credentials go to the protected store.
            foreach (var note in LegacySettingsMigration.Migrate().Concat(SecretStore.MigrateReadableCopies()))
            {
                _logger.LogWarning("Settings: {Note}", note);
            }

            // Settings go to the machine settings key, credentials to the protected store. A
            // value policy sets is left to policy.
            using (var settings = hklm.CreateSubKey(ReportMateSettingsKeys.SettingsRegistryPath, true))
            {
                if (settings == null)
                {
                    throw new InvalidOperationException("Could not create registry key");
                }

                using var policy = hklm.OpenSubKey(ReportMateSettingsKeys.PolicyRegistryPath, false);
                bool SetByPolicy(string name, string[] aliases) =>
                    policy != null && aliases.Prepend(name).Any(n => policy.GetValueNames().Contains(n, StringComparer.OrdinalIgnoreCase));

                void Set(string name, object value, RegistryValueKind kind, params string[] aliases)
                {
                    if (SetByPolicy(name, aliases)) return;
                    if (SecretStore.IsSecret(name))
                    {
                        SecretStore.Write(name, value.ToString());
                        return;
                    }
                    settings.SetValue(name, value, kind);
                }

                var apiUrl = _configuration["ReportMate:ApiUrl"];
                if (!string.IsNullOrEmpty(apiUrl))
                {
                    Set("ApiUrl", apiUrl, RegistryValueKind.String, "ServerUrl");
                }

                var deviceId = _configuration["ReportMate:DeviceId"] ?? await GenerateDeviceIdAsync();
                Set("DeviceId", deviceId, RegistryValueKind.String);

                var apiKey = _configuration["ReportMate:ApiKey"];
                if (!string.IsNullOrEmpty(apiKey))
                {
                    Set("ApiKey", apiKey, RegistryValueKind.String);
                }

                var collectionInterval = int.TryParse(_configuration["ReportMate:CollectionIntervalSeconds"], out var interval) ? interval : 3600;
                Set("CollectionIntervalSeconds", collectionInterval, RegistryValueKind.DWord, "CollectionInterval");
                Set("LogLevel", _configuration["Logging:LogLevel:Default"] ?? "Information", RegistryValueKind.String);
                Set("OsQueryPath", _configuration["ReportMate:OsQueryPath"] ?? @"C:\Program Files\osquery\osqueryi.exe", RegistryValueKind.String);
                var cimianEnabled = bool.TryParse(_configuration["ReportMate:CimianIntegrationEnabled"], out var enabled) ? enabled : true;
                Set("CimianIntegrationEnabled", cimianEnabled ? 1 : 0, RegistryValueKind.DWord);
            }

            // Install time and version are state, not settings, and stay on the top-level key.
            using var key = hklm.CreateSubKey(REGISTRY_KEY_PATH, true);
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

            var maxAgeMinutes = int.TryParse(_configuration["ReportMate:MaxDataAgeMinutes"], out var maxAge) ? maxAge : 30;
            var maxAgeSpan = TimeSpan.FromMinutes(maxAgeMinutes);
            var age = DateTime.UtcNow - config.LastRunTime.Value;
            
            var isRecent = age < maxAgeSpan;
            _logger.LogDebug("Last run was {Age} ago, max age is {MaxAge}, recent: {IsRecent}", 
                age, maxAgeSpan, isRecent);
            
            return isRecent;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error checking last run time");
            return false;
        }
    }

    private async Task<string> GenerateDeviceIdAsync()
    {
        try
        {
            // Use computer name + domain + hardware ID for consistency
            var computerName = Environment.MachineName;
            var domain = Environment.UserDomainName;
            
            // Try to get hardware UUID from osquery
            string hardwareId = "unknown";
            try
            {
                var systemInfo = await _osQueryService.ExecuteQueryAsync("SELECT uuid FROM system_info");
                if (systemInfo.ContainsKey("uuid"))
                {
                    hardwareId = systemInfo["uuid"]?.ToString() ?? "unknown";
                }
                
                if (hardwareId == "unknown")
                {
                    _logger.LogDebug("Could not retrieve hardware UUID via osquery, using machine name as fallback");
                    hardwareId = Environment.MachineName;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve hardware UUID, using fallback");
                hardwareId = Environment.MachineName;
            }

            var deviceId = $"{computerName}.{domain}.{hardwareId}".ToLowerInvariant();
            _logger.LogDebug("Generated device ID: {DeviceId}", deviceId);
            
            return deviceId;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error generating device ID, using fallback");
            return $"{Environment.MachineName}.{Environment.UserDomainName}".ToLowerInvariant();
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
