using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Main data collection service that orchestrates device data collection and API submission
/// </summary>
public interface IDataCollectionService
{
    Task<bool> CollectAndSendDataAsync(bool forceCollection = false);
    Task<Dictionary<string, object>> CollectDataAsync();
}

public class DataCollectionService : IDataCollectionService
{
    private readonly ILogger<DataCollectionService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IDeviceInfoService _deviceInfoService;
    private readonly IApiService _apiService;
    private readonly IConfigurationService _configurationService;

    public DataCollectionService(
        ILogger<DataCollectionService> logger,
        IConfiguration configuration,
        IDeviceInfoService deviceInfoService,
        IApiService apiService,
        IConfigurationService configurationService)
    {
        _logger = logger;
        _configuration = configuration;
        _deviceInfoService = deviceInfoService;
        _apiService = apiService;
        _configurationService = configurationService;
    }

    public async Task<bool> CollectAndSendDataAsync(bool forceCollection = false)
    {
        try
        {
            _logger.LogInformation("Starting data collection and transmission");

            // Check if we need to collect data
            if (!forceCollection && await _configurationService.IsRecentRunAsync())
            {
                _logger.LogInformation("Recent data collection detected, skipping collection (use --force to override)");
                return true;
            }

            // Validate configuration before proceeding
            var configValidation = await _configurationService.ValidateConfigurationAsync();
            if (!configValidation.IsValid)
            {
                _logger.LogError("Configuration validation failed: {Errors}", 
                    string.Join(", ", configValidation.Errors));
                return false;
            }

            // Log warnings but continue
            foreach (var warning in configValidation.Warnings)
            {
                _logger.LogWarning("Configuration warning: {Warning}", warning);
            }

            // Collect data
            _logger.LogInformation("Collecting device data");
            var deviceData = await CollectDataAsync();

            // Send to API
            _logger.LogInformation("Sending data to ReportMate API");
            var success = await _apiService.SendDeviceDataAsync(deviceData);

            if (success)
            {
                // Update last run time
                await _configurationService.UpdateLastRunTimeAsync();
                
                _logger.LogInformation("Data collection and transmission completed successfully");
                
                // Log summary
                LogCollectionSummary(deviceData);
                
                return true;
            }
            else
            {
                _logger.LogError("Failed to send data to API");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during data collection and transmission");
            return false;
        }
    }

    public async Task<Dictionary<string, object>> CollectDataAsync()
    {
        try
        {
            _logger.LogInformation("Collecting comprehensive device data");

            var deviceData = await _deviceInfoService.GetComprehensiveDeviceDataAsync();

            // Add ReportMate client metadata
            deviceData["reportmate_client"] = new Dictionary<string, object>
            {
                { "version", "1.0.0" },
                { "platform", "windows" },
                { "collection_time", DateTime.UtcNow.ToString("O") }
            };

            // Add environment context
            deviceData["environment"] = new Dictionary<string, object>
            {
                { "is_domain_joined", !string.IsNullOrEmpty(Environment.UserDomainName) && Environment.UserDomainName != Environment.MachineName },
                { "user_interactive", Environment.UserInteractive },
                { "current_directory", Environment.CurrentDirectory },
                { "machine_name", Environment.MachineName },
                { "user_domain_name", Environment.UserDomainName },
                { "processor_count", Environment.ProcessorCount },
                { "is_64bit_os", Environment.Is64BitOperatingSystem },
                { "is_64bit_process", Environment.Is64BitProcess },
                { "clr_version", Environment.Version.ToString() }
            };

            _logger.LogInformation("Device data collection completed. Data size: {DataSize} bytes", 
                System.Text.Json.JsonSerializer.Serialize(deviceData).Length);

            return deviceData;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting device data");
            throw;
        }
    }

    private void LogCollectionSummary(Dictionary<string, object> deviceData)
    {
        try
        {
            var summary = new List<string>();

            if (deviceData.TryGetValue("device", out var deviceInfo))
            {
                summary.Add($"Device: {deviceInfo}");
            }

            if (deviceData.TryGetValue("system", out var systemInfo))
            {
                summary.Add($"System data collected");
            }

            if (deviceData.TryGetValue("security", out var securityInfo))
            {
                summary.Add($"Security data collected");
            }

            if (deviceData.TryGetValue("osquery", out var osqueryInfo))
            {
                summary.Add($"osquery data collected");
            }

            if (deviceData.TryGetValue("reportmate_client", out var clientInfo))
            {
                summary.Add($"ReportMate client metadata collected");
            }

            _logger.LogInformation("Collection summary: {Summary}", string.Join(", ", summary));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error creating collection summary");
        }
    }
}
