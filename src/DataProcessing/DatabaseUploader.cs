#nullable enable
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.DataProcessing
{
    /// <summary>
    /// Direct database uploader that sends processed data straight to the database
    /// </summary>
    public class DatabaseUploader
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly string _apiBaseUrl;

        public DatabaseUploader(HttpClient httpClient, ILogger logger, string apiBaseUrl)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _apiBaseUrl = apiBaseUrl?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(apiBaseUrl));
        }

        /// <summary>
        /// Test connectivity to the API
        /// </summary>
        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                _logger.LogInformation("Testing API connectivity...");
                
                var response = await _httpClient.GetAsync($"{_apiBaseUrl}/api/health");
                var isHealthy = response.IsSuccessStatusCode;
                
                if (isHealthy)
                {
                    _logger.LogInformation("API connection successful");
                }
                else
                {
                    _logger.LogWarning($"API health check failed: {response.StatusCode}");
                }
                
                return isHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "API connectivity test failed");
                return false;
            }
        }

        /// <summary>
        /// Upload processed device data directly to the database
        /// </summary>
        public async Task<bool> UploadDeviceDataAsync(ProcessedDeviceData deviceData)
        {
            try
            {
                _logger.LogInformation($"Uploading device data for: {deviceData.BasicInfo.Name}");

                var payload = new
                {
                    deviceId = deviceData.DeviceId,
                    data = deviceData,
                    timestamp = DateTime.UtcNow
                };

                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                    WriteIndented = false
                });

                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/device/upsert", content);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Device data uploaded successfully");
                    
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogDebug($"Response: {responseContent}");
                    
                    return true;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Upload failed: {response.StatusCode} - {errorContent}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading device data");
                return false;
            }
        }

        /// <summary>
        /// Upload with offline caching capability
        /// </summary>
        public async Task<bool> UploadWithCacheFallbackAsync(ProcessedDeviceData deviceData, string cacheDirectory)
        {
            try
            {
                // Try direct upload first
                var uploadSuccess = await UploadDeviceDataAsync(deviceData);
                
                if (uploadSuccess)
                {
                    // Clear any cached data if upload succeeded
                    ClearCachedData(cacheDirectory);
                    return true;
                }
                
                // If upload failed, cache the data locally
                _logger.LogInformation("Caching data locally for later upload");
                await CacheDataLocallyAsync(deviceData, cacheDirectory);
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in upload with cache fallback");
                return false;
            }
        }

        private async Task CacheDataLocallyAsync(ProcessedDeviceData deviceData, string cacheDirectory)
        {
            try
            {
                if (!System.IO.Directory.Exists(cacheDirectory))
                {
                    System.IO.Directory.CreateDirectory(cacheDirectory);
                }

                var filename = $"cached_device_data_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
                var filepath = System.IO.Path.Combine(cacheDirectory, filename);

                var json = JsonSerializer.Serialize(deviceData, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                    WriteIndented = true
                });

                await System.IO.File.WriteAllTextAsync(filepath, json);
                _logger.LogInformation($"Data cached to: {filepath}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error caching data locally");
            }
        }

        private void ClearCachedData(string cacheDirectory)
        {
            try
            {
                if (!System.IO.Directory.Exists(cacheDirectory))
                    return;

                var cachedFiles = System.IO.Directory.GetFiles(cacheDirectory, "cached_device_data_*.json");
                
                foreach (var file in cachedFiles)
                {
                    System.IO.File.Delete(file);
                }

                if (cachedFiles.Length > 0)
                {
                    _logger.LogInformation($"Cleared {cachedFiles.Length} cached files");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error clearing cached data");
            }
        }
    }

    /// <summary>
    /// Simplified data structure for processed device information
    /// This replaces the complex processing done in Azure Functions
    /// </summary>
    public class ProcessedDeviceData
    {
        public string DeviceId { get; set; } = string.Empty;
        public BasicDeviceInfo BasicInfo { get; set; } = new();
        public OperatingSystemInfo OperatingSystem { get; set; } = new();
        public HardwareInfo Hardware { get; set; } = new();
        public NetworkInfo Network { get; set; } = new();
        public SecurityInfo Security { get; set; } = new();
        public ManagementInfo Management { get; set; } = new();
        public List<ApplicationInfo> Applications { get; set; } = new();
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
        public string ClientVersion { get; set; } = string.Empty;
        public string Platform { get; set; } = "Windows";
    }

    public class BasicDeviceInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string AssetTag { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
    }

    public class OperatingSystemInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Build { get; set; } = string.Empty;
        public string Architecture { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public TimeSpan? Uptime { get; set; }
    }

    public class HardwareInfo
    {
        public string Processor { get; set; } = string.Empty;
        public int Cores { get; set; }
        public string Architecture { get; set; } = string.Empty;
        public string Memory { get; set; } = string.Empty;
        public string Storage { get; set; } = string.Empty;
        public string Graphics { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
    }

    public class NetworkInfo
    {
        public string IpAddress { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string ConnectionType { get; set; } = string.Empty;
    }

    public class SecurityInfo
    {
        public Dictionary<string, object> Features { get; set; } = new();
    }

    public class ManagementInfo
    {
        public bool Enrolled { get; set; }
        public string Vendor { get; set; } = string.Empty;
        public string ServerUrl { get; set; } = string.Empty;
    }

    public class ApplicationInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
    }
}
