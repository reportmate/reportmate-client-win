#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.DataProcessing;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Device Info Service that processes data on the client side
    /// This eliminates the need for complex backend processing
    /// </summary>
    public class DeviceInfoService : IDeviceInfoService
    {
        private readonly ILogger<DeviceInfoService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IOsQueryService _osQueryService;
        private readonly DataProcessor _dataProcessor;
        
        // Cache to prevent redundant osquery calls
        private ProcessedDeviceData? _cachedProcessedData;
        private Dictionary<string, List<Dictionary<string, object>>>? _cachedOsqueryData;
        private DateTime? _cacheTimestamp;
        private readonly TimeSpan _cacheTimeout = TimeSpan.FromMinutes(5); // Cache for 5 minutes

        public DeviceInfoService(
            ILogger<DeviceInfoService> logger,
            IConfiguration configuration,
            IOsQueryService osQueryService)
        {
            _logger = logger;
            _configuration = configuration;
            _osQueryService = osQueryService;
            _dataProcessor = new DataProcessor(_logger); // Pass the existing logger
        }

        public async Task<ProcessedDeviceData> GetProcessedDeviceDataAsync()
        {
            try
            {
                // Check cache first to prevent redundant osquery calls
                if (_cachedProcessedData != null && _cacheTimestamp.HasValue && 
                    DateTime.UtcNow - _cacheTimestamp.Value < _cacheTimeout)
                {
                    _logger.LogInformation("Using cached processed data (avoiding redundant osquery call)");
                    return _cachedProcessedData;
                }

                _logger.LogInformation("Starting client-side data collection and processing...");

                // Step 1: Collect raw osquery data (with caching)
                var rawOsqueryData = await CollectRawOsqueryDataAsync();

                // Step 2: Process data on client side
                var processedData = _dataProcessor.ProcessDeviceData(rawOsqueryData);

                // Cache the results
                _cachedProcessedData = processedData;
                _cachedOsqueryData = rawOsqueryData;
                _cacheTimestamp = DateTime.UtcNow;

                _logger.LogInformation("Client-side data processing completed successfully");
                _logger.LogInformation("Processed Data Summary:");
                _logger.LogInformation($"   Device: {processedData.BasicInfo.Name}");
                _logger.LogInformation($"   Processor: {processedData.Hardware.Processor} ({processedData.Hardware.Cores} cores)");
                _logger.LogInformation($"   Graphics: {processedData.Hardware.Graphics}");
                _logger.LogInformation($"   Memory: {processedData.Hardware.Memory}");
                _logger.LogInformation($"   OS: {processedData.OperatingSystem.Name} {processedData.OperatingSystem.Version}");

                return processedData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during client-side data processing");
                throw;
            }
        }

        private async Task<Dictionary<string, List<Dictionary<string, object>>>> CollectRawOsqueryDataAsync()
        {
            // Check cache first to prevent redundant osquery calls
            if (_cachedOsqueryData != null && _cacheTimestamp.HasValue && 
                DateTime.UtcNow - _cacheTimestamp.Value < _cacheTimeout)
            {
                _logger.LogInformation("Using cached osquery data (avoiding redundant execution)");
                return _cachedOsqueryData;
            }

            var osqueryData = new Dictionary<string, List<Dictionary<string, object>>>();

            if (!await _osQueryService.IsOsQueryAvailableAsync())
            {
                _logger.LogWarning("osquery not available - using fallback data collection");
                return osqueryData;
            }

            try
            {
                // Use new modular osquery system
                var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
                var modularLogger = loggerFactory.CreateLogger<ModularOsQueryService>();
                var modularOsQueryService = new ModularOsQueryService(modularLogger);
                var queriesDict = modularOsQueryService.LoadModularQueries();
                
                if (queriesDict.Count == 0)
                {
                    _logger.LogError("No osquery queries loaded from modular system");
                    return osqueryData;
                }

                _logger.LogInformation($"Using modular osquery system with {queriesDict.Count} queries");

                // Create temporary queries file for compatibility with existing osQueryService
                var tempDir = Path.GetTempPath();
                var tempFile = Path.Combine(tempDir, $"reportmate-queries-{Guid.NewGuid()}.json");
                
                try
                {
                    // Convert modular queries to simple format and write to temp file
                    var simpleQueries = new Dictionary<string, string>();
                    foreach (var kvp in queriesDict)
                    {
                        if (kvp.Value is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Object)
                        {
                            if (jsonElement.TryGetProperty("query", out var queryElement))
                            {
                                simpleQueries[kvp.Key] = queryElement.GetString() ?? "";
                            }
                        }
                        else if (kvp.Value is Dictionary<string, object> queryObj && queryObj.ContainsKey("query"))
                        {
                            simpleQueries[kvp.Key] = queryObj["query"]?.ToString() ?? "";
                        }
                    }

                    await File.WriteAllTextAsync(tempFile, JsonSerializer.Serialize(simpleQueries, new JsonSerializerOptions { WriteIndented = true }));

                    // Execute all queries using existing method
                    osqueryData = await _osQueryService.ExecuteQueriesFromFileAsync(tempFile);

                    _logger.LogInformation($"Collected {osqueryData.Count} osquery datasets");
                    
                    // Log which queries returned data
                    foreach (var dataset in osqueryData)
                    {
                        var resultCount = dataset.Value?.Count ?? 0;
                        _logger.LogDebug($"   {dataset.Key}: {resultCount} rows");
                    }
                }
                finally
                {
                    // Clean up temp file
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                    }
                }
                foreach (var (queryName, results) in osqueryData)
                {
                    _logger.LogDebug($"   {queryName}: {results.Count} results");
                }

                return osqueryData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting osquery data");
                return osqueryData;
            }
        }

        public async Task<bool> SaveProcessedDataLocallyAsync(ProcessedDeviceData data, string filePath)
        {
            try
            {
                _logger.LogInformation($"Saving processed data to: {filePath}");

                var directory = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                    WriteIndented = true
                };

                var json = JsonSerializer.Serialize(data, options);
                await File.WriteAllTextAsync(filePath, json);

                _logger.LogInformation("Processed data saved successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving processed data");
                return false;
            }
        }

        public async Task<ProcessedDeviceData?> LoadProcessedDataFromFileAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning($"Processed data file not found: {filePath}");
                    return null;
                }

                _logger.LogInformation($"Loading processed data from: {filePath}");

                var json = await File.ReadAllTextAsync(filePath);
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                };

                var data = JsonSerializer.Deserialize<ProcessedDeviceData>(json, options);
                
                if (data != null)
                {
                    _logger.LogInformation("Processed data loaded successfully");
                    _logger.LogInformation($"   Last updated: {data.LastUpdated}");
                }

                return data;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading processed data");
                return null;
            }
        }

        public async Task<bool> UploadToSimplifiedBackendAsync(ProcessedDeviceData data)
        {
            try
            {
                var baseUrl = _configuration.GetValue<string>("ReportMate:ApiBaseUrl") ?? "https://reportmate-api.azurewebsites.net";
                
                using var httpClient = new HttpClient();
                var uploader = new DatabaseUploader(httpClient, _logger, baseUrl);

                // Test connection first
                var connectionOk = await uploader.TestConnectionAsync();
                if (!connectionOk)
                {
                    _logger.LogWarning("Database connection test failed - continuing anyway");
                }

                // Upload processed data
                var success = await uploader.UploadDeviceDataAsync(data);
                
                if (success)
                {
                    _logger.LogInformation(" Device data uploaded successfully to simplified backend");
                }
                else
                {
                    _logger.LogError("Failed to upload device data");
                }

                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading to simplified backend");
                return false;
            }
        }

        // Implementation of IDeviceInfoService interface for compatibility
        public async Task<DeviceInfo> GetBasicDeviceInfoAsync()
        {
            try
            {
                _logger.LogInformation("Getting basic device info via optimized enhanced service...");
                
                // Use cached data if available to prevent redundant osquery calls
                var processedData = _cachedProcessedData ?? await GetProcessedDeviceDataAsync();
                
                // Convert ProcessedDeviceData to DeviceInfo for compatibility
                var deviceInfo = new DeviceInfo
                {
                    DeviceId = processedData.DeviceId,
                    SerialNumber = processedData.BasicInfo.SerialNumber,
                    ComputerName = processedData.BasicInfo.Name,
                    Domain = "", // Not available in BasicDeviceInfo model
                    Manufacturer = processedData.BasicInfo.Manufacturer,
                    Model = processedData.BasicInfo.Model,
                    TotalMemoryGB = ExtractMemoryGB(processedData.Hardware.Memory),
                    LastSeen = DateTime.UtcNow,
                    ClientVersion = processedData.ClientVersion,
                    AssetTag = processedData.BasicInfo.AssetTag,
                    OsName = processedData.OperatingSystem.Name,
                    OsVersion = processedData.OperatingSystem.Version,
                    OsBuild = processedData.OperatingSystem.Build,
                    OsArchitecture = processedData.OperatingSystem.Architecture,
                    IpAddressV4 = processedData.Network.IpAddress,
                    IpAddressV6 = "", // Not separately tracked in NetworkInfo model
                    MacAddress = processedData.Network.MacAddress,
                    MdmEnrollmentId = "", // Not available in ManagementInfo model
                    MdmEnrollmentType = "", // Not available in ManagementInfo model
                    MdmEnrollmentState = "", // Not available in ManagementInfo model
                    MdmManagementUrl = "", // Not available in ManagementInfo model
                    Status = "online"
                };

                _logger.LogInformation("Enhanced device info converted to basic format (using cached data)");
                _logger.LogInformation($"   Device: {deviceInfo.ComputerName}");
                _logger.LogInformation($"   Processor: {processedData.Hardware.Processor}");
                
                return deviceInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting basic device info via enhanced service");
                throw;
            }
        }

        public async Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync()
        {
            try
            {
                _logger.LogInformation("OPTIMIZED: Single-pass comprehensive data collection starting...");
                
                // Get processed data (uses caching to prevent redundant osquery calls)
                var processedData = await GetProcessedDeviceDataAsync();
                
                // Convert ProcessedDeviceData to DeviceInfo format without additional calls
                var basicDeviceInfo = new DeviceInfo
                {
                    DeviceId = processedData.DeviceId,
                    SerialNumber = processedData.BasicInfo.SerialNumber,
                    ComputerName = processedData.BasicInfo.Name,
                    Domain = "", // Not available in BasicDeviceInfo model
                    Manufacturer = processedData.BasicInfo.Manufacturer,
                    Model = processedData.BasicInfo.Model,
                    TotalMemoryGB = ExtractMemoryGB(processedData.Hardware.Memory),
                    LastSeen = DateTime.UtcNow,
                    ClientVersion = processedData.ClientVersion,
                    AssetTag = processedData.BasicInfo.AssetTag,
                    OsName = processedData.OperatingSystem.Name,
                    OsVersion = processedData.OperatingSystem.Version,
                    OsBuild = processedData.OperatingSystem.Build,
                    OsArchitecture = processedData.OperatingSystem.Architecture,
                    IpAddressV4 = processedData.Network.IpAddress,
                    IpAddressV6 = "", // Not separately tracked in NetworkInfo model
                    MacAddress = processedData.Network.MacAddress,
                    MdmEnrollmentId = "", // Not available in ManagementInfo model
                    MdmEnrollmentType = "", // Not available in ManagementInfo model
                    MdmEnrollmentState = "", // Not available in ManagementInfo model
                    MdmManagementUrl = "", // Not available in ManagementInfo model
                    Status = "online"
                };
                
                // Convert ProcessedDeviceData to dictionary format for API compatibility
                var deviceData = new Dictionary<string, object>
                {
                    ["device"] = basicDeviceInfo,
                    ["data"] = new Dictionary<string, object>
                    {
                        ["processor"] = processedData.Hardware.Processor,
                        ["cores"] = processedData.Hardware.Cores,
                        ["memory"] = processedData.Hardware.Memory,
                        ["graphics"] = processedData.Hardware.Graphics,
                        ["storage"] = processedData.Hardware.Storage
                    },
                    ["osquery"] = _cachedOsqueryData ?? new Dictionary<string, List<Dictionary<string, object>>>(),
                    ["collection_timestamp"] = DateTime.UtcNow,
                    ["client_version"] = processedData.ClientVersion,
                    ["processing_method"] = "optimized_single_pass"
                };

                _logger.LogInformation("OPTIMIZED: Single-pass data collection completed");
                _logger.LogInformation($"   Processor: {processedData.Hardware.Processor}");
                _logger.LogInformation($"   Graphics: {processedData.Hardware.Graphics}");
                _logger.LogInformation($"   Memory: {processedData.Hardware.Memory}");
                
                return deviceData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in simplified data collection");
                throw;
            }
        }

        private int ExtractMemoryGB(string memoryString)
        {
            if (string.IsNullOrWhiteSpace(memoryString))
                return 0;

            // Extract numeric value from memory string like "32GB" or "16 GB"
            var match = Regex.Match(memoryString, @"(\d+)\s*GB", RegexOptions.IgnoreCase);
            if (match.Success && int.TryParse(match.Groups[1].Value, out var memoryGB))
            {
                return memoryGB;
            }

            return 0;
        }
    }
}
