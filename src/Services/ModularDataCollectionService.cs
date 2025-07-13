#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Modular data collection service that coordinates individual module data collection
    /// using the new modular architecture with individual module processors
    /// </summary>
    public interface IModularDataCollectionService
    {
        Task<UnifiedDevicePayload> CollectAllModuleDataAsync();
        Task<T?> CollectModuleDataAsync<T>(string moduleId) where T : BaseModuleData;
        Task SaveModuleDataLocallyAsync<T>(string moduleId, T data) where T : BaseModuleData;
        Task<UnifiedDevicePayload> LoadCachedDataAsync();
        Task<bool> ValidateModuleDataAsync(string moduleId, object data);
    }

    public class ModularDataCollectionService : IModularDataCollectionService
    {
        private readonly ILogger<ModularDataCollectionService> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly ModularOsQueryService _modularOsQueryService;
        private readonly IModuleProcessorFactory _moduleProcessorFactory;
        private readonly string _cacheDirectory;
        private readonly string _baseDirectory;

        public ModularDataCollectionService(
            ILogger<ModularDataCollectionService> logger,
            IOsQueryService osQueryService,
            ModularOsQueryService modularOsQueryService,
            IModuleProcessorFactory moduleProcessorFactory)
        {
            _logger = logger;
            _osQueryService = osQueryService;
            _modularOsQueryService = modularOsQueryService;
            _moduleProcessorFactory = moduleProcessorFactory;
            _baseDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ManagedReports", "cache");
            
            // Create timestamped cache directory (YYYY-MM-DD-HHmmss)
            var now = DateTime.Now;
            var timestamp = now.ToString("yyyy-MM-dd-HHmmss");
            _cacheDirectory = Path.Combine(_baseDirectory, timestamp);
            
            Directory.CreateDirectory(_cacheDirectory);
            
            // Clean up old cache files
            CleanupOldCacheFiles();
        }

        /// <summary>
        /// Collect data from all enabled modules and create unified payload
        /// </summary>
        public async Task<UnifiedDevicePayload> CollectAllModuleDataAsync()
        {
            _logger.LogInformation("Starting modular data collection...");

            try
            {
                // Load modular osquery configuration
                _logger.LogInformation("Loading modular queries...");
                var modularQueries = _modularOsQueryService.LoadModularQueries();
                _logger.LogInformation("Loaded {QueryCount} modular queries successfully", modularQueries.Count);
                
                // Execute all osquery queries in one pass
                var osqueryResults = await ExecuteModularQueriesAsync(modularQueries);
                _logger.LogInformation("Executed osquery with {ResultCount} result sets", osqueryResults.Count);
                
                // Extract device UUID for individual modules
                var deviceId = ExtractDeviceUuid(osqueryResults);
                
                // Create unified payload
                var payload = new UnifiedDevicePayload
                {
                    DeviceId = deviceId,
                    CollectedAt = DateTime.UtcNow,
                    ClientVersion = GetClientVersion(),
                    Platform = "Windows"
                };

                // Process each module's data using the modular architecture
                var enabledProcessors = _moduleProcessorFactory.GetEnabledProcessors().ToList();
                _logger.LogInformation("Processing {ProcessorCount} enabled modules", enabledProcessors.Count);

                for (int i = 0; i < enabledProcessors.Count; i++)
                {
                    var processor = enabledProcessors[i];
                    try
                    {
                        _logger.LogInformation("Processing module: {ModuleId}", processor.ModuleId);
                        
                        var moduleData = await processor.ProcessModuleAsync(osqueryResults, deviceId);
                        
                        // Validate the module data
                        var isValid = await processor.ValidateModuleDataAsync(moduleData);
                        if (!isValid)
                        {
                            _logger.LogWarning("Module {ModuleId} data validation failed", processor.ModuleId);
                        }

                        // Save module data locally - use the actual runtime type for proper serialization
                        await SaveModuleDataWithRuntimeType(processor.ModuleId, moduleData);

                        // Assign to payload based on module type
                        AssignModuleDataToPayload(payload, moduleData);
                        
                        // Log completion with checkmark
                        _logger.LogInformation("✓ Module {ModuleId} completed", processor.ModuleId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error processing module {ModuleId}", processor.ModuleId);
                        // Continue with other modules even if one fails
                    }
                }

                // Save unified payload
                await SaveUnifiedPayloadAsync(payload);

                _logger.LogInformation("Modular data collection completed successfully");
                return payload;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during modular data collection");
                throw;
            }
        }

        /// <summary>
        /// Collect data from a specific module
        /// </summary>
        public async Task<T?> CollectModuleDataAsync<T>(string moduleId) where T : BaseModuleData
        {
            _logger.LogDebug("Collecting data for module: {ModuleId}", moduleId);

            var processor = _moduleProcessorFactory.GetProcessor<T>();
            if (processor == null)
            {
                _logger.LogWarning("No processor found for module: {ModuleId}", moduleId);
                return null;
            }

            // Load and execute queries for this specific module
            var modularQueries = _modularOsQueryService.LoadModularQueries();
            var osqueryResults = await ExecuteModularQueriesAsync(modularQueries);
            var deviceId = ExtractDeviceUuid(osqueryResults);

            return await processor.ProcessModuleAsync(osqueryResults, deviceId);
        }

        /// <summary>
        /// Save module data to local cache using runtime type information
        /// </summary>
        private async Task SaveModuleDataWithRuntimeType(string moduleId, BaseModuleData data)
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, $"{moduleId}.json");
                
                // Serialize using the actual runtime type to preserve all properties
                var actualType = data.GetType();
                var json = JsonSerializer.Serialize(data, actualType, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                });

                await File.WriteAllTextAsync(filePath, json);
                _logger.LogDebug("Module {ModuleId} data saved to: {FilePath} (type: {DataType})", moduleId, filePath, actualType.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save module {ModuleId} data locally", moduleId);
            }
        }

        /// <summary>
        /// Save module data to local cache
        /// </summary>
        public async Task SaveModuleDataLocallyAsync<T>(string moduleId, T data) where T : BaseModuleData
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, $"{moduleId}.json");
                
                // Serialize using the actual runtime type to preserve all properties
                var json = JsonSerializer.Serialize((object)data, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                });

                await File.WriteAllTextAsync(filePath, json);
                _logger.LogDebug("Module {ModuleId} data saved to: {FilePath}", moduleId, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save module {ModuleId} data locally", moduleId);
            }
        }

        /// <summary>
        /// Load cached module data
        /// </summary>
        public async Task<UnifiedDevicePayload> LoadCachedDataAsync()
        {
            var payload = new UnifiedDevicePayload
            {
                CollectedAt = DateTime.UtcNow,
                Platform = "Windows"
            };

            try
            {
                var cacheFiles = Directory.GetFiles(_cacheDirectory, "*.json");
                _logger.LogInformation("Loading {FileCount} cached module files", cacheFiles.Length);

                foreach (var file in cacheFiles)
                {
                    try
                    {
                        var fileName = Path.GetFileNameWithoutExtension(file);
                        var moduleId = fileName; // Use filename directly as it's already the moduleId
                        
                        var json = await File.ReadAllTextAsync(file);
                        
                        // Load module data based on module ID
                        BaseModuleData? moduleData = moduleId switch
                        {
                            "applications" => JsonSerializer.Deserialize<ApplicationsData>(json),
                            "hardware" => JsonSerializer.Deserialize<HardwareData>(json),
                            "inventory" => JsonSerializer.Deserialize<InventoryData>(json),
                            "installs" => JsonSerializer.Deserialize<InstallsData>(json),
                            "management" => JsonSerializer.Deserialize<ManagementData>(json),
                            "network" => JsonSerializer.Deserialize<NetworkData>(json),
                            "profiles" => JsonSerializer.Deserialize<ProfilesData>(json),
                            "security" => JsonSerializer.Deserialize<SecurityData>(json),
                            "system" => JsonSerializer.Deserialize<SystemData>(json),
                            _ => null
                        };

                        if (moduleData != null)
                        {
                            AssignModuleDataToPayload(payload, moduleData);
                            payload.DeviceId = moduleData.DeviceId;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to load cached file: {File}", file);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading cached data");
            }

            return payload;
        }

        /// <summary>
        /// Validate module data
        /// </summary>
        public async Task<bool> ValidateModuleDataAsync(string moduleId, object data)
        {
            var processor = _moduleProcessorFactory.GetProcessor(moduleId);
            if (processor == null)
            {
                _logger.LogWarning("No processor found for validation of module: {ModuleId}", moduleId);
                return false;
            }

            if (data is BaseModuleData moduleData)
            {
                return await processor.ValidateModuleDataAsync(moduleData);
            }

            _logger.LogWarning("Data is not of type BaseModuleData for module: {ModuleId}", moduleId);
            return false;
        }

        /// <summary>
        /// Execute osquery queries using the modular configuration
        /// </summary>
        private async Task<Dictionary<string, List<Dictionary<string, object>>>> ExecuteModularQueriesAsync(
            Dictionary<string, object> modularQueries)
        {
            _logger.LogInformation("Executing {QueryCount} osquery queries", modularQueries.Count);
            
            try
            {
                var results = new Dictionary<string, List<Dictionary<string, object>>>();
                var current = 0;
                
                foreach (var kvp in modularQueries)
                {
                    current++;
                    string? queryString = null;
                    
                    try
                    {
                        // Extract the SQL query string from the modular query structure
                        if (kvp.Value is JsonElement element && element.ValueKind == JsonValueKind.Object)
                        {
                            if (element.TryGetProperty("query", out var queryProperty))
                            {
                                queryString = queryProperty.GetString();
                            }
                        }
                        else if (kvp.Value is string directQuery)
                        {
                            queryString = directQuery;
                        }

                        if (string.IsNullOrEmpty(queryString))
                        {
                            _logger.LogWarning("No query string found for query: {QueryName}", kvp.Key);
                            continue;
                        }

                        // Show progress with cool progress bar for osquery execution
                        ConsoleFormatter.WriteQueryProgress(kvp.Key, current, modularQueries.Count);
                        
                        var queryResult = await _osQueryService.ExecuteQueryAsync(queryString);
                        
                        if (queryResult != null && queryResult.Count > 0)
                        {
                            List<Dictionary<string, object>> resultList;
                            
                            // Check if this is a multi-result response
                            if (queryResult.ContainsKey("results") && queryResult["results"] is JsonElement resultsElement)
                            {
                                // Multiple results - extract the actual results array
                                try
                                {
                                    _logger.LogDebug("Query {QueryName} returned multi-results, parsing JSON array", kvp.Key);
                                    var resultsJson = resultsElement.GetRawText();
                                    var multiResults = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(resultsJson);
                                    resultList = multiResults ?? new List<Dictionary<string, object>>();
                                    _logger.LogDebug("Query {QueryName} parsed {Count} results from JSON array", kvp.Key, resultList.Count);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogWarning(ex, "Failed to parse multi-results for query {QueryName}, treating as single result", kvp.Key);
                                    resultList = new List<Dictionary<string, object>> { queryResult };
                                }
                            }
                            else if (queryResult.ContainsKey("results") && queryResult["results"] is List<Dictionary<string, object>> resultsList)
                            {
                                // Results is already a List<Dictionary<string, object>>
                                _logger.LogDebug("Query {QueryName} returned results as direct list with {Count} items", kvp.Key, resultsList.Count);
                                resultList = resultsList;
                            }
                            else
                            {
                                // Single result - wrap in list
                                _logger.LogDebug("Query {QueryName} returned single result, wrapping in list", kvp.Key);
                                resultList = new List<Dictionary<string, object>> { queryResult };
                            }
                            
                            results[kvp.Key] = resultList;
                            _logger.LogDebug("Query {QueryName} returned {ResultCount} results", kvp.Key, resultList.Count);
                        }
                        else
                        {
                            _logger.LogDebug("Query {QueryName} returned no results", kvp.Key);
                            results[kvp.Key] = new List<Dictionary<string, object>>();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error executing query: {QueryName}", kvp.Key);
                        results[kvp.Key] = new List<Dictionary<string, object>>();
                    }
                }

                _logger.LogInformation("Completed executing osquery queries. {ResultCount} result sets collected", results.Count);
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing modular queries");
                return new Dictionary<string, List<Dictionary<string, object>>>();
            }
        }

        /// <summary>
        /// Extract device UUID from osquery results
        /// </summary>
        private string ExtractDeviceUuid(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("uuid", out var uuid) && !string.IsNullOrEmpty(uuid?.ToString()))
                {
                    var uuidStr = uuid.ToString();
                    if (!string.IsNullOrEmpty(uuidStr) && uuidStr != "00000000-0000-0000-0000-000000000000")
                    {
                        return uuidStr;
                    }
                }
            }

            // Fallback to machine name if no valid UUID found
            return Environment.MachineName;
        }

        /// <summary>
        /// Get client version
        /// </summary>
        private string GetClientVersion()
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version;
                return version?.ToString() ?? "1.0.0";
            }
            catch
            {
                return "1.0.0";
            }
        }

        /// <summary>
        /// Assign module data to the appropriate property in the unified payload
        /// </summary>
        private void AssignModuleDataToPayload(UnifiedDevicePayload payload, BaseModuleData moduleData)
        {
            switch (moduleData)
            {
                case ApplicationsData applicationsData:
                    payload.Applications = applicationsData;
                    break;
                case HardwareData hardwareData:
                    payload.Hardware = hardwareData;
                    break;
                case InventoryData inventoryData:
                    payload.Inventory = inventoryData;
                    break;
                case InstallsData installsData:
                    payload.Installs = installsData;
                    break;
                case ManagementData managementData:
                    payload.Management = managementData;
                    break;
                case NetworkData networkData:
                    payload.Network = networkData;
                    break;
                case ProfilesData profilesData:
                    payload.Profiles = profilesData;
                    break;
                case SecurityData securityData:
                    payload.Security = securityData;
                    break;
                case SystemData systemData:
                    payload.System = systemData;
                    break;
                default:
                    _logger.LogWarning("Unknown module data type: {ModuleType}", moduleData.GetType().Name);
                    break;
            }
        }

        /// <summary>
        /// Save unified payload to cache
        /// </summary>
        private async Task SaveUnifiedPayloadAsync(UnifiedDevicePayload payload)
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, "event.json");
                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                });

                await File.WriteAllTextAsync(filePath, json);
                _logger.LogInformation("Unified payload saved to: {FilePath}", filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save unified payload");
            }
        }

        /// <summary>
        /// Clean up old cache directories to prevent disk space issues
        /// </summary>
        private void CleanupOldCacheFiles()
        {
            try
            {
                if (!Directory.Exists(_baseDirectory))
                    return;

                var directories = Directory.GetDirectories(_baseDirectory)
                    .Where(d => Path.GetFileName(d).Length == 17) // YYYY-MM-DD-HHmmss format
                    .Select(d => new DirectoryInfo(d))
                    .Where(di => di.CreationTime < DateTime.Now.AddHours(-24)) // Keep last 24 hours
                    .OrderBy(di => di.CreationTime)
                    .Take(Directory.GetDirectories(_baseDirectory).Length - 5) // Keep at least 5 most recent
                    .ToList();

                foreach (var dir in directories)
                {
                    try
                    {
                        dir.Delete(true);
                        _logger.LogDebug("Cleaned up old cache directory: {Directory}", dir.FullName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to cleanup cache directory: {Directory}", dir.FullName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during cache cleanup");
            }
        }
    }
}
