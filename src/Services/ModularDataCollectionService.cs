#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;
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
        Task<BaseModuleData?> CollectSingleModuleDataAsync(string moduleId);
        Task<UnifiedDevicePayload> CreateSingleModuleUnifiedPayloadAsync(BaseModuleData moduleData);
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
                
                // Process each module's data using the modular architecture
                var enabledProcessors = _moduleProcessorFactory.GetEnabledProcessors().ToList();
                _logger.LogInformation("Processing {ProcessorCount} enabled modules", enabledProcessors.Count);

                // Extract device UUID and serial number for individual modules
                var deviceId = ExtractDeviceUuid(osqueryResults);
                var serialNumber = ExtractSerialNumber(osqueryResults);
                
                // Create unified payload with metadata at the top
                var payload = new UnifiedDevicePayload();
                payload.Metadata = new EventMetadata
                {
                    DeviceId = deviceId,
                    SerialNumber = serialNumber,
                    CollectedAt = DateTime.UtcNow,
                    ClientVersion = GetClientVersion(),
                    Platform = "Windows",
                    CollectionType = "Full",
                    EnabledModules = enabledProcessors.Select(p => p.ModuleId).ToList()
                };

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

                        // Generate events from module data
                        try
                        {
                            var moduleEvents = await processor.GenerateEventsAsync(moduleData);
                            if (moduleEvents.Any())
                            {
                                payload.Events.AddRange(moduleEvents);
                                _logger.LogDebug("Generated {EventCount} events from module {ModuleId}", moduleEvents.Count, processor.ModuleId);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to generate events from module {ModuleId}", processor.ModuleId);
                        }
                        
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
        /// Collect data from a single specific module (efficient version for --run-module flag)
        /// </summary>
        public async Task<BaseModuleData?> CollectSingleModuleDataAsync(string moduleId)
        {
            _logger.LogInformation("Starting single module collection for: {ModuleId}", moduleId);

            try
            {
                // Get the processor for this module
                var processor = _moduleProcessorFactory.GetProcessor(moduleId);
                if (processor == null)
                {
                    _logger.LogWarning("No processor found for module: {ModuleId}", moduleId);
                    return null;
                }

                // Load queries for ONLY this specific module (plus system_info for device UUID)
                _logger.LogInformation("Loading queries for single module: {ModuleId}", moduleId);
                var moduleQueries = _modularOsQueryService.LoadModuleQueries(moduleId);
                _logger.LogInformation("Loaded {QueryCount} queries for module {ModuleId}", moduleQueries.Count, moduleId);
                
                // Execute only the queries for this specific module
                var osqueryResults = await ExecuteModularQueriesAsync(moduleQueries);
                _logger.LogInformation("Executed {ResultCount} queries for module {ModuleId}", osqueryResults.Count, moduleId);
                
                // Extract device UUID for individual modules
                var deviceId = ExtractDeviceUuid(osqueryResults);

                // Process the module data
                _logger.LogInformation("Processing module: {ModuleId}", processor.ModuleId);
                var moduleData = await processor.ProcessModuleAsync(osqueryResults, deviceId);
                
                // Validate the module data
                var isValid = await processor.ValidateModuleDataAsync(moduleData);
                if (!isValid)
                {
                    _logger.LogWarning("Module {ModuleId} data validation failed", processor.ModuleId);
                }

                // Generate events from module data (for single module collections)
                try
                {
                    var moduleEvents = await processor.GenerateEventsAsync(moduleData);
                    if (moduleEvents.Any())
                    {
                        _logger.LogInformation("Generated {EventCount} events from single module {ModuleId}", moduleEvents.Count, processor.ModuleId);
                        // Note: For single module collection, events will be added to unified payload in CreateSingleModuleUnifiedPayloadAsync
                    }
                    else
                    {
                        _logger.LogDebug("No events generated from single module {ModuleId}", processor.ModuleId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to generate events from single module {ModuleId}", processor.ModuleId);
                }

                // Save module data locally
                await SaveModuleDataWithRuntimeType(processor.ModuleId, moduleData);

                _logger.LogInformation("✓ Single module {ModuleId} collection completed", processor.ModuleId);
                return moduleData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during single module collection for {ModuleId}", moduleId);
                return null;
            }
        }

        /// <summary>
        /// Create a unified payload structure for a single module (for --run-module support)
        /// This enables --transmit-only to work with single module collections
        /// </summary>
        public async Task<UnifiedDevicePayload> CreateSingleModuleUnifiedPayloadAsync(BaseModuleData moduleData)
        {
            _logger.LogInformation("Creating unified payload for single module: {ModuleId}", moduleData.ModuleId);

            try
            {
                // For single module collection, we need to get serial number from a system query
                // Since we don't have the full osquery results, run a minimal query to get device info
                var systemQueries = new Dictionary<string, object>
                {
                    ["system_info"] = "SELECT uuid, hardware_serial, computer_name FROM system_info;"
                };

                var systemResults = await ExecuteModularQueriesAsync(systemQueries);
                var serialNumber = ExtractSerialNumber(systemResults);

                // Create unified payload with metadata
                var payload = new UnifiedDevicePayload();
                payload.Metadata = new EventMetadata
                {
                    DeviceId = moduleData.DeviceId,
                    SerialNumber = serialNumber,
                    CollectedAt = moduleData.CollectedAt,
                    ClientVersion = GetClientVersion(),
                    Platform = "Windows",
                    CollectionType = "Single",
                    EnabledModules = new List<string> { moduleData.ModuleId }
                };

                // Assign the single module data to the payload
                AssignModuleDataToPayload(payload, moduleData);

                // Generate events for the single module and add to unified payload
                try
                {
                    var processor = _moduleProcessorFactory.GetProcessor(moduleData.ModuleId);
                    if (processor != null)
                    {
                        var moduleEvents = await processor.GenerateEventsAsync(moduleData);
                        if (moduleEvents.Any())
                        {
                            payload.Events.AddRange(moduleEvents);
                            _logger.LogInformation("Added {EventCount} events from single module {ModuleId} to unified payload", moduleEvents.Count, moduleData.ModuleId);
                        }
                        else
                        {
                            _logger.LogDebug("No events to add from single module {ModuleId} to unified payload", moduleData.ModuleId);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to generate events for single module {ModuleId} in unified payload", moduleData.ModuleId);
                }

                // Save the unified payload as event.json
                await SaveUnifiedPayloadAsync(payload);

                _logger.LogInformation("✓ Unified payload created for single module: {ModuleId}", moduleData.ModuleId);
                return payload;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating unified payload for single module: {ModuleId}", moduleData.ModuleId);
                throw;
            }
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
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Prevent unnecessary Unicode escaping
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
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Prevent unnecessary Unicode escaping
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
            var payload = new UnifiedDevicePayload();
            payload.Metadata = new EventMetadata
            {
                CollectedAt = DateTime.UtcNow,
                Platform = "Windows"
            };

            try
            {
                // Find the most recent cache directory
                var baseCacheDirectory = Path.Combine("C:", "ProgramData", "ManagedReports", "cache");
                if (!Directory.Exists(baseCacheDirectory))
                {
                    _logger.LogWarning("Cache base directory not found: {Directory}", baseCacheDirectory);
                    return payload;
                }

                var cacheDirectories = Directory.GetDirectories(baseCacheDirectory)
                    .Where(d => Path.GetFileName(d).Length == 17) // Format: YYYY-MM-DD-HHmmss
                    .OrderByDescending(d => Path.GetFileName(d))
                    .ToList();

                if (!cacheDirectories.Any())
                {
                    _logger.LogWarning("No cache directories found in: {Directory}", baseCacheDirectory);
                    return payload;
                }

                // Find the latest cache directory that has data (not empty)
                string? latestCacheDirectory = null;
                foreach (var dir in cacheDirectories)
                {
                    var jsonFiles = Directory.GetFiles(dir, "*.json");
                    if (jsonFiles.Length > 0)
                    {
                        latestCacheDirectory = dir;
                        break;
                    }
                }

                if (latestCacheDirectory == null)
                {
                    _logger.LogWarning("No cache directories with data found in: {Directory}", baseCacheDirectory);
                    return payload;
                }

                _logger.LogInformation("Using latest cache directory: {Directory}", Path.GetFileName(latestCacheDirectory));

                var cacheFiles = Directory.GetFiles(latestCacheDirectory, "*.json");
                _logger.LogInformation("Loading {FileCount} cached module files", cacheFiles.Length);

                foreach (var file in cacheFiles)
                {
                    try
                    {
                        var fileName = Path.GetFileNameWithoutExtension(file);
                        var moduleId = fileName; // Use filename directly as it's already the moduleId
                        
                        // Skip the event.json file as it's the unified payload, not individual module data
                        if (moduleId == "event")
                        {
                            continue;
                        }
                        
                        var json = await File.ReadAllTextAsync(file);
                        
                        // JSON options for deserialization
                        var jsonOptions = new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
                            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Prevent unnecessary Unicode escaping
                        };
                        
                        // Load module data based on module ID
                        BaseModuleData? moduleData = moduleId switch
                        {
                            "applications" => JsonSerializer.Deserialize<ApplicationsData>(json, jsonOptions),
                            "hardware" => JsonSerializer.Deserialize<HardwareData>(json, jsonOptions),
                            "inventory" => JsonSerializer.Deserialize<InventoryData>(json, jsonOptions),
                            "installs" => JsonSerializer.Deserialize<InstallsData>(json, jsonOptions),
                            "management" => JsonSerializer.Deserialize<ManagementData>(json, jsonOptions),
                            "network" => JsonSerializer.Deserialize<NetworkData>(json, jsonOptions),
                            "printers" => JsonSerializer.Deserialize<PrinterData>(json, jsonOptions),
                            "displays" => JsonSerializer.Deserialize<DisplayData>(json, jsonOptions),
                            "profiles" => JsonSerializer.Deserialize<ProfilesData>(json, jsonOptions),
                            "security" => JsonSerializer.Deserialize<SecurityData>(json, jsonOptions),
                            "system" => JsonSerializer.Deserialize<SystemData>(json, jsonOptions),
                            _ => null
                        };

                        if (moduleData != null)
                        {
                            AssignModuleDataToPayload(payload, moduleData);
                            payload.Metadata.DeviceId = moduleData.DeviceId;
                            // Don't override ClientVersion - it's already set correctly in the payload initialization
                            
                            // Use the collection time from the cached data if it's more recent
                            if (moduleData.CollectedAt > payload.Metadata.CollectedAt || payload.Metadata.CollectedAt == DateTime.MinValue)
                            {
                                payload.Metadata.CollectedAt = moduleData.CollectedAt;
                            }

                            _logger.LogDebug("Loaded cached module: {ModuleId} (Device: {DeviceId})", moduleId, moduleData.DeviceId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to load cached file: {File}", file);
                    }
                }

                _logger.LogInformation("Loaded cached data with Device ID: {DeviceId}, Collection Time: {CollectedAt}", 
                    payload.Metadata.DeviceId, payload.Metadata.CollectedAt);
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
                        // Check if this is a known optional query that might fail
                        var isOptionalQuery = kvp.Key.Equals("battery", StringComparison.OrdinalIgnoreCase);
                        var isTableNotFoundError = ex.Message.Contains("no such table", StringComparison.OrdinalIgnoreCase);
                        
                        if (isOptionalQuery && isTableNotFoundError)
                        {
                            _logger.LogDebug("Optional query {QueryName} failed as expected on this platform: {Error}", kvp.Key, ex.Message);
                        }
                        else
                        {
                            _logger.LogError(ex, "Error executing query: {QueryName}", kvp.Key);
                        }
                        
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
            // Method 1: Try osquery system_info UUID
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("uuid", out var uuid) && !string.IsNullOrEmpty(uuid?.ToString()))
                {
                    var uuidStr = uuid.ToString();
                    if (!string.IsNullOrEmpty(uuidStr) && uuidStr != "00000000-0000-0000-0000-000000000000")
                    {
                        _logger.LogInformation("Device UUID extracted from osquery system_info: {UUID}", uuidStr);
                        return uuidStr;
                    }
                }
            }

            // Method 2: Try Registry MachineGuid (skip WMI due to reliability issues)
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    if (key != null)
                    {
                        var machineGuid = key.GetValue("MachineGuid")?.ToString();
                        if (!string.IsNullOrEmpty(machineGuid))
                        {
                            _logger.LogInformation("Device UUID extracted from Registry MachineGuid: {UUID}", machineGuid);
                            return machineGuid;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to extract UUID from Registry MachineGuid");
            }

            // Method 4: Generate a new UUID based on hardware characteristics
            try
            {
                var hardwareFingerprint = GenerateHardwareBasedUuid();
                if (!string.IsNullOrEmpty(hardwareFingerprint))
                {
                    _logger.LogInformation("Device UUID generated from hardware fingerprint: {UUID}", hardwareFingerprint);
                    return hardwareFingerprint;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to generate hardware-based UUID");
            }

            _logger.LogError("Unable to extract device UUID from any method - no fallback available");
            throw new InvalidOperationException("Failed to extract device UUID from osquery, BIOS serial, or motherboard serial");
        }

        /// <summary>
        /// Generate a deterministic UUID based on hardware characteristics
        /// This ensures the same machine gets the same UUID even if other methods fail
        /// </summary>
        private string GenerateHardwareBasedUuid()
        {
            try
            {
                var hardwareInfo = new List<string>();

                // Get CPU info
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                    {
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            var processorId = obj["ProcessorId"]?.ToString();
                            if (!string.IsNullOrEmpty(processorId))
                            {
                                hardwareInfo.Add($"CPU:{processorId}");
                                break; // Only need first CPU
                            }
                        }
                    }
                }
                catch { /* Continue with other methods */ }

                // Get motherboard serial
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                    {
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            var serialNumber = obj["SerialNumber"]?.ToString();
                            if (!string.IsNullOrEmpty(serialNumber) && serialNumber.Trim() != "." && !serialNumber.Contains("To be filled"))
                            {
                                hardwareInfo.Add($"MB:{serialNumber}");
                                break;
                            }
                        }
                    }
                }
                catch { /* Continue with other methods */ }

                // Get BIOS serial
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                    {
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            var biosSerial = obj["SerialNumber"]?.ToString();
                            if (!string.IsNullOrEmpty(biosSerial) && !biosSerial.Contains("To be filled"))
                            {
                                hardwareInfo.Add($"BIOS:{biosSerial}");
                                break;
                            }
                        }
                    }
                }
                catch { /* Continue with other methods */ }

                if (hardwareInfo.Count > 0)
                {
                    // Create deterministic UUID from hardware fingerprint
                    var fingerprint = string.Join("|", hardwareInfo);
                    var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fingerprint));
                    
                    // Convert hash to UUID format
                    var guidBytes = new byte[16];
                    Array.Copy(hash, 0, guidBytes, 0, 16);
                    var hardwareUuid = new Guid(guidBytes);
                    
                    return hardwareUuid.ToString().ToUpper();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to generate hardware-based UUID");
            }

            return string.Empty;
        }

        /// <summary>
        /// Extract device serial number from osquery results
        /// </summary>
        private string ExtractSerialNumber(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("hardware_serial", out var serial) && !string.IsNullOrEmpty(serial?.ToString()))
                {
                    var serialStr = serial.ToString();
                    if (!string.IsNullOrEmpty(serialStr) && 
                        serialStr != "0" && 
                        serialStr != "System Serial Number" &&
                        serialStr != "To be filled by O.E.M." &&
                        serialStr != "Default string" &&
                        serialStr != Environment.MachineName &&
                        !serialStr.StartsWith("00000000"))
                    {
                        return serialStr;
                    }
                }
                
                if (firstResult.TryGetValue("computer_name", out var computerName) && !string.IsNullOrEmpty(computerName?.ToString()))
                {
                    var computerNameStr = computerName.ToString();
                    if (!string.IsNullOrEmpty(computerNameStr) && computerNameStr != Environment.MachineName)
                    {
                        return computerNameStr;
                    }
                }
            }

            // Try chassis info as fallback
            if (osqueryResults.TryGetValue("chassis_info", out var chassisInfo) && chassisInfo.Count > 0)
            {
                var chassis = chassisInfo[0];
                if (chassis.TryGetValue("serial", out var chassisSerial) && !string.IsNullOrEmpty(chassisSerial?.ToString()))
                {
                    var chassisSerialStr = chassisSerial.ToString();
                    if (!string.IsNullOrEmpty(chassisSerialStr) && 
                        chassisSerialStr != "0" && 
                        chassisSerialStr != "System Serial Number" &&
                        chassisSerialStr != "To be filled by O.E.M." &&
                        chassisSerialStr != Environment.MachineName)
                    {
                        return chassisSerialStr;
                    }
                }
            }

            // Fallback to machine name if no valid serial found
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
                if (version != null)
                {
                    // Format as YYYY.MM.DD.HHMM (full 4-part version)
                    return $"{version.Major:D4}.{version.Minor:D2}.{version.Build:D2}.{version.Revision:D4}";
                }
                return "1.0.0";
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
                case PrinterData printerData:
                    payload.Printers = printerData;
                    break;
                case DisplayData displayData:
                    payload.Displays = displayData;
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
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Prevent unnecessary Unicode escaping
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
