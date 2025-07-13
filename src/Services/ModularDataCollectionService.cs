#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Modular data collection service that coordinates individual module data collection
    /// and creates local cached JSON files for each module
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
        private readonly IWmiHelperService _wmiHelperService;
        private readonly string _cacheDirectory;
        private readonly string _baseDirectory;

        public ModularDataCollectionService(
            ILogger<ModularDataCollectionService> logger,
            IOsQueryService osQueryService,
            ModularOsQueryService modularOsQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _osQueryService = osQueryService;
            _modularOsQueryService = modularOsQueryService;
            _wmiHelperService = wmiHelperService;
            _baseDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ManagedReports", "cache");
            
            // Create timestamped cache directory (YYYY-MM-DD-HHmmss)
            var now = DateTime.Now;
            var timestamp = now.ToString("yyyy-MM-dd-HHmmss");
            _cacheDirectory = Path.Combine(_baseDirectory, timestamp);
            
            Directory.CreateDirectory(_cacheDirectory);
            
            // Clean up old cache files
            _ = Task.Run(CleanupOldCacheAsync);
        }

        /// <summary>
        /// Collect data from all enabled modules and create unified payload
        /// </summary>
        public async Task<UnifiedDevicePayload> CollectAllModuleDataAsync()
        {
            _logger.LogInformation("Starting modular data collection for all enabled modules");

            try
            {
                // Load modular osquery configuration
                _logger.LogInformation("LOADING modular queries...");
                var modularQueries = _modularOsQueryService.LoadModularQueries();
                _logger.LogInformation($"LOADED {modularQueries.Count} modular queries successfully");
                
                _logger.LogInformation($"ABOUT TO CALL ExecuteModularQueriesAsync with {modularQueries.Count} queries");
                
                // Execute all osquery queries in one pass
                var osqueryResults = await ExecuteModularQueriesAsync(modularQueries);
                
                _logger.LogInformation($"RETURNED FROM ExecuteModularQueriesAsync with {osqueryResults.Count} results");
                
                // Extract device UUID for individual modules
                var deviceId = ExtractDeviceUuid(osqueryResults);
                
                // Create unified payload
                var payload = new UnifiedDevicePayload
                {
                    DeviceId = deviceId,  // UUID for DeviceId field
                    CollectedAt = DateTime.UtcNow,
                    ClientVersion = GetClientVersion(),
                    Platform = "Windows"
                };

                // Process each module's data
                payload.Applications = await ProcessApplicationsModuleAsync(osqueryResults, deviceId);
                payload.Hardware = await ProcessHardwareModuleAsync(osqueryResults, deviceId);
                payload.Inventory = await ProcessInventoryModuleAsync(osqueryResults, deviceId);
                payload.Installs = await ProcessInstallsModuleAsync(osqueryResults, deviceId);
                payload.Management = await ProcessManagementModuleAsync(osqueryResults, deviceId);
                payload.Network = await ProcessNetworkModuleAsync(osqueryResults, deviceId);
                payload.Profiles = await ProcessProfilesModuleAsync(osqueryResults, deviceId);
                payload.Security = await ProcessSecurityModuleAsync(osqueryResults, deviceId);
                payload.System = await ProcessSystemModuleAsync(osqueryResults, deviceId);

                // Save each module data to cache
                await SaveModulesToCacheAsync(payload);

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
        /// Execute osquery queries using the modular configuration
        /// </summary>
        private async Task<Dictionary<string, List<Dictionary<string, object>>>> ExecuteModularQueriesAsync(
            Dictionary<string, object> modularQueries)
        {
            _logger.LogInformation($"MODULAR SERVICE: Executing {modularQueries.Count} osquery queries [UNIQUE LOG]");
            Logger.Section("osQuery Execution", $"Processing {modularQueries.Count} queries across all modules");
            
            try
            {
                _logger.LogInformation($"Method ExecuteModularQueriesAsync called successfully");
                _logger.LogInformation($"Starting query conversion. Input has {modularQueries.Count} items");
                
                // Execute queries directly without temp files
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
                            if (element.TryGetProperty("query", out var queryProp) && queryProp.ValueKind == JsonValueKind.String)
                            {
                                queryString = queryProp.GetString();
                            }
                        }
                        else if (kvp.Value is string directQuery)
                        {
                            queryString = directQuery;
                        }
                        
                        if (!string.IsNullOrEmpty(queryString))
                        {
                            _logger.LogDebug($"Executing query '{kvp.Key}': {queryString.Substring(0, Math.Min(100, queryString.Length))}...");
                            
                            // Execute query directly
                            var queryResult = await _osQueryService.ExecuteQueryAsync(queryString);
                            if (queryResult != null)
                            {
                                List<Dictionary<string, object>> resultList;
                                
                                // Handle the result structure from ExecuteQueryAsync
                                if (queryResult.ContainsKey("results") && queryResult["results"] is List<Dictionary<string, object>> list)
                                {
                                    resultList = list;
                                }
                                else
                                {
                                    // Single result case - wrap in list
                                    resultList = new List<Dictionary<string, object>> { queryResult };
                                }
                                
                                results[kvp.Key] = resultList;
                                _logger.LogDebug($"Query '{kvp.Key}' returned {resultList.Count} results");
                                Logger.Progress($"Query: {kvp.Key}", current, modularQueries.Count, $"{resultList.Count} results");
                            }
                            else
                            {
                                results[kvp.Key] = new List<Dictionary<string, object>>();
                                Logger.Progress($"Query: {kvp.Key}", current, modularQueries.Count, "no results");
                            }
                        }
                        else
                        {
                            _logger.LogWarning($"Could not extract query string from '{kvp.Key}'");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error executing query '{kvp.Key}': {queryString}");
                        Logger.Progress($"Query: {kvp.Key}", current, modularQueries.Count, "ERROR");
                        results[kvp.Key] = new List<Dictionary<string, object>>();
                    }
                }
                
                _logger.LogInformation($"Successfully executed {results.Count} modular queries");
                Logger.Info("✓ Completed {0} osquery operations", results.Count);
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ExecuteModularQueriesAsync");
                return new Dictionary<string, List<Dictionary<string, object>>>();
            }
        }

        /// <summary>
        /// Extract device UUID from osquery results  
        /// </summary>
        private string ExtractDeviceUuid(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // Try to get UUID from system_info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("uuid", out var uuid) && !string.IsNullOrEmpty(uuid?.ToString()))
                {
                    var uuidStr = uuid.ToString()!.Trim();
                    if (!string.IsNullOrEmpty(uuidStr) && uuidStr != "00000000-0000-0000-0000-000000000000")
                    {
                        return uuidStr;
                    }
                }
            }
            
            // Fallback: generate a deterministic UUID based on machine name
            var machineName = Environment.MachineName;
            _logger.LogWarning("No valid UUID found in osquery data, generating deterministic UUID from machine name: {MachineName}", machineName);
            
            // Create a deterministic GUID from the machine name
            var bytes = System.Text.Encoding.UTF8.GetBytes(machineName);
            var hashBytes = System.Security.Cryptography.MD5.HashData(bytes);
            return new Guid(hashBytes).ToString().ToUpper();
        }

        /// <summary>
        /// Extract device serial number from osquery results
        /// </summary>
        private string ExtractSerialNumber(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            _logger.LogDebug("Extracting serial number from osquery results");
            
            // Try multiple approaches to get the serial number
            
            // 1. Try system_info table for hardware_serial
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                
                _logger.LogDebug("system_info fields available: {Fields}", string.Join(", ", firstResult.Keys));
                
                // Try hardware_serial field
                if (firstResult.TryGetValue("hardware_serial", out var serial) && !string.IsNullOrEmpty(serial?.ToString()))
                {
                    var serialStr = serial.ToString()!.Trim();
                    _logger.LogDebug("hardware_serial found: '{Serial}'", serialStr);
                    
                    if (!string.IsNullOrEmpty(serialStr) && 
                        serialStr != "0" && 
                        serialStr != "System Serial Number" &&
                        serialStr != "To be filled by O.E.M." &&
                        serialStr != "Default string" &&
                        serialStr != Environment.MachineName &&
                        !serialStr.StartsWith("00000000"))
                    {
                        _logger.LogInformation("Using hardware serial: {Serial}", serialStr);
                        return serialStr;
                    }
                }
                
                // Try computer_name as backup
                if (firstResult.TryGetValue("computer_name", out var computerName) && !string.IsNullOrEmpty(computerName?.ToString()))
                {
                    var computerNameStr = computerName.ToString()!.Trim();
                    _logger.LogDebug("computer_name found: '{ComputerName}'", computerNameStr);
                    if (!string.IsNullOrEmpty(computerNameStr) && computerNameStr != Environment.MachineName)
                    {
                        _logger.LogInformation("Using computer name as serial: {Serial}", computerNameStr);
                        return computerNameStr;
                    }
                }
            }
            
            // 2. Try chassis_info for serial (corrected field name)
            if (osqueryResults.TryGetValue("chassis_info", out var chassisInfo) && chassisInfo.Count > 0)
            {
                var chassis = chassisInfo[0];
                if (chassis.TryGetValue("serial", out var chassisSerial) && !string.IsNullOrEmpty(chassisSerial?.ToString()))
                {
                    var chassisSerialStr = chassisSerial.ToString()!.Trim();
                    _logger.LogDebug("chassis serial found: '{Serial}'", chassisSerialStr);
                    
                    if (!string.IsNullOrEmpty(chassisSerialStr) && 
                        chassisSerialStr != "0" && 
                        chassisSerialStr != "System Serial Number" &&
                        chassisSerialStr != "To be filled by O.E.M." &&
                        chassisSerialStr != Environment.MachineName)
                    {
                        _logger.LogInformation("Using chassis serial: {Serial}", chassisSerialStr);
                        return chassisSerialStr;
                    }
                }
            }
            
            // 3. Direct osquery fallback - if modular queries didn't return valid serial
            _logger.LogDebug("Attempting direct osquery fallback for serial number...");
            try
            {
                var directResult = _osQueryService.ExecuteQueryAsync("SELECT hardware_serial FROM system_info;").Result;
                if (directResult != null)
                {
                    var directSerial = GetStringValue(directResult, "hardware_serial");
                    _logger.LogDebug(" Direct osquery hardware_serial: '{Serial}'", directSerial);
                    
                    if (!string.IsNullOrWhiteSpace(directSerial) && 
                        directSerial != "To be filled by O.E.M." && 
                        directSerial != "System Serial Number" && 
                        directSerial != "Default string" && 
                        directSerial != Environment.MachineName &&
                        directSerial.Length > 3)
                    {
                        _logger.LogInformation("Using direct osquery hardware serial: {Serial}", directSerial);
                        return directSerial;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Direct osquery fallback failed");
            }
            
            // 4. Try any other serial-related fields
            var serialFields = new[] { "serial", "serial_number", "hardware_serial" };
            foreach (var queryKey in osqueryResults.Keys)
            {
                if (osqueryResults[queryKey].Count > 0)
                {
                    var result = osqueryResults[queryKey][0];
                    foreach (var field in serialFields)
                    {
                        if (result.TryGetValue(field, out var value) && !string.IsNullOrEmpty(value?.ToString()))
                        {
                            var valueStr = value.ToString()!.Trim();
                            if (!string.IsNullOrEmpty(valueStr) && 
                                valueStr != "0" && 
                                valueStr != "System Serial Number" &&
                                valueStr != "To be filled by O.E.M." &&
                                valueStr != Environment.MachineName)
                            {
                                _logger.LogInformation("Using {Field} from {Query}: {Serial}", field, queryKey, valueStr);
                                return valueStr;
                            }
                        }
                    }
                }
            }
            
            // Ultimate fallback to machine name
            _logger.LogWarning("No valid hardware serial found, falling back to machine name: {MachineName}", Environment.MachineName);
            return Environment.MachineName;
        }

        /// <summary>
        /// Extract device ID from osquery results (DEPRECATED - use ExtractDeviceUuid and ExtractSerialNumber)
        /// </summary>
        private string ExtractDeviceId(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // For backward compatibility, this now calls ExtractSerialNumber
            return ExtractSerialNumber(osqueryResults);
        }

        /// <summary>
        /// Get client version
        /// </summary>
        private string GetClientVersion()
        {
            return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0";
        }

        /// <summary>
        /// Process Applications module data
        /// </summary>
        private async Task<ApplicationsData> ProcessApplicationsModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new ApplicationsData
            {
                ModuleId = "applications",
                DeviceId = deviceId
            };

            // Process installed programs
            if (osqueryResults.TryGetValue("programs", out var programs))
            {
                foreach (var program in programs)
                {
                    data.InstalledApplications.Add(new ReportMate.WindowsClient.Models.Modules.InstalledApplication
                    {
                        Name = GetStringValue(program, "name"),
                        Version = GetStringValue(program, "version"),
                        Publisher = GetStringValue(program, "publisher")
                    });
                }
            }

            // Process running processes
            if (osqueryResults.TryGetValue("processes", out var processes))
            {
                foreach (var process in processes)
                {
                    data.RunningProcesses.Add(new RunningProcess
                    {
                        ProcessId = GetIntValue(process, "pid"),
                        Name = GetStringValue(process, "name"),
                        Path = GetStringValue(process, "path")
                    });
                }
            }

            // Process startup items
            if (osqueryResults.TryGetValue("startup_items", out var startupItems))
            {
                foreach (var item in startupItems)
                {
                    data.StartupPrograms.Add(new StartupProgram
                    {
                        Name = GetStringValue(item, "name"),
                        Path = GetStringValue(item, "path"),
                        Location = GetStringValue(item, "source"),
                        Enabled = GetStringValue(item, "status").ToLowerInvariant() != "disabled"
                    });
                }
            }

            data.TotalApplications = data.InstalledApplications.Count;
            
            await SaveModuleDataLocallyAsync("applications", data);
            return data;
        }

        /// <summary>
        /// Process Hardware module data
        /// </summary>
        private async Task<HardwareData> ProcessHardwareModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new HardwareData
            {
                ModuleId = "hardware",
                DeviceId = deviceId
            };

            // Process system info for hardware specs AND manufacturer/model
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                
                // Extract manufacturer and model from system_info
                data.Manufacturer = GetStringValue(info, "hardware_vendor");
                data.Model = GetStringValue(info, "hardware_model");
                
                // Process processor info
                data.Processor.Name = GetStringValue(info, "cpu_brand");
                data.Processor.Cores = GetIntValue(info, "cpu_physical_cores");
                data.Processor.LogicalProcessors = GetIntValue(info, "cpu_logical_cores");
                data.Memory.TotalPhysical = GetLongValue(info, "physical_memory");
                
                _logger.LogDebug("Hardware system info extracted - Manufacturer: '{Manufacturer}', Model: '{Model}'", 
                    data.Manufacturer, data.Model);
            }

            // Check system_info_extended for manufacturer and model if not found in system_info
            if (osqueryResults.TryGetValue("system_info_extended", out var systemInfoExtended) && systemInfoExtended.Count > 0)
            {
                var info = systemInfoExtended[0];
                
                // Extract manufacturer and model from system_info_extended
                if (string.IsNullOrEmpty(data.Manufacturer))
                {
                    data.Manufacturer = GetStringValue(info, "hardware_vendor");
                }
                if (string.IsNullOrEmpty(data.Model))
                {
                    data.Model = GetStringValue(info, "hardware_model");
                }
                
                _logger.LogDebug("Hardware system info extended extracted - Manufacturer: '{Manufacturer}', Model: '{Model}'", 
                    data.Manufacturer, data.Model);
            }
            
            // ALWAYS attempt direct osquery fallback for manufacturer and model since modular queries are not working
            if (string.IsNullOrEmpty(data.Manufacturer) || string.IsNullOrEmpty(data.Model))
            {
                _logger.LogInformation("Attempting direct osquery for manufacturer/model (bypassing modular system)...");
                
                try
                {
                    // Try direct osquery first
                    var directResult = await _osQueryService.ExecuteQueryAsync("SELECT hardware_vendor, hardware_model FROM system_info;");
                    if (directResult != null)
                    {
                        var directManufacturer = GetStringValue(directResult, "hardware_vendor");
                        var directModel = GetStringValue(directResult, "hardware_model");
                        
                        if (!string.IsNullOrEmpty(directManufacturer) && string.IsNullOrEmpty(data.Manufacturer))
                        {
                            data.Manufacturer = directManufacturer;
                            _logger.LogInformation("Retrieved manufacturer from direct osquery: {Manufacturer}", directManufacturer);
                        }
                        
                        if (!string.IsNullOrEmpty(directModel) && string.IsNullOrEmpty(data.Model))
                        {
                            data.Model = directModel;
                            _logger.LogInformation("Retrieved model from direct osquery: {Model}", directModel);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Direct osquery fallback failed for manufacturer/model");
                }
            }
            
            // If still empty after direct osquery, try WMI as final fallback
            if (string.IsNullOrEmpty(data.Manufacturer) || string.IsNullOrEmpty(data.Model))
            {
                _logger.LogInformation("Attempting WMI fallback for manufacturer/model...");
                
                try
                {
                    if (string.IsNullOrEmpty(data.Manufacturer))
                    {
                        var wmiManufacturer = await _wmiHelperService.QueryWmiSingleValueAsync<string>("SELECT Manufacturer FROM Win32_ComputerSystem", "Manufacturer");
                        if (!string.IsNullOrEmpty(wmiManufacturer))
                        {
                            data.Manufacturer = wmiManufacturer;
                            _logger.LogInformation("Retrieved manufacturer from WMI: {Manufacturer}", wmiManufacturer);
                        }
                    }
                    
                    if (string.IsNullOrEmpty(data.Model))
                    {
                        var wmiModel = await _wmiHelperService.QueryWmiSingleValueAsync<string>("SELECT Model FROM Win32_ComputerSystem", "Model");
                        if (!string.IsNullOrEmpty(wmiModel))
                        {
                            data.Model = wmiModel;
                            _logger.LogInformation("Retrieved model from WMI: {Model}", wmiModel);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "WMI fallback failed for manufacturer/model");
                }
            }

            // Process memory devices
            if (osqueryResults.TryGetValue("memory_info", out var memoryInfo))
            {
                foreach (var memory in memoryInfo)
                {
                    data.Memory.Modules.Add(new MemoryModule
                    {
                        Location = GetStringValue(memory, "device_locator"),
                        Type = GetStringValue(memory, "memory_type"),
                        Capacity = GetLongValue(memory, "size"),
                        Speed = GetIntValue(memory, "configured_clock_speed")
                    });
                }
            }

            // Process disk info
            if (osqueryResults.TryGetValue("disk_info", out var diskInfo))
            {
                foreach (var disk in diskInfo)
                {
                    data.Storage.Add(new StorageDevice
                    {
                        Name = GetStringValue(disk, "hardware_model"),
                        Type = GetStringValue(disk, "type"),
                        Capacity = GetLongValue(disk, "disk_size"),
                        Interface = GetStringValue(disk, "id")
                    });
                }
            }

            _logger.LogInformation("Hardware processed - Manufacturer: {Manufacturer}, Model: {Model}", 
                data.Manufacturer, data.Model);

            await SaveModuleDataLocallyAsync("hardware", data);
            return data;
        }

        /// <summary>
        /// Process inventory module - enhanced with external data integration
        /// </summary>
        private async Task<InventoryData> ProcessInventoryModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            // Debug: Log all available query keys
            _logger.LogInformation("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));
            
            var data = new InventoryData
            {
                ModuleId = "inventory",
                DeviceId = deviceId,
                SerialNumber = ExtractSerialNumber(osqueryResults),
                UUID = ExtractDeviceUuid(osqueryResults),
                DeviceName = Environment.MachineName
            };
            
            // Extract device name from system_info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                
                // Update device name from computer_name
                var computerName = GetStringValue(info, "computer_name");
                if (!string.IsNullOrEmpty(computerName))
                {
                    data.DeviceName = computerName;
                }
            }
            
            // Process chassis info for serial and asset tag
            if (osqueryResults.TryGetValue("chassis_info", out var chassisResults) && chassisResults.Count > 0)
            {
                var chassis = chassisResults[0];
                
                // Use chassis serial if system_info serial was not valid
                var chassisSerial = GetStringValue(chassis, "serial");
                if (!string.IsNullOrEmpty(chassisSerial) && 
                    chassisSerial != "0" && 
                    chassisSerial != "System Serial Number" &&
                    chassisSerial != "To be filled by O.E.M." &&
                    data.SerialNumber == Environment.MachineName)
                {
                    data.SerialNumber = chassisSerial;
                    _logger.LogInformation("Updated serial number from chassis_info: {Serial}", chassisSerial);
                }
                
                var assetTag = GetStringValue(chassis, "asset_tag");
                if (!string.IsNullOrEmpty(assetTag) && 
                    assetTag != "0" && 
                    assetTag != "Asset Tag" &&
                    assetTag != "To be filled by O.E.M.")
                {
                    data.AssetTag = assetTag;
                }
            }
            
            // Load external inventory data from C:\ProgramData\Management\Inventory.yaml
            await LoadExternalInventoryDataAsync(data);
            
            _logger.LogInformation("Inventory processed - Serial: {Serial}, UUID: {UUID}, Device: {Device}", 
                data.SerialNumber, data.UUID, data.DeviceName);
            
            await SaveModuleDataLocallyAsync("inventory", data);
            return data;
        }
        
        /// <summary>
        /// Load additional inventory data from external C:\ProgramData\Management\Inventory.yaml
        /// </summary>
        private async Task LoadExternalInventoryDataAsync(InventoryData data)
        {
            try
            {
                var inventoryPath = @"C:\ProgramData\Management\Inventory.yaml";
                if (!File.Exists(inventoryPath))
                {
                    _logger.LogDebug(" External inventory file not found: {Path}", inventoryPath);
                    return;
                }
                
                var content = await File.ReadAllTextAsync(inventoryPath);
                _logger.LogDebug(" Reading external inventory from: {Path}", inventoryPath);
                
                // Simple YAML parsing for specific fields
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                string? allocationValue = null;
                
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("allocation:"))
                    {
                        allocationValue = ExtractYamlValue(trimmed, "allocation:");
                        // Use allocation as device name priority but don't store allocation field
                        if (!string.IsNullOrEmpty(allocationValue))
                        {
                            if (data.DeviceName == Environment.MachineName || string.IsNullOrEmpty(data.DeviceName))
                            {
                                data.DeviceName = allocationValue;
                                _logger.LogInformation(" Device name updated from allocation: {DeviceName}", allocationValue);
                            }
                        }
                    }
                    else if (trimmed.StartsWith("catalog:"))
                    {
                        data.Catalog = ExtractYamlValue(trimmed, "catalog:");
                    }
                    else if (trimmed.StartsWith("area:"))
                    {
                        // Map area to department instead of area field
                        var areaValue = ExtractYamlValue(trimmed, "area:");
                        if (!string.IsNullOrEmpty(areaValue))
                        {
                            data.Department = areaValue;
                        }
                    }
                    else if (trimmed.StartsWith("location:"))
                    {
                        data.Location = ExtractYamlValue(trimmed, "location:");
                    }
                    else if (trimmed.StartsWith("usage:"))
                    {
                        data.Usage = ExtractYamlValue(trimmed, "usage:");
                    }
                    else if (trimmed.StartsWith("username:"))
                    {
                        data.Owner = ExtractYamlValue(trimmed, "username:");
                    }
                    else if (trimmed.StartsWith("asset:"))
                    {
                        var assetValue = ExtractYamlValue(trimmed, "asset:");
                        if (!string.IsNullOrEmpty(assetValue) && string.IsNullOrEmpty(data.AssetTag))
                        {
                            data.AssetTag = assetValue;
                        }
                    }
                    else if (trimmed.StartsWith("assetTag:"))
                    {
                        var assetTag = ExtractYamlValue(trimmed, "assetTag:");
                        if (!string.IsNullOrEmpty(assetTag) && string.IsNullOrEmpty(data.AssetTag))
                        {
                            data.AssetTag = assetTag;
                        }
                    }
                }
                
                _logger.LogInformation("External inventory loaded - Catalog: '{Catalog}', Usage: '{Usage}', AssetTag: '{AssetTag}', Location: '{Location}', Owner: '{Owner}', Department: '{Department}'",
                    data.Catalog, data.Usage, data.AssetTag, data.Location, data.Owner, data.Department);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load external inventory data");
            }
        }
        
        /// <summary>
        /// Extract value from YAML line format "key: value" with proper quote handling
        /// </summary>
        private string ExtractYamlValue(string line, string key)
        {
            if (!line.StartsWith(key)) return string.Empty;
            
            var value = line.Substring(key.Length).Trim();
            
            // Handle quoted values
            if ((value.StartsWith("\"") && value.EndsWith("\"")) || 
                (value.StartsWith("'") && value.EndsWith("'")))
            {
                value = value.Substring(1, value.Length - 2);
            }
            
            return value;
        }

        private async Task<InstallsData> ProcessInstallsModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new InstallsData
            {
                ModuleId = "installs",
                DeviceId = deviceId
            };
            
            await SaveModuleDataLocallyAsync("installs", data);
            return data;
        }

        private async Task<ManagementData> ProcessManagementModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new ManagementData
            {
                ModuleId = "management",
                DeviceId = deviceId
            };
            
            await SaveModuleDataLocallyAsync("management", data);
            return data;
        }

        private async Task<NetworkData> ProcessNetworkModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new NetworkData
            {
                ModuleId = "network",
                DeviceId = deviceId
            };

            // Process interface addresses
            if (osqueryResults.TryGetValue("interface_addresses", out var addresses))
            {
                foreach (var addr in addresses)
                {
                    var interfaceInfo = new ReportMate.WindowsClient.Models.Modules.NetworkInterface
                    {
                        Name = GetStringValue(addr, "interface"),
                        IpAddresses = new List<string> { GetStringValue(addr, "address") }
                    };
                    data.Interfaces.Add(interfaceInfo);
                }
            }
            
            await SaveModuleDataLocallyAsync("network", data);
            return data;
        }

        private async Task<ProfilesData> ProcessProfilesModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new ProfilesData
            {
                ModuleId = "profiles",
                DeviceId = deviceId
            };
            
            await SaveModuleDataLocallyAsync("profiles", data);
            return data;
        }

        private async Task<SecurityData> ProcessSecurityModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new SecurityData
            {
                ModuleId = "security",
                DeviceId = deviceId
            };
            
            await SaveModuleDataLocallyAsync("security", data);
            return data;
        }

        private async Task<SystemData> ProcessSystemModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            var data = new SystemData
            {
                ModuleId = "system",
                DeviceId = deviceId
            };

            // Process OS version and details
            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Count > 0)
            {
                var os = osVersion[0];
                data.OperatingSystem.Name = GetStringValue(os, "name");
                data.OperatingSystem.Version = GetStringValue(os, "version");
                data.OperatingSystem.Build = GetStringValue(os, "build");
                data.OperatingSystem.Architecture = GetStringValue(os, "arch");
                
                // Create detailed version breakdown - major.minor.point.build
                data.OperatingSystem.Major = GetIntValue(os, "major");
                data.OperatingSystem.Minor = GetIntValue(os, "minor");
                data.OperatingSystem.Patch = GetIntValue(os, "patch");
                
                // Parse install date if available from os_version table
                var installDateStr = GetStringValue(os, "install_date");
                if (!string.IsNullOrEmpty(installDateStr) && DateTime.TryParse(installDateStr, out var installDate))
                {
                    data.OperatingSystem.InstallDate = installDate;
                }
            }

            // Process detailed build information including UBR
            string currentBuildValue = "";
            string ubrValue = "";
            
            if (osqueryResults.TryGetValue("detailed_build", out var detailedBuild))
            {
                // First pass: collect build and UBR values
                foreach (var buildRecord in detailedBuild)
                {
                    var regPath = GetStringValue(buildRecord, "path");
                    var regName = GetStringValue(buildRecord, "name");
                    var regData = GetStringValue(buildRecord, "data");
                    
                    _logger.LogDebug("Processing build registry: Path='{Path}', Name='{Name}', Data='{Data}'", regPath, regName, regData);
                    
                    if (regName == "CurrentBuild" && !string.IsNullOrEmpty(regData))
                    {
                        currentBuildValue = regData;
                        _logger.LogDebug("Found CurrentBuild: {CurrentBuild}", currentBuildValue);
                    }
                    else if (regName == "UBR" && !string.IsNullOrEmpty(regData))
                    {
                        ubrValue = regData;
                        _logger.LogDebug("Found UBR: {UBR}", ubrValue);
                    }
                }
                
                // Set build from registry if not already set from os_version
                if (string.IsNullOrEmpty(data.OperatingSystem.Build) && !string.IsNullOrEmpty(currentBuildValue))
                {
                    data.OperatingSystem.Build = currentBuildValue;
                    _logger.LogDebug("Set build from CurrentBuild registry: {Build}", data.OperatingSystem.Build);
                }
                
                // Append UBR to build number if available
                if (!string.IsNullOrEmpty(ubrValue) && !string.IsNullOrEmpty(data.OperatingSystem.Build))
                {
                    // Handle both decimal and hex UBR values
                    int ubr = 0;
                    if (ubrValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        // Parse hex value
                        if (int.TryParse(ubrValue.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ubr))
                        {
                            var oldBuild = data.OperatingSystem.Build;
                            data.OperatingSystem.Build = $"{data.OperatingSystem.Build}.{ubr}";
                            _logger.LogInformation("Applied UBR (hex): {OldBuild} -> {NewBuild}", oldBuild, data.OperatingSystem.Build);
                        }
                    }
                    else if (int.TryParse(ubrValue, out ubr))
                    {
                        // Parse decimal value
                        var oldBuild = data.OperatingSystem.Build;
                        data.OperatingSystem.Build = $"{data.OperatingSystem.Build}.{ubr}";
                        _logger.LogInformation("Applied UBR (decimal): {OldBuild} -> {NewBuild}", oldBuild, data.OperatingSystem.Build);
                    }
                    else
                    {
                        _logger.LogWarning("Could not parse UBR value: {UBR}", ubrValue);
                    }
                }
                else
                {
                    _logger.LogDebug("UBR not applied - UBR: '{UBR}', Build: '{Build}'", ubrValue, data.OperatingSystem.Build);
                }
            }

            // Process display version (24H2, 23H2, etc.)
            if (osqueryResults.TryGetValue("display_version", out var displayVersion))
            {
                foreach (var versionRecord in displayVersion)
                {
                    var regPath = GetStringValue(versionRecord, "path");
                    var regData = GetStringValue(versionRecord, "data");
                    
                    if (regPath?.Contains("DisplayVersion") == true && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.DisplayVersion = regData;
                        break; // Prefer DisplayVersion over ReleaseId
                    }
                    else if (regPath?.Contains("ReleaseId") == true && string.IsNullOrEmpty(data.OperatingSystem.DisplayVersion))
                    {
                        data.OperatingSystem.DisplayVersion = regData ?? "";
                    }
                }
            }

            // Fallback to build-based display version if not found in registry
            if (string.IsNullOrEmpty(data.OperatingSystem.DisplayVersion))
            {
                var buildNumber = data.OperatingSystem.Build?.Split('.')[0]; // Get base build without UBR
                data.OperatingSystem.DisplayVersion = buildNumber switch
                {
                    "26100" => "24H2",
                    "22631" => "23H2", 
                    "22621" => "22H2",
                    "22000" => "21H2",
                    _ => $"Build {buildNumber}"
                };
            }

            // Process Windows edition from registry
            if (osqueryResults.TryGetValue("os_edition", out var osEdition))
            {
                foreach (var editionRecord in osEdition)
                {
                    var regPath = GetStringValue(editionRecord, "path");
                    var regData = GetStringValue(editionRecord, "data");
                    
                    if (regPath?.Contains("EditionID") == true && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.Edition = regData;
                        break; // Prefer EditionID over ProductName
                    }
                    else if (regPath?.Contains("ProductName") == true && string.IsNullOrEmpty(data.OperatingSystem.Edition))
                    {
                        // Extract edition from ProductName as fallback
                        data.OperatingSystem.Edition = ExtractWindowsEdition(regData ?? "");
                    }
                }
            }

            // If still no edition, try extracting from OS name
            if (string.IsNullOrEmpty(data.OperatingSystem.Edition) && !string.IsNullOrEmpty(data.OperatingSystem.Name))
            {
                data.OperatingSystem.Edition = ExtractWindowsEdition(data.OperatingSystem.Name);
            }

            // Process Windows Feature Experience Pack information (Service Pack equivalent)
            if (osqueryResults.TryGetValue("experience_pack", out var experiencePack))
            {
                foreach (var packRecord in experiencePack)
                {
                    var regPath = GetStringValue(packRecord, "path");
                    var regData = GetStringValue(packRecord, "data");
                    
                    // Look for Experience Pack version information
                    if (!string.IsNullOrEmpty(regData) && 
                        (regData.Contains("Experience Pack") || regData.Contains("1000.26100") || regData.Contains("Feature")))
                    {
                        data.OperatingSystem.ServicePack = regData;
                        break;
                    }
                }
            }

            // Provide default Experience Pack for Windows 11 24H2 if none found
            if (string.IsNullOrEmpty(data.OperatingSystem.ServicePack))
            {
                var buildNumber = data.OperatingSystem.Build?.Split('.')[0];
                data.OperatingSystem.ServicePack = buildNumber switch
                {
                    "26100" => "Windows Feature Experience Pack 1000.26100.128.0",
                    "22631" => "Windows Feature Experience Pack 1000.22700.1003.0", 
                    "22621" => "Windows Feature Experience Pack 1000.22636.1000.0",
                    "22000" => "Windows Feature Experience Pack 1000.22000.706.0",
                    _ => ""
                };
            }

            // Process install date from registry
            if (osqueryResults.TryGetValue("install_date", out var installDateReg) && installDateReg.Count > 0)
            {
                var installDataValue = GetStringValue(installDateReg[0], "data");
                if (!string.IsNullOrEmpty(installDataValue) && long.TryParse(installDataValue, out var unixTime))
                {
                    try
                    {
                        data.OperatingSystem.InstallDate = DateTimeOffset.FromUnixTimeSeconds(unixTime).DateTime;
                    }
                    catch
                    {
                        // Invalid timestamp, ignore
                    }
                }
            }

            // Process locale and timezone from registry
            if (osqueryResults.TryGetValue("locale_info", out var localeInfo))
            {
                foreach (var localeRecord in localeInfo)
                {
                    var regPath = GetStringValue(localeRecord, "path");
                    var regData = GetStringValue(localeRecord, "data");
                    
                    if (regPath?.Contains("Language\\Default") == true && !string.IsNullOrEmpty(regData))
                    {
                        // Convert language code to readable format
                        data.OperatingSystem.Locale = ConvertLanguageCodeToLocale(regData);
                    }
                    else if (regPath?.Contains("InstallLanguage") == true && string.IsNullOrEmpty(data.OperatingSystem.Locale) && !string.IsNullOrEmpty(regData))
                    {
                        // Use install language as fallback
                        data.OperatingSystem.Locale = ConvertLanguageCodeToLocale(regData);
                    }
                    else if (regPath?.Contains("TimeZoneKeyName") == true && !string.IsNullOrEmpty(regData))
                    {
                        data.OperatingSystem.TimeZone = regData;
                    }
                }
            }

            // Fallback locale detection if still empty
            if (string.IsNullOrEmpty(data.OperatingSystem.Locale))
            {
                try
                {
                    // Use system culture as fallback
                    data.OperatingSystem.Locale = System.Globalization.CultureInfo.CurrentCulture.Name;
                }
                catch
                {
                    data.OperatingSystem.Locale = "en-US"; // Ultimate fallback
                }
            }

            // Process uptime information
            if (osqueryResults.TryGetValue("uptime", out var uptime) && uptime.Count > 0)
            {
                var uptimeInfo = uptime[0];
                var totalSeconds = GetLongValue(uptimeInfo, "total_seconds");
                if (totalSeconds > 0)
                {
                    data.Uptime = TimeSpan.FromSeconds(totalSeconds);
                    
                    // Format uptime as human-readable string
                    var uptimeSpan = TimeSpan.FromSeconds(totalSeconds);
                    if (uptimeSpan.Days > 0)
                    {
                        data.UptimeString = $"{uptimeSpan.Days:D2}:{uptimeSpan.Hours:D2}:{uptimeSpan.Minutes:D2}:{uptimeSpan.Seconds:D2}";
                    }
                    else
                    {
                        data.UptimeString = $"{uptimeSpan.Hours:D2}:{uptimeSpan.Minutes:D2}:{uptimeSpan.Seconds:D2}";
                    }
                }
            }

            // Process boot time
            if (osqueryResults.TryGetValue("boot_time", out var bootTime) && bootTime.Count > 0)
            {
                var bootTimeStr = GetStringValue(bootTime[0], "boot_time");
                if (!string.IsNullOrEmpty(bootTimeStr))
                {
                    // Try to parse the datetime string (format: "2025-07-12 16:26:24")
                    if (DateTime.TryParseExact(bootTimeStr, "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.AssumeLocal, out var boot))
                    {
                        data.LastBootTime = boot;
                        _logger.LogDebug("Parsed boot time: {BootTime}", boot);
                    }
                    else if (DateTime.TryParse(bootTimeStr, out var bootFallback))
                    {
                        data.LastBootTime = bootFallback;
                        _logger.LogDebug("Parsed boot time (fallback): {BootTime}", bootFallback);
                    }
                    else
                    {
                        _logger.LogWarning("Failed to parse boot time: {BootTimeStr}", bootTimeStr);
                    }
                }
            }

            // Process time zone information
            if (osqueryResults.TryGetValue("time_info", out var timeInfo) && timeInfo.Count > 0)
            {
                var time = timeInfo[0];
                if (string.IsNullOrEmpty(data.OperatingSystem.TimeZone))
                {
                    data.OperatingSystem.TimeZone = GetStringValue(time, "timezone");
                }
            }

            // Process services
            if (osqueryResults.TryGetValue("services", out var services))
            {
                foreach (var service in services)
                {
                    var systemService = new SystemService
                    {
                        Name = GetStringValue(service, "name"),
                        DisplayName = GetStringValue(service, "display_name"),
                        Status = GetStringValue(service, "status"),
                        StartType = GetStringValue(service, "start_type"),
                        Path = GetStringValue(service, "path"),
                        Description = GetStringValue(service, "description")
                    };
                    data.Services.Add(systemService);
                }
            }

            // Process environment variables
            if (osqueryResults.TryGetValue("environment_variables", out var envVars))
            {
                foreach (var envVar in envVars)
                {
                    var envVariable = new EnvironmentVariable
                    {
                        Name = GetStringValue(envVar, "name"),
                        Value = GetStringValue(envVar, "value"),
                        Scope = "System" // osquery typically returns system-level vars
                    };
                    data.Environment.Add(envVariable);
                }
            }

            // Process Windows patches/updates
            if (osqueryResults.TryGetValue("windows_patches", out var patches))
            {
                foreach (var patch in patches)
                {
                    var update = new SystemUpdate
                    {
                        Id = GetStringValue(patch, "hotfix_id"),
                        Title = GetStringValue(patch, "description"),
                        Category = "Windows Update",
                        Status = "Installed"
                    };
                    
                    var installedOnStr = GetStringValue(patch, "installed_on");
                    if (!string.IsNullOrEmpty(installedOnStr) && DateTime.TryParse(installedOnStr, out var installedOn))
                    {
                        update.InstallDate = installedOn;
                    }
                    
                    data.Updates.Add(update);
                }
            }



            // Use WMI fallback for missing data
            await EnrichSystemDataWithWmiAsync(data);
            
            await SaveModuleDataLocallyAsync("system", data);
            return data;
        }



        /// <summary>
        /// Enrich system data with WMI fallback for missing information
        /// </summary>
        private async Task EnrichSystemDataWithWmiAsync(SystemData data)
        {
            try
            {
                // Get OS edition and service pack info from WMI
                if (string.IsNullOrEmpty(data.OperatingSystem.Edition))
                {
                    var osEdition = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                        "SELECT Caption FROM Win32_OperatingSystem", "Caption");
                    
                    if (!string.IsNullOrEmpty(osEdition))
                    {
                        data.OperatingSystem.Edition = ExtractWindowsEdition(osEdition);
                    }
                }

                // Try to get Windows Feature Experience Pack information
                if (string.IsNullOrEmpty(data.OperatingSystem.ServicePack))
                {
                    try
                    {
                        // Fallback to check for installed KBs that indicate Experience Pack
                        var hotfixes = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                            "SELECT Description FROM Win32_QuickFixEngineering WHERE HotFixID = 'KB4023057'", "Description");
                        
                        if (!string.IsNullOrEmpty(hotfixes))
                        {
                            // Determine Experience Pack version based on build
                            var buildNumber = data.OperatingSystem.Build?.Split('.')[0];
                            data.OperatingSystem.ServicePack = buildNumber switch
                            {
                                "26100" => "Windows Feature Experience Pack 1000.26100.128.0",
                                "22631" => "Windows Feature Experience Pack 1000.22700.1003.0", 
                                "22621" => "Windows Feature Experience Pack 1000.22636.1000.0",
                                _ => "Windows Feature Experience Pack"
                            };
                        }
                        else
                        {
                            // Legacy Service Pack check (for older Windows versions)
                            var servicePack = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                                "SELECT ServicePackMajorVersion FROM Win32_OperatingSystem", "ServicePackMajorVersion");
                            
                            if (!string.IsNullOrEmpty(servicePack) && servicePack != "0")
                            {
                                data.OperatingSystem.ServicePack = $"Service Pack {servicePack}";
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to retrieve Experience Pack information via WMI");
                    }
                }

                // Get locale information with better formatting
                if (string.IsNullOrEmpty(data.OperatingSystem.Locale))
                {
                    var locale = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                        "SELECT Locale FROM Win32_OperatingSystem", "Locale");
                    
                    if (!string.IsNullOrEmpty(locale))
                    {
                        data.OperatingSystem.Locale = ConvertLanguageCodeToLocale(locale);
                    }
                }

                // Get timezone information if missing
                if (string.IsNullOrEmpty(data.OperatingSystem.TimeZone))
                {
                    var timeZone = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                        "SELECT Description FROM Win32_TimeZone", "Description");
                    
                    if (!string.IsNullOrEmpty(timeZone))
                    {
                        data.OperatingSystem.TimeZone = timeZone;
                    }
                }

                // Get install date if not already set
                if (!data.OperatingSystem.InstallDate.HasValue)
                {
                    var installDate = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                        "SELECT InstallDate FROM Win32_OperatingSystem", "InstallDate");
                    
                    if (!string.IsNullOrEmpty(installDate) && DateTime.TryParse(installDate, out var parsed))
                    {
                        data.OperatingSystem.InstallDate = parsed;
                    }
                }



                _logger.LogDebug("Enhanced system data with WMI fallback information");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enrich system data with WMI");
            }
        }

        /// <summary>
        /// Extract Windows edition from caption string
        /// </summary>
        private string ExtractWindowsEdition(string caption)
        {
            if (string.IsNullOrEmpty(caption)) return "";
            
            // Handle direct edition names first
            var editionKeywords = new[] { "Enterprise", "Professional", "Pro", "Home", "Education", "Pro for Workstations" };
            foreach (var keyword in editionKeywords)
            {
                if (caption.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    return keyword == "Professional" ? "Pro" : keyword;
                }
            }
            
            // Extract edition from strings like "Microsoft Windows 11 Enterprise"
            var parts = caption.Split(' ');
            if (parts.Length >= 3)
            {
                var edition = string.Join(" ", parts.Skip(2));
                
                // Clean up common variations
                edition = edition.Replace("Professional", "Pro");
                return edition.Trim();
            }
            
            return "";
        }

        /// <summary>
        /// Convert Windows language code to readable locale
        /// </summary>
        private string ConvertLanguageCodeToLocale(string languageCode)
        {
            if (string.IsNullOrEmpty(languageCode)) return "";
            
            // Convert hex language codes to readable format
            return languageCode.ToLowerInvariant() switch
            {
                "0409" => "en-US",
                "0809" => "en-GB", 
                "0c09" => "en-AU",
                "1009" => "en-CA",
                "040c" => "fr-FR",
                "080c" => "fr-BE",
                "0407" => "de-DE",
                "0807" => "de-CH",
                "040a" => "es-ES",
                "080a" => "es-MX",
                "0410" => "it-IT",
                "0413" => "nl-NL",
                "0813" => "nl-BE",
                "0416" => "pt-BR",
                "0816" => "pt-PT",
                "041f" => "tr-TR",
                "0411" => "ja-JP",
                "0412" => "ko-KR",
                "0804" => "zh-CN",
                "0404" => "zh-TW",
                "0c04" => "zh-HK",
                "0419" => "ru-RU",
                "041d" => "sv-SE",
                "041e" => "th-TH",
                "0415" => "pl-PL",
                "0405" => "cs-CZ",
                "040e" => "hu-HU",
                "0414" => "nb-NO",
                "0406" => "da-DK",
                "040b" => "fi-FI",
                "0408" => "el-GR",
                "040d" => "he-IL",
                "041c" => "sq-AL",
                _ => languageCode
            };
        }

        /// <summary>
        /// Save individual module data to cache
        /// </summary>
        public async Task SaveModuleDataLocallyAsync<T>(string moduleId, T data) where T : BaseModuleData
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, $"{moduleId}.json");
                
                // Use pretty JSON formatting with indentation
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    TypeInfoResolver = ReportMateJsonContext.Default
                };
                
                var json = JsonSerializer.Serialize((object)data, options);
                
                await File.WriteAllTextAsync(filePath, json);
                _logger.LogDebug($"Saved {moduleId} module data to {filePath}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving {moduleId} module data to cache");
            }
        }

        /// <summary>
        /// Clean up old cache directories
        /// Keep last 10 days, but for current day keep all hourly runs
        /// </summary>
        private async Task CleanupOldCacheAsync()
        {
            try
            {
                await Task.Delay(1000); // Delay to avoid blocking startup
                
                if (!Directory.Exists(_baseDirectory))
                    return;

                var today = DateTime.Now.Date;
                var cutoffDate = today.AddDays(-10);
                
                // Parse cache folders with YYYY-MM-DD-HHmmss format
                var cacheFolders = Directory.GetDirectories(_baseDirectory)
                    .Where(d => {
                        var folderName = Path.GetFileName(d);
                        return folderName.Length >= 10 && DateTime.TryParseExact(folderName.Substring(0, 10), "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None, out var _);
                    })
                    .Select(d => {
                        var folderName = Path.GetFileName(d);
                        var dateStr = folderName.Substring(0, 10);
                        var folderDate = DateTime.ParseExact(dateStr, "yyyy-MM-dd", null);
                        return new { Path = d, Date = folderDate, FolderName = folderName };
                    })
                    .ToList();

                foreach (var folder in cacheFolders)
                {
                    if (folder.Date < cutoffDate)
                    {
                        // Delete folders older than 10 days
                        Directory.Delete(folder.Path, true);
                        _logger.LogInformation($"Cleaned up old cache folder: {folder.Path}");
                    }
                    else if (folder.Date < today)
                    {
                        // For past days (but within 10 days), keep only the latest run of the day
                        var sameDayFolders = cacheFolders
                            .Where(f => f.Date.Date == folder.Date.Date)
                            .OrderByDescending(f => f.FolderName)
                            .Skip(1) // Keep the latest one for that day
                            .ToList();

                        foreach (var oldFolder in sameDayFolders)
                        {
                            if (Directory.Exists(oldFolder.Path))
                            {
                                Directory.Delete(oldFolder.Path, true);
                                _logger.LogDebug($"Cleaned up old cache folder: {oldFolder.Path}");
                            }
                        }
                    }
                    // For today, keep all hourly runs (no cleanup)
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during cache cleanup");
            }
        }

        /// <summary>
        /// Save all modules to cache
        /// </summary>
        private async Task SaveModulesToCacheAsync(UnifiedDevicePayload payload)
        {
            var tasks = new List<Task>();
            
            if (payload.Applications != null) tasks.Add(SaveModuleDataLocallyAsync("applications", payload.Applications));
            if (payload.Hardware != null) tasks.Add(SaveModuleDataLocallyAsync("hardware", payload.Hardware));
            if (payload.Inventory != null) tasks.Add(SaveModuleDataLocallyAsync("inventory", payload.Inventory));
            if (payload.Installs != null) tasks.Add(SaveModuleDataLocallyAsync("installs", payload.Installs));
            if (payload.Management != null) tasks.Add(SaveModuleDataLocallyAsync("management", payload.Management));
            if (payload.Network != null) tasks.Add(SaveModuleDataLocallyAsync("network", payload.Network));
            if (payload.Profiles != null) tasks.Add(SaveModuleDataLocallyAsync("profiles", payload.Profiles));
            if (payload.Security != null) tasks.Add(SaveModuleDataLocallyAsync("security", payload.Security));
            if (payload.System != null) tasks.Add(SaveModuleDataLocallyAsync("system", payload.System));

            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Save unified payload
        /// </summary>
        private async Task SaveUnifiedPayloadAsync(UnifiedDevicePayload payload)
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, "event.json");
                
                // Use pretty JSON formatting with indentation
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    TypeInfoResolver = ReportMateJsonContext.Default
                };
                
                var json = JsonSerializer.Serialize(payload, options);
                
                await File.WriteAllTextAsync(filePath, json);
                _logger.LogInformation($"Saved unified payload to {filePath}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving unified payload to cache");
            }
        }

        /// <summary>
        /// Collect specific module data
        /// </summary>
        public async Task<T?> CollectModuleDataAsync<T>(string moduleId) where T : BaseModuleData
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, $"{moduleId}.json");
                if (File.Exists(filePath))
                {
                    var json = await File.ReadAllTextAsync(filePath);
                    // For now, return null - we'd need specific JsonTypeInfo for each T
                    // This can be enhanced with specific type handling later
                    return null;
                }
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error loading {moduleId} module data");
                return null;
            }
        }

        /// <summary>
        /// Load cached unified payload
        /// </summary>
        public async Task<UnifiedDevicePayload> LoadCachedDataAsync()
        {
            try
            {
                var filePath = Path.Combine(_cacheDirectory, "event.json");
                if (File.Exists(filePath))
                {
                    var json = await File.ReadAllTextAsync(filePath);
                    var payload = JsonSerializer.Deserialize(json, ReportMateJsonContext.Default.UnifiedDevicePayload);
                    return payload ?? new UnifiedDevicePayload();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading cached unified payload");
            }
            
            return new UnifiedDevicePayload();
        }

        /// <summary>
        /// Validate module data
        /// </summary>
        public async Task<bool> ValidateModuleDataAsync(string moduleId, object data)
        {
            try
            {
                // Basic validation - check if data is not null and has required properties
                if (data == null) return false;
                
                // For now, just return true - can be enhanced with specific validation logic
                return await Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating {moduleId} module data");
                return false;
            }
        }

        /// <summary>
        /// Helper method to safely get string values from osquery results
        /// </summary>
        private string GetStringValue(Dictionary<string, object> data, string key)
        {
            return data.TryGetValue(key, out var value) ? value?.ToString() ?? "" : "";
        }

        /// <summary>
        /// Helper method to safely get integer values from osquery results
        /// </summary>
        private int GetIntValue(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && int.TryParse(value?.ToString(), out var result))
            {
                return result;
            }
            return 0;
        }

        /// <summary>
        /// Helper method to safely get long values from osquery results
        /// </summary>
        private long GetLongValue(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && long.TryParse(value?.ToString(), out var result))
            {
                return result;
            }
            return 0;
        }

        /// <summary>
        /// Helper method to safely get double values from osquery results
        /// </summary>
        private double GetDoubleValue(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && double.TryParse(value?.ToString(), out var result))
            {
                return result;
            }
            return 0.0;
        }
    }
}
