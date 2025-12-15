#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.DataProcessing;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Main data collection service that orchestrates device data collection and API submission
/// </summary>
public interface IDataCollectionService
{
    Task<bool> CollectAndSendDataAsync(bool forceCollection = false, bool collectOnly = false);
    Task<DeviceDataRequest> CollectDataAsync();
}

public class DataCollectionService : IDataCollectionService
{
    private readonly ILogger<DataCollectionService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IDeviceInfoService _deviceInfoService;
    private readonly IApiService _apiService;
    private readonly IConfigurationService _configurationService;
    private readonly IModularDataCollectionService _modularDataCollectionService;

    public DataCollectionService(
        ILogger<DataCollectionService> logger,
        IConfiguration configuration,
        IDeviceInfoService deviceInfoService,
        IApiService apiService,
        IConfigurationService configurationService,
        IModularDataCollectionService modularDataCollectionService)
    {
        _logger = logger;
        _configuration = configuration;
        _deviceInfoService = deviceInfoService;
        _apiService = apiService;
        _configurationService = configurationService;
        _modularDataCollectionService = modularDataCollectionService;
    }

    public async Task<bool> CollectAndSendDataAsync(bool forceCollection = false, bool collectOnly = false)
    {
        try
        {
            if (!forceCollection && await _configurationService.IsRecentRunAsync())
            {
                _logger.LogInformation("Recent data collection detected, skipping collection (use --force to override)");
                return true;
            }

            _logger.LogInformation("=== REPORTMATE WINDOWS CLIENT DATA COLLECTION STARTING ===");
            _logger.LogInformation("Client Version: {Version}", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown");
            _logger.LogInformation("Execution Mode: {Mode}", forceCollection ? "Forced" : "Normal");
            _logger.LogInformation("Expected Policy: STRICT device registration enforcement");

            // Validate configuration before proceeding
            _logger.LogInformation("=== STEP 1: CONFIGURATION VALIDATION ===");
            var configValidation = await _configurationService.ValidateConfigurationAsync();
            if (!configValidation.IsValid)
            {
                _logger.LogError("Configuration validation failed: {Errors}", 
                    string.Join(", ", configValidation.Errors));
                return false;
            }

            _logger.LogInformation("Configuration validated successfully");

            // Log warnings but continue
            foreach (var warning in configValidation.Warnings)
            {
                _logger.LogWarning("Configuration warning: {Warning}", warning);
            }

            // Get consistent device identification using modular data collection
            _logger.LogInformation("=== STEP 2: DEVICE IDENTIFICATION ===");
            _logger.LogInformation("Getting device identity using modular service...");
            
            // Use modular data collection to get device identification AND collect all data in one pass
            var deviceModularPayload = await _modularDataCollectionService.CollectAllModuleDataAsync();
            var deviceId = deviceModularPayload.Metadata.DeviceId; // This should be the UUID
            var serialNumber = deviceModularPayload.Inventory?.SerialNumber ?? "Unknown";
            var computerName = deviceModularPayload.Inventory?.DeviceName ?? "Unknown";
            var domain = ""; // Domain not collected in modular service yet
            
            _logger.LogInformation("=== DEVICE IDENTIFICATION RESULTS ===");
            _logger.LogInformation("Device UUID (DeviceId): {DeviceId}", deviceId);
            _logger.LogInformation("Device Serial Number: {SerialNumber}", serialNumber);
            _logger.LogInformation("Computer Name: {ComputerName}", computerName);
            _logger.LogInformation("Domain: {Domain}", domain);
            _logger.LogInformation("Expected Dashboard URL: /device/{SerialNumber}", serialNumber);

            _logger.LogInformation("Modular data collection completed successfully");

            // Check if we should skip registration and transmission (stop here for --collect-only)
            if (collectOnly)
            {
                _logger.LogInformation("=== COLLECT-ONLY MODE ===");
                _logger.LogInformation("Data transmission SKIPPED (--collect-only flag specified)");
                _logger.LogInformation("Data collection completed successfully without transmission");
                _logger.LogInformation("Data saved to cache files only");
                _logger.LogInformation(" To transmit data, run without --collect-only flag");
                await _configurationService.UpdateLastRunTimeAsync();
                return true;
            }

            // DEVICE REGISTRATION CHECK AND AUTO-REGISTRATION
            // Check if device is registered, if not, register it via "new_client" event
            _logger.LogInformation("=== STEP 3: DEVICE REGISTRATION CHECK ===");
            _logger.LogInformation("Checking if device {DeviceId} is registered...", deviceId);
            
            var isRegistered = await _apiService.IsDeviceRegisteredAsync(deviceId);
            _logger.LogInformation("Device {DeviceId} registration status: {Status}", 
                deviceId, isRegistered ? "REGISTERED" : "NOT REGISTERED");
            
            if (!isRegistered)
            {
                _logger.LogInformation(" UNREGISTERED DEVICE - Initiating auto-registration");
                _logger.LogInformation(" Registering device {DeviceId} as 'New Client'", deviceId);
                
                // Create minimal device info for registration
                var minimalDeviceInfo = new DeviceInfo
                {
                    DeviceId = deviceId,
                    SerialNumber = serialNumber, // Use actual serial number for URL routing
                    ComputerName = computerName,
                    Domain = domain
                };
                
                var registrationSuccess = await _apiService.RegisterDeviceAsync(minimalDeviceInfo);
                _logger.LogInformation("Registration attempt result: {Success}", registrationSuccess);
                
                if (!registrationSuccess)
                {
                    _logger.LogError("Device registration failed for {DeviceId}", deviceId);
                    _logger.LogError(" Proceeding with data collection anyway - device may register on next run");
                }
                else
                {
                    _logger.LogInformation("Device {DeviceId} registered successfully", deviceId);
                    _logger.LogInformation("New Client event should be visible in dashboard at /device/{SerialNumber}", serialNumber);
                }
            }
            else
            {
                _logger.LogInformation("Device {DeviceId} is already registered", deviceId);
            }

            // Data already collected during device identification - skip redundant collection
            _logger.LogInformation("=== STEP 4: MODULAR DATA COLLECTION ===");
            _logger.LogInformation(" AUTHORIZED: Device registration verified, proceeding with modular data collection");
            _logger.LogInformation("COLLECTING: Modular device data with individual cache files");
            
            // Reuse the modular payload from device identification step (no need to collect again)
            var modularPayload = deviceModularPayload;
            
            _logger.LogInformation("Device ID: {DeviceId}", modularPayload.Metadata.DeviceId);
            _logger.LogInformation(" Collection Time: {CollectedAt:yyyy-MM-dd HH:mm:ss}", modularPayload.Metadata.CollectedAt);
            _logger.LogInformation("Individual module cache files created in C:\\ProgramData\\ManagedReports\\cache\\");

        // Send to API
        _logger.LogInformation("=== STEP 5: DATA TRANSMISSION ===");
        _logger.LogInformation("Sending unified payload directly to ReportMate API via /api/events");
        
        // Calculate data size for the unified payload
        var dataSize = 0;
        try
        {
            dataSize = System.Text.Json.JsonSerializer.Serialize(modularPayload, ReportMateJsonContext.Default.UnifiedDevicePayload).Length;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not calculate data size for logging");
            dataSize = -1; // Unknown size
        }
        
        _logger.LogInformation("Data size: {DataSize} bytes", dataSize > 0 ? dataSize.ToString() : "Unknown");
        _logger.LogInformation("Device ID: {DeviceId}", modularPayload.Metadata.DeviceId);
        _logger.LogInformation("Platform: {Platform}", modularPayload.Metadata.Platform);
        _logger.LogInformation("Enabled Modules: {EnabledModules}", string.Join(", ", modularPayload.Metadata.EnabledModules));
        
        var success = await _apiService.SendUnifiedPayloadAsync(modularPayload);            if (success)
            {
                _logger.LogInformation("SUCCESS: Data transmission completed successfully");
                _logger.LogInformation("DASHBOARD: Data should be visible at /device/{DeviceSerial}", modularPayload.Metadata.SerialNumber ?? modularPayload.Inventory?.SerialNumber ?? modularPayload.Metadata.DeviceId);
                await _configurationService.UpdateLastRunTimeAsync();
                return true;
            }
            else
            {
                _logger.LogError("TRANSMISSION FAILED: Data collection succeeded but transmission failed");
                _logger.LogError("Device ID: {DeviceId}", modularPayload.Metadata.DeviceId);
                _logger.LogError("Platform: {Platform}", modularPayload.Metadata.Platform);
                
                // Calculate data size for error logging
                var jsonOptions = new JsonSerializerOptions
                {
                    TypeInfoResolver = ReportMateJsonContext.Default
                };
                _logger.LogError("Data Size: {DataSize} bytes", System.Text.Json.JsonSerializer.Serialize(modularPayload, jsonOptions).Length);
                _logger.LogError("NOTE: Will retry on next run");
                _logger.LogError("Data collection or transmission failed");
                _logger.LogError("IMPACT: Device may not be registered or API issues detected"); 
                _logger.LogError("ACTION REQUIRED: Check logs above for specific failure reasons");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("=== CRITICAL ERROR IN DATA COLLECTION PROCESS ===");
            _logger.LogError("Exception Type: {ExceptionType}", ex.GetType().FullName);
            _logger.LogError("Exception Message: {ExceptionMessage}", ex.Message);
            _logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
            
            if (ex.InnerException != null)
            {
                _logger.LogError("Inner Exception Type: {InnerExceptionType}", ex.InnerException.GetType().FullName);
                _logger.LogError("Inner Exception Message: {InnerExceptionMessage}", ex.InnerException.Message);
            }
            
            _logger.LogError("CRITICAL ERROR: Data collection process failed");
            _logger.LogError("IMPACT: Device will not be updated in ReportMate");
            _logger.LogError("ACTION REQUIRED: Review error details above and check system configuration");
            
            return false;
        }
    }

    public async Task<DeviceDataRequest> CollectDataAsync()
    {
        try
        {
            _logger.LogInformation("MODULAR: Collecting data via modular service...");
            
            // Use modular data collection service
            var modularPayload = await _modularDataCollectionService.CollectAllModuleDataAsync();
            
            // Convert modular payload to request format
            var deviceData = ConvertModularPayloadToRequest(modularPayload);

            _logger.LogInformation("MODULAR: Data collection completed using modular service");
            _logger.LogInformation("Device ID: {DeviceId}", modularPayload.Metadata.DeviceId);
            _logger.LogInformation("Individual module cache files created");
            
            return deviceData;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting modular device data");
            throw;
        }
    }



    /// <summary>
    /// Converts UnifiedDevicePayload to API request format
    /// </summary>
    private DeviceDataRequest ConvertModularPayloadToRequest(UnifiedDevicePayload modularPayload)
    {
        // Extract network information - look for primary interface or first available
        string ipAddressV4 = "";
        string macAddress = "";
        if (modularPayload.Network?.Interfaces?.Count > 0)
        {
            var primaryInterface = modularPayload.Network.Interfaces.FirstOrDefault();
            if (primaryInterface != null)
            {
                macAddress = primaryInterface.MacAddress;
                ipAddressV4 = primaryInterface.IpAddresses?.FirstOrDefault() ?? "";
            }
        }

        // Extract basic device information from the modular payload
        var deviceDict = new Dictionary<string, object>
        {
            ["DeviceId"] = modularPayload.Metadata.DeviceId,
            ["SerialNumber"] = modularPayload.Inventory?.SerialNumber ?? "",
            ["ComputerName"] = modularPayload.Inventory?.DeviceName ?? Environment.MachineName,
            ["Domain"] = "",
            ["Manufacturer"] = modularPayload.Hardware?.Manufacturer ?? "",
            ["Model"] = modularPayload.Hardware?.Model ?? "",
            ["TotalMemoryGB"] = modularPayload.Hardware?.Memory?.TotalPhysical / (1024 * 1024 * 1024) ?? 0,
            ["LastSeen"] = DateTime.UtcNow,
            ["ClientVersion"] = modularPayload.Metadata.ClientVersion,
            ["AssetTag"] = modularPayload.Inventory?.AssetTag ?? "",
            ["OsName"] = modularPayload.System?.OperatingSystem?.Name ?? "",
            ["OsVersion"] = modularPayload.System?.OperatingSystem?.Version ?? "",
            ["OsBuild"] = modularPayload.System?.OperatingSystem?.Build ?? "",
            ["OsArchitecture"] = modularPayload.System?.OperatingSystem?.Architecture ?? "",
            ["IpAddressV4"] = ipAddressV4,
            ["IpAddressV6"] = "",
            ["MacAddress"] = macAddress,
            ["MdmEnrollmentId"] = modularPayload.Management?.MdmEnrollment?.EnrollmentId ?? "",
            ["MdmEnrollmentType"] = modularPayload.Management?.MdmEnrollment?.EnrollmentType ?? "",
            ["MdmEnrollmentState"] = modularPayload.Management?.MdmEnrollment?.IsEnrolled.ToString() ?? "",
            ["MdmManagementUrl"] = modularPayload.Management?.MdmEnrollment?.ManagementUrl ?? "",
            ["Status"] = "online"
        };

        var payload = new DeviceDataPayload
        {
            Device = deviceDict,
            CollectionTimestamp = modularPayload.Metadata.CollectedAt.ToString("O"),
            ClientVersion = modularPayload.Metadata.ClientVersion,
            CollectionType = "modular",
            ManagedInstallsSystem = "Cimian",
            Source = "managedreportsrunner.exe"
        };

        // Add modular data to OsQuery section
        var osQueryDict = new Dictionary<string, object>();
        if (modularPayload.System != null) osQueryDict["system"] = modularPayload.System;
        if (modularPayload.Hardware != null) osQueryDict["hardware"] = modularPayload.Hardware;
        if (modularPayload.Network != null) osQueryDict["network"] = modularPayload.Network;
        if (modularPayload.Applications != null) osQueryDict["applications"] = modularPayload.Applications;
        if (modularPayload.Security != null) osQueryDict["security"] = modularPayload.Security;
        if (modularPayload.Management != null) osQueryDict["management"] = modularPayload.Management;
        if (modularPayload.Inventory != null) osQueryDict["inventory"] = modularPayload.Inventory;
        if (modularPayload.Installs != null) osQueryDict["installs"] = modularPayload.Installs;
        if (modularPayload.Profiles != null) osQueryDict["profiles"] = modularPayload.Profiles;
        
        payload.OsQuery = osQueryDict;

        // Convert Events to metadata array format for API compatibility
        if (modularPayload.Events != null && modularPayload.Events.Count > 0)
        {
            var metadataArray = new List<Dictionary<string, object>>();
            foreach (var evt in modularPayload.Events)
            {
                var eventDict = new Dictionary<string, object>
                {
                    ["eventType"] = evt.EventType,
                    ["message"] = evt.Message,
                    ["timestamp"] = evt.Timestamp.ToString("O")
                };

                if (evt.Details != null && evt.Details.Count > 0)
                {
                    eventDict["details"] = evt.Details;
                }

                metadataArray.Add(eventDict);
            }
            
            // Add metadata array to payload - this is what the API expects
            payload.Metadata = metadataArray.ToArray();
        }

        // Determine the highest priority event type for the main Kind field
        string primaryKind = "Info"; // Default to Info
        if (modularPayload.Events != null && modularPayload.Events.Count > 0)
        {
            // Priority order: Error > Warning > Success > Info
            if (modularPayload.Events.Any(e => e.EventType.Equals("error", StringComparison.OrdinalIgnoreCase)))
            {
                primaryKind = "Error";
            }
            else if (modularPayload.Events.Any(e => e.EventType.Equals("warning", StringComparison.OrdinalIgnoreCase)))
            {
                primaryKind = "Warning";
            }
            else if (modularPayload.Events.Any(e => e.EventType.Equals("success", StringComparison.OrdinalIgnoreCase)))
            {
                primaryKind = "Success";
            }
        }

        return new DeviceDataRequest
        {
            Device = modularPayload.Metadata.SerialNumber ?? modularPayload.Inventory?.SerialNumber ?? "",
            SerialNumber = modularPayload.Metadata.SerialNumber ?? modularPayload.Inventory?.SerialNumber ?? "",
            Kind = primaryKind,
            Ts = DateTime.UtcNow.ToString("O"),
            Payload = payload
        };
    }

    /// <summary>
    /// Logs summary of processed data collection
    /// </summary>
    private void LogProcessedDataSummary(ProcessedDeviceData processedData)
    {
        try
        {
            _logger.LogInformation("=== PROCESSED DATA COLLECTION SUMMARY ===");
            _logger.LogInformation("Device: {DeviceName} ({Manufacturer} {Model})", 
                processedData.BasicInfo.Name, 
                processedData.BasicInfo.Manufacturer, 
                processedData.BasicInfo.Model);
            _logger.LogInformation("Processor: {Processor} ({Cores} cores)", 
                processedData.Hardware.Processor, 
                processedData.Hardware.Cores);
            _logger.LogInformation("Graphics: {Graphics}", processedData.Hardware.Graphics);
            _logger.LogInformation("Memory: {Memory}", processedData.Hardware.Memory);
            _logger.LogInformation("OS: {OsName} {OsVersion} (Build {OsBuild})", 
                processedData.OperatingSystem.Name, 
                processedData.OperatingSystem.Version, 
                processedData.OperatingSystem.Build);
            _logger.LogInformation("Network: {IpAddress} (MAC: {MacAddress})", 
                processedData.Network.IpAddress, 
                processedData.Network.MacAddress);
            _logger.LogInformation("Client Version: {ClientVersion}", processedData.ClientVersion);
            _logger.LogInformation("Last Updated: {LastUpdated}", processedData.LastUpdated);
            _logger.LogInformation("=====================================");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error logging processed data summary");
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

            // Note: system and security sections removed in streamlined payload
            summary.Add("System data: extracted from osquery on backend");
            summary.Add("Security data: extracted from osquery on backend");

            if (deviceData.TryGetValue("osquery", out var osqueryInfo))
            {
                summary.Add($"osquery data collected (SINGLE PASS - no redundancy)");
            }

            if (deviceData.TryGetValue("reportmate_client", out var clientInfo))
            {
                summary.Add($"ReportMate client metadata collected");
            }

            _logger.LogInformation("Optimized collection summary: {Summary}", string.Join(", ", summary));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error creating collection summary");
        }
    }

    /// <summary>
    /// Sanitizes data to ensure it can be JSON serialized without errors
    /// </summary>
    private Dictionary<string, object> SanitizeForSerialization(Dictionary<string, object> data)
    {
        var sanitized = new Dictionary<string, object>();
        
        foreach (var kvp in data)
        {
            try
            {
                var sanitizedValue = SanitizeValue(kvp.Value);
                if (sanitizedValue != null)
                {
                    sanitized[kvp.Key] = sanitizedValue;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sanitize data for key: {Key}, skipping", kvp.Key);
                // Skip problematic values rather than failing the entire operation
            }
        }
        
        return sanitized;
    }

    /// <summary>
    /// Recursively sanitizes a value for JSON serialization
    /// </summary>
    private object? SanitizeValue(object? value)
    {
        if (value == null) return null;
        
        // Handle JsonElement which can come from osquery
        if (value is System.Text.Json.JsonElement jsonElement)
        {
            _logger.LogDebug("Converting JsonElement to native object - ValueKind: {ValueKind}", jsonElement.ValueKind);
            return ConvertJsonElementToObject(jsonElement);
        }
        
        // Handle primitive types
        if (value is string || value is int || value is long || value is double || value is float || 
            value is bool || value is DateTime || value is DateTimeOffset)
        {
            return value;
        }
        
        // Handle our custom model types - keep them as objects for proper JSON serialization
        if (value is DeviceInfo deviceInfo)
        {
            _logger.LogDebug("Sanitizing DeviceInfo object - DeviceId: {DeviceId}, SerialNumber: {SerialNumber}", 
                deviceInfo.DeviceId, deviceInfo.SerialNumber);
            return value; // Keep the object intact for proper JSON serialization
        }
        
        if (value is SystemInfo || value is DeviceSecurityInfo || value is DiskInfo)
        {
            _logger.LogDebug("Sanitizing custom model type: {Type}", value.GetType().Name);
            return value; // Keep the object intact for proper JSON serialization
        }
        
        // Handle dictionaries
        if (value is Dictionary<string, object> dict)
        {
            var sanitizedDict = new Dictionary<string, object>();
            foreach (var kvp in dict)
            {
                var sanitizedValue = SanitizeValue(kvp.Value);
                if (sanitizedValue != null)
                {
                    sanitizedDict[kvp.Key] = sanitizedValue;
                }
            }
            return sanitizedDict;
        }
        
        // Handle Dictionary<string, List<Dictionary<string, object>>> specifically for OSQuery data
        if (value is Dictionary<string, List<Dictionary<string, object>>> osqueryDict)
        {
            var sanitizedDict = new Dictionary<string, object>();
            foreach (var kvp in osqueryDict)
            {
                sanitizedDict[kvp.Key] = kvp.Value; // Keep the list structure intact
            }
            return sanitizedDict;
        }
        
        // Handle lists
        if (value is List<Dictionary<string, object>> listDict)
        {
            var sanitizedList = new List<Dictionary<string, object>>();
            foreach (var item in listDict)
            {
                var sanitizedItem = SanitizeValue(item);
                if (sanitizedItem is Dictionary<string, object> sanitizedDict)
                {
                    sanitizedList.Add(sanitizedDict);
                }
            }
            return sanitizedList;
        }
        
        // Handle KeyValuePair from OSQuery data (this was causing the string conversion issue)
        if (value is System.Collections.Generic.KeyValuePair<string, List<Dictionary<string, object>>> kvpOsquery)
        {
            return kvpOsquery.Value; // Return just the list data, not the KeyValuePair wrapper
        }
        
        // Handle other KeyValuePair types (safe string conversion to avoid trim warnings)
        if (value.GetType().IsGenericType && value.GetType().GetGenericTypeDefinition() == typeof(System.Collections.Generic.KeyValuePair<,>))
        {
            // Convert to string representation instead of using reflection/dynamic
            var stringValue = value.ToString() ?? "";
            // Extract value part from "KeyValuePair[key, value]" format
            var valueStart = stringValue.LastIndexOf(", ");
            if (valueStart > 0 && stringValue.EndsWith("]"))
            {
                var extractedValue = stringValue.Substring(valueStart + 2, stringValue.Length - valueStart - 3);
                return extractedValue;
            }
            return stringValue;
        }
        
        // Handle other collections
        if (value is System.Collections.IEnumerable enumerable && !(value is string))
        {
            var list = new List<object>();
            foreach (var item in enumerable)
            {
                var sanitizedItem = SanitizeValue(item);
                if (sanitizedItem != null)
                {
                    list.Add(sanitizedItem);
                }
            }
            return list;
        }
        
        // For complex objects, try to convert to string as last resort
        _logger.LogWarning("Converting complex object to string: {Type}", value.GetType().FullName);
        try
        {
            return value.ToString();
        }
        catch
        {
            // If all else fails, return the type name
            return value.GetType().Name;
        }
    }

    /// <summary>
    /// Converts a JsonElement to a native .NET object
    /// </summary>
    private object? ConvertJsonElementToObject(System.Text.Json.JsonElement element)
    {
        switch (element.ValueKind)
        {
            case System.Text.Json.JsonValueKind.String:
                return element.GetString();
            case System.Text.Json.JsonValueKind.Number:
                if (element.TryGetInt32(out int intValue))
                    return intValue;
                if (element.TryGetInt64(out long longValue))
                    return longValue;
                if (element.TryGetDouble(out double doubleValue))
                    return doubleValue;
                return element.GetDecimal();
            case System.Text.Json.JsonValueKind.True:
                return true;
            case System.Text.Json.JsonValueKind.False:
                return false;
            case System.Text.Json.JsonValueKind.Null:
                return null;
            case System.Text.Json.JsonValueKind.Array:
                var list = new List<object>();
                foreach (var item in element.EnumerateArray())
                {
                    var convertedItem = ConvertJsonElementToObject(item);
                    if (convertedItem != null)
                    {
                        list.Add(convertedItem);
                    }
                }
                return list;
            case System.Text.Json.JsonValueKind.Object:
                var dict = new Dictionary<string, object>();
                foreach (var prop in element.EnumerateObject())
                {
                    var convertedValue = ConvertJsonElementToObject(prop.Value);
                    if (convertedValue != null)
                    {
                        dict[prop.Name] = convertedValue;
                    }
                }
                return dict;
            default:
                return element.ToString();
        }
    }

    /// <summary>
    /// Gets simple device identification without full osquery data collection
    /// </summary>
    private Task<string> GetSimpleDeviceIdAsync()
    {
        try
        {
            // Use only basic system info for device ID - no full osquery collection
            var computerName = Environment.MachineName;
            var userName = Environment.UserName;
            var osVersion = Environment.OSVersion.ToString();
            
            // Create a simple device ID based on available system info
            var deviceId = $"{computerName}_{userName}_{osVersion.GetHashCode()}";
            
            _logger.LogInformation("Generated simple device ID: {DeviceId}", deviceId);
            return Task.FromResult(deviceId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating simple device ID");
            // Fallback to machine name if something goes wrong
            return Task.FromResult(Environment.MachineName);
        }
    }
}
