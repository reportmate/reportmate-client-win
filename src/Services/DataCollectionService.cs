#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ReportMate.WindowsClient.Models;

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
                _logger.LogError("❌ Configuration validation failed: {Errors}", 
                    string.Join(", ", configValidation.Errors));
                return false;
            }

            _logger.LogInformation("✅ Configuration validated successfully");

            // Log warnings but continue
            foreach (var warning in configValidation.Warnings)
            {
                _logger.LogWarning("Configuration warning: {Warning}", warning);
            }

            // Collect basic device info first for registration
            _logger.LogInformation("=== STEP 2: DEVICE INFORMATION COLLECTION ===");
            _logger.LogInformation("Getting device information for registration check...");
            var deviceInfo = await _deviceInfoService.GetBasicDeviceInfoAsync();
            
            _logger.LogInformation("=== DEVICE IDENTIFICATION RESULTS ===");
            _logger.LogInformation("Device ID: {DeviceId} (PRIMARY IDENTIFIER)", deviceInfo.DeviceId);
            _logger.LogInformation("Serial Number: {SerialNumber}", deviceInfo.SerialNumber);
            _logger.LogInformation("Computer Name: {ComputerName}", deviceInfo.ComputerName);
            _logger.LogInformation("Domain: {Domain}", deviceInfo.Domain);

            // CRITICAL: DEVICE REGISTRATION CHECK AND AUTO-REGISTRATION
            // Check if device is registered, if not, register it via "new_client" event
            _logger.LogInformation("=== STEP 3: DEVICE REGISTRATION CHECK ===");
            _logger.LogInformation("� Checking if device {DeviceId} is registered...", deviceInfo.DeviceId);
            
            var isRegistered = await _apiService.IsDeviceRegisteredAsync(deviceInfo.DeviceId);
            _logger.LogInformation("Device {DeviceId} registration status: {Status}", 
                deviceInfo.DeviceId, isRegistered ? "✅ REGISTERED" : "❌ NOT REGISTERED");
            
            if (!isRegistered)
            {
                _logger.LogInformation("🚨 UNREGISTERED DEVICE - Initiating auto-registration");
                _logger.LogInformation("📝 Registering device {DeviceId} as 'New Client'", deviceInfo.DeviceId);
                
                var registrationSuccess = await _apiService.RegisterDeviceAsync(deviceInfo);
                _logger.LogInformation("Registration attempt result: {Success}", registrationSuccess);
                
                if (!registrationSuccess)
                {
                    _logger.LogError("❌ Device registration failed for {DeviceId}", deviceInfo.DeviceId);
                    _logger.LogError("⚠️  Proceeding with data collection anyway - device may register on next run");
                }
                else
                {
                    _logger.LogInformation("✅ Device {DeviceId} registered successfully", deviceInfo.DeviceId);
                    _logger.LogInformation("✅ New Client event should be visible in dashboard at /device/{DeviceId}", deviceInfo.DeviceId);
                }
            }
            else
            {
                _logger.LogInformation("✅ Device {DeviceId} is already registered", deviceInfo.DeviceId);
            }

            // Now collect comprehensive data - ONLY after registration is confirmed
            _logger.LogInformation("=== STEP 4: COMPREHENSIVE DATA COLLECTION ===");
            _logger.LogInformation("🔓 AUTHORIZED: Device registration verified, proceeding with data collection");
            _logger.LogInformation("📊 COLLECTING: Comprehensive device data including osquery results");
            
            var deviceData = await CollectDataAsync();

            _logger.LogInformation("✅ Data collection completed successfully");
            LogCollectionSummary(deviceData);

            // Send to API
            _logger.LogInformation("=== STEP 5: DATA TRANSMISSION ===");
            _logger.LogInformation("🚀 Sending data to ReportMate API via /api/device");
            
            var success = await _apiService.SendDeviceDataAsync(deviceData);

            if (success)
            {
                _logger.LogInformation("✅ SUCCESS: Data transmission completed successfully");
                _logger.LogInformation("✅ DASHBOARD: Data should be visible at /device/{DeviceId}", deviceInfo.DeviceId);
                await _configurationService.UpdateLastRunTimeAsync();
                return true;
            }
            else
            {
                _logger.LogError("❌ TRANSMISSION FAILED: Data collection succeeded but transmission failed");
                _logger.LogError("❌ NOTE: Will retry on next run");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ CRITICAL ERROR: Data collection process failed");
            return false;
        }
    }

    public async Task<Dictionary<string, object>> CollectDataAsync()
    {
        try
        {
            _logger.LogInformation("=== COMPREHENSIVE DATA COLLECTION STARTING ===");
            _logger.LogInformation("Collecting device, system, security, and osquery data...");

            var deviceData = await _deviceInfoService.GetComprehensiveDeviceDataAsync();
            
            _logger.LogInformation("Raw data collection completed. Analyzing collected data...");

            // Log detailed collection results
            if (deviceData.TryGetValue("device", out var deviceInfo))
            {
                _logger.LogInformation("✅ Device Info: Collected basic device information");
                if (deviceInfo is DeviceInfo di)
                {
                    _logger.LogInformation("   Device ID: {DeviceId}", di.DeviceId);
                    _logger.LogInformation("   Serial Number: {SerialNumber}", di.SerialNumber);
                    _logger.LogInformation("   Computer Name: {ComputerName}", di.ComputerName);
                    _logger.LogInformation("   Manufacturer: {Manufacturer}", di.Manufacturer);
                    _logger.LogInformation("   Model: {Model}", di.Model);
                }
            }

            if (deviceData.TryGetValue("system", out var systemInfo))
            {
                _logger.LogInformation("✅ System Info: Collected system information");
            }

            if (deviceData.TryGetValue("security", out var securityInfo))
            {
                _logger.LogInformation("✅ Security Info: Collected security status");
            }

            if (deviceData.TryGetValue("osquery", out var osqueryInfo))
            {
                _logger.LogInformation("✅ OSQuery Data: Collected osquery results");
                if (osqueryInfo is Dictionary<string, object> osqueryDict)
                {
                    _logger.LogInformation("   OSQuery queries executed: {QueryCount}", osqueryDict.Keys.Count);
                    foreach (var queryName in osqueryDict.Keys)
                    {
                        _logger.LogInformation("   - Query: {QueryName}", queryName);
                    }
                }
            }
            else
            {
                _logger.LogWarning("⚠️  OSQuery Data: No osquery data found");
            }

            // Sanitize the device data to ensure it's JSON serializable
            _logger.LogInformation("Sanitizing data for JSON serialization...");
            var sanitizedData = SanitizeForSerialization(deviceData);

            // Add ReportMate client metadata with enhanced info
            _logger.LogInformation("Adding ReportMate client metadata...");
            sanitizedData["reportmate_client"] = new Dictionary<string, object>
            {
                { "version", "2025.7.1.3" },
                { "platform", "windows" },
                { "collection_time", DateTime.UtcNow.ToString("O") },
                { "client_type", "windows_cimian" }, // Specify this is for Windows with Cimian support
                { "managed_installs_system", "Cimian" } // Use Cimian for Windows (vs Munki for Mac)
            };

            // Add environment context with enhanced details
            _logger.LogInformation("Adding environment context...");
            sanitizedData["environment"] = new Dictionary<string, object>
            {
                { "is_domain_joined", !string.IsNullOrEmpty(Environment.UserDomainName) && Environment.UserDomainName != Environment.MachineName },
                { "user_interactive", Environment.UserInteractive },
                { "current_directory", Environment.CurrentDirectory },
                { "machine_name", Environment.MachineName },
                { "user_domain_name", Environment.UserDomainName },
                { "processor_count", Environment.ProcessorCount },
                { "is_64bit_os", Environment.Is64BitOperatingSystem },
                { "is_64bit_process", Environment.Is64BitProcess },
                { "clr_version", Environment.Version.ToString() },
                { "collection_method", "runner.exe" },
                { "elevation_required", true }, // runner.exe requires admin
                { "data_source", "comprehensive" }
            };

            // Calculate and log data size
            try 
            {
                var jsonOptions = new JsonSerializerOptions { TypeInfoResolver = ReportMateJsonContext.Default };
                var serialized = System.Text.Json.JsonSerializer.Serialize(sanitizedData, ReportMateJsonContext.Default.DictionaryStringObject);
                var dataSizeKB = Math.Round(serialized.Length / 1024.0, 2);
                
                _logger.LogInformation("✅ Data collection completed successfully");
                _logger.LogInformation("📊 Final data size: {DataSize} KB ({DataSizeBytes} bytes)", dataSizeKB, serialized.Length);
                
                if (dataSizeKB > 100) // Log warning for large payloads
                {
                    _logger.LogWarning("⚠️  Large payload detected: {DataSize} KB - this may cause browser performance issues", dataSizeKB);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error calculating data size for logging");
                _logger.LogInformation("✅ Device data collection completed (size calculation failed)");
            }

            _logger.LogInformation("=== COMPREHENSIVE DATA COLLECTION COMPLETED ===");
            return sanitizedData;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error collecting comprehensive device data");
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
        
        if (value is SystemInfo || value is SecurityInfo || value is DiskInfo)
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
        
        // Handle other KeyValuePair types
        if (value.GetType().IsGenericType && value.GetType().GetGenericTypeDefinition() == typeof(System.Collections.Generic.KeyValuePair<,>))
        {
            // Use reflection to get the Value property
            var valueProperty = value.GetType().GetProperty("Value");
            if (valueProperty != null)
            {
                var extractedValue = valueProperty.GetValue(value);
                return SanitizeValue(extractedValue);
            }
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
}
