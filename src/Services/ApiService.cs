#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Text.Json.Serialization.Metadata;
using System.IO;
using System.Linq;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for communicating with the ReportMate API
/// Handles authentication, retries, and secure data transmission
/// </summary>
public interface IApiService
{
    Task<bool> SendDeviceDataAsync(DeviceDataRequest deviceData);
    Task<bool> SendUnifiedPayloadAsync(UnifiedDevicePayload payload);
    Task<bool> TestConnectivityAsync();
    Task<bool> RegisterDeviceAsync(DeviceInfo deviceInfo);
    Task<bool> IsDeviceRegisteredAsync(string deviceId);
}

public class ApiService : IApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ApiService> _logger;
    private readonly IConfiguration _configuration;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly string? _cacheDirectory;

    public ApiService(HttpClient httpClient, ILogger<ApiService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        _configuration = configuration;
        
        // Set up logs directory for transmission tracking (separate from cache)
        _cacheDirectory = Path.Combine(@"C:\ProgramData\ManagedReports\logs");
        try
        {
            if (!Directory.Exists(_cacheDirectory))
            {
                Directory.CreateDirectory(_cacheDirectory);
                _logger.LogInformation("Created transmission logs directory: {LogsDirectory}", _cacheDirectory);
            }
            
            // Clean up old payload_ files from cache directory (deprecated)
            CleanupDeprecatedPayloadFiles();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create logs directory, transmission logging will be disabled");
            _cacheDirectory = null;
        }
        
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            TypeInfoResolver = ReportMateJsonContext.Default
        };

        ConfigureHttpClient();
    }

    public async Task<bool> SendDeviceDataAsync(DeviceDataRequest deviceData)
    {
        try
        {
            _logger.LogInformation("=== DEVICE DATA TRANSMISSION STARTING ===");
            _logger.LogInformation("Preparing device data for transmission to ReportMate API...");

            // Extract device info for registration from the request payload
            DeviceInfo? deviceInfo = null;
            var devicePayload = deviceData.Payload?.Device;
            
            _logger.LogInformation("Device payload type: {Type}", devicePayload?.GetType().FullName);
            
            if (devicePayload != null)
            {
                // Create DeviceInfo object from the device payload dictionary
                deviceInfo = new DeviceInfo
                {
                    DeviceId = devicePayload.GetValueOrDefault("DeviceId")?.ToString() ?? "",
                    SerialNumber = devicePayload.GetValueOrDefault("SerialNumber")?.ToString() ?? "",
                    ComputerName = devicePayload.GetValueOrDefault("ComputerName")?.ToString() ?? "",
                    Manufacturer = devicePayload.GetValueOrDefault("Manufacturer")?.ToString() ?? "",
                    Model = devicePayload.GetValueOrDefault("Model")?.ToString() ?? ""
                };
                _logger.LogInformation("Device info created from payload");
                _logger.LogInformation("   DeviceId: {DeviceId}", deviceInfo.DeviceId);
                _logger.LogInformation("   SerialNumber: {SerialNumber}", deviceInfo.SerialNumber);
                _logger.LogInformation("   ComputerName: {ComputerName}", deviceInfo.ComputerName);
            }
            else
            {
                _logger.LogError("Device payload is null or invalid");
            }

            // Use Serial Number as the primary identifier for API routing
            // The URL should be /device/{serial} while DeviceId field shows the hardware UUID
            var deviceSerial = deviceInfo?.SerialNumber ?? Environment.MachineName;
            var hardwareUuid = deviceInfo?.DeviceId; // This is the actual hardware UUID
            
            _logger.LogInformation("=== TRANSMISSION DETAILS ===");
            _logger.LogInformation("Device Serial Number: {DeviceSerial} (used for URL routing)", deviceSerial);
            _logger.LogInformation("Hardware UUID: {HardwareUuid} (used for DeviceId field)", hardwareUuid);
            _logger.LogInformation("Computer Name: {ComputerName}", deviceInfo?.ComputerName ?? "Unknown");
            _logger.LogInformation("Expected Dashboard URL: /device/{DeviceSerial}", deviceSerial);

            // Analyze payload composition
            _logger.LogInformation("=== PAYLOAD ANALYSIS ===");
            if (deviceData.Payload?.Device != null) _logger.LogInformation("Device data included");
            if (deviceData.Payload?.System != null) _logger.LogInformation("System data included");
            if (deviceData.Payload?.Security != null) _logger.LogInformation("Security data included");
            if (deviceData.Payload?.OsQuery != null) _logger.LogInformation("OSQuery data included");
            _logger.LogInformation("ReportMate client metadata included");
            _logger.LogInformation("Environment context included");

            // Create the payload as a proper dictionary for JSON serialization
            _logger.LogInformation("Creating API payload for /api/device...");
            
            // Create a serializable device info object
            var deviceInfoPayload = new Dictionary<string, object>();
            if (deviceInfo != null)
            {
                deviceInfoPayload["deviceId"] = hardwareUuid ?? "";  // Hardware UUID for DeviceId field
                deviceInfoPayload["serialNumber"] = deviceInfo.SerialNumber ?? "";
                deviceInfoPayload["computerName"] = deviceInfo.ComputerName ?? "";
                deviceInfoPayload["domain"] = deviceInfo.Domain ?? "";
                deviceInfoPayload["manufacturer"] = deviceInfo.Manufacturer ?? "";
                deviceInfoPayload["model"] = deviceInfo.Model ?? "";
                deviceInfoPayload["totalMemoryGB"] = deviceInfo.TotalMemoryGB;
                deviceInfoPayload["lastSeen"] = deviceInfo.LastSeen.ToString("O");
                deviceInfoPayload["clientVersion"] = deviceInfo.ClientVersion ?? "";
                deviceInfoPayload["assetTag"] = deviceInfo.AssetTag ?? "";
                
                // Send granular OS information instead of combined string
                deviceInfoPayload["osName"] = deviceInfo.OsName ?? "";
                deviceInfoPayload["osVersion"] = deviceInfo.OsVersion ?? "";
                deviceInfoPayload["osBuild"] = deviceInfo.OsBuild ?? "";
                deviceInfoPayload["osArchitecture"] = deviceInfo.OsArchitecture ?? "";
                
                // Network information
                deviceInfoPayload["ipAddressV4"] = deviceInfo.IpAddressV4 ?? "";
                deviceInfoPayload["ipAddressV6"] = deviceInfo.IpAddressV6 ?? "";
                deviceInfoPayload["macAddress"] = deviceInfo.MacAddress ?? "";
                
                // MDM information
                deviceInfoPayload["mdmEnrollmentId"] = deviceInfo.MdmEnrollmentId ?? "";
                deviceInfoPayload["mdmEnrollmentType"] = deviceInfo.MdmEnrollmentType ?? "";
                deviceInfoPayload["mdmEnrollmentState"] = deviceInfo.MdmEnrollmentState ?? "";
                deviceInfoPayload["mdmManagementUrl"] = deviceInfo.MdmManagementUrl ?? "";
                
                // Dashboard hardware fields - enhanced specifications for frontend widgets
                if (!string.IsNullOrEmpty(deviceInfo.Processor))
                    deviceInfoPayload["processor"] = deviceInfo.Processor;
                if (deviceInfo.Cores.HasValue)
                    deviceInfoPayload["cores"] = deviceInfo.Cores.Value;
                if (!string.IsNullOrEmpty(deviceInfo.Memory))
                    deviceInfoPayload["memory"] = deviceInfo.Memory;
                if (!string.IsNullOrEmpty(deviceInfo.AvailableRAM))
                    deviceInfoPayload["availableRAM"] = deviceInfo.AvailableRAM;
                if (!string.IsNullOrEmpty(deviceInfo.Storage))
                    deviceInfoPayload["storage"] = deviceInfo.Storage;
                if (!string.IsNullOrEmpty(deviceInfo.AvailableStorage))
                    deviceInfoPayload["availableStorage"] = deviceInfo.AvailableStorage;
                if (!string.IsNullOrEmpty(deviceInfo.StorageType))
                    deviceInfoPayload["storageType"] = deviceInfo.StorageType;
                if (!string.IsNullOrEmpty(deviceInfo.Graphics))
                    deviceInfoPayload["graphics"] = deviceInfo.Graphics;
                if (!string.IsNullOrEmpty(deviceInfo.Vram))
                    deviceInfoPayload["vram"] = deviceInfo.Vram;
                if (!string.IsNullOrEmpty(deviceInfo.Platform))
                    deviceInfoPayload["platform"] = deviceInfo.Platform;
                if (!string.IsNullOrEmpty(deviceInfo.Architecture))
                    deviceInfoPayload["architecture"] = deviceInfo.Architecture;
                if (!string.IsNullOrEmpty(deviceInfo.Uptime))
                    deviceInfoPayload["uptime"] = deviceInfo.Uptime;
                if (!string.IsNullOrEmpty(deviceInfo.BootTime))
                    deviceInfoPayload["bootTime"] = deviceInfo.BootTime;
                if (deviceInfo.DiskUtilization.HasValue)
                    deviceInfoPayload["diskUtilization"] = deviceInfo.DiskUtilization.Value;
                if (deviceInfo.MemoryUtilization.HasValue)
                    deviceInfoPayload["memoryUtilization"] = deviceInfo.MemoryUtilization.Value;
                if (!string.IsNullOrEmpty(deviceInfo.BatteryLevel))
                    deviceInfoPayload["batteryLevel"] = deviceInfo.BatteryLevel;
                if (!string.IsNullOrEmpty(deviceInfo.Status))
                    deviceInfoPayload["status"] = deviceInfo.Status;
                if (deviceInfo.TotalEvents > 0)
                    deviceInfoPayload["totalEvents"] = deviceInfo.TotalEvents;
                if (deviceInfo.LastEventTime != default)
                    deviceInfoPayload["lastEventTime"] = deviceInfo.LastEventTime.ToString("O");
            }
            
            // The deviceData parameter already has the correct structure for transmission
            var payload = deviceData;

            // Add passphrase to payload if configured
            var passphrase = _configuration["ReportMate:Passphrase"];
            if (!string.IsNullOrEmpty(passphrase))
            {
                payload.Passphrase = passphrase;
                _logger.LogInformation("Client passphrase included in payload");
            }
            else
            {
                _logger.LogInformation(" No client passphrase configured - requests may be rejected if authentication is required");
            }

            _logger.LogInformation("Payload created with device serial: {DeviceSerial}", payload.Device);

            var maxRetries = int.TryParse(_configuration["ReportMate:MaxRetryAttempts"], out var retries) ? retries : 3;
            var retryDelay = TimeSpan.FromSeconds(1);

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    _logger.LogInformation("=== API TRANSMISSION ATTEMPT {Attempt}/{MaxRetries} ===", attempt, maxRetries);

                    // Use the ReportMateJsonContext for proper trim-safe JSON serialization
                    var jsonContent = JsonSerializer.Serialize(payload!, ReportMateJsonContext.Default.DeviceDataRequest);
                    var httpContent = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");
                    
                    // Cache the payload for replay testing in case of transmission failure
                    await CachePayloadAsync(jsonContent, deviceSerial, attempt);
                    
                    var dataSizeKB = Math.Round(jsonContent.Length / 1024.0, 2);
                    _logger.LogInformation("Sending POST to /api/device...");
                    _logger.LogInformation("Payload size: {DataSize} KB ({DataSizeBytes} bytes)", dataSizeKB, jsonContent.Length);
                    _logger.LogInformation("Device Serial in payload: {DeviceSerial}", payload?.Device ?? "Unknown");

                    var response = await _httpClient.PostAsync("/api/device", httpContent);
                    _logger.LogInformation("API Response: {StatusCode} {ReasonPhrase}", response.StatusCode, response.ReasonPhrase);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        _logger.LogInformation("SUCCESS: Device data sent to ReportMate API");
                        _logger.LogInformation("Data should now be visible in dashboard at /device/{DeviceSerial}", deviceSerial);
                        _logger.LogInformation("API Response: {Response}", responseContent);
                        
                        // Send event.json as a structured event
                        await SendStructuredEventAsync(deviceSerial, deviceData);
                        
                        return true;
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // Special handling for 404 - API endpoint not deployed yet
                        _logger.LogWarning("API endpoint /api/device not found (404). This is unexpected as the endpoint should be available.");
                        _logger.LogInformation("DATA READY FOR TRANSMISSION - Would have sent the following payload:");
                        _logger.LogInformation("Payload size: {PayloadSize} bytes", jsonContent.Length);
                        _logger.LogInformation("Device: {Device}", payload?.Device ?? "Unknown");
                        _logger.LogInformation("Kind: {Kind}", payload?.Kind ?? "Unknown");
                        _logger.LogInformation("Timestamp: {Timestamp}", payload?.Ts ?? "Unknown");
                        
                        // Log a sample of the actual data being collected
                        if (payload?.Payload != null)
                        {
                            if (payload.Payload.System != null)
                            {
                                _logger.LogInformation("System data collected and ready");
                            }
                            if (payload.Payload.Security != null)
                            {
                                _logger.LogInformation("Security data collected and ready");
                            }
                            if (payload.Payload.OsQuery != null)
                            {
                                _logger.LogInformation("OSQuery data collected and ready");
                            }
                        }
                        
                        _logger.LogInformation(" SUCCESS: ReportMate client is fully functional and ready to send data!");
                        _logger.LogInformation("Once the /api/device endpoint is available, this machine will automatically start reporting.");
                        
                        // Return true since the client is working correctly
                        return true;
                    }
                    else
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        
                        // Enhanced error logging for failed API responses
                        _logger.LogWarning("=== API REQUEST FAILED ===");
                        _logger.LogWarning("Status Code: {StatusCode}", response.StatusCode);
                        _logger.LogWarning("Reason Phrase: {ReasonPhrase}", response.ReasonPhrase);
                        _logger.LogWarning("Error Content: {ErrorContent}", errorContent);
                        _logger.LogWarning("Request URL: {RequestUrl}", _httpClient.BaseAddress + "/api/device");
                        _logger.LogWarning("Attempt: {Attempt}/{MaxRetries}", attempt, maxRetries);
                        
                        // Try to parse error response as JSON for additional details
                        try
                        {
                            var errorResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(errorContent, _jsonOptions);
                            if (errorResponse != null)
                            {
                                _logger.LogWarning("Parsed Error Response:");
                                foreach (var kvp in errorResponse)
                                {
                                    _logger.LogWarning("  {Key}: {Value}", kvp.Key, kvp.Value);
                                }
                                
                                // Log debug_info if present
                                if (errorResponse.TryGetValue("debug_info", out var debugInfo))
                                {
                                    _logger.LogWarning("Debug Information from API:");
                                    _logger.LogWarning("  {DebugInfo}", debugInfo);
                                }
                            }
                        }
                        catch (JsonException)
                        {
                            _logger.LogWarning("Error response is not valid JSON: {ErrorContent}", errorContent);
                        }
                        
                        // Don't retry on client errors (4xx)
                        if ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500)
                        {
                            _logger.LogError("=== CLIENT ERROR - NOT RETRYING ===");
                            _logger.LogError("Status Code: {StatusCode}", response.StatusCode);
                            _logger.LogError("This indicates a problem with the request data or API configuration");
                            _logger.LogError("Payload that caused the error:");
                            _logger.LogError("Device UUID (payload.Device): {DeviceUuid}", payload?.Device ?? "Unknown");
                            _logger.LogError("Device Serial Number: {DeviceSerial}", deviceSerial);
                            _logger.LogError("Payload Size: {PayloadSize} bytes", jsonContent.Length);
                            _logger.LogError("Kind: {Kind}", payload?.Kind ?? "Unknown");
                            return false;
                        }
                    }
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogWarning("=== HTTP REQUEST EXCEPTION ===");
                    _logger.LogWarning("Attempt: {Attempt}/{MaxRetries}", attempt, maxRetries);
                    _logger.LogWarning("Exception Type: {ExceptionType}", ex.GetType().Name);
                    _logger.LogWarning("Exception Message: {ExceptionMessage}", ex.Message);
                    _logger.LogWarning("Inner Exception: {InnerException}", ex.InnerException?.Message);
                    _logger.LogWarning("Request URL: {RequestUrl}", _httpClient.BaseAddress + "/api/device");
                    _logger.LogWarning("Device Serial: {DeviceSerial}", deviceSerial);
                    
                    if (ex.Data?.Count > 0)
                    {
                        _logger.LogWarning("Exception Data:");
                        foreach (var key in ex.Data.Keys)
                        {
                            _logger.LogWarning("  {Key}: {Value}", key, ex.Data[key]);
                        }
                    }
                }
                catch (TaskCanceledException ex) when (ex.CancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning("=== REQUEST TIMEOUT ===");
                    _logger.LogWarning("Attempt: {Attempt}/{MaxRetries}", attempt, maxRetries);
                    _logger.LogWarning("Request timed out after configured timeout period");
                    _logger.LogWarning("Device Serial: {DeviceSerial}", deviceSerial);
                    _logger.LogWarning("Configured Timeout: {Timeout} seconds", _configuration["ReportMate:ApiTimeoutSeconds"] ?? "300");
                    _logger.LogWarning("Exception Message: {ExceptionMessage}", ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogError("=== UNEXPECTED EXCEPTION DURING TRANSMISSION ===");
                    _logger.LogError("Attempt: {Attempt}/{MaxRetries}", attempt, maxRetries);
                    _logger.LogError("Exception Type: {ExceptionType}", ex.GetType().FullName);
                    _logger.LogError("Exception Message: {ExceptionMessage}", ex.Message);
                    _logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
                    _logger.LogError("Device Serial Number: {DeviceSerial}", deviceSerial);
                    _logger.LogError("Payload Size: {PayloadSize} bytes", payload != null ? JsonSerializer.Serialize(payload, _jsonOptions).Length : 0);
                    
                    if (ex.InnerException != null)
                    {
                        _logger.LogError("Inner Exception Type: {InnerExceptionType}", ex.InnerException.GetType().FullName);
                        _logger.LogError("Inner Exception Message: {InnerExceptionMessage}", ex.InnerException.Message);
                    }
                }

                // Wait before retrying (exponential backoff)
                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1));
                    _logger.LogDebug("Waiting {Delay} seconds before retry", delay.TotalSeconds);
                    await Task.Delay(delay);
                }
            }

            // Final failure logging with comprehensive debugging information
            _logger.LogError("=== TRANSMISSION FAILED ===");
            _logger.LogError("Failed to send device data after {MaxRetries} attempts", maxRetries);
            _logger.LogError("Device Serial Number: {DeviceSerial}", deviceSerial);
            _logger.LogError("Hardware UUID: {HardwareUuid}", hardwareUuid);
            _logger.LogError("Computer Name: {ComputerName}", deviceInfo?.ComputerName ?? "Unknown");
            _logger.LogError("API Base URL: {BaseUrl}", _httpClient.BaseAddress);
            _logger.LogError("Expected Endpoint: {Endpoint}", "/api/device");
            _logger.LogError("Payload Size: {PayloadSize} bytes", payload != null ? JsonSerializer.Serialize(payload, _jsonOptions).Length : 0);
            
            if (payload != null)
            {
                _logger.LogError("Payload Summary:");
                _logger.LogError("  Device: {Device}", payload.Device);
                _logger.LogError("  Kind: {Kind}", payload.Kind);
                _logger.LogError("  Has Device Info: {HasDevice}", payload.Payload?.Device?.Count > 0);
                _logger.LogError("  Has OSQuery Data: {HasOSQuery}", payload.Payload?.OsQuery?.Count > 0);
            }
            
            _logger.LogError("TRANSMISSION FAILED: Data collection succeeded but transmission failed");
            _logger.LogError("NOTE: Will retry on next run");
            _logger.LogError("Data collection or transmission failed");
            _logger.LogError("IMPACT: Device may not be registered or API issues detected");
            _logger.LogError("ACTION REQUIRED: Check logs above for specific failure reasons");
            
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending device data to API");
            return false;
        }
    }

    /// <summary>
    /// Send unified device payload directly to the API
    /// This is the simplified approach that sends the event.json structure directly
    /// </summary>
    public async Task<bool> SendUnifiedPayloadAsync(UnifiedDevicePayload payload)
    {
        try
        {
            _logger.LogInformation("=== UNIFIED PAYLOAD TRANSMISSION STARTING ===");
            _logger.LogInformation("Sending unified payload to ReportMate API...");

            var deviceSerial = payload.Inventory?.SerialNumber ?? payload.Metadata.DeviceId;
            var deviceId = payload.Metadata.DeviceId;
            
            _logger.LogInformation("=== TRANSMISSION DETAILS ===");
            _logger.LogInformation("Device UUID: {DeviceId}", deviceId);
            _logger.LogInformation("Device Serial: {DeviceSerial} (used for URL routing)", deviceSerial);
            _logger.LogInformation("Platform: {Platform}", payload.Metadata.Platform);
            _logger.LogInformation("Collection Type: {CollectionType}", payload.Metadata.CollectionType);
            _logger.LogInformation("Enabled Modules: [{EnabledModules}]", string.Join(", ", payload.Metadata.EnabledModules));
            _logger.LogInformation("Client Version: {ClientVersion}", payload.Metadata.ClientVersion);
            _logger.LogInformation("Expected Dashboard URL: /device/{DeviceSerial}", deviceSerial);

            // Add passphrase if configured
            var passphrase = _configuration["ReportMate:Passphrase"];
            if (!string.IsNullOrEmpty(passphrase))
            {
                payload.Metadata.Additional["passphrase"] = passphrase;
                _logger.LogInformation("Client passphrase included in payload");
            }

            var maxRetries = int.TryParse(_configuration["ReportMate:MaxRetryAttempts"], out var retries) ? retries : 3;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    _logger.LogInformation("=== API TRANSMISSION ATTEMPT {Attempt}/{MaxRetries} ===", attempt, maxRetries);

                    // Serialize the unified payload directly
                    var jsonContent = JsonSerializer.Serialize(payload, ReportMateJsonContext.Default.UnifiedDevicePayload);
                    var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                    
                    // Cache the payload for debugging
                    if (_cacheDirectory != null)
                    {
                        await CacheUnifiedPayloadAsync(jsonContent, deviceSerial, attempt);
                    }

                    var dataSizeKB = Math.Round(jsonContent.Length / 1024.0, 2);
                    _logger.LogInformation("Sending POST to /api/events...");
                    _logger.LogInformation("Payload size: {DataSize} KB ({DataSizeBytes} bytes)", dataSizeKB, jsonContent.Length);
                    _logger.LogInformation("Device Serial in payload: {DeviceSerial}", deviceSerial);

                    var response = await _httpClient.PostAsync("/api/events", httpContent);
                    _logger.LogInformation("API Response: {StatusCode} {ReasonPhrase}", response.StatusCode, response.ReasonPhrase);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        _logger.LogInformation("SUCCESS: Unified payload sent to ReportMate API");
                        _logger.LogInformation("Data should now be visible in dashboard at /device/{DeviceSerial}", deviceSerial);
                        _logger.LogInformation("API Response: {Response}", responseContent);
                        return true;
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        _logger.LogWarning("API endpoint /api/events not found (404). Endpoint may not be deployed yet.");
                        _logger.LogInformation("DATA READY FOR TRANSMISSION - Unified payload would have been sent:");
                        _logger.LogInformation("Payload size: {PayloadSize} bytes", jsonContent.Length);
                        _logger.LogInformation("Device: {Device}", deviceSerial);
                        _logger.LogInformation("Modules: [{Modules}]", string.Join(", ", payload.Metadata.EnabledModules));
                        return true; // Consider this success for development
                    }
                    else
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        _logger.LogWarning("API Request Failed - Status: {StatusCode}, Error: {ErrorContent}", 
                            response.StatusCode, errorContent);
                        
                        if (attempt == maxRetries)
                        {
                            return false;
                        }
                    }
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogWarning("HTTP Request Exception on attempt {Attempt}: {Exception}", attempt, ex.Message);
                    if (attempt == maxRetries)
                    {
                        return false;
                    }
                }
                catch (TaskCanceledException ex) when (ex.CancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning("Request timeout on attempt {Attempt}", attempt);
                    if (attempt == maxRetries)
                    {
                        return false;
                    }
                }

                // Wait before retrying
                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1));
                    _logger.LogDebug("Waiting {Delay} seconds before retry", delay.TotalSeconds);
                    await Task.Delay(delay);
                }
            }

            _logger.LogError("=== UNIFIED PAYLOAD TRANSMISSION FAILED ===");
            _logger.LogError("Failed to send unified payload after {MaxRetries} attempts", maxRetries);
            _logger.LogError("Device Serial: {DeviceSerial}", deviceSerial);
            _logger.LogError("Device UUID: {DeviceId}", deviceId);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending unified payload to API");
            return false;
        }
    }

    public async Task<bool> TestConnectivityAsync()
    {
        try
        {
            _logger.LogInformation("Testing API connectivity");

            // Use the health endpoint for connectivity testing
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/health");
            var response = await _httpClient.SendAsync(request);
            
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("API connectivity test successful");
                return true;
            }
            else
            {
                _logger.LogWarning("API connectivity test failed with status: {StatusCode}", response.StatusCode);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "API connectivity test failed");
            return false;
        }
    }

    public async Task<bool> RegisterDeviceAsync(DeviceInfo deviceInfo)
    {
        try
        {
            _logger.LogInformation("=== DEVICE REGISTRATION STARTING ===");
            _logger.LogInformation("Registering device: {DeviceId} ({Name})", deviceInfo.DeviceId, deviceInfo.ComputerName);
            _logger.LogInformation("This will create a 'New Client' event in ReportMate");

            // Create a device registration payload (simple format)
            var registrationPayload = new Dictionary<string, object>
            {
                { "device", deviceInfo.DeviceId }, // Use DeviceId as the primary identifier - API expects "device" field (lowercase)
                { "deviceId", deviceInfo.DeviceId }, // Also include deviceId for API compatibility
                { "serialNumber", deviceInfo.SerialNumber }, // Also include serial number
                { "computerName", deviceInfo.ComputerName },
                { "model", deviceInfo.Model },
                { "os", deviceInfo.OperatingSystem },
                { "manufacturer", deviceInfo.Manufacturer },
                { "domain", deviceInfo.Domain },
                { "platform", "windows" }
            };

            // Add passphrase to payload if configured
            var passphrase = _configuration["ReportMate:Passphrase"];
            if (!string.IsNullOrEmpty(passphrase))
            {
                registrationPayload["passphrase"] = passphrase;
                _logger.LogInformation("Client passphrase included in registration payload");
            }
            else
            {
                _logger.LogInformation(" No client passphrase configured - registration may be rejected if authentication is required");
            }

            _logger.LogInformation("Registration payload created:");
            _logger.LogInformation("  Device ID: {DeviceId}", deviceInfo.DeviceId);
            _logger.LogInformation("  Computer Name: {ComputerName}", deviceInfo.ComputerName);
            _logger.LogInformation("  Manufacturer: {Manufacturer}", deviceInfo.Manufacturer);
            _logger.LogInformation("  Model: {Model}", deviceInfo.Model);
            _logger.LogInformation("  OS: {OperatingSystem}", deviceInfo.OperatingSystem);

            var jsonContent = JsonSerializer.Serialize(registrationPayload, ReportMateJsonContext.Default.DictionaryStringObject);
            var httpContent = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

            _logger.LogInformation("Sending registration request to /api/device...");
            var response = await _httpClient.PostAsync("/api/device", httpContent);

            _logger.LogInformation("Registration response: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Device {DeviceId} registered successfully", deviceInfo.DeviceId);
                _logger.LogInformation("New Client event should be visible in dashboard at /device/{DeviceId}", deviceInfo.DeviceId);
                _logger.LogInformation("Response: {Response}", responseContent);
                return true;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Device registration failed with status {StatusCode}: {Error}", 
                    response.StatusCode, errorContent);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering device: {DeviceId}", deviceInfo.DeviceId);
            return false;
        }
    }

    public async Task<bool> IsDeviceRegisteredAsync(string deviceId)
    {
        try
        {
            _logger.LogInformation("=== DEVICE REGISTRATION CHECK ===");
            _logger.LogInformation("Checking if device is registered: {DeviceId}", deviceId);
            _logger.LogInformation("API endpoint: GET /api/device/{DeviceId}", deviceId);

            var response = await _httpClient.GetAsync($"/api/device/{deviceId}");
            _logger.LogInformation("Registration check response: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Device {DeviceId} is registered", deviceId);
                _logger.LogDebug("Device info: {DeviceInfo}", responseContent);
                return true;
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogInformation("Device {DeviceId} is not registered (404 Not Found)", deviceId);
                _logger.LogInformation("   Device needs to be registered before sending data");
                return false;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning(" Error checking device registration status {StatusCode}: {Error}", 
                    response.StatusCode, errorContent);
                _logger.LogWarning("   Assuming device is not registered due to API error");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking device registration: {DeviceId}", deviceId);
            _logger.LogError("   Assuming device is not registered due to exception");
            return false;
        }
    }

    private async Task CachePayloadAsync(string jsonContent, string deviceSerial, int attempt)
    {
        if (string.IsNullOrEmpty(_cacheDirectory))
        {
            return; // Logging disabled
        }

        try
        {
            // Create timestamped directory structure like cache (YYYY-MM-DD-HHmmss)
            var now = DateTime.UtcNow;
            var timestamp = now.ToString("yyyy-MM-dd-HHmmss");
            var logDir = Path.Combine(_cacheDirectory, timestamp);
            
            if (!Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }
            
            var filename = $"transmission_{deviceSerial}_attempt{attempt}.json";
            var filepath = Path.Combine(logDir, filename);
            
            await File.WriteAllTextAsync(filepath, jsonContent);
            _logger.LogDebug("Transmission payload logged to: {FilePath}", filepath);
            
            // Keep only the last 10 transmission logs to avoid disk space issues
            await CleanupOldCacheFilesAsync(deviceSerial);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to log transmission payload, continuing with transmission");
        }
    }

    private async Task CacheUnifiedPayloadAsync(string jsonContent, string deviceSerial, int attempt)
    {
        if (string.IsNullOrEmpty(_cacheDirectory))
        {
            return; // Logging disabled
        }

        try
        {
            // Create timestamped directory structure like cache (YYYY-MM-DD-HHmmss)
            var now = DateTime.UtcNow;
            var timestamp = now.ToString("yyyy-MM-dd-HHmmss");
            var logDir = Path.Combine(_cacheDirectory, timestamp);
            
            if (!Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }
            
            var filename = $"unified_payload_{deviceSerial}_attempt{attempt}.json";
            var filepath = Path.Combine(logDir, filename);
            
            await File.WriteAllTextAsync(filepath, jsonContent);
            _logger.LogDebug("Unified payload logged to: {FilePath}", filepath);
            
            // Keep only the last 10 transmission logs to avoid disk space issues
            await CleanupOldCacheFilesAsync(deviceSerial);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to log unified payload, continuing with transmission");
        }
    }

    private Task CleanupOldCacheFilesAsync(string deviceSerial)
    {
        try
        {
            if (string.IsNullOrEmpty(_cacheDirectory))
            {
                return Task.CompletedTask;
            }

            // Clean up old timestamped log directories (keep only last 10)
            var logDirs = Directory.GetDirectories(_cacheDirectory)
                .Where(d => Path.GetFileName(d).Length >= 19) // YYYY-MM-DD-HHmmss format
                .OrderByDescending(d => Path.GetFileName(d))
                .Skip(10)
                .ToArray();

            foreach (var dir in logDirs)
            {
                Directory.Delete(dir, true);
                _logger.LogDebug("Deleted old transmission log directory: {DirName}", Path.GetFileName(dir));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to cleanup old transmission log directories");
        }
        
        return Task.CompletedTask;
    }

    /// <summary>
    /// Clean up deprecated payload_ files from the old cache directory structure
    /// These files are being deprecated in favor of the new logs directory organization
    /// </summary>
    private void CleanupDeprecatedPayloadFiles()
    {
        try
        {
            var oldCacheDir = @"C:\ProgramData\ManagedReports\cache";
            if (!Directory.Exists(oldCacheDir))
                return;

            var payloadFiles = Directory.GetFiles(oldCacheDir, "payload_*.json");
            if (payloadFiles.Any())
            {
                _logger.LogInformation("Cleaning up {FileCount} deprecated payload_ files from cache directory", payloadFiles.Length);
                
                foreach (var file in payloadFiles)
                {
                    try
                    {
                        File.Delete(file);
                        _logger.LogDebug("Deleted deprecated payload file: {FileName}", Path.GetFileName(file));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete deprecated payload file: {FileName}", Path.GetFileName(file));
                    }
                }
                
                _logger.LogInformation("Deprecated payload_ files cleanup completed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to cleanup deprecated payload files");
        }
    }

    private void ConfigureHttpClient()
    {
        // Ensure base URL is set
        var apiUrl = _configuration["ReportMate:ApiUrl"];
        if (!string.IsNullOrEmpty(apiUrl) && _httpClient.BaseAddress == null)
        {
            _httpClient.BaseAddress = new Uri(apiUrl);
        }

        // Set user agent
        var userAgent = _configuration["ReportMate:UserAgent"] ?? "ReportMate/1.0";
        if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
        {
            _httpClient.DefaultRequestHeaders.Add("User-Agent", userAgent);
        }

        // Set API key if provided
        var apiKey = _configuration["ReportMate:ApiKey"];
        if (!string.IsNullOrEmpty(apiKey) && !_httpClient.DefaultRequestHeaders.Contains("X-API-Key"))
        {
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }

        // Set client passphrase if provided
        var passphrase = _configuration["ReportMate:Passphrase"];
        if (!string.IsNullOrEmpty(passphrase) && !_httpClient.DefaultRequestHeaders.Contains("X-Client-Passphrase"))
        {
            _httpClient.DefaultRequestHeaders.Add("X-Client-Passphrase", passphrase);
        }

        // Configure timeout
        var timeoutSeconds = int.TryParse(_configuration["ReportMate:ApiTimeoutSeconds"], out var timeout) ? timeout : 300;
        _httpClient.Timeout = TimeSpan.FromSeconds(timeoutSeconds);

        // Accept JSON
        if (!_httpClient.DefaultRequestHeaders.Contains("Accept"))
        {
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        _logger.LogDebug("HTTP client configured with BaseAddress: {BaseAddress}, timeout: {Timeout}s, User-Agent: {UserAgent}", 
            _httpClient.BaseAddress, timeoutSeconds, userAgent);
    }
    
    /// <summary>
    /// Send structured event from event.json to ReportMate events API
    /// </summary>
    private async Task SendStructuredEventAsync(string deviceSerial, DeviceDataRequest deviceData)
    {
        try
        {
            _logger.LogInformation("=== SENDING STRUCTURED EVENT ===");
            _logger.LogInformation("Loading event.json from cache for device: {DeviceSerial}", deviceSerial);
            
            // Load the most recent event.json from the cache
            var baseCacheDirectory = Path.Combine("C:", "ProgramData", "ManagedReports", "cache");
            if (!Directory.Exists(baseCacheDirectory))
            {
                _logger.LogWarning("Cache directory not found: {Directory}", baseCacheDirectory);
                return;
            }
            
            var cacheDirectories = Directory.GetDirectories(baseCacheDirectory)
                .Where(dir => DateTime.TryParseExact(Path.GetFileName(dir), "yyyy-MM-dd-HHmmss", null, System.Globalization.DateTimeStyles.None, out _))
                .OrderByDescending(dir => Path.GetFileName(dir))
                .ToArray();
            
            if (!cacheDirectories.Any())
            {
                _logger.LogWarning("No cache directories found in: {Directory}", baseCacheDirectory);
                return;
            }
            
            var latestCacheDirectory = cacheDirectories.First();
            var eventJsonPath = Path.Combine(latestCacheDirectory, "event.json");
            
            if (!File.Exists(eventJsonPath))
            {
                _logger.LogWarning("event.json not found at: {Path}", eventJsonPath);
                return;
            }
            
            _logger.LogInformation("Loading event.json from: {Path}", eventJsonPath);
            var eventJsonContent = await File.ReadAllTextAsync(eventJsonPath);
            var eventData = JsonSerializer.Deserialize<Dictionary<string, object>>(eventJsonContent, _jsonOptions);
            
            if (eventData == null)
            {
                _logger.LogWarning("Failed to parse event.json content");
                return;
            }
            
            // Create structured event for the API
            var eventRequest = new StructuredEventRequest
            {
                Device = deviceSerial,
                Kind = "System",
                Ts = DateTime.UtcNow.ToString("O"),
                Payload = eventData
            };
            
            var eventJsonPayload = JsonSerializer.Serialize(eventRequest, _jsonOptions);
            var eventHttpContent = new StringContent(eventJsonPayload, System.Text.Encoding.UTF8, "application/json");
            
            _logger.LogInformation("Sending structured event to /api/events...");
            _logger.LogInformation("Event payload size: {Size} KB", Math.Round(eventJsonPayload.Length / 1024.0, 2));
            
            var eventResponse = await _httpClient.PostAsync("/api/events", eventHttpContent);
            
            if (eventResponse.IsSuccessStatusCode)
            {
                _logger.LogInformation("✅ SUCCESS: Structured event sent to ReportMate API");
                var eventResponseContent = await eventResponse.Content.ReadAsStringAsync();
                _logger.LogInformation("Event API Response: {Response}", eventResponseContent);
            }
            else
            {
                _logger.LogWarning("⚠️ Failed to send structured event: {StatusCode} {ReasonPhrase}", 
                    eventResponse.StatusCode, eventResponse.ReasonPhrase);
                var errorContent = await eventResponse.Content.ReadAsStringAsync();
                _logger.LogWarning("Error response: {ErrorContent}", errorContent);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("❌ Error sending structured event: {Message}", ex.Message);
            _logger.LogError("Exception details: {Exception}", ex);
        }
    }
}

/// <summary>
/// Generic API response wrapper
/// </summary>
public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Error { get; set; }
}
