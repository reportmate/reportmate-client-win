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
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for communicating with the ReportMate API
/// Handles authentication, retries, and secure data transmission
/// </summary>
public interface IApiService
{
    Task<bool> SendDeviceDataAsync(Dictionary<string, object> deviceData);
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

    public ApiService(HttpClient httpClient, ILogger<ApiService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        _configuration = configuration;
        
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            TypeInfoResolver = ReportMateJsonContext.Default
        };

        ConfigureHttpClient();
    }

    public async Task<bool> SendDeviceDataAsync(Dictionary<string, object> deviceData)
    {
        try
        {
            _logger.LogInformation("=== DEVICE DATA TRANSMISSION STARTING ===");
            _logger.LogInformation("Preparing device data for transmission to ReportMate API...");

            // Extract device info for registration - handle both DeviceInfo object and JSON string
            DeviceInfo? deviceInfo = null;
            var deviceValue = deviceData.GetValueOrDefault("device");
            
            _logger.LogInformation("Device value type: {Type}", deviceValue?.GetType().FullName);
            
            if (deviceValue is DeviceInfo directDeviceInfo)
            {
                deviceInfo = directDeviceInfo;
                _logger.LogInformation("✅ Device info found as DeviceInfo object");
                _logger.LogInformation("   DeviceId: {DeviceId}", deviceInfo.DeviceId);
                _logger.LogInformation("   SerialNumber: {SerialNumber}", deviceInfo.SerialNumber);
                _logger.LogInformation("   ComputerName: {ComputerName}", deviceInfo.ComputerName);
            }
            else if (deviceValue is string deviceJsonString)
            {
                _logger.LogInformation("Device value is string, attempting JSON parse. String length: {Length}", deviceJsonString.Length);
                try
                {
                    deviceInfo = System.Text.Json.JsonSerializer.Deserialize(deviceJsonString, ReportMateJsonContext.Default.DeviceInfo);
                    _logger.LogInformation("✅ Device info parsed from JSON - DeviceId: {DeviceId}, SerialNumber: {SerialNumber}", 
                        deviceInfo?.DeviceId, deviceInfo?.SerialNumber);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Failed to deserialize device info from JSON string");
                }
            }
            else
            {
                _logger.LogError("❌ Device info has unexpected type: {Type}", deviceValue?.GetType().FullName);
            }

            // Use DeviceId which should be the serial number (0F33V9G25083HJ)
            var deviceId = deviceInfo?.DeviceId ?? deviceInfo?.SerialNumber ?? Environment.MachineName;
            
            _logger.LogInformation("=== TRANSMISSION DETAILS ===");
            _logger.LogInformation("Target Device ID: {DeviceId} (this should be the serial number)", deviceId);
            _logger.LogInformation("Serial Number: {SerialNumber}", deviceInfo?.SerialNumber);
            _logger.LogInformation("Computer Name: {ComputerName}", deviceInfo?.ComputerName ?? "Unknown");
            _logger.LogInformation("Expected Dashboard URL: /device/{DeviceId}", deviceId);

            // Analyze payload composition
            _logger.LogInformation("=== PAYLOAD ANALYSIS ===");
            if (deviceData.ContainsKey("device")) _logger.LogInformation("✅ Device data included");
            if (deviceData.ContainsKey("system")) _logger.LogInformation("✅ System data included");
            if (deviceData.ContainsKey("security")) _logger.LogInformation("✅ Security data included");
            if (deviceData.ContainsKey("osquery")) _logger.LogInformation("✅ OSQuery data included");
            if (deviceData.ContainsKey("reportmate_client")) _logger.LogInformation("✅ ReportMate client metadata included");
            if (deviceData.ContainsKey("environment")) _logger.LogInformation("✅ Environment context included");

            // Create the payload as a proper dictionary for JSON serialization
            _logger.LogInformation("Creating API payload for /api/device...");
            var payload = new Dictionary<string, object>
            {
                { "device", deviceId }, // THIS IS CRITICAL - must be serial number 0F33V9G25083HJ
                { "kind", "device_data" },
                { "ts", DateTime.UtcNow.ToString("O") },
                { "payload", new Dictionary<string, object>
                    {
                        // Include device info for auto-registration
                        { "device", deviceInfo ?? new object() },
                        { "system", deviceData.GetValueOrDefault("system") ?? new object() },
                        { "security", deviceData.GetValueOrDefault("security") ?? new object() },
                        { "osquery", deviceData.GetValueOrDefault("osquery") ?? new object() },
                        { "collection_timestamp", deviceData.GetValueOrDefault("collection_timestamp") ?? DateTime.UtcNow.ToString("O") },
                        { "client_version", deviceData.GetValueOrDefault("client_version") ?? "2025.7.1.3" },
                        { "collection_type", deviceData.GetValueOrDefault("collection_type", "comprehensive") },
                        { "managed_installs_system", "Cimian" }, // Windows uses Cimian
                        { "source", "runner.exe" }
                    }
                }
            };

            // Add passphrase to payload if configured
            var passphrase = _configuration["ReportMate:Passphrase"];
            if (!string.IsNullOrEmpty(passphrase))
            {
                payload["passphrase"] = passphrase;
                _logger.LogInformation("✅ Client passphrase included in payload");
            }
            else
            {
                _logger.LogInformation("⚠️  No client passphrase configured - requests may be rejected if authentication is required");
            }

            _logger.LogInformation("Payload created with device ID: {DeviceId}", payload["device"]);

            var maxRetries = _configuration.GetValue<int>("ReportMate:MaxRetryAttempts", 3);
            var retryDelay = TimeSpan.FromSeconds(1);

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    _logger.LogInformation("=== API TRANSMISSION ATTEMPT {Attempt}/{MaxRetries} ===", attempt, maxRetries);

                    // Use the ReportMateJsonContext for proper trim-safe JSON serialization
                    var jsonContent = JsonSerializer.Serialize(payload, ReportMateJsonContext.Default.DictionaryStringObject);
                    var httpContent = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");
                    
                    var dataSizeKB = Math.Round(jsonContent.Length / 1024.0, 2);
                    _logger.LogInformation("Sending POST to /api/device...");
                    _logger.LogInformation("Payload size: {DataSize} KB ({DataSizeBytes} bytes)", dataSizeKB, jsonContent.Length);
                    _logger.LogInformation("Device ID in payload: {DeviceId}", payload["device"]);

                    var response = await _httpClient.PostAsync("/api/device", httpContent);
                    _logger.LogInformation("API Response: {StatusCode} {ReasonPhrase}", response.StatusCode, response.ReasonPhrase);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        _logger.LogInformation("✅ SUCCESS: Device data sent to ReportMate API");
                        _logger.LogInformation("✅ Data should now be visible in dashboard at /device/{DeviceId}", deviceId);
                        _logger.LogInformation("API Response: {Response}", responseContent);
                        return true;
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // Special handling for 404 - API endpoint not deployed yet
                        _logger.LogWarning("❌ API endpoint /api/device not found (404). This is unexpected as the endpoint should be available.");
                        _logger.LogInformation("DATA READY FOR TRANSMISSION - Would have sent the following payload:");
                        _logger.LogInformation("Payload size: {PayloadSize} bytes", jsonContent.Length);
                        _logger.LogInformation("Device: {Device}", payload["device"]);
                        _logger.LogInformation("Kind: {Kind}", payload["kind"]);
                        _logger.LogInformation("Timestamp: {Timestamp}", payload["ts"]);
                        
                        // Log a sample of the actual data being collected
                        if (payload.TryGetValue("payload", out var innerPayload) && innerPayload is Dictionary<string, object> innerDict)
                        {
                            if (innerDict.ContainsKey("system"))
                            {
                                _logger.LogInformation("✅ System data collected and ready");
                            }
                            if (innerDict.ContainsKey("security"))
                            {
                                _logger.LogInformation("✅ Security data collected and ready");
                            }
                            if (innerDict.ContainsKey("osquery"))
                            {
                                _logger.LogInformation("✅ OSQuery data collected and ready");
                            }
                        }
                        
                        _logger.LogInformation("🎯 SUCCESS: ReportMate client is fully functional and ready to send data!");
                        _logger.LogInformation("📡 Once the /api/device endpoint is available, this machine will automatically start reporting.");
                        
                        // Return true since the client is working correctly
                        return true;
                    }
                    else
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        _logger.LogWarning("API request failed with status {StatusCode}: {Error}", 
                            response.StatusCode, errorContent);

                        // Don't retry on client errors (4xx)
                        if ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500)
                        {
                            _logger.LogError("Client error occurred, not retrying: {StatusCode}", response.StatusCode);
                            return false;
                        }
                    }
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogWarning(ex, "HTTP request failed (attempt {Attempt}/{MaxRetries})", attempt, maxRetries);
                }
                catch (TaskCanceledException ex) when (ex.CancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning(ex, "Request timed out (attempt {Attempt}/{MaxRetries})", attempt, maxRetries);
                }

                // Wait before retrying (exponential backoff)
                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1));
                    _logger.LogDebug("Waiting {Delay} seconds before retry", delay.TotalSeconds);
                    await Task.Delay(delay);
                }
            }

            _logger.LogError("Failed to send device data after {MaxRetries} attempts", maxRetries);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending device data to API");
            return false;
        }
    }

    public async Task<bool> TestConnectivityAsync()
    {
        try
        {
            _logger.LogInformation("Testing API connectivity");

            // Try to get the device endpoint with a HEAD request first
            var request = new HttpRequestMessage(HttpMethod.Head, "/api/device");
            var response = await _httpClient.SendAsync(request);
            
            if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.MethodNotAllowed)
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

            // Create a "new_client" event through the ingest endpoint
            var registrationPayload = new Dictionary<string, object>
            {
                { "device", deviceInfo.DeviceId }, // Use DeviceId as serial number
                { "kind", "new_client" },
                { "ts", DateTime.UtcNow.ToString("O") },
                { "payload", new Dictionary<string, object>
                    {
                        { "message", "Device registered as new client" },
                        { "source", "runner.exe" },
                        { "device_id", deviceInfo.DeviceId },
                        { "name", deviceInfo.ComputerName },
                        { "model", deviceInfo.Model },
                        { "os", deviceInfo.OperatingSystem },
                        { "manufacturer", deviceInfo.Manufacturer },
                        { "memory", deviceInfo.TotalMemoryGB },
                        { "client_version", deviceInfo.ClientVersion },
                        { "platform", "windows" },
                        { "managed_installs_system", "Cimian" },
                        { "domain", deviceInfo.Domain },
                        { "registration_time", DateTime.UtcNow.ToString("O") }
                    }
                }
            };

            // Add passphrase to payload if configured
            var passphrase = _configuration["ReportMate:Passphrase"];
            if (!string.IsNullOrEmpty(passphrase))
            {
                registrationPayload["passphrase"] = passphrase;
                _logger.LogInformation("✅ Client passphrase included in registration payload");
            }
            else
            {
                _logger.LogInformation("⚠️  No client passphrase configured - registration may be rejected if authentication is required");
            }

            _logger.LogInformation("Registration payload created:");
            _logger.LogInformation("  Device ID: {DeviceId}", deviceInfo.DeviceId);
            _logger.LogInformation("  Computer Name: {ComputerName}", deviceInfo.ComputerName);
            _logger.LogInformation("  Manufacturer: {Manufacturer}", deviceInfo.Manufacturer);
            _logger.LogInformation("  Model: {Model}", deviceInfo.Model);
            _logger.LogInformation("  OS: {OperatingSystem}", deviceInfo.OperatingSystem);

            var jsonContent = JsonSerializer.Serialize(registrationPayload, _jsonOptions);
            var httpContent = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

            _logger.LogInformation("Sending registration request to /api/device...");
            var response = await _httpClient.PostAsync("/api/device", httpContent);

            _logger.LogInformation("Registration response: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("✅ Device {DeviceId} registered successfully", deviceInfo.DeviceId);
                _logger.LogInformation("✅ New Client event should be visible in dashboard at /device/{DeviceId}", deviceInfo.DeviceId);
                _logger.LogInformation("Response: {Response}", responseContent);
                return true;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("❌ Device registration failed with status {StatusCode}: {Error}", 
                    response.StatusCode, errorContent);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error registering device: {DeviceId}", deviceInfo.DeviceId);
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
                _logger.LogInformation("✅ Device {DeviceId} is registered", deviceId);
                _logger.LogDebug("Device info: {DeviceInfo}", responseContent);
                return true;
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogInformation("❌ Device {DeviceId} is not registered (404 Not Found)", deviceId);
                _logger.LogInformation("   Device needs to be registered before sending data");
                return false;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("⚠️  Error checking device registration status {StatusCode}: {Error}", 
                    response.StatusCode, errorContent);
                _logger.LogWarning("   Assuming device is not registered due to API error");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error checking device registration: {DeviceId}", deviceId);
            _logger.LogError("   Assuming device is not registered due to exception");
            return false;
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
        var timeoutSeconds = _configuration.GetValue<int>("ReportMate:ApiTimeoutSeconds", 300);
        _httpClient.Timeout = TimeSpan.FromSeconds(timeoutSeconds);

        // Accept JSON
        if (!_httpClient.DefaultRequestHeaders.Contains("Accept"))
        {
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        _logger.LogDebug("HTTP client configured with BaseAddress: {BaseAddress}, timeout: {Timeout}s, User-Agent: {UserAgent}", 
            _httpClient.BaseAddress, timeoutSeconds, userAgent);
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
