#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for communicating with the ReportMate API
/// Handles authentication, retries, and secure data transmission
/// </summary>
public interface IApiService
{
    Task<bool> SendDeviceDataAsync(Dictionary<string, object> deviceData);
    Task<bool> TestConnectivityAsync();
    Task<ApiResponse<T>> GetAsync<T>(string endpoint);
    Task<ApiResponse<T>> PostAsync<T>(string endpoint, object data);
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
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        ConfigureHttpClient();
    }

    public async Task<bool> SendDeviceDataAsync(Dictionary<string, object> deviceData)
    {
        try
        {
            _logger.LogInformation("Sending device data to ReportMate API");

            // Add metadata
            var payload = new
            {
                device = deviceData.GetValueOrDefault("device"),
                kind = "device_data",
                timestamp = DateTime.UtcNow.ToString("O"),
                payload = new
                {
                    system = deviceData.GetValueOrDefault("system"),
                    security = deviceData.GetValueOrDefault("security"),
                    osquery = deviceData.GetValueOrDefault("osquery"),
                    collection_timestamp = deviceData.GetValueOrDefault("collection_timestamp"),
                    client_version = deviceData.GetValueOrDefault("client_version"),
                    collection_type = deviceData.GetValueOrDefault("collection_type", "comprehensive")
                }
            };

            var maxRetries = _configuration.GetValue<int>("ReportMate:MaxRetryAttempts", 3);
            var retryDelay = TimeSpan.FromSeconds(1);

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    _logger.LogDebug("Sending data to API (attempt {Attempt}/{MaxRetries})", attempt, maxRetries);

                    var response = await _httpClient.PostAsJsonAsync("/api/ingest", payload, _jsonOptions);

                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogInformation("Successfully sent device data to API");
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

            // Try to get a simple endpoint or negotiate connection
            var response = await _httpClient.GetAsync("/api/negotiate?device=connectivity-test");
            
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

    public async Task<ApiResponse<T>> GetAsync<T>(string endpoint)
    {
        try
        {
            _logger.LogDebug("GET request to: {Endpoint}", endpoint);

            var response = await _httpClient.GetAsync(endpoint);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var data = JsonSerializer.Deserialize<T>(content, _jsonOptions);
                return new ApiResponse<T> { Success = true, Data = data };
            }
            else
            {
                _logger.LogWarning("GET request failed: {StatusCode} - {Content}", response.StatusCode, content);
                return new ApiResponse<T> 
                { 
                    Success = false, 
                    Error = $"HTTP {response.StatusCode}: {content}" 
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in GET request to {Endpoint}", endpoint);
            return new ApiResponse<T> 
            { 
                Success = false, 
                Error = ex.Message 
            };
        }
    }

    public async Task<ApiResponse<T>> PostAsync<T>(string endpoint, object data)
    {
        try
        {
            _logger.LogDebug("POST request to: {Endpoint}", endpoint);

            var response = await _httpClient.PostAsJsonAsync(endpoint, data, _jsonOptions);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var responseData = JsonSerializer.Deserialize<T>(content, _jsonOptions);
                return new ApiResponse<T> { Success = true, Data = responseData };
            }
            else
            {
                _logger.LogWarning("POST request failed: {StatusCode} - {Content}", response.StatusCode, content);
                return new ApiResponse<T> 
                { 
                    Success = false, 
                    Error = $"HTTP {response.StatusCode}: {content}" 
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in POST request to {Endpoint}", endpoint);
            return new ApiResponse<T> 
            { 
                Success = false, 
                Error = ex.Message 
            };
        }
    }

    private void ConfigureHttpClient()
    {
        // Set user agent
        var userAgent = _configuration["ReportMate:UserAgent"] ?? "ReportMate/1.0";
        _httpClient.DefaultRequestHeaders.Add("User-Agent", userAgent);

        // Set API key if provided
        var apiKey = _configuration["ReportMate:ApiKey"];
        if (!string.IsNullOrEmpty(apiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }

        // Set client passphrase if provided
        var passphrase = _configuration["ReportMate:Passphrase"];
        if (!string.IsNullOrEmpty(passphrase))
        {
            _httpClient.DefaultRequestHeaders.Add("X-Client-Passphrase", passphrase);
        }

        // Configure timeout
        var timeoutSeconds = _configuration.GetValue<int>("ReportMate:ApiTimeoutSeconds", 300);
        _httpClient.Timeout = TimeSpan.FromSeconds(timeoutSeconds);

        // Accept JSON
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");

        _logger.LogDebug("HTTP client configured with timeout: {Timeout}s, User-Agent: {UserAgent}", 
            timeoutSeconds, userAgent);
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
