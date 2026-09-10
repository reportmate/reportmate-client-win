using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ReportMate.App.Services;

/// <summary>
/// Reads fleet-wide data from the ReportMate API for the Dashboard, Devices,
/// Events and Reports pages. The per-device page does not use this: it renders
/// the local cache, which is always available and never needs the network.
/// </summary>
public sealed class FleetApiClient
{
    public static FleetApiClient Instance { get; } = new();

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(45) };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Why a fleet read could not be served, in terms the page can show.</summary>
    public enum FleetStatus
    {
        Ok,
        NotConfigured,
        Unauthorized,
        Forbidden,
        Unreachable,
        Malformed,
    }

    public sealed record FleetResult<T>(FleetStatus Status, T? Data, string? Detail)
    {
        public bool Ok => Status == FleetStatus.Ok && Data is not null;
    }

    /// <summary>
    /// The consolidated dashboard payload: the same shape the web app's dashboard
    /// reads, so one call backs every widget on the Dashboard page.
    /// </summary>
    public Task<FleetResult<DashboardPayload>> GetDashboardAsync(CancellationToken ct = default) =>
        GetAsync<DashboardPayload>("/api/v1/dashboard", ct);

    public Task<FleetResult<DevicesPayload>> GetDevicesAsync(CancellationToken ct = default) =>
        GetAsync<DevicesPayload>("/api/v1/devices", ct);

    public Task<FleetResult<EventsPayload>> GetEventsAsync(int limit = 250, CancellationToken ct = default) =>
        GetAsync<EventsPayload>($"/api/v1/events?limit={limit}", ct);

    private async Task<FleetResult<T>> GetAsync<T>(string path, CancellationToken ct) where T : class
    {
        var config = ConfigManager.Instance.Config;
        if (string.IsNullOrWhiteSpace(config.ApiUrl))
            return new FleetResult<T>(FleetStatus.NotConfigured, null, "No API URL is configured for this device.");

        var url = config.ApiUrl.TrimEnd('/') + path;
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrWhiteSpace(config.ApiKey))
            request.Headers.TryAddWithoutValidation("X-API-Key", config.ApiKey);

        try
        {
            using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new FleetResult<T>(FleetStatus.Unauthorized, null, "The API rejected this device's credentials.");
            if (response.StatusCode == HttpStatusCode.Forbidden)
                return new FleetResult<T>(FleetStatus.Forbidden, null,
                    "This device's API key is an ingest key and is not allowed to read fleet data.");
            if (!response.IsSuccessStatusCode)
                return new FleetResult<T>(FleetStatus.Unreachable, null, $"The API returned {(int)response.StatusCode}.");

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var data = await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, ct);
            return data is null
                ? new FleetResult<T>(FleetStatus.Malformed, null, "The API returned an empty response.")
                : new FleetResult<T>(FleetStatus.Ok, data, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new FleetResult<T>(FleetStatus.Unreachable, null, "The API did not respond in time.");
        }
        catch (HttpRequestException ex)
        {
            return new FleetResult<T>(FleetStatus.Unreachable, null, ex.Message);
        }
        catch (JsonException ex)
        {
            return new FleetResult<T>(FleetStatus.Malformed, null, ex.Message);
        }
    }
}

/// <summary>One device as the fleet list and dashboard widgets see it.</summary>
public sealed class FleetDevice
{
    public string DeviceId { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string Name { get; set; } = "";
    public string? AssetTag { get; set; }
    public string? Status { get; set; }
    public string? Platform { get; set; }
    public string? OsName { get; set; }
    public string? OsVersion { get; set; }
    public string? Model { get; set; }
    public string? Manufacturer { get; set; }
    public string? IpAddress { get; set; }
    public string? Location { get; set; }
    public string? Usage { get; set; }
    public string? Catalog { get; set; }
    public DateTime? LastSeen { get; set; }
    public DateTime? CreatedAt { get; set; }
}

public sealed class FleetEvent
{
    public string? Id { get; set; }
    public string? Device { get; set; }
    public string? DeviceName { get; set; }
    public string? SerialNumber { get; set; }
    public string? Kind { get; set; }
    public string? EventType { get; set; }
    public string? Message { get; set; }
    public string? Platform { get; set; }
    public DateTime? Timestamp { get; set; }
}

/// <summary>Fleet-wide install counters the dashboard's error and warning cards show.</summary>
public sealed class InstallStats
{
    public int TotalDevices { get; set; }
    public int DevicesWithErrors { get; set; }
    public int DevicesWithWarnings { get; set; }
    public int TotalErrors { get; set; }
    public int TotalWarnings { get; set; }
}

public sealed class DashboardPayload
{
    public List<FleetDevice> Devices { get; set; } = new();
    public List<FleetEvent> Events { get; set; } = new();
    public InstallStats? InstallStats { get; set; }
}

public sealed class DevicesPayload
{
    public List<FleetDevice> Devices { get; set; } = new();
}

public sealed class EventsPayload
{
    public List<FleetEvent> Events { get; set; } = new();
}
