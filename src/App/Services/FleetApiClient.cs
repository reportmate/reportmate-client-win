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

    /// <summary>
    /// One fleet report: /api/v1/&lt;module&gt; returns a row per device. The row shape
    /// differs per module and changes as modules gain fields, so reports read it as
    /// JSON and address values by path rather than through nine sets of models that
    /// would silently drop anything new.
    /// </summary>
    public Task<FleetResult<List<JsonElement>>> GetModuleAsync(string module, int? limit = null, CancellationToken ct = default) =>
        GetAsync<List<JsonElement>>(limit is null ? $"/api/v1/{module}" : $"/api/v1/{module}?limit={limit}", ct);

    private async Task<FleetResult<T>> GetAsync<T>(string path, CancellationToken ct) where T : class
    {
        var config = ConfigManager.Instance.Config;
        if (string.IsNullOrWhiteSpace(config.ApiUrl))
            return new FleetResult<T>(FleetStatus.NotConfigured, null, "No API URL is configured for this device.");

        var url = config.ApiUrl.TrimEnd('/') + path;
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        // The endpoint's own ApiKey is an ingest credential and the fleet endpoints
        // reject it, so the shared passphrase is what actually reads today. A
        // read-scoped key set explicitly wins over it when one is provisioned.
        if (!string.IsNullOrWhiteSpace(config.ReadApiKey))
            request.Headers.TryAddWithoutValidation("X-API-Key", config.ReadApiKey);
        else if (!string.IsNullOrWhiteSpace(config.Passphrase))
            request.Headers.TryAddWithoutValidation("X-Client-Passphrase", config.Passphrase);
        else if (!string.IsNullOrWhiteSpace(config.ApiKey))
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
    public string Id { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Platform { get; set; }
    public string? OsName { get; set; }
    public string? OsVersion { get; set; }

    /// <summary>The API's own liveness verdict: online, idle or offline.</summary>
    public string? Status { get; set; }

    public bool Archived { get; set; }
    public DateTime? LastSeen { get; set; }
    public DateTime? CreatedAt { get; set; }

    /// <summary>Per-module summaries the list view shows without a second call.</summary>
    public DeviceModuleSummaries? Modules { get; set; }

    public string? Location => Modules?.Inventory?.Location;
    public string? Usage => Modules?.Inventory?.Usage;
    public string? Catalog => Modules?.Inventory?.Catalog;
    public string? Department => Modules?.Inventory?.Department;
}

public sealed class DeviceModuleSummaries
{
    public InventorySummary? Inventory { get; set; }
    public SystemSummary? System { get; set; }
}

public sealed class InventorySummary
{
    public string? DeviceName { get; set; }
    public string? Catalog { get; set; }
    public string? Usage { get; set; }
    public string? Department { get; set; }
    public string? Location { get; set; }
    public string? Area { get; set; }
    public string? Fleet { get; set; }
}

public sealed class SystemSummary
{
    public OperatingSystemSummary? OperatingSystem { get; set; }
}

public sealed class OperatingSystemSummary
{
    public string? Name { get; set; }
    public string? Version { get; set; }
    public string? DisplayVersion { get; set; }
    public string? Build { get; set; }
}

public sealed class FleetEvent
{
    public string? Id { get; set; }
    public string? Device { get; set; }
    public string? DeviceName { get; set; }
    public string? SerialNumber { get; set; }
    public string? AssetTag { get; set; }
    public string? Kind { get; set; }
    public string? EventType { get; set; }
    public string? Message { get; set; }
    public string? Platform { get; set; }

    /// <summary>The API sends both; ts is the one always populated.</summary>
    public DateTime? Ts { get; set; }
    public DateTime? Timestamp { get; set; }

    public DateTime? When => Ts ?? Timestamp;
}

/// <summary>
/// Fleet-wide install counters, split by platform exactly as the API reports them
/// so the dashboard can honour the platform filter without recomputing anything.
/// </summary>
public sealed class InstallStats
{
    public int DevicesWithErrors { get; set; }
    public int DevicesWithWarnings { get; set; }
    public int WinDevicesWithErrors { get; set; }
    public int WinDevicesWithWarnings { get; set; }
    public int MacDevicesWithErrors { get; set; }
    public int MacDevicesWithWarnings { get; set; }
    public int TotalErrorItems { get; set; }
    public int TotalWarningItems { get; set; }
    public int WinErrorItems { get; set; }
    public int WinWarningItems { get; set; }
    public int MacErrorItems { get; set; }
    public int MacWarningItems { get; set; }
    public bool HasInstallData { get; set; }
}

public sealed class DashboardPayload
{
    public List<FleetDevice> Devices { get; set; } = new();
    public List<FleetEvent> Events { get; set; } = new();
    public InstallStats? InstallStats { get; set; }
    public long TotalDevices { get; set; }
    public long TotalEvents { get; set; }
    public DateTime? LastUpdated { get; set; }
}

public sealed class DevicesPayload
{
    public List<FleetDevice> Devices { get; set; } = new();
    public long TotalDevices { get; set; }
}

public sealed class EventsPayload
{
    public List<FleetEvent> Events { get; set; } = new();
    public long TotalEvents { get; set; }
}
