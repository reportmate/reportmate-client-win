using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Services;

/// <summary>
/// Everything the device page renders, assembled from the runner's local cache.
/// Each module is the newest copy found across recent cache runs, so a partial
/// run (one or two modules) does not blank the rest of the report.
/// </summary>
public sealed class DeviceSnapshot
{
    public EventMetadata? Metadata { get; init; }
    public List<ReportMateEvent> Events { get; init; } = [];

    public InventoryData? Inventory { get; init; }
    public SystemData? System { get; init; }
    public HardwareData? Hardware { get; init; }
    public ManagementData? Management { get; init; }
    public InstallsData? Installs { get; init; }
    public SecurityData? Security { get; init; }
    public IdentityData? Identity { get; init; }
    public NetworkData? Network { get; init; }
    public PeripheralsModuleData? Peripherals { get; init; }
    public ApplicationsData? Applications { get; init; }

    /// <summary>When each module file was written, keyed by module id.</summary>
    public Dictionary<string, DateTime> ModuleCollectedAt { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Directory the newest run wrote to, or null when nothing has ever run.</summary>
    public string? NewestRunDirectory { get; init; }

    /// <summary>Most recent module write across the snapshot: the local "last seen".</summary>
    public DateTime? CollectedAt => ModuleCollectedAt.Count == 0 ? null : ModuleCollectedAt.Values.Max();

    public bool IsEmpty => Inventory is null && System is null && Hardware is null && Management is null
        && Installs is null && Security is null && Identity is null && Network is null
        && Peripherals is null && Applications is null;

    public bool HasModule(string moduleId) => ModuleCollectedAt.ContainsKey(moduleId);

    /// <summary>Modules whose JSON was on disk but unreadable, keyed by module id.</summary>
    public IReadOnlyDictionary<string, string> ModuleErrors { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The parse error for a module, or null when it simply was not collected.</summary>
    public string? ModuleError(string moduleId) =>
        ModuleErrors.TryGetValue(moduleId, out var e) ? e : null;

    // ── Identity helpers used by the header and every tab ────────────

    public string SerialNumber =>
        FirstNonEmpty(Inventory?.SerialNumber, Metadata?.SerialNumber) ?? "";

    public string DeviceName =>
        FirstNonEmpty(Inventory?.DeviceName, Management?.DeviceState?.DeviceName, Network?.Hostname,
                      Environment.MachineName) ?? "Unknown Device";

    public string AssetTag => Inventory?.AssetTag ?? "";

    public string DeviceId => FirstNonEmpty(Inventory?.UUID, Metadata?.DeviceId) ?? "";

    public string ClientVersion => Metadata?.ClientVersion ?? "";

    public static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}
