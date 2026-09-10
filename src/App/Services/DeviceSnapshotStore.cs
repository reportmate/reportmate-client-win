using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Services;

/// <summary>
/// Reads the runner's cache (<c>ProgramData\ManagedReports\cache\yyyy-MM-dd-HHmmss\</c>)
/// into a <see cref="DeviceSnapshot"/>. Runs are scanned newest first and the first
/// copy of each module wins, so the report is always the freshest data per module.
/// </summary>
public sealed class DeviceSnapshotStore
{
    public static DeviceSnapshotStore Instance { get; } = new();

    /// <summary>
    /// How many cache runs back to gather events from. Only bounds the event history --
    /// modules are searched across every run, because a module on a slow schedule
    /// (hardware's daily deep scan) can easily be further back than this.
    /// </summary>
    private const int EventRunsToScan = 12;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public string CacheRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ManagedReports", "cache");

    public Task<DeviceSnapshot> LoadAsync() => Task.Run(Load);

    public DeviceSnapshot Load()
    {
        var runs = ListRuns();
        if (runs.Count == 0) return new DeviceSnapshot();

        var collectedAt = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        var events = new List<ReportMateEvent>();
        var seenEvents = new HashSet<(DateTime, string, string)>();
        EventMetadata? metadata = null;

        InventoryData? inventory = null;
        SystemData? system = null;
        HardwareData? hardware = null;
        ManagementData? management = null;
        InstallsData? installs = null;
        SecurityData? security = null;
        IdentityData? identity = null;
        NetworkData? network = null;
        PeripheralsModuleData? peripherals = null;
        ApplicationsData? applications = null;

        for (var i = 0; i < runs.Count; i++)
        {
            var run = runs[i];
            inventory ??= Read<InventoryData>(run, "inventory", collectedAt);
            system ??= Read<SystemData>(run, "system", collectedAt);
            hardware ??= Read<HardwareData>(run, "hardware", collectedAt);
            management ??= Read<ManagementData>(run, "management", collectedAt);
            installs ??= Read<InstallsData>(run, "installs", collectedAt);
            security ??= Read<SecurityData>(run, "security", collectedAt);
            identity ??= Read<IdentityData>(run, "identity", collectedAt);
            network ??= Read<NetworkData>(run, "network", collectedAt);
            peripherals ??= Read<PeripheralsModuleData>(run, "peripherals", collectedAt);
            applications ??= Read<ApplicationsData>(run, "applications", collectedAt);

            // Every run's event.json carries that run's events; keep them all so the
            // Events tab has a history, deduplicated on (timestamp, module, message).
            if (i >= EventRunsToScan) continue;
            var unified = ReadFile<UnifiedDevicePayload>(Path.Combine(run, "event.json"));
            if (unified is not null)
            {
                metadata ??= unified.Metadata;
                foreach (var e in unified.Events ?? [])
                    if (seenEvents.Add((e.Timestamp, e.ModuleId ?? "", e.Message ?? ""))) events.Add(e);
            }
        }

        return new DeviceSnapshot
        {
            Metadata = metadata,
            Events = events,
            Inventory = inventory,
            System = system,
            Hardware = hardware,
            Management = management,
            Installs = installs,
            Security = security,
            Identity = identity,
            Network = network,
            Peripherals = peripherals,
            Applications = applications,
            ModuleCollectedAt = collectedAt,
            NewestRunDirectory = runs[0],
        };
    }

    /// <summary>Every cache run directory, newest first, by the timestamp in their name.</summary>
    public List<string> ListRuns()
    {
        if (!Directory.Exists(CacheRoot)) return [];
        return Directory.GetDirectories(CacheRoot)
            .Where(d => DateTime.TryParseExact(Path.GetFileName(d), "yyyy-MM-dd-HHmmss", null,
                System.Globalization.DateTimeStyles.None, out _))
            .OrderByDescending(d => Path.GetFileName(d), StringComparer.Ordinal)
            .ToList();
    }

    private static T? Read<T>(string run, string moduleId, Dictionary<string, DateTime> collectedAt) where T : class
    {
        var path = Path.Combine(run, moduleId + ".json");
        var data = ReadFile<T>(path);
        if (data is not null && !collectedAt.ContainsKey(moduleId))
            collectedAt[moduleId] = File.GetLastWriteTime(path);
        return data;
    }

    private static T? ReadFile<T>(string path) where T : class
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return JsonSerializer.Deserialize<T>(stream, JsonOptions);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
