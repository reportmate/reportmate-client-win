using System.Text.Json;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>How a value should read once it is out of the JSON.</summary>
public enum ValueFormat
{
    Text,
    Bytes,
    Megabytes,
    Count,
    RelativeTime,
}

/// <summary>
/// One addressable value in a report row. Paths are dotted and may cross an array
/// with <c>[]</c>, e.g. <c>storage[].type</c>, which yields every element's value.
/// </summary>
public sealed record Field(string Label, string Path, ValueFormat Format = ValueFormat.Text)
{
    /// <summary>The value as a display string, or empty when the path is absent.</summary>
    public string Read(JsonElement row) => Json.ReadOne(row, Path) is { } v ? Format switch
    {
        ValueFormat.Bytes => Json.Bytes(v),
        ValueFormat.Megabytes => Json.Megabytes(v),
        _ => Json.Text(v),
    } : "";

    /// <summary>Every value at this path — one for a scalar, many across an array.</summary>
    public IEnumerable<string> ReadAll(JsonElement row) =>
        Json.ReadMany(row, Path).Select(v => Format switch
        {
            ValueFormat.Bytes => Json.Bytes(v),
            ValueFormat.Megabytes => Json.Megabytes(v),
            _ => Json.Text(v),
        }).Where(s => !string.IsNullOrWhiteSpace(s));
}

/// <summary>A table column in a report.</summary>
public sealed record ReportColumn(string Header, Field Field, double? Width = null, bool Mono = false, bool Star = false);

/// <summary>
/// A whole fleet report: the charted distributions across the top and the table
/// underneath, matching how the web report pages are laid out.
/// </summary>
public sealed record ReportSpec(
    string Module,
    IReadOnlyList<Field> Distributions,
    IReadOnlyList<ReportColumn> Columns)
{
    public static ReportSpec? For(string module) => All.GetValueOrDefault(module);

    // Paths below are the report endpoints' own row shape, which is flattened and
    // NOT the nested per-device module JSON. They were read off the live responses;
    // guessing from the module shapes produced columns that were silently blank.
    private static readonly Dictionary<string, ReportSpec> All = new(StringComparer.OrdinalIgnoreCase)
    {
        ["hardware"] = new("hardware",
            [
                new("Manufacturer", "manufacturer"),
                new("Model", "model"),
                new("Architecture", "architecture"),
                new("Processor", "processor.name"),
                new("Graphics", "graphics.name"),
                new("Memory", "memory.totalPhysical", ValueFormat.Bytes),
                new("Storage type", "storage[].type"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Asset Tag", new("Asset Tag", "assetTag"), 110, Mono: true),
                new("Model", new("Model", "model"), 200),
                new("Processor", new("Processor", "processor.name"), 200),
                new("Memory", new("Memory", "memory.totalPhysical", ValueFormat.Bytes), 100),
                new("Graphics", new("Graphics", "graphics.name"), 170),
                new("Architecture", new("Architecture", "architecture"), 150),
            ]),

        ["system"] = new("system",
            [
                new("Operating system", "operatingSystem"),
                new("Version", "osVersion"),
                new("Display version", "displayVersion"),
                new("Edition", "edition"),
                new("Architecture", "architecture"),
                new("Activation", "activationStatus"),
                new("Locale", "locale"),
                new("Time zone", "timeZone"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("OS", new("OS", "operatingSystem"), 150),
                new("Version", new("Version", "displayVersion"), 110),
                new("Build", new("Build", "buildNumber"), 110),
                new("Edition", new("Edition", "edition"), 150),
                new("Uptime", new("Uptime", "uptimeString"), 120),
                new("Pending", new("Pending", "pendingUpdatesCount"), 90),
            ]),

        ["security"] = new("security",
            [
                new("Antivirus", "antivirusName"),
                new("Antivirus enabled", "antivirusEnabled"),
                new("Encryption", "encryptionEnabled"),
                new("Firewall", "firewallEnabled"),
                new("TPM present", "tpmPresent"),
                new("Secure Boot", "secureBootEnabled"),
                new("Tamper protection", "tamperProtected"),
                new("Smart App Control", "smartAppControlState"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Antivirus", new("Antivirus", "antivirusName"), 160),
                new("Encrypted", new("Encrypted", "encryptionEnabled"), 100),
                new("Firewall", new("Firewall", "firewallEnabled"), 95),
                new("Secure Boot", new("Secure Boot", "secureBootEnabled"), 110),
                new("Threats", new("Threats", "activeThreatCount"), 90),
                new("Critical CVEs", new("Critical CVEs", "criticalCveCount"), 110),
            ]),

        ["network"] = new("network",
            [
                new("Connection", "raw.activeConnection.connectionType"),
                new("Interface", "raw.primaryInterface"),
                new("DNS server", "raw.dns.servers[]"),
                new("Wi-Fi SSID", "raw.activeConnection.activeWifiSsid"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Hostname", new("Hostname", "raw.hostname"), 180, Mono: true),
                new("IP Address", new("IP Address", "raw.activeConnection.ipAddress"), 140, Mono: true),
                new("MAC", new("MAC", "raw.activeConnection.macAddress"), 150, Mono: true),
                new("Connection", new("Connection", "raw.activeConnection.connectionType"), 120),
                new("Gateway", new("Gateway", "raw.activeConnection.gateway"), 140, Mono: true),
            ]),

        ["identity"] = new("identity",
            [
                new("Domain joined", "directoryServices.activeDirectory.isDomainJoined"),
                new("Entra joined", "directoryServices.azureAd.joined"),
                new("Workgroup", "directoryServices.workgroup"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Users", new("Users", "summary.totalUsers"), 85),
                new("Admins", new("Admins", "summary.adminUsers"), 85),
                new("Disabled", new("Disabled", "summary.disabledUsers"), 90),
                new("Groups", new("Groups", "summary.groupCount"), 85),
                new("Logged in", new("Logged in", "summary.currentlyLoggedIn"), 100),
            ]),

        ["management"] = new("management",
            [
                new("Provider", "provider"),
                new("Enrolled", "isEnrolled"),
                new("Enrollment status", "enrollmentStatus"),
                new("Enrollment type", "enrollmentType"),
                new("Tenant", "tenantName"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Provider", new("Provider", "provider"), 150),
                new("Enrolled", new("Enrolled", "isEnrolled"), 95),
                new("Status", new("Status", "enrollmentStatus"), 140),
                new("Type", new("Type", "enrollmentType"), 140),
                new("Tenant", new("Tenant", "tenantName"), 170),
            ]),

        ["peripherals"] = new("peripherals",
            [
                new("Printer", "printers[].manufacturer"),
                new("USB vendor", "usbDevices[].vendor"),
                new("Audio", "audioDevices[].manufacturer"),
                new("Display", "displayDevices[].manufacturer"),
                new("Camera", "cameras[].manufacturer"),
            ],
            [
                new("Device", new("Device", "deviceName"), Star: true),
                new("Serial", new("Serial", "serialNumber"), 150, Mono: true),
                new("Printers", new("Printers", "printers[].name"), 200),
                new("USB", new("USB", "usbDevices[].name"), 220),
                new("Audio", new("Audio", "audioDevices[].name"), 180),
                new("Displays", new("Displays", "displayDevices[].friendlyName"), 170),
            ]),
    };

}

/// <summary>Reading values out of an arbitrary report row by dotted path.</summary>
public static class Json
{
    public static JsonElement? ReadOne(JsonElement root, string path) =>
        ReadMany(root, path).Select(e => (JsonElement?)e).FirstOrDefault();

    /// <summary>
    /// Every value at a dotted path. A <c>[]</c> segment fans out across an array,
    /// so <c>storage[].type</c> yields one value per disk.
    /// </summary>
    public static IEnumerable<JsonElement> ReadMany(JsonElement root, string path)
    {
        IEnumerable<JsonElement> current = [root];
        foreach (var rawSegment in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var fanOut = rawSegment.EndsWith("[]", StringComparison.Ordinal);
            var name = fanOut ? rawSegment[..^2] : rawSegment;
            current = Step(current, name, fanOut).ToList();
            if (!current.Any()) return [];
        }
        return current.Where(e => e.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined));
    }

    private static IEnumerable<JsonElement> Step(IEnumerable<JsonElement> nodes, string name, bool fanOut)
    {
        foreach (var node in nodes)
        {
            if (node.ValueKind != JsonValueKind.Object) continue;
            if (!TryGet(node, name, out var next)) continue;

            if (fanOut && next.ValueKind == JsonValueKind.Array)
                foreach (var item in next.EnumerateArray()) yield return item;
            else
                yield return next;
        }
    }

    /// <summary>Property lookup that tolerates the casing differences between modules.</summary>
    private static bool TryGet(JsonElement node, string name, out JsonElement value)
    {
        if (node.TryGetProperty(name, out value)) return true;
        foreach (var property in node.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        value = default;
        return false;
    }

    public static string Text(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() ?? "",
        JsonValueKind.Number => e.TryGetInt64(out var l) ? l.ToString("N0") : e.GetDouble().ToString("0.##"),
        JsonValueKind.True => "Yes",
        JsonValueKind.False => "No",
        JsonValueKind.Array => string.Join(", ", e.EnumerateArray().Select(Text).Where(s => s.Length > 0)),
        JsonValueKind.Object => "",
        _ => "",
    };

    public static string Bytes(JsonElement e) =>
        e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var bytes) ? Format.Bytes(bytes) : Text(e);

    public static string Megabytes(JsonElement e) =>
        e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var mb) ? Format.Bytes(mb * 1024L * 1024L) : Text(e);
}
