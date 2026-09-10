using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>The web app's device list: every reporting device, searchable and filterable.</summary>
public sealed class DevicesPage : FleetPage
{
    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetDevicesAsync();
        if (!result.Ok)
        {
            // The fleet list needs the API, but this machine's own report is always
            // available from the local cache -- so offer it rather than dead-ending.
            var panel = new StackPanel();
            panel.Children.Add(FleetUnavailable(result.Status, result.Detail));
            panel.Children.Add(ThisDeviceCard());
            return panel;
        }

        var devices = result.Data!.Devices;
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Devices", "Every device reporting to ReportMate", "", Accent.Blue,
            Ui.Caption($"{devices.Count:N0} devices")));

        if (devices.Count == 0)
        {
            page.Children.Add(Ui.Card(Ui.EmptyState("No devices are reporting yet.")));
            return page;
        }

        var rows = devices
            .OrderByDescending(d => d.LastSeen ?? DateTime.MinValue)
            .Select(d => new DeviceRow
            {
                Name = Display(d),
                Serial = d.SerialNumber,
                Liveness = DeviceStatus.Calculate(d),
                Status = DeviceStatus.Label(DeviceStatus.Calculate(d)),
                StatusTone = DeviceStatus.Calculate(d) switch
                {
                    DeviceLiveness.Active => Tone.Success,
                    DeviceLiveness.Stale => Tone.Warning,
                    DeviceLiveness.Missing => Tone.Error,
                    _ => Tone.Neutral,
                },
                Department = d.Department ?? "",
                Platform = Platform(d),
                OsVersion = Pick(d.OsVersion, d.Modules?.System?.OperatingSystem?.DisplayVersion,
                                 d.Modules?.System?.OperatingSystem?.Version) ?? "",
                Usage = d.Usage ?? "",
                Location = d.Location ?? "",
                LastSeen = d.LastSeen,
            })
            .ToList();

        var table = new FilteredTable<DeviceRow>("Devices", "{0} of {1} devices", rows,
            (r, q) => r.Matches(q),
            [
                Col.Text("Device", "Name", star: true, sub: "Department"),
                Col.Pill("Status", "Status", "StatusTone", 110),
                Col.Text("Serial", "Serial", 160, mono: true),
                Col.Text("Platform", "Platform", 110),
                Col.Text("OS", "OsVersion", 130),
                Col.Text("Usage", "Usage", 120),
                Col.Text("Location", "Location", 130),
                Col.Text("Last Seen", "LastSeenLabel", 130),
            ], "Search devices...", "No devices match the current filters")
            .Filter([
                new("all", "All", rows.Count),
                new("windows", "Windows", rows.Count(r => r.Platform == "Windows")),
                new("macos", "macOS", rows.Count(r => r.Platform == "macOS")),
            ], (r, k) => k switch { "windows" => r.Platform == "Windows", "macos" => r.Platform == "macOS", _ => true })
            .Filter([
                new("all", "Any status", rows.Count),
                new("active", "Active", rows.Count(r => r.Liveness == DeviceLiveness.Active)),
                new("stale", "Stale", rows.Count(r => r.Liveness == DeviceLiveness.Stale)),
                new("missing", "Missing", rows.Count(r => r.Liveness == DeviceLiveness.Missing)),
            ], (r, k) => k switch
            {
                "active" => r.Liveness == DeviceLiveness.Active,
                "stale" => r.Liveness == DeviceLiveness.Stale,
                "missing" => r.Liveness == DeviceLiveness.Missing,
                _ => true,
            })
            .Build();

        table.Margin = new Thickness(0, 20, 0, 0);
        page.Children.Add(table);
        return page;
    }

    /// <summary>A way into this machine's own report when the fleet list cannot load.</summary>
    private static UIElement ThisDeviceCard()
    {
        var body = new StackPanel();
        body.Children.Add(Ui.Text("This device", "TitleTextStyle"));
        var sub = Ui.Caption("Open the report for this machine, built from its local cache.");
        sub.Margin = new Thickness(0, 4, 0, 0);
        body.Children.Add(sub);

        var card = Ui.Card(body, new Thickness(18, 16, 18, 18));
        card.Margin = new Thickness(0, 16, 0, 0);
        card.MaxWidth = 620;
        card.HorizontalAlignment = HorizontalAlignment.Center;
        card.Cursor = System.Windows.Input.Cursors.Hand;
        card.MouseLeftButtonUp += (s, _) =>
        {
            if (Window.GetWindow((DependencyObject)s) is MainWindow main) main.NavigateTo("device");
        };
        return card;
    }

    private sealed class DeviceRow
    {
        public string Name { get; init; } = "";
        public string Serial { get; init; } = "";
        public string Status { get; init; } = "";
        public Tone StatusTone { get; init; }
        public DeviceLiveness Liveness { get; init; }
        public string Usage { get; init; } = "";
        public string Department { get; init; } = "";
        public string Platform { get; init; } = "";
        public string OsVersion { get; init; } = "";
        public string Location { get; init; } = "";
        public DateTime? LastSeen { get; init; }
        public string LastSeenLabel => Relative(LastSeen);

        public bool Matches(string query) =>
            string.IsNullOrWhiteSpace(query)
            || $"{Name} {Serial} {Usage} {Department} {Location} {OsVersion}"
                .Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private static string? Pick(params string?[] options) =>
        options.FirstOrDefault(o => !string.IsNullOrWhiteSpace(o));

    private static string Display(FleetDevice d) =>
        !string.IsNullOrWhiteSpace(d.Name) ? d.Name
        : !string.IsNullOrWhiteSpace(d.Modules?.Inventory?.DeviceName) ? d.Modules!.Inventory!.DeviceName!
        : !string.IsNullOrWhiteSpace(d.SerialNumber) ? d.SerialNumber
        : d.DeviceId;

    private static string Platform(FleetDevice d)
    {
        var raw = (d.Platform ?? d.OsName ?? d.Modules?.System?.OperatingSystem?.Name ?? "").ToLowerInvariant();
        if (raw.Contains("win")) return "Windows";
        if (raw.Contains("mac") || raw.Contains("darwin")) return "macOS";
        return string.IsNullOrWhiteSpace(raw) ? "Unknown" : Format.Capitalize(raw);
    }

    private static string Relative(DateTime? when)
    {
        if (when is null) return "never";
        var delta = DateTime.UtcNow - when.Value.ToUniversalTime();
        if (delta < TimeSpan.FromMinutes(1)) return "just now";
        if (delta < TimeSpan.FromHours(1)) return $"{(int)delta.TotalMinutes}m ago";
        if (delta < TimeSpan.FromDays(1)) return $"{(int)delta.TotalHours}h ago";
        return $"{(int)delta.TotalDays}d ago";
    }
}
