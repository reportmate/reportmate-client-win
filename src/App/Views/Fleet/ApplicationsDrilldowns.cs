using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>
/// The web app's applications coverage page: how many devices are actually reporting
/// usage, and which have gone dark. A device that stopped reporting looks identical to
/// a device nobody uses unless the two are told apart, which is what this page is for.
/// </summary>
public sealed class CoveragePage : FleetPage
{
    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetRawAsync(
            "/api/v1/applications/collection-health?freshDays=7&staleDays=30");
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Usage Coverage", "Which devices are reporting application usage", "", Accent.Emerald));

        if (!result.Ok)
        {
            page.Children.Add(FleetUnavailable(result.Status, result.Detail));
            return page;
        }

        var root = result.Data!.RootElement;
        var summary = root.TryGetProperty("summary", out var s) ? s : default;
        var total = Int(summary, "totalDevices");

        var cards = new StackPanel();
        var body = new StackPanel();
        body.Children.Add(Charts.Bar("Reporting", Int(summary, "healthy"), total, Tone.Success));
        body.Children.Add(Charts.Bar("Stale", Int(summary, "stale"), total, Tone.Warning));
        body.Children.Add(Charts.Bar("Dark", Int(summary, "dark"), total, Tone.Error));
        body.Children.Add(Charts.Bar("Never reported", Int(summary, "never"), total, Tone.Neutral));
        var caption = Ui.Caption($"Fresh within {Int(summary, "freshDays")} days, stale within {Int(summary, "staleDays")}");
        caption.Margin = new Thickness(0, 4, 0, 0);
        body.Children.Add(caption);
        cards.Children.Add(Ui.StatBlock("Coverage", $"{total:N0} devices", "", Accent.Emerald,
            new Border { Padding = new Thickness(20, 4, 20, 16), Child = body }));

        // The platform split matters here: one platform reporting and the other not is a
        // client problem, whereas both drifting together is a fleet problem.
        if (root.TryGetProperty("byPlatform", out var platforms) && platforms.ValueKind == JsonValueKind.Array)
        {
            var platformBody = new StackPanel();
            foreach (var entry in platforms.EnumerateArray())
                foreach (var platform in entry.EnumerateObject())
                {
                    var v = platform.Value;
                    var platformTotal = Int(v, "total");
                    platformBody.Children.Add(Ui.Caption($"{platform.Name} — {platformTotal:N0} devices"));
                    platformBody.Children.Add(Charts.Bar("Reporting", Int(v, "healthy"), platformTotal, Tone.Success));
                    platformBody.Children.Add(Charts.Bar("Never reported", Int(v, "never"), platformTotal, Tone.Neutral));
                }
            cards.Children.Add(Pad(Ui.StatBlock("By platform", null, "", Accent.Purple,
                new Border { Padding = new Thickness(20, 4, 20, 16), Child = platformBody })));
        }

        cards.Margin = new Thickness(0, 20, 0, 0);
        page.Children.Add(cards);

        if (root.TryGetProperty("darkDevices", out var dark) && dark.ValueKind == JsonValueKind.Array)
        {
            var rows = dark.EnumerateArray().Select(d => new DarkRow
            {
                Device = Str(d, "deviceName"),
                Serial = Str(d, "serialNumber"),
                Platform = Str(d, "platform"),
                Location = Str(d, "location"),
                Usage = Str(d, "usage"),
                Bucket = Str(d, "bucket"),
                LastUsage = Str(d, "lastUsageDate"),
                Days = Str(d, "daysSinceUsage"),
            }).ToList();

            if (rows.Count > 0)
            {
                var table = new FilteredTable<DarkRow>("Not reporting usage", "{0} of {1} devices", rows,
                    (r, q) => r.Matches(q),
                    [
                        Col.Text("Device", "Device", star: true),
                        Col.Text("Serial", "Serial", 150, mono: true),
                        Col.Text("Platform", "Platform", 100),
                        Col.Text("State", "Bucket", 110),
                        Col.Text("Last usage", "LastUsage", 140),
                        Col.Text("Days dark", "Days", 100),
                        Col.Text("Location", "Location", 120),
                    ], "Search devices...", "No devices match the current filters")
                    .Build();
                table.Margin = new Thickness(0, 14, 0, 0);
                page.Children.Add(table);
            }
        }

        return page;
    }

    private sealed class DarkRow
    {
        public string Device { get; init; } = "";
        public string Serial { get; init; } = "";
        public string Platform { get; init; } = "";
        public string Location { get; init; } = "";
        public string Usage { get; init; } = "";
        public string Bucket { get; init; } = "";
        public string LastUsage { get; init; } = "";
        public string Days { get; init; } = "";

        public bool Matches(string q) => string.IsNullOrWhiteSpace(q)
            || $"{Device} {Serial} {Platform} {Location} {Usage} {Bucket}".Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private static UIElement Pad(UIElement e)
    {
        if (e is FrameworkElement fe) fe.Margin = new Thickness(0, 14, 0, 0);
        return e;
    }

    internal static int Int(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : 0;

    internal static string Str(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var v)
            ? Json.Text(v) : "";
}

/// <summary>
/// The web app's per-application usage drill-down: which devices ran one application,
/// for how long, and by how many people.
/// </summary>
public sealed class AppUsagePage : FleetPage
{
    private readonly string _app;
    private readonly int _days;

    public AppUsagePage(string app, int days)
    {
        _app = app;
        _days = days;
    }

    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetRawAsync(
            $"/api/v1/applications/usage/by-device?app={Uri.EscapeDataString(_app)}&days={_days}");

        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader(_app, $"Usage across the fleet over the last {_days} days", "", Accent.Blue));

        if (!result.Ok)
        {
            page.Children.Add(FleetUnavailable(result.Status, result.Detail));
            return page;
        }

        var root = result.Data!.RootElement;
        var summary = root.TryGetProperty("summary", out var s) ? s : default;

        var stats = Ui.Columns(4, 14,
            Stat("Devices", CoveragePage.Int(summary, "deviceCount").ToString("N0")),
            Stat("Hours", Hours(summary)),
            Stat("Launches", CoveragePage.Int(summary, "totalLaunches").ToString("N0")),
            Stat("People", CoveragePage.Int(summary, "uniqueUsers").ToString("N0")));
        stats.Margin = new Thickness(0, 20, 0, 0);
        page.Children.Add(stats);

        if (!root.TryGetProperty("devices", out var devices) || devices.ValueKind != JsonValueKind.Array)
        {
            page.Children.Add(Ui.Card(Ui.EmptyState("No usage was reported for this application.")));
            return page;
        }

        var rows = devices.EnumerateArray().Select(d => new UsageRow
        {
            Device = CoveragePage.Str(d, "deviceName"),
            Serial = CoveragePage.Str(d, "serialNumber"),
            HoursLabel = CoveragePage.Str(d, "totalHours"),
            Launches = CoveragePage.Str(d, "launchCount"),
            Users = CoveragePage.Str(d, "userCount"),
            LastUsed = CoveragePage.Str(d, "lastUsed"),
            Location = CoveragePage.Str(d, "location"),
            Usage = CoveragePage.Str(d, "usage"),
        }).ToList();

        if (rows.Count == 0)
        {
            page.Children.Add(Ui.Card(Ui.EmptyState("No usage was reported for this application.")));
            return page;
        }

        var table = new FilteredTable<UsageRow>("Devices", "{0} of {1} devices", rows,
            (r, q) => r.Matches(q),
            [
                Col.Text("Device", "Device", star: true),
                Col.Text("Serial", "Serial", 150, mono: true),
                Col.Text("Hours", "HoursLabel", 90),
                Col.Text("Launches", "Launches", 100),
                Col.Text("People", "Users", 90),
                Col.Text("Last used", "LastUsed", 160),
                Col.Text("Location", "Location", 120),
            ], "Search devices...", "No devices match the current filters")
            .Build();
        table.Margin = new Thickness(0, 14, 0, 0);
        page.Children.Add(table);
        return page;
    }

    private static string Hours(JsonElement summary) =>
        summary.ValueKind == JsonValueKind.Object && summary.TryGetProperty("totalUsageHours", out var v)
            ? Json.Text(v) : "0";

    private static UIElement Stat(string label, string value)
    {
        var body = new StackPanel();
        var n = Ui.Text(value);
        n.FontSize = 26;
        n.FontWeight = FontWeights.SemiBold;
        body.Children.Add(n);
        body.Children.Add(Ui.Caption(label));
        return Ui.Card(body, new Thickness(18, 14, 18, 16));
    }

    private sealed class UsageRow
    {
        public string Device { get; init; } = "";
        public string Serial { get; init; } = "";
        public string HoursLabel { get; init; } = "";
        public string Launches { get; init; } = "";
        public string Users { get; init; } = "";
        public string LastUsed { get; init; } = "";
        public string Location { get; init; } = "";
        public string Usage { get; init; } = "";

        public bool Matches(string q) => string.IsNullOrWhiteSpace(q)
            || $"{Device} {Serial} {Location} {Usage}".Contains(q, StringComparison.OrdinalIgnoreCase);
    }
}
