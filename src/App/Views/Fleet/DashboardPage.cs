using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>
/// The web app's home dashboard. Layout follows it: a narrow left column of fleet
/// status and counters, a wide right column of recent activity and the platform and
/// OS breakdowns. One consolidated API call backs every widget, as on the web.
/// </summary>
public sealed class DashboardPage : FleetPage
{
    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetDashboardAsync();
        if (!result.Ok) return FleetUnavailable(result.Status, result.Detail);

        var data = result.Data!;
        var devices = data.Devices;

        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Dashboard", "Fleet status at a glance", "", Accent.Blue,
            Ui.Caption($"{devices.Count:N0} devices reporting")));

        var left = new StackPanel();
        Stack(left, StatusWidget(devices));
        Stack(left, Ui.Columns(2, 14,
            CounterCard("Errors", data.InstallStats?.TotalErrorItems ?? 0, data.InstallStats?.DevicesWithErrors ?? 0, Tone.Error),
            CounterCard("Warnings", data.InstallStats?.TotalWarningItems ?? 0, data.InstallStats?.DevicesWithWarnings ?? 0, Tone.Warning)));
        Stack(left, NewClientsWidget(devices));

        var right = new StackPanel();
        Stack(right, RecentEventsWidget(data.Events));
        Stack(right, PlatformDistributionWidget(devices));
        Stack(right, Ui.Columns(2, 14,
            OsVersionWidget(devices, "Windows"),
            OsVersionWidget(devices, "macOS")));

        var columns = Ui.Columns([3, 7], 18, left, right);
        columns.Margin = new Thickness(0, 20, 0, 0);
        page.Children.Add(columns);
        return page;
    }

    private static void Stack(Panel host, UIElement child)
    {
        if (host.Children.Count > 0 && child is FrameworkElement fe) fe.Margin = new Thickness(0, 14, 0, 0);
        host.Children.Add(child);
    }

    // ── Widgets ──────────────────────────────────────────────────────────

    /// <summary>Active / stale / missing counts, the web's StatusWidget.</summary>
    private static UIElement StatusWidget(List<FleetDevice> devices)
    {
        // Derived from lastSeen, not the API's own status field, because that is what
        // the web dashboard does -- see DeviceStatus for why the two disagree.
        var buckets = devices.GroupBy(DeviceStatus.Calculate)
            .ToDictionary(g => g.Key, g => g.Count());
        int Count(DeviceLiveness l) => buckets.TryGetValue(l, out var n) ? n : 0;

        var body = new StackPanel();
        body.Children.Add(BigNumber(devices.Count, "devices total"));
        body.Children.Add(Charts.Bar("Active", Count(DeviceLiveness.Active), devices.Count, Tone.Success));
        body.Children.Add(Charts.Bar("Stale", Count(DeviceLiveness.Stale), devices.Count, Tone.Warning));
        body.Children.Add(Charts.Bar("Missing", Count(DeviceLiveness.Missing), devices.Count, Tone.Error));
        if (Count(DeviceLiveness.Archived) > 0)
            body.Children.Add(Charts.Bar("Archived", Count(DeviceLiveness.Archived), devices.Count, Tone.Neutral));
        return Ui.StatBlock("Fleet Status", "Seen in the last 24 hours", "", Accent.Green, Pad(body));
    }

    private static UIElement CounterCard(string title, int total, int deviceCount, Tone tone)
    {
        var body = new StackPanel();
        var n = Ui.Text(total.ToString("N0"), "StatValueStyle", Ui.StatusBrush(tone));
        n.FontSize = 30;
        n.FontWeight = FontWeights.SemiBold;
        body.Children.Add(n);
        body.Children.Add(Ui.Caption(deviceCount == 1 ? "on 1 device" : $"across {deviceCount:N0} devices"));
        return Ui.StatBlock(title, null, "", tone == Tone.Error ? Accent.Red : Accent.Yellow, Pad(body));
    }

    /// <summary>Devices that first reported recently, the web's NewClientsWidget.</summary>
    private static UIElement NewClientsWidget(List<FleetDevice> devices)
    {
        var recent = devices
            .Where(d => d.CreatedAt is not null)
            .OrderByDescending(d => d.CreatedAt)
            .Take(8)
            .ToList();

        if (recent.Count == 0)
            return Ui.StatBlock("New Clients", "Recently enrolled", "", Accent.Indigo,
                Pad(Ui.EmptyState("No devices have first reported recently.")));

        var body = new StackPanel();
        foreach (var d in recent)
        {
            var row = new Grid();
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var name = Ui.Text(DisplayName(d));
            name.TextTrimming = TextTrimming.CharacterEllipsis;
            row.Children.Add(name);
            var when = Ui.Caption(Relative(d.CreatedAt));
            Grid.SetColumn(when, 1);
            row.Children.Add(when);
            row.Margin = new Thickness(0, 0, 0, 8);
            body.Children.Add(row);
        }
        return Ui.StatBlock("New Clients", "Recently enrolled", "", Accent.Indigo, Pad(body));
    }

    /// <summary>The web's RecentEventsTable.</summary>
    private static UIElement RecentEventsWidget(List<FleetEvent> events)
    {
        if (events.Count == 0)
            return Ui.StatBlock("Recent Events", "Across the fleet", "", Accent.Cyan,
                Pad(Ui.EmptyState("No events have been reported.")));

        var body = new StackPanel();
        foreach (var e in events.OrderByDescending(e => e.When ?? DateTime.MinValue).Take(12))
        {
            var row = new Grid { Margin = new Thickness(0, 0, 0, 9) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var kind = (e.Kind ?? e.EventType ?? "info").ToLowerInvariant();
            var pill = Ui.Pill(Format.Capitalize(kind), kind switch
            {
                "error" or "failed" => Tone.Error,
                "warning" or "warn" => Tone.Warning,
                "success" or "installed" => Tone.Success,
                _ => Tone.Neutral,
            });
            pill.Margin = new Thickness(0, 0, 10, 0);
            row.Children.Add(pill);

            var text = Ui.Text(Truncate(e.Message, 110));
            text.TextTrimming = TextTrimming.CharacterEllipsis;
            text.ToolTip = e.Message;
            Grid.SetColumn(text, 1);
            row.Children.Add(text);

            var meta = Ui.Caption($"{e.DeviceName ?? e.SerialNumber ?? ""}  ·  {Relative(e.When)}");
            Grid.SetColumn(meta, 2);
            row.Children.Add(meta);
            body.Children.Add(row);
        }
        return Ui.StatBlock("Recent Events", "Across the fleet", "", Accent.Cyan, Pad(body));
    }

    /// <summary>Windows / macOS split, the web's PlatformDistributionWidget.</summary>
    private static UIElement PlatformDistributionWidget(List<FleetDevice> devices)
    {
        var groups = devices
            .GroupBy(d => NormalizePlatform(d))
            .Select(g => (Name: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .ToList();

        var body = new StackPanel();
        var total = devices.Count;
        foreach (var (name, count) in groups)
            body.Children.Add(Charts.Bar(name, count, total, name == "Windows" ? Tone.Info : Tone.Neutral));

        return Ui.StatBlock("Platforms", "Devices by operating system", "", Accent.Purple, Pad(body));
    }

    private static UIElement OsVersionWidget(List<FleetDevice> devices, string platform)
    {
        var matching = devices.Where(d => NormalizePlatform(d) == platform).ToList();
        if (matching.Count == 0)
            return Ui.StatBlock($"{platform} Versions", null, "", Accent.Gray,
                Pad(Ui.EmptyState($"No {platform} devices are reporting.")));

        var groups = matching
            .GroupBy(OsLabel)
            .Select(g => (Name: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .Take(8)
            .ToList();

        var body = new StackPanel();
        foreach (var (name, count) in groups)
            body.Children.Add(Charts.Bar(name, count, matching.Count, Tone.Info));

        return Ui.StatBlock($"{platform} Versions", $"{matching.Count:N0} devices", "", Accent.Teal, Pad(body));
    }

    // ── Small parts ──────────────────────────────────────────────────────

    private static UIElement BigNumber(int value, string caption)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 16) };
        var n = Ui.Text(value.ToString("N0"));
        n.FontSize = 34;
        n.FontWeight = FontWeights.SemiBold;
        panel.Children.Add(n);
        panel.Children.Add(Ui.Caption(caption));
        return panel;
    }

    private static UIElement Pad(UIElement body) =>
        new Border { Padding = new Thickness(20, 4, 20, 18), Child = body };

    private static string NormalizePlatform(FleetDevice d)
    {
        var raw = (d.Platform ?? d.OsName ?? d.Modules?.System?.OperatingSystem?.Name ?? "").ToLowerInvariant();
        if (raw.Contains("win")) return "Windows";
        if (raw.Contains("mac") || raw.Contains("darwin") || raw.Contains("os x")) return "macOS";
        return string.IsNullOrWhiteSpace(raw) ? "Unknown" : Format.Capitalize(raw);
    }

    /// <summary>The OS version, preferring the flat field and falling back to the module summary.</summary>
    private static string OsLabel(FleetDevice d)
    {
        var os = d.Modules?.System?.OperatingSystem;
        var version = Pick(d.OsVersion, os?.DisplayVersion, os?.Version, os?.Build);
        return string.IsNullOrWhiteSpace(version) ? "Unknown" : version!;
    }

    private static string? Pick(params string?[] options) =>
        options.FirstOrDefault(o => !string.IsNullOrWhiteSpace(o));

    private static string DisplayName(FleetDevice d) =>
        !string.IsNullOrWhiteSpace(d.Name) ? d.Name
        : !string.IsNullOrWhiteSpace(d.Modules?.Inventory?.DeviceName) ? d.Modules!.Inventory!.DeviceName!
        : !string.IsNullOrWhiteSpace(d.SerialNumber) ? d.SerialNumber
        : d.DeviceId;

    private static string Truncate(string? s, int max) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..max] + "…";

    private static string Relative(DateTime? when)
    {
        if (when is null) return "unknown";
        var delta = DateTime.UtcNow - when.Value.ToUniversalTime();
        if (delta < TimeSpan.Zero) return "just now";
        if (delta < TimeSpan.FromMinutes(1)) return "just now";
        if (delta < TimeSpan.FromHours(1)) return $"{(int)delta.TotalMinutes}m ago";
        if (delta < TimeSpan.FromDays(1)) return $"{(int)delta.TotalHours}h ago";
        return $"{(int)delta.TotalDays}d ago";
    }
}
