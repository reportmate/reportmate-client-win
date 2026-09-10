using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>Installed applications with usage: summary stats, most-used chart, filterable inventory table.</summary>
public sealed class ApplicationsTab : DeviceTab
{
    public override string Id => "applications";
    public override string Label => "Applications";
    public override string Glyph => "";
    public override Accent Accent => Accent.Blue;
    public override string Description => "Installed applications and packages";

    /// <summary>One application row after merging the app's own usage with the daily history.</summary>
    public sealed class AppRow
    {
        public string Name { get; init; } = "";
        public string Publisher { get; init; } = "";
        public string Version { get; init; } = "";
        public string Architecture { get; init; } = "";
        public string Source { get; init; } = "";
        public string Path { get; init; } = "";
        public string Sub { get; init; } = "";
        public long LaunchCount { get; init; }
        public double TotalSeconds { get; init; }
        public DateTime? LastUsed { get; init; }
        public DateTime? FirstSeen { get; init; }
        public List<string> Users { get; init; } = [];
        public int DaysSeen { get; init; }
        public bool ActiveNow { get; init; }
        public bool Used => LaunchCount > 0 || TotalSeconds > 0;

        public string LastUsedLabel => Used && LastUsed is not null ? Format.RelativeTime(LastUsed) : "—";
        public string TimeLabel => Used && TotalSeconds > 0 ? Duration(TotalSeconds) : "—";
        public double Share { get; set; }
        public string LaunchesLabel => Used && LaunchCount > 0 ? Format.Number(LaunchCount) : "—";
        public string DaysLabel => Used && DaysSeen > 0 ? Format.Plural(DaysSeen, "day") : "";
        public string UsersLabel => Used && Users.Count > 0 ? string.Join(", ", Users.Take(2).Select(ShortUser)) + (Users.Count > 2 ? $" +{Users.Count - 2}" : "") : "—";
        public string Running => ActiveNow ? "running" : "";
        public Tone RunningTone => Tone.Success;
        public string VersionLabel => string.IsNullOrWhiteSpace(Version) || Version == "Unknown" ? "—" : Version;
    }

    protected override UIElement Build(DeviceSnapshot s)
    {
        var page = new StackPanel();
        var apps = s.Applications;
        var installed = apps?.InstalledApplications ?? [];
        if (!s.HasModule("applications") || apps is null || installed.Count == 0)
        {
            page.Children.Add(Ui.TabHeader("Applications", "Versions installed and how much each is used", Glyph, Accent));
            page.Children.Add(Ui.Card(Ui.EmptyState("The applications module has not reported an inventory for this device.", "")));
            return page;
        }

        var history = apps.DailyUsageHistory ?? [];
        var byName = new Dictionary<string, (long Launches, double Seconds, string Last, string First, HashSet<string> Users, HashSet<string> Days)>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in history)
        {
            var key = UsageKey(row.AppName);
            if (key.Length == 0) continue;
            var e = byName.TryGetValue(key, out var existing) ? existing : (0, 0, "", "", new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>());
            e.Launches += row.Launches;
            e.Seconds += row.TotalSeconds;
            if (!string.IsNullOrWhiteSpace(row.Date))
            {
                e.Days.Add(row.Date);
                if (e.Last.Length == 0 || string.CompareOrdinal(row.Date, e.Last) > 0) e.Last = row.Date;
                if (e.First.Length == 0 || string.CompareOrdinal(row.Date, e.First) < 0) e.First = row.Date;
            }
            foreach (var u in row.Users ?? []) e.Users.Add(u);
            byName[key] = e;
        }
        var activeSessions = apps.Usage?.ActiveSessions ?? [];
        var activeByPath = activeSessions.Where(x => x.IsActive && !string.IsNullOrWhiteSpace(x.Path)).Select(x => x.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var activeByName = activeSessions.Where(x => x.IsActive).Select(x => UsageKey(x.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var rows = new List<AppRow>();
        foreach (var app in installed)
        {
            var name = DeviceSnapshot.FirstNonEmpty(app.Name) ?? "Unknown Application";
            var u = app.Usage;
            long launches = u?.LaunchCount ?? 0;
            var seconds = u?.TotalSeconds ?? 0;
            var last = u?.LastUsed;
            var first = u?.FirstSeen;
            var users = new HashSet<string>(u?.Users ?? [], StringComparer.OrdinalIgnoreCase);
            var days = new HashSet<string>();
            if (byName.TryGetValue(UsageKey(name), out var h))
            {
                launches = Math.Max(launches, h.Launches);
                seconds = Math.Max(seconds, h.Seconds);
                if (h.Last.Length > 0 && DateTime.TryParse(h.Last, out var hl) && (last is null || hl.Date > last.Value.Date)) last = hl;
                if (h.First.Length > 0 && DateTime.TryParse(h.First, out var hf) && (first is null || hf < first)) first = hf;
                foreach (var x in h.Users) users.Add(x);
                foreach (var d in h.Days) days.Add(d);
            }
            var active = (!string.IsNullOrWhiteSpace(app.InstallLocation) && activeByPath.Contains(app.InstallLocation)) || activeByName.Contains(UsageKey(name)) || (u?.ActiveSessionCount ?? 0) > 0;
            var publisher = string.IsNullOrWhiteSpace(app.Publisher) ? "" : app.Publisher;
            rows.Add(new AppRow
            {
                Name = name, Publisher = publisher, Version = app.Version ?? "", Architecture = app.Architecture ?? "", Source = app.Source ?? "",
                Path = app.InstallLocation ?? "", Sub = publisher.Length > 0 ? publisher : app.InstallLocation ?? "",
                LaunchCount = launches, TotalSeconds = seconds, LastUsed = last, FirstSeen = first, Users = users.ToList(), DaysSeen = days.Count, ActiveNow = active,
            });
        }

        // Most-used first; the version report is the same table read top to bottom.
        rows = rows.OrderByDescending(r => r.TotalSeconds).ThenByDescending(r => r.LaunchCount).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var maxSeconds = rows.Count > 0 ? rows.Max(r => r.TotalSeconds) : 0;
        foreach (var r in rows) r.Share = maxSeconds > 0 && r.TotalSeconds > 0 ? Math.Max(2, Math.Round(r.TotalSeconds / maxSeconds * 100)) : 0;

        var used = rows.Where(r => r.Used).ToList();
        var running = rows.Where(r => r.ActiveNow).ToList();
        var unused = rows.Where(r => !r.Used).ToList();
        var distinctUsers = rows.SelectMany(r => r.Users).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var totalSeconds = used.Sum(r => r.TotalSeconds);
        var historyDays = history.Select(h => h.Date).Where(d => !string.IsNullOrWhiteSpace(d)).Distinct().Count();

        var countBadge = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
        countBadge.Children.Add(Ui.Caption("Applications"));
        var countText = Ui.Text(Format.Number(rows.Count));
        countText.FontSize = 22; countText.FontWeight = FontWeights.Bold; countText.TextAlignment = TextAlignment.Right;
        countBadge.Children.Add(countText);
        page.Children.Add(Ui.TabHeader("Applications", "Versions installed and how much each is used", Glyph, Accent, countBadge));

        page.Children.Add(Ui.TileRow(12,
            Ui.Tile("Used", Format.Number(used.Count), Ui.Caption(historyDays > 0 ? $"across {Format.Plural(historyDays, "day")} of history" : "in the current capture window")),
            Ui.Tile("Running now", Format.Number(running.Count), activeSessions.Count > 0 ? Ui.Caption($"{Format.Plural(activeSessions.Count, "session")} in the capture window") : null),
            Ui.Tile("Time in apps", Duration(totalSeconds), Ui.Caption("process lifetime, summed")),
            Ui.Tile("People", Format.Number(distinctUsers), Ui.Caption(distinctUsers == 1 ? "one account seen" : "accounts seen in usage"))));

        var top = used.Where(r => r.TotalSeconds > 0).Take(8).ToList();
        if (top.Count > 0)
        {
            var topMax = top[0].TotalSeconds;
            var list = new StackPanel();
            foreach (var app in top)
            {
                var item = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
                var line = new Grid();
                line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                line.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var left = new StackPanel { Orientation = Orientation.Horizontal };
                if (app.ActiveNow) left.Children.Add(new System.Windows.Shapes.Ellipse { Width = 8, Height = 8, Fill = Ui.StatusBrush(Tone.Success), Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center });
                var n = Ui.Text(app.Name); n.FontWeight = FontWeights.Medium; n.Margin = new Thickness(0);
                left.Children.Add(n);
                if (app.VersionLabel != "—") { var v = Ui.Caption(app.Version); v.Margin = new Thickness(8, 0, 0, 0); v.VerticalAlignment = VerticalAlignment.Center; left.Children.Add(v); }
                line.Children.Add(left);
                var meta = string.Join("  •  ", new[]
                {
                    Duration(app.TotalSeconds),
                    Format.Plural((int)Math.Min(app.LaunchCount, int.MaxValue), "launch").Replace("launchs", "launches"),
                    app.Users.Count > 0 ? Format.Plural(app.Users.Count, "user") : null,
                    app.LastUsed is not null ? Format.RelativeTime(app.LastUsed) : null,
                }.Where(x => !string.IsNullOrEmpty(x)));
                var m = Ui.Caption(meta); m.VerticalAlignment = VerticalAlignment.Center;
                Grid.SetColumn(m, 1);
                line.Children.Add(m);
                item.Children.Add(line);
                var bar = Ui.UsageBar(topMax > 0 ? Math.Max(2, app.TotalSeconds / topMax * 100) : 0, 6);
                bar.Margin = new Thickness(0, 6, 0, 0);
                foreach (var child in bar.Children) if (child is Border b && Grid.GetColumn(b) == 0 && b.Background != Ui.Brush("SubtleFillBrush")) b.Background = Ui.Brush("IconBlueForeground");
                item.Children.Add(bar);
                list.Children.Add(item);
            }
            var card = Ui.TableCard("Most used", null, new Border { Padding = new Thickness(20, 14, 20, 8), Child = list });
            card.Margin = new Thickness(0, 24, 0, 0);
            page.Children.Add(card);
        }

        var table = new FilteredTable<AppRow>("Applications", "{0} of {1} applications", rows, Search,
            [
                Col.Text("Application", "Name", star: true, sub: "Sub"),
                Col.Pill("", "Running", "RunningTone", 84),
                Col.Text("Version", "VersionLabel", 140, sub: "Architecture"),
                Col.Text("Last used", "LastUsedLabel", 130),
                Col.Bar("Time", "TimeLabel", "Share", 150),
                Col.Text("Launches", "LaunchesLabel", 100, sub: "DaysLabel"),
                Col.Text("Users", "UsersLabel", 170),
            ], "Search applications...", "No applications in this view")
            .Filter([new("all", "All", rows.Count), new("used", "Used", used.Count), new("active", "Running", running.Count), new("unused", "No usage", unused.Count)],
                (r, k) => k switch { "used" => r.Used, "active" => r.ActiveNow, "unused" => !r.Used, _ => true })
            .Build();
        table.Margin = new Thickness(0, 24, 0, 0);
        page.Children.Add(table);
        return page;
    }

    private static bool Search(AppRow r, string q)
        => r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase)
           || r.Version.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
           || r.Users.Any(u => u.Contains(q, StringComparison.OrdinalIgnoreCase));

    /// <summary>History names come as "Safari", "Safari.app", or "helper (Safari)"; normalise to the app name.</summary>
    public static string UsageKey(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var trimmed = name.Trim();
        var open = trimmed.LastIndexOf('(');
        if (trimmed.EndsWith(')') && open >= 0) trimmed = trimmed[(open + 1)..^1];
        if (trimmed.EndsWith(".app", StringComparison.OrdinalIgnoreCase)) trimmed = trimmed[..^4];
        if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) trimmed = trimmed[..^4];
        return trimmed.Trim().ToLowerInvariant();
    }

    public static string Duration(double seconds)
    {
        if (seconds <= 0) return "-";
        if (seconds < 60) return $"{Math.Round(seconds)}s";
        if (seconds < 3600) return $"{Math.Round(seconds / 60)}m";
        var hours = (int)Math.Floor(seconds / 3600);
        if (hours >= 48) return $"{Math.Round(hours / 24.0)}d {hours % 24}h";
        var mins = (int)Math.Round(seconds % 3600 / 60);
        return mins > 0 ? $"{hours}h {mins}m" : $"{hours}h";
    }

    private static string ShortUser(string user) => user.Contains('\\') ? user[(user.LastIndexOf('\\') + 1)..] : user;
}
