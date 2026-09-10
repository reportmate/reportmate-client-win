using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Managed Installs: Cimian configuration, last run log, run-level problems and the
/// managed items table grouped by category with per-item errors, warnings and
/// pending reasons. Status logic is a port of the web installs processor.
/// </summary>
public sealed class InstallsTab : DeviceTab
{
    public override string Id => "installs";
    public override string Label => "Installs";
    public override string Glyph => "";
    public override Accent Accent => Accent.Emerald;
    public override string Description => "Managed software installations and updates";

    public sealed class Message
    {
        public string Code { get; init; } = "";
        public string Text { get; init; } = "";
        public string? Details { get; init; }
        public DateTime? Timestamp { get; init; }
    }

    public sealed class Package
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string Version { get; init; } = "";
        public string InstalledVersion { get; init; } = "";
        public string Status { get; set; } = "Pending";
        public DateTime? LastUpdate { get; init; }
        public string Category { get; init; } = "";
        public string Developer { get; init; } = "";
        public string PendingReason { get; init; } = "";
        public List<Message> Errors { get; } = [];
        public List<Message> Warnings { get; } = [];
        public bool InLastRun => LastUpdate is not null;
        public bool Expandable => Errors.Count > 0 || Warnings.Count > 0 || (Status == "Pending" && PendingReason.Trim().Length > 0);
    }

    private readonly HashSet<string> _statusFilter = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _collapsed = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _expanded = new(StringComparer.OrdinalIgnoreCase);
    private string _query = "";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("installs") || s.Installs is null) return ModuleMissing("installs");
        var installs = s.Installs;
        var cimian = installs.Cimian;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        var sessions = cimian?.Sessions ?? [];
        var latest = sessions.FirstOrDefault();
        var lastRun = installs.LastCheckIn ?? latest?.StartTime;
        UIElement? right = null;
        if (lastRun is not null)
        {
            var p = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            p.Children.Add(Ui.Caption("Last Run"));
            var v = Ui.Text(CompactRelative(lastRun.Value));
            v.FontSize = 16; v.FontWeight = FontWeights.SemiBold; v.TextAlignment = TextAlignment.Right;
            p.Children.Add(v);
            right = p;
        }
        Add(Ui.TabHeader("Managed Installs", "Software deployment report", Glyph, Accent, right), 0);

        // Configuration card
        var config = cimian?.Config;
        var manifest = DeviceSnapshot.FirstNonEmpty(Format.Str(config, "ClientIdentifier", "manifest"), Format.Str(latest?.Config, "client_identifier", "ClientIdentifier")) ?? "No manifest configured";
        var repo = DeviceSnapshot.FirstNonEmpty(Format.Str(config, "SoftwareRepoURL", "software_repo_url"), Format.Str(latest?.Config, "software_repo_url", "SoftwareRepoURL")) ?? "No repo configured";
        var (runType, durationSeconds) = LatestRun(sessions);
        var catalog = CatalogLabel(cimian);
        var version = DeviceSnapshot.FirstNonEmpty(cimian?.Version) ?? "Unknown";
        var configGrid = Ui.Columns(3, 16,
            Ui.VStack(Ui.Stat("Manifest", manifest, mono: true, copy: true), Ui.Stat("Repo", repo, mono: true, copy: true, truncate: true)),
            Ui.VStack(Ui.Row("Run Type", Ui.Pill(Format.Capitalize(runType), Tone.Neutral)), Ui.Stat("Cimian Version", version)),
            Ui.VStack(Ui.Stat("Catalog", catalog), Ui.Stat("Last Seen", lastRun is null ? "Never" : lastRun.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                sublabel: durationSeconds > 0 ? $"Duration: {Format.Duration(durationSeconds)}" : null)));
        Add(Ui.Card(configGrid, new Thickness(20, 16, 20, 18)));

        // Run log
        if (!string.IsNullOrWhiteSpace(installs.RunLog))
            Add(RunLogSection(installs.RunLog));

        // Packages
        var packages = ProcessPackages(installs);
        var latestFailed = latest is not null && latest.Status is "failed" or "error" && (cimian?.Items?.Count ?? 0) == 0;
        if (latestFailed)
        {
            var banner = new StackPanel();
            var head = new StackPanel { Orientation = Orientation.Horizontal };
            head.Children.Add(Ui.Pill("Last run failed", Tone.Error));
            var note = Ui.Caption("The run did not complete, so no items were reported.");
            note.Margin = new Thickness(10, 0, 0, 0); note.VerticalAlignment = VerticalAlignment.Center;
            head.Children.Add(note);
            var stamp = Ui.Caption(string.Join(" · ", new[] { latest!.SessionId, Format.RelativeTime(latest.EndTime ?? latest.StartTime) }.Where(x => !string.IsNullOrWhiteSpace(x))));
            stamp.Margin = new Thickness(10, 0, 0, 0); stamp.VerticalAlignment = VerticalAlignment.Center;
            head.Children.Add(stamp);
            banner.Children.Add(head);
            Add(new Border { Background = Ui.Brush("PillRedBackground"), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 10, 14, 10), Child = banner });
        }

        var cacheMb = Format.Num(installs.CacheStatus?.GetValueOrDefault("cache_size_mb"));
        if (cacheMb <= 0 && sessions.Count > 0) cacheMb = sessions[0].CacheSizeMb;
        var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        void Render() => host.Content = PackagesCard(packages, cacheMb, latestFailed, lastRun, Render);
        Render();
        Add(host);
        return page;
    }

    // ── Packages card ────────────────────────────────────────────────

    private UIElement PackagesCard(List<Package> all, double cacheMb, bool runFailed, DateTime? lastRun, Action rerender)
    {
        var lastRunActive = _statusFilter.Contains("last_run");
        var statusOnly = _statusFilter.Where(f => f != "last_run").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var context = lastRunActive ? all.Where(p => p.InLastRun).ToList() : all;
        int Count(string st) => context.Count(p => p.Status.Equals(st, StringComparison.OrdinalIgnoreCase));

        IEnumerable<Package> filtered = all;
        if (lastRunActive) filtered = filtered.Where(p => p.InLastRun);
        if (statusOnly.Count > 0) filtered = filtered.Where(p => statusOnly.Contains(p.Status));
        if (_query.Trim().Length > 0) filtered = filtered.Where(p => p.DisplayName.Contains(_query.Trim(), StringComparison.OrdinalIgnoreCase) || p.Name.Contains(_query.Trim(), StringComparison.OrdinalIgnoreCase));
        var shown = filtered.ToList();

        var root = new StackPanel();

        // Header: title, counts, filters, search
        var header = new StackPanel { Margin = new Thickness(20, 14, 20, 12) };
        var titleRow = new Grid();
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var title = new StackPanel { Orientation = Orientation.Horizontal };
        title.Children.Add(Ui.Text("Managed Items:", "TitleTextStyle"));
        var count = Ui.Text(all.Count.ToString(), "TitleTextStyle"); count.Margin = new Thickness(6, 0, 0, 0); count.Foreground = Ui.Brush("TextSecondaryBrush");
        title.Children.Add(count);
        if (cacheMb > 0) { var c = Ui.Caption($"Cache: {cacheMb:F1} MB"); c.Margin = new Thickness(14, 0, 0, 0); c.VerticalAlignment = VerticalAlignment.Center; title.Children.Add(c); }
        if (_statusFilter.Count > 0)
        {
            var clear = new Button { Content = "Clear Filters", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(14, 0, 0, 0), FontSize = 11.5 };
            clear.Click += (_, _) => { _statusFilter.Clear(); rerender(); };
            title.Children.Add(clear);
        }
        var categories = shown.Select(p => p.Category.Trim()).Where(c => c.Length > 0).Distinct().ToList();
        if (categories.Count > 0 && !lastRunActive)
        {
            var toggle = new Button { Content = _collapsed.Count == 0 ? "Collapse All" : "Expand All", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(8, 0, 0, 0), FontSize = 11.5 };
            toggle.Click += (_, _) =>
            {
                if (_collapsed.Count == 0) { foreach (var c in categories) _collapsed.Add(c); if (shown.Any(p => p.Category.Trim().Length == 0)) _collapsed.Add("Uncategorized"); }
                else _collapsed.Clear();
                rerender();
            };
            title.Children.Add(toggle);
        }
        titleRow.Children.Add(title);

        var controls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        void FilterPill(string key, string label, int n, Tone tone)
        {
            var active = _statusFilter.Contains(key);
            var pill = Ui.Pill($"{label} - {n}", tone);
            pill.Cursor = Cursors.Hand; pill.Margin = new Thickness(0, 0, 6, 0); pill.Padding = new Thickness(11, 4, 11, 4);
            pill.BorderThickness = new Thickness(2);
            pill.BorderBrush = active ? Ui.StatusBrush(tone) : System.Windows.Media.Brushes.Transparent;
            pill.MouseLeftButtonUp += (_, _) =>
            {
                if (!_statusFilter.Remove(key))
                {
                    _statusFilter.Add(key);
                    if (key == "last_run") _statusFilter.RemoveWhere(f => f != "last_run");
                    else _statusFilter.Remove("last_run");
                }
                // A status filter narrows to the rows that need attention; open their detail.
                _expanded.Clear();
                if (_statusFilter.Count > 0)
                    foreach (var p in all.Where(p => p.Expandable && _statusFilter.Contains(p.Status))) _expanded.Add(p.Id);
                rerender();
            };
            controls.Children.Add(pill);
        }
        var lastRunCount = all.Count(p => p.InLastRun);
        if (lastRunCount > 0 && statusOnly.Count == 0) FilterPill("last_run", "Last Run", lastRunCount, Tone.Neutral);
        FilterPill("installed", "Installed", Count("Installed"), Tone.Success);
        FilterPill("pending", "Pending", Count("Pending"), Tone.Info);
        FilterPill("warning", "Warning", Count("Warning"), Tone.Warning);
        FilterPill("error", "Error", Count("Error"), Tone.Error);
        FilterPill("removed", "Removed", Count("Removed"), Tone.Purple);
        var search = new SearchBox("Search items...", q => { _query = q; rerender(); }) { Text = _query };
        controls.Children.Add(search);
        Grid.SetColumn(controls, 1);
        titleRow.Children.Add(controls);
        header.Children.Add(titleRow);
        if (_statusFilter.Count > 0)
            header.Children.Add(Ui.Caption($"Showing {shown.Count} of {all.Count} packages, filtered by: {string.Join(", ", _statusFilter.Select(f => f == "last_run" ? "Last Run" : f))}"));
        root.Children.Add(header);
        root.Children.Add(new Border { Height = 1, Background = Ui.Brush("DividerBrush") });

        // Column header
        root.Children.Add(HeaderRow());

        var body = new StackPanel();
        if (all.Count == 0)
        {
            body.Children.Add(Ui.EmptyState(runFailed
                ? "Last run did not complete. No items were reported because the run failed before it could evaluate the manifest."
                : "Cimian is configured and running, but no packages are currently assigned to this device."
                  + (lastRun is null ? "" : $" Last check: {Format.RelativeTime(lastRun)}"), runFailed ? "" : ""));
        }
        else if (shown.Count == 0)
        {
            body.Children.Add(Ui.EmptyState($"No items with {string.Join(" or ", _statusFilter.Select(f => f == "last_run" ? "last run" : f.ToLowerInvariant()))}. No packages match the selected filters."));
        }
        else
        {
            var groups = shown.GroupBy(p => p.Category.Trim().Length > 0 ? p.Category.Trim() : "Uncategorized")
                .OrderBy(g => g.Key == "Uncategorized" ? 1 : 0).ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase).ToList();
            var hasCategories = groups.Any(g => g.Key != "Uncategorized");
            foreach (var group in groups)
            {
                var items = group.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
                if (hasCategories)
                {
                    var collapsed = _collapsed.Contains(group.Key);
                    var head = new StackPanel { Orientation = Orientation.Horizontal };
                    head.Children.Add(Ui.Icon(collapsed ? "" : "", 10, Ui.Brush("TextSecondaryBrush")));
                    var name = Ui.Text(group.Key); name.FontWeight = FontWeights.SemiBold; name.Margin = new Thickness(8, 0, 0, 0);
                    head.Children.Add(name);
                    var n = Ui.Caption($"({Format.Plural(items.Count, "item")})"); n.Margin = new Thickness(8, 0, 0, 0); n.VerticalAlignment = VerticalAlignment.Center;
                    head.Children.Add(n);
                    var bar = new Border { Background = Ui.Brush("SubtleFillBrush"), Padding = new Thickness(20, 7, 20, 7), Child = head, Cursor = Cursors.Hand };
                    var key = group.Key;
                    bar.MouseLeftButtonUp += (_, _) => { if (!_collapsed.Remove(key)) _collapsed.Add(key); rerender(); };
                    body.Children.Add(bar);
                    if (collapsed) continue;
                }
                foreach (var p in items) body.Children.Add(PackageRow(p, rerender));
            }
        }
        root.Children.Add(body);
        return new Border { Style = (Style)Ui.Res("CardStyle"), Child = root };
    }

    private static Grid ColumnsGrid()
    {
        var g = new Grid();
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(190) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        return g;
    }

    private static Border HeaderRow()
    {
        var g = ColumnsGrid();
        var i = 0;
        foreach (var h in new[] { "Status", "Package", "Version", "Date Processed" })
        {
            var t = new TextBlock { Text = h.ToUpperInvariant(), FontSize = 10.5, FontWeight = FontWeights.SemiBold, Foreground = Ui.Brush("TextSecondaryBrush") };
            Grid.SetColumn(t, i++);
            g.Children.Add(t);
        }
        return new Border { Background = Ui.Brush("SubtleFillBrush"), Padding = new Thickness(20, 8, 20, 8), BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = g };
    }

    private Border PackageRow(Package p, Action rerender)
    {
        var g = ColumnsGrid();
        var pill = Ui.Pill(p.Status, StatusTone(p.Status));
        pill.HorizontalAlignment = HorizontalAlignment.Left;
        g.Children.Add(pill);
        var name = Ui.Text(p.DisplayName); name.FontWeight = FontWeights.Medium; name.Margin = new Thickness(0); name.TextTrimming = TextTrimming.CharacterEllipsis; name.TextWrapping = TextWrapping.NoWrap; name.ToolTip = p.Name;
        Grid.SetColumn(name, 1); g.Children.Add(name);
        var version = new StackPanel();
        var v = Ui.Text(Format.OrUnknown(p.Version)); v.Margin = new Thickness(0); v.TextTrimming = TextTrimming.CharacterEllipsis; v.TextWrapping = TextWrapping.NoWrap;
        version.Children.Add(v);
        if (!string.IsNullOrWhiteSpace(p.InstalledVersion) && p.InstalledVersion != p.Version) version.Children.Add(Ui.Caption($"{p.InstalledVersion} installed"));
        Grid.SetColumn(version, 2); g.Children.Add(version);
        var date = new StackPanel { Orientation = Orientation.Horizontal };
        date.Children.Add(Ui.Caption(p.LastUpdate is null ? "" : Format.RelativeTime(p.LastUpdate)));
        if (p.Expandable) { var chevron = Ui.Icon(_expanded.Contains(p.Id) ? "" : "", 10, Ui.Brush("TextSecondaryBrush")); chevron.Margin = new Thickness(8, 0, 0, 0); date.Children.Add(chevron); }
        Grid.SetColumn(date, 3); g.Children.Add(date);

        var stack = new StackPanel();
        var row = new Border { Padding = new Thickness(20, 9, 20, 9), Child = g, Background = System.Windows.Media.Brushes.Transparent, Cursor = p.Expandable ? Cursors.Hand : Cursors.Arrow };
        if (p.Expandable)
        {
            row.MouseLeftButtonUp += (_, _) => { if (!_expanded.Remove(p.Id)) _expanded.Add(p.Id); rerender(); };
            row.MouseEnter += (_, _) => row.Background = Ui.Brush("SubtleFillBrush");
            row.MouseLeave += (_, _) => row.Background = System.Windows.Media.Brushes.Transparent;
        }
        stack.Children.Add(row);
        if (p.Expandable && _expanded.Contains(p.Id))
        {
            var details = new StackPanel { Margin = new Thickness(20, 0, 20, 12) };
            foreach (var m in p.Errors) details.Children.Add(MessageBlock(m, Tone.Error));
            foreach (var m in p.Warnings) details.Children.Add(MessageBlock(m, Tone.Warning));
            if (p.Status == "Pending" && p.PendingReason.Trim().Length > 0)
                details.Children.Add(MessageBlock(new Message { Code = "PENDING", Text = p.PendingReason }, Tone.Info));
            stack.Children.Add(details);
        }
        return new Border { BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = stack };
    }

    private static Border MessageBlock(Message m, Tone tone)
    {
        var panel = new StackPanel();
        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var meta = new StackPanel { Orientation = Orientation.Horizontal };
        if (m.Code.Length > 0) meta.Children.Add(Ui.Pill(m.Code, tone, 10.5));
        if (m.Timestamp is not null) { var t = Ui.Caption(Format.ExactTime(m.Timestamp)); t.Margin = new Thickness(8, 0, 0, 0); t.VerticalAlignment = VerticalAlignment.Center; meta.Children.Add(t); }
        head.Children.Add(meta);
        var full = (m.Code.Length > 0 ? $"[{m.Code}] " : "") + m.Text + (m.Details is null ? "" : $"\n\nDetails: {m.Details}");
        var copy = Ui.CopyButton(full);
        Grid.SetColumn(copy, 1);
        head.Children.Add(copy);
        panel.Children.Add(head);
        var text = Ui.Text(m.Text); text.Foreground = Ui.StatusBrush(tone); text.FontWeight = FontWeights.Medium; text.Margin = new Thickness(0, 4, 0, 0);
        panel.Children.Add(text);
        if (!string.IsNullOrWhiteSpace(m.Details))
        {
            var pre = Ui.Mono(m.Details); pre.FontSize = 11; pre.Margin = new Thickness(0, 6, 0, 0);
            panel.Children.Add(new Border { Background = Ui.Brush("SubtleFillBrush"), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 8, 10, 8), Child = pre });
        }
        return new Border
        {
            Background = Ui.Brush(tone == Tone.Error ? "PillRedBackground" : tone == Tone.Warning ? "PillYellowBackground" : "PillBlueBackground"),
            CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 10, 12, 10), Margin = new Thickness(0, 6, 0, 0), Child = panel,
        };
    }

    private static UIElement RunLogSection(string log)
    {
        var text = CleanLogText(log);
        var pre = new TextBox
        {
            Text = text, IsReadOnly = true, FontFamily = (System.Windows.Media.FontFamily)Ui.Res("MonoFont"), FontSize = 11.5,
            TextWrapping = TextWrapping.NoWrap, BorderThickness = new Thickness(0), Background = Ui.Brush("SubtleFillBrush"),
            Foreground = Ui.Brush("TextPrimaryBrush"), Padding = new Thickness(10), MaxHeight = 480,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        var toolbar = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var search = new SearchBox("Search log...", q =>
            pre.Text = string.IsNullOrWhiteSpace(q) ? text : string.Join("\n", text.Split('\n').Where(l => l.Contains(q, StringComparison.OrdinalIgnoreCase))));
        search.Margin = new Thickness(0);
        search.HorizontalAlignment = HorizontalAlignment.Left;
        toolbar.Children.Add(search);
        var copy = Ui.CopyButton(text);
        Grid.SetColumn(copy, 1);
        toolbar.Children.Add(copy);
        var body = new StackPanel();
        body.Children.Add(toolbar);
        body.Children.Add(pre);
        return Ui.Card(Ui.Collapsible("Managed Software Update Last Run Log", body), new Thickness(20, 8, 20, 10));
    }

    // ── Processing (port of extractInstalls for the Cimian payload) ──

    private static List<Package> ProcessPackages(InstallsData installs)
    {
        var cimian = installs.Cimian;
        var packages = new List<Package>();
        if (cimian is null) return packages;
        var latest = cimian.Sessions?.FirstOrDefault();
        var latestSessionId = latest?.SessionId?.Trim() ?? "";
        var latestEnd = latest?.EndTime ?? latest?.StartTime;

        IEnumerable<CimianItem> items = cimian.Items ?? [];
        var source = items.Where(i =>
        {
            var name = DeviceSnapshot.FirstNonEmpty(i.ItemName, i.DisplayName) ?? "";
            var type = DeviceSnapshot.FirstNonEmpty(i.Type, i.ItemType) ?? "";
            return name is not ("managed_apps" or "managed_profiles") && type is not ("managed_apps" or "managed_profiles");
        }).ToList();

        if (source.Count == 0 && cimian.PendingPackages is { Count: > 0 })
        {
            foreach (var name in cimian.PendingPackages)
                packages.Add(new Package { Id = name.ToLowerInvariant(), Name = name, DisplayName = name, Status = "Pending", Version = "Unknown", LastUpdate = installs.LastCheckIn });
            return packages;
        }

        foreach (var item in source)
        {
            var name = DeviceSnapshot.FirstNonEmpty(item.ItemName, item.DisplayName) ?? "Unknown";
            var displayName = DeviceSnapshot.FirstNonEmpty(item.DisplayName, item.ItemName) ?? "Unknown";
            var rawStatus = DeviceSnapshot.FirstNonEmpty(item.CurrentStatus, item.MappedStatus) ?? "";
            var version = DeviceSnapshot.FirstNonEmpty(item.InstalledVersion, item.LatestVersion) ?? "Unknown";
            var installedVersion = item.InstalledVersion ?? "";
            var latestVersion = item.LatestVersion ?? "";

            var standardized = Standardize(rawStatus);
            string status;
            if (standardized is "Error" or "Warning" or "Removed") status = standardized;
            else if (!string.IsNullOrWhiteSpace(installedVersion) && !string.IsNullOrWhiteSpace(latestVersion))
                status = CompareVersions(installedVersion, latestVersion) >= 0 ? "Installed" : "Pending";
            else status = standardized;

            // Date processed: only for items acted on in the latest run, matched by session id.
            DateTime? lastUpdate = null;
            var marker = item.LastSeenInSession?.Trim() ?? "";
            if (marker.Length > 0)
            {
                if (IsSessionId(marker))
                {
                    if (latestSessionId.Length > 0 && marker == latestSessionId)
                        lastUpdate = item.LastAttemptTime ?? item.LastUpdate ?? latestEnd;
                }
                else if (latest?.StartTime is { } start && DateTime.TryParse(marker, out var t) && t >= start.AddMinutes(-1))
                    lastUpdate = t;
            }

            var pkg = new Package
            {
                Id = DeviceSnapshot.FirstNonEmpty(item.Id, item.ItemName?.ToLowerInvariant()) ?? "unknown",
                Name = name, DisplayName = displayName, Version = version, InstalledVersion = installedVersion,
                Status = status, LastUpdate = lastUpdate, Category = item.Category ?? "", Developer = item.Developer ?? "",
                PendingReason = item.PendingReason ?? "",
            };

            if (!string.IsNullOrWhiteSpace(item.LastError))
            {
                var (msg, details) = SplitLogText(item.LastError);
                pkg.Errors.Add(new Message { Code = item.HasInstallLoop || item.InstallLoopDetected ? "INSTALL_LOOP" : "ERROR", Text = msg, Details = details, Timestamp = AttemptTime(item, "failed", "error") });
            }
            if (!string.IsNullOrWhiteSpace(item.LastWarning))
            {
                var (msg, details) = SplitLogText(item.LastWarning);
                pkg.Warnings.Add(new Message { Code = item.HasInstallLoop || item.InstallLoopDetected ? "INSTALL_LOOP" : "WARNING", Text = msg, Details = details, Timestamp = AttemptTime(item, "warning") });
            }
            if (pkg.Errors.Count > 0) pkg.Status = "Error";
            else if (pkg.Warnings.Count > 0) pkg.Status = "Warning";
            packages.Add(pkg);
        }
        return packages;
    }

    private static DateTime? AttemptTime(CimianItem item, params string[] statuses)
    {
        DateTime? best = null;
        foreach (var attempt in item.RecentAttempts ?? [])
        {
            var st = (Format.Str(attempt, "status") ?? "").ToLowerInvariant();
            if (!statuses.Contains(st)) continue;
            var ts = Format.ParseDate(Format.Str(attempt, "timestamp"));
            if (ts is not null && (best is null || ts > best)) best = ts;
        }
        return best ?? item.LastAttemptTime ?? item.LastUpdate;
    }

    private static (string RunType, double DurationSeconds) LatestRun(List<CimianSession> sessions)
    {
        if (sessions.Count == 0) return ("Manual", 0);
        var withActivity = sessions.FirstOrDefault(s => s.Status is "completed" or "partial_failure"
            && (s.TotalActions > 0 || s.PackagesFailed > 0 || s.PackagesInstalled > 0 || s.Failures > 0 || s.Installs > 0 || s.Updates > 0) && s.DurationSeconds > 0);
        var chosen = withActivity ?? sessions.FirstOrDefault(s => s.Status == "completed" && s.DurationSeconds > 0) ?? sessions[0];
        return (DeviceSnapshot.FirstNonEmpty(chosen.RunType) ?? "Manual", chosen.DurationSeconds > 0 ? chosen.DurationSeconds : chosen.Duration.TotalSeconds);
    }

    private static string CatalogLabel(CimianInfo? cimian)
    {
        if (cimian?.Catalogs is { Count: > 0 } list) return string.Join(", ", list);
        var config = cimian?.Config;
        var def = Format.Str(config, "DefaultCatalog", "default_catalog");
        if (!string.IsNullOrWhiteSpace(def)) return def;
        var catalogs = Format.Str(config, "Catalogs", "catalogs");
        if (!string.IsNullOrWhiteSpace(catalogs) && catalogs != "[]")
        {
            try
            {
                var parsed = System.Text.Json.JsonSerializer.Deserialize<List<string>>(catalogs);
                if (parsed is { Count: > 0 }) return string.Join(", ", parsed);
            }
            catch { }
            return catalogs;
        }
        return "Not configured";
    }

    private static Tone StatusTone(string status) => status.ToLowerInvariant() switch
    {
        "installed" => Tone.Success, "pending" => Tone.Info, "warning" => Tone.Warning, "error" => Tone.Error, "removed" => Tone.Purple, _ => Tone.Neutral,
    };

    /// <summary>Port of standardizeInstallStatus: any collector status to Installed/Pending/Warning/Error/Removed.</summary>
    public static string Standardize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "Pending";
        var trimmed = raw.Trim();
        if (trimmed is "Installed" or "Pending" or "Warning" or "Error" or "Removed") return trimmed;
        return trimmed.ToLowerInvariant() switch
        {
            "installed" or "install" or "success" or "successful" or "completed" or "complete" or "up to date" or "uptodate" or "current" or "ok" or "install_succeeded" => "Installed",
            "pending" or "pending install" or "pending_install" or "pending update" or "pending_update" or "pendingupdate" or "available" or "update available" or "update_available"
                or "downloading" or "installing" or "queued" or "waiting" or "scheduled" or "not available" or "not_available" or "notavailable" => "Pending",
            "warning" or "warnings" or "warn" or "caution" or "needs attention" or "needs_attention" or "partial" or "partially installed" or "outdated" => "Warning",
            "error" or "errors" or "failed" or "failure" or "fail" or "broken" or "corrupt" or "corrupted" or "missing" or "not found" or "not_found" or "invalid" or "timeout" or "cancelled" or "canceled" => "Error",
            "removed" or "uninstalled" or "deleted" or "absent" or "not installed" or "not_installed" => "Removed",
            _ => "Pending",
        };
    }

    public static int CompareVersions(string a, string b)
    {
        if (a == b) return 0;
        static int[]? Parse(string v)
        {
            var m = Regex.Match(v.Trim(), @"^\d+(?:\.\d+)*");
            if (!m.Success) return null;
            return m.Value.Split('.').Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();
        }
        var pa = Parse(a); var pb = Parse(b);
        if (pa is null || pb is null) return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var ai = i < pa.Length ? pa[i] : 0;
            var bi = i < pb.Length ? pb[i] : 0;
            if (ai != bi) return ai > bi ? 1 : -1;
        }
        return 0;
    }

    private static bool IsSessionId(string value) => Regex.IsMatch(value, @"^\d{4}-\d{2}-\d{2}-\d{4}(\d{2})?$");

    private static readonly Regex Ansi = new(@"\u001b\[[0-9;]*[A-Za-z]|\u001b", RegexOptions.Compiled);

    public static string CleanLogText(string? raw)
    {
        var text = Ansi.Replace(raw ?? "", "").Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = text.Split('\n').Select(l => l.TrimEnd());
        var joined = string.Join("\n", lines);
        return Regex.Replace(joined, "\n{3,}", "\n\n").Trim();
    }

    public static (string Message, string? Details) SplitLogText(string? raw)
    {
        var text = CleanLogText(raw);
        var nl = text.IndexOf('\n');
        if (nl < 0) return (text, null);
        var details = text[(nl + 1)..].Trim();
        return (text[..nl].Trim(), details.Length > 0 ? details : null);
    }

    private static string CompactRelative(DateTime t)
    {
        var local = t.Kind == DateTimeKind.Utc ? t.ToLocalTime() : t;
        var diff = DateTime.Now - local;
        if (diff.TotalSeconds < 60) return "just now";
        if (diff.TotalMinutes < 60) return $"{(int)diff.TotalMinutes}m ago";
        if (diff.TotalHours < 24) return diff.Minutes > 0 ? $"{(int)diff.TotalHours}h {diff.Minutes}m ago" : $"{(int)diff.TotalHours}h ago";
        return $"{(int)diff.TotalDays}d ago";
    }
}
