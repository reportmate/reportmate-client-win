using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Reporting events from every cached run, bundled the way the web app bundles them:
/// routine info/system events within two minutes collapse into one row, while
/// success, warning and error events always stand alone.
/// </summary>
public sealed class EventsTab : DeviceTab
{
    public override string Id => "events";
    public override string Label => "Events";
    public override string Glyph => "";
    public override Accent Accent => Accent.Mono;
    public override string Description => "Event history and activity log";

    private static readonly string[] ValidKinds = ["info", "error", "warning", "success", "system"];
    private static readonly (string Key, string Label, Tone Tone)[] Filters =
    [
        ("success", "Success", Tone.Success), ("warning", "Warnings", Tone.Warning), ("error", "Errors", Tone.Error),
        ("system", "System", Tone.Purple), ("info", "Info", Tone.Info),
    ];

    private sealed class Bundle
    {
        public string Kind = "info";
        public DateTime Timestamp;
        public string Message = "";
        public List<ReportMateEvent> Events = [];
        public bool IsBundle => Events.Count > 1;
        public List<string> Kinds = [];
    }

    private string _filter = "all";

    protected override UIElement Build(DeviceSnapshot s)
    {
        var events = s.Events.Where(e => ValidKinds.Contains(Kind(e))).ToList();
        var page = new StackPanel();
        if (events.Count == 0)
        {
            page.Children.Add(Ui.TabHeader("Reporting Events", "Device activity and event monitoring", Glyph, Accent));
            page.Children.Add(Ui.Card(Ui.EmptyState("No events have been recorded for this device yet. Each collection run writes its events to the local cache.", "")));
            return page;
        }

        var bundles = BundleEvents(events);
        var counts = events.GroupBy(Kind).ToDictionary(g => g.Key, g => g.Count());

        var list = new StackPanel();
        var subtitle = Ui.Text("", "SubtitleTextStyle");
        var filterBar = new StackPanel { Orientation = Orientation.Horizontal };
        void Render()
        {
            var shown = _filter == "all" ? bundles : bundles.Where(b => b.Kind == _filter || b.Kinds.Contains(_filter)).ToList();
            subtitle.Text = _filter == "all" ? $"{bundles.Count} total events" : $"{shown.Count} {_filter} events";
            list.Children.Clear();
            foreach (var b in shown) list.Children.Add(Row(b));
            if (shown.Count == 0) list.Children.Add(Ui.Card(Ui.EmptyState($"No {_filter} events found.")));
            filterBar.Children.Clear();
            if (_filter != "all")
            {
                var clear = new Button { Content = "Clear", Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 0, 6, 0) };
                clear.Click += (_, _) => { _filter = "all"; Render(); };
                filterBar.Children.Add(clear);
            }
            foreach (var (key, label, tone) in Filters)
            {
                var count = counts.GetValueOrDefault(key);
                var pill = Ui.Pill(count > 0 ? $"{label}  {count}" : label, tone);
                pill.Cursor = System.Windows.Input.Cursors.Hand;
                pill.Margin = new Thickness(0, 0, 6, 0);
                pill.Padding = new Thickness(11, 4, 11, 4);
                pill.BorderThickness = new Thickness(2);
                pill.BorderBrush = _filter == key ? Ui.StatusBrush(tone) : System.Windows.Media.Brushes.Transparent;
                pill.MouseLeftButtonUp += (_, _) => { _filter = _filter == key ? "all" : key; Render(); };
                filterBar.Children.Add(pill);
            }
        }
        var header = new Grid { Margin = new Thickness(0, 0, 0, 20) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var tile = new Border { Width = 48, Height = 48, CornerRadius = new CornerRadius(10), Background = Ui.Brush("IconMonoBackground"), Child = Ui.Icon(Glyph, 22, Ui.Brush("IconMonoForeground")), Margin = new Thickness(0, 0, 14, 0) };
        ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
        header.Children.Add(tile);
        var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(Ui.Text("Reporting Events", "PageTitleTextStyle"));
        titles.Children.Add(subtitle);
        Grid.SetColumn(titles, 1);
        header.Children.Add(titles);
        filterBar.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(filterBar, 2);
        header.Children.Add(filterBar);
        page.Children.Add(header);
        page.Children.Add(Ui.Card(list, new Thickness(0)));
        Render();
        return page;
    }

    private static Border Row(Bundle b)
    {
        var tone = ToneFor(b.Kind);
        var body = new StackPanel();
        var head = new Grid { Margin = new Thickness(20, 12, 20, 12) };
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var pill = Ui.Pill(b.Kind, tone);
        pill.Width = 76; pill.Margin = new Thickness(0, 0, 12, 0);
        ((TextBlock)pill.Child).HorizontalAlignment = HorizontalAlignment.Center;
        head.Children.Add(pill);
        var msg = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var text = Ui.Text(b.Message.Length > 140 ? b.Message[..140] + "…" : b.Message);
        text.Margin = new Thickness(0); text.TextTrimming = TextTrimming.CharacterEllipsis; text.TextWrapping = TextWrapping.NoWrap; text.ToolTip = b.Message;
        msg.Children.Add(text);
        var modules = string.Join(", ", b.Events.Select(e => e.ModuleId).Where(m => !string.IsNullOrWhiteSpace(m)).Distinct());
        var sub = (b.IsBundle ? $"{b.Events.Count} events" : "") + (modules.Length > 0 ? (b.IsBundle ? " • " : "") + modules : "");
        if (sub.Length > 0) msg.Children.Add(Ui.Caption(sub));
        Grid.SetColumn(msg, 1);
        head.Children.Add(msg);
        var when = Ui.Caption(Format.RelativeTime(b.Timestamp));
        when.ToolTip = Format.ExactTime(b.Timestamp);
        when.VerticalAlignment = VerticalAlignment.Center; when.Margin = new Thickness(12, 0, 12, 0);
        Grid.SetColumn(when, 2);
        head.Children.Add(when);
        var toggle = new Button { Content = "Show Payload", Padding = new Thickness(8, 3, 8, 3), FontSize = 11.5 };
        Grid.SetColumn(toggle, 3);
        head.Children.Add(toggle);
        body.Children.Add(head);

        Border? details = null;
        toggle.Click += (_, _) =>
        {
            if (details is null)
            {
                details = new Border { Padding = new Thickness(20, 0, 20, 16), Child = Payload(b) };
                body.Children.Add(details);
                toggle.Content = "Hide Payload";
            }
            else
            {
                details.Visibility = details.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
                toggle.Content = details.Visibility == Visibility.Visible ? "Hide Payload" : "Show Payload";
            }
        };
        return new Border { BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = body };
    }

    private static UIElement Payload(Bundle b)
    {
        var panel = new StackPanel();
        // Error and warning detail lists, as the web's expandable rows show them.
        foreach (var e in b.Events)
        {
            var errors = Strings(e.Details, "error_messages", "errorMessages");
            var warnings = Strings(e.Details, "warning_messages", "warningMessages");
            var failed = Items(e.Details, "failed_items", "failedItems", "error");
            var warned = Items(e.Details, "warning_items", "warningItems", "warning");
            if (errors.Count + failed.Count > 0)
            {
                panel.Children.Add(Ui.Eyebrow("Errors"));
                foreach (var f in failed) panel.Children.Add(Ui.ListItem(f.Name, f.Text, "error", Tone.Error));
                foreach (var m in errors) panel.Children.Add(Ui.Status(m, Tone.Error, 12, FontWeights.Normal));
            }
            if (warnings.Count + warned.Count > 0)
            {
                panel.Children.Add(Ui.Eyebrow("Warnings"));
                foreach (var w in warned) panel.Children.Add(Ui.ListItem(w.Name, w.Text, "warning", Tone.Warning));
                foreach (var m in warnings) panel.Children.Add(Ui.Status(m, Tone.Warning, 12, FontWeights.Normal));
            }
        }

        var json = Serialize(b);
        var toolbar = new Grid { Margin = new Thickness(0, 8, 0, 6) };
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        toolbar.Children.Add(Ui.Label("Raw Payload"));
        var pre = new TextBox
        {
            Text = json, IsReadOnly = true, FontFamily = (System.Windows.Media.FontFamily)Ui.Res("MonoFont"), FontSize = 11.5,
            TextWrapping = TextWrapping.Wrap, BorderThickness = new Thickness(0), Background = Ui.Brush("SubtleFillBrush"),
            Foreground = Ui.Brush("TextPrimaryBrush"), Padding = new Thickness(10), MaxHeight = 420, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        var search = new SearchBox("Search payload...", q =>
        {
            if (string.IsNullOrWhiteSpace(q) || q.Length < 2) { pre.Text = json; return; }
            var lines = json.Split('\n');
            var keep = new SortedSet<int>();
            for (var i = 0; i < lines.Length; i++)
                if (lines[i].Contains(q, StringComparison.OrdinalIgnoreCase)) { if (i > 0) keep.Add(i - 1); keep.Add(i); if (i < lines.Length - 1) keep.Add(i + 1); }
            if (keep.Count == 0) { pre.Text = $"No matches for \"{q}\""; return; }
            var sb = new System.Text.StringBuilder();
            var last = -2;
            foreach (var i in keep) { if (i > last + 1 && sb.Length > 0) sb.AppendLine("  ..."); sb.AppendLine(lines[i]); last = i; }
            pre.Text = sb.ToString();
        });
        Grid.SetColumn(search, 1);
        toolbar.Children.Add(search);
        var copy = Ui.CopyButton(json);
        Grid.SetColumn(copy, 2);
        toolbar.Children.Add(copy);
        panel.Children.Add(toolbar);
        panel.Children.Add(pre);
        return panel;
    }

    private static string Serialize(Bundle b)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        if (!b.IsBundle) return JsonSerializer.Serialize(b.Events[0], opts);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Bundle Summary:");
        sb.AppendLine($"- Event Count: {b.Events.Count}");
        var modules = b.Events.Select(e => e.ModuleId).Where(m => !string.IsNullOrWhiteSpace(m)).Distinct().Select(Format.Capitalize).OrderBy(m => m).ToList();
        if (modules.Count > 0) sb.AppendLine($"- Modules: {string.Join(", ", modules)}");
        sb.AppendLine($"- Message: {b.Message}");
        sb.AppendLine();
        sb.AppendLine("Individual Event Payloads:");
        sb.AppendLine(new string('=', 50));
        var i = 1;
        foreach (var e in b.Events)
        {
            sb.AppendLine($"Event {i++}:");
            sb.AppendLine(new string('-', 30));
            sb.AppendLine(JsonSerializer.Serialize(e, opts));
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static List<Bundle> BundleEvents(List<ReportMateEvent> events)
    {
        var sorted = events.OrderByDescending(e => e.Timestamp).ToList();
        var processed = new HashSet<ReportMateEvent>();
        var result = new List<Bundle>();
        foreach (var e in sorted)
        {
            if (processed.Contains(e)) continue;
            var kind = Kind(e);
            var related = sorted.Where(o => !processed.Contains(o) && Math.Abs((o.Timestamp - e.Timestamp).TotalMinutes) <= 2 && ShouldBundle(kind, Kind(o))).ToList();
            if (related.Count > 1)
            {
                foreach (var r in related) processed.Add(r);
                var kinds = related.Select(Kind).Distinct().ToList();
                result.Add(new Bundle { Kind = PrimaryKind(kinds), Timestamp = e.Timestamp, Message = BundleMessage(related, kinds), Events = related, Kinds = kinds });
            }
            else
            {
                processed.Add(e);
                result.Add(new Bundle { Kind = kind, Timestamp = e.Timestamp, Message = string.IsNullOrWhiteSpace(e.Message) ? PayloadPreview(e) : e.Message, Events = [e], Kinds = [kind] });
            }
        }
        return result;
    }

    private static bool ShouldBundle(string a, string b) => a is "info" or "system" && b is "info" or "system";

    private static string PrimaryKind(List<string> kinds)
        => kinds.Contains("error") ? "error" : kinds.Contains("warning") ? "warning" : kinds.Contains("success") ? "success" : kinds.Contains("system") ? "system" : kinds.FirstOrDefault() ?? "info";

    private static string BundleMessage(List<ReportMateEvent> events, List<string> kinds)
    {
        var unique = events.Select(e => e.Message).Where(m => !string.IsNullOrWhiteSpace(m)).Distinct().ToList();
        if (unique.Count == 1) return unique[0];
        if (kinds.Contains("system") && kinds.Contains("info"))
        {
            var sys = events.FirstOrDefault(e => Kind(e) == "system" && !string.IsNullOrWhiteSpace(e.Message));
            if (sys is not null) return sys.Message;
        }
        var modules = events.SelectMany(ModuleNames).Distinct().Select(Format.Capitalize).ToList();
        if (modules.Count is > 0 and <= 3) return $"{string.Join(", ", modules)} data reported";
        if (modules.Count > 3) return $"{modules.Count} modules data reported";
        return $"{events.Count} data collection events";
    }

    private static string PayloadPreview(ReportMateEvent e)
    {
        var modules = ModuleNames(e).Select(Format.Capitalize).ToList();
        if (modules.Count is > 0 and <= 3) return $"{string.Join(", ", modules)} data reported";
        if (modules.Count > 3) return $"{modules.Count} modules data reported";
        return e.Details.Count == 0 ? "Event recorded" : "Data reported";
    }

    private static IEnumerable<string> ModuleNames(ReportMateEvent e)
    {
        if (!string.IsNullOrWhiteSpace(e.ModuleId)) yield return e.ModuleId;
        foreach (var key in new[] { "modules_processed", "modulesProcessed", "enabled_modules", "enabledModules", "modules" })
            if (e.Details.TryGetValue(key, out var v) && v is JsonElement { ValueKind: JsonValueKind.Array } arr)
                foreach (var item in arr.EnumerateArray()) if (item.ValueKind == JsonValueKind.String) yield return item.GetString() ?? "";
    }

    private static List<string> Strings(Dictionary<string, object> details, params string[] keys)
    {
        foreach (var key in keys)
            if (details.TryGetValue(key, out var v) && v is JsonElement { ValueKind: JsonValueKind.Array } arr)
                return arr.EnumerateArray().Select(x => Format.Str(x) ?? "").Where(x => x.Length > 0).ToList();
        return [];
    }

    private static List<(string Name, string Text)> Items(Dictionary<string, object> details, string key1, string key2, string textKey)
    {
        foreach (var key in new[] { key1, key2 })
            if (details.TryGetValue(key, out var v) && v is JsonElement { ValueKind: JsonValueKind.Array } arr)
                return arr.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object).Select(x =>
                {
                    string? Get(string k) => x.TryGetProperty(k, out var p) ? Format.Str(p) : null;
                    return (DeviceSnapshot.FirstNonEmpty(Get("displayName"), Get("name")) ?? "Unknown", DeviceSnapshot.FirstNonEmpty(Get(textKey), Get("message")) ?? "");
                }).ToList();
        return [];
    }

    private static string Kind(ReportMateEvent e) => (e.EventType ?? "info").Trim().ToLowerInvariant();

    private static Tone ToneFor(string kind) => kind switch
    {
        "success" => Tone.Success, "warning" => Tone.Warning, "error" => Tone.Error, "system" => Tone.Purple, _ => Tone.Info,
    };
}
